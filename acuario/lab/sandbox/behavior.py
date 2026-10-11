"""Real-time ptrace-based syscall behavior monitor for sandbox containers.

Replaces the post-hoc regex monitor (acuario/scanner/behavior_monitor.py) as the
primary behavior-auditing layer.  Where the regex monitor scans agent *output*
after the fact, this module attaches strace to the process inside the sandbox and
streams real kernel syscall events.

Architecture
------------
``PtraceBehaviorMonitor`` spawns a background ``strace`` process attached to a
target PID (or to a shell command it launches).  Events are streamed line-by-line
and written to a JSONL file at
``results/scanner/<session>/behavior_events.jsonl``.

The monitor exposes:
- ``start(pid)``   - attach to a running PID inside the container via
                     ``docker exec``.
- ``start_command(cmd)`` - launch a command *through* strace, capturing its
                           full syscall trace.
- ``stop()``       - send SIGTERM to the strace process, drain remaining events.
- ``read_events()`` - return all captured ``BehaviorEvent`` objects.
- ``read_events_jsonl()`` - return the raw JSONL path for the analyzer tool.

Portability / fallback
----------------------
If ``strace`` is not available inside the container (or the Docker daemon refuses
the ptrace attach), the monitor degrades gracefully: ``start()`` returns False and
the caller should fall back to ``BehaviorMonitor`` (the regex-based fallback).

The sandbox seccomp profile already adds ``SYS_PTRACE`` to the container's cap_add
list (see ``acuario/sandbox/container.py:57`` and
``acuario/sandbox/seccomp_profiles.py``), so ptrace works by default.

Tool surface
------------
``read_behavior_events(session_events_path)`` is a thin wrapper intended to be
registered as an agent tool so the analyzer can correlate its actions with real
syscall traces during an audit session.

Toggle
------
Enabled by default when the sandbox reports SYS_PTRACE capability is present.
Pass ``enabled=False`` to disable and fall back to regex monitor.
"""

from __future__ import annotations

import json
import logging
import queue
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Syscall interest filter
# ---------------------------------------------------------------------------

#: Syscalls whose paths/arguments we want to capture verbatim.
_OPEN_SYSCALLS = frozenset(
    {
        "open",
        "openat",
        "openat2",
        "creat",
    }
)

_EXEC_SYSCALLS = frozenset(
    {
        "execve",
        "execveat",
    }
)

_NET_SYSCALLS = frozenset(
    {
        "connect",
        "bind",
        "accept",
        "accept4",
        "sendto",
        "recvfrom",
        "socket",
        "socketpair",
    }
)

_MOUNT_SYSCALLS = frozenset(
    {
        "mount",
        "umount2",
        "pivot_root",
    }
)

TRACKED_SYSCALLS: frozenset[str] = _OPEN_SYSCALLS | _EXEC_SYSCALLS | _NET_SYSCALLS | _MOUNT_SYSCALLS

#: Paths of interest inside /open* syscalls.
_SENSITIVE_PATH_PREFIXES: tuple[str, ...] = (
    "/etc/",
    "/proc/self/",
    "/proc/1/",
    "/sys/fs/",
    "/var/run/docker.sock",
    "/root/",
)


# Files any process opens during normal startup / name resolution. Reading
# these is never a signal on its own - they dominate the ptrace noise.
# NOTE we do NOT demote /etc/passwd or /proc/self here - a bare read of those is
# genuine recon the monitor is specifically meant to catch.
_BENIGN_OPEN_PATHS: frozenset[str] = frozenset(
    {
        "/etc/ld.so.cache",
        "/etc/ld.so.preload",
        "/etc/hosts",
        "/etc/host.conf",
        "/etc/nsswitch.conf",
        "/etc/resolv.conf",
        "/etc/gai.conf",
        "/etc/localtime",
        "/etc/protocols",
        "/etc/services",
    }
)
_BENIGN_OPEN_PREFIXES: tuple[str, ...] = (
    "/etc/ld.so.conf",
    "/usr/lib/locale",
    "/usr/share/locale",
    "/usr/share/zoneinfo",
)

# An exec of a binary living under one of these trees is a freshly-staged /
# agent-authored payload being run - the single highest-value behavior signal,
# not a routine tool invocation.
_STAGED_EXEC_PREFIXES: tuple[str, ...] = ("/scratch/", "/tmp/", "/var/tmp/", "/dev/shm/")

# Routine, non-shell tools. Executing one is not a signal by itself
# (sleep/timeout dominate the exec noise). Shells (sh/bash/dash) are
# deliberately EXCLUDED - a shell spawn stays a 'warning' signal.
_ROUTINE_EXEC_BASENAMES: frozenset[str] = frozenset(
    {
        "sleep",
        "timeout",
        "cat",
        "ls",
        "echo",
        "true",
        "false",
        "which",
        "dirname",
        "basename",
        "uname",
        "id",
        "pwd",
        "head",
        "tail",
        "wc",
        "sort",
        "cut",
        "tr",
        "grep",
        "egrep",
        "fgrep",
        "sed",
        "awk",
        "find",
        "test",
        "expr",
        "mkdir",
        "rm",
        "cp",
        "mv",
        "ln",
        "chmod",
        "touch",
        "date",
        "seq",
        "xargs",
        "tee",
        "printf",
        "env",
        "git",
        "python",
        "python3",
        "node",
        "npm",
        "npx",
        "pip",
        "pip3",
        "gcc",
        "cc",
        "g++",
        "make",
        "cmake",
        "ld",
        "as",
        "ar",
    }
)


def _exec_basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if path else path


#: Severity ladder for matched events.
def _classify_severity(syscall: str, path: str, *, denied: bool = False) -> str:
    """Classify one syscall event's severity.

    Benign startup file reads and routine (non-shell) tool execs are
    demoted to 'info' - they dominate ptrace events - while a
    permission-denied access (EACCES/EPERM) or an exec of a freshly-staged
    binary is escalated, so the remaining warning/critical set carries signal.
    """
    if syscall in _MOUNT_SYSCALLS:
        return "critical"
    if syscall in _EXEC_SYSCALLS:
        # Check the staged-payload elevation BEFORE the routine downgrade so
        # a /scratch or /tmp binary can never be softened to info.
        if any(path.startswith(p) for p in _STAGED_EXEC_PREFIXES):
            return "critical"
        if _exec_basename(path) in _ROUTINE_EXEC_BASENAMES:
            return "info"
        return "warning"
    # A blocked access attempt is anomalous regardless of the target.
    if denied:
        return "warning"
    if syscall in _NET_SYSCALLS:
        return "warning"
    if path in _BENIGN_OPEN_PATHS or any(path.startswith(p) for p in _BENIGN_OPEN_PREFIXES):
        return "info"
    if any(path.startswith(p) for p in _SENSITIVE_PATH_PREFIXES):
        return "warning"
    return "info"


# ---------------------------------------------------------------------------
# Event schema
# ---------------------------------------------------------------------------


@dataclass
class BehaviorEvent:
    """A single syscall event captured by the ptrace monitor."""

    timestamp: str  # ISO-8601 UTC
    session_id: str
    syscall: str
    args: str  # raw argument string from strace
    path: str  # extracted first string argument (path), if any
    return_code: str  # strace return value ("= 3" or "= -1 ENOENT ...")
    severity: str  # info | warning | critical
    raw_line: str  # original strace output line

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Core monitor class
# ---------------------------------------------------------------------------


class PtraceBehaviorMonitor:
    """Real-time syscall monitor using strace.

    Parameters
    ----------
    session_id : str
        Identifier for the audit session.  Used in event records and as part
        of the output file name.
    output_path : Path | str | None
        Directory where ``behavior_events.jsonl`` is written.  Defaults to the
        current working directory.
    enabled : bool
        Set to False to disable entirely (all methods become no-ops).
    container : Any | None
        Optional SandboxContainer reference.  When provided, ``start(pid)``
        uses ``docker exec`` to attach strace inside the container.
    """

    def __init__(
        self,
        session_id: str,
        output_path: Path | str | None = None,
        enabled: bool = True,
        container: Any | None = None,
        output_filename: str = "behavior_events.jsonl",
    ) -> None:
        self._session_id = session_id
        self._enabled = enabled
        self._container = container
        self._events: list[BehaviorEvent] = []
        # Per-command instrumentation gives each command its own trace file
        # via wrap_argv() and ingests it synchronously after the exec
        # returns, so no background reader thread or long-running strace
        # process is needed.  These attributes are kept for backwards-compat
        # with test fixtures that mock subprocess.Popen.
        self._proc: subprocess.Popen | None = None
        self._reader_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._event_queue: queue.Queue[str] = queue.Queue()
        # Monotonic counter for unique per-command trace file paths
        # under /scratch/ inside the container.
        self._exec_counter: int = 0

        if output_path is not None:
            out_dir = Path(output_path)
            out_dir.mkdir(parents=True, exist_ok=True)
            # Analyzer sessions pass output_filename="analyzer_behavior_events.jsonl"
            # so their syscall stream doesn't collide with exploit-dev's.
            self._jsonl_path = out_dir / output_filename
        else:
            self._jsonl_path = Path.cwd() / f"behavior_events_{session_id}.jsonl"

        self._jsonl_file = None  # opened on start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def jsonl_path(self) -> Path:
        return self._jsonl_path

    def start(self, pid: int | None = None) -> bool:
        """Activate the per-command instrumentation pipeline.

        A single long-running ``strace -p <pid> -f`` attached to the
        container's init does not work on Docker: ``docker exec`` commands
        spawn outside the attached process tree, so strace cannot see them.
        Instead the monitor instruments every container exec individually -
        ``SandboxContainer.exec()`` calls ``wrap_argv()`` to inject
        ``strace -f -e trace=...`` around each command, then calls
        ``ingest_trace_text()`` after the command finishes.  This
        captures real syscalls from EVERY agent-issued subprocess.

        ``start()`` here is just bookkeeping: open the JSONL file and
        verify strace is reachable inside the container (the caller
        provides ``container`` at __init__ time).  ``pid`` is ignored -
        kept for API compatibility with the previous signature.
        """
        if not self._enabled:
            return False
        if self._container is None:
            logger.debug("[ptrace] no container reference - monitor cannot instrument")
            return False

        # Probe for strace inside the container; without it the wrap
        # is a no-op and we'd emit no events.
        if not self._strace_available_in_container():
            logger.info(
                "[ptrace] ⚠ strace not installed inside container for session %s - "
                "regex behavior monitor remains the active fallback",
                self._session_id,
            )
            return False

        try:
            self._jsonl_file = self._jsonl_path.open("a", encoding="utf-8")
        except Exception:
            logger.debug("[ptrace] could not open jsonl path", exc_info=True)
            return False

        logger.info(
            "[ptrace] ▸ monitor activated for session %s "
            "(per-command instrumentation via strace wrap)",
            self._session_id,
        )
        return True

    def _strace_available_in_container(self) -> bool:
        """Quick probe: does ``strace --version`` succeed inside the container?

        Accepts either a raw docker-py container (has ``.exec_run``) or an
        Acuario ``SandboxContainer`` (wraps the docker-py container under
        ``._container``).  Probe runs BEFORE the monitor is attached to
        ``sandbox.behavior_monitor``, so it doesn't recurse into the
        strace-wrap path.
        """
        raw = self._raw_container()
        if raw is None:
            return False
        try:
            res = raw.exec_run(
                ["strace", "--version"],
                tty=False,
                demux=False,
                environment={},
            )
            exit_code = getattr(res, "exit_code", None)
            if exit_code is None and isinstance(res, tuple) and len(res) >= 1:
                exit_code = res[0]
            return exit_code == 0
        except Exception:
            logger.debug("[ptrace] strace probe failed", exc_info=True)
            return False

    def _raw_container(self) -> Any | None:
        """Return the underlying docker-py container regardless of whether
        ``self._container`` is a raw docker-py object or an Acuario
        ``SandboxContainer`` wrapper.
        """
        if self._container is None:
            return None
        # SandboxContainer stores the raw container at ``._container``
        inner = getattr(self._container, "_container", None)
        if inner is not None and hasattr(inner, "exec_run"):
            return inner
        # Raw docker-py container - has exec_run directly
        if hasattr(self._container, "exec_run"):
            return self._container
        return None

    # -------- per-command instrumentation API ---------------------------

    def wrap_argv(self, argv: list[str]) -> tuple[list[str], str | None]:
        """Inject strace into the front of ``argv`` so the command's
        syscalls get traced into a fresh file under ``/scratch/``.

        Returns ``(wrapped_argv, trace_path_in_container)``.  When the
        monitor isn't active, returns ``(argv, None)`` - caller runs the
        original command unwrapped.

        The caller is expected to call :meth:`ingest_trace_text` with the
        contents of ``trace_path_in_container`` after the wrapped exec
        completes.
        """
        if self._jsonl_file is None:
            return argv, None
        self._exec_counter += 1
        trace_path = f"/scratch/_ptrace_{self._session_id}_{self._exec_counter}.log"
        syscall_expr = ",".join(sorted(TRACKED_SYSCALLS))
        # Note the ``--`` so argv that begins with a flag isn't reparsed
        # as a strace option.
        wrapped = [
            "strace",
            "-f",
            "-e",
            f"trace={syscall_expr}",
            "-tt",
            "-y",
            "-s",
            "256",
            "-o",
            trace_path,
            "--",
            *argv,
        ]
        return wrapped, trace_path

    def ingest_trace_text(self, text: str) -> int:
        """Parse a trace file's contents (as produced by ``strace -o``) and
        emit one BehaviorEvent per tracked syscall line.

        Returns the number of events ingested.  Safe to call when the
        monitor isn't active (returns 0).
        """
        if self._jsonl_file is None or not text:
            return 0
        count = 0
        for raw_line in text.splitlines():
            event = self._parse_line(raw_line)
            if event is not None:
                self._events.append(event)
                self._write_event(event)
                count += 1
        return count

    def stop(self, timeout: float = 5.0) -> None:
        """Flush and close the JSONL output file.

        With per-command instrumentation there's no daemon thread to
        terminate.  The legacy background-reader fields are still cleaned
        up in case an older test still wires them.
        """
        if not self._enabled:
            return
        self._stop_event.set()
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=timeout)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

        if self._reader_thread is not None:
            self._reader_thread.join(timeout=timeout + 1)
            self._reader_thread = None

        if self._jsonl_file is not None:
            try:
                self._jsonl_file.close()
            except Exception:
                pass
            self._jsonl_file = None

        logger.info(
            "[ptrace] ◇ monitor stopped - %d events captured for session %s",
            len(self._events),
            self._session_id,
        )

    def read_events(self) -> list[BehaviorEvent]:
        """Return all captured events so far."""
        return list(self._events)

    def read_events_jsonl(self) -> str:
        """Return the path to the JSONL event log."""
        return str(self._jsonl_path)

    def summary(self) -> dict[str, int]:
        """Return event counts grouped by syscall."""
        counts: dict[str, int] = {}
        for ev in self._events:
            counts[ev.syscall] = counts.get(ev.syscall, 0) + 1
        return counts

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_attach_command(self, pid: int | None) -> list[str] | None:
        """Build the strace command list.

        When a container reference is available, prefer ``docker exec
        <id> strace -f -p 1 ...`` so strace runs INSIDE the container's PID
        namespace and can follow the analyzer agent's exec'd subprocesses.
        A host-side ``strace -p <host_pid>`` can only see the container's
        init process (``sleep infinity``) because PID namespaces hide
        container subprocesses from the host without ``--pid=host``.

        Fallback ordering:
          1. ``docker exec <container> strace -f -p 1 ...`` (preferred)
          2. host ``strace -p <pid> ...`` (legacy; only useful without
             a PID namespace, e.g. processes started directly on the host)
          3. None (cannot attach - caller falls back to the regex monitor)
        """
        syscall_expr = ",".join(sorted(TRACKED_SYSCALLS))
        strace_flags = [
            "strace",
            "-e",
            f"trace={syscall_expr}",
            "-tt",  # timestamps
            "-y",  # annotate fd numbers with paths
            "-s",
            "256",  # max string length
            "-f",  # follow forks
        ]

        # Preferred: docker exec strace inside the container's PID namespace.
        # Requires `strace` installed inside the container image - if it's
        # missing, the docker exec invocation fails and start() returns False,
        # triggering the regex-monitor fallback path.
        container_id = self._get_container_id()
        if container_id:
            return [
                "docker",
                "exec",
                container_id,
                *strace_flags,
                "-p",
                "1",  # PID 1 inside the container always exists
            ]

        # Legacy fallback for host-side tracing.
        if pid is not None:
            return strace_flags + ["-p", str(pid)]
        return None

    def _get_container_id(self) -> str | None:
        """Pull the container ID off the SandboxContainer reference.

        Returns None when no container is attached or the ID isn't available.
        """
        if self._container is None:
            return None
        # SandboxContainer exposes ``container_id``; raw docker-py containers
        # expose ``id``.  Support both for flexibility.
        cid = getattr(self._container, "container_id", None)
        if cid:
            return str(cid)
        cid = getattr(self._container, "id", None)
        if cid:
            return str(cid)
        return None

    def _read_loop(self) -> None:
        """Background thread: read strace output line by line."""
        assert self._proc is not None
        assert self._proc.stdout is not None

        try:
            for raw_line in self._proc.stdout:
                if self._stop_event.is_set():
                    break
                raw_line = raw_line.rstrip("\n")
                event = self._parse_line(raw_line)
                if event is not None:
                    self._events.append(event)
                    self._write_event(event)
        except Exception:
            logger.debug("[ptrace] reader loop error", exc_info=True)

    def _parse_line(self, raw_line: str) -> BehaviorEvent | None:
        """Parse a single strace output line into a BehaviorEvent.

        strace output format (with -tt and -y):
            HH:MM:SS.usec  syscall(args) = retval

        We only emit events for tracked syscalls.
        """
        # Strip leading PID or timestamp prefix
        line = raw_line.strip()
        # Remove PID column if present (e.g. "12345 openat(...")
        if line and line[0].isdigit():
            parts = line.split(None, 1)
            if len(parts) == 2:
                # Could be "12345 openat(..." or "HH:MM:SS openat(..."
                # We keep stripping numeric/timestamp prefixes
                line = parts[1].strip()
            else:
                return None

        # Extract syscall name
        paren = line.find("(")
        if paren == -1:
            return None
        syscall = line[:paren].strip()
        # Remove strace timestamp prefix like "HH:MM:SS.usec " embedded in
        # syscall name after a second split
        if " " in syscall:
            syscall = syscall.rsplit(" ", 1)[-1]

        if syscall not in TRACKED_SYSCALLS:
            return None

        # Extract args and return code
        close_paren = line.rfind(")")
        args = line[paren + 1 : close_paren] if close_paren > paren else ""
        return_part = line[close_paren + 1 :].strip() if close_paren != -1 else ""
        # return_part looks like " = 3" or " = -1 ENOENT (No such file or directory)"
        return_code = return_part.lstrip("= ").split(" ")[0] if return_part else ""

        # Extract first quoted string as path
        path = _extract_first_quoted(args)

        # A permission-denied access (EACCES/EPERM) is anomalous regardless
        # of the target - surface it even when the path/binary looks routine.
        # Detect from the raw line, not return_part: a "(Permission denied)"
        # suffix makes rfind(")") land on the errno text, emptying return_part.
        denied = "-1 EACCES" in line or "-1 EPERM" in line
        severity = _classify_severity(syscall, path, denied=denied)

        event = BehaviorEvent(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            session_id=self._session_id,
            syscall=syscall,
            args=args[:256],
            path=path,
            return_code=return_code,
            severity=severity,
            raw_line=raw_line[:512],
        )

        if severity in ("warning", "critical"):
            logger.warning(
                "[ptrace] ⚠ %s(%s) in session %s [%s]",
                syscall,
                path or args[:60],
                self._session_id,
                severity,
            )

        return event

    def _write_event(self, event: BehaviorEvent) -> None:
        if self._jsonl_file is not None:
            try:
                self._jsonl_file.write(json.dumps(event.to_dict()) + "\n")
                self._jsonl_file.flush()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _extract_first_quoted(s: str) -> str:
    """Extract the first double-quoted string from a strace argument list."""
    start = s.find('"')
    if start == -1:
        return ""
    end = s.find('"', start + 1)
    if end == -1:
        return s[start + 1 :]
    return s[start + 1 : end]


# ---------------------------------------------------------------------------
# Agent tool surface
# ---------------------------------------------------------------------------


def read_behavior_events(events_path: str) -> str:
    """Read behavior events from a JSONL file and return a formatted summary.

    Intended as an agent tool: the analyzer can call this to correlate its
    actions with real syscall traces observed during the sandbox session.

    Parameters
    ----------
    events_path : str
        Path to the ``behavior_events.jsonl`` file produced by
        ``PtraceBehaviorMonitor``.

    Returns
    -------
    str
        Human-readable summary of captured events, grouped by severity and
        syscall category.  Returns an empty string if no events were found.
    """
    path = Path(events_path)
    if not path.exists():
        return ""

    events: list[dict] = []
    try:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    except Exception as exc:
        return f"[ptrace] Error reading {events_path}: {exc}"

    if not events:
        return ""

    critical = [e for e in events if e.get("severity") == "critical"]
    warnings = [e for e in events if e.get("severity") == "warning"]
    info = [e for e in events if e.get("severity") == "info"]

    lines = [
        f"Behavior events: {len(events)} total "
        f"({len(critical)} critical, {len(warnings)} warning, {len(info)} info)"
    ]

    for ev in critical + warnings:
        lines.append(
            f"  [{ev['severity'].upper()}] {ev['syscall']}({ev['path'] or ev['args'][:60]})"
            f" → {ev['return_code']} @ {ev['timestamp']}"
        )

    return "\n".join(lines)
