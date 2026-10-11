"""Generic Docker sandbox container with no-network and read-only-mount defaults.

This is the isolation primitive used by AnalyzerSandbox to run analyzer agents
against a cloned source tree. Distinct from kali_docker_tool - there are no
approval gates, no apt-get install, no network access, and no host-volume
write access to the source tree.
"""

from __future__ import annotations

import io
import logging
import os
import subprocess
import tarfile
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ExecResult:
    """Result from a single command executed inside a sandbox container."""

    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float = 0.0
    timed_out: bool = False


@dataclass
class SandboxConfig:
    """Isolation config for a SandboxContainer.

    Defaults are restrictive: no network, 2 GB RAM, 5 minute exec timeout.
    Override per use case (the analyzer sandbox, e.g., wants writable /scratch
    and an explicit working_dir of /workspace).
    """

    image: str
    network_mode: str = "none"  # "none" | "bridge" | "host"
    mounts: list[tuple[str, str, str]] = field(default_factory=list)
    # (host_path, container_path, "ro"|"rw")
    memory_mb: int = 2048
    cpu_shares: int = 1024
    cpus: float = 0.0  # 0 = no limit; otherwise docker --cpus
    timeout_seconds: int = 300  # default per-exec timeout
    env: dict[str, str] = field(default_factory=dict)
    working_dir: str = "/workspace"
    name: str | None = None
    auto_remove: bool = True
    pids_limit: int = 512
    security_opt: list[str] = field(default_factory=list)
    cap_drop: list[str] = field(default_factory=lambda: ["ALL"])
    cap_add: list[str] = field(default_factory=lambda: ["SYS_PTRACE"])
    read_only_rootfs: bool = False
    runtime: str | None = None
    labels: dict[str, str] = field(default_factory=lambda: {"managed-by": "acuario"})


class SandboxContainer:
    """Lifecycle-managed Docker container for scanner agents.

    Usage:
        with SandboxContainer(config) as sb:
            sb.start()
            result = sb.exec(["ls", "-la"])
            sb.write_file("/scratch/poc.bin", b"\\x00\\x01\\x02")
            assert result.exit_code == 0

    The container is created on `start()` and removed on `stop()` /  __exit__.
    On any unexpected exception, cleanup() is called to prevent leaks.
    """

    def __init__(self, config: SandboxConfig):
        self.config = config
        self._client = None
        self._container = None
        self.scratch_host_dir: str | None = None
        self.variant: list[str] | None = None
        # optional PtraceBehaviorMonitor reference.  When set, every
        # exec() call wraps the command with strace and ingests the
        # resulting trace file so real syscalls (not just text-pattern
        # matches) get captured.  Set externally by AgenticExploiter
        # after the container is up.
        self.behavior_monitor: Any = None

    # --- Lifecycle ----------------------------------------------------------

    def _get_client(self):
        if self._client is None:
            import docker  # local import - keeps the module importable without docker

            self._client = docker.from_env()
        return self._client

    def start(self) -> str:
        """Create and start the container. Returns the container id."""
        client = self._get_client()

        # Translate mounts into the docker SDK format
        volumes = {}
        for host_path, container_path, mode in self.config.mounts:
            volumes[host_path] = {"bind": container_path, "mode": mode}

        # Build kwargs
        # No `tty: True` here. The container runs `sleep infinity`, which
        # doesn't need a PTY, and a TTY on the container can leak into
        # the exec stream format - when docker-py reads back exec output
        # with `demux=True`, the daemon's TTY path strips the 8-byte
        # multiplex header and docker-py's `demux_adaptor` blows up with
        # `ValueError: N is not a valid stream` (first byte of payload
        # read as stream_id). Keep TTY off and exec stays multiplexed.
        kwargs = {
            "image": self.config.image,
            "command": "sleep infinity",
            "detach": True,
            "network_mode": self.config.network_mode,
            "mem_limit": f"{self.config.memory_mb}m",
            "cpu_shares": self.config.cpu_shares,
            "volumes": volumes,
            "environment": self.config.env,
            "working_dir": self.config.working_dir,
        }
        kwargs["pids_limit"] = self.config.pids_limit
        if self.config.security_opt:
            kwargs["security_opt"] = self.config.security_opt
        if self.config.cap_drop:
            kwargs["cap_drop"] = self.config.cap_drop
        if self.config.cap_add:
            kwargs["cap_add"] = self.config.cap_add
        if self.config.read_only_rootfs:
            kwargs["read_only"] = True
        if self.config.runtime:
            kwargs["runtime"] = self.config.runtime
        if self.config.cpus > 0:
            kwargs["nano_cpus"] = int(self.config.cpus * 1e9)
        if self.config.name:
            kwargs["name"] = self.config.name
        if self.config.labels:
            kwargs["labels"] = self.config.labels
        # auto_remove conflicts with detached non-restart containers in some
        # docker versions; we'll handle removal manually in stop()

        try:
            self._container = client.containers.run(**kwargs)
        except Exception as exc:
            # graceful gVisor fallback. When `--gvisor` is set but the
            # `runsc` runtime isn't installed/registered on this host, Docker
            # rejects the run with an "unknown runtime" error. Rather than
            # hard-fail the whole audit, retry once with the default runtime
            # and warn - the container still has cap_drop=ALL + seccomp +
            # network isolation, just not gVisor's extra kernel boundary.
            if kwargs.get("runtime") and self._is_unknown_runtime_error(exc):
                logger.warning(
                    "[sandbox] runtime %r unavailable (%s); falling back to the "
                    "default Docker runtime. Install gVisor (runsc) to enable it.",
                    kwargs.get("runtime"),
                    str(exc)[:200],
                )
                kwargs.pop("runtime", None)
                self._container = client.containers.run(**kwargs)
            else:
                raise
        logger.debug("Sandbox container started: %s", self._container.short_id)

        from .registry import ContainerRegistry

        ContainerRegistry.get().register(self)

        return self._container.id

    @staticmethod
    def _is_unknown_runtime_error(exc: Exception) -> bool:
        """True when the error looks like Docker rejecting an unknown runtime
        (e.g. runsc not installed). Matched on message text since docker-py
        surfaces it as a generic APIError."""
        text = str(exc).lower()
        return (
            "unknown or invalid runtime" in text
            or "unknown runtime" in text
            or ("runtime" in text and "not found" in text)
            or ("runtime" in text and "no such" in text)
        )

    def exec(
        self,
        command: list[str] | str,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        workdir: str | None = None,
    ) -> ExecResult:
        """Run a command inside the container.

        Args:
            command: A list of argv strings (preferred) or a shell string.
                Lists are passed directly; strings are run via /bin/sh -c.
            timeout: Per-exec timeout in seconds. Falls back to config.
            env: Extra environment variables for this exec.
            workdir: Override the container working_dir for this exec only.

        Returns:
            ExecResult(exit_code, stdout, stderr, duration_seconds, timed_out).
        """
        if self._container is None:
            raise RuntimeError("SandboxContainer.exec called before start()")

        start_time = time.monotonic()
        effective_timeout = timeout or self.config.timeout_seconds

        # docker SDK exec_run does not enforce timeouts natively - we shell-wrap
        # the command in `timeout` if provided
        if isinstance(command, list):
            argv = command
        else:
            argv = ["/bin/sh", "-c", command]

        # when a PtraceBehaviorMonitor is attached, wrap the command
        # with ``strace -o /scratch/_ptrace_<n>.log -f -e trace=...`` so
        # real syscalls are captured.  The trace file is read back below
        # and fed to ``monitor.ingest_trace_text()``.
        #
        # strace is the INNERMOST wrapper and `timeout` (below) the outermost:
        # `strace -f` follows forked children and does not exit until they all
        # do, so a command that backgrounds a never-exiting server (e.g.
        # `node index.js &` while probing it) keeps strace alive indefinitely.
        # If strace were outside `timeout`, the deadline would fire on the inner
        # command but strace would keep waiting and the exec would hang until the
        # caller's session backstop (~1h). With `timeout` outermost it terminates
        # strace itself at the deadline (and --kill-after SIGKILLs it), so the
        # exec always returns within effective_timeout.
        trace_path: str | None = None
        if self.behavior_monitor is not None:
            try:
                argv, trace_path = self.behavior_monitor.wrap_argv(argv)
            except Exception:
                logger.debug("[ptrace] wrap_argv failed", exc_info=True)
                trace_path = None

        if effective_timeout > 0:
            # Outermost wrapper: coreutils `timeout` bounds the whole exec
            # (strace included). Ignored if `timeout` is unavailable.
            argv = ["timeout", "--kill-after=2", str(effective_timeout)] + argv

        merged_env = dict(self.config.env)
        if env:
            merged_env.update(env)

        # docker-py's demux_adaptor intermittently raises `ValueError: N
        # is not a valid stream` when the socket header read gets
        # corrupted mid-stream (see docker/docker-py#3160 - spontaneous
        # Unix socket hiccup, not a Docker wire-format issue). The
        # command already ran; only the response parser choked. Treat
        # it as a transient and retry once with the same params - the
        # community-reported pattern is that subsequent attempts
        # succeed.
        def _do_exec_run():
            return self._container.exec_run(
                argv,
                tty=False,
                demux=True,
                environment=merged_env,
                workdir=workdir or self.config.working_dir,
            )

        try:
            exec_result = _do_exec_run()
        except ValueError as demux_err:
            logger.debug("exec_run demux race (%s); retrying once", demux_err)
            try:
                exec_result = _do_exec_run()
            except Exception as e:
                logger.warning("Sandbox exec failed (retry)", exc_info=True)
                return ExecResult(
                    exit_code=-1,
                    stdout="",
                    stderr=str(e),
                    duration_seconds=time.monotonic() - start_time,
                    timed_out=False,
                )
        except Exception as e:
            logger.warning("Sandbox exec failed", exc_info=True)
            return ExecResult(
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_seconds=time.monotonic() - start_time,
                timed_out=False,
            )

        exit_code = exec_result.exit_code if exec_result.exit_code is not None else -1
        # `demux=True` returns (stdout_bytes, stderr_bytes); either may be None
        out_bytes, err_bytes = exec_result.output or (b"", b"")
        stdout = (out_bytes or b"").decode("utf-8", errors="replace")
        stderr = (err_bytes or b"").decode("utf-8", errors="replace")
        duration = time.monotonic() - start_time
        # `timeout` exits with 124 on timeout, 137 on SIGKILL
        timed_out = exit_code in (124, 137)

        # if we wrapped the command with strace, read the trace file
        # back and let the behavior monitor ingest the syscalls.  Uses a
        # raw exec_run (no instrumentation) so we don't recursively wrap
        # the cat command.  The trace file is removed after ingestion to
        # keep /scratch clean.
        if trace_path is not None and self.behavior_monitor is not None:
            try:
                cat_res = self._container.exec_run(
                    ["cat", trace_path],
                    tty=False,
                    demux=False,
                    environment={},
                )
                cat_exit = getattr(cat_res, "exit_code", None)
                cat_out = getattr(cat_res, "output", None)
                if cat_exit == 0 and cat_out:
                    text = (
                        cat_out.decode("utf-8", errors="replace")
                        if isinstance(cat_out, (bytes, bytearray))
                        else str(cat_out)
                    )
                    self.behavior_monitor.ingest_trace_text(text)
                # Best-effort cleanup so /scratch doesn't accumulate per
                # command across a long exploit-dev session.
                self._container.exec_run(
                    ["rm", "-f", trace_path],
                    tty=False,
                    demux=False,
                    environment={},
                )
            except Exception:
                logger.debug("[ptrace] trace ingest failed", exc_info=True)

        return ExecResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            timed_out=timed_out,
        )

    def write_file(self, container_path: str, content: bytes) -> None:
        """Write a file into the container at `container_path`.

        Accepts either an absolute path (e.g. ``/scratch/poc.bin``) or a
        path relative to the configured working directory (e.g.
        ``app2/backend/server.js`` is anchored under ``/workspace`` by
        default). The latter is what the analyzer LLM produces - it knows
        files by their repo-relative paths, not by absolute container paths.

        Implementation: tar the file in-memory and put_archive() it.
        Useful for dropping fuzz inputs / test cases that the analyzer
        generated, or for landing patches the analyzer wrote.
        """
        if self._container is None:
            raise RuntimeError("SandboxContainer.write_file called before start()")

        # Anchor relative paths under the container's working directory.
        # Without this, `put_archive("app2/backend", ...)` fails with
        # "could not find /app2/backend in container" because docker
        # resolves relative paths against the container root.
        if not os.path.isabs(container_path):
            container_path = os.path.join(self.config.working_dir or "/", container_path)

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name=os.path.basename(container_path))
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        buf.seek(0)
        target_dir = os.path.dirname(container_path) or "/"

        # `put_archive` requires the destination directory to exist. If the
        # analyzer is writing into a subdirectory the archive doesn't have
        # yet (e.g. a fresh `app2/backend/`), create it first.
        try:
            self._container.put_archive(target_dir, buf.read())
        except Exception:
            try:
                self._container.exec_run(
                    f"mkdir -p {target_dir}",
                    workdir=self.config.working_dir,
                )
                buf.seek(0)
                self._container.put_archive(target_dir, buf.read())
            except Exception:
                raise

    def read_file(self, container_path: str) -> bytes:
        """Read a file from the container as bytes.

        Accepts absolute paths (e.g. ``/etc/hosts``) or paths relative to
        the configured working directory. See ``write_file`` for the
        rationale on relative-path anchoring.

        Implementation: get_archive() returns a tar stream; we extract the
        single file from it.
        """
        if self._container is None:
            raise RuntimeError("SandboxContainer.read_file called before start()")

        if not os.path.isabs(container_path):
            container_path = os.path.join(self.config.working_dir or "/", container_path)

        stream, _stat = self._container.get_archive(container_path)
        buf = io.BytesIO(b"".join(stream))
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f is not None:
                        return f.read()
        return b""

    def copy_tree_into(
        self,
        host_path: str,
        container_path: str = "/workspace",
    ) -> None:
        """Copy a host directory tree into the container.

        Uses streaming tar via subprocess to avoid holding large repos in
        memory. The container must already be started.
        """
        if self._container is None:
            raise RuntimeError("SandboxContainer.copy_tree_into called before start()")

        start_time = time.monotonic()
        cid = self._container.id

        self.exec(["mkdir", "-p", container_path], timeout=10)

        tar_proc = subprocess.Popen(
            ["tar", "cf", "-", "-C", host_path, "."],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # `--no-same-owner` - the extract happens inside a container whose
        # caps are dropped (cap_drop=["ALL"], no CAP_CHOWN), so any attempt
        # to restore the host uid/gid from the archive fails with
        # "Cannot change ownership ... Operation not permitted" and aborts
        # the extract. Telling tar not to chown makes files owned by the
        # (root) process running the extract, which is what we want anyway.
        docker_proc = subprocess.Popen(
            [
                "docker",
                "exec",
                "-i",
                cid,
                "tar",
                "xf",
                "-",
                "--no-same-owner",
                "-C",
                container_path,
            ],
            stdin=tar_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        tar_proc.stdout.close()
        _, docker_stderr = docker_proc.communicate(timeout=600)
        tar_proc.wait(timeout=10)

        duration = time.monotonic() - start_time
        if docker_proc.returncode != 0:
            err = (docker_stderr or b"").decode("utf-8", errors="replace")
            logger.warning("copy_tree_into failed (rc=%d): %s", docker_proc.returncode, err[:500])
            raise RuntimeError(f"copy_tree_into failed: {err[:500]}")
        logger.debug(
            "copy_tree_into %s → %s completed in %.1fs",
            host_path,
            container_path,
            duration,
        )

    def stop(self) -> None:
        """Stop and remove the container. Idempotent."""
        if self._container is None:
            return

        from .registry import ContainerRegistry

        ContainerRegistry.get().unregister(self)

        try:
            self._container.stop(timeout=5)
        except Exception:
            logger.debug("Sandbox container stop failed", exc_info=True)
        try:
            self._container.remove(force=True)
        except Exception:
            logger.debug("Sandbox container remove failed", exc_info=True)

        # Verify the container is actually gone; kill if still running
        try:
            self._container.reload()
            # If reload succeeds the container is still around
            logger.warning(
                "Container %s still present after remove, killing",
                self._container.short_id,
            )
            try:
                self._container.kill()
            except Exception:
                logger.debug("Container kill after failed remove", exc_info=True)
        except Exception:
            # Expected: reload raises when the container no longer exists
            pass

        self._container = None

    # --- Context manager ----------------------------------------------------

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    # --- Properties ---------------------------------------------------------

    @property
    def container_id(self) -> str | None:
        return self._container.id if self._container else None

    @property
    def short_id(self) -> str | None:
        return self._container.short_id if self._container else None

    @property
    def is_running(self) -> bool:
        return self._container is not None

    @property
    def main_pid(self) -> int | None:
        """Host-side PID of the container's main process, or None when
        the container isn't running or the daemon doesn't expose it.

        Used by the ptrace behavior monitor (acuario/lab/sandbox/behavior.py)
        to attach strace to the running sandbox.
        """
        if self._container is None:
            return None
        try:
            self._container.reload()
            pid = self._container.attrs.get("State", {}).get("Pid", 0)
            return int(pid) if pid else None
        except Exception:
            logger.debug("main_pid: container.reload() failed", exc_info=True)
            return None

    def __del__(self) -> None:
        if self._container is not None:
            logger.warning(
                "SandboxContainer %s was not stopped before garbage collection",
                getattr(self._container, "short_id", "unknown"),
            )
            try:
                self.stop()
            except Exception:
                logger.debug("SandboxContainer __del__ cleanup failed", exc_info=True)
