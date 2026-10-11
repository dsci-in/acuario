"""Tests for acuario/lab/sandbox/behavior.py - PtraceBehaviorMonitor (Phase C2)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from acuario.lab.sandbox.behavior import (
    TRACKED_SYSCALLS,
    BehaviorEvent,
    PtraceBehaviorMonitor,
    _extract_first_quoted,
    read_behavior_events,
)

# ---------------------------------------------------------------------------
# Unit: _extract_first_quoted
# ---------------------------------------------------------------------------


class TestExtractFirstQuoted:
    def test_extracts_simple_path(self):
        assert _extract_first_quoted('"/etc/passwd", O_RDONLY') == "/etc/passwd"

    def test_extracts_first_of_multiple(self):
        assert _extract_first_quoted('"a.txt", "b.txt"') == "a.txt"

    def test_empty_string_when_no_quotes(self):
        assert _extract_first_quoted("AT_FDCWD, 3, 0") == ""

    def test_unclosed_quote(self):
        result = _extract_first_quoted('"unclosed')
        assert "unclosed" in result


# ---------------------------------------------------------------------------
# Unit: syscall filtering - ptrace monitor catches /etc/passwd open
# ---------------------------------------------------------------------------


class TestParseLine:
    def _monitor(self, tmp_path):
        return PtraceBehaviorMonitor(
            session_id="test-sess",
            output_path=tmp_path,
            enabled=True,
        )

    def test_openat_etc_passwd_classified_warning(self, tmp_path):
        mon = self._monitor(tmp_path)
        raw = '12345 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
        event = mon._parse_line(raw)
        assert event is not None
        assert event.syscall == "openat"
        assert event.path == "/etc/passwd"
        assert event.severity == "warning"

    def test_openat_proc_self_classified_warning(self, tmp_path):
        mon = self._monitor(tmp_path)
        raw = '99 openat(AT_FDCWD, "/proc/self/mem", O_RDONLY) = 5'
        event = mon._parse_line(raw)
        assert event is not None
        assert event.path == "/proc/self/mem"
        assert event.severity == "warning"

    def test_execve_classified_warning(self, tmp_path):
        mon = self._monitor(tmp_path)
        raw = '42 execve("/bin/sh", ["sh", "-c", "id"], NULL) = 0'
        event = mon._parse_line(raw)
        assert event is not None
        assert event.syscall == "execve"
        assert event.severity == "warning"

    def test_mount_classified_critical(self, tmp_path):
        mon = self._monitor(tmp_path)
        raw = '7 mount("overlay", "/merged", "overlay", 0, NULL) = 0'
        event = mon._parse_line(raw)
        assert event is not None
        assert event.syscall == "mount"
        assert event.severity == "critical"

    def test_connect_classified_warning(self, tmp_path):
        mon = self._monitor(tmp_path)
        raw = '55 connect(4, {sa_family=AF_INET, sin_addr="1.2.3.4"}, 16) = 0'
        event = mon._parse_line(raw)
        assert event is not None
        assert event.syscall == "connect"
        assert event.severity == "warning"

    def test_untracked_syscall_returns_none(self, tmp_path):
        mon = self._monitor(tmp_path)
        raw = '88 read(3, "hello", 5) = 5'
        event = mon._parse_line(raw)
        assert event is None

    def test_garbage_line_returns_none(self, tmp_path):
        mon = self._monitor(tmp_path)
        assert mon._parse_line("") is None
        assert mon._parse_line("not a syscall line") is None
        assert mon._parse_line("--- SIGTERM {si_signo=SIGTERM} ---") is None


# ---------------------------------------------------------------------------
# Unit: regex fallback detects /etc/passwd access where ptrace would catch it
# ---------------------------------------------------------------------------


class TestRegexVsPtrace:
    """Demonstrates that the regex monitor would *miss* a bare /etc/passwd open
    (no write flag in the command text), while the ptrace monitor catches it via
    real syscall tracing."""

    def test_regex_monitor_misses_bare_read_of_etc_passwd(self):
        """BehaviorMonitor (regex) only matches '/etc/passwd.*w' (write access).
        A plain ``open("/etc/passwd", O_RDONLY)`` produces no regex match.
        """
        from acuario.scanner.behavior_monitor import BehaviorMonitor

        bm = BehaviorMonitor(session_id="test")
        # Simulated transcript: agent opened /etc/passwd read-only
        transcript = "result = open('/etc/passwd', 'r')\ndata = result.read()"
        alerts = bm.scan_text(transcript, finding_id="f1")
        # The regex pattern is r"/etc/passwd.*w" - read-only open does NOT match
        etc_alerts = [a for a in alerts if "/etc/passwd" in a.context]
        assert len(etc_alerts) == 0, "regex monitor should NOT catch a bare read"

    def test_ptrace_monitor_catches_bare_read_of_etc_passwd(self, tmp_path):
        """PtraceBehaviorMonitor parses the real strace line and emits a warning."""
        from acuario.lab.sandbox.behavior import PtraceBehaviorMonitor

        mon = PtraceBehaviorMonitor(
            session_id="test-ptrace",
            output_path=tmp_path,
            enabled=True,
        )
        # Strace line for a read-only open of /etc/passwd
        raw = '1234 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 4'
        event = mon._parse_line(raw)
        assert event is not None
        assert event.path == "/etc/passwd"
        assert event.severity == "warning"


# ---------------------------------------------------------------------------
# Unit: event writing to JSONL
# ---------------------------------------------------------------------------


class TestEventWriting:
    def test_write_event_creates_jsonl(self, tmp_path):
        mon = PtraceBehaviorMonitor(
            session_id="write-test",
            output_path=tmp_path,
            enabled=True,
        )
        mon._jsonl_file = (tmp_path / "behavior_events.jsonl").open("w")
        event = BehaviorEvent(
            timestamp="2026-01-01T00:00:00Z",
            session_id="write-test",
            syscall="openat",
            args='AT_FDCWD, "/etc/hosts", O_RDONLY',
            path="/etc/hosts",
            return_code="3",
            severity="warning",
            raw_line="1 openat(...) = 3",
        )
        mon._write_event(event)
        mon._jsonl_file.close()

        lines = (tmp_path / "behavior_events.jsonl").read_text().strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["syscall"] == "openat"
        assert record["path"] == "/etc/hosts"
        assert record["severity"] == "warning"

    def test_output_filename_override_for_analyzers(self, tmp_path):
        # N2: analyzer sessions write to a distinct file so they don't collide
        # with exploit-dev's behavior_events.jsonl.
        mon = PtraceBehaviorMonitor(
            session_id="a1",
            output_path=tmp_path,
            output_filename="analyzer_behavior_events.jsonl",
        )
        assert mon._jsonl_path == tmp_path / "analyzer_behavior_events.jsonl"


class TestAnalyzerPtraceWiring:
    """N2: HunterPool attaches the ptrace monitor to analyzer sandboxes."""

    def test_attach_sets_behavior_monitor_when_strace_available(self, tmp_path):
        from unittest.mock import patch

        from acuario.scanner.pool import HunterPool, HuntPoolConfig

        cfg = HuntPoolConfig(
            files=[],
            repo_path="/repo",
            enable_ptrace_for_analyzers=True,
            output_dir=str(tmp_path),
        )
        pool = HunterPool(cfg)
        sandbox = MagicMock()
        sandbox.behavior_monitor = None
        with patch.object(PtraceBehaviorMonitor, "start", return_value=True):
            monitor = pool._attach_analyzer_ptrace(sandbox)
        assert monitor is not None
        assert sandbox.behavior_monitor is monitor

    def test_attach_returns_none_when_strace_unavailable(self, tmp_path):
        from unittest.mock import patch

        from acuario.scanner.pool import HunterPool, HuntPoolConfig

        cfg = HuntPoolConfig(
            files=[],
            repo_path="/repo",
            enable_ptrace_for_analyzers=True,
            output_dir=str(tmp_path),
        )
        pool = HunterPool(cfg)
        sandbox = MagicMock()
        sandbox.behavior_monitor = None
        with patch.object(PtraceBehaviorMonitor, "start", return_value=False):
            monitor = pool._attach_analyzer_ptrace(sandbox)
        assert monitor is None
        # behavior_monitor must NOT be set when strace can't attach.
        assert sandbox.behavior_monitor is None


# ---------------------------------------------------------------------------
# Unit: read_behavior_events tool
# ---------------------------------------------------------------------------


class TestReadBehaviorEventsTool:
    def test_returns_empty_string_for_missing_file(self, tmp_path):
        result = read_behavior_events(str(tmp_path / "nonexistent.jsonl"))
        assert result == ""

    def test_returns_empty_string_for_empty_file(self, tmp_path):
        p = tmp_path / "behavior_events.jsonl"
        p.write_text("")
        assert read_behavior_events(str(p)) == ""

    def test_formats_events_by_severity(self, tmp_path):
        p = tmp_path / "behavior_events.jsonl"
        events = [
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "session_id": "s1",
                "syscall": "mount",
                "args": "",
                "path": "/merged",
                "return_code": "0",
                "severity": "critical",
                "raw_line": "...",
            },
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "session_id": "s1",
                "syscall": "openat",
                "args": "",
                "path": "/etc/passwd",
                "return_code": "3",
                "severity": "warning",
                "raw_line": "...",
            },
            {
                "timestamp": "2026-01-01T00:00:02Z",
                "session_id": "s1",
                "syscall": "open",
                "args": "",
                "path": "/tmp/safe",
                "return_code": "5",
                "severity": "info",
                "raw_line": "...",
            },
        ]
        p.write_text("\n".join(json.dumps(e) for e in events))

        result = read_behavior_events(str(p))
        assert "3 total" in result
        assert "1 critical" in result
        assert "1 warning" in result
        assert "1 info" in result
        # Critical and warning events appear in detail; info does not
        assert "mount" in result
        assert "/etc/passwd" in result


# ---------------------------------------------------------------------------
# Unit: disabled monitor is a no-op
# ---------------------------------------------------------------------------


class TestDisabledMonitor:
    def test_start_returns_false_when_disabled(self, tmp_path):
        mon = PtraceBehaviorMonitor(
            session_id="disabled",
            output_path=tmp_path,
            enabled=False,
        )
        assert mon.start(pid=1234) is False

    def test_stop_is_safe_when_disabled(self, tmp_path):
        mon = PtraceBehaviorMonitor(
            session_id="disabled",
            output_path=tmp_path,
            enabled=False,
        )
        mon.stop()  # should not raise


# ---------------------------------------------------------------------------
# Unit: TRACKED_SYSCALLS completeness
# ---------------------------------------------------------------------------


class TestTrackedSyscalls:
    def test_open_variants_tracked(self):
        assert "open" in TRACKED_SYSCALLS
        assert "openat" in TRACKED_SYSCALLS
        assert "openat2" in TRACKED_SYSCALLS

    def test_exec_tracked(self):
        assert "execve" in TRACKED_SYSCALLS

    def test_network_tracked(self):
        assert "connect" in TRACKED_SYSCALLS
        assert "socket" in TRACKED_SYSCALLS

    def test_mount_tracked(self):
        assert "mount" in TRACKED_SYSCALLS
        assert "pivot_root" in TRACKED_SYSCALLS


# ---------------------------------------------------------------------------
# J6: _build_attach_command prefers `docker exec` when a container is present
# ---------------------------------------------------------------------------


class TestBuildAttachCommandDockerExec:
    """The previous host-side `strace -p <host_pid>` could not see inside the
    container's PID namespace.  J6 switches to `docker exec <id> strace -f -p 1`
    so strace runs inside the namespace and can follow exec'd subprocesses.
    """

    def test_docker_exec_used_when_container_has_container_id(self, tmp_path):
        fake_container = MagicMock()
        fake_container.container_id = "abc123def"
        # raw `.id` attribute should NOT be preferred when container_id is set
        fake_container.id = "should-not-be-used"

        mon = PtraceBehaviorMonitor(
            session_id="s1",
            output_path=tmp_path,
            container=fake_container,
        )
        cmd = mon._build_attach_command(pid=99999)  # host pid is now ignored
        assert cmd is not None
        assert cmd[:3] == ["docker", "exec", "abc123def"]
        # strace is the first inside-container argument
        assert "strace" in cmd
        # Strace targets PID 1 inside the container (which always exists)
        assert "-p" in cmd and cmd[cmd.index("-p") + 1] == "1"
        # -f follow-forks must be present so analyzer subprocesses get traced
        assert "-f" in cmd

    def test_docker_exec_falls_back_to_id_attribute(self, tmp_path):
        """Raw docker-py Container objects expose `.id`, not `.container_id`."""
        fake_container = MagicMock(spec=[])  # no container_id attr
        fake_container.id = "raw-py-id"

        mon = PtraceBehaviorMonitor(
            session_id="s1",
            output_path=tmp_path,
            container=fake_container,
        )
        cmd = mon._build_attach_command(pid=None)
        assert cmd is not None
        assert cmd[:3] == ["docker", "exec", "raw-py-id"]

    def test_host_strace_fallback_when_no_container(self, tmp_path):
        """Without a container, fall back to host-side strace (legacy path)."""
        mon = PtraceBehaviorMonitor(
            session_id="s1",
            output_path=tmp_path,
            container=None,
        )
        cmd = mon._build_attach_command(pid=12345)
        assert cmd is not None
        # No docker exec prefix
        assert cmd[0] == "strace"
        # Target the host PID
        assert "-p" in cmd and cmd[cmd.index("-p") + 1] == "12345"

    def test_returns_none_when_no_container_and_no_pid(self, tmp_path):
        mon = PtraceBehaviorMonitor(
            session_id="s1",
            output_path=tmp_path,
            container=None,
        )
        assert mon._build_attach_command(pid=None) is None


# ---------------------------------------------------------------------------
# F5: per-command wrap_argv + ingest_trace_text
# ---------------------------------------------------------------------------


class TestWrapArgv:
    """The F5 redesign: every container exec gets wrapped with strace
    individually instead of attaching to a long-running PID 1.  That's
    the only approach that actually captures syscalls from docker-exec'd
    subprocesses (PID-1 attach can't see them - different process tree).
    """

    def test_wrap_inactive_when_jsonl_not_open(self, tmp_path):
        mon = PtraceBehaviorMonitor(
            session_id="s1",
            output_path=tmp_path,
            container=None,
        )
        # start() never called, so the monitor is inactive - wrap_argv
        # returns the original argv unchanged and no trace path.
        wrapped, trace_path = mon.wrap_argv(["echo", "hello"])
        assert wrapped == ["echo", "hello"]
        assert trace_path is None

    def test_wrap_when_active(self, tmp_path):
        mon = PtraceBehaviorMonitor(
            session_id="sess-xyz",
            output_path=tmp_path,
            container=None,
        )
        # Force-activate without calling start() (which would probe the
        # container we don't have here).
        mon._jsonl_file = (tmp_path / "behavior_events.jsonl").open("a", encoding="utf-8")
        try:
            wrapped, trace_path = mon.wrap_argv(["bash", "-c", "ls /tmp"])
            assert wrapped[0] == "strace"
            assert "-f" in wrapped
            assert "-e" in wrapped
            # Outputs to /scratch/ inside the container with a unique id
            assert trace_path is not None and trace_path.startswith("/scratch/_ptrace_sess-xyz_")
            assert trace_path in wrapped
            # The original argv is appended after the -- separator so
            # commands starting with a dash aren't mis-parsed as flags.
            assert "--" in wrapped
            sep_idx = wrapped.index("--")
            assert wrapped[sep_idx + 1 :] == ["bash", "-c", "ls /tmp"]
        finally:
            mon._jsonl_file.close()

    def test_each_wrap_gets_unique_trace_path(self, tmp_path):
        mon = PtraceBehaviorMonitor(
            session_id="s1",
            output_path=tmp_path,
            container=None,
        )
        mon._jsonl_file = (tmp_path / "behavior_events.jsonl").open("a", encoding="utf-8")
        try:
            _, p1 = mon.wrap_argv(["ls"])
            _, p2 = mon.wrap_argv(["ls"])
            _, p3 = mon.wrap_argv(["ls"])
            assert p1 != p2 != p3
            assert all("_1." in p1 or "_1.log" == p1[-5:] or p1.endswith("_1.log") for _ in [None])
        finally:
            mon._jsonl_file.close()


class TestIngestTraceText:
    """ingest_trace_text parses a strace output file (as written by
    ``strace -o``) and emits one BehaviorEvent per tracked syscall line.
    Untracked syscalls and noise lines are skipped silently.
    """

    def test_ingest_counts_tracked_syscalls(self, tmp_path):
        mon = PtraceBehaviorMonitor(
            session_id="s1",
            output_path=tmp_path,
            container=None,
        )
        mon._jsonl_file = (tmp_path / "behavior_events.jsonl").open("a", encoding="utf-8")
        try:
            trace = (
                # tracked: openat
                '12:00:00.001 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n'
                # tracked: execve
                '12:00:00.002 execve("/bin/sh", ["sh", "-c", "id"], 0x7fff) = 0\n'
                # tracked: connect
                "12:00:00.003 connect(4, {sa_family=AF_INET, ...}, 16) = 0\n"
                # not tracked: write (we only watch open/exec/net/mount)
                '12:00:00.004 write(1, "hello", 5) = 5\n'
            )
            n = mon.ingest_trace_text(trace)
            assert n == 3  # three tracked syscalls
            assert len(mon._events) == 3
            syscalls = [e.syscall for e in mon._events]
            assert syscalls == ["openat", "execve", "connect"]
        finally:
            mon._jsonl_file.close()

    def test_ingest_empty_text_is_noop(self, tmp_path):
        mon = PtraceBehaviorMonitor(
            session_id="s1",
            output_path=tmp_path,
            container=None,
        )
        mon._jsonl_file = (tmp_path / "behavior_events.jsonl").open("a", encoding="utf-8")
        try:
            assert mon.ingest_trace_text("") == 0
            assert mon.ingest_trace_text(None) == 0  # type: ignore[arg-type]
        finally:
            mon._jsonl_file.close()

    def test_ingest_when_inactive_returns_zero(self, tmp_path):
        mon = PtraceBehaviorMonitor(
            session_id="s1",
            output_path=tmp_path,
            container=None,
        )
        # No start() - _jsonl_file is None - ingest must not raise.
        n = mon.ingest_trace_text('12:00:00.001 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n')
        assert n == 0


class TestSandboxContainerInstrumentation:
    """SandboxContainer.exec() should consult an attached behavior_monitor
    to wrap argv with strace, run the command, then feed the trace file
    contents back to the monitor.  Verified with a mocked docker-py
    container.
    """

    def test_sandbox_calls_wrap_argv_and_ingest_when_monitor_attached(self, tmp_path, monkeypatch):
        from unittest.mock import MagicMock

        from acuario.sandbox.container import SandboxConfig, SandboxContainer

        # Build a SandboxContainer with mocked docker-py internals.
        cfg = SandboxConfig(image="fake", working_dir="/workspace")
        sc = SandboxContainer(cfg)
        fake_docker_container = MagicMock()
        # exec_run returns an object with exit_code + output (demux=True
        # → output is (stdout_bytes, stderr_bytes)).
        wrapped_exec_result = MagicMock(
            exit_code=0,
            output=(b"hello\n", b""),
        )
        cat_exec_result = MagicMock(
            exit_code=0,
            output=b'12:00:00.001 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n',
        )
        # Return wrapped result first, then cat result, then rm result.
        fake_docker_container.exec_run.side_effect = [
            wrapped_exec_result,
            cat_exec_result,
            MagicMock(exit_code=0, output=b""),  # rm cleanup
        ]
        sc._container = fake_docker_container

        # Attach a mock behavior monitor
        mon = MagicMock()
        mon.wrap_argv.return_value = (
            ["strace", "-f", "-o", "/scratch/_ptrace_s1_1.log", "--", "echo", "hi"],
            "/scratch/_ptrace_s1_1.log",
        )
        sc.behavior_monitor = mon

        result = sc.exec(["echo", "hi"], timeout=0)
        assert result.exit_code == 0
        # wrap_argv was called once.  The argv passed in is *after* the
        # SandboxContainer's own timeout-prefix wrap (coreutils ``timeout``),
        # so the wrapped argv starts with "timeout" and the original
        # command lands at the tail.
        mon.wrap_argv.assert_called_once()
        passed_argv = mon.wrap_argv.call_args.args[0]
        assert "echo" in passed_argv and "hi" in passed_argv
        # ingest_trace_text was called with the cat output
        mon.ingest_trace_text.assert_called_once()
        ingested_text = mon.ingest_trace_text.call_args.args[0]
        assert "openat" in ingested_text
        # Three exec_run calls: wrapped command, cat, rm
        assert fake_docker_container.exec_run.call_count == 3

    def test_sandbox_does_not_wrap_when_no_monitor(self, tmp_path):
        """Without an attached behavior_monitor, exec runs the bare argv
        and does NOT do the trace-readback round-trip."""
        from unittest.mock import MagicMock

        from acuario.sandbox.container import SandboxConfig, SandboxContainer

        cfg = SandboxConfig(image="fake", working_dir="/workspace")
        sc = SandboxContainer(cfg)
        fake = MagicMock()
        fake.exec_run.return_value = MagicMock(exit_code=0, output=(b"", b""))
        sc._container = fake
        sc.behavior_monitor = None
        sc.exec(["echo", "hi"], timeout=0)
        # Only ONE exec_run - no cat, no rm
        assert fake.exec_run.call_count == 1


# ---------------------------------------------------------------------------
# E1/E4: classifier tuning - benign reads / routine execs -> info, staged
# execs and denied accesses escalate (ptrace S/N ~0.7%).
# ---------------------------------------------------------------------------


class TestBehaviorClassificationTuning:
    def _mon(self, tmp_path):
        return PtraceBehaviorMonitor(session_id="tune", output_path=tmp_path, enabled=True)

    def test_ld_so_cache_open_is_info(self, tmp_path):
        raw = '1 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3'
        assert self._mon(tmp_path)._parse_line(raw).severity == "info"

    def test_etc_hosts_open_is_info(self, tmp_path):
        raw = '1 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3'
        assert self._mon(tmp_path)._parse_line(raw).severity == "info"

    def test_etc_passwd_still_warning(self, tmp_path):
        # E1 must NOT demote genuine recon targets.
        raw = '1 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
        assert self._mon(tmp_path)._parse_line(raw).severity == "warning"

    def test_routine_exec_sleep_is_info(self, tmp_path):
        raw = '1 execve("/bin/sleep", ["sleep", "1"], NULL) = 0'
        assert self._mon(tmp_path)._parse_line(raw).severity == "info"

    def test_shell_exec_stays_warning(self, tmp_path):
        raw = '1 execve("/bin/bash", ["bash", "-c", "id"], NULL) = 0'
        assert self._mon(tmp_path)._parse_line(raw).severity == "warning"

    def test_staged_exec_scratch_is_critical(self, tmp_path):
        raw = '1 execve("/scratch/exploit", ["exploit"], NULL) = 0'
        assert self._mon(tmp_path)._parse_line(raw).severity == "critical"

    def test_staged_exec_tmp_is_critical(self, tmp_path):
        raw = '1 execve("/tmp/payload.elf", ["payload.elf"], NULL) = 0'
        assert self._mon(tmp_path)._parse_line(raw).severity == "critical"

    def test_denied_access_is_warning_even_on_benign_path(self, tmp_path):
        raw = '1 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = -1 EACCES (Permission denied)'
        assert self._mon(tmp_path)._parse_line(raw).severity == "warning"
