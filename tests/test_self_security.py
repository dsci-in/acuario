"""Tests for self-security requirements (spec 013)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from acuario.sandbox.container import SandboxConfig
from acuario.sandbox.seccomp_profiles import (
    HUNTER_SECCOMP,
    get_seccomp_profile,
    write_seccomp_profile,
)
from acuario.scanner.audit import SecurityAuditLog
from acuario.scanner.behavior_monitor import (
    FILE_WRITE_THRESHOLD,
    BehaviorMonitor,
)

# --- SandboxConfig hardening tests -------------------------------------------


class TestSandboxConfigHardening:
    def test_pids_limit_default(self):
        cfg = SandboxConfig(image="test")
        assert cfg.pids_limit == 512

    def test_cap_drop_default(self):
        cfg = SandboxConfig(image="test")
        assert cfg.cap_drop == ["ALL"]

    def test_cap_add_default(self):
        cfg = SandboxConfig(image="test")
        assert cfg.cap_add == ["SYS_PTRACE"]

    def test_gvisor_runtime_config(self):
        cfg = SandboxConfig(image="test", runtime="runsc")
        assert cfg.runtime == "runsc"

    def test_read_only_rootfs(self):
        cfg = SandboxConfig(image="test", read_only_rootfs=True)
        assert cfg.read_only_rootfs is True

    def test_security_opt_empty_by_default(self):
        cfg = SandboxConfig(image="test")
        assert cfg.security_opt == []


# --- Seccomp profile tests ---------------------------------------------------


class TestSeccompProfiles:
    def test_hunter_profile_blocks_mount(self):
        profile = get_seccomp_profile("analyzer")
        blocked = profile["syscalls"][0]["names"]
        assert "mount" in blocked

    def test_hunter_profile_blocks_kexec(self):
        profile = get_seccomp_profile("analyzer")
        blocked = profile["syscalls"][0]["names"]
        assert "kexec_load" in blocked

    def test_hunter_profile_blocks_unshare(self):
        profile = get_seccomp_profile("analyzer")
        blocked = profile["syscalls"][0]["names"]
        assert "unshare" in blocked

    def test_exploit_profile_allows_unshare(self):
        profile = get_seccomp_profile("exploit")
        blocked = profile["syscalls"][0]["names"]
        assert "unshare" not in blocked

    def test_exploit_profile_still_blocks_mount(self):
        profile = get_seccomp_profile("exploit")
        blocked = profile["syscalls"][0]["names"]
        assert "mount" in blocked

    def test_write_seccomp_profile(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "seccomp.json"
            result = write_seccomp_profile("analyzer", path)
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["defaultAction"] == "SCMP_ACT_ALLOW"
            assert result == str(path)

    def test_default_returns_hunter(self):
        assert get_seccomp_profile() == HUNTER_SECCOMP
        assert get_seccomp_profile("unknown_mode") == HUNTER_SECCOMP

    def test_default_hunter_allows_socket(self):
        # N5: the default analyzer profile must NOT block sockets - a deep
        # analyzer may run a loopback server to confirm a bug.
        blocked = get_seccomp_profile("analyzer")["syscalls"][0]["names"]
        assert "socket" not in blocked

    def test_strict_profile_blocks_network(self):
        # N5: opt-in strict profile adds networking syscalls to the denylist.
        blocked = get_seccomp_profile("analyzer-strict")["syscalls"][0]["names"]
        assert "socket" in blocked
        assert "connect" in blocked
        assert "bind" in blocked
        # ...while still blocking the base escape syscalls.
        assert "mount" in blocked
        assert "unshare" in blocked

    def test_exploit_profile_keeps_socket(self):
        # N5: the live-app harness probes over loopback, so exploit mode must
        # keep sockets even though it blocks escape syscalls.
        blocked = get_seccomp_profile("exploit")["syscalls"][0]["names"]
        assert "socket" not in blocked


# --- ArtifactStore tests -----------------------------------------------------


class TestBehaviorMonitor:
    def test_detect_network_access(self):
        mon = BehaviorMonitor(session_id="test-1")
        alerts = mon.scan_text("running curl http://evil.com", finding_id="f1")
        assert len(alerts) >= 1
        assert alerts[0].pattern == "network_access_attempt"

    def test_detect_mount_attempt(self):
        mon = BehaviorMonitor(session_id="test-2")
        alerts = mon.scan_text("mount -t proc proc /proc", finding_id="f1")
        assert len(alerts) >= 1
        assert alerts[0].pattern == "mount_attempt"

    def test_detect_docker_socket(self):
        mon = BehaviorMonitor(session_id="test-3")
        alerts = mon.scan_text("cat /var/run/docker.sock", finding_id="f1")
        assert len(alerts) >= 1
        assert alerts[0].pattern == "unexpected_fs_path"

    def test_detect_permission_escalation(self):
        mon = BehaviorMonitor(session_id="test-4")
        alerts = mon.scan_text("sudo -i", finding_id="f1")
        assert len(alerts) >= 1
        assert alerts[0].pattern == "permission_escalation"

    def test_no_false_positive_normal_commands(self):
        mon = BehaviorMonitor(session_id="test-5")
        alerts = mon.scan_text(
            "gcc -o test test.c -fsanitize=address && ./test < input.bin",
            finding_id="f1",
        )
        assert len(alerts) == 0

    def test_file_write_threshold(self):
        mon = BehaviorMonitor(session_id="test-6")
        for i in range(FILE_WRITE_THRESHOLD + 1):
            mon.record_file_write(f"/scratch/file_{i}")
        alerts = mon.check_thresholds()
        assert len(alerts) >= 1
        assert alerts[0].pattern == "excessive_file_writes"

    def test_file_write_threshold_is_one_shot(self):
        """Regression: repeat calls to check_thresholds() after the
        threshold fires used to keep appending new alerts on every
        call, producing unbounded alert spam in long-running sessions.
        The threshold must latch and only fire once per session."""
        mon = BehaviorMonitor(session_id="test-latch")
        for i in range(FILE_WRITE_THRESHOLD + 1):
            mon.record_file_write(f"/scratch/f_{i}")
        first = mon.check_thresholds()
        second = mon.check_thresholds()
        third = mon.check_thresholds()
        assert len(first) == 1
        assert second == []  # latched - no spam
        assert third == []
        # Still exactly one alert on the object, not N
        alerts = [a for a in mon.get_alerts() if a.pattern == "excessive_file_writes"]
        assert len(alerts) == 1

    def test_large_binary_detection(self):
        mon = BehaviorMonitor(session_id="test-7")
        mon.record_file_write("/scratch/huge.bin", size_bytes=100 * 1024 * 1024)
        alerts = mon.get_alerts()
        assert len(alerts) >= 1
        assert alerts[0].pattern == "large_binary_creation"

    def test_summary(self):
        mon = BehaviorMonitor(session_id="test-8")
        mon.scan_text("curl http://x", finding_id="f1")
        mon.scan_text("sudo -i", finding_id="f2")
        summary = mon.summary()
        assert "network_access_attempt" in summary
        assert "permission_escalation" in summary

    def test_severity_critical_for_mount(self):
        mon = BehaviorMonitor(session_id="test-9")
        alerts = mon.scan_text("nsenter --target 1 --mount", finding_id="f1")
        assert len(alerts) >= 1
        assert alerts[0].severity == "critical"


# --- SecurityAuditLog tests --------------------------------------------------


class TestSecurityAuditLog:
    def test_log_and_query(self):
        with tempfile.TemporaryDirectory() as td:
            log = SecurityAuditLog(log_path=Path(td) / "audit.jsonl")
            entry = log.log("store_artifact", "finding-001", operator="test-user")
            assert entry.action == "store_artifact"
            results = log.query()
            assert len(results) == 1
            assert results[0].target == "finding-001"

    def test_append_only(self):
        with tempfile.TemporaryDirectory() as td:
            log = SecurityAuditLog(log_path=Path(td) / "audit.jsonl")
            log.log("store_artifact", "f1")
            log.log("retrieve_artifact", "f2")
            log.log("export_exploit", "f3")
            results = log.query()
            assert len(results) == 3

    def test_query_filter_by_action(self):
        with tempfile.TemporaryDirectory() as td:
            log = SecurityAuditLog(log_path=Path(td) / "audit.jsonl")
            log.log("store_artifact", "f1")
            log.log("retrieve_artifact", "f2")
            log.log("store_artifact", "f3")
            results = log.query(action="store_artifact")
            assert len(results) == 2

    def test_query_filter_by_target(self):
        with tempfile.TemporaryDirectory() as td:
            log = SecurityAuditLog(log_path=Path(td) / "audit.jsonl")
            log.log("store_artifact", "f1")
            log.log("retrieve_artifact", "f1")
            log.log("store_artifact", "f2")
            results = log.query(target="f1")
            assert len(results) == 2


# --- Runner injection tests --------------------------------------------------
