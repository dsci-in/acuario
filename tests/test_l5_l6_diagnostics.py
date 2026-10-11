"""Phase L5 + L6 diagnostic logging guard tests.

The orchestrator-plan diagnostic (L5) lives inside ``ScanRunner.arun()`` and
the ptrace-monitor diagnostic (L6) lives inside ``AgenticExploiter.aattempt()``.
Both code paths require substantial mock setup to exercise end-to-end, so
instead of brittle integration tests we use guard tests that verify the
diagnostic log strings are present in source.

These tests are intentionally narrow: their job is to fail loudly if a
future refactor accidentally drops the diagnostic, so the symptoms that
motivated L5 + L6 (5 plans → 0 findings; empty behavior_events.jsonl)
don't silently return.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (REPO / rel).read_text()


# --- L5 -------------------------------------------------------------------


def test_l5_orchestrator_plan_resolution_log_present():
    # Per-plan resolution log: "plan X requested N, resolved M, focus=..."
    # makes it obvious from audit.log whether the orchestrator's file lists
    # match the codebase (Hypothesis 1) or get filtered to empty.
    src = _read("acuario/scanner/runner.py")
    assert "plan %s → SubsystemTarget" in src, (
        "L5 diagnostic 'plan ... → SubsystemTarget' removed from runner.py"
    )
    assert "requested %d files, resolved %d" in src, (
        "L5 resolution-count diagnostic removed from runner.py"
    )


def test_l5_empty_target_warning_present():
    # When the plan converts to an empty target, the runner warns - pre-L5
    # the empty target was silently dropped.
    src = _read("acuario/scanner/runner.py")
    assert "has no valid files after filter" in src, (
        "L5 empty-target warning removed from runner.py - orchestrator "
        "plans that fail to match the codebase will go silently dropped "
        "again"
    )


# --- L6 -------------------------------------------------------------------


def test_l6_ptrace_start_outcome_log_present():
    # The symptom (0-byte behavior_events.jsonl) has three
    # indistinguishable root causes; L6 logs the start() outcome plus the
    # branch-skipped case so audit.log shows which one fired.
    src = _read("acuario/scanner/exploit_dev.py")
    assert "ptrace_monitor.start() →" in src, (
        "L6 start() outcome log removed from exploit_dev.py - three failure "
        "modes (disabled / no output dir / strace missing) will again be "
        "indistinguishable in audit.log"
    )


def test_l6_ptrace_skipped_branch_log_present():
    # The "skipped: enable_ptrace_monitor=..., output_dir=..." line covers
    # the case where the entire ptrace block is bypassed.  Pre-L6 this case
    # produced absolute silence.
    src = _read("acuario/scanner/exploit_dev.py")
    assert "ptrace monitor skipped" in src, "L6 skipped-branch log removed from exploit_dev.py"
    assert "enable_ptrace_monitor=%s, output_dir=%s" in src, (
        "L6 skipped-branch log no longer reports both gating conditions"
    )


def test_l6_ptrace_fallback_log_preserved():
    # Pre-existing line - make sure my L6 edit didn't drop the fallback log
    # message that distinguishes the regex monitor's takeover.
    src = _read("acuario/scanner/exploit_dev.py")
    assert "ptrace unavailable, regex monitor" in src, (
        "Pre-L6 fallback log was removed; the regex-monitor handoff is now invisible in audit.log"
    )
