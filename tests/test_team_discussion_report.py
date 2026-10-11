"""Tests for the team discussion report (G3).

Verifies that:
 - The report writer degrades gracefully when lab logs are missing.
 - Each agent's reasoning lands in its own section when present.
 - The refuted-findings appendix populates from skeptic_log.jsonl.
 - The behavior-monitor section appears when behavior_events.jsonl exists.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acuario.scanner.team_discussion_report import write_team_discussion_report


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def _make_session(
    tmp_path: Path,
    *,
    findings: list[dict] | None = None,
    verified: list[dict] | None = None,
    skeptic_log: list[dict] | None = None,
    skeptic_refuted: list[dict] | None = None,
    critic_log: list[dict] | None = None,
    orchestrator_log: list[dict] | None = None,
    behavior_events: list[dict] | None = None,
    manifest: dict | None = None,
) -> Path:
    """Build a synthetic session directory."""
    sd = tmp_path / "session-X"
    sd.mkdir()
    (sd / "findings.json").write_text(
        json.dumps(
            {
                "session_id": "session-X",
                "repo_url": "demo",
                "findings": findings or [],
                "verified_findings": verified or [],
            }
        )
    )
    if manifest is not None:
        (sd / "manifest.json").write_text(json.dumps(manifest))
    if skeptic_log is not None:
        _write_jsonl(sd / "skeptic_log.jsonl", skeptic_log)
    if skeptic_refuted is not None:
        _write_jsonl(sd / "skeptic_refuted.jsonl", skeptic_refuted)
    if critic_log is not None:
        _write_jsonl(sd / "critic_log.jsonl", critic_log)
    if orchestrator_log is not None:
        _write_jsonl(sd / "orchestrator_log.jsonl", orchestrator_log)
    if behavior_events is not None:
        _write_jsonl(sd / "behavior_events.jsonl", behavior_events)
    return sd


# ---------------------------------------------------------------------------
# Basic / degraded-input cases
# ---------------------------------------------------------------------------


def test_missing_session_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        write_team_discussion_report(tmp_path / "no-such-session")


def test_empty_session_still_produces_report(tmp_path: Path) -> None:
    sd = _make_session(tmp_path)
    out = write_team_discussion_report(sd)
    assert out.is_file()
    text = out.read_text()
    assert "# Team Discussion Report" in text
    assert "Pipeline activity" in text
    assert "_No findings in this session._" in text


def test_session_without_lab_logs_degrades(tmp_path: Path) -> None:
    sd = _make_session(
        tmp_path,
        findings=[
            {
                "id": "analyzer-aaa",
                "file": "x.py",
                "line_number": 5,
                "cwe": "CWE-89",
                "severity": "critical",
                "description": "Demo finding",
                "verified": True,
            }
        ],
        verified=[
            {
                "id": "analyzer-aaa",
                "file": "x.py",
                "line_number": 5,
                "cwe": "CWE-89",
                "severity": "critical",
                "description": "Demo finding",
                "verified": True,
            }
        ],
    )
    out = write_team_discussion_report(sd)
    text = out.read_text()
    # Per-finding debate appears
    assert "analyzer-aaa" in text
    # Skeptic section notes the missing record
    assert "No skeptic record" in text
    # No orchestrator / refuted / behavior sections when logs absent
    # (these check for section headings; the pipeline activity table
    # always references all stages.)
    assert "## 2. Cross-file orchestrator plans" not in text
    assert "## 4. Refuted findings appendix" not in text
    assert "## 5. Behavior monitor (ptrace)" not in text


# ---------------------------------------------------------------------------
# Per-agent rendering
# ---------------------------------------------------------------------------


def test_skeptic_log_drives_per_finding_section(tmp_path: Path) -> None:
    sd = _make_session(
        tmp_path,
        findings=[
            {
                "id": "analyzer-1",
                "file": "a.py",
                "line_number": 13,
                "cwe": "CWE-352",
                "severity": "critical",
                "description": "CSRF",
                "verified": True,
                "evidence_level": "crash_reproduced",
            }
        ],
        verified=[
            {
                "id": "analyzer-1",
                "file": "a.py",
                "line_number": 13,
                "cwe": "CWE-352",
                "severity": "critical",
                "description": "CSRF",
                "verified": True,
                "evidence_level": "crash_reproduced",
            }
        ],
        skeptic_log=[
            {
                "ts": "2025-01-01T00:00:00Z",
                "finding_id": "analyzer-1",
                "file": "a.py",
                "line_number": 13,
                "verdict": "accepted",
                "reasoning": "Could not find a refutation under callers.",
                "cross_file_context_used": True,
                "llm_response_excerpt": '{"verdict":"accepted"}',
                "elapsed_seconds": 0.84,
            }
        ],
    )
    text = write_team_discussion_report(sd).read_text()
    assert "Skeptic" in text
    assert "✓ accepted" in text
    assert "Could not find a refutation under callers." in text
    assert "Cross-file context shown:** yes" in text


def test_refuted_appendix_from_skeptic_log(tmp_path: Path) -> None:
    sd = _make_session(
        tmp_path,
        findings=[
            {
                "id": "analyzer-bad",
                "file": "a.py",
                "line_number": 1,
                "cwe": "CWE-89",
                "severity": "high",
                "description": "Bogus finding",
                "verified": False,
            }
        ],
        skeptic_log=[
            {
                "ts": "2025-01-01T00:00:00Z",
                "finding_id": "analyzer-bad",
                "file": "a.py",
                "line_number": 1,
                "cwe": "CWE-89",
                "verdict": "refuted",
                "reasoning": "Sanitizer at line 5 prevents the sink from running.",
                "elapsed_seconds": 0.55,
            }
        ],
    )
    text = write_team_discussion_report(sd).read_text()
    assert "Refuted findings appendix" in text
    assert "analyzer-bad" in text
    assert "Sanitizer at line 5" in text


def test_skeptic_refuted_fallback_when_no_skeptic_log(tmp_path: Path) -> None:
    """Older sessions that only have skeptic_refuted.jsonl (pre-G1a) should
    still populate the refuted appendix."""
    sd = _make_session(
        tmp_path,
        findings=[
            {
                "id": "analyzer-old",
                "file": "y.py",
                "line_number": 9,
                "cwe": "CWE-79",
                "severity": "medium",
                "description": "Old finding",
                "verified": False,
            }
        ],
        skeptic_refuted=[
            {
                "finding_id": "analyzer-old",
                "file": "y.py",
                "line_number": 9,
                "cwe": "CWE-79",
                "skeptic_reasoning": "Output is HTML-escaped before render.",
            }
        ],
    )
    text = write_team_discussion_report(sd).read_text()
    assert "Refuted findings appendix" in text
    assert "analyzer-old" in text
    assert "Output is HTML-escaped" in text


def test_orchestrator_section_renders_plans(tmp_path: Path) -> None:
    sd = _make_session(
        tmp_path,
        findings=[
            {
                "id": "analyzer-x",
                "file": "auth.py",
                "line_number": 1,
                "cwe": "CWE-287",
                "severity": "high",
                "description": "Weak check",
                "verified": True,
            }
        ],
        verified=[
            {
                "id": "analyzer-x",
                "file": "auth.py",
                "line_number": 1,
                "cwe": "CWE-287",
                "severity": "high",
                "description": "Weak check",
                "verified": True,
            }
        ],
        orchestrator_log=[
            {
                "ts": "2025-01-01T00:00:00Z",
                "plans": [
                    {
                        "plan_id": "plan-ab12cd34",
                        "files": ["auth.py", "session.py"],
                        "hunt_focus": "shared session-token contract",
                        "rationale": "Both files read SESSION_TOKEN without revalidating.",
                    }
                ],
                "plans_count": 1,
                "llm_response_excerpt": "[{...orchestrator full thought...}]",
                "elapsed_seconds": 2.0,
            }
        ],
    )
    text = write_team_discussion_report(sd).read_text()
    assert "Cross-file orchestrator plans" in text
    assert "plan-ab12cd34" in text
    assert "shared session-token contract" in text
    assert "Both files read SESSION_TOKEN" in text
    assert "...orchestrator full thought..." in text


def test_orchestrator_plan_findings_resolved_via_extra_nesting(
    tmp_path: Path,
) -> None:
    # L8: when findings get JSON-serialized (or are constructed via the
    # Finding dataclass), non-schema fields like ``subsystem_plan_id``
    # land under ``extra:`` rather than at the top level.  The pre-L8
    # reader at team_discussion_report.py:434 only checked the top level
    # and silently rendered "no findings surfaced" for every orchestrator
    # plan even when subsystem hunts had produced findings.
    sd = _make_session(
        tmp_path,
        findings=[
            # The shape we ACTUALLY get when findings.json is reloaded:
            # subsystem_plan_id under `extra:` because Finding stuffs
            # non-schema fields there.
            {
                "id": "analyzer-c47f3603",
                "file": "auth.js",
                "line_number": 10,
                "cwe": "CWE-345",
                "severity": "critical",
                "description": "JWT decode-without-verify",
                "verified": True,
                "discovered_by": "analyzer:subsystem",
                "extra": {
                    "subsystem_source": "orchestrator",
                    "subsystem_plan_id": "plan-4c71a574",
                    "subsystem_name": "Forged JWT exploitation chain",
                },
            },
        ],
        verified=[
            {
                "id": "analyzer-c47f3603",
                "file": "auth.js",
                "line_number": 10,
                "cwe": "CWE-345",
                "severity": "critical",
                "description": "JWT decode-without-verify",
                "verified": True,
                "discovered_by": "analyzer:subsystem",
                "extra": {
                    "subsystem_source": "orchestrator",
                    "subsystem_plan_id": "plan-4c71a574",
                    "subsystem_name": "Forged JWT exploitation chain",
                },
            },
        ],
        orchestrator_log=[
            {
                "ts": "2025-01-01T00:00:00Z",
                "plans": [
                    {
                        "plan_id": "plan-4c71a574",
                        "files": ["auth.js"],
                        "hunt_focus": "JWT signature bypass",
                        "rationale": "Cross-file JWT chain.",
                    }
                ],
                "plans_count": 1,
            }
        ],
    )
    text = write_team_discussion_report(sd).read_text()
    # Pre-L8 the section would have read "_No findings surfaced..." because
    # the lookup missed the nested location.  Post-fix the finding should
    # land in the plan's "Findings surfaced from this plan" block.
    assert "Findings surfaced from this plan" in text, (
        "L8 regression: orchestrator plan with valid subsystem_plan_id "
        "still rendered as 'no findings surfaced'"
    )
    assert "analyzer-c47f3603" in text
    assert "_No findings surfaced" not in text.split("plan-4c71a574")[1].split("###")[0], (
        "L8 regression: the per-plan section for plan-4c71a574 should "
        "list its findings, not the no-findings stub"
    )


def test_critic_origin_section_when_finding_discovered_by_critic(tmp_path: Path) -> None:
    sd = _make_session(
        tmp_path,
        findings=[
            {
                "id": "f-critic1",
                "file": "z.py",
                "line_number": 10,
                "cwe": "CWE-200",
                "severity": "medium",
                "description": "Info disclosure via debug log",
                "verified": True,
                "discovered_by": "critic",
                "evidence_level": "suspicion",
            }
        ],
        verified=[
            {
                "id": "f-critic1",
                "file": "z.py",
                "line_number": 10,
                "cwe": "CWE-200",
                "severity": "medium",
                "description": "Info disclosure via debug log",
                "verified": True,
                "discovered_by": "critic",
                "evidence_level": "suspicion",
            }
        ],
        critic_log=[
            {
                "ts": "2025-01-01T00:00:00Z",
                "file_path": "z.py",
                "existing_findings_count": 3,
                "trajectory_summary_excerpt": "Analyzer focused on input handling…",
                "cross_file_context_used": True,
                "prompt_excerpt": "## Analyzed file\nz.py …",
                "llm_response_excerpt": '[{"file":"z.py","cwe":"CWE-200",...}]',
                "leads": [
                    {
                        "file": "z.py",
                        "line_number": 10,
                        "cwe": "CWE-200",
                        "finding_type": "info_disclosure",
                        "description": "logger.debug(password)",
                        "confidence": "low",
                    }
                ],
                "leads_count": 1,
                "elapsed_seconds": 1.1,
            }
        ],
    )
    text = write_team_discussion_report(sd).read_text()
    assert "Critic (origin)" in text
    assert "z.py" in text
    # Analyzer-engaged section should note the critic origin
    assert "originated from the reflective critic" in text


def test_behavior_section_appears_when_events_present(tmp_path: Path) -> None:
    sd = _make_session(
        tmp_path,
        behavior_events=[
            {
                "timestamp": "12:00:00.001",
                "syscall": "openat",
                "severity": "warning",
                "path": "/etc/passwd",
            },
            {
                "timestamp": "12:00:00.002",
                "syscall": "execve",
                "severity": "warning",
                "path": "/bin/sh",
            },
            {"timestamp": "12:00:00.003", "syscall": "mount", "severity": "critical", "path": "/"},
        ],
    )
    text = write_team_discussion_report(sd).read_text()
    assert "Behavior monitor (ptrace)" in text
    assert "openat" in text and "execve" in text and "mount" in text
    assert "critical" in text and "warning" in text
    # B3: events render as a collapsible fenced code block, NOT a Markdown table
    # (a large ptrace capture as a table hangs the viewer).
    assert "<details><summary>All 3 syscall events" in text
    assert "```text" in text
    assert "| ts | syscall | severity | path/argument |" not in text


def test_findings_sorted_verified_first_then_severity(tmp_path: Path) -> None:
    sd = _make_session(
        tmp_path,
        findings=[
            {
                "id": "f-low",
                "file": "a.py",
                "line_number": 1,
                "cwe": "CWE-X",
                "severity": "low",
                "description": "Low",
                "verified": True,
            },
            {
                "id": "f-crit-unverified",
                "file": "b.py",
                "line_number": 1,
                "cwe": "CWE-Y",
                "severity": "critical",
                "description": "Crit but rejected",
                "verified": False,
            },
            {
                "id": "f-high",
                "file": "c.py",
                "line_number": 1,
                "cwe": "CWE-Z",
                "severity": "high",
                "description": "High",
                "verified": True,
            },
        ],
        verified=[
            {
                "id": "f-low",
                "file": "a.py",
                "line_number": 1,
                "cwe": "CWE-X",
                "severity": "low",
                "description": "Low",
                "verified": True,
            },
            {
                "id": "f-high",
                "file": "c.py",
                "line_number": 1,
                "cwe": "CWE-Z",
                "severity": "high",
                "description": "High",
                "verified": True,
            },
        ],
    )
    text = write_team_discussion_report(sd).read_text()
    # Verified high should appear before verified low, both before unverified critical
    high_idx = text.index("f-high")
    low_idx = text.index("f-low")
    crit_unv_idx = text.index("f-crit-unverified")
    assert high_idx < low_idx < crit_unv_idx


def test_short_title_truncates_on_word_boundary():
    """F5: long titles are capped on a word boundary, never mid-word."""
    from acuario.scanner.team_discussion_report import _short_title

    text = (
        "serious cross site scripting vulnerability affecting the comment "
        "rendering pipeline across many components"
    )
    title = _short_title(text, max_len=40)
    assert title.endswith("…")
    body = title[:-1]  # strip the ellipsis
    src_words = set(text.split())
    for w in body.split():
        assert w in src_words  # every word is a COMPLETE source word


def test_short_title_short_text_returned_whole():
    from acuario.scanner.team_discussion_report import _short_title

    assert _short_title("short clean title") == "short clean title"


def test_short_title_single_long_word_still_capped():
    from acuario.scanner.team_discussion_report import _short_title

    title = _short_title("x" * 200, max_len=40)
    assert len(title) <= 41  # max_len + ellipsis
