"""Phase H tests - report.md polish.

Covers the focused fixes (no GPU+electricity phrase, duration present) and
the format improvements (executive summary, LAB activity, orchestrator
plans subsection, severity table, team_discussion.md cross-link).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from acuario.scanner.reporter import write_scanner_report

_BASE_COST_SUMMARY_LOCAL: dict[str, Any] = {
    "input_tokens": 1_234_567,
    "output_tokens": 234_567,
    "total_cost_usd": 0.0,
    "reference_cost_opus_usd": 12.34,
    "reference_cost_gpt_usd": 5.67,
    "is_self_hosted": True,
    "endpoint_label": "qwen3.6-coder via openai_compat",
}


def _make_finding(**kw) -> dict:
    defaults = dict(
        id="analyzer-1",
        file="app/x.py",
        line_number=1,
        cwe="CWE-89",
        severity="critical",
        description="demo",
        evidence_level="static_corroboration",
        verified=True,
        discovered_by="analyzer",
        finding_type="sqli",
    )
    defaults.update(kw)
    return defaults


def _render(tmp_path: Path, **kwargs) -> str:
    """Render report.md with sensible defaults and return its contents."""
    findings = kwargs.pop("findings", [_make_finding()])
    paths = write_scanner_report(
        output_dir=str(tmp_path),
        session_id="test-session",
        repo_url=kwargs.pop("repo_url", "/demo"),
        findings=findings,
        verified_findings=kwargs.pop("verified_findings", findings),
        spent_per_tier=kwargs.pop("spent_per_tier", {"A": 0.0, "B": 0.0, "C": 0.0}),
        formats=["markdown"],
        cost_summary=kwargs.pop("cost_summary", _BASE_COST_SUMMARY_LOCAL),
        **kwargs,
    )
    return Path(paths["markdown"]).read_text()


# ---------------------------------------------------------------------------
# H1: phrase removal
# ---------------------------------------------------------------------------


def test_no_gpu_electricity_phrase_in_report(tmp_path: Path) -> None:
    text = _render(tmp_path)
    # The phrase that was unprofessional must be gone from report.md.
    assert "GPU + electricity" not in text
    assert "your GPU" not in text
    # "self-hosted" remains as the qualifier.
    assert "self-hosted" in text


# ---------------------------------------------------------------------------
# H2 + H3: duration plumbed through and surfaced in two places
# ---------------------------------------------------------------------------


def test_duration_line_present_and_formatted(tmp_path: Path) -> None:
    text = _render(tmp_path, duration_seconds=8 * 3600 + 33 * 60)
    # Executive Summary block has it...
    assert "**Total duration:** 8h 33m" in text
    # ...and so does the LLM Usage section (both points the user looks at).
    # Exactly two occurrences expected.
    assert text.count("**Total duration:** 8h 33m") == 2


def test_short_duration_formats_in_minutes(tmp_path: Path) -> None:
    text = _render(tmp_path, duration_seconds=125.0)
    assert "**Total duration:** 2m 5s" in text


def test_subminute_duration_formats_in_seconds(tmp_path: Path) -> None:
    text = _render(tmp_path, duration_seconds=42.7)
    assert "**Total duration:** 42.7s" in text


def test_missing_duration_omits_the_line(tmp_path: Path) -> None:
    text = _render(tmp_path, duration_seconds=None)
    assert "Total duration" not in text


# ---------------------------------------------------------------------------
# H3: executive summary block
# ---------------------------------------------------------------------------


def test_executive_summary_block_present(tmp_path: Path) -> None:
    text = _render(tmp_path)
    # Right under the H1 title
    h1_idx = text.index("# Acuario Audit Report")
    exec_idx = text.index("## Executive Summary")
    assert exec_idx > h1_idx
    # No other H2 between them
    between = text[h1_idx:exec_idx]
    assert "## " not in between.replace("## Executive Summary", "")


def test_executive_summary_shows_severity_breakdown(tmp_path: Path) -> None:
    # Distinct loci so the same-locus dedup does not merge them.
    findings = [
        _make_finding(id="f1", severity="critical", line_number=1),
        _make_finding(id="f2", severity="critical", line_number=2),
        _make_finding(id="f3", severity="high", line_number=3),
        _make_finding(id="f4", severity="low", line_number=4),
    ]
    text = _render(tmp_path, findings=findings, verified_findings=findings)
    # Severity shown on both bases (total / verified); here all are verified.
    assert "2 / 2 critical · 1 / 1 high · 0 / 0 medium · 1 / 1 low" in text


def test_executive_summary_team_discussion_pointer(tmp_path: Path) -> None:
    text = _render(tmp_path)
    assert "see `team_discussion.md`" in text


# ---------------------------------------------------------------------------
# H4: LAB Activity section
# ---------------------------------------------------------------------------


def test_lab_activity_section_appears_when_stats_non_zero(tmp_path: Path) -> None:
    lab_stats = {
        "skeptic_accepted": 37,
        "skeptic_refuted": 119,
        "critic_leads": 8,
        "critic_verified": 3,
        "orchestrator_plans": 4,
        "orchestrator_findings": 2,
        "snapshot_cycles": 18,
        "ptrace_events": 21,
    }
    text = _render(tmp_path, lab_stats=lab_stats)
    assert "## LAB Activity" in text
    assert "accepted 37" in text and "refuted 119" in text
    assert "8 low-confidence lead(s)" in text
    assert "4 plan(s)" in text
    assert "18 snapshot/rollback cycle(s)" in text
    assert "21 ptrace event(s)" in text


def test_lab_activity_section_hidden_when_all_zero(tmp_path: Path) -> None:
    text = _render(
        tmp_path,
        lab_stats={
            "skeptic_accepted": 0,
            "skeptic_refuted": 0,
            "critic_leads": 0,
            "critic_verified": 0,
            "orchestrator_plans": 0,
            "orchestrator_findings": 0,
            "snapshot_cycles": 0,
            "ptrace_events": 0,
        },
    )
    assert "## LAB Activity" not in text


def test_lab_activity_partial_stats_render_what_is_present(tmp_path: Path) -> None:
    # Only skeptic numbers - critic/orchestrator/sandbox lines must NOT appear.
    text = _render(
        tmp_path,
        lab_stats={
            "skeptic_accepted": 5,
            "skeptic_refuted": 1,
        },
    )
    assert "## LAB Activity" in text
    assert "accepted 5" in text
    assert "low-confidence lead" not in text
    assert "plan(s) emitted" not in text
    assert "snapshot/rollback" not in text


# ---------------------------------------------------------------------------
# H4: orchestrator plans subsection (reads orchestrator_log.jsonl)
# ---------------------------------------------------------------------------


def test_orchestrator_plans_section_reads_jsonl(tmp_path: Path) -> None:
    # Pre-create the session dir and the orchestrator log so the renderer
    # picks it up.
    session_dir = tmp_path / "test-session"
    session_dir.mkdir()
    plan_record = {
        "ts": "2025-01-01T00:00:00Z",
        "plans": [
            {
                "plan_id": "plan-abc12345",
                "files": ["app/auth.php", "app/session.php"],
                "hunt_focus": "shared session-token contract",
                "rationale": "Both read SESSION_TOKEN without re-validation.",
            },
            {
                "plan_id": "plan-def67890",
                "files": ["app/admin.php", "app/user.php"],
                "hunt_focus": "privilege escalation across admin/user boundary",
                "rationale": "admin.php trusts role= from user.py.",
            },
        ],
        "plans_count": 2,
    }
    (session_dir / "orchestrator_log.jsonl").write_text(
        json.dumps(plan_record) + "\n",
    )
    text = _render(tmp_path)
    assert "## Cross-file Orchestrator Plans" in text
    assert "plan-abc12345" in text and "plan-def67890" in text
    assert "shared session-token contract" in text
    assert "Both read SESSION_TOKEN" in text
    assert "`app/auth.php`" in text and "`app/session.php`" in text


def test_orchestrator_plans_section_omitted_when_jsonl_absent(tmp_path: Path) -> None:
    text = _render(tmp_path)
    assert "## Cross-file Orchestrator Plans" not in text


def test_orchestrator_plans_section_omitted_when_jsonl_empty(tmp_path: Path) -> None:
    session_dir = tmp_path / "test-session"
    session_dir.mkdir()
    (session_dir / "orchestrator_log.jsonl").write_text("")
    text = _render(tmp_path)
    assert "## Cross-file Orchestrator Plans" not in text


def test_orchestrator_plans_section_omitted_when_no_plans(tmp_path: Path) -> None:
    # An emission record with zero plans (e.g. orchestrator ran but the LLM
    # returned []).  The section must be omitted, not rendered with an
    # empty body.
    session_dir = tmp_path / "test-session"
    session_dir.mkdir()
    (session_dir / "orchestrator_log.jsonl").write_text(
        json.dumps({"plans": [], "plans_count": 0}) + "\n",
    )
    text = _render(tmp_path)
    assert "## Cross-file Orchestrator Plans" not in text


# ---------------------------------------------------------------------------
# H5: severity histogram as a Markdown table
# ---------------------------------------------------------------------------


def test_severity_histogram_renders_as_markdown_table(tmp_path: Path) -> None:
    # Distinct loci so the same-locus dedup does not merge them.
    findings = [
        _make_finding(id="f1", severity="critical", line_number=1),
        _make_finding(id="f2", severity="high", line_number=2),
        _make_finding(id="f3", severity="high", line_number=3),
        _make_finding(id="f4", severity="medium", line_number=4),
    ]
    text = _render(tmp_path, findings=findings, verified_findings=findings)
    # The new section header
    assert "## Severity Breakdown" in text
    # Markdown table header with Total + Verified columns
    assert "| Severity | Total | Verified |" in text
    assert "|---|---:|---:|" in text
    # Rows (all verified here, so total == verified)
    assert "| critical | 1 | 1 |" in text
    assert "| high | 2 | 2 |" in text
    # Total row
    assert "| **Total** | **4** | **4** |" in text
    # The old bullet-list header must be gone (replaced by the table)
    assert "## Severity Histogram" not in text


# ---------------------------------------------------------------------------
# H5: team_discussion.md cross-link in footer
# ---------------------------------------------------------------------------


def test_team_discussion_md_cross_link_present_when_file_exists(
    tmp_path: Path,
) -> None:
    # Pre-create the team_discussion.md sentinel so the renderer's
    # conditional triggers (this mirrors what runner._write_report does).
    session_dir = tmp_path / "test-session"
    session_dir.mkdir()
    (session_dir / "team_discussion.md").touch()
    text = _render(tmp_path)
    assert "[`team_discussion.md`](team_discussion.md)" in text
    # The link should be in the footer after a horizontal rule
    assert "---" in text


def test_team_discussion_md_cross_link_omitted_when_file_absent(
    tmp_path: Path,
) -> None:
    text = _render(tmp_path)
    # The Executive Summary mentions team_discussion.md as a forward pointer
    # (unconditionally), but the footer cross-link should only fire when
    # the file actually exists.  Strip the Exec Summary and check the rest.
    footer_region = text.split("## Findings", 1)[-1]
    assert "[`team_discussion.md`](team_discussion.md)" not in footer_region


# ---------------------------------------------------------------------------
# L4: Dedup Summary renamed to "Analyzer Pool Dedup (initial pass)"
# ---------------------------------------------------------------------------


def test_dedup_section_renamed_to_analyzer_pool_dedup(tmp_path: Path) -> None:
    # The pre-L4 heading was misleading because subsystem + variant
    # findings bypass the pool and aren't counted here.  After L4 the
    # heading is scoped honestly.
    text = _render(
        tmp_path,
        pool_stats={"total_findings": 51, "total_clusters": 51, "duplicates": 0},
    )
    assert "## Analyzer Pool Dedup (initial pass)" in text
    # Old heading is gone - readers won't expect it to match findings.json
    assert "## Dedup Summary" not in text


def test_dedup_section_includes_scoping_disclaimer(tmp_path: Path) -> None:
    text = _render(
        tmp_path,
        pool_stats={"total_findings": 51, "total_clusters": 51, "duplicates": 0},
    )
    # The disclaimer text makes the scope unambiguous so users don't have
    # to read the source to understand why these numbers can differ from
    # the Executive Summary total.
    assert "per-file analyzer pool" in text
    assert "subsystem" in text.lower()
    assert "variant" in text.lower()


def test_dedup_section_omitted_when_no_pool_stats(tmp_path: Path) -> None:
    text = _render(tmp_path)  # no pool_stats kwarg
    assert "## Analyzer Pool Dedup" not in text
    assert "## Dedup Summary" not in text  # also confirms the rename


def test_dedup_section_still_shows_underlying_counts(tmp_path: Path) -> None:
    text = _render(
        tmp_path,
        pool_stats={"total_findings": 51, "total_clusters": 51, "duplicates": 0},
    )
    # The rename is presentation-only; the underlying numbers must still
    # land in the section so the section keeps its diagnostic value.
    assert "**Total findings:** 51" in text
    assert "**Unique clusters:** 51" in text
    assert "**Duplicates removed:** 0" in text


# ---------------------------------------------------------------------------
# N3: sandbox behavior anomalies section
# ---------------------------------------------------------------------------


def _seed_behavior_events(tmp_path: Path, records: list[dict], fname: str) -> None:
    """Pre-create the session dir + a behavior-events JSONL the report reads."""
    session_dir = tmp_path / "test-session"
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / fname).write_text("\n".join(json.dumps(r) for r in records) + "\n")


def test_behavior_anomalies_section_lists_warning_and_critical(tmp_path: Path) -> None:
    _seed_behavior_events(
        tmp_path,
        [
            {"severity": "warning", "syscall": "openat", "path": "/etc/passwd"},
            {"severity": "critical", "syscall": "mount", "path": "/"},
            {"severity": "info", "syscall": "read", "path": "/workspace/a.c"},
        ],
        "analyzer_behavior_events.jsonl",
    )
    text = _render(tmp_path)
    assert "## Sandbox Behavior Anomalies" in text
    assert "/etc/passwd" in text
    assert "mount" in text
    # info-level events are NOT surfaced as anomalies
    assert "/workspace/a.c" not in text


def test_behavior_anomalies_section_omitted_when_no_events(tmp_path: Path) -> None:
    text = _render(tmp_path)  # no behavior JSONL seeded
    assert "## Sandbox Behavior Anomalies" not in text


def test_behavior_anomalies_section_omitted_when_only_info(tmp_path: Path) -> None:
    _seed_behavior_events(
        tmp_path,
        [{"severity": "info", "syscall": "read", "path": "/workspace/x.c"}],
        "behavior_events.jsonl",
    )
    text = _render(tmp_path)
    assert "## Sandbox Behavior Anomalies" not in text


def test_behavior_anomalies_groups_repeated_events(tmp_path: Path) -> None:
    _seed_behavior_events(
        tmp_path,
        [{"severity": "warning", "syscall": "openat", "path": "/etc/shadow"}] * 5,
        "analyzer_behavior_events.jsonl",
    )
    text = _render(tmp_path)
    # Five identical events collapse to one row with a count of 5.
    assert "/etc/shadow" in text
    assert "| 5 |" in text


# ---------------------------------------------------------------------------
# P4: cost-by-agent section
# ---------------------------------------------------------------------------


def test_cost_by_agent_section_renders(tmp_path: Path) -> None:
    cs = dict(_BASE_COST_SUMMARY_LOCAL)
    cs["by_agent"] = {
        "analyzer": {
            "input_tokens": 12000,
            "output_tokens": 3400,
            "cost_usd": 0.0,
            "ref_cost_usd": 0.51,
            "calls": 25,
        },
        "skeptic": {
            "input_tokens": 800,
            "output_tokens": 120,
            "cost_usd": 0.0,
            "ref_cost_usd": 0.02,
            "calls": 40,
        },
    }
    text = _render(tmp_path, cost_summary=cs)
    assert "### Cost by agent" in text
    assert "analyzer" in text and "skeptic" in text
    # Self-hosted → reference-cost column header.
    assert "Ref. cost" in text


def test_cost_by_agent_section_omitted_without_attribution(tmp_path: Path) -> None:
    text = _render(tmp_path)  # _BASE_COST_SUMMARY_LOCAL has no by_agent
    assert "### Cost by agent" not in text


# ---------------------------------------------------------------------------
# F1: canonical cost total  +  B1 belt: artifact-path findings dropped
# ---------------------------------------------------------------------------


def test_manifest_total_spend_includes_subsystem(tmp_path: Path) -> None:
    """F1: total_spent = tiers + subsystem (was tiers only, dropping subsystem)."""
    paths = write_scanner_report(
        output_dir=str(tmp_path),
        session_id="sess",
        repo_url="/demo",
        findings=[_make_finding()],
        verified_findings=[_make_finding()],
        spent_per_tier={"A": 10.0, "B": 5.0, "C": 1.0},
        subsystem_stats={"subsystems_hunted": 3, "subsystem_spent_usd": 4.0},
        formats=["json"],
    )
    manifest = json.loads(Path(paths["manifest"]).read_text())
    assert manifest["subsystem_spent"] == 4.0
    assert manifest["total_spent"] == 20.0  # 16 tiers + 4 subsystem


def test_manifest_total_spend_without_subsystem(tmp_path: Path) -> None:
    paths = write_scanner_report(
        output_dir=str(tmp_path),
        session_id="sess2",
        repo_url="/demo",
        findings=[_make_finding()],
        verified_findings=[_make_finding()],
        spent_per_tier={"A": 2.0, "B": 0.0, "C": 0.0},
        formats=["json"],
    )
    manifest = json.loads(Path(paths["manifest"]).read_text())
    assert manifest["subsystem_spent"] == 0.0
    assert manifest["total_spent"] == 2.0


def test_belt_drops_findings_under_output_dir(tmp_path: Path) -> None:
    """B1 belt: a finding whose path is under the scanner's output dir is dropped
    from the deliverable; a real target finding is kept."""
    artifact = _make_finding(
        id="artifact",
        file=str(tmp_path / "test-session" / "findings_pool.jsonl"),
        finding_type="info_leak",
    )
    real = _make_finding(id="real", file="app/x.py")
    paths = write_scanner_report(
        output_dir=str(tmp_path),
        session_id="test-session",
        repo_url="/demo",
        findings=[artifact, real],
        verified_findings=[artifact, real],
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
        formats=["json"],
    )
    data = json.loads(Path(paths["json"]).read_text())
    ids = {f.get("id") for f in data["findings"]}
    assert "real" in ids
    assert "artifact" not in ids
    manifest = json.loads(Path(paths["manifest"]).read_text())
    assert manifest["finding_count"] == 1
