"""Tests for acuario/ui/commands/inspect.py (Phase D)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from acuario.ui.commands.inspect import (
    AuditInspector,
    _build_fix_prompt,
    _safe_id,
    _severity_color,
    _severity_rank,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_FINDINGS = [
    {
        "id": "analyzer-aaaa0001",
        "severity": "critical",
        "cwe": "CWE-89",
        "file": "app/login.php",
        "line_number": 42,
        "description": "SQL injection via unsanitised $user_id",
        "verified": True,
        "evidence_level": "crash_reproduced",
        "code_snippet": "SELECT * FROM users WHERE id = $user_id",
        "cluster_id": "cluster-sql-001",
    },
    {
        "id": "analyzer-bbbb0002",
        "severity": "high",
        "cwe": "CWE-79",
        "file": "app/comments.php",
        "line_number": 17,
        "description": "XSS in comment rendering",
        "verified": False,
        "discovered_by": "critic",
        "evidence_level": "suspicion",
        "cluster_id": "cluster-xss-002",
    },
    {
        "id": "analyzer-cccc0003",
        "severity": "critical",
        "cwe": "CWE-89",
        "file": "app/search.php",
        "line_number": 8,
        "description": "SQL injection in search endpoint",
        "verified": True,
        "evidence_level": "static_corroboration",
        "cluster_id": "cluster-sql-001",  # same cluster as aaaa0001
    },
]


def _panel_body(p):
    """The renderable inside a rich Panel (and/or a width-capping Constrain), else
    the object itself - so a test can assert on LLM output whether it is printed
    bare, framed in a theme.panel, or width-capped."""
    from rich.constrain import Constrain
    from rich.panel import Panel

    if isinstance(p, Constrain):
        p = p.renderable
    return p.renderable if isinstance(p, Panel) else p


def _make_session(
    tmp_path: Path,
    findings=None,
    refuted=None,
    manifest=None,
    skeptic_log=None,
    orchestrator_log=None,
):
    """Create a fake session directory with JSON artifacts."""
    session_dir = tmp_path / "audit-test-0001"
    session_dir.mkdir()

    findings_list = findings if findings is not None else SAMPLE_FINDINGS
    (session_dir / "findings.json").write_text(json.dumps(findings_list))

    if refuted is not None:
        lines = "\n".join(json.dumps(r) for r in refuted)
        (session_dir / "skeptic_refuted.jsonl").write_text(lines)

    if skeptic_log is not None:
        lines = "\n".join(json.dumps(r) for r in skeptic_log)
        (session_dir / "skeptic_log.jsonl").write_text(lines)

    if orchestrator_log is not None:
        lines = "\n".join(json.dumps(r) for r in orchestrator_log)
        (session_dir / "orchestrator_log.jsonl").write_text(lines)

    if manifest is not None:
        (session_dir / "manifest.json").write_text(json.dumps(manifest))

    return session_dir


def _make_cli():
    cli = MagicMock()
    cli.console = MagicMock()
    cli.console.print = MagicMock()
    cli.console.width = 120  # an int, so width-capping (Constrain) math works
    return cli


def _rendered(insp, fn, *args) -> str:
    """Run an inspector command with a real themed console and return the plain
    text, so assertions can see content that renders inside a Constrain/Group."""
    import io
    import re as _re

    from acuario.ui import theme

    buf = io.StringIO()
    insp.cli.console = theme.build_console(file=buf, force_terminal=True, no_color=True, width=120)
    fn(*args)
    return _re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())


def _make_inspector(session_dir: Path):
    cli = _make_cli()
    inspector = AuditInspector(
        session_id="audit-test-0001",
        session_dir=session_dir,
        cli=cli,
    )
    inspector._load_artifacts()
    return inspector


# ---------------------------------------------------------------------------
# Tests: artifact loading
# ---------------------------------------------------------------------------


class TestArtifactLoading:
    def test_loads_findings_from_json(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        assert len(insp._findings) == 3

    def test_builds_findings_by_id_index(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        assert "analyzer-aaaa0001" in insp._findings_by_id
        assert "analyzer-bbbb0002" in insp._findings_by_id

    def test_loads_skeptic_refuted_jsonl(self, tmp_path):
        refuted = [
            {
                "id": "analyzer-aaaa0001",
                "refutation_reason": "False positive - input is sanitised at line 38",
                "code_reference": "app/login.php:38",
            }
        ]
        sd = _make_session(tmp_path, refuted=refuted)
        insp = _make_inspector(sd)
        assert len(insp._skeptic_refuted) == 1
        assert insp._skeptic_refuted[0]["id"] == "analyzer-aaaa0001"

    def test_identifies_critic_leads(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        # analyzer-bbbb0002 has discovered_by="critic"
        assert len(insp._critic_leads) == 1
        assert insp._critic_leads[0]["id"] == "analyzer-bbbb0002"

    def test_excludes_variant_loop_findings(self, tmp_path):
        # Regression (QA F1): findings.json carries variant_loop pattern-match
        # suspicions that historical_findings.db / `history` never persist, some
        # pointing at the scanner's own artifact files. The on-disk inspect path
        # must drop them so its count matches the canonical DB-backed set, while
        # leaving critic-lead detection intact.
        findings = SAMPLE_FINDINGS + [
            {
                "id": "variant-deadbeef",
                "severity": "info",
                "cwe": "",
                "file": "results/scanner/audit-test-0001/findings_pool.jsonl",
                "line_number": 6,
                "description": "Variant of analyzer-aaaa0001: No vulnerable pattern detected",
                "verified": False,
                "discovered_by": "variant_loop",
                "evidence_level": "suspicion",
            }
        ]
        sd = _make_session(tmp_path, findings=findings)
        insp = _make_inspector(sd)
        ids = {f.get("id") for f in insp._findings}
        assert "variant-deadbeef" not in ids
        assert len(insp._findings) == len(SAMPLE_FINDINGS)  # only the canonical set
        assert "variant-deadbeef" not in insp._findings_by_id
        # critic leads still detected (filter keys on variant_loop, not verified)
        assert [lead["id"] for lead in insp._critic_leads] == ["analyzer-bbbb0002"]

    def test_loads_orchestrator_plans_from_manifest(self, tmp_path):
        manifest = {
            "orchestrator_plans": [
                {
                    "files": ["app/login.php", "app/search.php"],
                    "hunt_focus": "SQL injection shared contract",
                    "rationale": "Both files share unsanitised DB query pattern",
                    "findings_from_plan": ["analyzer-cccc0003"],
                }
            ]
        }
        sd = _make_session(tmp_path, manifest=manifest)
        insp = _make_inspector(sd)
        assert len(insp._orchestrator_plans) == 1
        assert "SQL injection" in insp._orchestrator_plans[0]["hunt_focus"]

    def test_loads_skeptic_log_jsonl(self, tmp_path):
        skeptic_log = [
            {"finding_id": "analyzer-aaaa0001", "verdict": "accepted", "reasoning": "clear sink"}
        ]
        sd = _make_session(tmp_path, skeptic_log=skeptic_log)
        insp = _make_inspector(sd)
        assert insp._skeptic_log_by_id["analyzer-aaaa0001"]["verdict"] == "accepted"

    def test_loads_orchestrator_plans_from_log(self, tmp_path):
        orchestrator_log = [
            {
                "plans": [
                    {
                        "plan_id": "p1",
                        "files": ["a.py"],
                        "hunt_focus": "SQLi",
                        "rationale": "shared query pattern",
                    }
                ]
            }
        ]
        sd = _make_session(tmp_path, orchestrator_log=orchestrator_log)
        insp = _make_inspector(sd)
        assert len(insp._orchestrator_plans) == 1
        assert insp._orchestrator_plans[0]["hunt_focus"] == "SQLi"

    def test_fallback_to_findings_pool_jsonl(self, tmp_path):
        session_dir = tmp_path / "fallback-sess"
        session_dir.mkdir()
        # Write findings_pool.jsonl instead of findings.json
        lines = "\n".join(json.dumps(f) for f in SAMPLE_FINDINGS[:2])
        (session_dir / "findings_pool.jsonl").write_text(lines)

        insp = AuditInspector(
            session_id="fallback-sess",
            session_dir=session_dir,
            cli=_make_cli(),
        )
        insp._load_artifacts()
        assert len(insp._findings) == 2


# ---------------------------------------------------------------------------
# Tests: list command
# ---------------------------------------------------------------------------


class TestCmdList:
    def test_list_default_renders_table(self, tmp_path):
        from rich.table import Table

        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_list([])
        printed = [c.args[0] for c in insp.cli.console.print.call_args_list if c.args]
        assert any(isinstance(p, Table) for p in printed)

    def test_list_plain_prints_a_line_per_finding(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_list(["--plain"])
        assert insp.cli.console.print.call_count >= 3

    def test_list_ids_only(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_list(["--ids-only"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("analyzer-aaaa0001" in c for c in calls)

    def test_list_severity_filter(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_list(["--severity", "critical", "--plain"])
        # Should print 2 critical findings (aaaa0001, cccc0003) + no others
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        matching = [c for c in calls if "CRITICAL" in c]
        assert len(matching) == 2

    def test_list_no_match_prints_dim(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_list(["--severity", "info"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("No findings match" in c for c in calls)

    def test_list_marks_critic_leads(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_list(["--plain"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("critic" in c for c in calls)

    def test_list_unknown_severity_errors(self, tmp_path):
        # Regression (QA F17): an unknown --severity value must error, not silently
        # fold to "info" and return a plausible wrong list.
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        out = _rendered(insp, insp._cmd_list, ["--severity", "criticl"])
        assert "unknown severity" in out
        assert "criticl" in out

    def test_list_aliased_severity_still_works(self, tmp_path):
        # The validation must still accept documented aliases (e.g. "crit").
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        out = _rendered(insp, insp._cmd_list, ["--severity", "crit", "--plain"])
        assert "unknown severity" not in out
        assert "CRITICAL" in out

    def test_list_caps_table_and_hints_more(self, tmp_path):
        # Regression (QA F8): the framed table caps at 25 rows with a "+N more" hint;
        # --all shows everything; the full list stays selectable via _last_list.
        many = [dict(SAMPLE_FINDINGS[0], id=f"analyzer-{i:08d}") for i in range(40)]
        sd = _make_session(tmp_path, findings=many)
        insp = _make_inspector(sd)
        out = _rendered(insp, insp._cmd_list, [])
        assert "more" in out and "list --all" in out
        assert len(insp._last_list) == 40  # full list retained for show/next/prev
        out_all = _rendered(insp, insp._cmd_list, ["--all"])
        assert "more ·" not in out_all


# ---------------------------------------------------------------------------
# Tests: show command
# ---------------------------------------------------------------------------


class TestCmdShow:
    def test_show_existing_finding(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        out = _rendered(insp, insp._cmd_show, ["analyzer-aaaa0001"])
        assert "analyzer-aaaa0001" in out
        assert "SQL injection" in out

    def test_show_missing_finding_prints_error(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_show(["nonexistent-xyz"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("not found" in c.lower() or "Finding not found" in c for c in calls)

    def test_show_prefix_match(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        # "analyzer-aaaa" matches exactly one finding
        out = _rendered(insp, insp._cmd_show, ["analyzer-aaaa"])
        assert "SQL injection" in out

    def test_show_ambiguous_prefix(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        # "analyzer-" matches all 3 → should warn about ambiguity
        insp._cmd_show(["analyzer-"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("Ambiguous" in c for c in calls)

    def test_show_out_of_range_row_errors(self, tmp_path):
        # Regression (QA F15): a numeric but out-of-range row (0, negative, too big)
        # reports the valid range instead of loose id-substring matching.
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        for bad in ("0", "-1", "99"):
            out = _rendered(insp, insp._cmd_show, [bad])
            assert "out of range" in out
            assert "Ambiguous" not in out

    def test_show_renders_verified_as_glyph_and_hides_source(self, tmp_path):
        # Regression (QA F14): verified renders as a glyph (not "True") and the
        # internal discovered_by tag is not surfaced in the detail view.
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        out = _rendered(insp, insp._cmd_show, ["analyzer-aaaa0001"])  # verified=True
        assert "✓ yes" in out
        assert "discovered_by" not in out

    def test_show_no_args_prints_error(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_show([])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("required" in c.lower() for c in calls)


# ---------------------------------------------------------------------------
# Tests: skeptic command
# ---------------------------------------------------------------------------


class TestCmdSkeptic:
    def test_skeptic_accepted_when_not_in_refuted_list(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_skeptic(["analyzer-aaaa0001"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("accepted" in c.lower() or "✓" in c for c in calls)

    def test_skeptic_shows_refutation_when_in_refuted_list(self, tmp_path):
        refuted = [
            {
                "id": "analyzer-aaaa0001",
                "refutation_reason": "Input sanitised at line 38",
                "code_reference": "app/login.php:38",
            }
        ]
        sd = _make_session(tmp_path, refuted=refuted)
        insp = _make_inspector(sd)
        insp._cmd_skeptic(["analyzer-aaaa0001"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("refuted" in c.lower() for c in calls)
        assert any("line 38" in c for c in calls)

    def test_skeptic_shows_verdict_and_reasoning_from_log(self, tmp_path):
        # Real shape: verdict + reasoning come from skeptic_log.jsonl keyed by
        # finding_id. The id deliberately does NOT contain the verdict word, so
        # the assertion proves the verdict is rendered, not matched in the id.
        skeptic_log = [
            {
                "finding_id": "analyzer-aaaa0001",
                "verdict": "refuted",
                "reasoning": "Access is restricted to the uploads prefix.",
            }
        ]
        sd = _make_session(tmp_path, skeptic_log=skeptic_log)
        insp = _make_inspector(sd)
        insp._cmd_skeptic(["analyzer-aaaa0001"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("refuted" in c.lower() for c in calls)
        assert any("restricted to the uploads prefix" in c for c in calls)


# ---------------------------------------------------------------------------
# Tests: critic command
# ---------------------------------------------------------------------------


class TestCmdCritic:
    def test_critic_shows_leads(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        out = _rendered(insp, insp._cmd_critic)  # rendered as a framed table
        assert "bbbb0002" in out
        assert "Reflective critic leads" in out

    def test_critic_empty_session(self, tmp_path):
        findings = [
            {
                "id": "analyzer-no-critic",
                "severity": "high",
                "cwe": "CWE-22",
                "file": "a.php",
                "line_number": 1,
                "description": "No critic leads here",
            }
        ]
        sd = _make_session(tmp_path, findings=findings)
        insp = _make_inspector(sd)
        out = _rendered(insp, insp._cmd_critic)
        # Empty-state copy must not expose the internal discovered_by tag.
        assert "No reflective-critic leads" in out
        assert "discovered_by" not in out


# ---------------------------------------------------------------------------
# Tests: orchestrator command
# ---------------------------------------------------------------------------


class TestCmdOrchestrator:
    def test_orchestrator_shows_plans(self, tmp_path):
        manifest = {
            "orchestrator_plans": [
                {
                    "files": ["a.php", "b.php"],
                    "hunt_focus": "shared auth bypass",
                    "rationale": "Both files check the same session token",
                    "findings_from_plan": ["analyzer-aaaa0001"],
                }
            ]
        }
        sd = _make_session(tmp_path, manifest=manifest)
        insp = _make_inspector(sd)
        out = _rendered(insp, insp._cmd_orchestrator)  # rendered as a framed table
        assert "auth bypass" in out

    def test_orchestrator_no_plans(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_orchestrator()
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("No orchestrator plans" in c for c in calls)


# ---------------------------------------------------------------------------
# Tests: debate stub
# ---------------------------------------------------------------------------


class TestCmdDebate:
    def test_debate_replays_recorded_exchange(self, tmp_path):
        # O2: debate command reads debate_log.jsonl and replays the exchange.
        sd = _make_session(tmp_path)
        (sd / "debate_log.jsonl").write_text(
            json.dumps(
                {
                    "finding_id": "analyzer-aaaa0001",
                    "refutation": "the ORM parameterizes this",
                    "conceded": False,
                    "rebuttal": "raw f-string at line 42, no ORM on this path",
                    "final_verdict": "overturned",
                    "reasoning": "the analyst cited concrete code I missed",
                    "reinstated": True,
                }
            )
            + "\n"
        )
        insp = _make_inspector(sd)
        insp._cmd_debate(["analyzer-aaaa0001"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        blob = " ".join(calls)
        assert "Debate" in blob
        assert "rebuttal" in blob.lower()
        assert "reinstated" in blob.lower()

    def test_debate_no_record_message(self, tmp_path):
        sd = _make_session(tmp_path)  # no debate_log.jsonl
        insp = _make_inspector(sd)
        insp._cmd_debate(["analyzer-aaaa0001"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("No debate recorded" in c for c in calls)


# ---------------------------------------------------------------------------
# Tests: fix command (read-only)
# ---------------------------------------------------------------------------


class TestCmdFix:
    def test_fix_calls_llm_and_prints_diff(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)

        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.content = (
            "--- a/app/login.php\n+++ b/app/login.php\n- $user_id\n+ (int)$user_id"
        )

        with patch.object(insp, "_get_llm", return_value=mock_llm):
            with patch("asyncio.run", return_value=mock_response):
                insp._cmd_fix(["analyzer-aaaa0001"])

        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        # Must warn that this is read-only
        assert any("read-only" in c.lower() or "Note" in c for c in calls)

    def test_fix_never_writes_files(self, tmp_path):
        """Verify fix does not create or modify any files."""

        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)

        before = set(str(p) for p in tmp_path.rglob("*"))

        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "--- diff ---"
        with patch.object(insp, "_get_llm", return_value=mock_llm):
            with patch("asyncio.run", return_value=mock_response):
                insp._cmd_fix(["analyzer-aaaa0001"])

        after = set(str(p) for p in tmp_path.rglob("*"))
        # No new files should appear outside the session dir
        new_files = after - before
        assert new_files == set(), f"fix wrote unexpected files: {new_files}"

    def test_fix_no_llm_prints_error(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        with patch.object(insp, "_get_llm", return_value=None):
            insp._cmd_fix(["analyzer-aaaa0001"])
        # Should have printed the read-only note, then returned early (no LLM call)
        # The test just ensures no exception is raised.

    def test_fix_prompt_is_read_only(self):
        finding = SAMPLE_FINDINGS[0]
        prompt = _build_fix_prompt(finding, "SELECT * FROM users WHERE id=$x")
        assert (
            "read-only" in prompt.lower()
            or "read only" in prompt.lower()
            or "not applied" in prompt.lower()
        )


# ---------------------------------------------------------------------------
# Tests: exploit command
# ---------------------------------------------------------------------------


class TestCmdExploit:
    def test_exploit_shows_no_result_message(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_exploit(["analyzer-aaaa0001"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("No exploit result" in c or "exploit" in c.lower() for c in calls)

    def test_exploit_shows_inline_result(self, tmp_path):
        findings = [
            {
                "id": "analyzer-has-exploit",
                "severity": "critical",
                "cwe": "CWE-89",
                "file": "app.php",
                "line_number": 5,
                "description": "SQLi",
                "exploit_result": {
                    "success": True,
                    "impact": "info_disclosure",
                    "notes": "Dumped users table via UNION SELECT",
                },
            }
        ]
        sd = _make_session(tmp_path, findings=findings)
        insp = _make_inspector(sd)
        insp._cmd_exploit(["analyzer-has-exploit"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("SUCCESS" in c for c in calls)
        assert any("info_disclosure" in c for c in calls)


# ---------------------------------------------------------------------------
# Tests: related command
# ---------------------------------------------------------------------------


class TestCmdRelated:
    def test_related_finds_same_cluster(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        # analyzer-aaaa0001 and analyzer-cccc0003 share cluster-sql-001
        out = _rendered(insp, insp._cmd_related, ["analyzer-aaaa0001"])
        assert "cccc0003" in out  # the sibling is listed in the related table
        assert "Related to analyzer-aaaa0001" in out  # titled by the source id

    def test_related_no_siblings(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        # bbbb0002 has a unique cluster
        insp._cmd_related(["analyzer-bbbb0002"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("No related findings" in c for c in calls)

    def test_related_renders_bracketed_sibling_without_crash(self, tmp_path):
        """A sibling description with a `[/route]` must not crash the render.

        The MagicMock-console tests above never render, so they miss markup
        crashes; this one renders on a real themed console.
        """
        from io import StringIO

        from acuario.ui.theme import build_console

        insp = _make_inspector(_make_session(tmp_path))
        buf = StringIO()
        insp.cli.console = build_console(file=buf, force_terminal=True, no_color=True, width=100)
        main = {"id": "f-main", "cluster_id": "c1", "severity": "high", "file": "a.py", "cwe": "CWE-79"}
        sib = {
            "id": "f-sib",
            "cluster_id": "c1",
            "severity": "critical",
            "file": "b.py",
            "line_number": 3,
            "description": "sibling on [/admin] route",
            "cwe": "CWE-79",
        }
        insp._findings = [main, sib]
        insp._findings_by_id = {"f-main": main, "f-sib": sib}

        # Would raise rich.errors.MarkupError on the bracketed sibling before the fix.
        insp._cmd_related(["f-main"])

        out = buf.getvalue()
        assert "f-sib" in out
        assert "[/admin]" in out  # bracketed free text preserved verbatim


# ---------------------------------------------------------------------------
# Tests: utility helpers
# ---------------------------------------------------------------------------


class TestUtilities:
    def test_severity_rank_order(self):
        assert _severity_rank("critical") < _severity_rank("high")
        assert _severity_rank("high") < _severity_rank("medium")
        assert _severity_rank("medium") < _severity_rank("low")

    def test_severity_color_returns_string(self):
        assert isinstance(_severity_color("critical"), str)
        assert isinstance(_severity_color("unknown"), str)

    def test_safe_id_strips_special_chars(self):
        assert "/" not in _safe_id("analyzer/finding-123")
        assert " " not in _safe_id("some finding id")


# ---------------------------------------------------------------------------
# Tests: CLI registration
# ---------------------------------------------------------------------------


class TestCLIRegistration:
    def test_inspect_visible_in_help(self):
        """Smoke: add_parser registers the inspect subcommand."""
        import argparse

        from acuario.ui.commands.inspect import add_parser

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        add_parser(sub)
        ns = parser.parse_args(["inspect", "audit-abc123"])
        assert ns.session_id == "audit-abc123"

    def test_inspect_in_all_commands(self):
        from acuario.ui.commands import ALL_COMMANDS
        from acuario.ui.commands import inspect as inspect_mod

        assert inspect_mod in ALL_COMMANDS


# ---------------------------------------------------------------------------
# Tests: command dispatch
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_handler_table_covers_commands(self, tmp_path):
        insp = _make_inspector(_make_session(tmp_path))
        expected = {
            "help",
            "list",
            "show",
            "why",
            "skeptic",
            "critic",
            "orchestrator",
            "debate",
            "fix",
            "exploit",
            "related",
            "next",
            "prev",
            "n",
            "p",
            "triage",
            "top",
        }
        assert set(insp._handlers) == expected
        assert all(callable(h) for h in insp._handlers.values())

    def test_run_dispatches_to_handler(self, tmp_path):
        insp = _make_inspector(_make_session(tmp_path))
        called = MagicMock()
        insp._handlers["list"] = called
        inputs = iter(["list", "quit"])
        insp._read_line = lambda: next(inputs)
        insp.run()
        called.assert_called_once()

    def test_run_rejects_unknown_command(self, tmp_path):
        insp = _make_inspector(_make_session(tmp_path))
        inputs = iter(["bogusquux", "quit"])
        insp._read_line = lambda: next(inputs)
        insp.run()
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("unknown command" in c.lower() for c in calls)


# ---------------------------------------------------------------------------
# Tests: selection context (current finding, row-number, navigation)
# ---------------------------------------------------------------------------


class TestSelectionContext:
    def test_show_sets_current(self, tmp_path):
        insp = _make_inspector(_make_session(tmp_path))
        insp._cmd_show(["analyzer-aaaa0001"])
        assert insp._current is not None
        assert insp._current.get("id") == "analyzer-aaaa0001"

    def test_optional_id_acts_on_current(self, tmp_path):
        insp = _make_inspector(_make_session(tmp_path))
        insp._cmd_show(["analyzer-aaaa0001"])  # sets the current selection
        out = _rendered(insp, insp._cmd_show, [])  # no id -> acts on current
        assert "analyzer-aaaa0001" in out

    def test_show_no_args_without_selection_errors(self, tmp_path):
        insp = _make_inspector(_make_session(tmp_path))
        insp._cmd_show([])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("required" in c.lower() for c in calls)

    def test_select_by_row_number(self, tmp_path):
        insp = _make_inspector(_make_session(tmp_path))
        insp._cmd_list([])  # populates _last_list
        row2_id = insp._last_list[1].get("id")
        insp._cmd_show(["2"])
        assert insp._current.get("id") == row2_id

    def test_out_of_range_number_is_not_a_row(self, tmp_path):
        insp = _make_inspector(_make_session(tmp_path))
        insp._cmd_list([])
        # 999 is out of range, so it must not resolve to a row.
        assert insp._candidates("999") == []

    def test_next_prev_navigation(self, tmp_path):
        insp = _make_inspector(_make_session(tmp_path))
        insp._cmd_list([])
        insp._current = insp._last_list[0]
        insp._cmd_next([])
        assert insp._current.get("id") == insp._last_list[1].get("id")
        insp._cmd_prev([])
        assert insp._current.get("id") == insp._last_list[0].get("id")

    def test_prompt_reflects_selection(self, tmp_path):
        insp = _make_inspector(_make_session(tmp_path))
        assert insp._prompt_str().strip() == ">"
        insp._cmd_show(["analyzer-aaaa0001"])
        assert "analyzer-aaaa0001" in insp._prompt_str()

    def test_bare_token_shows_finding(self, tmp_path):
        insp = _make_inspector(_make_session(tmp_path))
        insp._cmd_list([])
        inputs = iter(["analyzer-aaaa0001", "quit"])
        insp._read_line = lambda: next(inputs)
        insp.run()
        assert insp._current is not None
        assert insp._current.get("id") == "analyzer-aaaa0001"


# ---------------------------------------------------------------------------
# Tests: LLM-output rendering (why / fix)
# ---------------------------------------------------------------------------


class TestRendering:
    def test_why_renders_markdown(self, tmp_path):
        from rich.markdown import Markdown

        insp = _make_inspector(_make_session(tmp_path))
        with (
            patch.object(insp, "_get_llm", return_value=MagicMock()),
            patch("asyncio.run", return_value="resp"),
            patch("acuario.ui.commands.inspect._extract_text", return_value="# Why\n\nBecause X."),
        ):
            insp._cmd_why(["analyzer-aaaa0001"])
        printed = [c.args[0] for c in insp.cli.console.print.call_args_list if c.args]
        # E27 frames the LLM output in a theme.panel; the Markdown is its body.
        assert any(isinstance(_panel_body(p), Markdown) for p in printed)

    def test_fix_renders_diff_as_syntax(self, tmp_path):
        from rich.syntax import Syntax

        insp = _make_inspector(_make_session(tmp_path))
        diff = "--- a/x\n+++ b/x\n-bad\n+good"
        with (
            patch.object(insp, "_get_llm", return_value=MagicMock()),
            patch("asyncio.run", return_value="resp"),
            patch("acuario.ui.commands.inspect._extract_text", return_value=diff),
        ):
            insp._cmd_fix(["analyzer-aaaa0001"])
        printed = [c.args[0] for c in insp.cli.console.print.call_args_list if c.args]
        # E27 frames the diff in a theme.panel; the Syntax is its body.
        assert any(isinstance(_panel_body(p), Syntax) for p in printed)

    def test_strip_code_fences(self):
        from acuario.ui.commands.inspect import _strip_code_fences

        assert _strip_code_fences("```diff\n-a\n+b\n```") == "-a\n+b"
        assert _strip_code_fences("-a\n+b") == "-a\n+b"


class TestOpenSession:
    """open_session() falls back to the findings DB when the results dir is gone,
    so a session listed in `acuario history` is always openable."""

    def test_db_fallback_loads_findings(self, monkeypatch, tmp_path):
        import acuario.ui.commands.inspect as I

        monkeypatch.setattr(I, "_resolve_results_dir", lambda d: str(tmp_path))  # dir won't exist
        db = [{"id": "f1", "severity": "high", "file": "a.py", "line_number": 1, "verified": True}]
        monkeypatch.setattr(I, "_load_findings_from_db", lambda sid: db)

        seen: dict = {}

        def _fake_run(self):
            self._load_artifacts()
            seen["db"] = self._db_findings
            seen["findings"] = list(self._findings)
            return "back"

        monkeypatch.setattr(I.AuditInspector, "run", _fake_run)
        assert I.open_session(MagicMock(), "audit-x", from_hub=True) == "back"
        assert seen["db"] == db and seen["findings"] == db  # loaded from the DB

    def test_no_dir_and_no_db_reports_back(self, monkeypatch, tmp_path):
        import acuario.ui.commands.inspect as I

        monkeypatch.setattr(I, "_resolve_results_dir", lambda d: str(tmp_path))
        monkeypatch.setattr(I, "_load_findings_from_db", lambda sid: None)
        assert I.open_session(MagicMock(), "gone", from_hub=True) == "back"

    def test_prefers_recorded_session_path_over_db(self, monkeypatch, tmp_path):
        import acuario.scanner.session_index as SI
        import acuario.ui.commands.inspect as I

        sdir = tmp_path / "audit-z"
        sdir.mkdir()
        (sdir / "findings.json").write_text('{"findings":[{"id":"f1","severity":"high"}]}')
        monkeypatch.setattr(SI, "lookup_session_path", lambda sid: sdir)

        captured: dict = {}

        def _fake_run(self):
            self._load_artifacts()
            captured["db"] = self._db_findings
            captured["n"] = len(self._findings)
            return "back"

        monkeypatch.setattr(I.AuditInspector, "run", _fake_run)
        I.open_session(MagicMock(), "audit-z", from_hub=True)  # results_dir=None -> index
        assert captured["db"] is None  # used the real dir, not the DB fallback
        assert captured["n"] == 1

    def test_row_number_resolves_before_any_listing(self):
        from pathlib import Path

        from acuario.ui.commands.inspect import AuditInspector

        db = [
            {"id": "f1", "severity": "high", "file": "a.py", "line_number": 1},
            {"id": "f2", "severity": "low", "file": "b.py", "line_number": 2},
        ]
        insp = AuditInspector("s", Path("/nonexistent"), MagicMock(), db_findings=db)
        insp._load_artifacts()
        # `show 2` must work the moment the session opens, before any list/triage.
        assert insp._candidates("2") == [db[1]]


# ---------------------------------------------------------------------------
# Tests: validation panel in show
# ---------------------------------------------------------------------------


class TestValidationPanel:
    def test_show_renders_validation(self, tmp_path):
        findings = [
            {
                "id": "analyzer-val0001",
                "severity": "critical",
                "description": "SQLi",
                "verifier_pro_argument": "User input flows to SQL",
                "verifier_counter_argument": "Behind auth",
                "verifier_tie_breaker": "Static inspection confirms interpolation",
                "extra": {
                    "validator_axes": {
                        "REAL": {
                            "passed": True,
                            "confidence": "high",
                            "rationale": "f-string into SQL",
                        }
                    }
                },
            }
        ]
        insp = _make_inspector(_make_session(tmp_path, findings=findings))
        out = _rendered(insp, insp._cmd_show, ["analyzer-val0001"])
        assert "validation" in out.lower()
        assert "User input flows to SQL" in out
        assert "REAL" in out and "f-string into SQL" in out

    def test_show_validation_graceful_when_unvalidated(self, tmp_path):
        findings = [
            {
                "id": "analyzer-unval01",
                "severity": "low",
                "description": "x",
                "evidence_level": "suspicion",
            }
        ]
        insp = _make_inspector(_make_session(tmp_path, findings=findings))
        out = _rendered(insp, insp._cmd_show, ["analyzer-unval01"])
        assert "not validated" in out.lower()
        assert "evidence=suspicion" in out

    def test_efield_reads_extra(self):
        from acuario.ui.commands.inspect import _efield

        f = {"a": 1, "extra": {"b": 2}}
        assert _efield(f, "a") == 1
        assert _efield(f, "b") == 2
        assert _efield(f, "missing", "def") == "def"


# ---------------------------------------------------------------------------
# Tests: triage rank
# ---------------------------------------------------------------------------


class TestTriage:
    def test_rank_score_orders_by_priority(self):
        from acuario.ui.commands.inspect import _rank_score

        high = {
            "severity": "critical",
            "verified": True,
            "evidence_level": "exploit_demonstrated",
            "confidence": "high",
            "extra": {"exploit_transcript_path": "x"},
        }
        low = {
            "severity": "low",
            "verified": False,
            "evidence_level": "suspicion",
            "confidence": "low",
        }
        assert _rank_score(high) > _rank_score(low)

    def test_triage_renders_table_and_sets_last_list(self, tmp_path):
        from rich.table import Table

        insp = _make_inspector(_make_session(tmp_path))
        insp._cmd_triage([])
        printed = [c.args[0] for c in insp.cli.console.print.call_args_list if c.args]
        assert any(isinstance(p, Table) for p in printed)
        assert insp._last_list  # ranked list is selectable by number

    def test_list_sort_rank_orders_by_score(self, tmp_path):
        from acuario.ui.commands.inspect import _rank_score

        insp = _make_inspector(_make_session(tmp_path))
        insp._cmd_list(["--sort", "rank", "--plain"])
        assert insp._last_list
        scores = [_rank_score(f) for f in insp._last_list]
        assert scores == sorted(scores, reverse=True)


class TestTruncateDesc:
    def test_truncate_desc_adds_ellipsis_on_word_boundary(self):
        # Regression (QA F9): long descriptions get a trailing ellipsis, broken on
        # a word boundary, instead of a silent mid-word slice.
        from acuario.ui.commands.inspect import _truncate_desc

        assert _truncate_desc("short enough", 60) == "short enough"
        long = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda"
        out = _truncate_desc(long, 30)
        assert out.endswith("…")
        assert len(out) <= 31
        assert not out[:-1].endswith(" ")  # no dangling space before the ellipsis
        # an unbroken token longer than the limit still gets cut + ellipsis
        assert _truncate_desc("x" * 100, 10) == "x" * 10 + "…"
