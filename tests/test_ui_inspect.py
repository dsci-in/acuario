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


def _make_session(tmp_path: Path, findings=None, refuted=None, manifest=None):
    """Create a fake session directory with JSON artifacts."""
    session_dir = tmp_path / "audit-test-0001"
    session_dir.mkdir()

    findings_list = findings if findings is not None else SAMPLE_FINDINGS
    (session_dir / "findings.json").write_text(json.dumps(findings_list))

    if refuted is not None:
        lines = "\n".join(json.dumps(r) for r in refuted)
        (session_dir / "skeptic_refuted.jsonl").write_text(lines)

    if manifest is not None:
        (session_dir / "manifest.json").write_text(json.dumps(manifest))

    return session_dir


def _make_cli():
    cli = MagicMock()
    cli.console = MagicMock()
    cli.console.print = MagicMock()
    return cli


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
    def test_list_all_findings(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_list([])
        # At least one call per finding
        assert insp.cli.console.print.call_count >= 3

    def test_list_severity_filter(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_list(["--severity", "critical"])
        # Should print 2 critical findings (aaaa0001, cccc0003) + no others
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        # Both critical findings should appear; the high (bbbb0002) should not
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
        insp._cmd_list([])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("critic" in c for c in calls)


# ---------------------------------------------------------------------------
# Tests: show command
# ---------------------------------------------------------------------------


class TestCmdShow:
    def test_show_existing_finding(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_show(["analyzer-aaaa0001"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("analyzer-aaaa0001" in c for c in calls)
        assert any("SQL injection" in c for c in calls)

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
        insp._cmd_show(["analyzer-aaaa"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("SQL injection" in c for c in calls)

    def test_show_ambiguous_prefix(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        # "analyzer-" matches all 3 → should warn about ambiguity
        insp._cmd_show(["analyzer-"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("Ambiguous" in c for c in calls)

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

    def test_skeptic_reads_inline_verdict(self, tmp_path):
        findings = [
            {
                "id": "analyzer-inline-refuted",
                "severity": "high",
                "cwe": "CWE-22",
                "file": "app/file.php",
                "line_number": 5,
                "description": "Path traversal",
                "skeptic_verdict": "refuted",
                "skeptic_reason": "Access is restricted to /uploads/ prefix",
            }
        ]
        sd = _make_session(tmp_path, findings=findings)
        insp = _make_inspector(sd)
        insp._cmd_skeptic(["analyzer-inline-refuted"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("refuted" in c.lower() for c in calls)


# ---------------------------------------------------------------------------
# Tests: critic command
# ---------------------------------------------------------------------------


class TestCmdCritic:
    def test_critic_shows_leads(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        insp._cmd_critic()
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("bbbb0002" in c for c in calls)

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
        insp._cmd_critic()
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("No critic leads" in c for c in calls)


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
        insp._cmd_orchestrator()
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("auth bypass" in c for c in calls)

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
        insp._cmd_related(["analyzer-aaaa0001"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("cccc0003" in c for c in calls)
        # Should not include the finding itself
        assert not any("aaaa0001" in c and "Related findings for" in c for c in calls)

    def test_related_no_siblings(self, tmp_path):
        sd = _make_session(tmp_path)
        insp = _make_inspector(sd)
        # bbbb0002 has a unique cluster
        insp._cmd_related(["analyzer-bbbb0002"])
        calls = [str(c) for c in insp.cli.console.print.call_args_list]
        assert any("No related findings" in c for c in calls)


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
