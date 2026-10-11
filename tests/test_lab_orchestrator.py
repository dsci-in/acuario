"""Tests for the CrossFileOrchestrator lab agent (lab/B3)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from acuario.findings.types import Finding
from acuario.lab.agents.orchestrator import CrossFileOrchestrator, SubsystemPlan


def _make_finding(**kw) -> Finding:
    defaults = dict(
        id="f-1",
        file="src/auth.php",
        line_number=17,
        finding_type="sql_injection",
        cwe="CWE-89",
        severity="high",
        description="SQLi in login query",
        evidence_level="static_corroboration",
    )
    defaults.update(kw)
    return Finding(**defaults)


def _mock_llm(response_text: str) -> AsyncMock:
    mock = AsyncMock()
    resp = MagicMock()
    resp.first_text.return_value = response_text
    mock.achat.return_value = resp
    return mock


# --- SubsystemPlan parsing ----------------------------------------------------


class TestSubsystemPlanParsing:
    def test_parse_valid_plans(self):
        text = json.dumps(
            [
                {
                    "files": ["src/auth.php", "src/session.php"],
                    "hunt_focus": "Session fixation between auth and session modules",
                    "rationale": "auth.php sets tokens that session.php trusts without re-validation",
                }
            ]
        )
        plans = CrossFileOrchestrator._parse_plans(text)
        assert len(plans) == 1
        assert plans[0].files == ["src/auth.php", "src/session.php"]
        assert "fixation" in plans[0].hunt_focus
        assert plans[0].plan_id.startswith("plan-")

    def test_parse_empty_array(self):
        plans = CrossFileOrchestrator._parse_plans("[]")
        assert plans == []

    def test_parse_garbage_returns_empty(self):
        plans = CrossFileOrchestrator._parse_plans("this is not json")
        assert plans == []

    def test_parse_skips_single_file_plans(self):
        text = json.dumps(
            [
                {
                    "files": ["src/auth.php"],  # only one file - invalid
                    "hunt_focus": "Should be skipped",
                    "rationale": "single file",
                },
                {
                    "files": ["src/a.php", "src/b.php"],
                    "hunt_focus": "Valid cross-file plan",
                    "rationale": "shared state",
                },
            ]
        )
        plans = CrossFileOrchestrator._parse_plans(text)
        assert len(plans) == 1
        assert plans[0].hunt_focus == "Valid cross-file plan"

    def test_parse_caps_at_five_plans(self):
        items = [
            {
                "files": [f"src/a{i}.php", f"src/b{i}.php"],
                "hunt_focus": f"plan {i}",
                "rationale": "shared",
            }
            for i in range(10)
        ]
        plans = CrossFileOrchestrator._parse_plans(json.dumps(items))
        assert len(plans) == 5


# --- CrossFileOrchestrator.aplan ---------------------------------------------


class TestCrossFileOrchestratorPlan:
    @pytest.mark.asyncio
    async def test_no_llm_returns_empty(self):
        orch = CrossFileOrchestrator(llm=None)
        plans = await orch.aplan(findings=[_make_finding()])
        assert plans == []

    @pytest.mark.asyncio
    async def test_no_findings_returns_empty(self):
        llm = _mock_llm('[{"files": ["a.php", "b.php"], "hunt_focus": "x", "rationale": "y"}]')
        orch = CrossFileOrchestrator(llm=llm)
        plans = await orch.aplan(findings=[])
        assert plans == []

    @pytest.mark.asyncio
    async def test_llm_returns_plans(self):
        response = json.dumps(
            [
                {
                    "files": ["src/auth.php", "src/session.php"],
                    "hunt_focus": "Session fixation across auth boundary",
                    "rationale": "auth sets tokens without invalidating prior sessions",
                },
                {
                    "files": ["src/cart.php", "src/payment.php"],
                    "hunt_focus": "TOCTOU race in cart/payment flow",
                    "rationale": "cart state checked in cart.php but trusted in payment.php",
                },
            ]
        )
        llm = _mock_llm(response)
        orch = CrossFileOrchestrator(llm=llm)
        findings = [
            _make_finding(id="f1", file="src/auth.php"),
            _make_finding(id="f2", file="src/cart.php"),
        ]
        plans = await orch.aplan(findings=findings)
        assert len(plans) == 2
        assert plans[0].files == ["src/auth.php", "src/session.php"]
        assert "fixation" in plans[0].hunt_focus

    @pytest.mark.asyncio
    async def test_llm_error_returns_empty(self):
        llm = AsyncMock()
        llm.achat.side_effect = RuntimeError("timeout")
        orch = CrossFileOrchestrator(llm=llm)
        plans = await orch.aplan(findings=[_make_finding()])
        assert plans == []

    @pytest.mark.asyncio
    async def test_top_n_caps_output(self):
        many_plans = json.dumps(
            [
                {
                    "files": [f"src/a{i}.php", f"src/b{i}.php"],
                    "hunt_focus": f"focus {i}",
                    "rationale": "shared",
                }
                for i in range(10)
            ]
        )
        llm = _mock_llm(many_plans)
        orch = CrossFileOrchestrator(llm=llm, top_n=3)
        plans = await orch.aplan(findings=[_make_finding()])
        assert len(plans) <= 3

    @pytest.mark.asyncio
    async def test_summary_string(self):
        response = json.dumps(
            [
                {"files": ["a.php", "b.php"], "hunt_focus": "cross-auth", "rationale": "r"},
            ]
        )
        llm = _mock_llm(response)
        orch = CrossFileOrchestrator(llm=llm)
        await orch.aplan(findings=[_make_finding()])
        s = orch.summary()
        assert "1 subsystem plan" in s

    def test_top_n_constructor_clamped(self):
        orch_big = CrossFileOrchestrator(top_n=99)
        assert orch_big._top_n == 5
        orch_small = CrossFileOrchestrator(top_n=0)
        assert orch_small._top_n == 1


# --- G5: SubsystemPlan → SubsystemTarget conversion --------------------------


class TestSubsystemPlanToTarget:
    """G5: plan.to_subsystem_target() must produce a SubsystemTarget that the
    SubsystemHuntRunner can actually execute, with source='orchestrator' so
    findings can be traced back."""

    def test_known_files_round_trip(self):
        plan = SubsystemPlan(
            files=["src/auth.php", "src/session.php"],
            hunt_focus="shared session contract",
            rationale="both touch SESSION_TOKEN",
        )
        file_targets = [
            {"path": "src/auth.php", "priority": 4.5, "tier": "A"},
            {"path": "src/session.php", "priority": 3.8, "tier": "B"},
            {"path": "src/unused.php", "priority": 1.0, "tier": "C"},
        ]
        target = plan.to_subsystem_target(file_targets)

        assert target.source == "orchestrator"
        # Highest matched priority wins
        assert target.priority == 4.5
        # Only matched files are included
        matched_paths = [ft.get("path") for ft in target.files]
        assert matched_paths == ["src/auth.php", "src/session.php"]
        # Name uses the hunt_focus
        assert target.name == "shared session contract"
        # Description is the rationale
        assert "SESSION_TOKEN" in target.description
        # Root path is the common directory
        assert target.root_path == "src/"
        # O4: the full hunt_focus is carried as the hypothesis for the hunter
        assert target.hunt_hypothesis == "shared session contract"

    def test_hunt_hypothesis_injected_into_subsystem_prompt(self):
        # O4 (a): an orchestrator-sourced subsystem leads its hunter prompt
        # with the concrete hypothesis; an auto-detected one does not.
        from acuario.scanner.analyzer import _build_subsystem_prompt
        from acuario.scanner.state import SubsystemTarget

        orch = SubsystemTarget(
            name="auth/session",
            root_path="app/",
            files=[{"path": "app/login.php", "priority": 3.0, "tags": []}],
            source="orchestrator",
            hunt_hypothesis="login.php sets SESSION_TOKEN without an origin check",
        )
        prompt = _build_subsystem_prompt(orch, "demo")
        assert "orchestrator flagged" in prompt
        assert "SESSION_TOKEN" in prompt

        auto = SubsystemTarget(
            name="parsers",
            root_path="lib/",
            files=[{"path": "lib/p.c", "priority": 2.0, "tags": []}],
            source="auto",
        )
        assert "orchestrator flagged" not in _build_subsystem_prompt(auto, "demo")

    def test_hunt_hypothesis_sanitized(self):
        # O4: control chars stripped, length bounded, so a malformed hypothesis
        # can't derail the prompt.
        from acuario.scanner.analyzer import _build_subsystem_prompt
        from acuario.scanner.state import SubsystemTarget

        t = SubsystemTarget(
            name="x",
            root_path="a/",
            files=[{"path": "a.py", "priority": 1.0, "tags": []}],
            source="orchestrator",
            hunt_hypothesis="bad\x00\x01chars " + ("z" * 400),
        )
        prompt = _build_subsystem_prompt(t, "demo")
        assert "\x00" not in prompt and "\x01" not in prompt

    def test_unmatched_plan_produces_empty_target(self):
        plan = SubsystemPlan(
            files=["nowhere/a.py", "nowhere/b.py"],
            hunt_focus="phantom subsystem",
            rationale="files do not exist in this audit's scope",
        )
        target = plan.to_subsystem_target(
            file_targets=[{"path": "src/auth.py", "priority": 5.0}],
        )
        # Runner skips targets with empty files; the call must not raise
        assert target.files == []
        assert target.source == "orchestrator"

    def test_partial_match_keeps_known_files_only(self):
        plan = SubsystemPlan(
            files=["src/known.py", "src/unknown.py"],
            hunt_focus="partial match",
            rationale="one file is missing from scope",
        )
        target = plan.to_subsystem_target(
            file_targets=[{"path": "src/known.py", "priority": 2.5}],
        )
        assert len(target.files) == 1
        assert target.files[0].get("path") == "src/known.py"

    def test_long_hunt_focus_truncated_in_name(self):
        plan = SubsystemPlan(
            files=["a", "b"],
            hunt_focus="x" * 200,
            rationale="long",
        )
        target = plan.to_subsystem_target(
            file_targets=[{"path": "a", "priority": 1.0}],
        )
        assert len(target.name) <= 60
