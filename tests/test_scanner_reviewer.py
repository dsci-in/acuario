"""Unit tests for the scanner reviewer.

Critical assertions:
- Independent context - reviewer message NEVER contains analyzer reasoning
- v0.1 prompt is non-adversarial; v0.2 flag flips to adversarial
- Output schema includes pro_argument / counter_argument / tie_breaker_evidence
  (counter_argument is empty in v0.1)
- evidence_level is set to crash_reproduced or root_cause_explained on success
- apply_verifier_result merges the verdict into the Finding
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from genai_pyo3 import ChatResponse

from acuario.scanner.reviewer import (
    VERIFIER_SYSTEM_PROMPT_V01,
    VERIFIER_SYSTEM_PROMPT_V02,
    Reviewer,
    VerifierResult,
    apply_verifier_result,
)


def _mock_llm_returning_json(payload: dict) -> AsyncMock:
    mock = AsyncMock()
    mock.aask_text.return_value = ChatResponse(content=[{"text": json.dumps(payload)}])
    return mock


def _mock_llm_raw(content: str) -> AsyncMock:
    mock = AsyncMock()
    mock.aask_text.return_value = ChatResponse(content=[{"text": content}])
    return mock


def _run(coro):
    return asyncio.run(coro)


def _make_finding(**kwargs) -> dict:
    base = {
        "id": "analyzer-abc",
        "file": "src/codec_a.c",
        "line_number": 9,
        "finding_type": "memory_safety",
        "cwe": "CWE-787",
        "severity": "critical",
        "description": "memcpy with unchecked length",
        "code_snippet": "memcpy(frame, input, input_len);",
        "evidence_level": "static_corroboration",
        "discovered_by": "analyzer:general",
    }
    base.update(kwargs)
    return base


# --- v0.1 / v0.2 prompt selection -------------------------------------------


class TestVerifierPromptSelection:
    def test_v01_default_non_adversarial(self):
        v = Reviewer(MagicMock())
        assert v._system_prompt is VERIFIER_SYSTEM_PROMPT_V01
        assert v.adversarial is False

    def test_v02_flag_flips_to_adversarial(self):
        v = Reviewer(MagicMock(), adversarial=True)
        assert v._system_prompt is VERIFIER_SYSTEM_PROMPT_V02
        assert v.adversarial is True

    def test_v01_prompt_is_simpler(self):
        # v0.1 doesn't require steel-manning; v0.2 does
        assert "STEEL-MAN" not in VERIFIER_SYSTEM_PROMPT_V01
        assert "STEEL-MAN" in VERIFIER_SYSTEM_PROMPT_V02

    def test_both_prompts_request_json(self):
        assert "JSON" in VERIFIER_SYSTEM_PROMPT_V01
        assert "JSON" in VERIFIER_SYSTEM_PROMPT_V02


# --- Independent context guarantee ------------------------------------------


class TestAdversarialBudgetGate:
    """v0.4: the reviewer only spends adversarial budget on findings with
    evidence_level >= static_corroboration (default threshold)."""

    def test_suspicion_falls_back_to_v01(self):
        """A suspicion-level finding gets the cheap non-adversarial prompt."""
        llm = _mock_llm_returning_json(
            {
                "is_real": False,
                "severity": "low",
                "evidence_level": "suspicion",
                "pro_argument": "p",
                "counter_argument": "",
                "tie_breaker": "t",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm, adversarial=True)  # default threshold = static_corroboration
        _run(v.averify(_make_finding(evidence_level="suspicion")))
        system_msg = SimpleNamespace(content=llm.aask_text.call_args.kwargs["system"])
        # Below the gate → V01 (no STEEL-MAN wording)
        assert "STEEL-MAN" not in system_msg.content

    def test_static_corroboration_uses_v02(self):
        """Exactly at the threshold → adversarial prompt."""
        llm = _mock_llm_returning_json(
            {
                "is_real": True,
                "severity": "high",
                "evidence_level": "root_cause_explained",
                "pro_argument": "p",
                "counter_argument": "c",
                "tie_breaker": "t",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm, adversarial=True)
        _run(v.averify(_make_finding(evidence_level="static_corroboration")))
        system_msg = SimpleNamespace(content=llm.aask_text.call_args.kwargs["system"])
        assert "STEEL-MAN" in system_msg.content

    def test_crash_reproduced_uses_v02(self):
        llm = _mock_llm_returning_json(
            {
                "is_real": True,
                "severity": "critical",
                "evidence_level": "root_cause_explained",
                "pro_argument": "p",
                "counter_argument": "c",
                "tie_breaker": "t",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm, adversarial=True)
        _run(v.averify(_make_finding(evidence_level="crash_reproduced")))
        system_msg = SimpleNamespace(content=llm.aask_text.call_args.kwargs["system"])
        assert "STEEL-MAN" in system_msg.content

    def test_custom_threshold_crash_reproduced(self):
        """A caller can set a stricter threshold - e.g. only spend adversarial
        budget when there's an actual sanitizer crash."""
        llm = _mock_llm_returning_json(
            {
                "is_real": False,
                "severity": "low",
                "evidence_level": "static_corroboration",
                "pro_argument": "p",
                "counter_argument": "",
                "tie_breaker": "t",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm, adversarial=True, adversarial_threshold="crash_reproduced")
        _run(v.averify(_make_finding(evidence_level="static_corroboration")))
        system_msg = SimpleNamespace(content=llm.aask_text.call_args.kwargs["system"])
        # static_corroboration < crash_reproduced → V01
        assert "STEEL-MAN" not in system_msg.content

    def test_threshold_none_disables_gate(self):
        """adversarial_threshold=None → adversarial runs on every finding."""
        llm = _mock_llm_returning_json(
            {
                "is_real": False,
                "severity": "low",
                "evidence_level": "suspicion",
                "pro_argument": "p",
                "counter_argument": "x",
                "tie_breaker": "t",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm, adversarial=True, adversarial_threshold=None)
        _run(v.averify(_make_finding(evidence_level="suspicion")))
        system_msg = SimpleNamespace(content=llm.aask_text.call_args.kwargs["system"])
        assert "STEEL-MAN" in system_msg.content

    def test_gate_does_nothing_when_adversarial_off(self):
        """adversarial=False → V01 for every finding regardless of level."""
        llm = _mock_llm_returning_json(
            {
                "is_real": True,
                "severity": "high",
                "evidence_level": "patch_validated",
                "pro_argument": "p",
                "counter_argument": "",
                "tie_breaker": "t",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm, adversarial=False)
        _run(v.averify(_make_finding(evidence_level="patch_validated")))
        system_msg = SimpleNamespace(content=llm.aask_text.call_args.kwargs["system"])
        assert "STEEL-MAN" not in system_msg.content

    def test_missing_evidence_level_falls_back_below_gate(self):
        """A finding without an evidence_level field → suspicion → below gate."""
        llm = _mock_llm_returning_json(
            {
                "is_real": False,
                "severity": "low",
                "evidence_level": "suspicion",
                "pro_argument": "",
                "counter_argument": "",
                "tie_breaker": "",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm, adversarial=True)
        finding = {"id": "f", "file": "x.c"}  # no evidence_level
        _run(v.averify(finding))
        system_msg = SimpleNamespace(content=llm.aask_text.call_args.kwargs["system"])
        assert "STEEL-MAN" not in system_msg.content

    def test_mixed_batch_picks_per_finding(self):
        """Running verify() across a mixed batch picks the right prompt per call."""
        llm = AsyncMock()
        # Response doesn't matter - we only care about which prompt was used
        llm.aask_text.return_value = ChatResponse(
            content=[
                {
                    "text": json.dumps(
                        {
                            "is_real": True,
                            "severity": "high",
                            "evidence_level": "crash_reproduced",
                            "pro_argument": "p",
                            "counter_argument": "c",
                            "tie_breaker": "t",
                            "duplicate_cve": None,
                        }
                    )
                }
            ]
        )

        v = Reviewer(llm, adversarial=True)
        findings = [
            _make_finding(id="low", evidence_level="suspicion"),
            _make_finding(id="med", evidence_level="static_corroboration"),
            _make_finding(id="high", evidence_level="crash_reproduced"),
        ]
        for f in findings:
            _run(v.averify(f))

        assert llm.aask_text.call_count == 3
        prompts = [call.kwargs["system"] for call in llm.aask_text.call_args_list]
        assert "STEEL-MAN" not in prompts[0]  # suspicion
        assert "STEEL-MAN" in prompts[1]  # static_corroboration
        assert "STEEL-MAN" in prompts[2]  # crash_reproduced


class TestIndependentContext:
    """The reviewer must NOT see analyzer reasoning messages - only the finding."""

    def test_user_message_does_not_contain_hunter_reasoning(self):
        llm = _mock_llm_returning_json(
            {
                "is_real": True,
                "severity": "critical",
                "evidence_level": "root_cause_explained",
                "pro_argument": "yes",
                "counter_argument": "no",
                "tie_breaker": "x",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm)
        finding = _make_finding()
        _run(v.averify(finding, file_content="int main() {}\n"))

        # Inspect what was passed to the LLM
        call_kwargs = llm.aask_text.call_args.kwargs
        assert "system" in call_kwargs and "user" in call_kwargs
        human_msg = call_kwargs["user"]
        # The analyzer's reasoning chain must NOT appear
        assert "analyzer" not in human_msg.lower() or "discovered_by" in human_msg
        # But the finding metadata IS present
        assert "memcpy with unchecked length" in human_msg
        assert "src/codec_a.c" in human_msg

    def test_user_message_includes_file_content_when_provided(self):
        llm = _mock_llm_returning_json(
            {
                "is_real": True,
                "severity": "high",
                "evidence_level": "crash_reproduced",
                "pro_argument": "p",
                "counter_argument": "",
                "tie_breaker": "t",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm)
        finding = _make_finding()
        _run(v.averify(finding, file_content="#include <string.h>\nvoid bug() {}\n"))
        human_msg = llm.aask_text.call_args.kwargs["user"]
        assert "<string.h>" in human_msg

    def test_file_content_is_capped(self):
        llm = _mock_llm_returning_json(
            {
                "is_real": False,
                "severity": None,
                "evidence_level": "suspicion",
                "pro_argument": "",
                "counter_argument": "",
                "tie_breaker": "",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm)
        finding = _make_finding()
        huge = "x" * 50000
        _run(v.averify(finding, file_content=huge))
        human_msg = llm.aask_text.call_args.kwargs["user"]
        # File content section is capped to 8KB
        assert "x" * 8001 not in human_msg


# --- Response parsing -------------------------------------------------------


class TestResponseParsing:
    def test_basic_json_response(self):
        llm = _mock_llm_returning_json(
            {
                "is_real": True,
                "severity": "high",
                "evidence_level": "crash_reproduced",
                "pro_argument": "memcpy length is unchecked",
                "counter_argument": "",
                "tie_breaker": "ASan crash on input >64",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm)
        result = _run(v.averify(_make_finding()))
        assert isinstance(result, VerifierResult)
        assert result.is_real is True
        assert result.severity_verified == "high"
        assert result.evidence_level == "crash_reproduced"
        assert "memcpy" in result.pro_argument
        assert result.counter_argument == ""

    def test_v02_response_with_counter_argument(self):
        llm = _mock_llm_returning_json(
            {
                "is_real": False,
                "severity": "low",
                "evidence_level": "static_corroboration",
                "pro_argument": "looks like memcpy bug",
                "counter_argument": "but caller validates length",
                "tie_breaker": "validation in callers/main.c:42",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm, adversarial=True)
        result = _run(v.averify(_make_finding()))
        assert result.is_real is False
        assert result.severity_verified is None  # not_real → None
        assert "validates length" in result.counter_argument
        assert "validation in callers/main.c:42" in result.tie_breaker

    def test_invalid_severity_clamped(self):
        llm = _mock_llm_returning_json(
            {
                "is_real": True,
                "severity": "apocalyptic",  # not a valid level
                "evidence_level": "crash_reproduced",
                "pro_argument": "x",
                "counter_argument": "",
                "tie_breaker": "",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm)
        result = _run(v.averify(_make_finding()))
        # Reviewer coerces invalid severity to None (caller decides what to do)
        assert result.severity_verified is None

    def test_invalid_evidence_level_falls_back_to_suspicion(self):
        llm = _mock_llm_returning_json(
            {
                "is_real": True,
                "severity": "high",
                "evidence_level": "made_up_level",
                "pro_argument": "x",
                "counter_argument": "",
                "tie_breaker": "",
                "duplicate_cve": None,
            }
        )
        v = Reviewer(llm)
        result = _run(v.averify(_make_finding()))
        assert result.evidence_level == "suspicion"

    def test_no_json_in_response(self):
        llm = _mock_llm_raw("I'm just a chatty model with no JSON")
        v = Reviewer(llm)
        result = _run(v.averify(_make_finding()))
        assert result.is_real is False
        assert "no JSON" in result.tie_breaker

    def test_invalid_json_in_response(self):
        llm = _mock_llm_raw("{ not valid json }")
        v = Reviewer(llm)
        result = _run(v.averify(_make_finding()))
        assert result.is_real is False

    def test_llm_exception_returns_error_result(self):
        llm = AsyncMock()
        llm.aask_text.side_effect = Exception("rate limited")
        v = Reviewer(llm)
        result = _run(v.averify(_make_finding()))
        assert result.is_real is False
        assert "rate limited" in result.tie_breaker


# --- apply_verifier_result --------------------------------------------------


class TestApplyVerifierResult:
    def test_merges_basic_fields(self):
        finding = _make_finding(evidence_level="static_corroboration")
        result = VerifierResult(
            finding_id="analyzer-abc",
            is_real=True,
            severity_verified="critical",
            evidence_level="root_cause_explained",
            pro_argument="strong case",
            counter_argument="weak counter",
            tie_breaker="conclusive",
            duplicate_cve=None,
        )
        merged = apply_verifier_result(finding, result, session_id="reviewer-1")
        assert merged["verified"] is True
        assert merged["severity_verified"] == "critical"
        assert merged["verifier_pro_argument"] == "strong case"
        assert merged["verifier_counter_argument"] == "weak counter"
        assert merged["verifier_tie_breaker"] == "conclusive"
        assert merged["verifier_session_id"] == "reviewer-1"

    def test_evidence_level_only_bumps_up(self):
        # If finding already has root_cause_explained and reviewer returns
        # crash_reproduced (lower), keep root_cause_explained
        finding = _make_finding(evidence_level="root_cause_explained")
        result = VerifierResult(
            finding_id="x",
            is_real=True,
            severity_verified="high",
            evidence_level="crash_reproduced",
            pro_argument="",
            counter_argument="",
            tie_breaker="",
            duplicate_cve=None,
        )
        apply_verifier_result(finding, result)
        # Did not regress
        assert finding["evidence_level"] == "root_cause_explained"

    def test_evidence_level_bumps_when_verifier_stronger(self):
        finding = _make_finding(evidence_level="static_corroboration")
        result = VerifierResult(
            finding_id="x",
            is_real=True,
            severity_verified="high",
            evidence_level="crash_reproduced",
            pro_argument="",
            counter_argument="",
            tie_breaker="",
            duplicate_cve=None,
        )
        apply_verifier_result(finding, result)
        assert finding["evidence_level"] == "crash_reproduced"

    def test_not_real_clears_severity_verified(self):
        finding = _make_finding()
        result = VerifierResult(
            finding_id="x",
            is_real=False,
            severity_verified=None,
            evidence_level="suspicion",
            pro_argument="",
            counter_argument="",
            tie_breaker="",
            duplicate_cve=None,
        )
        apply_verifier_result(finding, result)
        assert finding["verified"] is False
        assert finding["severity_verified"] is None

    def test_invalid_existing_evidence_level_falls_back_to_suspicion(self):
        finding = _make_finding(evidence_level="made_up_level")
        result = VerifierResult(
            finding_id="x",
            is_real=True,
            severity_verified="high",
            evidence_level="crash_reproduced",
            pro_argument="",
            counter_argument="",
            tie_breaker="",
            duplicate_cve=None,
        )
        apply_verifier_result(finding, result)
        assert finding["evidence_level"] == "crash_reproduced"
