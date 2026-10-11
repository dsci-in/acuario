"""Tests for the 4-axis Validator's context injection (O5 + O1 surfacing).

The validator is the agent that actually sets ``verified``. O5 gives it the
same cross-file context the skeptic/critic get so it judges TRIGGERABLE /
IMPACTFUL from real reachability; O1 surfaces the skeptic's unrefuted doubt
into the prompt so a flagged finding isn't treated as unchallenged.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from acuario.findings.types import Finding
from acuario.scanner.validator import Validator


def _make_finding(**kw) -> Finding:
    defaults = dict(
        id="f-1",
        file="app/search.py",
        line_number=27,
        finding_type="sql_injection",
        cwe="CWE-89",
        severity="high",
        description="user-controlled q reaches a raw query",
        code_snippet="cur.execute(f'SELECT * FROM t WHERE q={q}')",
        evidence_level="static_corroboration",
    )
    defaults.update(kw)
    return Finding(**defaults)


def _validator() -> Validator:
    return Validator(MagicMock())


def test_cross_file_context_injected_into_user_message():
    v = _validator()
    msg = v._build_user_message(
        _make_finding(),
        file_content="",
        cross_file_context="CALLER: app/router.py -> search(); reachable from POST /search",
    )
    assert "Known cross-file context" in msg
    assert "POST /search" in msg


def test_no_cross_file_context_section_when_empty():
    v = _validator()
    msg = v._build_user_message(_make_finding(), file_content="", cross_file_context="")
    assert "Known cross-file context" not in msg


def test_cross_file_context_capped():
    v = _validator()
    msg = v._build_user_message(_make_finding(), file_content="", cross_file_context="Z" * 9000)
    # Bounded to 3000 chars so a huge context can't dominate the prompt.
    assert "Z" * 3001 not in msg


def test_skeptic_uncertain_doubt_surfaced():
    # O1: a finding the skeptic flagged uncertain must carry that doubt into
    # the validator prompt, not arrive looking unchallenged.
    v = _validator()
    f = _make_finding()
    f["skeptic_flag"] = "uncertain"
    f["skeptic_doubt"] = "the ORM probably parameterizes but I couldn't see where"
    msg = v._build_user_message(f, file_content="")
    assert "skeptic_doubt" in msg
    assert "ORM probably parameterizes" in msg


def test_accepted_finding_has_no_skeptic_doubt_field():
    v = _validator()
    msg = v._build_user_message(_make_finding(), file_content="")
    assert "skeptic_doubt" not in msg


# --- O6: deterministic severity recalibration --------------------------------


def _ax(name, passed, conf="high"):
    from acuario.scanner.state import AxisResult

    return AxisResult(axis=name, passed=passed, confidence=conf, rationale="")


class TestSeverityRecalibration:
    def test_impactful_fail_caps_low(self):
        sev, reason = Validator._recalibrate_severity(
            "critical", {"IMPACTFUL": _ax("IMPACTFUL", False)}
        )
        assert sev == "low"
        assert "IMPACTFUL" in reason

    def test_triggerable_fail_caps_medium(self):
        sev, _r = Validator._recalibrate_severity(
            "critical", {"TRIGGERABLE": _ax("TRIGGERABLE", False)}
        )
        assert sev == "medium"

    def test_triggerable_low_confidence_caps_high(self):
        sev, _r = Validator._recalibrate_severity(
            "critical", {"TRIGGERABLE": _ax("TRIGGERABLE", True, "low")}
        )
        assert sev == "high"

    def test_all_low_confidence_drops_one_rank(self):
        sev, _r = Validator._recalibrate_severity(
            "high",
            {"REAL": _ax("REAL", True, "low"), "TRIGGERABLE": _ax("TRIGGERABLE", True, "low")},
        )
        assert sev == "medium"

    def test_all_low_rule_reachable_with_triggerable_low_pass(self):
        # Review O6 regression: when TRIGGERABLE passes at low confidence AND
        # every axis is low-confidence, the "all axes low-confidence" rule must
        # still fire and be the recorded reason - previously it was unreachable
        # because the TRIGGERABLE-low cap moved new_idx first.
        sev, reason = Validator._recalibrate_severity(
            "critical",
            {
                "REAL": _ax("REAL", True, "low"),
                "TRIGGERABLE": _ax("TRIGGERABLE", True, "low"),
                "IMPACTFUL": _ax("IMPACTFUL", True, "low"),
            },
        )
        assert sev == "high"
        assert "all axes low-confidence" in reason

    def test_triggerable_fail_dominates_all_low(self):
        # A hard cap (failed axis) suppresses the soft all-low −1 rank, so a
        # failed TRIGGERABLE still caps at medium, not "medium then −1".
        sev, _r = Validator._recalibrate_severity(
            "critical",
            {
                "TRIGGERABLE": _ax("TRIGGERABLE", False, "low"),
                "REAL": _ax("REAL", True, "low"),
            },
        )
        assert sev == "medium"

    def test_clean_high_confidence_no_change(self):
        sev, reason = Validator._recalibrate_severity(
            "high",
            {"REAL": _ax("REAL", True, "high"), "TRIGGERABLE": _ax("TRIGGERABLE", True, "high")},
        )
        assert sev is None
        assert reason == ""

    def test_never_upgrades(self):
        # A low-severity claim with strong axes is never raised.
        sev, _r = Validator._recalibrate_severity("low", {"IMPACTFUL": _ax("IMPACTFUL", True)})
        assert sev is None

    def test_disabled_by_default_in_parse(self):
        # When the flag is off, the verdict carries no recalibration.
        import json as _json

        v = Validator(MagicMock())  # enable_severity_recalibration defaults False
        content = _json.dumps(
            {
                "advance": True,
                "severity": "critical",
                "evidence_level": "crash_reproduced",
                "axes": {"TRIGGERABLE": {"passed": True, "confidence": "low", "rationale": "x"}},
            }
        )
        verdict = v._parse_response(_make_finding(), content)
        assert verdict.severity_recalibrated is None

    def test_enabled_recalibrates_in_parse(self):
        import json as _json

        v = Validator(MagicMock(), enable_severity_recalibration=True)
        content = _json.dumps(
            {
                "advance": True,
                "severity": "critical",
                "evidence_level": "crash_reproduced",
                "axes": {"TRIGGERABLE": {"passed": True, "confidence": "low", "rationale": "x"}},
            }
        )
        verdict = v._parse_response(_make_finding(), content)
        assert verdict.severity_recalibrated == "high"
        assert verdict.severity_validated == "critical"  # original claim preserved


def test_apply_verdict_uses_recalibrated_severity():
    from acuario.scanner.state import ValidatorVerdict
    from acuario.scanner.validator import apply_validator_verdict

    f = _make_finding()
    verdict = ValidatorVerdict(
        finding_id="f-1",
        axes={},
        advance=True,
        severity_validated="critical",
        evidence_level="crash_reproduced",
        pro_argument="",
        counter_argument="",
        tie_breaker="",
        duplicate_cve=None,
        severity_recalibrated="high",
        severity_recalibration_reason="TRIGGERABLE passed at low confidence → cap high",
    )
    apply_validator_verdict(f, verdict)
    assert f["severity_verified"] == "high"
    assert f["severity_claimed"] == "critical"
    assert "TRIGGERABLE" in f["severity_recalibration_reason"]
