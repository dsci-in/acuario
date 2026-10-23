"""Tests for the measurement framework (NF4 / acuario eval).

The analyzer reads only artifacts that already exist and degrades to empty
sections when files are missing - these tests lock in both the metric math
and the graceful-degradation behavior.
"""

from __future__ import annotations

import json
from pathlib import Path

from acuario.scanner.eval import analyze_session, compare_reports


def _write_session(tmp_path: Path, **files) -> Path:
    sd = tmp_path / "audit-eval-0001"
    sd.mkdir(parents=True, exist_ok=True)
    if "findings" in files:
        sd.joinpath("findings.json").write_text(
            json.dumps({"session_id": "audit-eval-0001", "findings": files["findings"]})
        )
    if "manifest" in files:
        sd.joinpath("manifest.json").write_text(json.dumps(files["manifest"]))
    for name in ("skeptic_log", "debate_log", "calibration"):
        if name in files:
            sd.joinpath(f"{name}.jsonl").write_text(
                "\n".join(json.dumps(r) for r in files[name]) + "\n"
            )
    return sd


class TestPerSourceVerifiedRate:
    def test_groups_by_discovered_by(self, tmp_path):
        findings = [
            {"id": "a", "discovered_by": "analyzer:unconstrained", "verified": True},
            {"id": "b", "discovered_by": "analyzer:unconstrained", "verified": False},
            {"id": "c", "discovered_by": "variant_loop", "verified": False},
            {"id": "d", "discovered_by": "critic", "verified": True},
        ]
        r = analyze_session(_write_session(tmp_path, findings=findings))
        # Headline counts exclude variant_loop (canonical set only), so the rate
        # agrees with inspect/history; by_source still lists variant_loop separately.
        assert r.total_findings == 3
        assert r.verified_findings == 2
        assert r.by_source["analyzer:unconstrained"] == {"total": 2, "verified": 1}
        assert r.by_source["variant_loop"] == {"total": 1, "verified": 0}
        assert r.by_source["critic"] == {"total": 1, "verified": 1}

    def test_missing_discovered_by_defaults_to_analyzer(self, tmp_path):
        r = analyze_session(_write_session(tmp_path, findings=[{"id": "a", "verified": True}]))
        assert "analyzer" in r.by_source


class TestSkepticAndDebate:
    def test_skeptic_distribution(self, tmp_path):
        skeptic = [
            {"finding_id": "a", "verdict": "accepted"},
            {"finding_id": "b", "verdict": "refuted"},
            {"finding_id": "c", "verdict": "uncertain"},
            {"finding_id": "d", "verdict": "refuted"},
        ]
        r = analyze_session(_write_session(tmp_path, findings=[], skeptic_log=skeptic))
        assert r.skeptic_distribution == {"accepted": 1, "refuted": 2, "uncertain": 1}

    def test_debate_outcomes(self, tmp_path):
        debate = [
            {"finding_id": "a", "reinstated": True, "conceded": False},
            {"finding_id": "b", "reinstated": False, "conceded": False},
            {"finding_id": "c", "reinstated": False, "conceded": True},
        ]
        r = analyze_session(_write_session(tmp_path, findings=[], debate_log=debate))
        assert r.debate == {"overturned": 1, "upheld": 1, "conceded": 1}


class TestAgreementMatrix:
    def test_skeptic_validator_agreement(self, tmp_path):
        cal = [
            # skeptic refuted but validator advanced → possible killed TP
            {
                "finding_id": "a",
                "skeptic_verdict": "refuted",
                "validator": {"validator_advance": True},
            },
            # skeptic accepted & validator rejected → let a likely-FP through
            {
                "finding_id": "b",
                "skeptic_verdict": "accepted",
                "validator": {"validator_advance": False},
            },
            # agreed advance
            {
                "finding_id": "c",
                "skeptic_verdict": "accepted",
                "validator": {"validator_advance": True},
            },
            # agreed kill
            {
                "finding_id": "d",
                "skeptic_verdict": "refuted",
                "validator": {"validator_advance": False},
            },
            # uncertain treated as accept
            {
                "finding_id": "e",
                "skeptic_verdict": "uncertain",
                "validator": {"validator_advance": True},
            },
        ]
        r = analyze_session(_write_session(tmp_path, findings=[], calibration=cal))
        ag = r.agreement
        assert ag["refute_advance"] == 1
        assert ag["accept_reject"] == 1
        assert ag["accept_advance"] == 2  # c + e (uncertain)
        assert ag["refute_reject"] == 1

    def test_rows_without_both_verdicts_skipped(self, tmp_path):
        cal = [{"finding_id": "a", "skeptic_verdict": None, "validator": {}}]
        r = analyze_session(_write_session(tmp_path, findings=[], calibration=cal))
        assert r.agreement == {}


class TestSeverityRecalibration:
    def test_counts_changes_and_downgrades(self, tmp_path):
        findings = [
            {"id": "a", "severity": "critical", "severity_recalibrated": "high"},  # downgrade
            {"id": "b", "severity": "high", "severity_recalibrated": "high"},  # unchanged
            {
                "id": "c",
                "severity": "low",
                "severity_recalibrated": "medium",
            },  # up (changed, not down)
        ]
        r = analyze_session(_write_session(tmp_path, findings=findings))
        sr = r.severity_recalibration
        assert sr["changed"] == 2
        assert sr["downgraded"] == 1
        assert sr["unchanged"] == 1

    def test_non_standard_base_severity_does_not_crash(self, tmp_path):
        # Review fix: a legacy/external `base` severity not in the standard
        # ladder must still count as "changed" without losing direction
        # tracking for the others or raising.
        findings = [
            {"id": "a", "severity": "blocker", "severity_recalibrated": "high"},  # base unknown
            {"id": "b", "severity": "critical", "severity_recalibrated": "high"},  # downgrade
        ]
        r = analyze_session(_write_session(tmp_path, findings=findings))
        sr = r.severity_recalibration
        assert sr["changed"] == 2
        # 'blocker' isn't in the ladder so its direction is indeterminate and
        # not counted; the standard critical→high downgrade still counts.
        assert sr["downgraded"] == 1


class TestAnnotationsOverlay:
    def test_true_precision_from_labels(self, tmp_path):
        findings = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        ann = {"a": {"label": "TP"}, "b": {"label": "FP"}, "c": {"label": "TP"}}
        r = analyze_session(_write_session(tmp_path, findings=findings), annotations=ann)
        assert r.labeled["tp"] == 2
        assert r.labeled["fp"] == 1
        assert abs(r.labeled["precision"] - (2 / 3)) < 1e-9


class TestGracefulDegradation:
    def test_empty_session(self, tmp_path):
        sd = tmp_path / "empty"
        sd.mkdir()
        r = analyze_session(sd)
        assert r.total_findings == 0
        assert r.by_source == {}
        assert r.skeptic_distribution == {}
        # to_markdown must not raise on an empty report
        assert "Eval" in r.to_markdown()

    def test_endpoint_label_from_manifest(self, tmp_path):
        sd = _write_session(
            tmp_path,
            findings=[{"id": "a"}],
            manifest={"cost_summary": {"endpoint_label": "qwen via vllm"}},
        )
        r = analyze_session(sd)
        assert r.endpoint_label == "qwen via vllm"


class TestCompare:
    def test_compare_shows_delta(self, tmp_path):
        a = analyze_session(
            _write_session(tmp_path / "x", findings=[{"id": "a", "verified": True}])
        )
        b = analyze_session(
            _write_session(
                tmp_path / "y",
                findings=[{"id": "a", "verified": True}, {"id": "b", "verified": True}],
            )
        )
        md = compare_reports(a, b)
        assert "comparison" in md.lower()
        assert "verified findings" in md
