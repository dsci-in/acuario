"""Tests for SARIF generation, including the code-scanning enrichment."""

from __future__ import annotations

from acuario.runners.cicd.sarif import SARIFGenerator


def _gen(findings):
    return SARIFGenerator().generate(findings=findings, target="/repo", tool_name="acuario")


def test_basic_shape_and_level_mapping():
    sarif = _gen(
        [
            {
                "description": "SQLi",
                "severity": "critical",
                "cve": "CWE-89",
                "file": "a.py",
                "line_number": 3,
            },
            {
                "description": "info leak",
                "severity": "low",
                "cve": "CWE-200",
                "file": "b.py",
                "line_number": 5,
            },
        ]
    )
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    levels = [r["level"] for r in run["results"]]
    assert levels == ["error", "note"]


def test_result_has_security_severity_and_fingerprint():
    sarif = _gen(
        [
            {
                "description": "SQLi",
                "severity": "critical",
                "cve": "CWE-89",
                "file": "a.py",
                "line_number": 3,
                "evidence_level": "exploit_demonstrated",
            }
        ]
    )
    res = sarif["runs"][0]["results"][0]
    assert res["properties"]["security-severity"] == "9.5"
    assert res["properties"]["severity"] == "critical"
    assert res["properties"]["evidence_level"] == "exploit_demonstrated"
    assert "acuarioLocus/v1" in res["partialFingerprints"]


def test_rule_has_cwe_help_uri_and_tags():
    sarif = _gen(
        [
            {
                "description": "SQLi",
                "severity": "high",
                "cve": "CWE-89",
                "file": "a.py",
                "line_number": 3,
            }
        ]
    )
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == "https://cwe.mitre.org/data/definitions/89.html"
    assert "security" in rule["properties"]["tags"]
    assert "external/cwe/cwe-89" in rule["properties"]["tags"]
    assert rule["properties"]["security-severity"] == "8.0"


def test_non_cwe_rule_has_no_help_uri():
    sarif = _gen(
        [{"description": "generic", "severity": "medium", "file": "a.py", "line_number": 1}]
    )
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "helpUri" not in rule
    # still tagged 'security' and ranked, just no CWE tag
    assert rule["properties"]["tags"] == ["security"]


def test_fingerprint_is_stable_for_same_locus():
    f = {"description": "x", "severity": "high", "cve": "CWE-89", "file": "a.py", "line_number": 3}
    fp1 = _gen([f])["runs"][0]["results"][0]["partialFingerprints"]["acuarioLocus/v1"]
    fp2 = _gen([dict(f, description="reworded")])["runs"][0]["results"][0]["partialFingerprints"][
        "acuarioLocus/v1"
    ]
    # Fingerprint tracks the locus (file:line:rule), not the wording.
    assert fp1 == fp2
