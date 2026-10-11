from __future__ import annotations

import hashlib
import re
from typing import Any


class SARIFGenerator:
    """Generate SARIF v2.1.0 output for GitHub Security tab integration."""

    SEVERITY_MAP: dict[str, str] = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    # GitHub code scanning ranks + colours alerts by the numeric
    # ``security-severity`` property (0.0-10.0, CVSS-like). Without it every
    # alert imports as unranked. Mapped from our qualitative severity.
    SECURITY_SEVERITY: dict[str, str] = {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.0",
        "low": "3.0",
        "info": "0.0",
    }

    _CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

    def generate(
        self,
        findings: list[dict[str, Any]],
        target: str,
        tool_name: str = "acuario",
    ) -> dict[str, Any]:
        """Convert findings to SARIF v2.1.0 format.

        Each finding becomes a result with:
        - ruleId from CVE or generated ID
        - level: error/warning/note based on severity
        - message with description
        - locations (target info)

        Args:
            findings: List of finding dicts with keys description, severity,
                      cve (optional), and details (optional).
            target: The scan target (URL or IP).
            tool_name: Name of the tool producing the report.

        Returns:
            A SARIF v2.1.0 compliant dictionary.
        """
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        seen_rule_ids: set[str] = set()

        for idx, finding in enumerate(findings):
            rule_id = finding.get("cve") or f"VULN-{idx + 1:04d}"
            severity = (finding.get("severity") or "info").lower()
            level = self.SEVERITY_MAP.get(severity, "note")
            description = finding.get("description", "No description provided")
            details = finding.get("details", "")

            if rule_id not in seen_rule_ids:
                rule: dict[str, Any] = {
                    "id": rule_id,
                    "shortDescription": {"text": description},
                }
                if details:
                    rule["fullDescription"] = {"text": details}
                # helpUri: link CWE-based rules to the MITRE definition so the
                # code-scanning UI's "learn more" resolves.
                help_uri = self._cwe_help_uri(rule_id)
                if help_uri:
                    rule["helpUri"] = help_uri
                # tags + security-severity so GitHub can filter by CWE and rank
                # the alert instead of importing it flat/unranked.
                tags = ["security"]
                cwe_tag = self._cwe_tag(rule_id)
                if cwe_tag:
                    tags.append(cwe_tag)
                rule["properties"] = {
                    "tags": tags,
                    "security-severity": self.SECURITY_SEVERITY.get(severity, "0.0"),
                }
                rules.append(rule)
                seen_rule_ids.add(rule_id)

            physical: dict[str, Any] = {
                "artifactLocation": {
                    "uri": finding.get("file") or target,
                }
            }
            if "line_number" in finding and finding["line_number"]:
                region: dict[str, Any] = {"startLine": int(finding["line_number"])}
                end_line = finding.get("end_line")
                if end_line:
                    region["endLine"] = int(end_line)
                physical["region"] = region

            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": description},
                "locations": [{"physicalLocation": physical}],
                # Per-result security-severity so ranking survives even when a
                # tool imports results without their rules.
                "properties": {
                    "security-severity": self.SECURITY_SEVERITY.get(severity, "0.0"),
                    "severity": severity,
                },
                # Stable identity (file:line:rule) so a scanning UI can track the
                # same alert across scans instead of re-opening it every run.
                "partialFingerprints": {
                    "acuarioLocus/v1": self._fingerprint(finding, rule_id, target),
                },
            }
            evidence = finding.get("evidence_level")
            if evidence:
                result["properties"]["evidence_level"] = evidence
            results.append(result)

        sarif: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": "1.0.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
        return sarif

    def _cwe_help_uri(self, rule_id: str) -> str:
        m = self._CWE_RE.search(rule_id or "")
        if not m:
            return ""
        return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"

    def _cwe_tag(self, rule_id: str) -> str:
        m = self._CWE_RE.search(rule_id or "")
        if not m:
            return ""
        # GitHub's convention for CWE filtering in the code-scanning UI.
        return f"external/cwe/cwe-{m.group(1)}"

    @staticmethod
    def _fingerprint(finding: dict[str, Any], rule_id: str, target: str) -> str:
        loc = finding.get("file") or target
        line = finding.get("line_number") or ""
        raw = f"{loc}:{line}:{rule_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
