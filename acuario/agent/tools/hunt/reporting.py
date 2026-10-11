"""Finding-reporting tool for the source-hunt analyzer.

A single tool, `record_finding`, that the analyzer calls to surface a
vulnerability into `ctx.findings`. This is where analyzer-emitted hits
become `acuario.findings.Finding` dataclass instances - the canonical
shape consumed by the scanner reviewer, exploit_dev, patcher, and
reporter stages downstream.
"""

from __future__ import annotations

import uuid

from acuario.llm import NativeToolSpec
from acuario.scanner.state import Finding

from .sandbox import HunterContext


def build_reporting_tools(ctx: HunterContext) -> list:
    """Build the single finding-reporter tool for a analyzer session."""

    def record_finding(
        description: str = "",
        file: str = "",
        finding_type: str = "unknown",
        severity: str = "medium",
        cwe: str = "",
        line_number: int = 0,
        code_snippet: str = "",
        crash_evidence: str = "",
        poc: str = "",
        confidence: str = "medium",
        evidence_level: str = "suspicion",
        crypto_protocol: str = "",
        algorithm: str = "",
        crypto_attack_class: str = "",
        key_material_exposed: str = "",
        **_: object,
    ) -> str:
        """Record a finding into the analyzer's state.

        Only ``description`` is required. Every other field has a sensible
        default so that smaller LLMs (qwen3.6, llama-3.3, etc.) can call
        ``record_finding`` even when they forget to fill in `severity`,
        `cwe`, `finding_type`, etc. The downstream Finding shape tolerates
        empty/default values; we trade some metadata fidelity for run
        completion robustness.

        Args:
            description: One- or two-sentence description of the bug. Required.
            file: Repo-relative file path where the finding lives. Defaults
                to the analyzer's file_path if available, else "".
            finding_type: e.g. sql_injection, memory_safety, timing_side_channel.
                Defaults to "unknown".
            severity: critical / high / medium / low / info. Defaults to "medium".
            cwe: CWE identifier (e.g. CWE-89, CWE-787, CWE-208).
            line_number: 1-indexed line number. Defaults to 0 (unknown).
            code_snippet: Relevant code snippet (helpful for triage).
            crash_evidence: Sanitizer/PoC output if available.
            poc: Proof-of-concept input.
            confidence: high / medium / low. Defaults to "medium".
            evidence_level: One of [suspicion, static_corroboration,
                parameter_anomaly, timing_confirmed, crash_reproduced,
                root_cause_explained, assumption_broken, exploit_demonstrated,
                key_material_recovered, patch_validated]. Defaults to suspicion.
            crypto_protocol: Crypto protocol name (e.g. SRP-6a, TLS 1.3).
            algorithm: Algorithm name (e.g. PBKDF2-HMAC-SHA256, AES-256-GCM).
            crypto_attack_class: Attack class (e.g. timing_side_channel,
                parameter_validation, nonce_reuse, padding_oracle).
            key_material_exposed: Description of key material at risk.
        """
        # If the analyzer didn't pass a file path, fall back to the context's
        # file_path (the analyzer is per-file, so we know it).
        if not file:
            file = getattr(ctx, "file_path", "") or ""

        # reject non-findings at the boundary. Small local models sometimes
        # repurpose record_finding as a scratchpad ("placeholder init", "loading
        # state", "checking existing state", ...). Drop a record with no real
        # description, or with no locus at all AND no classification, before it
        # costs a skeptic call and pollutes the pool. Runs AFTER the file fallback
        # so a real finding that merely omitted `file` is not wrongly rejected.
        desc = (description or "").strip()
        if not desc:
            return "Not recorded: a finding needs a non-empty `description`."
        has_locus = bool(file) or int(line_number or 0) > 0
        classified = (finding_type not in ("", "unknown")) or bool(cwe)
        if not has_locus and not classified:
            return (
                "Not recorded: this looks like a scratchpad note, not a finding "
                "(no file/line and no finding_type/cwe). Record a real finding with a "
                "concrete locus, or omit it."
            )

        finding = Finding(
            id=f"analyzer-{uuid.uuid4().hex[:8]}",
            file=file,
            line_number=line_number,
            finding_type=finding_type,
            cwe=cwe,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            description=description,
            code_snippet=code_snippet,
            crash_evidence=crash_evidence or None,
            poc=poc or None,
            evidence_level=evidence_level,  # type: ignore[arg-type]
            discovered_by=f"analyzer:{ctx.specialist}",
            seeded_from_crash=ctx.seeded_crash is not None,
            hunter_session_id=ctx.session_id or "",
            crypto_protocol=crypto_protocol or None,
            algorithm=algorithm or None,
            crypto_attack_class=crypto_attack_class or None,
            key_material_exposed=key_material_exposed or None,
        )
        ctx.findings.append(finding)
        return (
            f"Finding recorded: {finding_type} at {file}:{line_number} "
            f"(severity={severity}, evidence_level={evidence_level})"
        )

    return [
        NativeToolSpec(
            name="record_finding",
            description=(
                "Record a verified or suspected finding into the analyzer "
                "state. Only `description` is strictly required; every "
                "other field has a sensible default."
            ),
            schema={
                "type": "object",
                "properties": {
                    "description": {"type": "string"},
                    "file": {"type": "string", "default": ""},
                    "finding_type": {"type": "string", "default": "unknown"},
                    "severity": {"type": "string", "default": "medium"},
                    "cwe": {"type": "string", "default": ""},
                    "line_number": {"type": "integer", "default": 0},
                    "code_snippet": {"type": "string", "default": ""},
                    "crash_evidence": {"type": "string", "default": ""},
                    "poc": {"type": "string", "default": ""},
                    "confidence": {"type": "string", "default": "medium"},
                    "evidence_level": {"type": "string", "default": "suspicion"},
                    "crypto_protocol": {"type": "string", "default": ""},
                    "algorithm": {"type": "string", "default": ""},
                    "crypto_attack_class": {"type": "string", "default": ""},
                    "key_material_exposed": {"type": "string", "default": ""},
                },
                "required": [],
            },
            handler=record_finding,
        )
    ]
