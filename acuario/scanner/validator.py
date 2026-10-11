"""Unified 4-axis validator.

A single stage evaluating: REAL, TRIGGERABLE, IMPACTFUL, GENERAL. The
Reviewer class in reviewer.py remains available.

Independence guarantee: the validator sees ONLY the finding report, PoC,
and exploit - never the discovery agent's transcript or reasoning chain.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from itertools import islice
from typing import cast

from acuario.core.event_payloads import ValidationResultPayload
from acuario.core.events import EventBus
from acuario.llm import AsyncLLMClient

from .state import (
    EVIDENCE_LEVELS,
    AxisResult,
    EvidenceLevel,
    Finding,
    ValidatorVerdict,
    evidence_at_or_above,
)

logger = logging.getLogger(__name__)

_LINE_REF_RE = re.compile(r"\blines?\s+(\d+)(?:\s*-\s*(\d+))?")

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

_VALID_CONFIDENCES = {"high", "medium", "low"}

_VALID_BOUNDARIES = {
    "privilege",
    "tenant",
    "origin",
    "user",
    "kernel",
    "sandbox",
    "none",
}


# --- Prompts -----------------------------------------------------------------


VALIDATOR_SYSTEM_PROMPT = """\
You are an INDEPENDENT VALIDATOR. A discovery agent reported a potential \
vulnerability. You did NOT find this bug. Your job is to determine whether \
it is real and interesting by evaluating four axes.

For each axis, build the STRONGEST possible counter-argument, then decide.

## AXIS 1: REAL
Does this bug actually exist in the code as described? Reproduce the crash \
or behavior if a PoC is provided. Run it. Is the root cause what the report \
claims, or is the analysis wrong?

## AXIS 2: TRIGGERABLE
Can attacker-controlled input reach this code path in a production deployment?
- Is this reachable from any external entry point (network, file parsing, IPC)?
- Do callers enforce invariants that prevent the dangerous input?
- Is the function dead code or only called from test harnesses?

## AXIS 3: IMPACTFUL
Does this cross a meaningful security boundary?
- Privilege escalation, tenant isolation, cross-origin, user boundary, \
kernel/user, sandbox escape?
- Or is it same-origin / same-process with no escalation?
- Is severity proportional to actual impact, or overstated?

## AXIS 4: GENERAL
Is this exploitable in realistic configurations?
- Default configs? Common deployment patterns?
- Or does it require exotic compile flags, deprecated features, unusual setup?

## REPRODUCTION (MANDATORY)
If a PoC is provided, you MUST attempt to reproduce it. Report the exact result.

## OUTPUT - return ONLY this JSON:
{
  "axes": {
    "REAL": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "..."},
    "TRIGGERABLE": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "..."},
    "IMPACTFUL": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "...", \
"boundary_crossed": "privilege|tenant|origin|user|kernel|sandbox|none"},
    "GENERAL": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "..."}
  },
  "advance": true|false,
  "severity": "critical|high|medium|low|info",
  "evidence_level": "static_corroboration|crash_reproduced|root_cause_explained",
  "pro_argument": "max 200 words - strongest case FOR the vulnerability",
  "counter_argument": "max 200 words - strongest case AGAINST",
  "tie_breaker": "what single piece of evidence resolved it",
  "duplicate_cve": null
}

A finding advances ONLY if all four axes pass, or if REAL + IMPACTFUL pass \
and TRIGGERABLE + GENERAL have confidence >= medium with stated assumptions."""


VALIDATOR_QUICK_PROMPT = """\
You are a quick-pass validator. Check ONLY whether:

1. REAL - does this bug exist in the code as described? If there is a PoC, \
reproduce it.
2. TRIGGERABLE - is this code path reachable from attacker-controlled input \
in a production deployment?

If BOTH pass, the finding advances to full validation. If either fails, reject.

Return ONLY this JSON:
{
  "axes": {
    "REAL": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "..."},
    "TRIGGERABLE": {"passed": true|false, "confidence": "high|medium|low", \
"rationale": "..."}
  },
  "advance": true|false,
  "severity": "critical|high|medium|low|info",
  "evidence_level": "static_corroboration|crash_reproduced|root_cause_explained",
  "pro_argument": "one paragraph",
  "counter_argument": "one paragraph",
  "tie_breaker": "what evidence resolved it",
  "duplicate_cve": null
}"""


# --- Validator class ---------------------------------------------------------


class Validator:
    """Unified 4-axis validator.

    Uses a single prompt that evaluates REAL, TRIGGERABLE, IMPACTFUL, and
    GENERAL axes independently. The budget gate selects between the full
    4-axis prompt and a cheaper 2-axis quick-pass for low-evidence findings.
    """

    def __init__(
        self,
        llm: AsyncLLMClient,
        *,
        gate_threshold: EvidenceLevel | None = "static_corroboration",
        enable_quick_pass: bool = True,
        enable_severity_recalibration: bool = False,
    ):
        self.llm = llm
        self.gate_threshold = gate_threshold
        self.enable_quick_pass = enable_quick_pass
        # deterministic, rule-based severity recalibration from the 4-axis
        # confidences. Off by default - opt-in until validated against ground
        # truth. NOT an LLM call: pure rules over AxisResult.confidence.
        self.enable_severity_recalibration = enable_severity_recalibration

    def _prompt_for_finding(self, finding: Finding) -> str:
        if not self.enable_quick_pass:
            return VALIDATOR_SYSTEM_PROMPT
        if self.gate_threshold is None:
            return VALIDATOR_SYSTEM_PROMPT
        level = cast(EvidenceLevel, finding.get("evidence_level", "suspicion"))
        try:
            above = evidence_at_or_above(level, self.gate_threshold)
        except KeyError:
            above = False
        return VALIDATOR_SYSTEM_PROMPT if above else VALIDATOR_QUICK_PROMPT

    async def avalidate(
        self,
        finding: Finding,
        file_content: str = "",
        cross_file_context: str = "",
    ) -> ValidatorVerdict:
        user_msg = self._build_user_message(finding, file_content, cross_file_context)
        system_prompt = self._prompt_for_finding(finding)

        # retry the reviewer call when the LLM returns an empty body.
        # The LLM transport layer (_with_rate_limit_retries) already covers
        # network/rate-limit failures; this loop catches successful HTTP
        # responses that contain no usable text.
        max_attempts = 3
        content = ""
        for attempt in range(max_attempts):
            try:
                response = await self.llm.aask_text(
                    system=system_prompt,
                    user=user_msg,
                )
                content = response.first_text() or ""
            except Exception as e:
                logger.warning("Validator LLM call failed", exc_info=True)
                if attempt + 1 >= max_attempts:
                    return self._error_verdict(finding, f"validator error: {e}")
                await asyncio.sleep(1.0 * (2**attempt))
                continue

            if content.strip():
                break

            # Empty body - retry with exponential backoff before falling
            # through to the parse path (which would log "no JSON" and
            # emit an error verdict).
            if attempt + 1 < max_attempts:
                logger.warning(
                    "Validator returned empty response (attempt %d/%d); retrying",
                    attempt + 1,
                    max_attempts,
                )
                await asyncio.sleep(1.0 * (2**attempt))

        verdict = self._parse_response(finding, content)

        EventBus().emit_validation_result(
            ValidationResultPayload(
                finding_id=verdict.finding_id,
                axes={name: ar.passed for name, ar in verdict.axes.items()},
                advance=verdict.advance,
                severity=verdict.severity_validated,
                evidence_level=verdict.evidence_level,
            )
        )

        return verdict

    def _build_user_message(
        self, finding: Finding, file_content: str, cross_file_context: str = ""
    ) -> str:
        finding_view = {
            "id": finding.get("id"),
            "file": finding.get("file"),
            "line_number": finding.get("line_number"),
            "finding_type": finding.get("finding_type"),
            "cwe": finding.get("cwe"),
            "severity_proposed": finding.get("severity"),
            "description": finding.get("description"),
            "code_snippet": finding.get("code_snippet"),
            "crash_evidence": finding.get("crash_evidence"),
            "poc": finding.get("poc"),
            "exploit": finding.get("exploit"),
            "discovered_by": finding.get("discovered_by"),
        }
        # surface the skeptic's unrefuted doubt so the validator weighs it
        # on the TRIGGERABLE / REAL axes instead of treating the finding as
        # unchallenged.
        if finding.get("skeptic_flag") == "uncertain":
            finding_view["skeptic_doubt"] = finding.get("skeptic_doubt", "")
        msg = "Validate the following bug report:\n\n"
        msg += json.dumps(finding_view, indent=2)
        if file_content:
            excerpts = self._build_file_context(finding, file_content)
            if excerpts:
                msg += f"\n\nRelevant file excerpts:\n{excerpts}"
        # the same callers/callees/imports block the skeptic and critic
        # get - so the validator judges TRIGGERABLE (is this reachable from
        # attacker input?) and IMPACTFUL from real cross-file reachability
        # instead of guessing from the single file.
        if cross_file_context:
            msg += f"\n\nKnown cross-file context for this file:\n{cross_file_context[:3000]}"
        return msg

    def _build_file_context(self, finding: Finding, file_content: str) -> str:
        lines = file_content.splitlines()
        if not lines:
            return ""

        requested_lines = self._line_refs_from_finding(finding)
        windows = self._merge_windows(
            [
                (max(1, ln - 24), min(len(lines), ln + 24))
                for ln in requested_lines
                if 1 <= ln <= len(lines)
            ]
        )

        excerpts: list[str] = []
        total_chars = 0
        # Outcome-quality: bumped 6 → 12 windows and 12 KB → 24 KB total.
        # The validator's 4-axis verdict is what determines `verified=True`,
        # so a finding that spans multiple call sites (e.g. source at line
        # 10, sink at line 200, mitigation check at line 400) needs all
        # three windows visible.  At 24 KB total we still fit comfortably
        # in a 32 KB context with room for the prompt + LLM response.
        for start, end in islice(windows, 12):
            header = f"--- lines {start}-{end} ---"
            body = "\n".join(f"{n:5d}: {lines[n - 1]}" for n in range(start, end + 1))
            chunk = f"{header}\n{body}"
            total_chars += len(chunk)
            if total_chars > 24000 and excerpts:
                break
            excerpts.append(chunk)

        if excerpts:
            return "\n\n".join(excerpts)

        # Outcome-quality: when no line references are extractable (a rare,
        # malformed-finding case), bumped the fallback head from 8 KB → 24 KB
        # so the validator at least sees the same amount of source it would
        # have seen via windowed extraction.
        capped = file_content[:24000]
        return f"--- file head (fallback, capped to 24 KB) ---\n{capped}"

    def _line_refs_from_finding(self, finding: Finding) -> list[int]:
        refs: list[int] = []
        for key in ("line_number", "end_line"):
            value = finding.get(key)
            if isinstance(value, int) and value > 0:
                refs.append(value)
        text_fields = [
            str(finding.get("description") or ""),
            str(finding.get("code_snippet") or ""),
            str(finding.get("crash_evidence") or ""),
        ]
        for f in text_fields:
            for match in _LINE_REF_RE.finditer(f):
                start = int(match.group(1))
                end = int(match.group(2) or start)
                refs.extend(range(start, min(end, start + 6) + 1))
        seen: set[int] = set()
        ordered: list[int] = []
        for ref in refs:
            if ref not in seen:
                seen.add(ref)
                ordered.append(ref)
        return ordered

    def _merge_windows(
        self,
        windows: list[tuple[int, int]],
    ) -> list[tuple[int, int]]:
        if not windows:
            return []
        merged: list[tuple[int, int]] = []
        for start, end in sorted(windows):
            if not merged or start > merged[-1][1] + 5:
                merged.append((start, end))
                continue
            prev_start, prev_end = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end))
        return merged

    def _parse_response(
        self,
        finding: Finding,
        content: str,
    ) -> ValidatorVerdict:
        match = re.search(r"\{[\s\S]*\}", content)
        if not match:
            logger.warning(
                "Validator response had no JSON; got: %s",
                content[:300],
            )
            return self._error_verdict(finding, "no JSON in response")
        try:
            parsed = json.loads(match.group(0))
        except json.JSONDecodeError:
            return self._error_verdict(finding, "JSON parse failed")

        axes = self._parse_axes(parsed.get("axes", {}))
        advance = bool(parsed.get("advance", False))

        severity = parsed.get("severity")
        if severity not in _VALID_SEVERITIES:
            severity = None

        evidence_level = parsed.get("evidence_level", "suspicion")
        if evidence_level not in EVIDENCE_LEVELS:
            evidence_level = "suspicion"

        severity_validated = severity if advance else None
        recal, recal_reason = (None, "")
        if self.enable_severity_recalibration and severity_validated:
            recal, recal_reason = self._recalibrate_severity(severity_validated, axes)

        return ValidatorVerdict(
            finding_id=finding.get("id", "unknown"),
            axes=axes,
            advance=advance,
            severity_validated=severity_validated,
            evidence_level=evidence_level,
            pro_argument=str(parsed.get("pro_argument", "")),
            counter_argument=str(parsed.get("counter_argument", "")),
            tie_breaker=str(parsed.get("tie_breaker", "")),
            duplicate_cve=parsed.get("duplicate_cve"),
            raw_response=content,
            severity_recalibrated=recal,
            severity_recalibration_reason=recal_reason,
        )

    # Most-severe first; index is the rank (lower = more severe).
    _SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

    @classmethod
    def _recalibrate_severity(
        cls, claimed: str, axes: dict[str, AxisResult]
    ) -> tuple[str | None, str]:
        """O6: deterministically cap a verified finding's severity using the
        4-axis confidences. Returns (recalibrated_severity, reason), or
        (None, "") when no adjustment applies.

        Rules (only ever *cap* - never raise the analyzer's claim):
        - IMPACTFUL failed        → cap at "low"   (little real impact)
        - TRIGGERABLE failed      → cap at "medium" (hard to reach)
        - TRIGGERABLE low-confidence pass → cap at "high" (reachability shaky)
        - every present axis passed only at "low" confidence → drop one rank
        """
        order = cls._SEVERITY_ORDER
        if claimed not in order:
            return None, ""
        idx = order.index(claimed)

        def cap_to(ceiling: str) -> int:
            return max(idx, order.index(ceiling))

        new_idx = idx
        reasons: list[str] = []
        # Track whether a *hard* cap (a failed axis) fired. The soft
        # "all-axes-low-confidence → −1 rank" rule should apply only when no
        # failed axis already pinned the severity down - but it must NOT be
        # gated on ``new_idx == idx``, because the soft TRIGGERABLE-low-confidence
        # cap below also moves new_idx and would otherwise make this rule
        # unreachable (review finding O6).
        hard_capped = False

        impactful = axes.get("IMPACTFUL")
        triggerable = axes.get("TRIGGERABLE")

        if impactful is not None and not impactful.passed:
            c = cap_to("low")
            if c != new_idx:
                new_idx = max(new_idx, c)
                reasons.append("IMPACTFUL failed → cap low")
            hard_capped = True
        if triggerable is not None and not triggerable.passed:
            c = cap_to("medium")
            if c > new_idx:
                new_idx = c
                reasons.append("TRIGGERABLE failed → cap medium")
            hard_capped = True

        # Soft rule: every present axis passed only at low confidence → drop one
        # rank. Independent of the soft TRIGGERABLE cap below; only suppressed
        # when a failed axis already hard-capped the severity.
        present = [ax for ax in axes.values() if ax.passed]
        if present and all(ax.confidence == "low" for ax in present) and not hard_capped:
            if new_idx < len(order) - 1:
                new_idx += 1
                reasons.append("all axes low-confidence → −1 rank")

        # Soft rule: TRIGGERABLE passed but only at low confidence → reachability
        # is shaky, cap at high. Runs last so it can tighten further if needed.
        if (
            not hard_capped
            and triggerable is not None
            and triggerable.passed
            and triggerable.confidence == "low"
        ):
            c = cap_to("high")
            if c > new_idx:
                new_idx = c
                reasons.append("TRIGGERABLE passed at low confidence → cap high")

        if new_idx == idx:
            return None, ""
        return order[new_idx], "; ".join(reasons)

    def _parse_axes(self, axes_raw: dict) -> dict[str, AxisResult]:
        axes: dict[str, AxisResult] = {}
        for name in ("REAL", "TRIGGERABLE", "IMPACTFUL", "GENERAL"):
            data = axes_raw.get(name)
            if data and isinstance(data, dict):
                conf = data.get("confidence", "low")
                if conf not in _VALID_CONFIDENCES:
                    conf = "low"
                boundary = data.get("boundary_crossed", "")
                if boundary and boundary not in _VALID_BOUNDARIES:
                    boundary = ""
                axes[name] = AxisResult(
                    axis=name,
                    passed=bool(data.get("passed", False)),
                    confidence=conf,
                    # J2 refinement: keep the reviewer's full per-axis
                    # reasoning.  The LLM already targets ~200 words via
                    # the prompt; the 500-char hard cap was an arbitrary
                    # additional truncation that lost the tail of useful
                    # explanations.
                    rationale=str(data.get("rationale", "")),
                    boundary_crossed=boundary,
                )
        return axes

    def _error_verdict(
        self,
        finding: Finding,
        reason: str,
    ) -> ValidatorVerdict:
        return ValidatorVerdict(
            finding_id=finding.get("id", "unknown"),
            axes={},
            advance=False,
            severity_validated=None,
            evidence_level="suspicion",
            pro_argument="",
            counter_argument="",
            tie_breaker=reason,
            duplicate_cve=None,
        )


# --- apply function ----------------------------------------------------------


def _bump_evidence(finding: Finding, new_level: EvidenceLevel) -> None:
    current = finding.get("evidence_level", "suspicion")
    if current not in EVIDENCE_LEVELS:
        current = "suspicion"
    if new_level not in EVIDENCE_LEVELS:
        return
    if EVIDENCE_LEVELS.index(new_level) > EVIDENCE_LEVELS.index(current):
        finding["evidence_level"] = new_level


def apply_validator_verdict(
    finding: Finding,
    verdict: ValidatorVerdict,
    session_id: str | None = None,
    discoverer_severity: str | None = None,
) -> Finding:
    """Merge a ValidatorVerdict into a Finding (in-place + return).

    Sets the same backward-compat fields as apply_verifier_result so
    downstream code that reads finding["verified"] etc. still works.
    """
    finding["verified"] = verdict.advance
    # prefer the deterministic recalibrated severity when present, but
    # record both so the analyzer's claim and the rule that adjusted it stay
    # auditable in the report / findings.json.
    if verdict.severity_recalibrated:
        finding["severity_verified"] = verdict.severity_recalibrated
        finding["severity_claimed"] = verdict.severity_validated
        finding["severity_recalibration_reason"] = verdict.severity_recalibration_reason
    else:
        finding["severity_verified"] = verdict.severity_validated
    finding["verifier_pro_argument"] = verdict.pro_argument
    finding["verifier_counter_argument"] = verdict.counter_argument
    finding["verifier_tie_breaker"] = verdict.tie_breaker
    finding["verifier_session_id"] = session_id
    finding["validation_mode"] = "v2"

    finding["validator_axes"] = {
        name: {
            "passed": ax.passed,
            "confidence": ax.confidence,
            "rationale": ax.rationale,
        }
        for name, ax in verdict.axes.items()
    }

    _bump_evidence(finding, verdict.evidence_level)

    if discoverer_severity and verdict.severity_validated:
        d = _SEVERITY_RANK.get(discoverer_severity, 0)
        v = _SEVERITY_RANK.get(verdict.severity_validated, 0)
        if abs(d - v) >= 2:
            finding["severity_disagreement"] = (
                f"discoverer={discoverer_severity} "
                f"validator={verdict.severity_validated} "
                f"delta={abs(d - v)}"
            )

    if not verdict.advance:
        failed = [name for name, ax in verdict.axes.items() if not ax.passed]
        finding["rejected_axes"] = failed

    return finding
