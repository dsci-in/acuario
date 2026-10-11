"""Independent-context reviewer agent for scanner findings.

The reviewer takes a single Finding from a analyzer and decides whether
it's real. In adversarial mode the reviewer is required to steel-man both
sides. An optional patch-oracle truth test writes a minimal defensive fix,
recompiles, and re-runs the PoC. If the crash disappears the root cause theory
is causally validated; if it survives, the theory is suspect and should bounce
back to the analyzer.

Independence: the reviewer never sees the analyzer's reasoning messages. Only
the finding dict and the file content. This is enforced at the orchestration
level (the runner builds a fresh agent per finding).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from itertools import islice
from typing import cast

from acuario.findings.types import Severity
from acuario.llm import AsyncLLMClient

from .state import EVIDENCE_LEVELS, EvidenceLevel, Finding, evidence_at_or_above

logger = logging.getLogger(__name__)

_LINE_REF_RE = re.compile(r"\blines?\s+(\d+)(?:\s*-\s*(\d+))?")


# --- Reviewer prompts -------------------------------------------------------


VERIFIER_SYSTEM_PROMPT_V01 = """You are an independent reviewer checking whether a vulnerability report from another agent is real.

You did NOT find this bug. Your job is to confirm or refute it from a fresh perspective. You have access to the project source code and a sandbox.

Please:
1. Reproduce the bug using the provided proof-of-concept (if any).
2. Confirm the crash / behavior is genuine (or refute it).
3. Assess whether this is exploitable in production or just an edge case.
4. Rate severity: critical / high / medium / low / info.
5. Flag if this looks like a duplicate of a known CVE.

Return ONLY a JSON object, no other text:
{
  "is_real": true|false,
  "severity": "critical|high|medium|low|info",
  "evidence_level": "static_corroboration|crash_reproduced|root_cause_explained",
  "pro_argument": "one paragraph of why this IS a vulnerability",
  "counter_argument": "",
  "tie_breaker": "what evidence resolved it",
  "duplicate_cve": null
}
"""


PATCH_ORACLE_PROMPT = """You are writing a MINIMAL DEFENSIVE FIX for a verified vulnerability. This is a TRUTH TEST - not a production patch. If your fix eliminates the crash, that confirms the root cause theory. If the crash survives, the theory is suspect.

The fix MUST:
1. Be the smallest diff that could plausibly eliminate the crash.
2. Change ONLY the target file. No cross-file edits.
3. Apply an obvious defensive pattern: widen a bound, add a guard, initialize a default, check for NULL, validate a length.
4. NOT change the function signature.
5. NOT rewrite the function from scratch.
6. NOT delete the vulnerable code path.

You'll be given:
- The verified finding (file, line, description, crash evidence)
- The current source of the file

Return ONLY a JSON object:
{
  "diff": "unified-diff text (or the full new function if a unified diff is impractical)",
  "fix_description": "one sentence - what the fix does and why",
  "confidence": "high|medium|low - how confident that this will stop the crash"
}

Do NOT return anything else."""


# Adversarial mode - schema unchanged
VERIFIER_SYSTEM_PROMPT_V02 = """You are an independent reviewer. A analyzer has reported a finding. Your job is NOT to confirm it - your job is to STEEL-MAN BOTH SIDES and determine which is correct.

1. PRO-VULNERABILITY ARGUMENT
   Construct the strongest possible case that this IS a real, exploitable vulnerability. Reproduce the crash if there's a PoC. Identify the root cause precisely. Rate severity assuming the worst plausible exploit.

2. COUNTER-ARGUMENT (steel-manned)
   Construct the strongest possible case that this is NOT a real vulnerability or that severity is overstated. Specifically check:
     a. Is the crash caused by harness misuse (caller never passes these inputs in production)?
     b. Is the code path actually reachable from any real entry point?
     c. Do invariants enforced elsewhere in the codebase neutralize this?
     d. Is the severity overstated? Mitigating context?
     e. Is this a duplicate of a known CVE that's already mitigated?

3. TIE-BREAKER
   What single piece of evidence (a specific call site, a unit test, an invariant in a file you haven't read yet) would resolve the disagreement? GO LOOK FOR IT.

4. VERDICT
   Return ONLY a JSON object:
   {
     "is_real": true|false,
     "severity": "critical|high|medium|low",
     "evidence_level": "crash_reproduced|root_cause_explained",
     "pro_argument": "max 200 words",
     "counter_argument": "max 200 words",
     "tie_breaker": "what evidence resolved it",
     "duplicate_cve": null
   }
"""


# --- Result -----------------------------------------------------------------


@dataclass
class VerifierResult:
    """Output of a single reviewer run."""

    finding_id: str
    is_real: bool
    severity_verified: str | None
    evidence_level: EvidenceLevel
    pro_argument: str
    counter_argument: str
    tie_breaker: str
    duplicate_cve: str | None
    raw_response: str = ""


# --- Reviewer agent ---------------------------------------------------------


class Reviewer:
    """Independent-context reviewer for scanner findings.

    VERIFIER_SYSTEM_PROMPT_V01 is the non-adversarial prompt;
    VERIFIER_SYSTEM_PROMPT_V02 is the adversarial steel-man prompt.
    A per-finding budget gate: when `adversarial_threshold` is set,
    the reviewer only spends adversarial-prompt budget on findings whose
    evidence level is AT OR ABOVE the threshold. Below the gate, it falls
    back to the cheaper V01 prompt for that one call.

    The output schema is identical in both modes - V01 just leaves the
    counter_argument field empty.
    """

    def __init__(
        self,
        llm: AsyncLLMClient,
        adversarial: bool = False,
        adversarial_threshold: EvidenceLevel | None = "static_corroboration",
    ):
        self.llm = llm
        self.adversarial = adversarial
        # None disables the gate - adversarial runs on every finding when set.
        # The default threshold matches the plan: only spend steel-man budget
        # on findings with at least static corroboration (e.g. a Semgrep hit,
        # SourceAnalyzer regex match, or a analyzer-recorded static finding).
        self.adversarial_threshold = adversarial_threshold
        # Keep the "base" prompt for backwards compat - the per-call prompt
        # is selected in verify() based on the gate.
        self._system_prompt = (
            VERIFIER_SYSTEM_PROMPT_V02 if adversarial else VERIFIER_SYSTEM_PROMPT_V01
        )

    def _prompt_for_finding(self, finding: Finding) -> str:
        """Pick the prompt per-finding, respecting the adversarial budget gate."""
        if not self.adversarial:
            return VERIFIER_SYSTEM_PROMPT_V01
        if self.adversarial_threshold is None:
            return VERIFIER_SYSTEM_PROMPT_V02
        level = cast(EvidenceLevel, finding.get("evidence_level", "suspicion"))
        try:
            gated = evidence_at_or_above(level, self.adversarial_threshold)
        except KeyError:
            # Unknown evidence level → treat as below the gate (fail cheap)
            gated = False
        return VERIFIER_SYSTEM_PROMPT_V02 if gated else VERIFIER_SYSTEM_PROMPT_V01

    async def averify(
        self,
        finding: Finding,
        file_content: str = "",
    ) -> VerifierResult:
        """Run a single verification pass on one finding.

        The reviewer sees ONLY the finding dict and (optionally) the file
        content. It does NOT see the analyzer's message history - that's the
        independence guarantee.
        """
        user_msg = self._build_user_message(finding, file_content)
        system_prompt = self._prompt_for_finding(finding)
        try:
            response = await self.llm.aask_text(system=system_prompt, user=user_msg)
            content = response.first_text() or ""
        except Exception as e:
            logger.warning("Reviewer LLM call failed", exc_info=True)
            return VerifierResult(
                finding_id=finding.get("id", "unknown"),
                is_real=False,
                severity_verified=None,
                evidence_level="suspicion",
                pro_argument="",
                counter_argument="",
                tie_breaker=f"reviewer error: {e}",
                duplicate_cve=None,
            )

        return self._parse_response(finding, content)

    def _build_user_message(self, finding: Finding, file_content: str) -> str:
        # Note: we deliberately do NOT include the analyzer's reasoning chain
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
            "discovered_by": finding.get("discovered_by"),
        }
        msg = "Verify the following bug report:\n\n"
        msg += json.dumps(finding_view, indent=2)
        if file_content:
            excerpts = self._build_file_context(finding, file_content)
            if excerpts:
                msg += f"\n\nRelevant file excerpts:\n{excerpts}"
        return msg

    def _build_file_context(self, finding: Finding, file_content: str) -> str:
        lines = file_content.splitlines()
        if not lines:
            return ""

        requested_lines = self._line_refs_from_finding(finding)
        windows = self._merge_windows(
            [
                (
                    max(1, line_number - 24),
                    min(len(lines), line_number + 24),
                )
                for line_number in requested_lines
                if 1 <= line_number <= len(lines)
            ]
        )

        excerpts: list[str] = []
        total_chars = 0
        for start, end in islice(windows, 6):
            header = f"--- lines {start}-{end} ---"
            body = "\n".join(
                f"{line_no:5d}: {lines[line_no - 1]}" for line_no in range(start, end + 1)
            )
            chunk = f"{header}\n{body}"
            total_chars += len(chunk)
            if total_chars > 12000 and excerpts:
                break
            excerpts.append(chunk)

        if excerpts:
            return "\n\n".join(excerpts)

        capped = file_content[:8000]
        return f"--- file head (fallback, capped to 8 KB) ---\n{capped}"

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
        for field in text_fields:
            for match in _LINE_REF_RE.finditer(field):
                start = int(match.group(1))
                end = int(match.group(2) or start)
                refs.extend(range(start, min(end, start + 6) + 1))

        # Preserve order while deduplicating.
        seen: set[int] = set()
        ordered: list[int] = []
        for ref in refs:
            if ref not in seen:
                seen.add(ref)
                ordered.append(ref)
        return ordered

    def _merge_windows(self, windows: list[tuple[int, int]]) -> list[tuple[int, int]]:
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

    def _parse_response(self, finding: Finding, content: str) -> VerifierResult:
        match = re.search(r"\{[\s\S]*\}", content)
        if not match:
            logger.warning("Reviewer response had no JSON object; got: %s", content[:300])
            return self._error_result(finding, content, "no JSON in response")
        try:
            parsed = json.loads(match.group(0))
        except json.JSONDecodeError:
            return self._error_result(finding, content, "JSON parse failed")

        is_real = bool(parsed.get("is_real", False))
        severity = parsed.get("severity")
        if severity not in ("critical", "high", "medium", "low", "info", None):
            severity = None
        evidence_level = parsed.get("evidence_level", "suspicion")
        if evidence_level not in EVIDENCE_LEVELS:
            evidence_level = "suspicion"

        return VerifierResult(
            finding_id=finding.get("id", "unknown"),
            is_real=is_real,
            severity_verified=severity if is_real else None,
            evidence_level=evidence_level,
            pro_argument=str(parsed.get("pro_argument", "")),
            counter_argument=str(parsed.get("counter_argument", "")),
            tie_breaker=str(parsed.get("tie_breaker", "")),
            duplicate_cve=parsed.get("duplicate_cve"),
            raw_response=content,
        )

    def _error_result(
        self,
        finding: Finding,
        raw: str,
        reason: str,
    ) -> VerifierResult:
        return VerifierResult(
            finding_id=finding.get("id", "unknown"),
            is_real=False,
            severity_verified=None,
            evidence_level="suspicion",
            pro_argument="",
            counter_argument="",
            tie_breaker=reason,
            duplicate_cve=None,
            raw_response=raw,
        )


def apply_verifier_result(
    finding: Finding,
    result: VerifierResult,
    session_id: str | None = None,
) -> Finding:
    """Merge a VerifierResult into a Finding (in-place + return).

    Delegates to ``finding.mark_verified()`` and ``finding.bump_evidence()``
    for the actual mutation when *finding* is a Finding dataclass. Falls back
    to dict-style assignment for plain-dict callers (legacy tests / callers).
    """
    if isinstance(finding, Finding):
        finding.mark_verified(
            is_real=result.is_real,
            severity_verified=cast("Severity | None", result.severity_verified),
            evidence_level=result.evidence_level,
            pro_argument=result.pro_argument,
            counter_argument=result.counter_argument,
            tie_breaker=result.tie_breaker,
            session_id=session_id,
        )
    else:
        # Legacy dict path
        finding["verified"] = result.is_real
        finding["severity_verified"] = result.severity_verified
        finding["verifier_pro_argument"] = result.pro_argument
        finding["verifier_counter_argument"] = result.counter_argument
        finding["verifier_tie_breaker"] = result.tie_breaker
        finding["verifier_session_id"] = session_id
        current = finding.get("evidence_level", "suspicion")
        if current not in EVIDENCE_LEVELS:
            current = "suspicion"
        new = result.evidence_level
        if new not in EVIDENCE_LEVELS:
            new = "suspicion"
        if EVIDENCE_LEVELS.index(new) > EVIDENCE_LEVELS.index(current):
            finding["evidence_level"] = new
    return finding
