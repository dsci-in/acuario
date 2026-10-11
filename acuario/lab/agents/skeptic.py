"""Skeptic Gate - adversarial finding review agent.

For every finding emitted by an analyzer, the skeptic attempts to produce
a concrete refutation *before* the finding can enter the shared pool.  If
the skeptic fails to refute within its budget, the finding is accepted.

Design rationale
----------------
The existing Reviewer (acuario/scanner/reviewer.py) is a downstream,
single-shot plausibility judge.  The skeptic is adversarially different:

  1. It fires on *every* finding (not just a sample).
  2. It tries *hard* to kill the finding - its job is to find a reason
     the finding is wrong, not just to rate its plausibility.
  3. Its output is deterministic: "accepted" or "refuted" with a specific
     code reference that contradicts the claim.

A finding is accepted when:
  - The LLM skeptic fails to produce a coherent refutation, OR
  - The refutation is too vague (no concrete code reference), OR
  - Any exception occurs (fail-open for reliability).

Refuted findings are:
  - NOT added to the live findings pool.
  - Written to ``skeptic_refuted.jsonl`` alongside ``findings_pool.jsonl``
    for post-run inspection via ``acuario inspect``.

Usage
-----
The hook point is ``acuario/scanner/runner.py`` - after each analyzer
completes, the runner passes findings through ``SkepticGate.ascreen()``
before calling ``FindingsPool.add()``.

Toggle: ``--no-skeptic-gate`` (default: on).
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# On-disk excerpt caps for skeptic_log.jsonl.  ``None`` disables the cap -
# every byte the LLM returned is recorded verbatim.
_PROMPT_EXCERPT_MAX: int | None = None
_RESPONSE_EXCERPT_MAX: int | None = None

# Live terminal / audit.log summary length.  This is what scrolls past you
# during a run - kept short so each refusal occupies at most one wrapped
# terminal line and the live log stays scannable.  The FULL reasoning is
# always preserved in skeptic_log.jsonl and rendered uncapped in
# team_discussion.md - read those when you want the complete refutation.
_LIVE_LOG_SUMMARY_MAX = 200


def _summarize_for_log(reasoning: str) -> str:
    """Return a clean one-line summary of a longer reasoning string.

    Picks the first sentence (split on ``. ``) when that's a reasonable
    length, otherwise hard-caps at ``_LIVE_LOG_SUMMARY_MAX`` chars.  Newlines
    are collapsed to single spaces so a multi-line reasoning still fits one
    log line.  Appends ``…`` when the original was truncated.
    """
    if not reasoning:
        return ""
    flat = " ".join(reasoning.split())  # collapse newlines + runs of whitespace
    period_idx = flat.find(". ")
    if 30 <= period_idx <= _LIVE_LOG_SUMMARY_MAX:
        head = flat[: period_idx + 1]
    else:
        head = flat[:_LIVE_LOG_SUMMARY_MAX]
    if len(head) < len(flat):
        head = head.rstrip() + "…"
    return head


_SKEPTIC_SYSTEM = """\
You are a security code review skeptic. Your job is to challenge vulnerability reports
and find concrete reasons why they might be false positives.

Given a reported vulnerability and the source context, you must:
1. Read the code carefully, especially around the reported location.
2. Look for mitigating controls: input validation, sanitization, framework protections,
   access controls, or type constraints that would prevent exploitation.
3. Check whether the reported vulnerability actually requires attacker-controlled input
   to reach the reported code path.
4. Check whether the described impact is actually achievable given the code context.

Your output MUST be valid JSON with exactly three fields:
  "verdict": "refuted" | "uncertain" | "accepted"
  "confidence": a number from 0.0 to 1.0 - how sure you are of the verdict
  "reasoning": "one to three sentences explaining your conclusion"

Verdict rules (read carefully - this is the most important instruction):
- "refuted": you found a CONCRETE reason the finding is a false positive AND you can point
  to the SPECIFIC code that proves it - the exact sanitizer/validation call, the exact
  parameterized-query construction, the exact access-control check on the reachable path.
  Cite it (line number or function name) in the reasoning.
- "uncertain": you suspect it might be a false positive, but your reason rests on a GENERAL
  assumption you CANNOT pin to specific code in front of you - e.g. "the framework probably
  escapes this", "this is usually only reached from trusted code", "an ORM typically
  parameterizes". These are guesses, not refutations.
- "accepted": you could not find any reason to doubt the finding.

A refutation that appeals to framework / library / ORM / upstream behavior WITHOUT citing
where that protection is actually invoked in THIS codebase is "uncertain", never "refuted".
Do not accept a finding just because it is hard to refute. Do not refute on hand-waving.

Credentials & secrets (per-value, O-W): disposition each secret VALUE on its own - never
blanket-refute a mixed config as "all mock/demo/placeholder". A value in a recognizable
credential FORMAT is a real secret regardless of "mock"/"test"/"client-side" framing:
GitHub tokens (ghp_ / gho_ / ghu_ / ghs_ / github_pat_), AWS keys (AKIA.../ASIA...), Google
API keys (AIza...), Slack tokens (xox[baprs]-...), private keys (-----BEGIN ... PRIVATE
KEY-----), and JWTs (eyJ...). Do NOT use "long high-entropy hex" as a lever in EITHER
direction - mock and test fixtures routinely ship fake 32/40-char hex, so entropy alone
proves nothing.

Client-side & server enforcement (O-W): a frontend / client-side finding is NOT refuted
merely because "the server probably enforces this". Assert server-side enforcement ONLY if
the server code proving it is in the context in front of you; otherwise that reasoning is
"uncertain", never "refuted". "It's only mock/demo data" refutes a finding only when the
data flow reaching the sink is provably developer-controlled with NO user-input path.
"""

_SKEPTIC_PROMPT = """\
## Finding to challenge

File: {file}:{line_number}
CWE: {cwe}
Severity: {severity}
Type: {finding_type}
Description: {description}

Code snippet:
```
{code_snippet}
```

{context_block}

Challenge this finding. Refute it ONLY if you can cite the specific code that makes it a
false positive; if your doubt rests on a general assumption you can't point to in the code,
say "uncertain".
Respond with JSON:
{{"verdict": "refuted"|"uncertain"|"accepted", "confidence": 0.0-1.0, "reasoning": "..."}}
"""


# --- debate / rebuttal round prompts ------------------------------------

_REBUTTAL_ANALYZER_SYSTEM = """\
You are the security analyst who reported a vulnerability. A skeptical reviewer has
REFUTED your finding. You get exactly one rebuttal. Defend the finding ONLY if you can
point to concrete evidence in the code or your investigation that the skeptic's
refutation is wrong or incomplete; otherwise concede honestly - a withdrawn false
positive is a good outcome.

Your output MUST be valid JSON with exactly two fields:
  "concede": true | false   (true = you accept the refutation and withdraw)
  "rebuttal": "your strongest evidence-backed argument, citing specific code / behavior"

Do not restate the original report. Address the skeptic's specific refutation. If your
only answer is a general assumption with no concrete code to point to, concede.
"""

_REBUTTAL_ANALYZER_PROMPT = """\
## Your finding
File: {file}:{line_number}  CWE: {cwe}  Severity: {severity}
Description: {description}

## Your investigation (trajectory excerpt)
{trajectory}

## The skeptic's refutation
{refutation}

{context_block}

Rebut or concede. Respond with JSON: {{"concede": true|false, "rebuttal": "..."}}
"""

_REBUTTAL_SKEPTIC_SYSTEM = """\
You are the skeptical reviewer who refuted a vulnerability finding. The analyst has
responded with a rebuttal. Decide your FINAL verdict honestly: does the rebuttal cite
concrete code/behavior that overturns your refutation, or does your refutation still
stand?

Your output MUST be valid JSON with exactly two fields:
  "final_verdict": "upheld" | "overturned"
    ("upheld" = your refutation stands, the finding stays refuted;
     "overturned" = the rebuttal is convincing, the finding should be reinstated)
  "reasoning": "one to three sentences"

Be honest, not stubborn. If the analyst pointed to concrete evidence you missed,
overturn. If the rebuttal is hand-waving with no concrete code, uphold.
"""

_REBUTTAL_SKEPTIC_PROMPT = """\
## The finding
File: {file}:{line_number}  CWE: {cwe}

## Your original refutation
{refutation}

## The analyst's rebuttal
{rebuttal}

Final verdict. Respond with JSON: {{"final_verdict": "upheld"|"overturned", "reasoning": "..."}}
"""


@dataclass
class RebuttalOutcome:
    """Result of one analyzer↔skeptic debate over a refuted finding."""

    finding_id: str
    file: str
    line_number: int | str
    refutation: str  # the skeptic's original refutation reasoning
    conceded: bool  # analyst withdrew
    rebuttal: str  # analyst's argument (empty if conceded with no text)
    final_verdict: str  # "upheld" | "overturned"
    reasoning: str  # skeptic's final reasoning
    reinstated: bool  # True when final_verdict == "overturned" (finding survives)
    _analyst_prompt_excerpt: str = field(default="", repr=False)
    _analyst_response_excerpt: str = field(default="", repr=False)
    _skeptic_prompt_excerpt: str = field(default="", repr=False)
    _skeptic_response_excerpt: str = field(default="", repr=False)
    _elapsed_seconds: float = field(default=0.0, repr=False)


@dataclass
class SkepticVerdict:
    """Result of a skeptic review."""

    verdict: str  # "accepted" | "refuted" | "uncertain"
    reasoning: str
    finding_id: str
    file: str
    line_number: int | str
    # The skeptic's self-reported confidence in the verdict (0.0-1.0).
    # Only "refuted" verdicts drop a finding; "uncertain" passes through with
    # a flag so the downstream validator weighs it instead of silently losing
    # a possible true positive to a hand-wave refutation.
    confidence: float = 1.0
    # Internal-use fields populated by _run_skeptic() for log persistence.
    # Not serialized to consumers; consumed only by _write_log_entry().
    _prompt_excerpt: str = field(default="", repr=False)
    _response_excerpt: str = field(default="", repr=False)
    _elapsed_seconds: float = field(default=0.0, repr=False)
    _cross_file_context_used: bool = field(default=False, repr=False)


class SkepticGate:
    """Adversarial gate between analyzer output and the findings pool.

    Parameters
    ----------
    llm : AsyncLLMClient
        The LLM client to use.  If None the gate is a no-op (all accepted).
    output_dir : Path | None
        Where to write ``skeptic_refuted.jsonl``.  None disables the file.
    max_refuted_per_session : int
        Cap on refuted findings written to disk (avoids unbounded file growth).
    """

    def __init__(
        self,
        llm: Any = None,
        output_dir: Path | None = None,
        *,
        max_refuted_per_session: int = 500,
        shadow_mode: bool = False,
    ) -> None:
        self._llm = llm
        self._output_dir = output_dir
        self._max_refuted = max_refuted_per_session
        # Shadow mode - the skeptic computes and LOGS its true verdict but
        # never gates (every finding passes through). This lets the downstream
        # validator act as ground truth for the skeptic's refutations, so a run
        # can measure the skeptic's false-negative rate without losing findings.
        self._shadow_mode = shadow_mode
        self._shadow_would_refute = 0
        self._shadow_would_uncertain = 0
        self._accepted = 0
        self._refuted = 0
        # Findings the skeptic doubted but couldn't refute with a concrete
        # code citation. They pass THROUGH to the pool (flagged) rather than
        # being dropped - a hand-wave shouldn't kill a possible true positive.
        self._uncertain = 0
        # Count of findings accepted because the LLM call failed (not
        # because the skeptic chose to accept). A non-zero value means the
        # gate was partially blind - surfaced in Pipeline Health.
        self._fail_open = 0
        # Debate / rebuttal round. When the skeptic refutes a finding, the
        # analyzer gets one evidence-backed rebuttal and the skeptic re-judges.
        # An overturned refutation reinstates the finding (advisory - the
        # downstream validator still judges it independently).
        self._debate_upheld = 0  # skeptic stood by the refutation
        self._debate_overturned = 0  # analyzer's rebuttal won; finding reinstated
        self._debate_failed = 0  # debate LLM call failed after retries (refutation stands)
        self._refuted_file: Path | None = None
        # Also persist every decision (accept + refute) with prompt/response
        # excerpts to a comprehensive skeptic_log.jsonl so the team-discussion
        # report can show the skeptic's reasoning for every finding.
        self._log_file: Path | None = None
        self._debate_file: Path | None = None
        if output_dir is not None:
            self._refuted_file = output_dir / "skeptic_refuted.jsonl"
            self._log_file = output_dir / "skeptic_log.jsonl"
            self._debate_file = output_dir / "debate_log.jsonl"

    @property
    def accepted_count(self) -> int:
        return self._accepted

    @property
    def refuted_count(self) -> int:
        return self._refuted

    @property
    def fail_open_count(self) -> int:
        """Findings accepted because the LLM call failed. Non-zero means
        the gate was blind for that many findings - a precision risk."""
        return self._fail_open

    @property
    def debate_overturned_count(self) -> int:
        """Refutations the analyst's rebuttal overturned (findings reinstated)."""
        return self._debate_overturned

    @property
    def debate_upheld_count(self) -> int:
        """Refutations the skeptic stood by after the rebuttal."""
        return self._debate_upheld

    async def ascreen(
        self,
        finding: Any,
        source_snippet: str = "",
        cross_file_context: str = "",
    ) -> SkepticVerdict:
        """Screen a single finding.

        Returns a SkepticVerdict.  If ``verdict == "accepted"`` the caller
        should pass the finding to the pool.  If ``verdict == "refuted"`` the
        caller should skip the pool (but can log to skeptic_refuted.jsonl).

        This method is fail-open: any LLM error → accepted.
        """
        fid = finding.get("id", "unknown")
        file_path = finding.get("file", "?")
        line = finding.get("line_number", "?")

        if self._llm is None:
            self._accepted += 1
            return SkepticVerdict(
                verdict="accepted",
                reasoning="no skeptic LLM configured",
                finding_id=fid,
                file=file_path,
                line_number=line,
            )

        # Outer retry around the run-skeptic body for parse-recoverable
        # failures.  The LLM client already retries transient network errors;
        # this layer catches "we got an LLM reply but couldn't extract a
        # verdict from it" cases that recover on a second attempt.
        from acuario.lab.agents._retry import retry_transient

        try:
            verdict = await retry_transient(
                lambda: self._run_skeptic(finding, source_snippet, cross_file_context),
                agent="skeptic",
                max_attempts=3,
            )
        except Exception:
            # Fail-open is deliberate (a dead skeptic must not block the
            # audit), but it must be VISIBLE - a silently-dead gate accepts
            # 100% of findings and the precision pitch is a lie.  Count it,
            # log at WARNING, and let the runner surface the count in Pipeline
            # Health via record_degraded.
            self._fail_open += 1
            logger.warning(
                "[skeptic] LLM call failed for %s - accepted by default (fail-open #%d)",
                fid,
                self._fail_open,
                exc_info=True,
            )
            verdict = SkepticVerdict(
                verdict="accepted",
                reasoning="skeptic error (fail-open)",
                finding_id=fid,
                file=file_path,
                line_number=line,
            )

        # Shadow mode - record the TRUE verdict for calibration, but never
        # gate. Everything passes through so the validator judges it too.
        if self._shadow_mode:
            true_verdict = verdict.verdict
            self._write_log_entry(finding, verdict)  # log the real decision
            if true_verdict == "refuted":
                self._shadow_would_refute += 1
            elif true_verdict == "uncertain":
                self._shadow_would_uncertain += 1
            # Stamp the finding with the doubt the skeptic WOULD have raised, so
            # the validator and report see the same signal they'd get in normal
            # mode - otherwise shadow mode silently strips the calibration
            # signal it exists to collect (the in-memory finding would look like
            # a clean accept while skeptic_log.jsonl says otherwise).
            if true_verdict in ("refuted", "uncertain"):
                try:
                    finding["skeptic_flag"] = (
                        "uncertain" if true_verdict == "uncertain" else "would-refute"
                    )
                    finding["skeptic_doubt"] = verdict.reasoning
                except Exception:
                    logger.debug("[skeptic:shadow] could not stamp flag on %s", fid)
            self._accepted += 1
            logger.info(
                "[skeptic:shadow] would-%s %s (passed through for calibration)",
                true_verdict,
                fid,
            )
            verdict.reasoning = f"[shadow: would-{true_verdict}] {verdict.reasoning}"
            verdict.verdict = "accepted"
            return verdict

        if verdict.verdict == "refuted":
            self._refuted += 1
            # Live terminal / audit.log get a SHORT, scannable summary so
            # the live scan output stays readable.  Full reasoning + full
            # LLM response are persisted to skeptic_log.jsonl and rendered
            # in team_discussion.md without any cap - that's where you
            # read the complete refutation.
            #
            # The summary takes the first sentence (or the first 200
            # chars, whichever comes first) plus a "…" indicator when
            # truncated, so the terminal occupies at most one wrapped line.
            summary = _summarize_for_log(verdict.reasoning)
            logger.info(
                "[skeptic] ✗ refute %s  %s:%s  (%s)",
                fid,
                file_path,
                line,
                summary,
            )
            self._write_refuted(finding, verdict)
        elif verdict.verdict == "uncertain":
            # The skeptic doubted the finding but couldn't cite code to
            # refute it. Don't drop it - flag it so the downstream validator
            # (and the report) can see the skeptic's unease, and let it through.
            self._uncertain += 1
            try:
                finding["skeptic_flag"] = "uncertain"
                finding["skeptic_doubt"] = verdict.reasoning
            except Exception:
                logger.debug("[skeptic] could not stamp uncertain flag on %s", fid)
            logger.info(
                "[skeptic] ~ uncertain %s  %s:%s  (%s)",
                fid,
                file_path,
                line,
                _summarize_for_log(verdict.reasoning),
            )
        else:
            self._accepted += 1
            logger.debug("[skeptic] ✓ accept %s", fid)

        # Persist every decision (all verdicts) to skeptic_log.jsonl
        self._write_log_entry(finding, verdict)

        return verdict

    async def ascreen_batch(
        self,
        findings: list[Any],
        source_snippets: dict[str, str] | None = None,
        cross_file_contexts: dict[str, str] | None = None,
    ) -> tuple[list[Any], list[SkepticVerdict]]:
        """Screen a list of findings concurrently.

        Replaces the serial per-finding ``await ascreen(...)`` loops in the
        pool: all findings from one analyzer session are screened in parallel
        (bounded by the LLM client's own semaphore), collapsing N multi-second
        round trips into one wall-clock batch.

        ``source_snippets`` and ``cross_file_contexts`` are keyed by the
        finding's file path so each finding still gets the same per-file
        context the serial path provided.

        Returns ``(accepted_findings, all_verdicts)`` with verdicts in the
        same order as ``findings``.
        """
        import asyncio

        snippets = source_snippets or {}
        contexts = cross_file_contexts or {}
        tasks = [
            self.ascreen(
                f,
                source_snippet=snippets.get(f.get("file", ""), ""),
                cross_file_context=contexts.get(f.get("file", ""), ""),
            )
            for f in findings
        ]
        verdicts: list[SkepticVerdict] = await asyncio.gather(*tasks)
        # Only "refuted" drops a finding. "uncertain" passes through
        # (flagged) so a hand-wave doesn't silently kill a true positive.
        accepted = [f for f, v in zip(findings, verdicts, strict=False) if v.verdict != "refuted"]
        return accepted, list(verdicts)

    @property
    def uncertain_count(self) -> int:
        """Findings passed through with an unrefuted-doubt flag."""
        return self._uncertain

    def summary(self) -> str:
        total = self._accepted + self._refuted + self._uncertain
        s = (
            f"Skeptic gate: accepted {self._accepted}, refuted {self._refuted}, "
            f"uncertain {self._uncertain} of {total} findings"
        )
        if self._debate_overturned or self._debate_upheld or self._debate_failed:
            s += f"; debate: {self._debate_overturned} reinstated, {self._debate_upheld} upheld"
            if self._debate_failed:
                s += f", {self._debate_failed} failed"
        return s

    # --- debate / rebuttal round ------------------------------------------

    async def adebate_batch(
        self,
        refuted: list[tuple[Any, SkepticVerdict]],
        trajectory_summary: str = "",
        cross_file_contexts: dict[str, str] | None = None,
    ) -> list[Any]:
        """Run an analyzer↔skeptic debate on each refuted finding concurrently.

        ``refuted`` is a list of ``(finding, skeptic_verdict)`` pairs the gate
        refuted. For each, the analyst gets one evidence-backed rebuttal and
        the skeptic re-judges. Returns the list of findings that were
        REINSTATED (refutation overturned) - the caller should re-admit them.
        Reinstatement is advisory: the downstream validator still judges them.

        Fail-open: any error leaves the finding refuted (not reinstated), so a
        debate failure can never *add* an unscreened finding.
        """
        import asyncio

        if self._llm is None or not refuted:
            return []
        contexts = cross_file_contexts or {}
        outcomes: list[RebuttalOutcome | None] = await asyncio.gather(
            *[
                self.adebate(f, v, trajectory_summary, contexts.get(f.get("file", ""), ""))
                for f, v in refuted
            ]
        )
        reinstated: list[Any] = []
        for (finding, _v), outcome in zip(refuted, outcomes, strict=False):
            if outcome is None:
                # Debate failed (LLM error after retries). Count it so the
                # debate tallies reconcile with the number of refuted findings
                # actually debated - a silently-dropped failure would make
                # summary() under-report.
                self._debate_failed += 1
                continue
            if outcome.reinstated:
                self._debate_overturned += 1
                try:
                    finding["debate_overturned"] = True
                    finding["debate_rebuttal"] = outcome.rebuttal
                except Exception:
                    logger.debug("[debate] could not stamp finding %s", outcome.finding_id)
                reinstated.append(finding)
            else:
                self._debate_upheld += 1
            self._write_debate_entry(outcome)
        return reinstated

    async def adebate(
        self,
        finding: Any,
        skeptic_verdict: SkepticVerdict,
        trajectory_summary: str = "",
        cross_file_context: str = "",
    ) -> RebuttalOutcome | None:
        """One debate round over a single refuted finding. None on hard error."""
        from acuario.lab.agents._retry import retry_transient

        try:
            return await retry_transient(
                lambda: self._run_debate(
                    finding, skeptic_verdict, trajectory_summary, cross_file_context
                ),
                agent="debate",
                max_attempts=2,
            )
        except Exception:
            logger.debug(
                "[debate] failed for %s - refutation stands", finding.get("id"), exc_info=True
            )
            return None

    async def _run_debate(
        self,
        finding: Any,
        skeptic_verdict: SkepticVerdict,
        trajectory_summary: str,
        cross_file_context: str,
    ) -> RebuttalOutcome:
        from acuario.llm.native import ChatMessage

        fid = finding.get("id", "unknown")
        file_path = finding.get("file", "?")
        line = finding.get("line_number", "?")
        refutation = skeptic_verdict.reasoning or "(no reasoning recorded)"
        context_block = ""
        if cross_file_context:
            context_block = f"Cross-file context:\n{cross_file_context[:2000]}"

        _start = time.monotonic()
        # Turn 1: the analyst rebuts (or concedes).
        analyst_prompt = _REBUTTAL_ANALYZER_PROMPT.format(
            file=file_path,
            line_number=line,
            cwe=finding.get("cwe", "?"),
            severity=finding.get("severity", "?"),
            description=str(finding.get("description", ""))[:600],
            trajectory=(trajectory_summary or "(no trajectory available)")[:3000],
            refutation=refutation[:1500],
            context_block=context_block,
        )
        a_resp = await self._llm.achat(
            messages=[ChatMessage("user", analyst_prompt)],
            system=_REBUTTAL_ANALYZER_SYSTEM,
            tools=[],
        )
        a_text = a_resp.first_text() or ""
        conceded, rebuttal = self._parse_rebuttal(a_text)

        if conceded:
            # Analyst withdrew - refutation stands, no need for turn 2.
            return RebuttalOutcome(
                finding_id=fid,
                file=file_path,
                line_number=line,
                refutation=refutation,
                conceded=True,
                rebuttal=rebuttal,
                final_verdict="upheld",
                reasoning="analyst conceded the refutation",
                reinstated=False,
                _analyst_prompt_excerpt=analyst_prompt,
                _analyst_response_excerpt=a_text,
                _elapsed_seconds=round(time.monotonic() - _start, 3),
            )

        # Turn 2: the skeptic issues a final verdict on the rebuttal.
        skeptic_prompt = _REBUTTAL_SKEPTIC_PROMPT.format(
            file=file_path,
            line_number=line,
            cwe=finding.get("cwe", "?"),
            refutation=refutation[:1500],
            rebuttal=rebuttal[:1500],
        )
        s_resp = await self._llm.achat(
            messages=[ChatMessage("user", skeptic_prompt)],
            system=_REBUTTAL_SKEPTIC_SYSTEM,
            tools=[],
        )
        s_text = s_resp.first_text() or ""
        final_verdict, reasoning = self._parse_final_verdict(s_text)
        return RebuttalOutcome(
            finding_id=fid,
            file=file_path,
            line_number=line,
            refutation=refutation,
            conceded=False,
            rebuttal=rebuttal,
            final_verdict=final_verdict,
            reasoning=reasoning,
            reinstated=(final_verdict == "overturned"),
            _analyst_prompt_excerpt=analyst_prompt,
            _analyst_response_excerpt=a_text,
            _skeptic_prompt_excerpt=skeptic_prompt,
            _skeptic_response_excerpt=s_text,
            _elapsed_seconds=round(time.monotonic() - _start, 3),
        )

    @staticmethod
    def _parse_rebuttal(text: str) -> tuple[bool, str]:
        """Return (conceded, rebuttal_text).

        - Valid JSON with a ``concede`` key → that boolean (defaulting to True
          if the key is absent, so a malformed-but-JSON reply concedes).
        - Non-empty but non-JSON text → treated as a rebuttal (conceded=False)
          so even a weakly-argued response still gets Turn-2 skeptic scrutiny;
          it cannot reinstate on its own because ``_parse_final_verdict``
          defaults to "upheld" when the skeptic's reply is unparseable.
        - Empty text → raises ``EmptyLLMResponse`` for the retry layer."""
        from acuario.lab.agents._retry import EmptyLLMResponse

        if not text or not text.strip():
            raise EmptyLLMResponse("empty response from debate analyst")
        m = re.search(r"\{[^{}]*\"concede\"[^{}]*\}", text, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(0))
                return bool(obj.get("concede", True)), str(obj.get("rebuttal", ""))
            except json.JSONDecodeError:
                pass
        # Non-JSON but non-empty: treat the whole thing as a rebuttal, not a concede.
        return False, text.strip()[:1500]

    @staticmethod
    def _parse_final_verdict(text: str) -> tuple[str, str]:
        """Return (final_verdict, reasoning). Defaults to 'upheld' so an
        unparseable skeptic reply never reinstates a refuted finding."""
        from acuario.lab.agents._retry import EmptyLLMResponse

        if not text or not text.strip():
            raise EmptyLLMResponse("empty response from debate skeptic")
        m = re.search(r"\{[^{}]*\"final_verdict\"[^{}]*\}", text, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(0))
                fv = str(obj.get("final_verdict", "upheld")).lower()
                if fv not in ("upheld", "overturned"):
                    fv = "upheld"
                return fv, str(obj.get("reasoning", ""))
            except json.JSONDecodeError:
                pass
        if re.search(r"overturned", text, re.IGNORECASE):
            return "overturned", text.strip()[:500]
        return "upheld", "verdict could not be parsed (refutation stands)"

    def _write_debate_entry(self, outcome: RebuttalOutcome) -> None:
        if self._debate_file is None:
            return
        try:
            self._debate_file.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "finding_id": outcome.finding_id,
                "file": outcome.file,
                "line_number": outcome.line_number,
                "refutation": outcome.refutation,
                "conceded": outcome.conceded,
                "rebuttal": outcome.rebuttal,
                "final_verdict": outcome.final_verdict,
                "reasoning": outcome.reasoning,
                "reinstated": outcome.reinstated,
                "analyst_prompt_excerpt": outcome._analyst_prompt_excerpt,
                "analyst_response_excerpt": outcome._analyst_response_excerpt,
                "skeptic_prompt_excerpt": outcome._skeptic_prompt_excerpt,
                "skeptic_response_excerpt": outcome._skeptic_response_excerpt,
                "elapsed_seconds": outcome._elapsed_seconds,
            }
            with self._debate_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:
            logger.debug("[debate] failed to write debate_log entry", exc_info=True)

    # --- Internals ------------------------------------------------------------

    async def _run_skeptic(
        self,
        finding: Any,
        source_snippet: str,
        cross_file_context: str,
    ) -> SkepticVerdict:
        from acuario.llm.native import ChatMessage

        # Context caps sized so the skeptic can actually reason about the code
        # and its surroundings.  code_snippet[:4000] captures an entire small
        # function plus context; cross_file_context[:3000] fits ~10 callers +
        # 10 callees + 10 prior findings.
        context_block = ""
        if cross_file_context:
            context_block = f"Cross-file context:\n{cross_file_context[:3000]}"

        prompt = _SKEPTIC_PROMPT.format(
            file=finding.get("file", "?"),
            line_number=finding.get("line_number", "?"),
            cwe=finding.get("cwe", "?"),
            severity=finding.get("severity", "?"),
            finding_type=finding.get("finding_type", "?"),
            description=str(finding.get("description", ""))[:600],
            code_snippet=str(source_snippet or finding.get("code_snippet", ""))[:4000],
            context_block=context_block,
        )

        _start = time.monotonic()
        response = await self._llm.achat(
            messages=[ChatMessage("user", prompt)],
            system=_SKEPTIC_SYSTEM,
            tools=[],
        )
        elapsed = time.monotonic() - _start
        text = response.first_text() or ""

        # Parse the JSON verdict
        verdict_str, reasoning, confidence = self._parse_verdict(text)
        fid = finding.get("id", "unknown")
        return SkepticVerdict(
            verdict=verdict_str,
            reasoning=reasoning,
            finding_id=fid,
            file=finding.get("file", "?"),
            line_number=finding.get("line_number", "?"),
            confidence=confidence,
            _prompt_excerpt=prompt[:_PROMPT_EXCERPT_MAX],
            _response_excerpt=text[:_RESPONSE_EXCERPT_MAX],
            _elapsed_seconds=round(elapsed, 3),
            _cross_file_context_used=bool(cross_file_context),
        )

    @staticmethod
    def _parse_verdict(text: str) -> tuple[str, str, float]:
        """Extract (verdict, reasoning, confidence) from LLM text.

        The verdict is three-way - "refuted" | "uncertain" | "accepted".
        Anything not recognized falls back to "accepted" (fail-open).

        When the LLM response is truly empty or contains no parseable
        verdict signal, raise ``EmptyLLMResponse`` so the outer retry helper
        can re-issue the call. When the text contains *some* signal but JSON
        decoding fails, fall back to accept-by-default on ambiguous-but-
        non-empty responses.
        """
        from acuario.lab.agents._retry import EmptyLLMResponse

        if not text or not text.strip():
            raise EmptyLLMResponse("empty response from skeptic LLM")

        def _coerce_conf(raw: Any, default: float) -> float:
            try:
                c = float(raw)
            except (TypeError, ValueError):
                return default
            return max(0.0, min(1.0, c))

        # Structured JSON first: scan for the first '{' and raw_decode from there.
        # raw_decode parses correctly through braces nested inside strings - e.g.
        # a verdict object whose `reasoning` string contains a brace ("req.body
        # || {}") - which a simple brace-excluding regex cannot, so a valid
        # verdict is never dropped to the fail-open default.
        decoder = json.JSONDecoder()
        for i, ch in enumerate(text):
            if ch != "{":
                continue
            try:
                obj, _end = decoder.raw_decode(text[i:])
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and "verdict" in obj:
                verdict = str(obj.get("verdict", "accepted")).lower()
                if verdict not in ("accepted", "refuted", "uncertain"):
                    verdict = "accepted"
                reasoning = str(obj.get("reasoning", ""))
                # Default confidence: high for a clean accept/refute, low for
                # uncertain (it IS the low-confidence bucket).
                default_conf = 0.4 if verdict == "uncertain" else 0.8
                confidence = _coerce_conf(obj.get("confidence"), default_conf)
                return verdict, reasoning, confidence
            # A JSON object without "verdict" - keep scanning for a later one.

        # Fallback: keyword search, tolerating single OR double quotes. Local
        # models (qwen/llama) often emit single-quoted verdicts that raw_decode
        # rejects; without single-quote tolerance those would fail-open to accepted
        # and silently admit a truly-refuted finding.
        if re.search(r"""['"]verdict['"]\s*:\s*['"]refuted['"]""", text, re.IGNORECASE):
            reason_match = re.search(r"""['"]reasoning['"]\s*:\s*['"]([^'"]{10,})['"]""", text)
            reasoning = reason_match.group(1) if reason_match else "refuted (unparsed)"
            return "refuted", reasoning, 0.6
        if re.search(r"""['"]verdict['"]\s*:\s*['"]uncertain['"]""", text, re.IGNORECASE):
            reason_match = re.search(r"""['"]reasoning['"]\s*:\s*['"]([^'"]{10,})['"]""", text)
            reasoning = reason_match.group(1) if reason_match else "uncertain (unparsed)"
            return "uncertain", reasoning, 0.4

        return "accepted", "verdict could not be parsed (fail-open)", 0.5

    def _write_refuted(self, finding: Any, verdict: SkepticVerdict) -> None:
        if self._refuted_file is None:
            return
        if self._refuted >= self._max_refuted:
            return
        try:
            self._refuted_file.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "finding_id": verdict.finding_id,
                "file": verdict.file,
                "line_number": verdict.line_number,
                "cwe": finding.get("cwe", ""),
                "severity": finding.get("severity", ""),
                "finding_type": finding.get("finding_type", ""),
                "description": str(finding.get("description", ""))[:300],
                "skeptic_reasoning": verdict.reasoning,
            }
            with self._refuted_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:
            logger.debug("[skeptic] Failed to write refuted record", exc_info=True)

    def _write_log_entry(self, finding: Any, verdict: SkepticVerdict) -> None:
        """Append every skeptic decision (accept + refute) to skeptic_log.jsonl.

        The log includes prompt and raw response excerpts so the team-discussion
        report can render the skeptic's full reasoning for any finding without
        re-running the LLM call.
        """
        if self._log_file is None:
            return
        try:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "finding_id": verdict.finding_id,
                "file": verdict.file,
                "line_number": verdict.line_number,
                "cwe": finding.get("cwe", ""),
                "severity": finding.get("severity", ""),
                "finding_type": finding.get("finding_type", ""),
                "verdict": verdict.verdict,
                "confidence": verdict.confidence,
                "reasoning": verdict.reasoning,
                "prompt_excerpt": verdict._prompt_excerpt,
                "llm_response_excerpt": verdict._response_excerpt,
                "cross_file_context_used": verdict._cross_file_context_used,
                "elapsed_seconds": verdict._elapsed_seconds,
            }
            with self._log_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:
            logger.debug("[skeptic] Failed to write skeptic_log entry", exc_info=True)
