"""Reflective Critic - post-ReAct missed-bug analysis agent.

After an analyzer's ReAct loop terminates, the reflective critic fires one
additional LLM call: "You analyzed file X and produced these findings.  What
would a skeptic say you missed?  Which code paths did you not follow?"

The critic's output is folded back into the pipeline as low-confidence leads
tagged ``discovered_by="critic"``.  These leads flow through the normal
validator/skeptic pipeline, so noise gets filtered.

Design rationale
----------------
The analyzer's ReAct loop has an inherent bias toward paths it already
suspects.  Once the agent finds a buffer overflow in a parsing function it
tends to go deeper on that function and shallower on adjacent functions.
The critic sees the final trajectory and asks "what else was there?" with
no anchoring bias toward what was already found.

Cost is low (one LLM call per completed analyzer session) with potentially
high recall ROI: the critic surface is the same file the analyzer already
loaded, so context tokens are already in the LLM's attention window.

Usage
-----
The hook point is ``acuario/scanner/pool.py`` - after each analyzer task
completes, a critic call is launched.  The caller decides whether to add
the returned leads to the findings pool (through the skeptic gate).

Toggle: ``--no-critic`` (default: on).
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

# Caps removed.  Critic prompts include the full file trajectory and
# source snippet (capped at 3 KB by the critic API itself), so the natural
# bound is already comfortable.  ``None`` lets Python's slicing behave as
# ``s[:]`` - full content.
_PROMPT_EXCERPT_MAX: int | None = None
_RESPONSE_EXCERPT_MAX: int | None = None

_CRITIC_SYSTEM = """\
You are a reflective code security reviewer. You will be shown:
  1. The file that was analyzed.
  2. The findings an AI security agent produced.
  3. A summary of the analysis trajectory (what the agent investigated).

Your job is to identify what the agent MISSED - code paths, patterns, or
vulnerability classes that the agent's findings do not cover.

For each gap you identify, produce a brief finding lead:
  - file and approximate line number
  - what vulnerability class / CWE might be present
  - one concrete reason why this location deserves scrutiny

Return valid JSON array:
[
  {
    "file": "src/example.php",
    "line_number": 42,
    "cwe": "CWE-89",
    "finding_type": "sql_injection",
    "description": "Unparameterized query constructed from user input at login route",
    "confidence": "low"
  },
  ...
]

Rules:
- Only report locations NOT already covered by the existing findings.
- Maximum 5 leads. Prefer high-confidence gaps over speculative ones.
- If you cannot identify genuine gaps, return an empty array: []
- Every lead must have a file, a finding_type, and a description.
"""

_CRITIC_PROMPT = """\
## Analyzed file

{file_path}

## Existing findings (what the agent found)

{findings_summary}

## Analysis trajectory summary

{trajectory_summary}

{cross_file_block}## File source (first {max_source_chars} characters)

```
{source_snippet}
```

What did the agent miss?  Return a JSON array of finding leads.
"""


@dataclass
class CriticLead:
    """A low-confidence finding lead from the reflective critic."""

    file: str
    line_number: int | str
    cwe: str
    finding_type: str
    description: str
    confidence: str = "low"
    discovered_by: str = "critic"
    extra: dict = field(default_factory=dict)


class ReflectiveCritic:
    """Post-ReAct reflective critic that asks "what did you miss?".

    Parameters
    ----------
    llm : AsyncLLMClient
        The LLM client to use.  If None the critic is a no-op.
    output_dir : Path | None
        Where to write ``critic_log.jsonl``.  None disables persistence.
    """

    def __init__(
        self,
        llm: Any = None,
        output_dir: Path | None = None,
    ) -> None:
        self._llm = llm
        self._sessions_reflected = 0
        self._leads_total = 0
        # Persist every reflection (prompt + response + emitted leads)
        # to critic_log.jsonl so the team-discussion report can show the
        # critic's full reasoning, not just the parsed CriticLead objects.
        self._log_file: Path | None = None
        if output_dir is not None:
            self._log_file = output_dir / "critic_log.jsonl"

    @property
    def sessions_reflected(self) -> int:
        return self._sessions_reflected

    @property
    def leads_total(self) -> int:
        return self._leads_total

    async def areflect(
        self,
        file_path: str,
        existing_findings: list[Any],
        trajectory_summary: str = "",
        source_snippet: str = "",
        # Cap on how much source to show the critic.  12 KB covers ~300
        # lines of typical source and still leaves room in a 32 KB context
        # for the rest of the prompt + the LLM's response.  A smaller cap
        # limits what the critic can flag as "missed by the analyzer".
        max_source_chars: int = 12000,
        cross_file_context: str = "",
    ) -> list[CriticLead]:
        """Run a reflection pass on a completed analyzer session.

        Parameters
        ----------
        file_path : str
            Path of the file that was analyzed.
        existing_findings : list
            Findings the analyzer already produced for this file.
        trajectory_summary : str
            Short summary of what the analyzer investigated (from ReAct log).
        source_snippet : str
            Source text of the file (first N chars).
        max_source_chars : int
            Cap on how much source to show the critic.
        cross_file_context : str
            Optional callers/callees/prior-findings block (G2b).  Injected
            into the prompt so the critic can reason about the file's
            relationships, not just its body.

        Returns
        -------
        list[CriticLead]
            Low-confidence leads for paths the analyzer may have missed.
            Empty list on error or when LLM is None.
        """
        if self._llm is None:
            return []

        _start = time.monotonic()
        prompt_excerpt = ""
        response_excerpt = ""

        # Outer retry for parse-recoverable failures.  Transient network
        # errors are already handled by the LLM client; this wrapper covers
        # the case where the LLM responds but with garbage that the lead
        # parser can't consume.
        from acuario.lab.agents._retry import retry_transient

        try:
            leads, prompt_excerpt, response_excerpt = await retry_transient(
                lambda: self._run_critic(
                    file_path,
                    existing_findings,
                    trajectory_summary,
                    source_snippet,
                    max_source_chars,
                    cross_file_context,
                ),
                agent="critic",
                max_attempts=3,
            )
        except Exception:
            logger.debug("[critic] LLM call failed for %s", file_path, exc_info=True)
            self._write_log_entry(
                file_path=file_path,
                existing_findings=existing_findings,
                trajectory_summary=trajectory_summary,
                cross_file_context_used=bool(cross_file_context),
                prompt_excerpt=prompt_excerpt,
                response_excerpt=response_excerpt,
                leads=[],
                elapsed=round(time.monotonic() - _start, 3),
                error="llm_call_failed",
            )
            return []

        self._sessions_reflected += 1
        self._leads_total += len(leads)

        if leads:
            logger.info(
                "[critic] added %d low-confidence lead%s from %s trajectory",
                len(leads),
                "" if len(leads) == 1 else "s",
                file_path,
            )

        self._write_log_entry(
            file_path=file_path,
            existing_findings=existing_findings,
            trajectory_summary=trajectory_summary,
            cross_file_context_used=bool(cross_file_context),
            prompt_excerpt=prompt_excerpt,
            response_excerpt=response_excerpt,
            leads=leads,
            elapsed=round(time.monotonic() - _start, 3),
        )

        return leads

    def summary(self) -> str:
        return (
            f"Reflective critic: {self._sessions_reflected} sessions reflected, "
            f"{self._leads_total} leads generated"
        )

    # --- Internals ------------------------------------------------------------

    async def _run_critic(
        self,
        file_path: str,
        existing_findings: list[Any],
        trajectory_summary: str,
        source_snippet: str,
        max_source_chars: int,
        cross_file_context: str = "",
    ) -> tuple[list[CriticLead], str, str]:
        from acuario.llm.native import ChatMessage

        findings_summary = self._format_findings(existing_findings)
        if not findings_summary:
            findings_summary = "(no findings - agent reported nothing suspicious)"

        cross_file_block = ""
        if cross_file_context:
            # 3 KB so the critic sees the full callers/callees/prior-findings
            # block the analyzer already had access to.
            cross_file_block = f"## Cross-file context\n\n{cross_file_context[:3000]}\n\n"

        prompt = _CRITIC_PROMPT.format(
            file_path=file_path,
            findings_summary=findings_summary,
            trajectory_summary=trajectory_summary[:1500] or "(no trajectory summary)",
            cross_file_block=cross_file_block,
            max_source_chars=max_source_chars,
            source_snippet=source_snippet[:max_source_chars],
        )

        response = await self._llm.achat(
            messages=[ChatMessage("user", prompt)],
            system=_CRITIC_SYSTEM,
            tools=[],
        )
        text = response.first_text() or ""
        leads = self._parse_leads(text, file_path)
        return (
            leads,
            prompt[:_PROMPT_EXCERPT_MAX],
            text[:_RESPONSE_EXCERPT_MAX],
        )

    @staticmethod
    def _format_findings(findings: list[Any]) -> str:
        if not findings:
            return ""
        lines = []
        # The critic's job is "what did the analyzer miss?" - showing too
        # few prior findings can cause it to re-emit leads the analyzer
        # already found (false-positive critic leads) or to skip surfacing
        # complementary primitives.
        for f in findings[:30]:
            lines.append(
                f"  - {f.get('cwe', '?')} line {f.get('line_number', '?')}: "
                f"{str(f.get('description', ''))[:120]}"
            )
        return "\n".join(lines)

    @staticmethod
    def _parse_leads(text: str, file_path: str) -> list[CriticLead]:
        """Extract CriticLead list from LLM JSON output.

        An empty response from the LLM is treated as a transient
        condition (raises ``EmptyLLMResponse`` for the outer retry); a
        non-empty response with no JSON array is treated as "the LLM
        genuinely had no leads to add" and returns an empty list.
        """
        import json

        from acuario.lab.agents._retry import EmptyLLMResponse

        if not text or not text.strip():
            raise EmptyLLMResponse("empty response from critic LLM")

        # Find JSON array in text
        arr_match = re.search(r"\[\s*\{.*?\}\s*\]", text, re.DOTALL)
        if not arr_match:
            # An LLM that responds "I don't see additional gaps" with no
            # JSON array is a legitimate empty-result, not a parse failure.
            return []
        try:
            raw = json.loads(arr_match.group(0))
        except json.JSONDecodeError:
            return []

        leads: list[CriticLead] = []
        for item in raw[:5]:  # cap at 5 per session
            if not isinstance(item, dict):
                continue
            try:
                leads.append(
                    CriticLead(
                        file=str(item.get("file", file_path)),
                        line_number=item.get("line_number", "?"),
                        cwe=str(item.get("cwe", "unknown")),
                        finding_type=str(item.get("finding_type", "unknown")),
                        description=str(item.get("description", ""))[:300],
                        confidence=str(item.get("confidence", "low")),
                        discovered_by="critic",
                    )
                )
            except Exception:
                continue
        return leads

    def _write_log_entry(
        self,
        *,
        file_path: str,
        existing_findings: list[Any],
        trajectory_summary: str,
        cross_file_context_used: bool,
        prompt_excerpt: str,
        response_excerpt: str,
        leads: list[CriticLead],
        elapsed: float,
        error: str = "",
    ) -> None:
        """Append every critic reflection to critic_log.jsonl.

        Captures the prompt, raw LLM response, and parsed leads so the
        team-discussion report can show what the critic considered and
        why it emitted (or did not emit) leads for each file.
        """
        if self._log_file is None:
            return
        try:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "file_path": file_path,
                "existing_findings_count": len(existing_findings),
                "trajectory_summary_excerpt": (trajectory_summary or "")[:1200],
                "cross_file_context_used": cross_file_context_used,
                "prompt_excerpt": prompt_excerpt,
                "llm_response_excerpt": response_excerpt,
                "leads": [
                    {
                        "file": lead.file,
                        "line_number": lead.line_number,
                        "cwe": lead.cwe,
                        "finding_type": lead.finding_type,
                        "description": lead.description,
                        "confidence": lead.confidence,
                    }
                    for lead in leads
                ],
                "leads_count": len(leads),
                "elapsed_seconds": elapsed,
            }
            if error:
                record["error"] = error
            with self._log_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:
            logger.debug("[critic] Failed to write critic_log entry", exc_info=True)
