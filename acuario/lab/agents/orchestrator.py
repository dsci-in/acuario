"""Cross-file Orchestrator - proactive subsystem investigation planner.

The orchestrator runs once per audit, after the initial per-file analyzer
pool completes.  It reads the live findings pool + callgraph + file priority
list and emits "investigation plans" of the form:

    "files X, Y, Z share a contract - hunt them together for shared-state
     violations / auth bypass across the boundary"

These plans are fed into a follow-up subsystem-hunter pass using the existing
``build_subsystem_hunter_agent`` factory in ``acuario/scanner/analyzer.py``.

Design rationale
----------------
Most LLM audit tools are per-file.  Acuario's existing subsystem hunter IS
capable of cross-file analysis, but it's reactive - you have to tell it what
to hunt.  The orchestrator makes it proactive: it decides what deserves a
cross-file look based on the live findings, the callgraph topology, and the
file priority scores.

Cost is low (1 LLM call to emit plans, then N follow-up subsystem analyzers).
Coverage impact can be high: auth bypass chains, shared-state races, and
privilege escalations almost always span multiple files.

Usage
-----
Hook point: ``acuario/scanner/runner.py`` - runs between the primary per-file
pool and the variant loop.  The orchestrator's subsystem plans are executed
as additional analyzer sessions.

Toggle: ``--no-orchestrator`` (default: on).
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Caps removed.  Orchestrator prompts scale with project size (one
# structural summary per file).  On large repos a hard cap of 8 KB would
# silently truncate the structural map and degrade plan quality, so we
# log the full prompt.  ``None`` lets Python's slicing behave as
# ``s[:]`` - full content.
_PROMPT_EXCERPT_MAX: int | None = None
_RESPONSE_EXCERPT_MAX: int | None = None

_ORCHESTRATOR_SYSTEM = """\
You are a security audit orchestrator. You have access to:
  1. Findings from an automated per-file security analysis.
  2. A callgraph summary showing which files call into which.
  3. A priority-ranked file list.

Your job is to identify cross-file investigation opportunities that the
per-file analysis may have missed - places where a vulnerability chains
across a module boundary or where shared state / trust relationships
between files create exploitation paths.

Return a JSON array of investigation plans:
[
  {
    "files": ["src/auth.php", "src/session.php"],
    "hunt_focus": "Cross-module session fixation between auth and session handling",
    "rationale": "auth.php sets session tokens without invalidating prior tokens; session.php trusts those tokens downstream"
  },
  ...
]

Rules:
- Maximum 5 plans.
- Each plan must name at least 2 files.
- The hunt_focus must be a concrete, specific vulnerability hypothesis.
- The rationale must reference actual findings or callgraph relationships.
- Prefer plans where the individual per-file findings suggest a larger chain.
- Return [] if no clear cross-file patterns emerge.
"""

_ORCHESTRATOR_PROMPT = """\
## Per-file findings summary

{findings_summary}

## Repository structural map

For each in-scope file: definitions, internal dependencies, and call boundaries.

{structural_summary}

## Priority-ranked files (top 20)

{files_summary}

Based on these findings and the structural map of the codebase, identify
cross-file investigation opportunities.  Return a JSON array of plans.
"""


@dataclass
class SubsystemPlan:
    """A cross-file investigation plan emitted by the orchestrator."""

    files: list[str]
    hunt_focus: str
    rationale: str
    plan_id: str = ""

    def __post_init__(self) -> None:
        if not self.plan_id:
            import uuid

            self.plan_id = f"plan-{uuid.uuid4().hex[:8]}"

    def to_subsystem_target(
        self,
        file_targets: list[Any],
    ) -> Any:
        """Convert this plan into a SubsystemTarget so the existing
        SubsystemHuntRunner can actually execute it.

        Looks up each path in ``file_targets`` to recover the full FileTarget
        dict (with priority, tier, transitive_callers, etc.).  Paths that
        don't match any known FileTarget are skipped - the SubsystemHuntRunner
        needs file metadata, not bare strings.

        Returns
        -------
        SubsystemTarget
            Tagged with ``source="orchestrator"`` so findings produced by the
            follow-up hunt can be traced back to this plan.
        """
        from acuario.scanner.state import SubsystemTarget

        by_path: dict[str, Any] = {ft.get("path", ""): ft for ft in file_targets if ft.get("path")}
        matched_files: list[Any] = []
        for path in self.files:
            if path in by_path:
                matched_files.append(by_path[path])

        if not matched_files:
            # Nothing to hunt - fall back to a minimal stub so callers can skip.
            return SubsystemTarget(
                name=self.hunt_focus[:60] or self.plan_id,
                root_path=_common_path_prefix(self.files),
                files=[],
                description=self.rationale,
                priority=0.0,
                source="orchestrator",
                plan_id=self.plan_id,  # trace back to originating plan
                hunt_hypothesis=self.hunt_focus,  # full hypothesis for the hunter
            )

        priority = max(
            (float(ft.get("priority", 0.0)) for ft in matched_files),
            default=0.0,
        )
        return SubsystemTarget(
            name=self.hunt_focus[:60] or self.plan_id,
            root_path=_common_path_prefix([ft.get("path", "") for ft in matched_files]),
            files=matched_files,
            description=self.rationale,
            priority=priority,
            source="orchestrator",
            plan_id=self.plan_id,  # trace back to originating plan
            hunt_hypothesis=self.hunt_focus,  # full hypothesis for the hunter
        )


def _common_path_prefix(paths: list[str]) -> str:
    """Return the longest common directory prefix of the given paths."""
    if not paths:
        return ""
    try:
        import os.path

        common = os.path.commonpath([p for p in paths if p]) if paths else ""
        # Ensure it ends with a separator so it reads as a directory
        if common and not common.endswith("/"):
            common += "/"
        return common
    except ValueError:
        return ""


class CrossFileOrchestrator:
    """Proactive cross-file investigation planner.

    Parameters
    ----------
    llm : AsyncLLMClient
        The LLM client to use.  If None the orchestrator is a no-op.
    top_n : int
        Maximum number of subsystem plans to emit per audit.
    """

    def __init__(
        self,
        llm: Any = None,
        top_n: int = 5,
        output_dir: Path | None = None,
    ) -> None:
        self._llm = llm
        self._top_n = min(max(1, top_n), 5)
        self._plans_emitted: list[SubsystemPlan] = []
        # Persist prompt + response + emitted plans to orchestrator_log.jsonl
        self._log_file: Path | None = None
        if output_dir is not None:
            self._log_file = output_dir / "orchestrator_log.jsonl"

    @property
    def plans(self) -> list[SubsystemPlan]:
        return list(self._plans_emitted)

    async def aplan(
        self,
        findings: list[Any],
        file_targets: list[Any] | None = None,
        callgraph: Any = None,
    ) -> list[SubsystemPlan]:
        """Produce cross-file investigation plans.

        Parameters
        ----------
        findings : list
            All findings from the per-file analyzer pool.
        file_targets : list | None
            Ranked file targets (with ``priority`` and ``tier`` fields).
        callgraph : CallGraph | None
            The repo callgraph for topology reasoning.

        Returns
        -------
        list[SubsystemPlan]
            Ordered list of investigation plans.  Empty on error / no LLM.
        """
        if self._llm is None or not findings:
            return []

        _start = time.monotonic()
        prompt_excerpt = ""
        response_excerpt = ""

        # Outer retry around _run_orchestrator for parse-recoverable
        # failures.  Same rationale as the skeptic / critic wrappers.
        from acuario.lab.agents._retry import retry_transient

        try:
            plans, prompt_excerpt, response_excerpt = await retry_transient(
                lambda: self._run_orchestrator(
                    findings,
                    file_targets or [],
                    callgraph,
                ),
                agent="orchestrate",
                max_attempts=3,
            )
        except Exception:
            logger.debug("[orchestrate] LLM call failed", exc_info=True)
            self._write_log_entry(
                findings=findings,
                file_targets=file_targets or [],
                prompt_excerpt=prompt_excerpt,
                response_excerpt=response_excerpt,
                plans=[],
                elapsed=round(time.monotonic() - _start, 3),
                error="llm_call_failed",
            )
            return []

        plans = plans[: self._top_n]
        self._plans_emitted = plans

        if plans:
            logger.info(
                "[orchestrate] emitted %d cross-file plan%s from findings pool",
                len(plans),
                "" if len(plans) == 1 else "s",
            )
            for p in plans:
                logger.debug(
                    "[orchestrate]   %s: %s → %s",
                    p.plan_id,
                    ", ".join(p.files),
                    p.hunt_focus,
                )

        self._write_log_entry(
            findings=findings,
            file_targets=file_targets or [],
            prompt_excerpt=prompt_excerpt,
            response_excerpt=response_excerpt,
            plans=plans,
            elapsed=round(time.monotonic() - _start, 3),
        )

        return plans

    def summary(self) -> str:
        return f"Cross-file orchestrator: emitted {len(self._plans_emitted)} subsystem plan(s)"

    # --- Internals ------------------------------------------------------------

    async def _run_orchestrator(
        self,
        findings: list[Any],
        file_targets: list[Any],
        callgraph: Any,
    ) -> tuple[list[SubsystemPlan], str, str]:
        from acuario.llm.native import ChatMessage

        findings_summary = self._format_findings(findings)
        # Per-file structural summary for every in-scope file (definitions,
        # imports/calls, callers) so the orchestrator can reason about what a
        # file actually does, not only how it's wired up.
        structural_summary = self._format_structural_summary(callgraph, file_targets)
        files_summary = self._format_files(file_targets)

        prompt = _ORCHESTRATOR_PROMPT.format(
            findings_summary=findings_summary,
            structural_summary=structural_summary,
            files_summary=files_summary,
        )

        response = await self._llm.achat(
            messages=[ChatMessage("user", prompt)],
            system=_ORCHESTRATOR_SYSTEM,
            tools=[],
        )
        text = response.first_text() or ""
        plans = self._parse_plans(text)
        return (
            plans,
            prompt[:_PROMPT_EXCERPT_MAX],
            text[:_RESPONSE_EXCERPT_MAX],
        )

    @staticmethod
    def _format_findings(findings: list[Any]) -> str:
        if not findings:
            return "(none)"
        # Group by file
        by_file: dict[str, list[str]] = {}
        for f in findings[:50]:  # cap to keep prompt manageable
            fp = f.get("file", "?")
            desc = f"{f.get('cwe', '?')} {f.get('finding_type', '?')}: {str(f.get('description', ''))[:80]}"
            by_file.setdefault(fp, []).append(desc)
        lines = []
        for fp, descs in list(by_file.items())[:20]:
            lines.append(f"  {fp}:")
            for d in descs[:3]:
                lines.append(f"    - {d}")
        return "\n".join(lines)

    @staticmethod
    def _format_structural_summary(callgraph: Any, file_targets: list[Any]) -> str:
        """Build a compact per-file structural map for orchestrator reasoning.

        For each in-scope file, emit a block like:

            == app/auth.py ==
            defines (3): authenticate@12, register@31, reset_password@47
            calls into: db.query, session.set, crypto.hash, jwt.encode
            called from: app/router.py, app/middleware.py
            internal deps: app/db.py, app/crypto.py

        Bounded per-file so the prompt scales linearly with project size at a
        few dozen tokens per file (well within 32k context for a 100-file
        project).
        """
        if callgraph is None or not file_targets:
            return "(no callgraph available)"
        try:
            # Order by priority so the most relevant files come first
            ranked = sorted(
                file_targets,
                key=lambda ft: ft.get("priority", 0.0),
                reverse=True,
            )
            lines: list[str] = []
            for ft in ranked:
                path = ft.get("path", "?")
                # Definitions with line numbers (cap at 6 per file)
                fn_info = (
                    callgraph.function_info.get(path, [])
                    if hasattr(callgraph, "function_info")
                    else []
                )
                defs_compact = ", ".join(f"{fi.name}@{fi.start_line}" for fi in fn_info[:6])
                if len(fn_info) > 6:
                    defs_compact += f", … +{len(fn_info) - 6} more"
                # Outgoing calls (cap at 8)
                calls_out = sorted(callgraph.calls_out.get(path, set()))[:8]
                # Callers of this file (files, cap at 5)
                callers = sorted(callgraph.callers_of_file(path))[:5]
                # Internal deps: files in this project that define names this file calls
                internal_deps: set[str] = set()
                for name in callgraph.calls_out.get(path, set()):
                    for defining_file in callgraph.defined_in.get(name, set()):
                        if defining_file != path:
                            internal_deps.add(defining_file)
                internal_deps_sorted = sorted(internal_deps)[:5]

                block = [f"== {path} =="]
                if defs_compact:
                    block.append(f"  defines ({len(fn_info)}): {defs_compact}")
                if calls_out:
                    block.append(f"  calls into: {', '.join(calls_out)}")
                if callers:
                    block.append(f"  called from: {', '.join(callers)}")
                if internal_deps_sorted:
                    block.append(f"  internal deps: {', '.join(internal_deps_sorted)}")
                # Only emit the file if it has any structural content
                if len(block) > 1:
                    lines.append("\n".join(block))
            return "\n\n".join(lines) if lines else "(no structural data extracted)"
        except Exception:
            logger.debug("[orchestrate] structural summary failed", exc_info=True)
            return "(structural summary unavailable)"

    @staticmethod
    def _format_files(file_targets: list[Any]) -> str:
        if not file_targets:
            return "(none)"
        ranked = sorted(file_targets, key=lambda ft: ft.get("priority", 0.0), reverse=True)[:20]
        lines = [
            f"  [{ft.get('tier', '?')}] {ft.get('path', '?')} "
            f"(priority={ft.get('priority', 0.0):.1f})"
            for ft in ranked
        ]
        return "\n".join(lines)

    @staticmethod
    def _parse_plans(text: str) -> list[SubsystemPlan]:
        """Extract SubsystemPlan list from LLM JSON output.

        Empty LLM responses raise ``EmptyLLMResponse`` to trigger
        the outer retry; non-empty responses with no JSON array return
        an empty list (the LLM legitimately said "no cross-file
        patterns to hunt").
        """
        from acuario.lab.agents._retry import EmptyLLMResponse

        if not text or not text.strip():
            raise EmptyLLMResponse("empty response from orchestrator LLM")

        arr_match = re.search(r"\[\s*[\{\[].*\]", text, re.DOTALL)
        if not arr_match:
            # Try full text as array
            arr_match = re.search(r"\[.*\]", text, re.DOTALL)
        if not arr_match:
            return []
        try:
            raw = json.loads(arr_match.group(0))
        except json.JSONDecodeError:
            return []

        plans: list[SubsystemPlan] = []
        for item in raw[:5]:
            if not isinstance(item, dict):
                continue
            files = item.get("files", [])
            if not isinstance(files, list) or len(files) < 2:
                continue
            hunt_focus = str(item.get("hunt_focus", "")).strip()
            rationale = str(item.get("rationale", "")).strip()
            if not hunt_focus:
                continue
            plans.append(
                SubsystemPlan(
                    files=[str(f) for f in files],
                    hunt_focus=hunt_focus,
                    rationale=rationale,
                )
            )
        return plans

    def _write_log_entry(
        self,
        *,
        findings: list[Any],
        file_targets: list[Any],
        prompt_excerpt: str,
        response_excerpt: str,
        plans: list[SubsystemPlan],
        elapsed: float,
        error: str = "",
    ) -> None:
        """Persist every orchestrator emission to orchestrator_log.jsonl.

        One record per `aplan()` call.  Captures the input shape (counts),
        the prompt and raw LLM response excerpts, and the parsed plans so
        the team-discussion report can render the orchestrator's reasoning.
        """
        if self._log_file is None:
            return
        try:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            # Summarize the findings input (counts by file + CWE)
            by_file: dict[str, int] = {}
            by_cwe: dict[str, int] = {}
            for f in findings:
                by_file[f.get("file", "?")] = by_file.get(f.get("file", "?"), 0) + 1
                by_cwe[f.get("cwe", "?")] = by_cwe.get(f.get("cwe", "?"), 0) + 1
            record = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "findings_summary": {
                    "total": len(findings),
                    "by_file_top": dict(sorted(by_file.items(), key=lambda kv: -kv[1])[:10]),
                    "by_cwe_top": dict(sorted(by_cwe.items(), key=lambda kv: -kv[1])[:10]),
                },
                "file_targets_count": len(file_targets),
                "prompt_excerpt": prompt_excerpt,
                "llm_response_excerpt": response_excerpt,
                "plans": [
                    {
                        "plan_id": p.plan_id,
                        "files": p.files,
                        "hunt_focus": p.hunt_focus,
                        "rationale": p.rationale,
                    }
                    for p in plans
                ],
                "plans_count": len(plans),
                "elapsed_seconds": elapsed,
            }
            if error:
                record["error"] = error
            with self._log_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:
            logger.debug(
                "[orchestrate] Failed to write orchestrator_log entry",
                exc_info=True,
            )
