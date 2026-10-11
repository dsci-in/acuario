"""HunterPool: tiered parallel fan-out with budget rollover.

HunterPool is a thin adapter over acuario/runners/parallel/executor.py -
the generalized ParallelExecutor handles both network-pentest (flat) and
scanner (tiered) execution. HunterPool's job is:

    1. Convert a HuntPoolConfig into a ParallelScanConfig with the right
       scanner seams (file tier function, per-tier cost caps, etc.)
    2. Wrap each file in a runner that spawns a sandbox + analyzer graph
       and streams it to completion
    3. Extract Finding objects from the resulting TargetResults

Public HunterPool API: run() → list[Finding], spent_per_tier, total_spent,
cancel, assign_tier.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, cast

from acuario.core.event_payloads import HuntProgressPayload
from acuario.core.events import EventBus
from acuario.runners.parallel.executor import (
    TargetResult,
)
from acuario.runners.parallel.executor import (
    TierBudget as _ExecutorTierBudget,
)

from .state import FileTarget, Finding

logger = logging.getLogger(__name__)
_DEFAULT_HUNTER_FACTORY = None


# Re-export so existing callers that import from pool.py still work
TierBudget = _ExecutorTierBudget

# --- Band promotion ---------------------------------------------

BAND_ORDER = ("fast", "standard", "deep")


@dataclass
class BandBudget:
    """Per-band cost caps in USD."""

    fast_usd: float = 5.0
    standard_usd: float = 25.0
    deep_usd: float = 100.0

    def for_band(self, band: str) -> float:
        return {"fast": self.fast_usd, "standard": self.standard_usd, "deep": self.deep_usd}[band]


@dataclass
class WorkItem:
    """A single (file, band, attempt) unit of work."""

    file_target: FileTarget
    band: str  # "fast" | "standard" | "deep"
    attempt: int = 0
    seed_transcript: str | None = None
    entry_point: Any = None  # EntryPoint | None
    seed_context: str | None = None  # seed corpus


def _file_rank(file_target: FileTarget) -> int:
    p = file_target.get("priority", 0.0)
    if p >= 4.0:
        return 5
    if p >= 3.0:
        return 4
    if p >= 2.0:
        return 3
    if p >= 1.0:
        return 2
    return 1


def _redundancy_for_rank(rank: int, override: int | None = None) -> int:
    if override is not None:
        return min(override, 5)
    if rank >= 5:
        return 3
    if rank >= 4:
        return 2
    return 1


def promotion_decision(
    findings: list,
    stop_reason: str,
    current_band: str,
    max_band: str,
) -> str | None:
    """Return the next band to promote to, or None."""
    if current_band == max_band:
        return None
    idx = BAND_ORDER.index(current_band)
    max_idx = BAND_ORDER.index(max_band)
    if idx >= max_idx:
        return None
    next_band = BAND_ORDER[idx + 1]

    if current_band == "fast":
        # P2.4: promote only when the fast band ran OUT of budget while it was
        # finding things - that signals there is more to find with a deeper pass.
        # A fast run that COMPLETED cleanly has already exhausted the file at this
        # depth (its findings dedup to 0 new on a standard re-hunt), and a
        # budget-exhausted run with 0 findings just burns more budget for nothing
        # (observed ~$4.5-per-file 0-yield re-hunts on a large multi-service run).
        if stop_reason == "budget_exhausted" and findings:
            return next_band
    elif current_band == "standard":
        confirmed_levels = {
            "static_corroboration",
            "crash_reproduced",
            "root_cause_explained",
            "exploit_demonstrated",
        }
        has_confirmed = any(f.get("evidence_level") in confirmed_levels for f in findings)
        if has_confirmed and stop_reason == "budget_exhausted":
            return next_band
    return None


# --- Tier assignment --------------------------------------------------------


def assign_tier(file_target: FileTarget) -> Literal["A", "B", "C"]:
    """Return 'A', 'B', or 'C' from the file's priority.

    Thresholds:
        priority >= 3.0 → A
        priority >= 2.0 → B
        otherwise       → C

    Calibrated so:
      - (surface=4, influence=2, reach=3) → 0.5*4 + 0.2*2 + 0.3*3 = 3.3 → A
      - (surface=2, influence=2, reach=3) → 0.5*2 + 0.2*2 + 0.3*3 = 2.3 → B
      - (surface=1, influence=1, reach=3) → 0.5*1 + 0.2*1 + 0.3*3 = 1.6 → C
      - (surface=1, influence=5, reach=3) → 0.5*1 + 0.2*5 + 0.3*3 = 2.4 → B
        (the FFmpeg-style propagation case lands in Tier B, never Tier C)
    """
    p = file_target.get("priority", 0.0)
    if p >= 3.0:
        return "A"
    if p >= 2.0:
        return "B"
    return "C"


# --- Config -----------------------------------------------------------------


@dataclass
class HuntPoolConfig:
    files: list[FileTarget]
    repo_path: str
    sandbox_factory: Callable | None = None
    # Callable[[], SandboxContainer] - a fresh
    # container per analyzer. None → host-fallback.
    hunter_factory: Callable | None = None
    # Callable[[FileTarget, sandbox, session_id], (graph, ctx)]
    # If None, the pool will import build_hunter_agent
    # at run time and require an llm in the config.
    llm: object | None = None  # Required if hunter_factory is None
    max_parallel: int = 8
    budget_usd: float = 0.0
    tier_budget: TierBudget = field(default_factory=TierBudget)
    cost_limit_per_file_a: float = 0.25
    cost_limit_per_file_b: float = 0.15
    cost_limit_per_file_c: float = 0.04
    timeout_minutes_per_file: int = 0
    on_finding: Callable | None = None
    # called with a list[Finding] each time a file completes (not at
    # end-of-pool like on_finding). The runner wires this to incrementally
    # persist findings to the historical DB so a mid-pool crash is resumable.
    on_file_complete: Callable | None = None
    session_id_prefix: str = "hunt"
    sandbox_manager: Any = None
    # optional warm ContainerPool. When set, _run_file borrows a
    # pre-spawned container instead of cold-spawning via sandbox_factory, and
    # returns it (reset to pristine) instead of stopping it. None = per-file
    # spawn (the guaranteed-fresh default).
    container_pool: Any = None  # acuario.sandbox.container_pool.ContainerPool | None
    # attach the ptrace syscall monitor to analyzer sandboxes (not just
    # exploit-dev). Off by default; the runner turns it on in deep mode. When
    # on, each file's compile/run commands are strace-wrapped and real
    # syscalls stream to <output_dir>/analyzer_behavior_events.jsonl.
    enable_ptrace_for_analyzers: bool = False
    output_dir: str | None = None  # session output dir for the analyzer ptrace JSONL
    # run the analyzer↔skeptic debate round on refuted findings. On by
    # default - recall-positive and (on a local LLM) free; reinstatements are
    # advisory (the validator still judges them). Disable via --no-debate.
    enable_debate: bool = True
    # seeded-crash lookup: {repo_relative_file_path: {report, target_function, ...}}
    seeded_crashes_by_file: dict = field(default_factory=dict)
    # Semgrep hints: {repo_relative_file_path: [semgrep_finding_dicts]}
    semgrep_hints_by_file: dict = field(default_factory=dict)
    agent_mode: str = "constrained"  # "constrained" | "deep"
    prompt_mode: str = "unconstrained"  # "unconstrained" | "specialist"
    campaign_hint: str | None = None
    exploit_mode: bool = False
    starting_band: str = "fast"  # "fast" | "standard" | "deep"
    max_band: str = "standard"  # highest band promotion can reach
    band_budget: BandBudget = field(default_factory=BandBudget)
    redundancy_override: int | None = None
    entry_points_by_file: dict = field(default_factory=dict)  # {path: [EntryPoint]}
    seed_corpus_by_file: dict = field(default_factory=dict)  # {path: [SeedCorpusEntry]}
    shard_entry_points: bool = False
    findings_pool: Any = None  # FindingsPool | None
    # per-file mechanism recall. If a store is supplied, each analyzer
    # dispatch queries it with (language, tags, path-keywords) and the top-K
    # results are injected into the analyzer's system prompt as a "prior
    # patterns" block. None disables recall.
    mechanism_store: Any = None  # acuario.scanner.mechanism_memory.MechanismStore | None
    mechanism_recall_k: int = 3

    # cross-file context pre-seed. When a callgraph is present, each
    # analyzer dispatch gets a "Known cross-file context" block in its prompt
    # showing direct callers, callees, and (optionally) prior findings from
    # the historical DB. Capped at cross_file_context_max_entries per list.
    callgraph: Any = None  # acuario.scanner.callgraph.CallGraph | None
    historical_findings_db: Any = None  # HistoricalFindingsDB | None
    repo_url: str = ""  # used for HistoricalFindingsDB queries
    enable_cross_file_context: bool = True
    cross_file_context_max_entries: int = 10

    # skeptic gate - adversarial finding review before pool admission.
    # When set, every finding is screened by the skeptic agent before being
    # added to the findings pool.  Refuted findings go to skeptic_refuted.jsonl.
    skeptic_gate: Any = None  # acuario.lab.agents.skeptic.SkepticGate | None

    # reflective critic - post-ReAct missed-bug pass.
    # When set, fires one LLM call after each analyzer session completes.
    # Critic leads are injected as low-confidence findings into the pool.
    critic_agent: Any = None  # acuario.lab.agents.critic.ReflectiveCritic | None


def _format_seed_context(entries: list) -> str | None:
    """Format seed corpus entries for prompt injection. Returns None if empty."""
    if not entries:
        return None
    try:
        from .seed_corpus import format_seed_context

        return format_seed_context(entries) or None
    except ImportError:
        return None


def _extract_transcript(result: TargetResult) -> str:
    """Build a brief transcript summary from a TargetResult for seeding promoted runs."""
    parts: list[str] = []
    for f in result.findings:
        desc = f.get("description", "") if isinstance(f, dict) else str(f)
        parts.append(f"Finding: {desc[:200]}")
    if not parts:
        parts.append(f"Run completed with status={result.status}, stop_reason={result.stop_reason}")
    return "\n".join(parts)[:500]


# --- HunterPool -------------------------------------------------------------


class HunterPool:
    """Tiered parallel analyzer executor with native async LLM scheduling."""

    def __init__(self, config: HuntPoolConfig):
        self.config = config
        for ft in self.config.files:
            ft["tier"] = assign_tier(ft)
        self._results: dict[str, TargetResult] = {}
        # distinct file paths that have reached a terminal status. Progress
        # is reported from THIS set (not len(_results)), so a file re-hunted at
        # fast+standard bands / with redundancy counts once, not N times.
        self._completed_files: set[str] = set()
        self._spent_per_tier: dict[str, float] = {"A": 0.0, "B": 0.0, "C": 0.0}
        self._spent_per_band: dict[str, float] = {"fast": 0.0, "standard": 0.0, "deep": 0.0}
        self._runs_per_band: dict[str, int] = {"fast": 0, "standard": 0, "deep": 0}
        # Use ASCII arrows so non-UTF-8 terminals (e.g. bash without
        # `LANG` set) don't render the keys as mojibake (`fastâ†’standard`).
        self._promotion_counts: dict[str, int] = {"fast->standard": 0, "standard->deep": 0}
        self._state_lock = asyncio.Lock()
        self._cancelled = False
        # total analyzer-session syscall events captured (ptrace).
        self._analyzer_ptrace_events = 0
        # per-file cache of cross_file_context strings so the skeptic
        # gate and reflective critic can reuse the analyzer's pre-seeded block
        # without re-running the build (and without spamming [context] logs).
        self._cross_file_context_cache: dict[str, str] = {}
        # per-file lab (skeptic/debate/critic) tasks detached off the dispatch
        # critical path. Pool-level (not phase-local) so a per-file timeout
        # early-return or a phase transition cannot orphan them - arun()'s
        # phase-end join barrier awaits every task here before all_findings().
        self._lab_tasks: list[asyncio.Task[None]] = []
        # files whose reflective critic has already run. The critic fires at
        # a file's terminal band, but redundant/promoted runs each reach the
        # terminal band and would re-fire it (per completed work-item, not per
        # distinct file), multiplying low-yield speculative leads (~62 leads / pool
        # 87->330 / ~$130->$260 on a large run). Gate it to once per distinct file.
        self._critic_ran: set[str] = set()

    def run(self) -> list[Finding]:
        return asyncio.run(self.arun())

    def _expand_to_work_items(self, files: list[FileTarget], band: str) -> list[WorkItem]:
        """Expand files into WorkItems respecting redundancy and entry-point sharding."""
        items: list[WorkItem] = []
        for ft in files:
            rank = _file_rank(ft)
            n = _redundancy_for_rank(rank, self.config.redundancy_override)
            file_path = ft.get("path", "")
            entry_points = (
                self.config.entry_points_by_file.get(file_path, [])
                if self.config.shard_entry_points and rank >= 4
                else []
            )
            seed_entries = self.config.seed_corpus_by_file.get(file_path, [])

            if entry_points:
                for ep in entry_points:
                    ep_seeds = [
                        s
                        for s in seed_entries
                        if s.function_name is None or s.function_name == ep.function_name
                    ]
                    seed_ctx = _format_seed_context(ep_seeds) if ep_seeds else None
                    for attempt in range(n):
                        items.append(
                            WorkItem(
                                file_target=ft,
                                band=band,
                                attempt=attempt,
                                entry_point=ep,
                                seed_context=seed_ctx,
                            )
                        )
            else:
                seed_ctx = _format_seed_context(seed_entries) if seed_entries else None
                for attempt in range(n):
                    items.append(
                        WorkItem(
                            file_target=ft,
                            band=band,
                            attempt=attempt,
                            seed_context=seed_ctx,
                        )
                    )
        return items

    async def arun(self) -> list[Finding]:
        """Run the full A → B → C pipeline with band promotion. Returns merged findings."""
        logger.info(
            "[analyze] %s dispatching %d tiered investigations", "▸", len(self.config.files)
        )
        by_tier: dict[str, list[FileTarget]] = {"A": [], "B": [], "C": []}
        for item in self.config.files:
            by_tier[item.get("tier", "C")].append(item)

        total_budget = self.config.budget_usd
        tb = self.config.tier_budget
        if total_budget <= 0:
            budget_a = budget_b = budget_c = float("inf")
        else:
            budget_a = total_budget * tb.tier_a_fraction
            budget_b = total_budget * tb.tier_b_fraction
            budget_c = total_budget * tb.tier_c_fraction

        starting_band = self.config.starting_band

        try:
            work_items_a = self._expand_to_work_items(by_tier["A"], starting_band)
            spent_a = await self._run_tier_phase(work_items_a, "A", budget_a)
            budget_b += max(0.0, budget_a - spent_a)

            work_items_b = self._expand_to_work_items(by_tier["B"], starting_band)
            spent_b = await self._run_tier_phase(work_items_b, "B", budget_b)
            budget_c += max(0.0, budget_b - spent_b)

            if by_tier["C"] and tb.tier_c_fraction > 0:
                work_items_c = self._expand_to_work_items(by_tier["C"], starting_band)
                await self._run_tier_phase(work_items_c, "C", budget_c)
        finally:
            # JOIN BARRIER: the lab (skeptic-gate + debate + reflective
            # critic) runs as detached per-file tasks off the dispatch path.
            # Await ALL of them here - in a finally, so it runs on the normal
            # fall-through, a per-file timeout early-return, a cancel/budget
            # drain, or a phase exception - strictly BEFORE all_findings() is read
            # below. Each task awaits its findings_pool.add() directly, so joining
            # the task guarantees every admitted / reinstated / critic-lead
            # finding is committed and visible. return_exceptions=True so a single
            # failing lab task can never sink the whole pool result.
            if self._lab_tasks:
                _lab_results = await asyncio.gather(*self._lab_tasks, return_exceptions=True)
                for _lab_exc in _lab_results:
                    if isinstance(_lab_exc, BaseException):
                        logger.warning("[analyze] detached lab task failed", exc_info=_lab_exc)
                self._lab_tasks.clear()

        target_results = list(self._results.values())
        status_counts = Counter(tr.status for tr in target_results)
        if status_counts:
            logger.info("[analyze] %s result statuses: %s", "▸", dict(status_counts))
        error_results = [tr for tr in target_results if tr.status == "error"]
        for tr in error_results[:10]:
            logger.warning(
                "[analyze] %s investigation error for %s: %s",
                "⚠",
                tr.target,
                tr.error or "(no error text)",
            )
        all_findings: list[Finding] = []
        if self.config.findings_pool is not None:
            all_findings = self.config.findings_pool.all_findings()
        else:
            for tr in target_results:
                if tr.status == "completed":
                    for f in cast(list[Finding], tr.findings):
                        all_findings.append(f)
        if self.config.on_finding:
            for f in all_findings:
                try:
                    self.config.on_finding(f)
                except Exception:
                    logger.debug("on_finding callback failed", exc_info=True)
        logger.info(
            "[analyze] %s pool complete: sessions=%d findings=%d spent_tier=%s spent_band=%s promotions=%s",
            "●",
            sum(1 for tr in target_results if tr.status == "completed"),
            len(all_findings),
            self.spent_per_tier,
            self.spent_per_band,
            self.promotion_counts,
        )
        return all_findings

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def spent_per_band(self) -> dict[str, float]:
        return dict(self._spent_per_band)

    @property
    def runs_per_band(self) -> dict[str, int]:
        return dict(self._runs_per_band)

    @property
    def promotion_counts(self) -> dict[str, int]:
        return dict(self._promotion_counts)

    @property
    def spent_per_tier(self) -> dict[str, float]:
        return dict(self._spent_per_tier)

    @property
    def total_spent(self) -> float:
        return sum(self._spent_per_tier.values())

    @property
    def analyzer_ptrace_events(self) -> int:
        """N2: total syscall events captured across analyzer sessions."""
        return self._analyzer_ptrace_events

    @staticmethod
    def _global_budget_exceeded() -> bool:
        """P4: True when the global --budget cost limit (armed on the
        CostTracker singleton) has been crossed. Best-effort - telemetry must
        never abort the pool, so any failure reads as 'not exceeded'."""
        try:
            from acuario.observability.telemetry import CostTracker

            return CostTracker().is_over_limit()
        except Exception:
            return False

    async def _run_tier_phase(
        self,
        work_items: list[WorkItem],
        tier: str,
        budget: float,
    ) -> float:
        if not work_items or budget <= 0:
            return 0.0

        timeout = (
            self.config.timeout_minutes_per_file * 60
            if self.config.timeout_minutes_per_file > 0
            else None
        )
        spent = 0.0
        in_flight: dict[asyncio.Task[TargetResult], WorkItem] = {}
        item_iter = iter(work_items)
        promotion_queue: list[WorkItem] = []

        def _submit_next() -> bool:
            nonlocal spent
            if self._cancelled or spent >= budget:
                return False
            # enforce the global --budget cost limit. CostTracker.cost_limit
            # is armed from --budget at audit start; once cumulative spend
            # crosses it we stop dispatching new files (in-flight ones finish
            # and flush). Previously the limit was armed but never consulted, so
            # --budget was silently ignored during the hunt.
            if self._global_budget_exceeded():
                if not self._cancelled:
                    logger.warning(
                        "[budget] global cost limit reached; halting new analyzer dispatch"
                    )
                self._cancelled = True
                return False
            wi: WorkItem | None = None
            try:
                wi = next(item_iter)
            except StopIteration:
                if promotion_queue:
                    wi = promotion_queue.pop(0)
            if wi is None:
                return False
            band_cost = self.config.band_budget.for_band(wi.band)
            task = asyncio.create_task(
                self._run_file_task(
                    wi.file_target,
                    cost_limit=band_cost,
                    tier=tier,
                    band=wi.band,
                    seed_transcript=wi.seed_transcript,
                    entry_point=wi.entry_point,
                    seed_context=wi.seed_context,
                )
            )
            in_flight[task] = wi
            return True

        for _ in range(max(1, self.config.max_parallel)):
            if not _submit_next():
                break

        while in_flight:
            done, _pending = await asyncio.wait(
                list(in_flight.keys()),
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if timeout is not None and not done:
                logger.warning(
                    "tier %s had no completed analyzers within %ss; marking %d in-flight items as timeout",
                    tier,
                    timeout,
                    len(in_flight),
                )
                for task, wi in list(in_flight.items()):
                    task.cancel()
                    key = wi.file_target.get("path", "")
                    async with self._state_lock:
                        self._results[key] = TargetResult(
                            target=key,
                            status="timeout",
                            error=f"Analyzer did not complete within {timeout}s",
                            tier=tier,
                            band=wi.band,
                        )
                return spent

            for task in done:
                wi = in_flight.pop(task)
                key = wi.file_target.get("path", "")
                try:
                    result = await task
                except asyncio.CancelledError:
                    result = TargetResult(
                        target=key,
                        status="cancelled",
                        tier=tier,
                        band=wi.band,
                    )
                except Exception as exc:
                    logger.warning("tier %s analyzer for %s failed: %s", tier, key, exc)
                    result = TargetResult(
                        target=key,
                        status="error",
                        error=str(exc),
                        tier=tier,
                        band=wi.band,
                    )
                ep_suffix = f":{wi.entry_point.function_name}" if wi.entry_point else ""
                async with self._state_lock:
                    self._results[f"{key}{ep_suffix}:{wi.band}:{wi.attempt}"] = result
                    if result.status in ("completed", "error", "timeout"):
                        self._completed_files.add(key)  # distinct-file progress
                    self._spent_per_tier[tier] += result.cost_usd
                    self._spent_per_band[wi.band] = (
                        self._spent_per_band.get(wi.band, 0.0) + result.cost_usd
                    )
                    self._runs_per_band[wi.band] = self._runs_per_band.get(wi.band, 0) + 1
                    spent += result.cost_usd

                # incremental checkpoint. Persist this file's findings the
                # moment it completes, so a crash mid-pool leaves the
                # already-done files recoverable by `acuario audit --resume`
                # (which re-runs verify+report from the historical DB). Called
                # outside the state lock; it is a synchronous best-effort write
                # so no other coroutine interleaves mid-write under asyncio.
                if self.config.on_file_complete is not None and result.status == "completed":
                    try:
                        self.config.on_file_complete(list(result.findings))
                    except Exception:
                        # WARNING, not debug: a silently-dropped checkpoint means
                        # a --resume after a crash would lose this file's findings.
                        logger.warning(
                            "on_file_complete checkpoint failed for %s", key, exc_info=True
                        )

                # distinct completed files (not work-items - see
                # _completed_files), so progress never overshoots files_total.
                completed_count = len(self._completed_files)
                total_files = len(self.config.files)
                findings_count = sum(
                    len(r.findings) for r in self._results.values() if r.status == "completed"
                )
                EventBus().emit_hunt_progress(
                    HuntProgressPayload(
                        session_id=self.config.session_id_prefix,
                        tier=tier,
                        band=wi.band,
                        files_completed=completed_count,
                        files_total=total_files,
                        findings_this_tier=findings_count,
                        cost_usd=spent,
                        budget_remaining=max(0.0, budget - spent),
                    )
                )

                # compute the promotion decision up front so the
                # reflective critic runs ONCE per file - only at the terminal
                # band the file actually reaches.
                next_band = None
                if result.status == "completed":
                    next_band = promotion_decision(
                        cast(list[Finding], result.findings),
                        result.stop_reason,
                        wi.band,
                        self.config.max_band,
                    )

                # run the per-file lab (skeptic-gate + debate + reflective
                # critic) as ONE detached task off the dispatch path, then submit
                # the next file immediately. The critic's terminal-band gate is
                # decided synchronously here (run_critic); the task is joined at
                # arun()'s phase-end barrier before all_findings() is read.
                if result.status == "completed" and self.config.findings_pool is not None:
                    # run the reflective critic at most once per distinct file.
                    # Decided synchronously on the dispatch path, so the set access
                    # needs no lock.
                    _critic_file = wi.file_target.get("path", "")
                    run_critic = (
                        next_band is None
                        and self.config.critic_agent is not None
                        and _critic_file not in self._critic_ran
                    )
                    if run_critic:
                        self._critic_ran.add(_critic_file)
                    self._lab_tasks.append(
                        asyncio.create_task(
                            self._run_lab_for_file(
                                result=result, wi=wi, key=key, run_critic=run_critic
                            )
                        )
                    )

                if result.status == "completed":
                    if next_band:
                        promo_key = f"{wi.band}->{next_band}"
                        async with self._state_lock:
                            self._promotion_counts[promo_key] = (
                                self._promotion_counts.get(promo_key, 0) + 1
                            )
                        logger.info(
                            "[analyze] %s %s promoted %s → %s band",
                            "▸",
                            key,
                            wi.band,
                            next_band,
                        )
                        promotion_queue.append(
                            WorkItem(
                                file_target=wi.file_target,
                                band=next_band,
                                attempt=wi.attempt,
                                seed_transcript=_extract_transcript(result),
                            )
                        )

                _submit_next()

        return spent

    async def _run_lab_for_file(
        self,
        *,
        result: TargetResult,
        wi: WorkItem,
        key: str,
        run_critic: bool,
    ) -> None:
        """The per-file lab (skeptic-gate + debate + reflective critic),
        run as a DETACHED task off the dispatch critical path.

        ONE sequential coroutine (skeptic -> debate -> critic): debate reuses the
        screen's verdicts + cross-file context, and the critic reads the finding
        dicts the skeptic stamped, so they must not be split. Every
        findings_pool.add() is a direct ``await`` here, so arun()'s phase-end join
        barrier - which awaits this task - guarantees every admitted / reinstated
        / critic-lead finding is committed and visible before all_findings() is
        read. All original inner fail-open try/except blocks are preserved, so
        this task effectively never raises (the barrier also uses
        return_exceptions=True as a backstop).

        Preconditions the caller decides SYNCHRONOUSLY: result.status == 'completed'
        and findings_pool is set; ``run_critic`` already encodes the
        terminal-band gate (next_band is None) AND critic_agent is not None.
        """
        findings_pool = self.config.findings_pool
        if findings_pool is None:
            return
        findings_list = cast(list[Finding], result.findings)
        # --- skeptic-gate + debate (the analyzer-findings chain) ------------
        admitted = findings_list
        if self.config.skeptic_gate is not None and findings_list:
            try:
                # backfill an empty code_snippet from disk so the skeptic
                # adjudicates on the actual code, not the description alone (~18
                # empty-snippet verdicts on a large run). Mirrors the critic-lead
                # backfill and runs before findings_pool.add so the richer snippet
                # also persists. Per-finding (keyed by line), unlike the file-keyed
                # source_snippets seam - and it passes no new arg to ascreen_batch.
                for _f in findings_list:
                    if str(_f.get("code_snippet") or "").strip():
                        continue
                    _fp = _f.get("file", "") or ""
                    _ln = _f.get("line_number", 0)
                    if _fp and isinstance(_ln, int) and _ln > 0:
                        _snip = self._read_code_snippet_around(_fp, _ln)
                        if _snip:
                            _f["code_snippet"] = _snip
                # Per-file cross_file_context, built once per distinct file.
                files = {(f.get("file", "") or "") for f in findings_list}
                cfc_by_file = {
                    fp: self._build_cross_file_context({"path": fp}, quiet=True) for fp in files
                }
                admitted, verdicts = await self.config.skeptic_gate.ascreen_batch(
                    findings_list,
                    cross_file_contexts=cfc_by_file,
                )
                # debate round - one analyst rebuttal on every REFUTED
                # finding; an overturned refutation reinstates the finding.
                if self.config.enable_debate and hasattr(self.config.skeptic_gate, "adebate_batch"):
                    refuted_pairs = [
                        (f, v)
                        for f, v in zip(findings_list, verdicts, strict=False)
                        if getattr(v, "verdict", "") == "refuted"
                    ]
                    if refuted_pairs:
                        reinstated = await self.config.skeptic_gate.adebate_batch(
                            refuted_pairs,
                            trajectory_summary=_extract_transcript(result),
                            cross_file_contexts=cfc_by_file,
                        )
                        if reinstated:
                            logger.info(
                                "[debate] reinstated %d refuted finding(s) after rebuttal",
                                len(reinstated),
                            )
                            admitted = list(admitted) + reinstated
            except Exception:
                logger.warning(
                    "Skeptic gate batch error (fail-open): admitting %d finding(s) unscreened",
                    len(findings_list),
                    exc_info=True,
                )
                admitted = findings_list
        for f in admitted:
            try:
                await findings_pool.add(f)
            except Exception:
                logger.debug("findings_pool.add failed", exc_info=True)

        # --- reflective critic (only at the file's terminal band) ----------
        critic_agent = self.config.critic_agent
        if not run_critic or critic_agent is None:
            return
        file_path = wi.file_target.get("path", "")
        trajectory_summary = _extract_transcript(result)
        critic_source_snippet = self._read_source_for_critic(file_path)
        critic_cfc = self._build_cross_file_context(wi.file_target, quiet=True)
        try:
            from acuario.findings.types import Finding as FindingClass

            leads = await critic_agent.areflect(
                file_path=file_path,
                existing_findings=list(result.findings),
                trajectory_summary=trajectory_summary,
                source_snippet=critic_source_snippet,
                cross_file_context=critic_cfc,
            )
            critic_findings: list[Finding] = []
            for lead in leads:
                try:
                    lead_line = lead.line_number if isinstance(lead.line_number, int) else None
                    critic_snippet = (
                        self._read_code_snippet_around(lead.file, lead_line, window_lines=10)
                        if lead_line
                        else ""
                    )
                    critic_findings.append(
                        FindingClass(
                            file=lead.file,
                            line_number=lead_line,
                            cwe=lead.cwe,
                            finding_type=lead.finding_type,
                            description=lead.description,
                            code_snippet=critic_snippet,
                            severity="info",
                            confidence="low",
                            discovered_by="critic",
                            evidence_level="suspicion",
                        )
                    )
                except Exception:
                    logger.debug("Critic lead build failed", exc_info=True)

            admitted_critic = critic_findings
            if self.config.skeptic_gate is not None and critic_findings:
                try:
                    lead_files = {(cf.get("file", "") or "") for cf in critic_findings}
                    lead_cfc_by_file = {
                        fp: self._build_cross_file_context({"path": fp}, quiet=True)
                        for fp in lead_files
                    }
                    admitted_critic, _v = await self.config.skeptic_gate.ascreen_batch(
                        critic_findings,
                        cross_file_contexts=lead_cfc_by_file,
                    )
                except Exception:
                    logger.warning(
                        "Critic skeptic batch error (fail-open): admitting %d "
                        "critic lead(s) unscreened",
                        len(critic_findings),
                        exc_info=True,
                    )
                    admitted_critic = critic_findings
            for critic_finding in admitted_critic:
                try:
                    await findings_pool.add(critic_finding)
                except Exception:
                    logger.debug("Critic lead pool add failed", exc_info=True)
        except Exception:
            logger.debug("[critic] areflect failed", exc_info=True)

    # --- Internals: analyzer-specific logic the runner delegates back to ----

    async def _run_file_task(
        self,
        file_target: FileTarget,
        cost_limit: float,
        tier: str,
        band: str = "",
        seed_transcript: str | None = None,
        entry_point: Any = None,
        seed_context: str | None = None,
    ) -> TargetResult:
        findings, cost, tokens, stop_reason = await self._run_one_hunter(
            file_target,
            cost_limit,
            seed_transcript=seed_transcript,
            entry_point=entry_point,
            seed_context=seed_context,
        )
        return TargetResult(
            target=file_target.get("path", ""),
            status="completed",
            findings=cast(list[dict], findings),
            cost_usd=cost,
            tokens_used=tokens,
            tier=tier,
            band=band,
            stop_reason=stop_reason,
        )

    async def _run_one_hunter(
        self,
        file_target: FileTarget,
        cost_limit: float,
        seed_transcript: str | None = None,
        entry_point: Any = None,
        seed_context: str | None = None,
    ) -> tuple[list[Finding], float, int, str]:
        """Run a single analyzer. Returns (findings, cost_usd, tokens_used, stop_reason)."""
        _TIER_LABEL = {"A": "surface", "B": "depth", "C": "trace"}
        _tier = file_target.get("tier", "?")
        _tlabel = _TIER_LABEL.get(_tier, _tier)
        logger.info(
            "[analyze:%s] %s engage %s",
            _tlabel,
            "◐",
            file_target.get("path"),
        )

        sandbox = None
        # prefer borrowing a warm container; fall back to a cold spawn when
        # the pool is empty or not configured.
        pooled = False
        if self.config.container_pool is not None:
            try:
                sandbox = await self.config.container_pool.acquire()
                pooled = sandbox is not None
            except Exception as e:
                logger.warning(
                    "container_pool.acquire failed for %s: %s", file_target.get("path"), e
                )
        if sandbox is None and self.config.sandbox_factory is not None:
            try:
                sandbox = await asyncio.to_thread(self.config.sandbox_factory)
            except Exception as e:
                logger.warning("sandbox_factory failed for %s: %s", file_target.get("path"), e)

        # attach the ptrace syscall monitor to this analyzer's sandbox so
        # its compile/run commands are strace-wrapped and real syscalls stream
        # to analyzer_behavior_events.jsonl. Same mechanism exploit-dev uses;
        # gated to deep mode by the runner. Degrades gracefully when strace is
        # absent (start() returns False → no wrap, regex monitor stays).
        ptrace_monitor = None
        if (
            self.config.enable_ptrace_for_analyzers
            and sandbox is not None
            and self.config.output_dir
        ):
            ptrace_monitor = self._attach_analyzer_ptrace(sandbox)

        try:
            analyzer, ctx = self._build_hunter_for_file(
                file_target,
                sandbox,
                budget_usd=cost_limit,
                seed_transcript=seed_transcript,
                entry_point=entry_point,
                seed_context=seed_context,
            )
            run_result = await analyzer.arun()

            logger.info(
                "[analyze:%s] %s %s → %d findings ($%.2f)",
                _tlabel,
                "●",
                file_target.get("path"),
                len(run_result.findings),
                run_result.cost_usd,
            )
            return (
                list(run_result.findings),
                run_result.cost_usd,
                run_result.tokens_used,
                run_result.stop_reason,
            )
        finally:
            try:
                if "ctx" in locals():
                    ctx.cleanup_variants()
            except Exception:
                logger.debug("Variant sandbox cleanup failed", exc_info=True)
            # detach + stop the analyzer ptrace monitor (flushes JSONL).
            # Detach before pool release so the reset commands aren't wrapped.
            if ptrace_monitor is not None and sandbox is not None:
                try:
                    if getattr(sandbox, "behavior_monitor", None) is ptrace_monitor:
                        sandbox.behavior_monitor = None
                    ptrace_monitor.stop()
                    async with self._state_lock:
                        self._analyzer_ptrace_events += len(ptrace_monitor.read_events())
                except Exception:
                    logger.debug("analyzer ptrace stop failed", exc_info=True)
            if sandbox is not None:
                if pooled:
                    # return to the pool (reset to pristine), don't stop.
                    try:
                        await self.config.container_pool.release(sandbox)
                    except Exception:
                        logger.debug("container_pool.release failed", exc_info=True)
                else:
                    try:
                        await asyncio.to_thread(sandbox.stop)
                    except Exception:
                        pass

    def _attach_analyzer_ptrace(self, sandbox: Any) -> Any:
        """N2: create + start a PtraceBehaviorMonitor for an analyzer sandbox.

        Returns the monitor when strace attached (and sets
        ``sandbox.behavior_monitor`` so exec() wraps commands), else None.
        Imported lazily so the pool stays importable without the lab module.
        """
        try:
            from pathlib import Path

            from acuario.lab.sandbox.behavior import PtraceBehaviorMonitor

            session_id = f"{self.config.session_id_prefix}-analyzer-{uuid.uuid4().hex[:8]}"
            monitor = PtraceBehaviorMonitor(
                session_id=session_id,
                output_path=Path(self.config.output_dir),  # type: ignore[arg-type]
                container=sandbox,
                output_filename="analyzer_behavior_events.jsonl",
            )
            if monitor.start():
                sandbox.behavior_monitor = monitor
                return monitor
        except Exception:
            logger.debug("analyzer ptrace attach failed", exc_info=True)
        return None

    def _build_hunter_for_file(
        self,
        file_target: FileTarget,
        sandbox: Any,
        budget_usd: float = 0.0,
        seed_transcript: str | None = None,
        entry_point: Any = None,
        seed_context: str | None = None,
    ) -> Any:
        """Either invoke the user-supplied hunter_factory or import build_hunter_agent."""
        session_id = f"{self.config.session_id_prefix}-{uuid.uuid4().hex[:8]}"

        if self.config.hunter_factory is not None:
            return self.config.hunter_factory(file_target, sandbox, session_id)

        global _DEFAULT_HUNTER_FACTORY
        if _DEFAULT_HUNTER_FACTORY is None:
            from .analyzer import build_hunter_agent

            _DEFAULT_HUNTER_FACTORY = build_hunter_agent

        if self.config.llm is None:
            raise ValueError("HuntPoolConfig.llm is required when hunter_factory is None")

        file_path = file_target.get("path", "")
        seeded_crash = self.config.seeded_crashes_by_file.get(file_path)
        semgrep_hints = self.config.semgrep_hints_by_file.get(file_path)
        prior_mechanisms = self._recall_for_file(file_target)
        cross_file_context = self._build_cross_file_context(file_target)

        return _DEFAULT_HUNTER_FACTORY(
            file_target=file_target,
            repo_path=self.config.repo_path,
            sandbox=sandbox,
            llm=self.config.llm,  # type: ignore[arg-type]
            session_id=session_id,
            seeded_crash=seeded_crash,
            semgrep_hints=semgrep_hints,
            sandbox_manager=self.config.sandbox_manager,
            agent_mode=self.config.agent_mode,
            prompt_mode=self.config.prompt_mode,
            campaign_hint=self.config.campaign_hint,
            exploit_mode=self.config.exploit_mode,
            budget_usd=budget_usd,
            seed_transcript=seed_transcript,
            entry_point=entry_point,
            seed_context=seed_context,
            findings_pool=self.config.findings_pool,
            prior_mechanisms=prior_mechanisms,
            cross_file_context=cross_file_context,
        )

    def _recall_for_file(self, file_target: FileTarget) -> list[Any]:
        """A1: per-file mechanism recall.

        Builds a recall query from the file's language, tags, and a few
        keywords from the path (basename minus extension). Returns the
        top-K mechanisms - or an empty list if recall is disabled, the
        store is empty, or anything fails.

        Telemetry-only failures are swallowed; we never let mechanism
        recall break an audit.
        """
        store = self.config.mechanism_store
        if store is None or self.config.mechanism_recall_k <= 0:
            return []
        try:
            language = file_target.get("language", "") or ""
            tags = list(file_target.get("tags", []) or [])
            path = file_target.get("path", "") or ""
            # Cheap path-keyword extraction: basename without extension,
            # split on common separators. Helps the TF-IDF backend.
            basename = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            path_keywords = " ".join(
                t for t in basename.replace("-", " ").replace("_", " ").split() if t and len(t) > 2
            )
            query_text = f"{language} {path_keywords} {' '.join(tags)}".strip()
            recalled = store.recall(
                language=language,
                tags=tags,
                top_n=self.config.mechanism_recall_k,
                query_text=query_text or None,
            )
            if recalled:
                logger.info(
                    "[recall] injected %d prior mechanism%s into %s prompt",
                    len(recalled),
                    "" if len(recalled) == 1 else "s",
                    path,
                )
            return list(recalled)
        except Exception:
            logger.debug("Mechanism recall failed for file_target", exc_info=True)
            return []

    def _read_source_for_critic(self, file_path: str, max_chars: int = 3000) -> str:
        """G2b: read up to ``max_chars`` of source from the repo for the critic.

        Best-effort: returns an empty string if the file can't be read.  Does
        NOT try to read from the sandbox container (the critic runs in the
        runner process, not inside a sandbox) - uses ``HuntPoolConfig.repo_path``
        directly on the host filesystem.
        """
        if not file_path or not self.config.repo_path:
            return ""
        try:
            from pathlib import Path as _Path

            src = _Path(self.config.repo_path) / file_path
            if not src.is_file():
                return ""
            return src.read_text(encoding="utf-8", errors="replace")[:max_chars]
        except Exception:
            logger.debug("source read failed for critic: %s", file_path, exc_info=True)
            return ""

    def _read_code_snippet_around(
        self,
        file_path: str,
        line_number: int | None,
        window_lines: int = 10,
    ) -> str:
        """Extract a code snippet around ``line_number`` for a finding.

        Used to backfill ``code_snippet`` on critic-discovered findings
        (which emit CWE + description but no surrounding code).  Returns
        an empty string if the file or line isn't readable.  The snippet
        is a window of ±``window_lines`` lines around the target.
        """
        if not file_path or not self.config.repo_path or not line_number:
            return ""
        try:
            from pathlib import Path as _Path

            src = _Path(self.config.repo_path) / file_path
            if not src.is_file():
                return ""
            all_lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
            total = len(all_lines)
            if total == 0:
                return ""
            # Clamp to a 1-indexed line that exists in the file
            ln = max(1, min(int(line_number), total))
            start = max(0, ln - 1 - window_lines)
            end = min(total, ln + window_lines)
            return "\n".join(all_lines[start:end])
        except Exception:
            logger.debug(
                "snippet read failed for %s:%s",
                file_path,
                line_number,
                exc_info=True,
            )
            return ""

    def _build_cross_file_context(
        self,
        file_target: FileTarget,
        *,
        quiet: bool = False,
    ) -> str:
        """A4: build a cross-file context block for the analyzer prompt.

        Pulls three kinds of structural context:
          - direct callers (files that call into this file, from callgraph)
          - direct callees (files this file calls into, from callgraph)
          - prior findings on this file (from HistoricalFindingsDB)

        Returns an empty string if none of these are available or if
        ``enable_cross_file_context`` is disabled.  Never raises.

        Results are cached per-file path on the HunterPool instance so the
        skeptic gate and reflective critic can reuse the analyzer's pre-seeded
        block without rebuilding it.  When ``quiet=True`` the ``[context]``
        emission log line is suppressed (used by skeptic / critic reuse).
        """
        if not self.config.enable_cross_file_context:
            return ""

        cap = self.config.cross_file_context_max_entries
        path = file_target.get("path", "") or ""

        # serve from per-pool cache when available
        if path and path in self._cross_file_context_cache:
            return self._cross_file_context_cache[path]

        sections: list[str] = []

        # --- callgraph-derived context --------------------------------------
        cg = self.config.callgraph
        if cg is not None and path:
            try:
                # Direct callers: files that contain a call to a function
                # defined in `path`.
                caller_files: list[str] = sorted(f for f in cg.callers_of_file(path) if f)[:cap]

                # Direct callees: files that define functions called FROM `path`.
                callee_names = cg.calls_out.get(path, set())
                callee_files: list[str] = sorted(
                    {
                        def_file
                        for name in callee_names
                        for def_file in cg.defined_in.get(name, set())
                        if def_file and def_file != path
                    }
                )[:cap]

                if caller_files:
                    sections.append(
                        "Direct callers (files that call into this file):\n"
                        + "\n".join(f"  - {f}" for f in caller_files)
                    )
                if callee_files:
                    sections.append(
                        "Direct callees (files this file calls into):\n"
                        + "\n".join(f"  - {f}" for f in callee_files)
                    )
            except Exception:
                logger.debug("Callgraph cross-file context failed", exc_info=True)

        # --- historical findings for this file ------------------------------
        hdb = self.config.historical_findings_db
        repo_url = self.config.repo_url
        if hdb is not None and path and repo_url:
            try:
                # exclude THIS run's own mid-run findings (session_id_prefix
                # == the campaign session id used when persisting) so they don't
                # resurface here as "prior findings from previous audits".
                prior = hdb.query_prior(
                    repo_url=repo_url,
                    file=path,
                    exclude_session_id=self.config.session_id_prefix,
                )[:cap]
                if prior:
                    lines = [
                        f"  - {h.get('cwe', '?')} line {h.get('line_number', '?')}: "
                        f"{h.get('description', '')[:120]}"
                        for h in prior
                    ]
                    sections.append(
                        "Prior findings on this file (from previous audits):\n" + "\n".join(lines)
                    )
            except Exception:
                logger.debug("Historical findings cross-file context failed", exc_info=True)

        if not sections:
            # Cache empty result too so we don't re-query historical DB
            if path:
                self._cross_file_context_cache[path] = ""
            return ""

        block = "## Known cross-file context for this file\n\n" + "\n\n".join(sections)
        if not quiet:
            logger.info(
                "[context] pre-seeded %s with %d cross-file section(s)",
                path,
                len(sections),
            )
        if path:
            self._cross_file_context_cache[path] = block
        return block
