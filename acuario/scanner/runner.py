"""ScanRunner - the public orchestrator for the scanner pipeline.

Analog of acuario/runners/cicd/runner.py::CICDRunner, but for source-code
analyzing instead of network targets.

Pipeline:
    preprocess → sandbox build → rank → tiered hunt → verify → exploit → report
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from acuario.core.event_payloads import SourcehuntStagePayload
from acuario.core.events import EventBus
from acuario.llm.native import AsyncLLMClient
from acuario.providers import (
    ENV_ANTHROPIC_KEY,
    ENV_API_KEY,
    ENV_BASE_URL,
    ProviderManager,
    resolve_llm_endpoint,
)

from ..sandbox.analyzer_sandbox import AnalyzerSandbox
from .config import ScanConfig
from .dedup import annotate_duplicate_loci
from .mechanism_memory import (
    MechanismExtractor,
    MechanismStore,
)
from .pool import HunterPool, HuntPoolConfig, TierBudget
from .preprocessor import Preprocessor, PreprocessResult
from .prioritizer import Prioritizer, RankerConfig
from .reviewer import Reviewer, apply_verifier_result
from .state import (
    ElaborationResult,
    EvidenceLevel,
    FileTarget,
    Finding,
    PipelineStatus,
    StageOutcome,
    evidence_at_or_above,
)
from .variant_loop import (
    VariantLoop,
    VariantPatternGenerator,
)

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of a complete scanner run."""

    exit_code: int  # 0=clean, 1=medium, 2=critical/high
    repo_url: str
    repo_path: str
    findings: list[Finding]
    verified_findings: list[Finding]
    exploited_findings: list[Finding]
    files_ranked: int
    files_hunted: int
    duration_seconds: float
    cost_usd: float
    spent_per_tier: dict[str, float]
    tokens_used: int
    # Token + cost detail for the post-trim reporting. ``cost_usd`` above
    # is what the user actually paid: $0 on self-hosted, real bill on
    # commercial APIs. The fields here let the reporter render either
    # "tokens consumed + reference quote" (self-hosted) or
    # "tokens consumed + real spend" (commercial) without re-deriving
    # anything from the global CostTracker singleton.
    input_tokens: int = 0
    output_tokens: int = 0
    is_self_hosted_endpoint: bool = False
    endpoint_label: str = ""
    reference_cost_opus_usd: float = 0.0
    reference_cost_gpt_usd: float = 0.0
    output_paths: dict[str, str] = field(default_factory=dict)
    session_id: str = ""
    subsystems_hunted: int = 0
    subsystem_spent_usd: float = 0.0
    elaborated_findings: list[Finding] = field(default_factory=list)
    pipeline_status: PipelineStatus = field(default_factory=PipelineStatus)
    # Lab agent stats (populated when lab agents are active)
    skeptic_accepted: int = 0
    skeptic_refuted: int = 0
    skeptic_uncertain: int = 0  # passed through with unrefuted-doubt flag
    debate_reinstated: int = 0  # refutations the rebuttal overturned
    debate_upheld: int = 0  # refutations the skeptic stood by
    critic_leads: int = 0
    critic_verified: int = 0
    orchestrator_plans: int = 0
    orchestrator_findings: int = 0
    # subsystem-hunt yield split - how many findings came from
    # orchestrator-planned hunts vs auto-detected subsystems.
    orchestrator_plan_findings: int = 0
    auto_subsystem_findings: int = 0
    snapshot_cycles: int = 0
    ptrace_events: int = 0

    @property
    def critical_count(self) -> int:
        # Count unique loci: same-locus duplicates are marked (duplicate_of) and
        # excluded so the banner doesn't over-count a bug reported several times.
        return sum(
            1
            for f in self.verified_findings
            if not f.get("duplicate_of")
            and (f.get("severity_verified") or f.get("severity")) == "critical"
        )

    @property
    def high_count(self) -> int:
        return sum(
            1
            for f in self.verified_findings
            if not f.get("duplicate_of")
            and (f.get("severity_verified") or f.get("severity")) == "high"
        )

    @property
    def total_critical_count(self) -> int:
        # All findings (not just verified), unique loci - the "total" basis the
        # banner shows alongside the verified count so the two never contradict.
        return sum(
            1
            for f in self.findings
            if not f.get("duplicate_of")
            and (f.get("severity_verified") or f.get("severity")) == "critical"
        )

    @property
    def total_high_count(self) -> int:
        return sum(
            1
            for f in self.findings
            if not f.get("duplicate_of")
            and (f.get("severity_verified") or f.get("severity")) == "high"
        )

    @property
    def unique_finding_count(self) -> int:
        return sum(1 for f in self.findings if not f.get("duplicate_of"))

    @property
    def unique_verified_count(self) -> int:
        return sum(1 for f in self.verified_findings if not f.get("duplicate_of"))


_IMPACT_TO_SEVERITY = {
    "code_execution": "critical",
    "remote_code_execution": "critical",
    "sandbox_escape": "critical",
    "privilege_escalation": "critical",
    "cross_origin_bypass": "high",
    "info_disclosure": "high",
    "denial_of_service": "medium",
}


# finding_type values that report the ABSENCE of a vulnerability ("I looked
# and found nothing here") rather than a real bug. Matched EXPLICITLY - a bare
# empty finding_type is deliberately NOT included, because a real-but-
# unclassified finding can also carry an empty finding_type. We do NOT gate on
# evidence_level: a finding_type=none record can still carry a confirmed
# evidence_level (static_corroboration/root_cause_explained) spuriously attached
# by the LLM, so finding_type is the only reliable signal.
_NO_VULN_FINDING_TYPES = frozenset(
    {"none", "no-vulnerability", "no_vulnerability", "no-vuln", "no_vuln", "not_vulnerable"}
)


def _is_no_vulnerability_finding(finding: Finding) -> bool:
    """True if *finding* is a 'no vulnerability found' record, not a real bug.

    Such records belong in a cleared bucket, excluded from the verified set
    and the deliverable, so they don't pad the headline count.
    """
    ft = str(finding.get("finding_type") or "").strip().lower()
    return ft in _NO_VULN_FINDING_TYPES


_SEVERITY_RANK_FOR_DEDUP = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _dedup_by_location(findings: list[Finding]) -> tuple[list[Finding], int]:
    """collapse findings that share the SAME (file, line, cwe) into one
    representative (the highest-severity one) BEFORE severity recalibration.

    The same bug reported N times otherwise renders N times with N severities.
    Keyed STRICTLY on (file, line, cwe) - NEVER the coarse semantic cluster_id, which
    would collapse genuinely-distinct reinstated findings at DIFFERENT locations
    (the api.js -> Admin.jsx GitHub-PAT cluster the debate correctly reinstated).
    Findings without a concrete file + integer line + cwe are never merged - an
    empty key is not a reliable same-bug signal.

    Returns (deduped_findings, merged_count), order-preserving on first sight.
    """

    def _sev_rank(f: Finding) -> int:
        sev = (f.get("severity_verified") or f.get("severity") or "info").lower()
        return _SEVERITY_RANK_FOR_DEDUP.get(sev, 4)

    reps: dict[tuple[str, int, str], Finding] = {}
    order: list[Any] = []  # a (file,line,cwe) key for merged, or the Finding itself
    merged = 0
    for f in findings:
        file = str(f.get("file") or "").strip().lower()
        line = f.get("line_number")
        cwe = str(f.get("cwe") or "").strip().upper()
        if not file or not isinstance(line, int) or not cwe:
            order.append(f)  # no reliable dedup key - pass through untouched
            continue
        key = (file, line, cwe)
        if key not in reps:
            reps[key] = f
            order.append(key)
        else:
            merged += 1
            if _sev_rank(f) < _sev_rank(reps[key]):
                reps[key] = f  # keep the higher-severity representative
    out = [reps[k] if isinstance(k, tuple) else k for k in order]
    return out, merged


def _apply_elaboration(finding: Finding, elab_result: ElaborationResult) -> Finding:
    """Create a new finding from a successful elaboration."""
    import uuid

    sev = _IMPACT_TO_SEVERITY.get(
        elab_result.upgraded_impact or "",
        "high",
    )
    return cast(
        "Finding",
        {
            "id": f"elab-{uuid.uuid4().hex[:8]}",
            "related_finding_id": finding.get("id", "unknown"),
            "file": finding.get("file", ""),
            "line_number": finding.get("line_number"),
            "end_line": finding.get("end_line"),
            "finding_type": finding.get("finding_type", "unknown"),
            "cwe": finding.get("cwe"),
            "severity": sev,
            "severity_verified": sev,
            "evidence_level": "exploit_demonstrated",
            "verified": True,
            "description": (
                f"Elaborated from {finding.get('id', '?')}: {elab_result.upgrade_path}"
            ),
            "exploit": elab_result.upgraded_exploit_code or "",
            "exploit_success": True,
            "exploit_impact": elab_result.upgraded_impact or "",
            "discovered_by": "elaboration_agent",
            "elaboration_upgrade_path": elab_result.upgrade_path,
            "exploit_chained_findings": elab_result.chained_findings,
        },
    )


class ScanRunner:
    """Public entry point for the scanner pipeline."""

    def __init__(
        self,
        repo_url: str = "",
        branch: str = "main",
        local_path: str | None = None,
        depth: str = "standard",  # quick | standard | deep
        budget_usd: float = 0.0,
        max_parallel: int = 8,
        tier_budget: TierBudget | None = None,
        output_dir: str | None = None,
        output_formats: list[str] | None = None,
        no_verify: bool = False,
        no_exploit: bool = False,
        exploit_budget: str | None = None,  # "standard" | "deep" | "campaign" | None (auto)
        adversarial_verifier: bool = True,  # on by default
        adversarial_threshold: EvidenceLevel | None = "static_corroboration",  # budget gate
        validator_mode: str = "v2",  # "v1" (Reviewer) | "v2" (4-axis Validator)
        recalibrate_severity: bool = False,  # deterministic axis-based severity caps
        skeptic_shadow_mode: bool = False,  # skeptic logs verdicts but doesn't gate
        enable_mechanism_memory: bool = True,  # cross-run mechanism store
        mechanism_store_path: Any = None,  # override default store location
        mechanism_recall_k: int = 3,  # top-K mechanisms recalled per file
        enable_stability_verification: bool = True,  # Stage 2.5 PoC stability
        enable_variant_loop: bool = False,  # default OFF - 0/97 verified yield
        enable_sca: bool = True,  # deterministic vulnerable-dependency scan
        model_override: str | None = None,
        provider_manager: ProviderManager | None = None,
        prioritizer_llm: Any = None,  # injectable for tests
        analyzer_llm: Any = None,
        reviewer_llm: Any = None,
        exploit_dev_llm: Any = None,
        sandbox_factory: Any = None,  # callable[[], SandboxContainer]
        parent_session_id: str | None = None,
        agent_mode: str = "auto",  # "auto" | "constrained" | "deep"
        prompt_mode: str = "unconstrained",  # "unconstrained" | "specialist"
        campaign_hint: str | None = None,
        exploit_mode: bool = False,
        starting_band: str | None = None,  # "fast" | "standard" | "deep" | None (auto)
        redundancy_override: int | None = None,
        shard_entry_points: bool | None = None,  # None = auto (deep depth)
        min_shard_rank: int = 4,
        min_project_loc: int = 50_000,
        enable_findings_pool: bool = True,
        historical_db_path: Any = None,
        enable_cross_file_context: bool = True,  # cross-file context pre-seed
        enable_skeptic_gate: bool = True,  # adversarial finding gate
        enable_debate: bool = True,  # analyzer↔skeptic rebuttal on refuted findings
        enable_critic: bool = True,  # reflective post-ReAct critic
        enable_orchestrator: bool = True,  # cross-file investigation planner
        enable_subsystem_hunt: bool = False,
        subsystem_paths: list[str] | None = None,
        no_per_file_hunt: bool = False,
        subsystem_budget_usd: float = 0.0,
        subsystem_max_parallel: int = 4,
        enable_behavior_monitor: bool = True,
        enable_sandbox_snapshots: bool = True,  # docker-commit checkpoints
        enable_ptrace_monitor: bool = True,  # real-time syscall monitor
        enable_warm_pool: bool = False,  # reuse warm containers across files
        strict_seccomp: bool = False,  # add network syscalls to analyzer denylist
        exploit_compose: bool = True,  # host-orchestrate compose apps for exploit-dev
        gvisor_runtime: str | None = None,
        preprocessing: bool = True,
        seed_harness_crashes: bool = False,
        *,
        config: ScanConfig | None = None,
    ):
        # --- Resolve from ScanConfig when provided ----------------------
        if config is not None:
            t = config.target
            b = config.budget
            o = config.output
            f = config.features
            h = config.tuning
            # Target params - keyword args override config if explicitly given
            repo_url = repo_url or t.repo_url
            branch = branch if branch != "main" else t.branch
            local_path = local_path if local_path is not None else t.local_path
            depth = depth if depth != "standard" else t.depth
            # Budget params
            budget_usd = budget_usd if budget_usd != 0.0 else b.budget_usd
            max_parallel = max_parallel if max_parallel != 8 else b.max_parallel
            tier_budget = tier_budget if tier_budget is not None else b.tier_budget
            exploit_budget = exploit_budget if exploit_budget is not None else b.exploit_budget
            subsystem_budget_usd = (
                subsystem_budget_usd if subsystem_budget_usd != 0.0 else b.subsystem_budget_usd
            )
            subsystem_max_parallel = (
                subsystem_max_parallel if subsystem_max_parallel != 4 else b.subsystem_max_parallel
            )
            # Output params
            output_dir = output_dir if output_dir is not None else (o.output_dir or None)
            output_formats = output_formats if output_formats is not None else o.output_formats
            # Feature flags
            no_verify = no_verify or f.no_verify
            no_exploit = no_exploit or f.no_exploit
            enable_variant_loop = enable_variant_loop and f.enable_variant_loop
            enable_stability_verification = (
                enable_stability_verification and f.enable_stability_verification
            )
            enable_mechanism_memory = enable_mechanism_memory and f.enable_mechanism_memory
            enable_behavior_monitor = enable_behavior_monitor and f.enable_behavior_monitor
            enable_findings_pool = enable_findings_pool and f.enable_findings_pool
            enable_subsystem_hunt = enable_subsystem_hunt or f.enable_subsystem_hunt
            no_per_file_hunt = no_per_file_hunt or f.no_per_file_hunt
            seed_harness_crashes = seed_harness_crashes or f.seed_harness_crashes
            preprocessing = preprocessing and f.preprocessing
            adversarial_verifier = adversarial_verifier and f.adversarial_verifier
            adversarial_threshold = (
                adversarial_threshold
                if adversarial_threshold != "static_corroboration"
                else cast("EvidenceLevel", f.adversarial_threshold)
            )
            validator_mode = validator_mode if validator_mode != "v2" else f.validator_mode
            exploit_mode = exploit_mode or f.exploit_mode
            agent_mode = agent_mode if agent_mode != "auto" else f.agent_mode
            prompt_mode = prompt_mode if prompt_mode != "unconstrained" else f.prompt_mode
            # Hunt tuning
            starting_band = starting_band if starting_band is not None else h.starting_band
            redundancy_override = (
                redundancy_override if redundancy_override is not None else h.redundancy_override
            )
            shard_entry_points = (
                shard_entry_points if shard_entry_points is not None else h.shard_entry_points
            )
            min_shard_rank = min_shard_rank if min_shard_rank != 4 else h.min_shard_rank
            min_project_loc = min_project_loc if min_project_loc != 50_000 else h.min_project_loc
            subsystem_paths = subsystem_paths if subsystem_paths is not None else h.subsystem_paths
            campaign_hint = campaign_hint if campaign_hint is not None else h.campaign_hint
            gvisor_runtime = gvisor_runtime if gvisor_runtime is not None else h.gvisor_runtime

        if not repo_url:
            raise ValueError(
                "repo_url is required - pass it directly or via "
                "config=ScanConfig(target=TargetConfig(repo_url=...))"
            )

        # Store the config for introspection (None if constructed the old way)
        self._config = config

        self.repo_url = repo_url
        self.branch = branch
        self.local_path = local_path
        self.depth = depth
        self.budget_usd = budget_usd
        self.max_parallel = max_parallel
        self.tier_budget = tier_budget or TierBudget()
        if output_dir is None:
            from acuario.core.config import default_results_dir

            output_dir = default_results_dir("scanner")
        self.output_dir = output_dir
        self.output_formats = output_formats or ["sarif", "markdown", "json", "pdf"]
        self.no_verify = no_verify
        self.no_exploit = no_exploit
        self._exploit_budget_override = exploit_budget
        self.adversarial_verifier = adversarial_verifier
        self.adversarial_threshold = adversarial_threshold
        self.validator_mode = validator_mode
        self._recalibrate_severity = recalibrate_severity
        # calibration instrumentation. Rows accumulate during verify and
        # flush to calibration.jsonl after exploit-dev, joining the skeptic
        # verdict, the validator verdict, and the exploit outcome per finding.
        self._calibration_rows: list[dict] = []
        self._skeptic_shadow_mode = skeptic_shadow_mode
        # Calibration tracking is not active; _record_calibration()
        # short-circuits when the store is None.
        self._calibration_store = None
        self.enable_mechanism_memory = enable_mechanism_memory
        self._mechanism_store = (
            MechanismStore(path=mechanism_store_path) if enable_mechanism_memory else None
        )
        # how many prior mechanisms to recall per file. Clamp to [0, 10].
        self._mechanism_recall_k = max(0, min(10, int(mechanism_recall_k)))
        self.enable_stability_verification = enable_stability_verification
        self.enable_variant_loop = enable_variant_loop
        self._enable_sca = enable_sca
        self.model_override = model_override
        self.provider_manager: ProviderManager | None = provider_manager
        self.prioritizer_llm = prioritizer_llm
        self.analyzer_llm = analyzer_llm
        self.reviewer_llm = reviewer_llm
        self.exploit_dev_llm = exploit_dev_llm
        self.sandbox_factory = sandbox_factory
        self._sandbox_manager: AnalyzerSandbox | None = None
        self._session_id = parent_session_id or f"audit-{uuid.uuid4().hex[:8]}"
        self._agent_mode_override = agent_mode
        self._prompt_mode = prompt_mode
        self._campaign_hint = campaign_hint
        self._exploit_mode = exploit_mode
        self._starting_band_override = starting_band
        self._redundancy_override = redundancy_override
        self._shard_entry_points_override = shard_entry_points
        self._min_shard_rank = min_shard_rank
        self._min_project_loc = min_project_loc
        self._enable_findings_pool = enable_findings_pool
        self._historical_db_path = historical_db_path
        self._enable_cross_file_context = enable_cross_file_context
        self._enable_skeptic_gate = enable_skeptic_gate
        self._enable_debate = enable_debate
        self._enable_critic = enable_critic
        self._enable_orchestrator = enable_orchestrator
        self._enable_subsystem_hunt = enable_subsystem_hunt or bool(subsystem_paths)
        self._subsystem_paths = subsystem_paths
        self._no_per_file_hunt = no_per_file_hunt
        self._subsystem_budget_usd = subsystem_budget_usd
        self._subsystem_max_parallel = subsystem_max_parallel
        self._injected_findings_pool = None
        self._injected_historical_db = None
        self._enable_behavior_monitor = enable_behavior_monitor
        self._enable_sandbox_snapshots = enable_sandbox_snapshots
        self._enable_ptrace_monitor = enable_ptrace_monitor
        self._enable_warm_pool = enable_warm_pool
        self._strict_seccomp = strict_seccomp
        # P0.3: bring a multi-service docker-compose target up on the host (on an
        # internal-only network) for live exploit-dev. Default on; --no-exploit-compose
        # disables it and forces the single-process loopback + fail-fast path.
        self._exploit_compose = exploit_compose
        # syscall events captured across analyzer sessions (folded into the
        # ScanResult ptrace_events total alongside exploit-dev's count).
        self._analyzer_ptrace_events = 0
        self._gvisor_runtime = gvisor_runtime
        self._preprocessing = preprocessing
        self._seed_harness_crashes = seed_harness_crashes
        # Live snapshot of findings for the optional progress dashboard to READ
        # (populated per file during analyze via on_file_complete). Read-only to
        # the dashboard; never affects the scan. Empty until the first file lands.
        self.live_findings: list[Finding] = []

    def _inject_campaign_pool(
        self,
        findings_pool: Any,
        historical_db: Any = None,
    ) -> None:
        """Allow campaign runner to inject a shared pool. Must be called before arun()."""
        self._injected_findings_pool = findings_pool
        self._injected_historical_db = historical_db

    @property
    def _agent_mode(self) -> str:
        if self._agent_mode_override != "auto":
            return self._agent_mode_override
        if self.depth in ("standard", "deep"):
            return "deep"
        return "constrained"

    @property
    def _starting_band(self) -> str:
        if self._starting_band_override:
            return self._starting_band_override
        return {"standard": "fast", "deep": "standard"}.get(self.depth, "fast")

    @property
    def _max_band(self) -> str:
        if self._starting_band_override:
            return self._starting_band_override
        return {"standard": "standard", "deep": "deep"}.get(self.depth, "standard")

    @property
    def _exploit_budget_band(self) -> str:
        if self._exploit_budget_override:
            return self._exploit_budget_override
        if self.depth == "deep":
            return "deep"
        return "standard"

    @property
    def _shard_entry_points(self) -> bool:
        if self._shard_entry_points_override is not None:
            return self._shard_entry_points_override
        return self.depth == "deep"

    # --- Public API ---------------------------------------------------------

    def _emit_stage(
        self,
        stage: str,
        status: str,
        findings_so_far: int = 0,
        cost_usd: float = 0.0,
        detail: str = "",
    ) -> None:
        EventBus().emit_scanner_stage(
            SourcehuntStagePayload(
                session_id=self._session_id,
                repo=self.repo_url,
                stage=stage,
                status=status,
                findings_so_far=findings_so_far,
                cost_usd=cost_usd,
                detail=detail,
            )
        )

    def run(self) -> ScanResult:
        return asyncio.run(self.arun())

    async def arun(self) -> ScanResult:
        start_time = time.monotonic()
        self._ensure_output_dir_layout()
        pipeline_status = PipelineStatus()
        logger.info("[audit] ◐ starting session %s on %s", self._session_id, self.repo_url)
        # bound before the try so the outer finally can shut the warm pool
        # down even if a stage between pool-run and the inline shutdown raises.
        container_pool = None
        try:
            # 1. Preprocess
            self._emit_stage("preprocess", "started")
            preprocess_result = self._preprocess()
            repo_path = preprocess_result.repo_path
            files = preprocess_result.file_targets
            files_ranked = len(files)
            logger.info("[preprocess] ▸ enumerated %d source file(s)", files_ranked)
            self._emit_stage("preprocess", "completed", detail=f"Enumerated {files_ranked} files")
            # record preprocessor success so Pipeline Health doesn't only
            # show the post-preprocess stages.  Failure paths live inside
            # ``_preprocess()`` and surface via raised exceptions captured in
            # the outer ``try`` of arun(); we only land here on success.
            pipeline_status.record_succeeded("preprocessor")
            self._ensure_sandbox_factory(repo_path, files)

            # Note: callgraph-based reachability (A2) is already stamped by
            # the preprocessor's _propagate_reachability() which runs with
            # the extended web_entry/cli_entry tags for web applications.
            # The prioritizer's _apply_floors() then enforces the
            # hop-distance-based floor/ceiling rules.

            # 2. Rank - unless depth=quick AND no LLM available
            prioritizer_llm = self._get_native_client("prioritizer", self.prioritizer_llm)
            self._emit_stage("rank", "started", detail=f"{len(files)} files")
            if prioritizer_llm is not None and files:
                logger.info("[prioritize] ▸ scoring %d file(s)", len(files))
                try:
                    ranker_config = RankerConfig()
                    if not self._preprocessing:
                        ranker_config.include_static_hints = False
                        ranker_config.include_imports_by = False
                    if prioritizer_llm.provider_name == "openai_resp":
                        ranker_config.chunk_size = 30
                        ranker_config.max_inflight_chunks = self.max_parallel
                        logger.info(
                            "Prioritizer tuned for openai_resp backend: chunk_size=%d max_inflight_chunks=%d",
                            ranker_config.chunk_size,
                            ranker_config.max_inflight_chunks,
                        )
                    await Prioritizer(prioritizer_llm, ranker_config).arank(files)
                    logger.info("[prioritize] ● scoring complete")
                    pipeline_status.record_succeeded("prioritizer")
                    self._emit_stage("rank", "completed", detail=f"Ranked {len(files)} files")
                except Exception:
                    logger.warning("Prioritizer failed", exc_info=True)
                    pipeline_status.record_degraded(
                        "prioritizer",
                        "All files assigned default priority scores (surface=3, influence=2)",
                    )
                    self._emit_stage("rank", "degraded", detail="Default priority scores used")
            else:
                logger.info("[prioritize] ▸ skipped (no LLM configured)")
                pipeline_status.record_degraded(
                    "prioritizer",
                    "All files assigned default priority scores (surface=3, influence=2)",
                )
                # Fallback: assign reasonable defaults so tier assignment still works
                for ft in files:
                    ft["surface"] = ft.get("surface") or 3
                    ft["influence"] = ft.get("influence") or 2
                    ft["reachability"] = ft.get("reachability") or 3
                    ft["priority"] = (
                        ft["surface"] * 0.5 + ft["influence"] * 0.2 + ft["reachability"] * 0.3
                    )

            # depth=quick exits here with the static_findings as-is
            if self.depth == "quick":
                return self._build_quick_result(
                    start_time=start_time,
                    repo_path=repo_path,
                    preprocess_result=preprocess_result,
                    files_ranked=files_ranked,
                    pipeline_status=pipeline_status,
                )

            # The analyzer pool runs without seeded crash context.
            seeded_by_file: dict[str, dict] = {}

            # Build a per-file Semgrep hint lookup so analyzers get their file's hits
            semgrep_hints_by_file: dict[str, list[dict]] = {}
            for sf in preprocess_result.semgrep_findings:
                semgrep_hints_by_file.setdefault(sf.get("file", ""), []).append(sf)

            # per-file mechanism recall is done inside HunterPool
            # (`_recall_for_file`), so we just hand the store to the pool config
            # below.

            # 2.7. Entry-point extraction
            entry_points_by_file: dict = {}
            if self._shard_entry_points and preprocess_result.callgraph is not None:
                total_loc = sum(ft.get("loc", 0) for ft in files)
                if total_loc >= self._min_project_loc:
                    try:
                        from .entry_points import extract_entry_points_batch

                        entry_points_by_file = extract_entry_points_batch(
                            file_targets=files,
                            callgraph=preprocess_result.callgraph,
                            repo_path=repo_path,
                            min_rank=self._min_shard_rank,
                        )
                    except Exception:
                        logger.warning("Entry-point extraction failed", exc_info=True)
                        pipeline_status.record_degraded(
                            "entry_points",
                            "Entry-point sharding unavailable; analyzing at file level",
                        )

            seed_corpus_by_file: dict = {}

            # 2.9. Shared findings pool
            findings_pool = None
            historical_db = None
            if self._injected_findings_pool is not None:
                # Campaign mode: use shared pool
                findings_pool = self._injected_findings_pool
                historical_db = self._injected_historical_db
            elif self._enable_findings_pool:
                from .findings_pool import FindingsPool
                from .historical_findings_db import HistoricalFindingsDB

                checkpoint_path = Path(self.output_dir) / self._session_id / "findings_pool.jsonl"
                findings_pool = FindingsPool(checkpoint_path=checkpoint_path)
                try:
                    # Opened for downstream use: per-file "prior findings" prompt
                    # context in the hunt pool (pool.py query_prior) and
                    # mark_reviewed/mark_exploited persistence. No campaign-start
                    # dedup pass runs here.
                    historical_db = HistoricalFindingsDB(path=self._historical_db_path)
                except Exception:
                    logger.warning("Historical findings DB load failed", exc_info=True)
                    historical_db = None

            # 3. Tiered hunt
            analyzer_llm = self._get_native_client("analyzer", self.analyzer_llm)
            all_findings: list[Finding] = []
            files_hunted = 0
            pool = None  # kept in scope so the reviewer can reuse the
            # pool's cross-file-context builder even on paths where the hunt
            # branch below doesn't run.
            spent_per_tier: dict[str, float] = {"A": 0.0, "B": 0.0, "C": 0.0}
            band_stats: dict | None = None

            # Lab agents - instantiate per-session (after analyzer_llm is resolved).
            session_out = Path(self.output_dir) / self._session_id
            session_out.mkdir(parents=True, exist_ok=True)

            skeptic_gate = None
            if self._enable_skeptic_gate and analyzer_llm is not None:
                try:
                    from acuario.lab.agents.skeptic import SkepticGate

                    skeptic_gate = SkepticGate(
                        llm=self._get_native_client("skeptic", self.analyzer_llm),
                        output_dir=session_out,
                        shadow_mode=self._skeptic_shadow_mode,  # O8
                    )
                    if self._skeptic_shadow_mode:
                        logger.info(
                            "[skeptic] shadow mode ON - verdicts logged but NOT "
                            "gating; validator acts as ground truth"
                        )
                except Exception:
                    logger.debug("Skeptic gate init failed", exc_info=True)

            critic_agent = None
            if self._enable_critic and analyzer_llm is not None:
                try:
                    from acuario.lab.agents.critic import ReflectiveCritic

                    critic_agent = ReflectiveCritic(
                        llm=self._get_native_client("critic", self.analyzer_llm),
                        output_dir=session_out,
                    )
                except Exception:
                    logger.debug("Reflective critic init failed", exc_info=True)

            orchestrator = None
            if self._enable_orchestrator and analyzer_llm is not None:
                try:
                    from acuario.lab.agents.orchestrator import CrossFileOrchestrator

                    orchestrator = CrossFileOrchestrator(
                        llm=self._get_native_client("orchestrator", self.analyzer_llm),
                        output_dir=session_out,
                    )
                except Exception:
                    logger.debug("Cross-file orchestrator init failed", exc_info=True)

            # optionally pre-warm a container pool the analyzer pool borrows
            # from. Opt-in (--warm-container-pool); default stays per-file spawn.
            container_pool = None
            if (
                self._enable_warm_pool
                and self.sandbox_factory is not None
                and not self._no_per_file_hunt
                and analyzer_llm is not None
                and files
            ):
                from ..sandbox.container_pool import ContainerPool

                container_pool = ContainerPool(
                    factory=self.sandbox_factory,
                    size=max(1, self.max_parallel),
                )
                live = await container_pool.start()
                if live == 0:
                    logger.warning("[pool] no warm containers spawned; using per-file spawn")
                    container_pool = None

            if self._no_per_file_hunt:
                logger.info("Per-file hunt skipped (--no-per-file-hunt)")
            elif analyzer_llm is not None and files:
                self._emit_stage("hunt", "started", detail=f"{len(files)} files")
                logger.info("[analyze] ▸ pool starting on %d file(s)", len(files))

                # incremental checkpoint hook. Persist each file's findings
                # to the historical DB the moment the file completes, so a crash
                # mid-pool leaves the done files recoverable via
                # `acuario audit --resume`. INSERT OR IGNORE makes this and the
                # end-of-pool batch ingest idempotent. Skipped under campaign
                # (injected pool) - campaign owns bulk ingestion.
                def _on_file_complete(file_findings: list[Finding]) -> None:
                    if not file_findings:
                        return
                    # Feed the live progress snapshot (dashboard reads this). Guarded
                    # so a dashboard/accounting hiccup can never affect the scan.
                    try:
                        self.live_findings.extend(file_findings)
                    except Exception:
                        pass
                    if historical_db is not None and self._injected_findings_pool is None:
                        try:
                            historical_db.ingest_campaign(
                                file_findings,
                                repo_url=self.repo_url,
                                session_id=self._session_id,
                            )
                        except Exception:
                            # WARNING, not debug: a dropped incremental checkpoint
                            # means --resume after a crash loses this file's
                            # findings, with no record that persistence failed.
                            logger.warning("incremental DB checkpoint failed", exc_info=True)

                pool = HunterPool(
                    HuntPoolConfig(
                        files=files,
                        repo_path=repo_path,
                        sandbox_factory=self.sandbox_factory,
                        sandbox_manager=self._sandbox_manager,
                        container_pool=container_pool,
                        hunter_factory=None,
                        llm=analyzer_llm,
                        max_parallel=self.max_parallel,
                        budget_usd=self.budget_usd,
                        tier_budget=self.tier_budget,
                        on_file_complete=_on_file_complete,
                        session_id_prefix=self._session_id,
                        seeded_crashes_by_file=seeded_by_file,
                        semgrep_hints_by_file=semgrep_hints_by_file,
                        agent_mode=self._agent_mode,
                        prompt_mode=self._prompt_mode,
                        campaign_hint=self._campaign_hint,
                        exploit_mode=self._exploit_mode,
                        starting_band=self._starting_band,
                        max_band=self._max_band,
                        redundancy_override=self._redundancy_override,
                        entry_points_by_file=entry_points_by_file,
                        seed_corpus_by_file=seed_corpus_by_file,
                        shard_entry_points=self._shard_entry_points,
                        findings_pool=findings_pool,
                        # per-file mechanism recall
                        mechanism_store=self._mechanism_store,
                        mechanism_recall_k=self._mechanism_recall_k,
                        # cross-file context pre-seed
                        callgraph=preprocess_result.callgraph,
                        historical_findings_db=historical_db,
                        repo_url=self.repo_url,
                        enable_cross_file_context=self._enable_cross_file_context,
                        # skeptic gate
                        skeptic_gate=skeptic_gate,
                        # reflective critic
                        critic_agent=critic_agent,
                        # ptrace the analyzer sandboxes too (deep mode only,
                        # respects --no-ptrace-monitor). Streams to
                        # analyzer_behavior_events.jsonl in the session dir.
                        enable_ptrace_for_analyzers=(
                            self._enable_ptrace_monitor and self.depth == "deep"
                        ),
                        output_dir=str(session_out),
                        # analyzer↔skeptic debate on refuted findings.
                        enable_debate=self._enable_debate,
                    )
                )
                try:
                    all_findings = await pool.arun()
                    self.live_findings = all_findings  # authoritative snapshot (dashboard reads it)
                    self._analyzer_ptrace_events = pool.analyzer_ptrace_events
                    logger.info(
                        "[analyze] ● pool complete · %d finding(s) collected", len(all_findings)
                    )
                    if skeptic_gate is not None:
                        logger.info("[skeptic] %s", skeptic_gate.summary())
                        # record skeptic_gate outcome.  The pool drives
                        # the gate inline (pool.py), so by the time we land here
                        # the gate has been exercised end-to-end.  If any finding
                        # was accepted only because the LLM call failed
                        # (fail-open), the gate was partially blind - mark it
                        # DEGRADED so Pipeline Health shows the precision risk
                        # instead of a clean "succeeded".
                        fail_open = getattr(skeptic_gate, "fail_open_count", 0)
                        if fail_open > 0:
                            logger.warning(
                                "[skeptic] gate degraded: %d finding(s) accepted on LLM "
                                "failure (fail-open) - precision not enforced for those",
                                fail_open,
                            )
                            pipeline_status.record_degraded(
                                "skeptic_gate",
                                fallback=(
                                    f"{fail_open} finding(s) accepted without screening "
                                    "(skeptic LLM errors); precision gate partially blind"
                                ),
                            )
                        else:
                            pipeline_status.record_succeeded("skeptic_gate")
                    if critic_agent is not None:
                        # critic ran alongside the analyzer pool (the pool
                        # invokes ReflectiveCritic per file).  We treat the
                        # pool's success as critic success - per-file critic
                        # errors are already swallowed inside pool.py and do
                        # not abort the pool run.
                        pipeline_status.record_succeeded("critic")
                    pipeline_status.record_succeeded("hunter_pool")
                    self._emit_stage(
                        "hunt",
                        "completed",
                        findings_so_far=len(all_findings),
                        cost_usd=pool.total_spent,
                        detail=f"{len(all_findings)} findings",
                    )
                except Exception:
                    logger.warning("Analyzer pool run failed", exc_info=True)
                    pipeline_status.record_degraded(
                        "hunter_pool",
                        "Analyzer phase produced no findings due to error",
                    )
                spent_per_tier = pool.spent_per_tier
                band_stats = {
                    "fast_runs": pool.runs_per_band.get("fast", 0),
                    "fast_cost": pool.spent_per_band.get("fast", 0.0),
                    "standard_runs": pool.runs_per_band.get("standard", 0),
                    "standard_cost": pool.spent_per_band.get("standard", 0.0),
                    "deep_runs": pool.runs_per_band.get("deep", 0),
                    "deep_cost": pool.spent_per_band.get("deep", 0.0),
                    "promotions": pool.promotion_counts,
                }
                files_hunted = sum(
                    [
                        p.get("tier") in ("A", "B", "C")
                        for p in files
                        if p.get("tier") != "C" or self.tier_budget.tier_c_fraction > 0
                    ]
                )
            else:
                logger.info("[analyze] ▸ pool skipped (no LLM configured)")

            # the warm pool is only borrowed by the analyzer pool above;
            # the subsystem hunt spawns its own containers. Shut it down now so
            # we don't hold idle containers through the rest of the pipeline.
            if container_pool is not None:
                logger.info("[pool] %s", container_pool.stats)
                await container_pool.shutdown()
                container_pool = None

            # Cross-file orchestrator - emit subsystem investigation
            # plans after the primary pool completes, then materialize them as
            # SubsystemTarget objects that the subsystem-hunt block below will
            # actually execute.
            orchestrator_targets: list = []
            if orchestrator is not None and all_findings and findings_pool is not None:
                try:
                    plans = await orchestrator.aplan(
                        findings=all_findings,
                        file_targets=files,
                        callgraph=preprocess_result.callgraph,
                    )
                    logger.info("[orchestrate] %s", orchestrator.summary())
                    # orchestrator success recorded after aplan() returns.
                    # An empty plan list still counts as success - the
                    # orchestrator ran, it just had nothing cross-file-worthy
                    # to emit.  Failure path is the outer except below.
                    pipeline_status.record_succeeded("orchestrator")
                    # orchestrator-derived plans always execute when the
                    # orchestrator is on, regardless of --subsystem-hunt.
                    # The whole point of the orchestrator is to drive hunts, so
                    # auto-enable subsystem hunt as a side effect so the
                    # downstream block actually runs and emits findings.
                    if plans:
                        if not self._enable_subsystem_hunt:
                            logger.info(
                                "[orchestrate] auto-enabling subsystem hunt "
                                "to execute %d orchestrator plan(s)",
                                len(plans[:3]),
                            )
                            self._enable_subsystem_hunt = True
                        # convert each plan into a SubsystemTarget so the
                        # existing SubsystemHuntRunner can execute them as
                        # full multi-file investigations rather than just
                        # log lines.  Cap at 3 follow-ups to bound cost.
                        for plan in plans[:3]:
                            logger.info(
                                "[orchestrate] follow-up hunt: %s → %s",
                                ", ".join(plan.files),
                                plan.hunt_focus,
                            )
                            try:
                                target = plan.to_subsystem_target(files)
                                # Log the plan → target conversion so the run
                                # reveals whether the orchestrator is asking
                                # for files that don't exist, files that already
                                # got hunted, or something else - instead of a
                                # silently-empty target.files dropping the plan
                                # with no signal in the log.
                                logger.info(
                                    "[orchestrate] plan %s → SubsystemTarget: "
                                    "requested %d files, resolved %d, focus=%r",
                                    plan.plan_id,
                                    len(plan.files),
                                    len(target.files),
                                    plan.hunt_focus,
                                )
                                if target.files:
                                    orchestrator_targets.append(target)
                                else:
                                    logger.warning(
                                        "[orchestrate] plan %s has no valid files after filter - requested %s but none match the codebase; skipping hunt",  # noqa: E501
                                        plan.plan_id,
                                        plan.files,
                                    )
                            except Exception:
                                logger.debug(
                                    "Failed to convert plan %s to SubsystemTarget",
                                    plan.plan_id,
                                    exc_info=True,
                                )
                except Exception:
                    logger.debug("Orchestrator failed", exc_info=True)

            # 3.5. Behavioral monitoring of findings text.
            if self._enable_behavior_monitor and all_findings:
                try:
                    from .behavior_monitor import BehaviorMonitor

                    bmon = BehaviorMonitor(session_id=self._session_id)
                    for f in all_findings:
                        for field in ("description", "poc", "exploit", "evidence"):
                            text = f.get(field, "")
                            if text:
                                bmon.scan_text(str(text), finding_id=f.get("id", ""))
                    alerts = bmon.get_alerts()
                    if alerts:
                        logger.warning(
                            "Behavior monitor: %d alerts - %s",
                            len(alerts),
                            bmon.summary(),
                        )
                    # regex behavior monitor ran end-to-end.  This is the
                    # post-hoc text-scan path (the fallback when ptrace
                    # isn't available); a separate ptrace success record lives
                    # in exploit_dev.py if/when it actually attaches.
                    pipeline_status.record_succeeded("behavior_monitor")
                except Exception:
                    logger.debug("Behavior monitor failed", exc_info=True)
                    pipeline_status.record_degraded(
                        "behavior_monitor",
                        "Regex behavior monitor failed; no behavior alerts emitted",
                    )

            # Promote static findings into the all_findings list so depth=quick
            # output is still useful when no analyzer llm is available
            all_findings = self._merge_static_findings(all_findings, preprocess_result)
            self.live_findings = all_findings  # include merged static findings in the live tally

            # 3.5. Persist findings to historical DB
            # Skip when running under campaign - campaign handles bulk ingestion.
            if historical_db is not None and all_findings and self._injected_findings_pool is None:
                try:
                    count = historical_db.ingest_campaign(
                        all_findings,
                        repo_url=self.repo_url,
                        session_id=self._session_id,
                    )
                    logger.info("[audit] ▸ persisted %d finding(s) to historical DB", count)
                except Exception:
                    logger.warning("Historical DB ingest failed", exc_info=True)
                finally:
                    historical_db.close()

            # 3.7. Subsystem hunt
            subsystems_hunted = 0
            subsystem_spent = 0.0
            _subsystem_findings_count = 0
            # A/B yield split - orchestrator-planned vs auto-detected.
            _orchestrator_plan_findings = 0
            _auto_subsystem_findings = 0
            if self._enable_subsystem_hunt and analyzer_llm is not None:
                from .subsystem import (
                    SubsystemHuntConfig,
                    identify_subsystems_auto,
                    subsystem_from_path,
                )
                from .subsystem import (
                    SubsystemHuntRunner as SubsysRunner,
                )

                subsystem_targets: list = []
                # orchestrator-derived targets take precedence - they come
                # from LLM reasoning over findings + callgraph + structural
                # summaries, so they're more informed than the auto-detector's
                # purely structural heuristics.
                if orchestrator_targets:
                    subsystem_targets.extend(orchestrator_targets)
                    logger.info(
                        "[orchestrate] queued %d orchestrator-derived subsystem target(s)",
                        len(orchestrator_targets),
                    )

                if self._subsystem_paths:
                    for sp in self._subsystem_paths:
                        try:
                            st = subsystem_from_path(
                                sp,
                                files,
                                callgraph=preprocess_result.callgraph,
                                entry_points_by_file=entry_points_by_file,
                            )
                            subsystem_targets.append(st)
                        except ValueError:
                            logger.warning("No files match subsystem path: %s", sp)
                elif not orchestrator_targets:
                    # fall back to auto-detection only if the orchestrator
                    # produced nothing (e.g. when --no-orchestrator is set or
                    # the LLM emitted no plans).  Avoids duplicating the same
                    # subsystem investigations the orchestrator already covered.
                    subsystem_targets = identify_subsystems_auto(
                        files,
                        callgraph=preprocess_result.callgraph,
                        entry_points_by_file=entry_points_by_file,
                    )

                if subsystem_targets:
                    logger.info(
                        "Subsystem hunt: %d targets identified",
                        len(subsystem_targets),
                    )
                    for st in subsystem_targets:
                        logger.info(
                            "  %s (%d files, priority=%.2f)",
                            st.name,
                            len(st.files),
                            st.priority,
                        )
                    subsys_runner = SubsysRunner(
                        SubsystemHuntConfig(
                            subsystems=subsystem_targets,
                            repo_path=repo_path,
                            sandbox_factory=self.sandbox_factory,
                            llm=analyzer_llm,
                            max_parallel=self._subsystem_max_parallel,
                            budget_per_subsystem_usd=self._subsystem_budget_usd or 30.0,
                            findings_pool=findings_pool,
                            session_id_prefix=f"{self._session_id}-subsys",
                            sandbox_manager=self._sandbox_manager,
                            campaign_hint=self._campaign_hint,
                            callgraph=preprocess_result.callgraph,
                        )
                    )
                    try:
                        subsys_findings = await subsys_runner.arun()
                        # route subsystem findings through the FindingsPool
                        # so a subsystem hunt that re-discovers a bug the
                        # analyzer pool already found gets merged instead of
                        # double-counted in the report. Keep only the
                        # survivors (new representatives) in all_findings.
                        if findings_pool is not None and subsys_findings:
                            kept_subsys: list[Finding] = []
                            for f in subsys_findings:
                                try:
                                    if await findings_pool.add_dedup(f):
                                        kept_subsys.append(f)
                                except Exception:
                                    logger.debug(
                                        "subsystem findings_pool.add_dedup failed", exc_info=True
                                    )
                                    kept_subsys.append(f)
                            merged = len(subsys_findings) - len(kept_subsys)
                            if merged:
                                logger.info(
                                    "[subsystem] dedup merged %d of %d findings into "
                                    "existing clusters",
                                    merged,
                                    len(subsys_findings),
                                )
                            all_findings.extend(kept_subsys)
                        else:
                            kept_subsys = list(subsys_findings)
                            all_findings.extend(subsys_findings)
                        subsystems_hunted = len(subsystem_targets)
                        subsystem_spent = subsys_runner.total_spent
                        _subsystem_findings_count = len(subsys_findings)
                        # A/B yield - split by whether each finding came
                        # from an orchestrator plan or auto-detection. Count only
                        # findings that survived dedup into all_findings
                        # (kept_subsys), so the yield matches the report and a
                        # deduped-out finding isn't double-counted.
                        # subsystem_source lands under extra: on reload, so check
                        # both top-level and nested.
                        for _sf in kept_subsys:
                            src = _sf.get("subsystem_source") or (
                                (_sf.get("extra") or {}).get("subsystem_source")
                                if hasattr(_sf, "get")
                                else None
                            )
                            if src == "orchestrator":
                                _orchestrator_plan_findings += 1
                            else:
                                _auto_subsystem_findings += 1
                        logger.info(
                            "Subsystem hunt completed: %d findings "
                            "(%d from orchestrator plans, %d from auto-detection), $%.4f spent",
                            len(subsys_findings),
                            _orchestrator_plan_findings,
                            _auto_subsystem_findings,
                            subsystem_spent,
                        )
                        # subsystem hunt success.  Findings count may be 0
                        # legitimately (no shared-state bugs found) - that's
                        # still a success of the stage, not a degradation.
                        pipeline_status.record_succeeded("subsystem_hunt")
                    except Exception:
                        logger.warning("Subsystem hunt failed", exc_info=True)
                        pipeline_status.record_degraded(
                            "subsystem_hunt",
                            "Subsystem hunt failed; only per-file findings available",
                        )

            # route "no vulnerability found" records (finding_type=none) to a
            # cleared bucket BEFORE verification. They are the analyzer/critic
            # explicitly reporting the ABSENCE of a bug, so they must not be
            # counted as verified findings or rendered as live findings.
            cleared_findings = [f for f in all_findings if _is_no_vulnerability_finding(f)]
            if cleared_findings:
                all_findings = [f for f in all_findings if not _is_no_vulnerability_finding(f)]
                self.live_findings = all_findings  # keep the live tally in sync after filtering
                logger.info(
                    "[review] cleared %d no-vulnerability record(s) (finding_type=none) "
                    "before verification",
                    len(cleared_findings),
                )

            # collapse findings that share the same (file, line, cwe) into a
            # single representative BEFORE recalibration, so one bug reported N
            # times doesn't render N times with N severities. Keyed on
            # (file,line,cwe), never cluster_id - different-location reinstated
            # findings (the PAT cluster) are preserved.
            all_findings, _b3_merged = _dedup_by_location(all_findings)
            if _b3_merged:
                logger.info(
                    "[review] merged %d duplicate finding(s) sharing (file,line,cwe) "
                    "before validation",
                    _b3_merged,
                )

            # 4. Verify (unless --no-verify)
            verified: list[Finding] = []
            rejected: list[Finding] = []
            self._emit_stage(
                "verify",
                "started",
                findings_so_far=len(all_findings),
                detail=f"{len(all_findings)} findings to verify",
            )
            if not self.no_verify:
                reviewer_llm = self._get_native_client("reviewer", self.reviewer_llm)
                if reviewer_llm is not None:
                    if self.validator_mode == "v2":
                        # give the validator the same cross-file context the
                        # skeptic/critic got, built via the pool's cached helper.
                        cfc_fn = None
                        if pool is not None and self._enable_cross_file_context:
                            cfc_fn = lambda path: pool._build_cross_file_context(  # noqa: E731
                                {"path": path}, quiet=True
                            )
                        verified, rejected = await self._verify_v2(
                            reviewer_llm,
                            all_findings,
                            repo_path,
                            cross_file_context_fn=cfc_fn,
                        )
                    else:
                        verified = await self._verify_v1(
                            reviewer_llm,
                            all_findings,
                            repo_path,
                        )
                    # reviewer success.  ``_verify_v1`` / ``_verify_v2``
                    # already swallow per-finding LLM errors internally and
                    # log the partial verdicts; if execution reaches here the
                    # reviewer stage as a whole succeeded.
                    pipeline_status.record_succeeded("reviewer")
                else:
                    for f in all_findings:
                        f["verified"] = True
                    verified = all_findings
                    pipeline_status.record_degraded(
                        "reviewer",
                        "Findings auto-verified without independent review",
                    )
            else:
                verified = all_findings
                pipeline_status.record(
                    "reviewer",
                    StageOutcome.SKIPPED,
                    fallback_description="Verification skipped (--no-verify)",
                )

            self._emit_stage(
                "verify",
                "completed",
                findings_so_far=len(all_findings),
                detail=f"{len(verified)} verified, {len(rejected)} rejected",
            )
            if rejected:
                self._write_rejected_findings(rejected)

            # 4.5 + 4.75 (M5): mechanism extraction and the variant loop both
            # read `verified` read-only and write disjoint state (the
            # cross-run mechanism store vs all_findings / the findings pool),
            # so they overlap instead of running back-to-back. Stability
            # (4.9) stays sequential below - it rebinds `verified` and gates
            # exploit-dev. Each pass keeps its own try/except + PipelineStatus
            # recording, so one failing doesn't abort the other.
            async def _mechanism_pass() -> None:
                # Extract mechanisms from verified findings and persist
                # them to the cross-run store. Cheap LLM pass; non-fatal.
                if self._mechanism_store is None or not verified:
                    return
                reviewer_llm_for_extract = self._get_native_client("reviewer", self.reviewer_llm)
                if reviewer_llm_for_extract is None:
                    return
                try:
                    extractor = MechanismExtractor(reviewer_llm_for_extract)
                    for finding in verified:
                        mech = await extractor.aextract(finding, source_repo=self.repo_url)
                        if mech is not None:
                            self._mechanism_store.append(mech)
                    # per-finding extraction failures are swallowed inside
                    # ``aextract``; only outer failures (bad LLM, OOM) land here.
                    pipeline_status.record_succeeded("mechanism_extraction")
                except Exception:
                    logger.warning("Mechanism extraction failed", exc_info=True)
                    pipeline_status.record_degraded(
                        "mechanism_extraction",
                        "Mechanism extraction failed; cross-run memory not updated",
                    )

            async def _variant_pass() -> None:
                # Variant Analyzer Loop - compound finding density within
                # this run. For each verified finding, generate a grep pattern,
                # search the codebase for structural matches, and surface each
                # match as a new suspicion-level finding linked to the original.
                if not self.enable_variant_loop or not verified:
                    return
                variant_llm = self._get_native_client("reviewer", self.reviewer_llm)
                if variant_llm is None:
                    return
                try:
                    loop = VariantLoop(
                        pattern_gen=VariantPatternGenerator(variant_llm),
                    )
                    already_seen = {
                        (f.get("file", ""), f.get("line_number", 0)) for f in all_findings
                    }
                    variant_result = await loop.arun(
                        verified_findings=verified,
                        repo_path=repo_path,
                        already_seen_locations=already_seen,
                        reverify_callback=None,
                    )
                    # gate variants through the skeptic before the pool.
                    (
                        new_findings,
                        variants_skeptic_accepted,
                        variants_skeptic_refuted,
                    ) = await self._gate_variant_seeds(variant_result.seeds, skeptic_gate)
                    # route skeptic-accepted variants through the pool so a
                    # variant on an existing file:line:cwe merges, not double-counts.
                    if findings_pool is not None and new_findings:
                        kept_variants: list[Finding] = []
                        for f in new_findings:
                            try:
                                if await findings_pool.add_dedup(f):
                                    kept_variants.append(f)
                            except Exception:
                                logger.debug(
                                    "variant findings_pool.add_dedup failed", exc_info=True
                                )
                                kept_variants.append(f)
                        v_merged = len(new_findings) - len(kept_variants)
                        if v_merged:
                            logger.info(
                                "[variant] dedup merged %d of %d variants into existing clusters",
                                v_merged,
                                len(new_findings),
                            )
                        all_findings.extend(kept_variants)
                    else:
                        all_findings.extend(new_findings)
                    logger.info(
                        "Variant loop: %d patterns, %d matches surfaced "
                        "(skeptic: %d accepted, %d refuted)",
                        variant_result.patterns_generated,
                        variant_result.matches_found,
                        variants_skeptic_accepted,
                        variants_skeptic_refuted,
                    )
                    # zero matches is still a successful run of the stage.
                    pipeline_status.record_succeeded("variant_loop")
                except Exception:
                    logger.warning("Variant loop failed", exc_info=True)
                    pipeline_status.record_degraded(
                        "variant_loop",
                        "Variant loop failed; no sibling bugs surfaced",
                    )

            await asyncio.gather(_mechanism_pass(), _variant_pass())

            # 4.9. Stage 2.5: PoC stability verification.
            # Rerun PoCs in fresh containers to measure reliability.
            if (
                self.enable_stability_verification
                and verified
                and self._sandbox_manager is not None
            ):
                from .stability import StabilityVerifier, apply_stability_result

                stability_llm = self._get_native_client("reviewer", self.reviewer_llm)
                sv = StabilityVerifier(
                    sandbox_manager=self._sandbox_manager,
                    hardening_llm=stability_llm,
                )
                stability_eligible = [
                    f
                    for f in verified
                    if f.get("poc")
                    and f.get("crash_evidence")
                    and evidence_at_or_above(
                        f.get("evidence_level", "suspicion"),
                        "crash_reproduced",
                    )
                ]
                stable_verified: list[Finding] = []
                for finding in stability_eligible:
                    try:
                        sr = await sv.averify(finding)
                        # apply_stability_result demotes an unreliable
                        # PoC's evidence (crash_reproduced → static_corroboration)
                        # with a reason. We KEEP the finding verified rather than
                        # dropping it - a real bug with a flaky PoC is still a
                        # real bug; the demoted evidence + reason tell the honest
                        # story instead of silently deleting it from the report.
                        apply_stability_result(finding, sr)
                        stable_verified.append(finding)
                        if sr.classification == "unreliable":
                            logger.info(
                                "Finding %s kept but evidence demoted - unreliable PoC "
                                "(%.0f%% success rate)",
                                finding.get("id"),
                                sr.success_rate * 100,
                            )
                    except Exception:
                        logger.warning(
                            "Stability check failed for %s",
                            finding.get("id"),
                            exc_info=True,
                        )
                        stable_verified.append(finding)
                non_poc = [f for f in verified if f not in stability_eligible]
                verified = stable_verified + non_poc

            # 5. Exploit-triage (unless --no-exploit) - gated on evidence_level
            self._emit_stage("exploit", "started", findings_so_far=len(all_findings))
            exploited: list[Finding] = []
            # sandbox-lab counters that ScanResult reads at the end.
            # Declared here so they survive --no-exploit and other early-exit
            # paths inside the exploit block.
            _agentic_snapshot_cycles = 0
            _agentic_ptrace_events = 0
            # 5.5 Exploit dev (opt-in via --exploit) - runs on verified findings
            #     with root-cause-level evidence. The agent generates a PoC and
            #     runs it inside the sandbox to confirm exploitability.
            if not self.no_exploit:
                # The exploit stage is a single shared unit (acuario.scanner.
                # exploit_stage) so the full run and `--resume --exploit` execute
                # identical logic. Full runs use the automatic evidence gate
                # (finding_ids=None).
                from .exploit_stage import run_exploit_stage

                _outcome = await run_exploit_stage(
                    verified=verified,
                    repo_path=repo_path,
                    exploit_dev_llm=self._get_native_client("exploit_dev", self.exploit_dev_llm),
                    sandbox_manager=self._sandbox_manager,
                    sandbox_factory=self.sandbox_factory,
                    findings_pool=findings_pool,
                    session_id=self._session_id,
                    budget_band=self._exploit_budget_band,
                    output_dir=str(self._ensure_output_dir_layout()),
                    project_name=(self.repo_url.split("/")[-1] if self.repo_url else "target"),
                    enable_sandbox_snapshots=self._enable_sandbox_snapshots,
                    enable_ptrace_monitor=self._enable_ptrace_monitor,
                    exploit_compose=getattr(self, "_exploit_compose", True),
                    historical_db_path=self._historical_db_path,
                    persist_to_db=historical_db is not None,
                    finding_ids=None,
                )
                exploited = _outcome.exploited
                _agentic_snapshot_cycles = _outcome.snapshot_cycles
                _agentic_ptrace_events = _outcome.ptrace_events

            self._emit_stage(
                "exploit",
                "completed",
                findings_so_far=len(all_findings),
                detail=f"{len(exploited)} exploited",
            )
            # exploit_dev success.  Per-finding exploit failures are
            # logged and tolerated inside the loop; we only land here when
            # the stage as a whole runs to completion.  An empty
            # ``exploited`` list (no findings qualified) still counts as a
            # successful stage execution.
            pipeline_status.record_succeeded("exploit_dev")

            # SCA / vulnerable-dependency findings. Deterministic advisory
            # match against package.json + lockfiles, routed AROUND the accuracy
            # layer (no skeptic/validator) and added post-exploit so it triggers
            # no LLM stage. A dependency finding has no code trace and would be
            # mass-refuted, corrupting the sound refute statistics.
            if self._enable_sca:
                try:
                    from .sca import scan_dependencies

                    sca_findings = scan_dependencies(repo_path)
                    for _f in sca_findings:
                        _f["verified"] = True
                        _f["severity_verified"] = _f.get("severity")
                    if sca_findings:
                        all_findings.extend(sca_findings)
                        verified.extend(sca_findings)
                        logger.info(
                            "[sca] ▸ %d vulnerable dependency finding(s)", len(sca_findings)
                        )
                except Exception:
                    logger.warning("SCA dependency scan failed", exc_info=True)

            # mark same-locus duplicate findings non-destructively. The
            # analyzer re-hunts a file several times (band promotion, critic
            # leads, cross-file follow-ups) and the clusterer under-merges, so
            # one bug can land several times at a single file:line under
            # slightly different labels. Nothing is deleted - every id stays so
            # inspect / --resume --findings / the exploit transcripts keep
            # resolving - only the report and headline counts treat a
            # non-primary as an alias. Marks the shared Finding objects, so the
            # `verified` subset sees the same markers.
            annotate_duplicate_loci(all_findings)

            # 5.9. Reconcile the historical DB with the final canonical set.
            # The 3.5 ingest ran (and closed the DB) before the subsystem hunt and
            # SCA, so findings from those post-pool stages never reached the
            # cross-campaign dedup cache - leaving `history`'s DB-fallback count
            # short for sessions that used them. Re-ingest the canonical set now:
            # INSERT OR IGNORE makes already-persisted rows no-ops, adds the
            # subsystem / SCA rows, and canonical_findings keeps variant_loop out.
            # Standalone only (campaigns own ingest); best-effort, never fails the run.
            if (
                historical_db is not None
                and self._injected_findings_pool is None
                and self._historical_db_path
            ):
                try:
                    from acuario.findings.types import canonical_findings

                    from .historical_findings_db import HistoricalFindingsDB

                    _recon_db = HistoricalFindingsDB(path=self._historical_db_path)
                    try:
                        _added = _recon_db.ingest_campaign(
                            canonical_findings(all_findings),
                            repo_url=self.repo_url,
                            session_id=self._session_id,
                        )
                        if _added:
                            logger.info(
                                "[audit] ▸ reconciled %d post-pool finding(s) to historical DB",
                                _added,
                            )
                    finally:
                        _recon_db.close()
                except Exception:
                    logger.warning("Historical DB reconcile failed", exc_info=True)

            # 6. Report
            self._emit_stage("report", "started", findings_so_far=len(all_findings))
            _pool_stats = findings_pool.pool_stats() if findings_pool is not None else None
            _subsystem_stats = (
                {"subsystems_hunted": subsystems_hunted, "subsystem_spent_usd": subsystem_spent}
                if subsystems_hunted > 0
                else None
            )
            # flush calibration.jsonl now that verify + exploit-dev outcomes
            # are all stamped on the findings (best-effort).
            self._flush_calibration(session_out, all_findings)
            # compute duration BEFORE the report write so it can land in
            # report.md.
            duration = time.monotonic() - start_time
            # assemble lab_stats from the in-scope lab agents so the
            # LAB Activity section in report.md and the existing terminal
            # summary share the same numbers.
            _lab_stats_for_report = {
                "skeptic_accepted": (
                    skeptic_gate.accepted_count if skeptic_gate is not None else 0
                ),
                "skeptic_refuted": (skeptic_gate.refuted_count if skeptic_gate is not None else 0),
                "skeptic_uncertain": (
                    skeptic_gate.uncertain_count if skeptic_gate is not None else 0
                ),
                "debate_reinstated": (
                    skeptic_gate.debate_overturned_count if skeptic_gate is not None else 0
                ),
                "debate_upheld": (
                    skeptic_gate.debate_upheld_count if skeptic_gate is not None else 0
                ),
                "critic_leads": (critic_agent.leads_total if critic_agent is not None else 0),
                "critic_verified": sum(1 for f in verified if f.get("discovered_by") == "critic"),
                "orchestrator_plans": (len(orchestrator.plans) if orchestrator is not None else 0),
                "orchestrator_findings": _subsystem_findings_count,
                "orchestrator_plan_findings": _orchestrator_plan_findings,
                "auto_subsystem_findings": _auto_subsystem_findings,
                "snapshot_cycles": _agentic_snapshot_cycles,
                "ptrace_events": _agentic_ptrace_events + self._analyzer_ptrace_events,
            }
            output_paths = self._write_report(
                findings=all_findings,
                verified=verified,
                spent_per_tier=spent_per_tier,
                band_stats=band_stats,
                pool_stats=_pool_stats,
                subsystem_stats=_subsystem_stats,
                pipeline_status=pipeline_status,
                duration_seconds=duration,
                lab_stats=_lab_stats_for_report,
            )
            # reporter success.  By the time ``_write_report`` returns,
            # the SARIF, JSON, markdown, manifest, and team_discussion files
            # have all been emitted (or the renderer logged its own warning
            # and returned an empty paths dict - in which case the records
            # below for prior stages remain accurate).
            pipeline_status.record_succeeded("reporter")

            # Pull the live token / dual-cost figures out of the singleton
            # CostTracker BEFORE the stage emit so the reported cost is the
            # GRAND TOTAL across every agent - analyzer tiers + exploit-dev +
            # reviewer + skeptic + critic + prioritizer + orchestrator - not
            # just the analyzer tiers + subsystem spend. The old
            # ``sum(spent_per_tier) + subsystem_spent`` silently dropped the
            # lab / exploit-dev spend (~21% of the true bill on the App run),
            # so the terminal banner undercounted while the report's
            # ``cost_summary.total_cost_usd`` (this same figure) was correct.
            # For self-hosted runs cost_usd reads as $0 (no bill); the
            # reference quotes carry the "what it would have cost" figure.
            from acuario.observability.telemetry import CostTracker

            ct = CostTracker().get_summary()
            actual_cost = 0.0 if ct.is_self_hosted else ct.total_cost_usd

            self._emit_stage(
                "report",
                "completed",
                findings_so_far=len(all_findings),
                cost_usd=actual_cost,
            )

            # `duration` already computed above (H2) before _write_report;
            # don't recompute or the report and ScanResult would disagree.
            return ScanResult(
                exit_code=self._exit_code(verified),
                repo_url=self.repo_url,
                repo_path=repo_path,
                findings=all_findings,
                verified_findings=verified,
                exploited_findings=exploited,
                files_ranked=files_ranked,
                files_hunted=files_hunted,
                duration_seconds=round(duration, 2),
                cost_usd=actual_cost,
                spent_per_tier=spent_per_tier,
                tokens_used=ct.input_tokens + ct.output_tokens,
                input_tokens=ct.input_tokens,
                output_tokens=ct.output_tokens,
                is_self_hosted_endpoint=ct.is_self_hosted,
                endpoint_label=ct.endpoint_label,
                reference_cost_opus_usd=ct.reference_cost_opus_usd,
                reference_cost_gpt_usd=ct.reference_cost_gpt_usd,
                output_paths=output_paths,
                session_id=self._session_id,
                subsystems_hunted=subsystems_hunted,
                subsystem_spent_usd=subsystem_spent,
                pipeline_status=pipeline_status,
                # Lab agent stats
                skeptic_accepted=(skeptic_gate.accepted_count if skeptic_gate is not None else 0),
                skeptic_refuted=(skeptic_gate.refuted_count if skeptic_gate is not None else 0),
                skeptic_uncertain=(skeptic_gate.uncertain_count if skeptic_gate is not None else 0),
                debate_reinstated=(
                    skeptic_gate.debate_overturned_count if skeptic_gate is not None else 0
                ),
                debate_upheld=(skeptic_gate.debate_upheld_count if skeptic_gate is not None else 0),
                critic_leads=(critic_agent.leads_total if critic_agent is not None else 0),
                critic_verified=sum(1 for f in verified if f.get("discovered_by") == "critic"),
                orchestrator_plans=(len(orchestrator.plans) if orchestrator is not None else 0),
                orchestrator_findings=_subsystem_findings_count,
                orchestrator_plan_findings=_orchestrator_plan_findings,
                auto_subsystem_findings=_auto_subsystem_findings,
                snapshot_cycles=_agentic_snapshot_cycles,
                ptrace_events=_agentic_ptrace_events + self._analyzer_ptrace_events,
            )
        finally:
            # safety net - if a stage between the analyzer pool and the
            # inline warm-pool shutdown raised, the containers would otherwise
            # leak. On the normal path container_pool is already None here.
            if container_pool is not None:
                try:
                    await container_pool.shutdown()
                except Exception:
                    logger.debug("warm container pool shutdown failed", exc_info=True)
            if self._sandbox_manager is not None:
                try:
                    self._sandbox_manager.cleanup(remove_image=False)
                except Exception:
                    logger.debug("AnalyzerSandbox cleanup failed", exc_info=True)

    @property
    def session_id(self) -> str:
        return self._session_id

    # --- Pipeline helpers ---------------------------------------------------

    def _ensure_output_dir_layout(self) -> Path:
        session_dir = Path(self.output_dir) / self._session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        # Record where this session's artifacts live so `inspect` / `eval` can
        # find them later regardless of the directory the audit ran from
        # (best-effort; never fails the run).
        from .session_index import record_session_path

        record_session_path(self._session_id, session_dir)
        return session_dir

    async def _verify_v1(
        self,
        reviewer_llm: AsyncLLMClient,
        all_findings: list[Finding],
        repo_path: str,
    ) -> list[Finding]:
        """Legacy v1 verification using the Reviewer class."""
        verified: list[Finding] = []
        v = Reviewer(
            reviewer_llm,
            adversarial=self.adversarial_verifier,
            adversarial_threshold=self.adversarial_threshold,
        )
        for finding in all_findings:
            try:
                result = await v.averify(
                    finding,
                    file_content=self._load_file_content(repo_path, finding),
                )
                apply_verifier_result(
                    finding,
                    result,
                    session_id=self._session_id + "-v",
                )
                if finding.get("verified"):
                    verified.append(finding)
            except Exception:
                logger.warning(
                    "Reviewer failed for %s",
                    finding.get("id"),
                    exc_info=True,
                )
        return verified

    async def _verify_v2(
        self,
        reviewer_llm: AsyncLLMClient,
        all_findings: list[Finding],
        repo_path: str,
        cross_file_context_fn: Any = None,
    ) -> tuple[list[Finding], list[Finding]]:
        """4-axis validation.

        Runs serially: one finding at a time. Parallel verification compounds
        the FD pressure that already kills audit runs around the 80-finding
        mark on hosts with the default ``ulimit -n 1024``, and the reviewer is
        a small share of total runtime, so it doesn't justify the resource
        amplification.
        """
        from .validator import Validator, apply_validator_verdict

        val = Validator(
            reviewer_llm,
            gate_threshold=self.adversarial_threshold,
            enable_severity_recalibration=self._recalibrate_severity,
        )
        verified: list[Finding] = []
        rejected: list[Finding] = []
        total = len(all_findings)
        logger.info("[review] %s starting on %d findings (serial)", "▸", total)

        for i, finding in enumerate(all_findings, start=1):
            try:
                discoverer_sev = finding.get("severity")
                cfc = ""
                if cross_file_context_fn is not None:
                    try:
                        cfc = cross_file_context_fn(finding.get("file", "") or "") or ""
                    except Exception:
                        logger.debug("validator cross-file context build failed", exc_info=True)
                verdict = await val.avalidate(
                    finding,
                    file_content=self._load_file_content(repo_path, finding),
                    cross_file_context=cfc,
                )
                apply_validator_verdict(
                    finding,
                    verdict,
                    session_id=self._session_id + "-v",
                    discoverer_severity=discoverer_sev,
                )
                if finding.get("verified"):
                    verified.append(finding)
                else:
                    rejected.append(finding)
                _verdict_glyph = "✓" if finding.get("verified") else "✗"
                logger.info(
                    "[review] %s %s (%d/%d)",
                    _verdict_glyph,
                    finding.get("id"),
                    i,
                    total,
                )
                self._record_calibration(finding, verdict, discoverer_sev)
            except BaseException:
                # Catches PyO3 panics too so a single LLM-client failure
                # does not abort the entire validation pass.
                logger.warning(
                    "Validator failed for %s",
                    finding.get("id"),
                    exc_info=True,
                )
                rejected.append(finding)

        logger.info(
            "[review] %s complete: %d verified, %d rejected",
            "●",
            len(verified),
            len(rejected),
        )
        # Stamp the verdicts into the historical DB so subsequent
        # `acuario audit --resume` calls treat these as already-judged
        # and don't re-roll the dice on borderline LLM verdicts.
        try:
            from .historical_findings_db import HistoricalFindingsDB

            hdb = HistoricalFindingsDB()
            try:
                for f in verified:
                    hdb.mark_reviewed(
                        f.get("id", ""),
                        verified=True,
                        evidence_level=f.get("evidence_level"),
                    )
                for f in rejected:
                    hdb.mark_reviewed(
                        f.get("id", ""),
                        verified=False,
                        evidence_level=f.get("evidence_level"),
                    )
            finally:
                hdb.close()
        except Exception:
            logger.debug("Failed to stamp reviewer verdicts in historical DB", exc_info=True)
        return verified, rejected

    async def _gate_variant_seeds(
        self,
        seeds: list,
        skeptic_gate: Any,
    ) -> tuple[list[Finding], int, int]:
        """L1: Build variant Finding objects and pass them through the skeptic.

        Variants are pattern-matched suspicions, not analyzer-traced findings.
        The 4-axis reviewer downstream rejects them at near-100% rates because
        they lack the cross-file evidence chain a real analyzer hunt produces.
        Gating at the skeptic refutes them cheaply (one LLM call per variant)
        before they enter the pool, instead of waiting for the heavier
        reviewer to do the same job later.

        Parameters
        ----------
        seeds:
            ``variant_result.seeds`` - each carries an ``original_finding``
            and a ``match`` with ``file``, ``line_number``, ``matched_text``,
            and ``pattern.semantic_description``.
        skeptic_gate:
            A ``SkepticGate`` instance, or ``None`` when the gate is disabled.
            When ``None`` every variant is accepted (legacy behaviour).

        Returns
        -------
        (findings, accepted_count, refuted_count)
            ``findings`` is the list of variant ``Finding`` objects that the
            caller should append to ``all_findings``.  ``accepted_count`` and
            ``refuted_count`` are the skeptic decision tallies (both 0 when
            ``skeptic_gate is None``).
        """
        accepted: list[Finding] = []
        accepted_count = 0
        refuted_count = 0
        for seed in seeds:
            parent = seed.original_finding
            variant_finding = Finding(
                id=f"variant-{uuid.uuid4().hex[:8]}",
                file=seed.match.file,
                line_number=seed.match.line_number,
                finding_type=parent.finding_type or "variant",
                cwe=parent.cwe,
                severity=parent.effective_severity or "medium",
                confidence="low",
                description=(f"Variant of {parent.id}: {seed.match.pattern.semantic_description}"),
                code_snippet=seed.match.matched_text,
                evidence_level="suspicion",
                discovered_by="variant_loop",
                related_finding_id=parent.id or None,
                related_cve=parent.related_cve,
                hunter_session_id=self._session_id,
            )
            if skeptic_gate is None:
                accepted.append(variant_finding)
                continue
            # ascreen is fail-open: LLM errors → accepted.  Cross-file
            # context is intentionally empty for variants - they're pattern
            # matches in files the analyzer hasn't traced, so we'd have no
            # cached context to inject.  The matched text itself goes in
            # as source_snippet.
            try:
                verdict = await skeptic_gate.ascreen(
                    variant_finding,
                    source_snippet=str(seed.match.matched_text or ""),
                    cross_file_context="",
                )
            except Exception:
                logger.warning(
                    "Variant skeptic gate raised; accepting variant %s",
                    variant_finding.get("id"),
                    exc_info=True,
                )
                accepted.append(variant_finding)
                accepted_count += 1
                continue
            if verdict is not None and verdict.verdict == "refuted":
                refuted_count += 1
                continue
            accepted_count += 1
            accepted.append(variant_finding)
        return accepted, accepted_count, refuted_count

    def _record_calibration(self, finding: Any, verdict: Any, discoverer_sev: object) -> None:
        # capture the validator's verdict per finding during the verify
        # loop. The skeptic verdict (from skeptic_log.jsonl) and the exploit
        # outcome (stamped on the finding later) are joined in at flush time.
        try:
            self._calibration_rows.append(
                {
                    "finding_id": finding.get("id", ""),
                    "discoverer_severity": discoverer_sev,
                    "validator_advance": bool(getattr(verdict, "advance", False)),
                    "validator_severity": getattr(verdict, "severity_validated", None),
                    "severity_recalibrated": getattr(verdict, "severity_recalibrated", None),
                    "validator_evidence_level": getattr(verdict, "evidence_level", None),
                    "validator_axes": {
                        name: {"passed": ax.passed, "confidence": ax.confidence}
                        for name, ax in getattr(verdict, "axes", {}).items()
                    },
                }
            )
        except Exception:
            logger.debug("calibration row capture failed", exc_info=True)

    def _flush_calibration(self, session_dir: Path, all_findings: list[Finding]) -> None:
        """O8: write calibration.jsonl joining skeptic + validator + exploit
        outcome per finding, so a run yields agreement data with no annotation
        labor. Best-effort; never breaks the audit."""
        if not self._calibration_rows and not self._skeptic_shadow_mode:
            return
        import json

        try:
            # Skeptic verdicts (all decisions, incl. refuted/uncertain) from the log.
            skeptic_by_id: dict[str, dict] = {}
            log_path = session_dir / "skeptic_log.jsonl"
            if log_path.is_file():
                with log_path.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        fid = rec.get("finding_id", "")
                        if fid:
                            skeptic_by_id[fid] = rec
            validator_by_id = {r["finding_id"]: r for r in self._calibration_rows}
            exploit_by_id: dict[str, dict] = {}
            for f in all_findings:
                fid = f.get("id", "")
                if fid:
                    exploit_by_id[fid] = {
                        "exploit_success": bool(f.get("exploit_success", False)),
                        "exploit_blocked_by": f.get("exploit_blocked_by"),
                        "evidence_level": f.get("evidence_level"),
                        "verified": bool(f.get("verified", False)),
                    }
            all_ids = set(skeptic_by_id) | set(validator_by_id) | set(exploit_by_id)
            out_path = session_dir / "calibration.jsonl"
            with out_path.open("w", encoding="utf-8") as fh:
                for fid in sorted(all_ids):
                    sk = skeptic_by_id.get(fid, {})
                    row = {
                        "finding_id": fid,
                        "skeptic_verdict": sk.get("verdict"),
                        "skeptic_confidence": sk.get("confidence"),
                        "validator": validator_by_id.get(fid),
                        "exploit": exploit_by_id.get(fid),
                        "shadow_mode": self._skeptic_shadow_mode,
                    }
                    fh.write(json.dumps(row, default=str) + "\n")
            logger.info(
                "[calibration] wrote %d row(s) to calibration.jsonl%s",
                len(all_ids),
                " (skeptic shadow mode)" if self._skeptic_shadow_mode else "",
            )
        except Exception:
            logger.debug("calibration flush failed", exc_info=True)

    def _write_rejected_findings(self, rejected: list[Finding]) -> None:
        import json as _json

        session_dir = self._ensure_output_dir_layout()
        path = session_dir / "rejected_findings.jsonl"
        try:
            with open(path, "w", encoding="utf-8") as f:
                for finding in rejected:
                    f.write(_json.dumps(finding, default=str) + "\n")
            logger.info("Wrote %d rejected findings to %s", len(rejected), path)
        except OSError:
            logger.warning("Failed to write rejected findings", exc_info=True)

    def _load_file_content(self, repo_path: str, finding: Finding) -> str:
        """Read the file referenced by a finding. Used by the patch oracle."""
        rel = finding.get("file", "")
        if not rel:
            return ""
        abs_path = os.path.join(repo_path, rel)
        try:
            with open(abs_path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    # --- callgraph reachability stamping --------------------------------

    # File-level entry markers. A file is treated as an "attacker-reachable
    # entry" when it carries any of these tags or its basename matches one
    # of these patterns. Cheap, language-agnostic, no LLM needed.
    _ENTRY_TAGS: frozenset[str] = frozenset(
        {
            "web",
            "route",
            "router",
            "controller",
            "handler",
            "endpoint",
            "api",
            "rest",
            "graphql",
            "cli",
            "main",
            "entry",
            "rpc",
            "deserializer",
            "parser",
        }
    )
    _ENTRY_BASENAME_HINTS: tuple[str, ...] = (
        "main",
        "index",
        "app",
        "server",
        "router",
        "routes",
        "handler",
        "controller",
        "api",
        "cli",
        "entrypoint",
        "endpoint",
    )

    def _file_is_entry(self, ft: FileTarget) -> bool:
        tags = {str(t).lower() for t in (ft.get("tags") or [])}
        if tags & self._ENTRY_TAGS:
            return True
        path = (ft.get("path") or "").lower()
        basename = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        if basename in self._ENTRY_BASENAME_HINTS:
            return True
        return False

    def _stamp_reachability_hops(
        self,
        files: list[FileTarget],
        callgraph: Any,
    ) -> None:
        """Stamp `min_hops_from_entry` and a callgraph-derived
        `reachability` floor onto each FileTarget before the prioritizer
        runs. The prioritizer's existing reachability scoring then has
        a real signal to work with instead of the hard-coded default.

        Semantics of `min_hops_from_entry`:
          *  0  - the file IS an entry-point file
          *  N  - minimum hops from any entry-point file (BFS in callgraph)
          * -1  - unreachable from any entry-point file

        No-op when the callgraph is absent or empty. Failures are logged
        and swallowed - telemetry must never break an audit.
        """
        if callgraph is None or getattr(callgraph, "empty", True):
            return
        try:
            entry_files = {ft.get("path", "") for ft in files if self._file_is_entry(ft)}
            entry_files.discard("")
            if not entry_files:
                return
            hops_map = callgraph.reachable_from(entry_files, max_depth=8)
            entry_count = len(entry_files)
            stamped = 0
            for ft in files:
                path = ft.get("path", "")
                if path in entry_files:
                    ft["min_hops_from_entry"] = 0
                    ft["reachability"] = max(int(ft.get("reachability") or 0), 5)
                    stamped += 1
                elif path in hops_map:
                    hops = hops_map[path]
                    ft["min_hops_from_entry"] = hops
                    if hops <= 1:
                        ft["reachability"] = max(int(ft.get("reachability") or 0), 5)
                    elif hops <= 2:
                        ft["reachability"] = max(int(ft.get("reachability") or 0), 4)
                    elif hops <= 4:
                        ft["reachability"] = max(int(ft.get("reachability") or 0), 3)
                    else:
                        ft["reachability"] = max(int(ft.get("reachability") or 0), 2)
                    stamped += 1
                else:
                    ft["min_hops_from_entry"] = -1
                    ft["reachability"] = max(int(ft.get("reachability") or 0), 1)
            logger.info(
                "[reach] callgraph: %d entry file(s) -> %d reachable files stamped (max-depth 8)",
                entry_count,
                stamped,
            )
        except Exception:
            logger.debug("reachability stamping failed", exc_info=True)

    def _preprocess(self) -> PreprocessResult:
        # enable callgraph + reachability + Semgrep by default at
        # standard/deep depths. Quick depth stays cheap - just enumerate
        # and tag files.
        pp = Preprocessor(
            repo_url=self.repo_url,
            branch=self.branch,
            local_path=self.local_path,
            tag_files=True,
            build_callgraph=(self.depth != "quick" and self._preprocessing),
            propagate_reachability=(self.depth != "quick" and self._preprocessing),
            run_semgrep=(self.depth != "quick" and self._preprocessing),
            run_taint=(self.depth != "quick" and self._preprocessing),
            # never enumerate the scanner's own output tree as target source
            # (prior-run results/scanner/** artifacts caused ~35% self-noise).
            exclude_paths=[os.path.abspath(self.output_dir)],
        )
        return pp.run()

    def _ensure_sandbox_factory(self, repo_path: str, files: list[FileTarget]) -> None:
        if self.depth == "quick":
            return
        if self.sandbox_factory is not None:
            return
        if self._sandbox_manager is not None:
            self.sandbox_factory = self._sandbox_manager.spawn
            return

        languages = sorted(
            {
                str(ft.get("language", "")).lower()
                for ft in files
                if str(ft.get("language", "")).strip()
            }
        )
        logger.info(
            "[sandbox] ▸ initializing for %s (languages: %s)",
            repo_path,
            ",".join(languages) or "unknown",
        )
        use_deep = self._agent_mode == "deep"
        # Exploit toolchain (gdb/pwntools/ROPgadget/...) is only useful for
        # native/binary targets; baking it into a pure-web image just wastes
        # build time. Enable it when exploits are on and a native language is
        # present. Build-time install only - the exploit RUNTIME stays offline.
        exploit_mode = (
            use_deep and not self.no_exploit and bool({"c", "cpp", "rust"} & set(languages))
        )
        try:
            manager = AnalyzerSandbox(
                repo_path=repo_path,
                languages=languages,
                deep_agent_mode=use_deep,
                exploit_agent_mode=exploit_mode,
                strict_seccomp=self._strict_seccomp,
            )
            image_tag = manager.build_image()
        except Exception as exc:
            logger.warning(
                "AnalyzerSandbox unavailable (%s); falling back to host mode. "
                "Start Docker to enable sanitizer-backed containers.",
                exc,
            )
            logger.debug("AnalyzerSandbox initialization failed", exc_info=True)
            return

        logger.info("[sandbox] ● ready · image=%s", image_tag)
        self._sandbox_manager = manager

        # prune snapshot images orphaned by prior crashed runs (best-effort).
        # Only touches acuario-snap-* images older than 2h, so a concurrent
        # audit's live snapshots are left alone.
        if self._enable_sandbox_snapshots:
            try:
                from ..lab.sandbox.snapshot import prune_orphan_snapshots

                prune_orphan_snapshots(older_than_hours=2.0)
            except Exception:
                logger.debug("snapshot prune failed (non-fatal)", exc_info=True)
        gvisor_rt = self._gvisor_runtime
        if use_deep:
            self.sandbox_factory = lambda **kw: manager.spawn(
                writable_workspace=True,
                memory_mb=kw.pop("memory_mb", 16384),
                cpus=kw.pop("cpus", 8.0),
                timeout_seconds=kw.pop("timeout_seconds", 600),
                runtime=kw.pop("runtime", gvisor_rt),
                **kw,
            )
        else:
            if gvisor_rt:
                self.sandbox_factory = lambda **kw: manager.spawn(
                    runtime=kw.pop("runtime", gvisor_rt),
                    **kw,
                )
            else:
                self.sandbox_factory = manager.spawn

    def _build_quick_result(
        self,
        start_time: float,
        repo_path: str,
        preprocess_result: PreprocessResult,
        files_ranked: int,
        pipeline_status: PipelineStatus | None = None,
    ) -> ScanResult:
        """depth=quick exit - only static findings, no LLM analyzers."""
        all_findings = self._merge_static_findings([], preprocess_result)
        self.live_findings = all_findings  # static findings in the live tally (quick mode)
        annotate_duplicate_loci(all_findings)  # same-locus dedup markers
        # compute duration BEFORE writing the report so it can land
        # in report.md's Executive Summary and LLM Usage sections.
        duration = time.monotonic() - start_time
        output_paths = self._write_report(
            findings=all_findings,
            verified=[],
            spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
            pipeline_status=pipeline_status,
            duration_seconds=round(duration, 2),
        )
        # depth=quick has no LLM calls, so token totals are 0 and any
        # endpoint-mode flags are still set from the audit-handler init.
        from acuario.observability.telemetry import CostTracker

        ct = CostTracker().get_summary()
        return ScanResult(
            exit_code=self._exit_code(all_findings),
            repo_url=self.repo_url,
            repo_path=repo_path,
            findings=all_findings,
            verified_findings=[],
            exploited_findings=[],
            files_ranked=files_ranked,
            files_hunted=0,
            duration_seconds=round(duration, 2),
            cost_usd=0.0,
            spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
            tokens_used=0,
            input_tokens=0,
            output_tokens=0,
            is_self_hosted_endpoint=ct.is_self_hosted,
            endpoint_label=ct.endpoint_label,
            output_paths=output_paths,
            session_id=self._session_id,
            pipeline_status=pipeline_status or PipelineStatus(),
        )

    def _merge_static_findings(
        self,
        existing: list[Finding],
        preprocess_result: PreprocessResult,
    ) -> list[Finding]:
        """Promote SourceAnalyzer static findings into the Finding shape.

        These get evidence_level="static_corroboration" because they're
        regex/AST hits, not just suspicion.
        """
        out = list(existing)
        for sf in preprocess_result.static_findings:
            out.append(
                Finding(
                    id=f"static-{uuid.uuid4().hex[:8]}",
                    file=Path(
                        os.path.relpath(sf.file_path, preprocess_result.repo_path)
                    ).as_posix(),
                    line_number=sf.line_number,
                    finding_type=sf.finding_type,
                    cwe=sf.cwe,
                    severity=sf.severity,  # type: ignore[arg-type]
                    confidence=sf.confidence,  # type: ignore[arg-type]
                    description=sf.description,
                    code_snippet=sf.code_snippet,
                    evidence_level="static_corroboration",
                    discovered_by="source_analyzer",
                )
            )
        return out

    def _exit_code(self, findings: list[Finding]) -> int:
        severities = {
            (f.get("severity_verified") or f.get("severity") or "info").lower() for f in findings
        }
        if severities & {"critical", "high"}:
            return 2
        if "medium" in severities:
            return 1
        return 0

    # --- LLM resolution -----------------------------------------------------

    def _get_llm(self, task: str, override: Any) -> Any:
        """Return an LLM for the given task, or None if not available.

        Resolution order:
          1. Explicit kwarg override (prioritizer_llm=, analyzer_llm=, etc.)
          2. self.provider_manager (injected by the scanner CLI
             command, which builds one from `resolve_llm_endpoint()`)
          3. self.model_override (single model for all tasks,
             resolved through the endpoint layer)
          4. A default `ProviderManager.for_endpoint(resolve_llm_endpoint())`
             - which picks up ACUARIO_BASE_URL / ACUARIO_API_KEY /
             ACUARIO_MODEL env vars or falls through to Anthropic
             direct via ANTHROPIC_API_KEY.
          5. None - caller falls back to a no-LLM path
        """
        if override is not None:
            return override

        # Inject-via-constructor wins (scanner CLI command + tests)
        if self.provider_manager is not None:
            try:
                return self.provider_manager.get_llm(task)
            except Exception:
                logger.debug("Injected ProviderManager failed for task=%s", task, exc_info=True)

        # Preflight: does *any* credential / endpoint exist? If not,
        # skip the LLM entirely so we don't throw a noisy stack trace
        # at first .invoke().
        has_creds = any(
            os.environ.get(name)
            for name in (ENV_BASE_URL, ENV_API_KEY, ENV_ANTHROPIC_KEY, "OPENAI_API_KEY")
        )
        if not has_creds:
            logger.debug("No API key / endpoint in environment; skipping LLM for task=%s", task)
            return None

    def _get_native_client(
        self,
        task: str,
        override: AsyncLLMClient | None,
    ) -> AsyncLLMClient | None:
        """Return a native async LLM client for scanner tasks."""
        if override is not None:
            return override

        if self.provider_manager is not None:
            try:
                return self.provider_manager.get_native_client(task)
            except Exception:
                logger.debug(
                    "Injected ProviderManager native client failed for task=%s", task, exc_info=True
                )

        has_creds = any(
            os.environ.get(name)
            for name in (ENV_BASE_URL, ENV_API_KEY, ENV_ANTHROPIC_KEY, "OPENAI_API_KEY")
        )
        if not has_creds:
            logger.debug(
                "No API key / endpoint in environment; skipping native client for task=%s", task
            )
            return None

        if self.model_override:
            return self._build_native_from_model_string(self.model_override)

        try:
            endpoint = resolve_llm_endpoint()
            return ProviderManager.for_endpoint(endpoint).get_native_client(task)
        except Exception:
            logger.debug("Default endpoint native resolution failed", exc_info=True)
            return None

        # --model override (single model string, routed through the
        # same endpoint resolution as --base-url)
        if self.model_override:
            return self._build_llm_from_model_string(self.model_override)

        # Last resort - build a default manager from the env triple
        try:
            endpoint = resolve_llm_endpoint()
            return ProviderManager.for_endpoint(endpoint).get_llm(task)
        except Exception:
            logger.debug("Default endpoint resolution failed", exc_info=True)
            return None

    def _build_llm_from_model_string(self, model: str) -> Any:
        """Build a single LLM from a model string. Used by --model override.

        Honors ACUARIO_BASE_URL / ACUARIO_API_KEY - so `--model
        anthropic/claude-opus-4` + ACUARIO_BASE_URL=https://openrouter.ai/api/v1
        lands on OpenRouter, not on Anthropic direct.
        """
        try:
            endpoint = resolve_llm_endpoint(cli_model=model)
            return ProviderManager.for_endpoint(endpoint).get_llm("default")
        except Exception:
            logger.warning("Failed to build LLM from model string", exc_info=True)
            return None

    def _build_native_from_model_string(self, model: str) -> AsyncLLMClient | None:
        try:
            endpoint = resolve_llm_endpoint(cli_model=model)
            return ProviderManager.for_endpoint(endpoint).get_native_client("default")
        except Exception:
            logger.warning("Failed to build native client from model string", exc_info=True)
            return None

    # --- Reporting ----------------------------------------------------------

    def _write_report(
        self,
        findings: list[Finding],
        verified: list[Finding],
        spent_per_tier: dict,
        band_stats: dict | None = None,
        pool_stats: dict | None = None,
        subsystem_stats: dict | None = None,
        pipeline_status: PipelineStatus | None = None,
        duration_seconds: float | None = None,
        lab_stats: dict | None = None,
    ) -> dict[str, str]:
        """Write SARIF / markdown / JSON outputs to the output directory.

        The implementation lives in reporter.py - but that module isn't built
        yet at the time this runner is being constructed. Keep the call here
        and let reporter.py register itself lazily.
        """
        try:
            from .reporter import write_scanner_report
        except ImportError:
            logger.warning("reporter.py not yet available; skipping report")
            return {}

        # Pull a fresh CostTracker snapshot so the reporter can render
        # the dual-cost section (real spend + token totals + reference
        # quotes) without needing to import the singleton itself.
        cost_summary: dict | None
        try:
            from acuario.observability.telemetry import CostTracker

            tracker = CostTracker()
            cs = tracker.get_summary()
            cost_summary = {
                "input_tokens": cs.input_tokens,
                "output_tokens": cs.output_tokens,
                "total_cost_usd": cs.total_cost_usd,
                "reference_cost_opus_usd": cs.reference_cost_opus_usd,
                "reference_cost_gpt_usd": cs.reference_cost_gpt_usd,
                "is_self_hosted": cs.is_self_hosted,
                "endpoint_label": cs.endpoint_label,
                # per-agent token/cost attribution (copy so the report
                # reader can't mutate the live tracker state).
                "by_agent": {k: dict(v) for k, v in tracker.by_agent.items()},
            }
        except Exception:
            cost_summary = None

        # Render a sentinel team_discussion.md FIRST. The main report.md emits a
        # footer cross-link only when team_discussion.md exists, so we touch an
        # empty team_discussion.md before the main report runs so the cross-link
        # condition triggers; team_discussion_report.py then overwrites the
        # sentinel with the real content.
        session_dir = Path(self.output_dir) / self._session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        _td_path = session_dir / "team_discussion.md"
        _td_existed = _td_path.exists()
        if not _td_existed:
            try:
                _td_path.touch()  # sentinel so report.md's cross-link fires
            except Exception:
                logger.debug("Failed to create team_discussion.md sentinel", exc_info=True)

        try:
            paths = write_scanner_report(
                output_dir=self.output_dir,
                session_id=self._session_id,
                repo_url=self.repo_url,
                findings=findings,
                verified_findings=verified,
                spent_per_tier=spent_per_tier,
                formats=self.output_formats,
                band_stats=band_stats,
                pool_stats=pool_stats,
                subsystem_stats=subsystem_stats,
                pipeline_status=pipeline_status,
                cost_summary=cost_summary,
                duration_seconds=duration_seconds,
                lab_stats=lab_stats,
                # advertise the projected team_discussion.md path so the
                # manifest's `outputs` map lists it.  The renderer below
                # overwrites the sentinel file we touched above.
                team_discussion_path=str(_td_path),
            )
        except Exception:
            logger.warning("Reporter failed", exc_info=True)
            if not _td_existed and _td_path.exists() and _td_path.stat().st_size == 0:
                # Clean up our sentinel if the main report didn't run
                try:
                    _td_path.unlink()
                except Exception:
                    pass
            return {}

        # render the team-discussion report after the main outputs so it
        # can read findings.json plus all per-agent JSONL logs that the lab
        # agents wrote during this run.  Failure is non-fatal (the existing
        # SARIF/MD/JSON outputs are still valid without it).
        try:
            from .team_discussion_report import write_team_discussion_report

            td_path = write_team_discussion_report(session_dir)
            paths["team_discussion"] = str(td_path)
        except Exception:
            logger.warning("Team discussion report failed", exc_info=True)
            # If we created an empty sentinel and the real renderer failed,
            # remove it so users aren't left with a misleading empty file.
            if not _td_existed and _td_path.exists() and _td_path.stat().st_size == 0:
                try:
                    _td_path.unlink()
                except Exception:
                    pass

        return paths
