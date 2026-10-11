"""State schemas for the Acuario source-hunt pipeline.

Critical schema discipline: every type accepts new fields with sensible
defaults. Future features land as additions, not refactors.

Evidence ladder gates downstream budget allocation:
    suspicion < static_corroboration < crash_reproduced
        < root_cause_explained < exploit_demonstrated < patch_validated

The ExploitDeveloper only runs on findings >= crash_reproduced.
The Auto-Patcher only runs on findings >= root_cause_explained.
Findings reaching patch_validated are the gold standard in reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from acuario.scanner.reviewer import VerifierResult

from typing_extensions import TypedDict

from acuario.findings.types import (
    EVIDENCE_LEVELS,  # noqa: F401 - re-exported for backwards compatibility
    EvidenceLevel,
    Finding,
    evidence_at_or_above,
    evidence_compare,  # noqa: F401 - re-exported for backwards compatibility
)
from acuario.llm import BaseMessage

# --- Evidence ladder ---------------------------------------------------------
# Canonical definitions now live in acuario.findings.types.
# Re-exported here for backwards compatibility.


def filter_by_evidence(
    findings: list[Finding],
    threshold: EvidenceLevel,
) -> list[Finding]:
    """Return only findings with evidence_level >= threshold.

    Findings without an evidence_level field are treated as 'suspicion'.
    Used as a budget gate before passing to expensive downstream agents.
    """
    return [
        f for f in findings if evidence_at_or_above(f.get("evidence_level", "suspicion"), threshold)
    ]


# --- File tagging ------------------------------------------------------------

FileTag = Literal[
    "memory_unsafe",
    "parser",
    "crypto",
    "auth_boundary",
    "syscall_entry",
    "fuzzable",
    "attacker_reachable",
    "web_entry",  # web-framework entry point (route file, main app file, index, etc.)
    "cli_entry",  # CLI entry point (main.py, cli.py, __main__.py, etc.)
]


# --- FileTarget --------------------------------------------------------------


class FileTarget(TypedDict, total=False):
    """A source file to be ranked and (potentially) hunted.

    All fields are optional in the TypedDict to allow incremental population:
    the preprocessor sets path/language/loc/static_hint/imports_by/tags;
    the prioritizer fills in surface/influence/rationale; the pool computes tier.

    Optional enrichment fields (transitive_callers, semgrep_hint,
    has_fuzz_entry_point, fuzz_harness_path, reachability_rationale) are
    present with safe defaults so the schema is forward-compatible.
    """

    path: str  # relative to repo root
    absolute_path: str
    surface: int  # 1-5 - direct vulnerability likelihood
    influence: int  # 1-5 - downstream danger if this file is wrong
    reachability: int  # 1-5 - attacker-reachability through callgraph
    # defaults to 3 (unknown); real propagation fills it in
    priority: float  # surface*0.5 + influence*0.2 + reachability*0.3
    tier: Literal["A", "B", "C"]
    tags: list[FileTag]  # heuristic tagger + LLM polish
    language: str
    loc: int
    surface_rationale: str
    influence_rationale: str
    reachability_rationale: str
    static_hint: int  # SourceAnalyzer regex hits → surface boost
    semgrep_hint: int  # Semgrep findings count → surface boost + hint
    taint_hits: int  # tree-sitter taint paths touching this file
    imports_by: int  # cheap influence signal
    transitive_callers: int  # tree-sitter callgraph (better influence)
    defines_constants: bool
    has_fuzz_entry_point: bool  # detected by tagger
    fuzz_harness_path: str | None  # filled by Harness Generator
    min_hops_from_entry: int  # callgraph distance from nearest entry point


# The canonical `Finding` dataclass from `acuario.findings.types` is
# imported at the top of this module and used directly in the state
# TypedDicts below.


# --- SubsystemTarget ---------------------------------------------


@dataclass
class SubsystemTarget:
    """A group of related files to hunt as a unit."""

    name: str  # e.g. "tcp_sack", "h264_decoder"
    root_path: str  # e.g. "net/ipv4/", "libavcodec/"
    files: list[FileTarget]  # max 50 files, sorted by priority
    entry_points: list[Any] = field(default_factory=list)
    description: str = ""
    priority: float = 0.0  # max(file.priority for file in files)
    source: str = "auto"  # "auto" | "manual" | "orchestrator"
    # when source=="orchestrator", links back to the originating plan so
    # findings emitted from this subsystem hunt can be traced to the plan
    # that asked for them.  Empty for "auto" and "manual" targets.
    plan_id: str = ""
    # the orchestrator's concrete cross-file vulnerability hypothesis
    # (full hunt_focus, not the truncated name). Injected into the subsystem
    # hunter's prompt so the hunt is guided by the hypothesis instead of
    # re-hunting blind. Empty for auto-detected subsystems.
    hunt_hypothesis: str = ""


# --- ElaborationResult --------------------------------------------


@dataclass
class ElaborationResult:
    """Result of a Stage 1.5 exploit elaboration attempt."""

    original_finding_id: str
    elaborated: bool
    upgraded_impact: str | None = None
    upgraded_exploit_code: str | None = None
    chained_findings: list[str] = field(default_factory=list)
    upgrade_path: str = ""
    blocking_mitigations: list[str] = field(default_factory=list)
    human_guided: bool = False
    cost: float = 0.0
    transcript_path: str = ""


# --- Validation types ---------------------------------------------


@dataclass
class AxisResult:
    """Result of a single validation axis."""

    axis: str  # "REAL" | "TRIGGERABLE" | "IMPACTFUL" | "GENERAL"
    passed: bool
    confidence: str  # "high" | "medium" | "low"
    rationale: str
    boundary_crossed: str = ""  # only for IMPACTFUL axis


@dataclass
class ValidatorVerdict:
    """Output of the unified 4-axis validator."""

    finding_id: str
    axes: dict[str, AxisResult]
    advance: bool
    severity_validated: str | None
    evidence_level: EvidenceLevel
    pro_argument: str
    counter_argument: str
    tie_breaker: str
    duplicate_cve: str | None
    raw_response: str = ""
    # deterministic severity recalibration from the 4-axis confidences.
    # None means "not recalibrated" (flag off or no adjustment) - consumers
    # fall back to severity_validated.
    severity_recalibrated: str | None = None
    severity_recalibration_reason: str = ""

    def to_verifier_result(self) -> VerifierResult:
        from acuario.scanner.reviewer import VerifierResult

        return VerifierResult(
            finding_id=self.finding_id,
            is_real=self.advance,
            severity_verified=self.severity_validated,
            evidence_level=self.evidence_level,
            pro_argument=self.pro_argument,
            counter_argument=self.counter_argument,
            tie_breaker=self.tie_breaker,
            duplicate_cve=self.duplicate_cve,
            raw_response=self.raw_response,
        )


# --- Stability types -----------------------------------------------


@dataclass
class StabilityResult:
    """Output of Stage 2.5 PoC stability verification."""

    finding_id: str
    total_runs: int
    successes: int
    success_rate: float  # 0.0-1.0
    per_container_rates: list[float]
    classification: str  # "stable" | "flaky" | "unreliable"
    hardened: bool = False
    hardening_improved: bool = False
    failure_analysis: str = ""
    original_poc: str = ""
    hardened_poc: str | None = None


# --- Disclosure lifecycle ------------------------------------------


class StageOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    DEGRADED = "degraded"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class StageStatus:
    """Status of a single pipeline stage."""

    name: str
    outcome: StageOutcome
    error: str | None = None
    fallback_description: str | None = None


@dataclass
class PipelineStatus:
    """Aggregated health status for the full pipeline run."""

    stages: dict[str, StageStatus] = field(default_factory=dict)

    def record(self, name: str, outcome: StageOutcome, **kwargs: Any) -> None:
        self.stages[name] = StageStatus(name=name, outcome=outcome, **kwargs)

    def record_degraded(
        self,
        name: str,
        fallback: str,
        error: str = "",
    ) -> None:
        self.stages[name] = StageStatus(
            name=name,
            outcome=StageOutcome.DEGRADED,
            error=error or None,
            fallback_description=fallback,
        )

    def record_succeeded(self, name: str) -> None:
        self.stages[name] = StageStatus(name=name, outcome=StageOutcome.SUCCEEDED)

    @property
    def any_degraded(self) -> bool:
        return any(s.outcome == StageOutcome.DEGRADED for s in self.stages.values())

    @property
    def any_failed(self) -> bool:
        return any(s.outcome == StageOutcome.FAILED for s in self.stages.values())

    def summary_lines(self) -> list[str]:
        lines: list[str] = []
        for s in self.stages.values():
            line = f"  {s.name}: {s.outcome.value}"
            if s.fallback_description:
                line += f" - {s.fallback_description}"
            if s.error:
                line += f" (error: {s.error})"
            lines.append(line)
        return lines


class DisclosureState(str, Enum):
    PENDING_REVIEW = "pending_review"
    IN_REVIEW = "in_review"
    VALIDATED = "validated"
    REJECTED = "rejected"
    NEEDS_REVISION = "needs_revision"
    PENDING_DISCLOSURE = "pending_disclosure"
    DISCLOSED = "disclosed"
    ACKNOWLEDGED = "acknowledged"
    PATCH_IN_PROGRESS = "patch_in_progress"
    PATCHED = "patched"
    PUBLIC = "public"
    WONTFIX = "wontfix"


# --- ScanState ---------------------------------------------------------


class ScanState(TypedDict, total=False):
    """State for analyzer/reviewer/exploit_dev sub-graphs.

    Every optional field is present with safe defaults so the schema is
    forward-compatible; code paths that don't need a field simply don't
    read or write it.
    """

    messages: list[BaseMessage]
    repo_url: str
    repo_path: str
    branch: str
    files: list[FileTarget]
    files_scanned: list[str]
    current_file: str | None

    # seams
    callgraph: dict | None  # tree-sitter callgraph
    semgrep_findings: list[dict]  # pre-scan hits used as hints
    fuzz_corpora: list[dict]  # detected OSS-Fuzz / project corpora
    seeded_crashes: list[dict]  # harness generator output

    findings: list[Finding]
    verified_findings: list[Finding]

    # seams
    variant_seeds: list[dict]  # hypotheses from variant analyzer loop
    exploited_findings: list[Finding]
    patch_attempts: list[dict]  # auto-patcher output (validated or not)

    # Budget & cost
    budget_usd: float
    spent_usd: float
    spent_per_tier: dict[str, float]  # {"A": ..., "B": ..., "C": ...}
    total_tokens: int

    phase: Literal[
        "preprocess",
        "tag",
        "rank",
        "fuzz",
        "hunt",
        "verify",
        "variant_loop",
        "stability",
        "exploit",
        "elaborate",
        "auto_patch",
        "report",
    ]
    session_id: str | None
    flags_found: list[dict]
