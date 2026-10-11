"""Acuario source-code vulnerability analyzing pipeline.

A file-parallel agent-driven discovery pipeline:
    preprocess (clone + enumerate + tag)
    → rank (three axes: surface, influence, reachability)
    → tiered HunterPool (70/25/5 budget across A/B/C)
    → verify (independent context, adversarial)
    → exploit (sandboxed PoC, gated on evidence_level >= crash_reproduced)
    → report (SARIF + markdown + JSON)

Public entry points: ScanRunner (programmatic), `acuario scanner`
(CLI), and `hunt_source_code` (interactive @tool).
"""

from acuario.findings.types import Finding

from .config import (
    BudgetConfig,
    FeatureFlags,
    HuntTuning,
    OutputConfig,
    ScanConfig,
    TargetConfig,
)
from .state import (
    EVIDENCE_LEVELS,
    EvidenceLevel,
    FileTag,
    FileTarget,
    ScanState,
    evidence_at_or_above,
    evidence_compare,
    filter_by_evidence,
)

__all__ = [
    "BudgetConfig",
    "EvidenceLevel",
    "FeatureFlags",
    "FileTag",
    "FileTarget",
    "Finding",
    "HuntTuning",
    "OutputConfig",
    "ScanConfig",
    "ScanState",
    "TargetConfig",
    "EVIDENCE_LEVELS",
    "evidence_at_or_above",
    "evidence_compare",
    "filter_by_evidence",
]
