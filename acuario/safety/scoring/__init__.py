from __future__ import annotations

from acuario.safety.scoring.cvss import VULN_PRESETS, CVSSCalculator, CVSSVector
from acuario.safety.scoring.dedup import DedupRecord, FindingDeduplicator

__all__ = [
    "CVSSVector",
    "CVSSCalculator",
    "VULN_PRESETS",
    "DedupRecord",
    "FindingDeduplicator",
]
