"""Measurement framework - turn audit artifacts into a quality scoreboard.

A full precision/recall eval needs labeled ground truth, which we don't have
yet. But a great deal of *proxy* signal is already sitting in every session's
artifacts and just isn't being read:

- ``findings.json``        → per-source verified-rate (analyzer / critic /
                             variant / subsystem / orchestrator)
- ``calibration.jsonl``    → skeptic↔validator agreement (O8): where the
                             skeptic refuted but the validator advanced
                             (suspected false-negatives), and vice-versa
- ``skeptic_log.jsonl``    → refute / uncertain / accept distribution
- ``debate_log.jsonl``     → how often the rebuttal overturned a refutation
- severity_recalibrated    → how often the deterministic recalibration moved a
                             severity, and in which direction

``analyze_session`` reads whatever is present and degrades to empty sections
when a file is missing, so it works on old sessions too. An optional
``annotations.json`` overlay (``finding_id -> {label: TP|FP}``) upgrades the
proxy metrics to true precision/recall when a human has labeled a run.

This is the *instrument*: run an audit, then ``acuario eval --session <id>``
to read what the lab actually did, and ``--compare <other>`` to see the delta
between two runs (e.g. before/after a change).
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acuario.findings.types import canonical_findings

logger = logging.getLogger(__name__)


def _read_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        logger.debug("eval: failed reading %s", path, exc_info=True)
        return {}


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out: list[dict] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        logger.debug("eval: failed reading %s", path, exc_info=True)
    return out


@dataclass
class EvalReport:
    """Computed metrics for one audit session."""

    session_id: str
    endpoint_label: str = ""
    total_findings: int = 0
    verified_findings: int = 0
    # discovered_by -> {"total": n, "verified": n}
    by_source: dict[str, dict[str, int]] = field(default_factory=dict)
    skeptic_distribution: dict[str, int] = field(default_factory=dict)  # verdict -> count
    debate: dict[str, int] = field(default_factory=dict)  # overturned/upheld/conceded
    # skeptic↔validator agreement (only findings present in calibration.jsonl)
    agreement: dict[str, int] = field(default_factory=dict)
    severity_recalibration: dict[str, int] = field(default_factory=dict)
    evidence_levels: dict[str, int] = field(default_factory=dict)
    # Populated only when an annotations.json overlay is supplied.
    labeled: dict[str, Any] = field(default_factory=dict)

    @property
    def verified_rate(self) -> float:
        return self.verified_findings / self.total_findings if self.total_findings else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "endpoint_label": self.endpoint_label,
            "total_findings": self.total_findings,
            "verified_findings": self.verified_findings,
            "verified_rate": round(self.verified_rate, 4),
            "by_source": self.by_source,
            "skeptic_distribution": self.skeptic_distribution,
            "debate": self.debate,
            "agreement": self.agreement,
            "severity_recalibration": self.severity_recalibration,
            "evidence_levels": self.evidence_levels,
            "labeled": self.labeled,
        }

    def to_markdown(self) -> str:
        lines: list[str] = []
        lines.append(f"# Eval - {self.session_id}")
        lines.append("")
        if self.endpoint_label:
            lines.append(f"**Model:** {self.endpoint_label}")
        lines.append(
            f"**Findings:** {self.total_findings} total · {self.verified_findings} verified "
            f"({self.verified_rate * 100:.1f}%)"
        )
        lines.append("")
        lines.append(
            "> These are PROXY metrics derived from the run's own artifacts "
            "(the validator's verdict is the reference, not human ground truth). "
            "They compare agents and runs; they are not absolute precision/recall "
            "unless an annotations overlay is supplied."
        )
        lines.append("")

        # Per-source verified rate
        if self.by_source:
            lines.append("## Verified-rate by source")
            lines.append("")
            lines.append("| Source | Findings | Verified | Rate |")
            lines.append("|---|---:|---:|---:|")
            for src, d in sorted(self.by_source.items(), key=lambda kv: -kv[1]["total"]):
                tot = d["total"]
                ver = d["verified"]
                rate = (ver / tot * 100) if tot else 0.0
                lines.append(f"| {src} | {tot} | {ver} | {rate:.1f}% |")
            lines.append("")

        # Skeptic distribution + debate
        if self.skeptic_distribution:
            sd = self.skeptic_distribution
            lines.append("## Skeptic gate")
            lines.append("")
            parts = " · ".join(f"{k}: {v}" for k, v in sorted(sd.items()))
            lines.append(f"- Verdicts - {parts}")
            if self.debate:
                db = self.debate
                lines.append(
                    f"- Debate - overturned/reinstated: {db.get('overturned', 0)} · "
                    f"upheld: {db.get('upheld', 0)} · conceded: {db.get('conceded', 0)}"
                )
            lines.append("")

        # Agreement matrix
        if self.agreement:
            ag = self.agreement
            lines.append("## Skeptic ↔ validator agreement")
            lines.append("")
            lines.append("Of findings that reached the validator with a recorded skeptic verdict:")
            lines.append("")
            lines.append(f"- skeptic accepted & validator advanced: {ag.get('accept_advance', 0)}")
            lines.append(
                f"- skeptic accepted & validator rejected (skeptic let a likely-FP through): "
                f"{ag.get('accept_reject', 0)}"
            )
            lines.append(
                f"- skeptic refuted & validator advanced (skeptic may have killed a TP): "
                f"{ag.get('refute_advance', 0)}"
            )
            lines.append(
                f"- skeptic refuted & validator rejected (agreed kill): {ag.get('refute_reject', 0)}"
            )
            lines.append("")

        # Severity recalibration
        if self.severity_recalibration:
            sr = self.severity_recalibration
            lines.append("## Severity recalibration (O6)")
            lines.append("")
            lines.append(
                f"- moved: {sr.get('changed', 0)} · downgraded: {sr.get('downgraded', 0)} · "
                f"unchanged: {sr.get('unchanged', 0)}"
            )
            lines.append("")

        # Evidence levels
        if self.evidence_levels:
            lines.append("## Evidence-level distribution")
            lines.append("")
            for lvl, n in sorted(self.evidence_levels.items(), key=lambda kv: -kv[1]):
                lines.append(f"- {lvl}: {n}")
            lines.append("")

        # Labeled (true precision/recall) overlay
        if self.labeled:
            lab = self.labeled
            lines.append("## Labeled precision (annotations overlay)")
            lines.append("")
            lines.append(
                f"- labeled findings: {lab.get('labeled', 0)} "
                f"(TP {lab.get('tp', 0)} · FP {lab.get('fp', 0)})"
            )
            if lab.get("precision") is not None:
                lines.append(f"- precision (verified findings): {lab['precision'] * 100:.1f}%")
            lines.append("")

        return "\n".join(lines)


_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _source_severity_evidence(
    findings: list[dict],
) -> tuple[dict[str, dict[str, int]], dict[str, int], dict[str, int]]:
    """Return (by_source, severity_recalibration, evidence_levels)."""
    by_source: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "verified": 0})
    ev_levels: Counter = Counter()
    changed = down = unchanged = 0
    for f in findings:
        src = f.get("discovered_by") or "analyzer"
        by_source[src]["total"] += 1
        if f.get("verified"):
            by_source[src]["verified"] += 1
        lvl = f.get("evidence_level")
        if lvl:
            ev_levels[lvl] += 1
        recal = f.get("severity_recalibrated") or (f.get("extra") or {}).get(
            "severity_recalibrated"
        )
        if recal:
            base = f.get("severity_verified") or f.get("severity")
            if base and recal != base:
                changed += 1
                # Determine downgrade direction defensively: `base` can be a
                # non-standard severity from a legacy/external analyzer, so look
                # up each index independently - a bad `base` must not silently
                # drop the (valid) recal's direction for the others.
                recal_idx = _SEV_ORDER.index(recal) if recal in _SEV_ORDER else None
                base_idx = _SEV_ORDER.index(base) if base in _SEV_ORDER else None
                if recal_idx is not None and base_idx is not None and recal_idx < base_idx:
                    down += 1
            else:
                unchanged += 1
    recal_stats = (
        {"changed": changed, "downgraded": down, "unchanged": unchanged}
        if (changed or unchanged)
        else {}
    )
    return {k: dict(v) for k, v in by_source.items()}, recal_stats, dict(ev_levels)


def _skeptic_distribution(session_dir: Path) -> dict[str, int]:
    dist: Counter = Counter()
    for rec in _read_jsonl(session_dir / "skeptic_log.jsonl"):
        v = rec.get("verdict")
        if v:
            dist[v] += 1
    return dict(dist)


def _debate_outcomes(session_dir: Path) -> dict[str, int]:
    debate: Counter = Counter()
    for rec in _read_jsonl(session_dir / "debate_log.jsonl"):
        if rec.get("conceded"):
            debate["conceded"] += 1
        elif rec.get("reinstated"):
            debate["overturned"] += 1
        else:
            debate["upheld"] += 1
    return dict(debate)


def _agreement_matrix(session_dir: Path) -> dict[str, int]:
    agreement: Counter = Counter()
    for row in _read_jsonl(session_dir / "calibration.jsonl"):
        sk = row.get("skeptic_verdict")
        adv = (row.get("validator") or {}).get("validator_advance")
        if sk is None or adv is None:
            continue
        # "uncertain" passes through to the pool, so treat it as accept here.
        sk_accept = sk in ("accepted", "uncertain")
        key = ("accept" if sk_accept else "refute") + ("_advance" if adv else "_reject")
        agreement[key] += 1
    return dict(agreement)


def _labeled_precision(findings: list[dict], annotations: dict) -> dict[str, Any]:
    tp = fp = 0
    for f in findings:
        label = annotations.get(f.get("id", ""))
        if not isinstance(label, dict):
            continue
        lab = str(label.get("label", "")).upper()
        if lab == "TP":
            tp += 1
        elif lab == "FP":
            fp += 1
    total = tp + fp
    return {"labeled": total, "tp": tp, "fp": fp, "precision": (tp / total) if total else None}


def analyze_session(session_dir: Path, annotations: dict | None = None) -> EvalReport:
    """Compute an :class:`EvalReport` from a session's artifacts."""
    session_dir = Path(session_dir)
    findings_doc = _read_json(session_dir / "findings.json")
    manifest = _read_json(session_dir / "manifest.json")
    findings = list(findings_doc.get("findings") or [])

    by_source, recal, ev_levels = _source_severity_evidence(findings)
    # Headline counts cover the canonical set only - the same set inspect / report
    # show, and history now reconciles to from findings.json. variant_loop is a
    # default-OFF pattern-match stage the reviewer rejects at ~100%, so counting its
    # 0%-verified rows would drag the headline rate down. (The historical DB is a
    # dedup cache; its raw COUNT(*) can differ, which is why history reads the
    # report's findings.json when it is on disk.) by_source still lists variant_loop.
    canonical = canonical_findings(findings)
    report = EvalReport(
        session_id=findings_doc.get("session_id") or manifest.get("session_id") or session_dir.name,
        endpoint_label=(manifest.get("cost_summary") or {}).get("endpoint_label", ""),
        total_findings=len(canonical),
        verified_findings=sum(1 for f in canonical if f.get("verified")),
        by_source=by_source,
        severity_recalibration=recal,
        evidence_levels=ev_levels,
        skeptic_distribution=_skeptic_distribution(session_dir),
        debate=_debate_outcomes(session_dir),
        agreement=_agreement_matrix(session_dir),
    )
    if annotations:
        report.labeled = _labeled_precision(findings, annotations)
    return report


def compare_reports(a: EvalReport, b: EvalReport) -> str:
    """Render a short markdown delta between two session reports."""
    lines = [f"# Eval comparison - {a.session_id} → {b.session_id}", ""]
    lines.append("| Metric | " + a.session_id + " | " + b.session_id + " | Δ |")
    lines.append("|---|---:|---:|---:|")

    def _row(label: str, x: float, y: float, pct: bool = False) -> str:
        d = y - x
        fmt = (lambda v: f"{v * 100:.1f}%") if pct else (lambda v: f"{v:g}")
        sign = "+" if d >= 0 else ""
        return f"| {label} | {fmt(x)} | {fmt(y)} | {sign}{fmt(d)} |"

    lines.append(_row("total findings", a.total_findings, b.total_findings))
    lines.append(_row("verified findings", a.verified_findings, b.verified_findings))
    lines.append(_row("verified rate", a.verified_rate, b.verified_rate, pct=True))
    lines.append("")
    return "\n".join(lines)
