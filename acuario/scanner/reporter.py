"""Audit report writer - SARIF + markdown + JSON.

Reuses acuario/runners/cicd/sarif.py::SARIFGenerator (now file-aware via R2)
for SARIF output. Markdown and JSON are written directly.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from acuario.findings.types import canonical_findings
from acuario.observability.telemetry import CostTracker
from acuario.runners.cicd.sarif import SARIFGenerator

from .dedup import primaries
from .state import EVIDENCE_LEVELS, Finding, PipelineStatus

logger = logging.getLogger(__name__)


_EVIDENCE_RANK = {level: idx for idx, level in enumerate(EVIDENCE_LEVELS)}


def _fence(text: str) -> str:
    """A backtick run longer than any inside ``text`` (minimum 3), so an embedded
    code fence in a snippet / crash evidence can't break out of the block."""
    longest = max((len(m) for m in re.findall(r"`+", text or "")), default=0)
    return "`" * max(longest + 1, 3)


def _sev_counts(findings: list[Finding]) -> dict[str, int]:
    """Severity histogram over unique loci - same-locus duplicates (marked
    ``duplicate_of`` by the dedup pass) are excluded so a bug reported several
    times is counted once.
    """
    out: dict[str, int] = {}
    for f in findings:
        if f.get("duplicate_of"):
            continue
        s = (f.get("severity_verified") or f.get("severity") or "info").lower()
        out[s] = out.get(s, 0) + 1
    return out


def write_scanner_report(
    output_dir: str,
    session_id: str,
    repo_url: str,
    findings: list[Finding],
    verified_findings: list[Finding],
    spent_per_tier: dict,
    formats: list[str] | None = None,
    band_stats: dict | None = None,
    pool_stats: dict | None = None,
    subsystem_stats: dict | None = None,
    pipeline_status: PipelineStatus | None = None,
    cost_summary: dict | None = None,
    duration_seconds: float | None = None,
    lab_stats: dict | None = None,
    team_discussion_path: str | None = None,
) -> dict[str, str]:
    """Write the requested formats. Returns {format: filesystem_path}.

    ``cost_summary`` is the optional token / dual-cost detail produced by
    the runner from the live ``CostTracker``. When supplied, the markdown
    report and the manifest gain a "Cost & tokens" section that shows
    real spend (commercial APIs) or token totals + reference quotes
    (self-hosted endpoints).

    ``duration_seconds`` and ``lab_stats`` (Phase H) - when supplied,
    the markdown report gains an Executive Summary header block, a LAB
    Activity section showing skeptic/critic/orchestrator/sandbox totals,
    and a duration line in the LLM Usage section.  Both are optional so
    legacy callers keep working.  ``lab_stats`` is expected to contain
    keys: ``skeptic_accepted``, ``skeptic_refuted``, ``critic_leads``,
    ``critic_verified``, ``orchestrator_plans``, ``orchestrator_findings``,
    ``snapshot_cycles``, ``ptrace_events`` (all ints, all optional).
    """
    formats = formats or ["sarif", "markdown", "json", "pdf"]
    if "all" in formats:
        formats = ["sarif", "markdown", "json", "pdf"]

    session_dir = Path(output_dir) / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    # B1 (belt): drop any finding whose path resolves under the scanner's OWN
    # output dir - defense in depth over the enumeration exclusion, catching a
    # finding an agent's file tools may have produced against a results/ or
    # scratch artifact mid-hunt. Absolute-path matched, so a target app's own
    # paths are never affected.
    _output_abs = os.path.abspath(output_dir)

    def _under_output_dir(f: Finding) -> bool:
        fp = f.get("file")
        if not fp:
            return False
        ap = os.path.abspath(str(fp))
        return ap == _output_abs or ap.startswith(_output_abs + os.sep)

    _artifact_findings = [f for f in findings if _under_output_dir(f)]
    if _artifact_findings:
        logger.info(
            "[report] dropped %d finding(s) targeting the scanner's own output dir",
            len(_artifact_findings),
        )
        findings = [f for f in findings if not _under_output_dir(f)]
        verified_findings = [f for f in verified_findings if not _under_output_dir(f)]

    paths: dict[str, str] = {}

    if "sarif" in formats:
        sarif_path = session_dir / "findings.sarif"
        sarif = SARIFGenerator().generate(
            findings=_to_sarif_findings(findings),
            target=repo_url,
            tool_name="acuario-scanner",
        )
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
        paths["sarif"] = str(sarif_path)

    if "markdown" in formats:
        md_path = session_dir / "report.md"
        md = _render_markdown(
            session_id=session_id,
            repo_url=repo_url,
            findings=findings,
            verified_findings=verified_findings,
            spent_per_tier=spent_per_tier,
            band_stats=band_stats,
            pool_stats=pool_stats,
            subsystem_stats=subsystem_stats,
            pipeline_status=pipeline_status,
            cost_summary=cost_summary,
            duration_seconds=duration_seconds,
            lab_stats=lab_stats,
            session_dir=session_dir,
        )
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        paths["markdown"] = str(md_path)

    if "pdf" in formats:
        # Native, paginated deliverable alongside report.md (reportlab, no system
        # deps). Best-effort: a PDF failure must never lose the other artifacts.
        try:
            from .pdf_report import render_pdf

            pdf_path = session_dir / "report.pdf"
            render_pdf(
                str(pdf_path),
                session_id=session_id,
                repo_url=repo_url,
                findings=findings,
                verified_findings=verified_findings,
                cost_summary=cost_summary,
                duration_seconds=duration_seconds,
                lab_stats=lab_stats,
            )
            paths["pdf"] = str(pdf_path)
        except Exception:
            logger.warning("[report] PDF generation failed; other formats written", exc_info=True)

    if "json" in formats:
        json_path = session_dir / "findings.json"
        json_data: dict[str, Any] = {
            "session_id": session_id,
            "repo_url": repo_url,
            "spent_per_tier": spent_per_tier,
            "findings": findings,
            "verified_findings": verified_findings,
        }
        if band_stats:
            json_data["band_stats"] = band_stats
        if pool_stats:
            json_data["pool_stats"] = pool_stats
        if subsystem_stats:
            json_data["subsystem_stats"] = subsystem_stats
        if pipeline_status and pipeline_status.stages:
            json_data["pipeline_status"] = {
                name: {
                    "outcome": s.outcome.value,
                    "error": s.error,
                    "fallback": s.fallback_description,
                }
                for name, s in pipeline_status.stages.items()
            }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=_json_default)
        paths["json"] = str(json_path)

    # include the team-discussion path in the outputs map so manifest
    # consumers (CI integrations, the inspect REPL, dashboards) can discover
    # it without filesystem assumptions.  The runner generates the actual
    # file AFTER this returns; passing the projected path here just records
    # where it WILL land.
    if team_discussion_path:
        paths["team_discussion"] = team_discussion_path

    # Always write a manifest
    manifest_path = session_dir / "manifest.json"
    # canonical total spend = tiers + subsystem. Summing only spent_per_tier
    # would silently drop subsystem-hunt spend, so surface subsystem_spent
    # explicitly.
    _tier_spent = sum(spent_per_tier.values())
    _subsystem_spent = (
        float(subsystem_stats.get("subsystem_spent_usd", 0.0) or 0.0) if subsystem_stats else 0.0
    )
    manifest = {
        "session_id": session_id,
        "repo_url": repo_url,
        "finding_count": len(findings),
        "verified_count": len(verified_findings),
        # Unique-locus counts (same-locus duplicates folded into a primary).
        # Raw counts above are kept for back-compat; these are what the report
        # headline and the terminal banner show.
        "unique_finding_count": len(primaries(findings)),
        "unique_verified_count": len(primaries(verified_findings)),
        "spent_per_tier": spent_per_tier,
        "subsystem_spent": _subsystem_spent,
        "total_spent": _tier_spent + _subsystem_spent,
        "outputs": paths,
    }
    if cost_summary:
        # Inline the dual-cost summary so machine readers don't have to
        # cross-reference a separate file. Self-hosted runs expose the
        # reference quotes here for downstream "estimate cloud cost" UIs.
        manifest["cost_summary"] = cost_summary
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    paths["manifest"] = str(manifest_path)

    return paths


# --- Format-specific helpers ------------------------------------------------


def _to_sarif_findings(findings: list[Finding]) -> list[dict]:
    """Convert Finding entries into the dict shape SARIFGenerator expects.

    SARIFGenerator (after R2) honors `file` and `line_number` if present.
    Same-locus duplicates are excluded so each unique finding is one SARIF
    result (no repeated alerts on the same line in code-scanning UIs).
    """
    out = []
    # Exclude variant_loop (default-OFF, reviewer-rejected noise) from SARIF so
    # code-scanning UIs show only the canonical findings, matching report.md.
    for f in primaries(canonical_findings(findings)):
        out.append(
            {
                "description": f.get("description", ""),
                "severity": f.get("severity_verified") or f.get("severity") or "info",
                "cve": f.get("cwe"),  # use CWE as the rule_id
                "details": _details_block(f),
                "file": f.get("file"),
                "line_number": f.get("line_number"),
                "end_line": f.get("end_line"),
                "evidence_level": f.get("evidence_level"),
            }
        )
    return out


def _details_block(f: Finding) -> str:
    parts = []
    if f.get("evidence_level"):
        parts.append(f"evidence_level: {f['evidence_level']}")
    if f.get("discovered_by"):
        parts.append(f"discovered_by: {f['discovered_by']}")
    if f.get("crash_evidence"):
        parts.append(f"crash:\n{f['crash_evidence']}")
    if f.get("verifier_pro_argument"):
        parts.append(f"verifier_pro: {f['verifier_pro_argument']}")
    if f.get("verifier_counter_argument"):
        parts.append(f"verifier_counter: {f['verifier_counter_argument']}")
    if f.get("stability_classification"):
        rate = f.get("stability_success_rate", 0) * 100
        parts.append(f"stability: {f['stability_classification']} ({rate:.0f}% reproduction)")
    if f.get("crypto_protocol"):
        parts.append(f"crypto_protocol: {f['crypto_protocol']}")
    if f.get("algorithm"):
        parts.append(f"algorithm: {f['algorithm']}")
    if f.get("crypto_attack_class"):
        parts.append(f"attack_class: {f['crypto_attack_class']}")
    if f.get("key_material_exposed"):
        parts.append(f"key_material: {f['key_material_exposed']}")
    return "\n\n".join(parts)


def _render_markdown(
    session_id: str,
    repo_url: str,
    findings: list[Finding],
    verified_findings: list[Finding],
    spent_per_tier: dict,
    band_stats: dict | None = None,
    pool_stats: dict | None = None,
    subsystem_stats: dict | None = None,
    pipeline_status: PipelineStatus | None = None,
    cost_summary: dict | None = None,
    duration_seconds: float | None = None,
    lab_stats: dict | None = None,
    session_dir: Path | None = None,
) -> str:
    lines: list[str] = []
    # Keep report.md to the canonical finding set (same as inspect / eval / the DB):
    # variant_loop is a default-OFF pattern-match stage the reviewer rejects at
    # ~100% and that is never persisted, so it must not pad the findings list or the
    # severity/executive counts. findings.json (dumped elsewhere) stays raw.
    findings = canonical_findings(findings)
    verified_findings = canonical_findings(verified_findings)
    lines.append(f"# Acuario Audit Report - {session_id}")
    lines.append("")

    # Severity counts, reused by the Executive Summary (H3) and the Severity
    # table (H5). Same-locus duplicates (marked ``duplicate_of``) are excluded
    # so a bug reported several times counts once (B1), and both the
    # all-findings and verified-only bases are kept so the report headline and
    # the terminal banner never look contradictory (B2b).
    sev_counts = _sev_counts(findings)
    sev_counts_verified = _sev_counts(verified_findings)

    # Executive Summary - headline numbers visible without scrolling.
    lines.extend(
        _render_executive_summary(
            repo_url=repo_url,
            findings=findings,
            verified_findings=verified_findings,
            sev_counts=sev_counts,
            sev_counts_verified=sev_counts_verified,
            duration_seconds=duration_seconds,
            cost_summary=cost_summary,
        )
    )

    # Tokens + cost: self-hosted runs show token totals + reference quotes
    # against frontier APIs; commercial runs show real spend.
    if cost_summary:
        is_local = bool(cost_summary.get("is_self_hosted"))
        in_tok = int(cost_summary.get("input_tokens", 0))
        out_tok = int(cost_summary.get("output_tokens", 0))
        endpoint = cost_summary.get("endpoint_label", "")
        lines.append("")
        lines.append("## LLM usage")
        if endpoint:
            lines.append(f"- **Endpoint:** {endpoint}")
        # total duration in the LLM Usage section so it sits next to
        # the token / cost figures users already look for here.
        if duration_seconds is not None:
            lines.append(f"- **Total duration:** {_format_duration(duration_seconds)}")
        lines.append(
            f"- **Tokens used:** {in_tok + out_tok:,} (input {in_tok:,} / output {out_tok:,})"
        )
        if is_local:
            lines.append("- **Cost paid:** $0.00 - self-hosted")
            lines.append("- **Reference quote (same workload on commercial APIs):**")
            # Priced from this run's token totals against the current frontier
            # lineup (CostTracker.REFERENCE_MODELS), so the names, rates, and
            # figures come from one place and cannot drift apart.
            for _label, _usd in CostTracker.reference_quotes(in_tok, out_tok):
                lines.append(f"    - {_label}: ~${_usd:,.2f}")
            lines.append(
                "    - *(Estimated at the providers' published per-token "
                "rates. Actual cloud cost varies with prompt-cache hits.)*"
            )
        else:
            lines.append(f"- **Cost paid:** ${float(cost_summary.get('total_cost_usd', 0.0)):.4f}")
            lines.append(
                f"- **Spend by tier:** "
                f"A=${spent_per_tier.get('A', 0):.4f}, "
                f"B=${spent_per_tier.get('B', 0):.4f}, "
                f"C=${spent_per_tier.get('C', 0):.4f}"
            )
    else:
        # Legacy callers without a cost_summary fall back to the old layout.
        lines.append(
            f"- **Spend by tier:** "
            f"A=${spent_per_tier.get('A', 0):.4f}, "
            f"B=${spent_per_tier.get('B', 0):.4f}, "
            f"C=${spent_per_tier.get('C', 0):.4f}"
        )
        lines.append(f"- **Total spend:** ${sum(spent_per_tier.values()):.4f}")
        if duration_seconds is not None:
            lines.append(f"- **Total duration:** {_format_duration(duration_seconds)}")
    lines.append("")

    # per-agent token/cost attribution. Shows which pipeline role is
    # eating the budget - the data behind any future "is this agent worth it"
    # decision. Omitted when no attribution was recorded.
    lines.extend(_render_cost_by_agent(cost_summary or {}))

    # LAB Activity - mirrors the terminal end-of-run LAB block.
    # Omitted entirely when no lab activity recorded (all-zero stats).
    lab_section = _render_lab_activity(lab_stats or {})
    if lab_section:
        lines.extend(lab_section)

    if pipeline_status and pipeline_status.stages:
        lines.append("## Pipeline Health")
        lines.append("")
        # ``summary_lines()`` returns ``  <stage>: <outcome>`` strings with
        # two-space indentation but no list marker - that renders as orphan
        # text in strict Markdown viewers.  Normalize to proper bullets so
        # the section reads consistently with the rest of the report.
        for status_line in pipeline_status.summary_lines():
            lines.append(f"- {status_line.lstrip()}")
        lines.append("")

    # severity histogram rendered as a Markdown table so the breakdown
    # scans at a glance instead of one-bullet-per-severity. Total and verified
    # columns (both over unique loci) so the basis is explicit.
    if sev_counts:
        lines.extend(_render_severity_table(sev_counts, sev_counts_verified))

    if band_stats:
        lines.append("## Band Distribution")
        for band in ("fast", "standard", "deep"):
            runs = band_stats.get(f"{band}_runs", 0)
            cost = band_stats.get(f"{band}_cost", 0.0)
            avg = cost / runs if runs else 0.0
            lines.append(f"- **{band.title()}:** {runs} runs, ${cost:.2f} (avg ${avg:.2f}/run)")
        promos = band_stats.get("promotions", {})
        if promos:
            promo_parts = ", ".join(f"{k}: {v}" for k, v in promos.items() if v)
            if promo_parts:
                lines.append(f"- **Promotions:** {promo_parts}")
        lines.append("")

    if pool_stats:
        # This section reports the FindingsPool's dedup result after the
        # per-file analyzer pool, but BEFORE subsystem hunts and the variant
        # loop append their findings directly to ``all_findings``.  The
        # numbers here therefore reflect only the initial analyzer-pool pass,
        # not the final pool size shown in the Executive Summary.
        lines.append("## Analyzer Pool Dedup (initial pass)")
        lines.append(
            "_Counts reflect the per-file analyzer pool only; "
            "subsystem-hunt and variant-loop findings append later "
            "and don't flow through the same clustering._"
        )
        lines.append("")
        lines.append(f"- **Total findings:** {pool_stats.get('total_findings', 0)}")
        lines.append(f"- **Unique clusters:** {pool_stats.get('total_clusters', 0)}")
        lines.append(f"- **Duplicates removed:** {pool_stats.get('duplicates', 0)}")
        lines.append("")

    if subsystem_stats:
        lines.append("## Subsystem Hunts")
        lines.append(f"- **Subsystems hunted:** {subsystem_stats.get('subsystems_hunted', 0)}")
        lines.append(f"- **Subsystem spend:** ${subsystem_stats.get('subsystem_spent_usd', 0):.2f}")
        lines.append("")

    # orchestrator plans - read from orchestrator_log.jsonl when present.
    # Omitted when the file is absent (orchestrator disabled or never ran).
    orch_section = _render_orchestrator_plans(session_dir)
    if orch_section:
        lines.extend(orch_section)

    # sandbox behavior anomalies - read from the ptrace event JSONL files.
    # Omitted when nothing anomalous was captured.
    anomaly_section = _render_behavior_anomalies(session_dir)
    if anomaly_section:
        lines.extend(anomaly_section)

    # Findings sorted by evidence_level descending, then severity. Only primary
    # findings are rendered; same-locus duplicates are folded into their
    # primary's "Also reported as" note below, so the list isn't the same
    # bug repeated under different labels.
    lines.append("## Findings")
    sorted_findings = sorted(
        primaries(findings),
        key=lambda f: (
            -_EVIDENCE_RANK.get(f.get("evidence_level", "suspicion"), 0),
            -_severity_rank(f),
        ),
    )
    for i, f in enumerate(sorted_findings, 1):
        sev = (f.get("severity_verified") or f.get("severity") or "info").upper()
        lines.append(
            f"### {i}. [{sev}] {f.get('finding_type', 'unknown')} "
            f"at `{f.get('file', '?')}:{f.get('line_number', '?')}`"
        )
        lines.append("")
        lines.append(f"- **CWE:** {f.get('cwe', 'N/A')}")
        lines.append(f"- **Evidence:** {f.get('evidence_level', 'suspicion')}")
        if f.get("discovered_by"):
            lines.append(f"- **Discovered by:** {f['discovered_by']}")
        if f.get("verified") is True:
            lines.append("- **Verified:** yes")
        if f.get("alias_ids"):
            _labels = f.get("alias_labels") or []
            _as = f" as {', '.join(_labels)}" if _labels else ""
            lines.append(
                f"- **Also reported{_as}:** {len(f['alias_ids'])} duplicate finding(s) "
                f"at this location, merged here (`{'`, `'.join(f['alias_ids'])}`)"
            )
        if f.get("crypto_protocol"):
            lines.append(f"- **Crypto protocol:** {f['crypto_protocol']}")
        if f.get("algorithm"):
            lines.append(f"- **Algorithm:** {f['algorithm']}")
        if f.get("crypto_attack_class"):
            lines.append(f"- **Attack class:** {f['crypto_attack_class']}")
        if f.get("key_material_exposed"):
            lines.append(f"- **Key material at risk:** {f['key_material_exposed']}")
        lines.append("")
        lines.append(f.get("description", ""))
        if f.get("code_snippet"):
            lines.append("")
            _snip_fence = _fence(f["code_snippet"])
            lines.append(_snip_fence)
            lines.append(f["code_snippet"])
            lines.append(_snip_fence)
            lines.append("")  # ensure separation from any following block
        if f.get("crash_evidence"):
            lines.append("")
            lines.append("**Crash evidence:**")
            lines.append("")
            _crash_fence = _fence(f["crash_evidence"])
            lines.append(_crash_fence)
            # J2 refinement: emit full crash evidence in report.md (the
            # exploit-dev step is the only thing that writes this field and
            # it's already bounded by the sandbox-execution captured output).
            lines.append(f["crash_evidence"])
            lines.append(_crash_fence)
            lines.append("")  # ensure separation from any following block
        # All the per-finding metadata bullets go first as one cohesive
        # list.  The verifier counter-argument paragraph is rendered AFTER
        # the metadata block so the bullets stay together and the
        # counter-argument reads as its own footnote paragraph.
        if f.get("validator_axes"):
            lines.append("")
            lines.append("**Validation axes:**")
            lines.append("")
            for axis_name, axis_data in f["validator_axes"].items():
                status = "PASS" if axis_data["passed"] else "FAIL"
                lines.append(f"- {axis_name}: {status} ({axis_data['confidence']})")
            lines.append("")

        # Extra metadata bullets - grouped together so Markdown sees one
        # continuous list and a blank line cleanly separates them from
        # adjacent prose.
        extra_meta_lines: list[str] = []
        if f.get("severity_disagreement"):
            extra_meta_lines.append(f"- **Severity disagreement:** {f['severity_disagreement']}")
        # show the analyzer's original claim when the validator recalibrated it.
        if f.get("severity_recalibration_reason"):
            extra_meta_lines.append(
                f"- **Severity recalibrated:** {f.get('severity_claimed', '?')} → "
                f"{f.get('severity_verified', '?')} ({f['severity_recalibration_reason']})"
            )
        # an attempted exploit that was blocked - verified bug, blocked PoC.
        if f.get("exploit_blocked_by"):
            extra_meta_lines.append(
                f"- **Exploit attempted but blocked by:** {f['exploit_blocked_by']}"
            )
        # evidence walked back because the PoC proved flaky.
        if f.get("evidence_demotion_reason"):
            extra_meta_lines.append(f"- **Evidence demoted:** {f['evidence_demotion_reason']}")
        # skeptic doubt that wasn't a code-cited refutation (passed through).
        if f.get("skeptic_flag") == "uncertain" and f.get("skeptic_doubt"):
            extra_meta_lines.append(f"- **Skeptic doubt (unrefuted):** {f['skeptic_doubt']}")
        if f.get("exploit_partial"):
            extra_meta_lines.append(
                f"- **Exploit partial:** primitive={f.get('exploit_primitive_type', '?')}"
            )
        if f.get("exploit_mitigations_bypassed"):
            extra_meta_lines.append(
                f"- **Mitigations bypassed:** {', '.join(f['exploit_mitigations_bypassed'])}"
            )
        if f.get("exploit_mitigations_blocking"):
            extra_meta_lines.append(
                f"- **Mitigations blocking:** {', '.join(f['exploit_mitigations_blocking'])}"
            )
        if f.get("exploit_chained_findings"):
            extra_meta_lines.append(
                f"- **Chained findings:** {', '.join(f['exploit_chained_findings'])}"
            )
        if f.get("exploit_cost_usd"):
            extra_meta_lines.append(f"- **Exploit cost:** ${f['exploit_cost_usd']:.2f}")
        if f.get("discovered_by") == "elaboration_agent":
            extra_meta_lines.append(f"- **Elaborated from:** {f.get('related_finding_id', '?')}")
        if f.get("elaboration_upgrade_path"):
            extra_meta_lines.append(f"- **Upgrade path:** {f['elaboration_upgrade_path']}")
        if f.get("stability_classification"):
            cls = f["stability_classification"]
            rate = f.get("stability_success_rate", 0) * 100
            extra_meta_lines.append(f"- **Stability:** {cls} ({rate:.0f}% reproduction rate)")
            if f.get("stability_hardened"):
                improved = "improved" if f.get("stability_hardening_improved") else "no improvement"
                extra_meta_lines.append(f"- **Hardened:** {improved}")
        if extra_meta_lines:
            lines.extend(extra_meta_lines)
            lines.append("")

        # Counter-argument as a clearly-set-off footnote paragraph,
        # surrounded by blank lines so it doesn't bleed into adjacent
        # bullets.  Renders consistently across Markdown viewers.
        if f.get("verifier_counter_argument"):
            # Leading blank: protects against being glued to a preceding
            # code-fence or bullet when intermediate metadata blocks were
            # absent for this finding.
            if lines and lines[-1] != "":
                lines.append("")
            lines.append("> **Verifier counter-argument:** " + f["verifier_counter_argument"])
            lines.append("")

        # Guaranteed trailing blank line - separates this finding from the
        # next ``### N+1. ...`` heading even when none of axes / metadata /
        # counter-argument blocks rendered (e.g. minimal static findings).
        # Cheap: a duplicate blank just collapses in any Markdown viewer.
        if not lines or lines[-1] != "":
            lines.append("")

    # Tier disagreements section
    disagreements = [f for f in findings if f.get("severity_disagreement")]
    if disagreements:
        lines.append("## Tier Disagreements")
        lines.append("")
        lines.append("Findings where discoverer and validator severity differ by 2+ levels:")
        lines.append("")
        for f in disagreements:
            lines.append(
                f"- `{f.get('id', '?')}` at `{f.get('file', '?')}:{f.get('line_number', '?')}`: "
                f"{f['severity_disagreement']}"
            )
        lines.append("")

    # Rejected findings appendix
    rejected = [f for f in findings if f.get("rejected_axes")]
    if rejected:
        lines.append("## Rejected Findings")
        lines.append("")
        for f in rejected:
            fid = f.get("id", "?")
            axes = ", ".join(f["rejected_axes"])
            lines.append(
                f"- `{fid}` at `{f.get('file', '?')}:{f.get('line_number', '?')}` - failed: {axes}"
            )
        lines.append("")

    # footer cross-link.  When team_discussion.md exists alongside
    # report.md, point readers at it for the full per-agent
    # debate transcript.
    if session_dir is not None and (session_dir / "team_discussion.md").is_file():
        lines.append("---")
        lines.append("")
        lines.append(
            "For the full per-agent debate transcript on every finding "
            "(analyzer trajectory + skeptic verdict + reviewer 4-axis + "
            "exploit-dev outcome), see "
            "[`team_discussion.md`](team_discussion.md)."
        )
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Phase H helpers - Executive Summary, LAB Activity, Orchestrator Plans,
# Severity table, duration formatter.
# ---------------------------------------------------------------------------


def _format_duration(seconds: float) -> str:
    """Format a duration the same way the terminal banner does.

    Mirrors ``acuario/ui/narration.py::_format_duration`` so the report
    and terminal show the same string for the same audit.
    """
    if seconds is None or seconds < 0:
        return "n/a"
    if seconds >= 3600:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h}h {m}m"
    if seconds >= 60:
        m = int(seconds // 60)
        s = int(seconds % 60)
        return f"{m}m {s}s"
    return f"{seconds:.1f}s"


def _render_executive_summary(
    *,
    repo_url: str,
    findings: list[Finding],
    verified_findings: list[Finding],
    sev_counts: dict[str, int],
    sev_counts_verified: dict[str, int],
    duration_seconds: float | None,
    cost_summary: dict | None,
) -> list[str]:
    """Render the at-a-glance summary block right under the H1 header.

    Returns the markdown lines (no leading H1, the caller already wrote it).
    The block is bullet-style but kept short so it fits in the first
    scroll-page even on a long audit. Counts are over unique loci (same-locus
    duplicates excluded) and shown on both the all-findings and verified bases
    so this block never contradicts the terminal banner.
    """
    lines: list[str] = []
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Repository:** {repo_url or '(local target)'}")
    total_unique = len(primaries(findings))
    verified_unique = len(primaries(verified_findings))
    raw_note = f" ({len(findings)} raw incl. duplicates)" if len(findings) != total_unique else ""
    lines.append(f"- **Findings:** {total_unique} unique{raw_note} · {verified_unique} verified")

    def _tv(sev: str) -> str:
        return f"{sev_counts.get(sev, 0)} / {sev_counts_verified.get(sev, 0)}"

    lines.append(
        f"- **Severity (total / verified):** {_tv('critical')} critical · "
        f"{_tv('high')} high · {_tv('medium')} medium · {_tv('low')} low"
    )
    if duration_seconds is not None:
        lines.append(f"- **Total duration:** {_format_duration(duration_seconds)}")
    if cost_summary:
        is_local = bool(cost_summary.get("is_self_hosted"))
        if is_local:
            lines.append("- **Cost paid:** $0.00 (self-hosted)")
        else:
            lines.append(f"- **Cost paid:** ${float(cost_summary.get('total_cost_usd', 0.0)):.4f}")
    lines.append(
        "- **Full debate transcript:** see `team_discussion.md` "
        "for each finding's analyzer reasoning, skeptic verdict, "
        "reviewer arguments, and exploit-dev outcome."
    )
    lines.append("")
    return lines


def _render_cost_by_agent(cost_summary: dict) -> list[str]:
    """P4: per-agent token/cost attribution table.

    Returns [] when no attribution was recorded (legacy runs / no LLM calls).
    On self-hosted endpoints the paid cost is $0, so the table shows tokens and
    the reference (Opus-rate) cost as the relative "how expensive" signal.
    """
    by_agent = cost_summary.get("by_agent") or {}
    if not by_agent:
        return []
    is_local = bool(cost_summary.get("is_self_hosted"))
    rows = sorted(by_agent.items(), key=lambda kv: -(kv[1].get("ref_cost_usd", 0.0)))
    lines = ["### Cost by agent", ""]
    cost_col = "Ref. cost" if is_local else "Cost"
    lines.append(f"| Agent | Calls | Input tok | Output tok | {cost_col} |")
    lines.append("|---|---:|---:|---:|---:|")
    for agent_name, d in rows:
        cost = d.get("ref_cost_usd", 0.0) if is_local else d.get("cost_usd", 0.0)
        lines.append(
            f"| {agent_name} | {int(d.get('calls', 0))} | "
            f"{int(d.get('input_tokens', 0)):,} | {int(d.get('output_tokens', 0)):,} | "
            f"${cost:.4f} |"
        )
    lines.append("")
    return lines


def _render_lab_activity(lab_stats: dict) -> list[str]:
    """Render the LAB Activity section.  Returns [] when no lab activity
    occurred (all stats zero / missing) so the section is omitted entirely.
    """
    sa = int(lab_stats.get("skeptic_accepted", 0) or 0)
    sr = int(lab_stats.get("skeptic_refuted", 0) or 0)
    su = int(lab_stats.get("skeptic_uncertain", 0) or 0)
    dr = int(lab_stats.get("debate_reinstated", 0) or 0)
    du = int(lab_stats.get("debate_upheld", 0) or 0)
    cl = int(lab_stats.get("critic_leads", 0) or 0)
    cv = int(lab_stats.get("critic_verified", 0) or 0)
    op = int(lab_stats.get("orchestrator_plans", 0) or 0)
    of = int(lab_stats.get("orchestrator_findings", 0) or 0)
    sc = int(lab_stats.get("snapshot_cycles", 0) or 0)
    pe = int(lab_stats.get("ptrace_events", 0) or 0)

    if not any([sa, sr, su, dr, du, cl, cv, op, of, sc, pe]):
        return []

    lines: list[str] = []
    lines.append("## LAB Activity")
    lines.append("")
    if sa or sr or su:
        total = sa + sr + su
        line = f"- **Skeptic gate:** accepted {sa}, refuted {sr}"
        if su:
            line += f", uncertain {su}"
        line += f" ({total} screened)"
        lines.append(line)
    if dr or du:
        lines.append(
            f"- **Debate round (O2):** {dr} refutation(s) overturned & reinstated, {du} upheld"
        )
    if cl:
        lines.append(
            f"- **Reflective critic:** {cl} low-confidence lead(s) added "
            f"({cv} reached verified status)"
        )
    if op:
        opf = int(lab_stats.get("orchestrator_plan_findings", 0) or 0)
        asf = int(lab_stats.get("auto_subsystem_findings", 0) or 0)
        lines.append(
            f"- **Cross-file orchestrator:** {op} plan(s) emitted "
            f"({of} finding(s) surfaced from follow-up hunts)"
        )
        if opf or asf:
            # O4 (d): A/B yield - does the orchestrator earn its keep vs
            # auto-detected subsystems?
            lines.append(
                f"    - subsystem-hunt yield: {opf} from orchestrator plans · "
                f"{asf} from auto-detection"
            )
    if sc or pe:
        lines.append(
            f"- **Sandbox lab:** {sc} snapshot/rollback cycle(s) · {pe} ptrace event(s) captured"
        )
    lines.append("")
    return lines


def _render_orchestrator_plans(session_dir: Path | None) -> list[str]:
    """Render the per-plan section by reading ``orchestrator_log.jsonl``
    (written by Phase G1c).  Returns [] when the file is absent or empty
    so the section is omitted from the report.
    """
    if session_dir is None:
        return []
    log_path = session_dir / "orchestrator_log.jsonl"
    if not log_path.is_file():
        return []
    plans: list[dict] = []
    try:
        with log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for plan in record.get("plans") or []:
                    plans.append(plan)
    except Exception:
        logger.debug("Failed reading orchestrator_log.jsonl for report", exc_info=True)
        return []

    if not plans:
        return []

    lines: list[str] = []
    lines.append("## Cross-file Orchestrator Plans")
    lines.append("")
    lines.append(
        f"The orchestrator emitted {len(plans)} cross-file investigation plan(s) "
        "after the per-file analyzer pool completed.  Each plan was executed "
        "as a follow-up subsystem hunt."
    )
    lines.append("")
    for plan in plans:
        pid = plan.get("plan_id", "?")
        focus = plan.get("hunt_focus", "?")
        files = plan.get("files") or []
        rationale = plan.get("rationale", "")
        lines.append(f"### Plan `{pid}` - {focus}")
        lines.append("")
        if files:
            lines.append(f"- **Files:** {', '.join(f'`{f}`' for f in files)}")
        if rationale:
            lines.append(f"- **Rationale:** {rationale}")
        lines.append("")
    return lines


def _render_behavior_anomalies(session_dir: Path | None) -> list[str]:
    """N3: surface anomalous syscalls the ptrace monitor captured.

    Reads the behavior-event JSONL files (analyzer + exploit-dev) and lists
    the events the monitor classified as ``warning`` / ``critical`` - the
    sandbox watching the analysis. The monitor's built-in classifier is the
    practical "baseline": it flags syscalls a normal compile/run shouldn't
    make (``/etc/passwd`` / ``/proc/self`` reads, ``mount``, ``unshare``,
    outbound connects). Returns [] when there's nothing anomalous so the
    section is omitted.

    (A full per-language syscall-baseline diff is deliberately deferred - a
    dynamically-collected baseline is circular, and a curated one belongs with
    the deferred eval corpus. The deny-list classifier captures the
    high-signal anomalies without that machinery.)
    """
    if session_dir is None:
        return []
    anomalies: list[dict] = []
    for fname, origin in (
        ("analyzer_behavior_events.jsonl", "analyzer"),
        ("behavior_events.jsonl", "exploit-dev"),
    ):
        path = session_dir / fname
        if not path.is_file():
            continue
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("severity") in ("warning", "critical"):
                        ev["_origin"] = origin
                        anomalies.append(ev)
        except Exception:
            logger.debug("Failed reading %s for report", fname, exc_info=True)

    if not anomalies:
        return []

    # Group identical (syscall, path) anomalies and keep a count so a noisy
    # loop doesn't flood the section.
    grouped: dict[tuple, dict] = {}
    for ev in anomalies:
        key = (ev.get("severity"), ev.get("syscall"), ev.get("path"), ev["_origin"])
        slot = grouped.setdefault(key, {"count": 0, "sample": ev})
        slot["count"] += 1

    crit = sum(1 for k in grouped if k[0] == "critical")
    warn = sum(1 for k in grouped if k[0] == "warning")
    lines: list[str] = []
    lines.append("## Sandbox Behavior Anomalies")
    lines.append("")
    lines.append(
        f"The syscall monitor flagged {len(grouped)} distinct anomalous "
        f"behavior(s) ({crit} critical · {warn} warning) while the sandbox ran "
        "analyzer / exploit commands. These are syscalls a normal build/run "
        "shouldn't make - the sandbox observing the analysis at the kernel level."
    )
    lines.append("")
    lines.append("| Severity | Syscall | Path / target | Where | Count |")
    lines.append("|---|---|---|---|---|")
    # critical first, then by count desc
    for key, slot in sorted(
        grouped.items(), key=lambda kv: (kv[0][0] != "critical", -kv[1]["count"])
    ):
        sev, syscall, path_, origin = key
        target = (path_ or "-")[:80]
        lines.append(f"| {sev} | `{syscall or '?'}` | `{target}` | {origin} | {slot['count']} |")
    lines.append("")
    return lines


def _render_severity_table(
    sev_counts: dict[str, int], sev_counts_verified: dict[str, int]
) -> list[str]:
    """Render the severity breakdown as a Markdown table.

    Two columns - Total (all findings) and Verified - both counted over unique
    loci, so the reader sees the full picture and the post-review number
    without either looking like a contradiction.
    """
    lines: list[str] = []
    lines.append("## Severity Breakdown")
    lines.append("")
    lines.append("_Counts are over unique locations; same-locus duplicates excluded._")
    lines.append("")
    lines.append("| Severity | Total | Verified |")
    lines.append("|---|---:|---:|")
    total = 0
    total_verified = 0
    for sev in ("critical", "high", "medium", "low", "info"):
        n = sev_counts.get(sev, 0)
        nv = sev_counts_verified.get(sev, 0)
        if n or nv:
            total += n
            total_verified += nv
            lines.append(f"| {sev} | {n} | {nv} |")
    lines.append(f"| **Total** | **{total}** | **{total_verified}** |")
    lines.append("")
    return lines


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _severity_rank(f: Finding) -> int:
    sev = (f.get("severity_verified") or f.get("severity") or "info").lower()
    return _SEVERITY_ORDER.get(sev, 0)


def _json_default(obj: Any) -> Any:
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)
