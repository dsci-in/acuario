"""Native PDF audit report via reportlab (pure-Python, no system deps).

Written alongside report.md so a run yields a paginated, print-ready deliverable
that opens instantly, without the buffering a very large Markdown file causes in
viewers. The content mirrors the Markdown report's substance - executive
summary, severity breakdown, cost, lab activity, and per-finding detail - laid
out for the page. Same-locus duplicates are folded (primaries only), matching
report.md and the SARIF output.

Kept deliberately dependency-light: reportlab is already a project dependency
and needs no system libraries (unlike an HTML-to-PDF path).
"""

from __future__ import annotations

import logging
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .dedup import primaries
from .state import EVIDENCE_LEVELS, Finding

logger = logging.getLogger(__name__)

_SEV_COLOR = {
    "critical": colors.HexColor("#b3121f"),
    "high": colors.HexColor("#c2570f"),
    "medium": colors.HexColor("#8a6d00"),
    "low": colors.HexColor("#2a6fb0"),
    "info": colors.HexColor("#5b6472"),
}
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_EVIDENCE_RANK = {level: idx for idx, level in enumerate(EVIDENCE_LEVELS)}
_INK = colors.HexColor("#1b2430")
_MUTE = colors.HexColor("#5b6472")
_RULE = colors.HexColor("#d5dae1")
_CODE_BG = colors.HexColor("#f4f6f8")
_CODE_WRAP = 96  # soft-wrap width for code lines so they don't overflow the page
_CODE_MAX_LINES = 60  # cap a single snippet so one finding can't run for pages


def _esc(text: Any) -> str:
    """Escape the mini-markup reportlab Paragraph interprets."""
    s = "" if text is None else str(text)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sev(f: Finding) -> str:
    return (f.get("severity_verified") or f.get("severity") or "info").lower()


def _wrap_code(snippet: str) -> str:
    """Soft-wrap long lines and cap the total so a snippet fits the page."""
    out: list[str] = []
    for raw in str(snippet).replace("\t", "    ").splitlines():
        if len(raw) <= _CODE_WRAP:
            out.append(raw)
        else:
            for i in range(0, len(raw), _CODE_WRAP):
                out.append(raw[i : i + _CODE_WRAP])
        if len(out) >= _CODE_MAX_LINES:
            out.append("... (snippet truncated)")
            break
    return "\n".join(out)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = base["BodyText"]
    fonts = {"body": "Helvetica", "bold": "Helvetica-Bold", "mono": "Courier"}
    s: dict[str, ParagraphStyle] = {}
    s["title"] = ParagraphStyle(
        "AcTitle",
        parent=body,
        fontName=fonts["bold"],
        fontSize=20,
        leading=24,
        textColor=_INK,
        spaceAfter=2,
    )
    s["subtitle"] = ParagraphStyle(
        "AcSub",
        parent=body,
        fontName=fonts["body"],
        fontSize=9.5,
        leading=13,
        textColor=_MUTE,
        spaceAfter=2,
    )
    s["h2"] = ParagraphStyle(
        "AcH2",
        parent=body,
        fontName=fonts["bold"],
        fontSize=13.5,
        leading=17,
        textColor=_INK,
        spaceBefore=14,
        spaceAfter=6,
    )
    s["finding"] = ParagraphStyle(
        "AcFinding",
        parent=body,
        fontName=fonts["bold"],
        fontSize=11.5,
        leading=15,
        textColor=_INK,
        spaceBefore=12,
        spaceAfter=3,
    )
    s["body"] = ParagraphStyle(
        "AcBody",
        parent=body,
        fontName=fonts["body"],
        fontSize=9.5,
        leading=14,
        textColor=_INK,
        spaceAfter=5,
    )
    s["meta"] = ParagraphStyle(
        "AcMeta",
        parent=body,
        fontName=fonts["body"],
        fontSize=8.5,
        leading=12,
        textColor=_MUTE,
    )
    s["code"] = ParagraphStyle(
        "AcCode",
        parent=body,
        fontName=fonts["mono"],
        fontSize=7.6,
        leading=9.6,
        textColor=_INK,
    )
    return s


def _severity_table(sev_counts: dict, sev_counts_verified: dict, st: dict) -> Table:
    header = [
        Paragraph("<b>Severity</b>", st["meta"]),
        Paragraph("<b>Total</b>", st["meta"]),
        Paragraph("<b>Verified</b>", st["meta"]),
    ]
    rows = [header]
    style = [
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, _RULE),
        ("LINEBELOW", (0, -1), (-1, -1), 0.6, _RULE),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    r = 1
    tot = totv = 0
    for sev in ("critical", "high", "medium", "low", "info"):
        n, nv = sev_counts.get(sev, 0), sev_counts_verified.get(sev, 0)
        if not (n or nv):
            continue
        tot += n
        totv += nv
        chip = ParagraphStyle(
            "chip", parent=st["meta"], textColor=_SEV_COLOR[sev], fontName="Helvetica-Bold"
        )
        rows.append(
            [
                Paragraph(sev.upper(), chip),
                Paragraph(str(n), st["meta"]),
                Paragraph(str(nv), st["meta"]),
            ]
        )
        r += 1
    rows.append(
        [
            Paragraph("<b>Total</b>", st["meta"]),
            Paragraph(f"<b>{tot}</b>", st["meta"]),
            Paragraph(f"<b>{totv}</b>", st["meta"]),
        ]
    )
    t = Table(rows, colWidths=[70 * mm, 30 * mm, 30 * mm], hAlign="LEFT")
    t.setStyle(TableStyle(style))
    return t


def _sev_counts(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        if f.get("duplicate_of"):
            continue
        out[_sev(f)] = out.get(_sev(f), 0) + 1
    return out


def _format_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "n/a"
    if seconds >= 3600:
        return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"
    if seconds >= 60:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{seconds:.1f}s"


def render_pdf(
    path: str,
    *,
    session_id: str,
    repo_url: str,
    findings: list[Finding],
    verified_findings: list[Finding],
    cost_summary: dict | None = None,
    duration_seconds: float | None = None,
    lab_stats: dict | None = None,
) -> None:
    """Write a styled PDF audit report to ``path``.

    Renders primaries only (same-locus duplicates folded), matching report.md.
    """
    st = _styles()
    story: list[Any] = []

    # --- Title block --------------------------------------------------------
    story.append(Paragraph("Acuario Audit Report", st["title"]))
    story.append(Paragraph(_esc(session_id), st["subtitle"]))
    story.append(Paragraph(f"Repository: {_esc(repo_url or '(local target)')}", st["subtitle"]))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=0.8, color=_RULE))

    prim = primaries(findings)
    prim_v = primaries(verified_findings)
    sev_counts = _sev_counts(findings)
    sev_counts_verified = _sev_counts(verified_findings)

    # --- Executive summary --------------------------------------------------
    story.append(Paragraph("Executive Summary", st["h2"]))
    raw_note = f" ({len(findings)} raw incl. duplicates)" if len(findings) != len(prim) else ""
    story.append(
        Paragraph(
            f"<b>{len(prim)}</b> unique findings{_esc(raw_note)} &middot; "
            f"<b>{len(prim_v)}</b> verified",
            st["body"],
        )
    )
    if duration_seconds is not None:
        story.append(Paragraph(f"Duration: {_format_duration(duration_seconds)}", st["meta"]))
    if cost_summary:
        if cost_summary.get("is_self_hosted"):
            story.append(Paragraph("Cost paid: $0.00 (self-hosted)", st["meta"]))
        else:
            story.append(
                Paragraph(
                    f"Cost paid: ${float(cost_summary.get('total_cost_usd', 0.0)):.2f}", st["meta"]
                )
            )
    story.append(Spacer(1, 8))
    story.append(_severity_table(sev_counts, sev_counts_verified, st))

    # --- Lab activity (compact) --------------------------------------------
    if lab_stats:
        bits = []
        sa, sr, su = (
            int(lab_stats.get(k, 0) or 0)
            for k in ("skeptic_accepted", "skeptic_refuted", "skeptic_uncertain")
        )
        if sa or sr or su:
            bits.append(f"Skeptic gate: {sa} accepted, {sr} refuted, {su} uncertain")
        pe = int(lab_stats.get("ptrace_events", 0) or 0)
        sc = int(lab_stats.get("snapshot_cycles", 0) or 0)
        if sc or pe:
            bits.append(f"Sandbox: {sc} snapshot cycles, {pe} ptrace events")
        if bits:
            story.append(Paragraph("Lab Activity", st["h2"]))
            for b in bits:
                story.append(Paragraph(_esc(b), st["meta"]))

    # --- Findings -----------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Findings", st["h2"]))
    ordered = sorted(
        prim,
        key=lambda f: (
            -_EVIDENCE_RANK.get(f.get("evidence_level", "suspicion"), 0),
            -_SEV_ORDER.get(_sev(f), 0),
        ),
    )
    for i, f in enumerate(ordered, 1):
        story.extend(_finding_flowables(i, f, st))

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"Acuario Audit Report - {session_id}",
        author="Acuario",
    )
    doc.build(story, onFirstPage=_chrome, onLaterPages=_chrome)


def _finding_flowables(idx: int, f: Finding, st: dict) -> list[Any]:
    sev = _sev(f)
    color = _SEV_COLOR.get(sev, _MUTE)
    head_style = ParagraphStyle(f"fh{idx}", parent=st["finding"], textColor=color)
    head = Paragraph(
        f"{idx}. [{sev.upper()}] {_esc(f.get('finding_type', 'unknown'))} "
        f"<font color='#5b6472'>at {_esc(f.get('file', '?'))}:{_esc(f.get('line_number', '?'))}</font>",
        head_style,
    )
    meta_bits = [
        f"CWE: {_esc(f.get('cwe', 'N/A'))}",
        f"Evidence: {_esc(f.get('evidence_level', 'suspicion'))}",
        f"Discovered by: {_esc(f.get('discovered_by', 'unknown'))}",
    ]
    if f.get("verified") is True:
        meta_bits.append("Verified: yes")
    if f.get("exploit_success") is True:
        meta_bits.append("Exploited: yes")
    meta = Paragraph("  &bull;  ".join(meta_bits), st["meta"])
    flow: list[Any] = [head, meta]
    if f.get("alias_ids"):
        labels = ", ".join(_esc(x) for x in (f.get("alias_labels") or [])) or "same location"
        flow.append(
            Paragraph(
                f"<i>Also reported as {labels}: {len(f['alias_ids'])} duplicate finding(s) merged.</i>",
                st["meta"],
            )
        )
    flow.append(Spacer(1, 3))
    if f.get("description"):
        flow.append(Paragraph(_esc(f.get("description")), st["body"]))
    snippet = f.get("code_snippet")
    if snippet:
        code = Preformatted(_wrap_code(snippet), st["code"])
        boxed = Table([[code]], colWidths=[174 * mm])
        boxed.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), _CODE_BG),
                    ("BOX", (0, 0), (-1, -1), 0.4, _RULE),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        flow.append(boxed)
    flow.append(Spacer(1, 4))
    flow.append(HRFlowable(width="100%", thickness=0.4, color=_RULE))
    # Keep the heading + metadata together; let long bodies flow across pages.
    return [KeepTogether(flow[:3])] + flow[3:]


def _chrome(canvas: Any, doc: Any) -> None:
    """Header rule + footer with report name and page number."""
    canvas.saveState()
    w, h = A4
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(_MUTE)
    canvas.drawString(18 * mm, h - 10 * mm, "Acuario Audit Report")
    canvas.drawRightString(w - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(_RULE)
    canvas.setLineWidth(0.4)
    canvas.line(18 * mm, h - 12 * mm, w - 18 * mm, h - 12 * mm)
    canvas.restoreState()
