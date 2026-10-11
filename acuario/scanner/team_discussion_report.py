"""Team discussion report (G3) - multi-agent debate transcript per finding.

The audit pipeline produces a coordinated team of agents (analyzer, skeptic,
critic, orchestrator, reviewer, exploit-dev).  Each leaves artifacts behind,
but the artifacts are scattered:

    findings.json                 → analyzer + reviewer verdicts on each finding
    skeptic_log.jsonl             → every skeptic decision (G1a) with reasoning
    skeptic_refuted.jsonl         → legacy: refuted findings only (kept for compat)
    critic_log.jsonl              → every critic reflection (G1b) with leads
    orchestrator_log.jsonl        → every orchestrator emission (G1c) with plans
    ~/.acuario/scanner/trajectories/<session>-<file>/  → analyzer ReAct trajectories
    exploits/<finding-id>/transcript.jsonl             → exploit-dev transcripts
    behavior_events.jsonl         → ptrace events (G6)
    audit.log                     → stage timing

This module merges them into a single ``team_discussion.md`` so a human can
read the per-finding debate without grep-ing across eight different files.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .state import Finding

logger = logging.getLogger(__name__)


_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "": 5,
}

# J2 (refined): no caps on analyzer-trajectory rendering.
#   - Every non-empty reasoning_content thought is emitted in full
#     (``_TRAJECTORY_THOUGHT_MAX = None``).
#   - All thoughts in the trajectory are shown, not just the first N
#     (``_TOP_THOUGHTS_PER_FINDING = None``).
# To keep the report scannable, the renderer wraps the analyzer thoughts
# in a collapsed ``<details>`` block - Markdown viewers (GitHub,
# VSCode preview, glow, etc.) honor it and the reader can expand on demand.
_TOP_THOUGHTS_PER_FINDING: int | None = None
_TRAJECTORY_THOUGHT_MAX: int | None = None


# ---------------------------------------------------------------------------
# Artifact loading
# ---------------------------------------------------------------------------


@dataclass
class _Artifacts:
    """All session artifacts the team-discussion report consumes."""

    session_dir: Path
    session_id: str = ""
    repo_url: str = ""
    duration_seconds: float = 0.0
    depth: str = "unknown"
    lab_flags: dict[str, bool] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    verified_findings: list[Finding] = field(default_factory=list)
    skeptic_log: dict[str, dict] = field(default_factory=dict)  # finding_id → record
    debate_log: dict[str, dict] = field(default_factory=dict)  # finding_id → debate record
    skeptic_refuted_fallback: dict[str, dict] = field(default_factory=dict)
    critic_log: list[dict] = field(default_factory=list)
    orchestrator_log: list[dict] = field(default_factory=list)
    behavior_events: list[dict] = field(default_factory=list)
    pipeline_status: dict = field(default_factory=dict)
    cost_summary: dict = field(default_factory=dict)
    # lazy {file_path → trajectory_records} cache built by
    # _load_analyzer_trajectory on first access.  Empty dict sentinel means
    # "not yet built"; an empty list value means "no trajectory for this file".
    _trajectory_index: dict[str, list[dict]] = field(default_factory=dict)
    _trajectory_index_built: bool = False


def _read_jsonl(path: Path) -> list[dict]:
    """Best-effort JSONL reader: skips malformed lines, returns [] on missing file."""
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
        logger.debug("Failed reading %s", path, exc_info=True)
    return out


def _read_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        logger.debug("Failed reading %s", path, exc_info=True)
        return {}


def _load_artifacts(session_dir: Path) -> _Artifacts:
    """Read every artifact relevant to the team-discussion report.

    Files that are missing are silently treated as empty - this lets the
    report work on partial sessions (e.g. a crashed audit that never wrote
    its lab logs, or runs that disabled the orchestrator entirely).
    """
    art = _Artifacts(session_dir=session_dir)

    # findings.json - primary source of finding metadata
    findings_doc = _read_json(session_dir / "findings.json")
    art.session_id = findings_doc.get("session_id", session_dir.name)
    art.repo_url = findings_doc.get("repo_url", "")
    art.findings = list(findings_doc.get("findings") or [])
    art.verified_findings = list(findings_doc.get("verified_findings") or [])

    # manifest.json - session-level summary
    manifest = _read_json(session_dir / "manifest.json")
    art.cost_summary = manifest.get("cost_summary") or {}
    if not art.session_id:
        art.session_id = manifest.get("session_id", session_dir.name)

    # skeptic_log.jsonl (G1a) - every skeptic decision keyed by finding_id
    for rec in _read_jsonl(session_dir / "skeptic_log.jsonl"):
        fid = rec.get("finding_id", "")
        if fid:
            art.skeptic_log[fid] = rec
    # Fallback: skeptic_refuted.jsonl (only refused findings, no prompts)
    for rec in _read_jsonl(session_dir / "skeptic_refuted.jsonl"):
        fid = rec.get("finding_id", "")
        if fid and fid not in art.skeptic_log:
            art.skeptic_refuted_fallback[fid] = rec

    # debate_log.jsonl - analyzer↔skeptic rebuttals on refuted findings,
    # keyed by finding_id (last entry wins).
    for rec in _read_jsonl(session_dir / "debate_log.jsonl"):
        fid = rec.get("finding_id", "")
        if fid:
            art.debate_log[fid] = rec

    # critic_log.jsonl (G1b) and orchestrator_log.jsonl (G1c)
    art.critic_log = _read_jsonl(session_dir / "critic_log.jsonl")
    art.orchestrator_log = _read_jsonl(session_dir / "orchestrator_log.jsonl")

    # behavior_events.jsonl (G6) - ptrace events if the monitor was wired up
    art.behavior_events = _read_jsonl(session_dir / "behavior_events.jsonl")

    return art


# ---------------------------------------------------------------------------
# Trajectory reader (analyzer)
# ---------------------------------------------------------------------------


def _safe_path_slug(file_path: str) -> str:
    """Reproduce the slug acuario.agent.tools.hunt.sandbox uses for trajectory dirs."""
    if not file_path:
        return "unknown"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", file_path).strip("._") or "unknown"


def _build_trajectory_index(
    art: _Artifacts,
    session_id: str,
    trajectories_root: Path | None,
) -> None:
    """J3: build the {file_path → trajectory_records} index for this session.

    Trajectory dirs are named ``<session_id>-<8-char-sub-session-hex>``, NOT
    ``<session_id>-<file-path-slug>`` as the original loader assumed.  The
    actual file path is inside the JSONL's first ``event=start`` record.

    Scanned dirs match ``<session_id>-*`` so all sub-sessions for this audit
    are discovered.  For each JSONL we read the head, extract ``file_path``,
    and store the full record list under that key.  When multiple sub-sessions
    targeted the same file (band promotion / redundancy), the most-recent
    sub-session's records win (later glob iteration overwrites earlier).
    """
    if trajectories_root is None:
        trajectories_root = Path.home() / ".acuario" / "scanner" / "trajectories"
    if not trajectories_root.is_dir():
        art._trajectory_index_built = True
        return

    for dir_path in sorted(trajectories_root.glob(f"{session_id}-*")):
        if not dir_path.is_dir():
            continue
        for jsonl in dir_path.glob("*.jsonl"):
            recs = _read_jsonl(jsonl)
            if not recs:
                continue
            # First record is the analyzer's "start" event and carries the
            # original (un-sanitized) file path.
            file_path = recs[0].get("file_path") or recs[0].get("file") or ""
            if file_path:
                art._trajectory_index[file_path] = recs
    art._trajectory_index_built = True


def _load_analyzer_trajectory(
    art: _Artifacts,
    file_path: str,
    trajectories_root: Path | None,
) -> list[dict]:
    """Return the analyzer ReAct trajectory for ``file_path``, or [] if absent.

    J3: lazy builds the per-session trajectory index on the first call, then
    serves all subsequent finding lookups from the cache.  Old API (positional
    ``session_id``) is gone - callers pass the ``_Artifacts`` instance so the
    cache is reused.
    """
    if not art._trajectory_index_built:
        _build_trajectory_index(art, art.session_id, trajectories_root)
    return art._trajectory_index.get(file_path, [])


def _top_analyzer_thoughts(
    trajectory: list[dict],
    n: int | None = _TOP_THOUGHTS_PER_FINDING,
) -> list[str]:
    """Pull reasoning excerpts from a trajectory.

    J3: rewritten for the actual trajectory record format used by
    ``NativeHunter``.  Records look like::

        {"event": "message",
         "message": {"role": "assistant", "content": "...", "tool_calls": [...]},
         "reasoning_content": "the chain-of-thought the model emitted",
         "step": N, ...}

    The model's analytical thought lands on ``reasoning_content`` (when the
    provider exposes it), and the assistant's textual reply lands on
    ``message.content``.  Prefer reasoning_content; fall back to content.

    J2 refinement: when ``n is None`` every non-empty thought is returned
    and each is rendered in full (``_TRAJECTORY_THOUGHT_MAX`` may also be
    ``None``).  The caller wraps the result in a ``<details>`` HTML block
    so the report stays scannable.
    """
    if not trajectory:
        return []
    thoughts: list[str] = []
    for rec in trajectory:
        text = ""
        # Newer trajectory format: reasoning_content on message events
        rc = rec.get("reasoning_content")
        if isinstance(rc, str) and rc.strip():
            text = rc.strip()
        else:
            # Fallback: assistant content
            msg = rec.get("message") or {}
            if isinstance(msg, dict) and msg.get("role") == "assistant":
                content = msg.get("content") or ""
                if isinstance(content, str) and content.strip():
                    text = content.strip()
            # Legacy event types we keep supporting for older trajectories
            if not text:
                kind = rec.get("event") or rec.get("type") or ""
                if kind in ("think", "thought", "reasoning"):
                    text = str(
                        rec.get("text") or rec.get("content") or rec.get("message") or ""
                    ).strip()
        if text:
            thoughts.append(text)
        if n is not None and len(thoughts) >= n:
            break
    return [t[:_TRAJECTORY_THOUGHT_MAX] for t in thoughts]


# ---------------------------------------------------------------------------
# Exploit transcript reader
# ---------------------------------------------------------------------------


def _load_exploit_transcript(session_dir: Path, finding_id: str) -> dict:
    """Read exploit-dev outcome for a finding.  Returns {} if absent."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", finding_id).strip("._") or "unknown"
    transcript = session_dir / "exploits" / slug / "transcript.jsonl"
    recs = _read_jsonl(transcript)
    if not recs:
        return {}
    # The final record_exploit_result tool call carries the verdict.
    final: dict = {}
    for rec in recs:
        tc = rec.get("tool_call") or {}
        if tc.get("fn_name") == "record_exploit_result":
            final = dict(tc.get("fn_arguments") or {})
    return final


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _md_esc(s: Any) -> str:
    """Light markdown escaping - keeps the report readable when descriptions
    contain markdown special chars."""
    if s is None:
        return ""
    text = str(s)
    return text.replace("|", "\\|")


def _short_title(text: str, max_len: int = 120) -> str:
    """Extract a short, heading-friendly title from a longer description.

    Picks the first sentence (split on ``. ``) when it fits in ``max_len``;
    otherwise caps at ``max_len`` chars on a WORD boundary.
    Collapses whitespace so a multi-paragraph description still produces a
    single-line title, keeping Markdown headings readable in TOC panes.
    """
    if not text:
        return "untitled finding"
    flat = " ".join(text.split())
    period_idx = flat.find(". ")
    if 30 <= period_idx <= max_len:
        head = flat[: period_idx + 1]
    elif len(flat) <= max_len:
        head = flat
    else:
        # back up to the last word boundary within max_len so we don't cut a
        # word in half (unless the first word itself is longer than max_len).
        head = flat[:max_len]
        boundary = head.rsplit(" ", 1)[0]
        if boundary:
            head = boundary
    if len(head) < len(flat):
        head = head.rstrip(" .") + "…"
    return head


def _safe_code_fence(text: str) -> str:
    """Return a code-fence delimiter that won't be closed prematurely.

    When ``text`` contains its own triple-backtick fences (common in raw
    LLM responses that themselves quote code), wrapping it in another
    ``\\`\\`\\``` fence ends the outer fence early and corrupts the document.
    Markdown's CommonMark spec allows variable-length fences as long as the
    opening and closing match (or the closer is at least as long).  This
    function returns the smallest backtick run not present in ``text`` (at
    least three backticks).
    """
    if not text:
        return "```"
    longest = max((len(m.group(0)) for m in re.finditer(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _severity_sort_key(f: Finding) -> tuple[int, int, str]:
    """Verified first, then by severity rank, then by file/line."""
    sev = (f.get("severity_verified") or f.get("severity") or "").lower()
    return (
        0 if f.get("verified") else 1,
        _SEVERITY_RANK.get(sev, 99),
        f.get("file", ""),
    )


def _render_header(art: _Artifacts) -> str:
    lines = [
        f"# Team Discussion Report - Acuario session `{art.session_id}`",
        "",
        f"**Target:** {art.repo_url or 'local repository'}",
    ]
    if art.cost_summary:
        endpoint = art.cost_summary.get("endpoint_label", "")
        if endpoint:
            lines.append(f"**LLM endpoint:** {endpoint}")
    lines.append("")
    lines.append(
        "This report aggregates every agent's reasoning on every finding "
        "produced by the audit.  Each per-finding section walks through what "
        "the analyzer found, whether the skeptic gate accepted or refuted it, "
        "what the reflective critic added, the 4-axis reviewer's verdict, and "
        "(when `--exploit` was on) the exploit-dev outcome."
    )
    lines.append("")
    return "\n".join(lines)


def _render_pipeline_activity(art: _Artifacts) -> str:
    findings = art.findings
    verified = art.verified_findings
    # Skeptic counts
    skeptic_accept = sum(1 for r in art.skeptic_log.values() if r.get("verdict") == "accepted")
    skeptic_refute = sum(1 for r in art.skeptic_log.values() if r.get("verdict") == "refuted")
    # third bucket - doubted but not refuted (passed through flagged).
    skeptic_uncertain = sum(1 for r in art.skeptic_log.values() if r.get("verdict") == "uncertain")
    if not skeptic_accept and not skeptic_refute and art.skeptic_refuted_fallback:
        skeptic_refute = len(art.skeptic_refuted_fallback)
    # Critic counts
    critic_sessions = len(art.critic_log)
    critic_leads_emitted = sum(len(r.get("leads") or []) for r in art.critic_log)
    critic_verified = sum(1 for f in verified if f.get("discovered_by") == "critic")
    # Orchestrator counts
    orch_plans_total = sum(len(r.get("plans") or []) for r in art.orchestrator_log)
    # Reviewer counts (derived from findings)
    rev_verified = len(verified)
    rev_rejected = len(findings) - len(verified) if findings else 0

    lines = [
        "## 1. Pipeline activity",
        "",
        "| Stage | Sessions | Outcome |",
        "|---|---:|---|",
        f"| Analyzer pool | {len({f.get('file') for f in findings})} files | "
        f"{len(findings)} findings produced |",
        f"| Skeptic gate | {skeptic_accept + skeptic_refute + skeptic_uncertain} | "
        f"{skeptic_accept} accepted · {skeptic_refute} refuted · "
        f"{skeptic_uncertain} uncertain |",
        f"| Reflective critic | {critic_sessions} | "
        f"{critic_leads_emitted} leads emitted ({critic_verified} verified) |",
        f"| Cross-file orchestrator | {len(art.orchestrator_log)} | "
        f"{orch_plans_total} plan(s) emitted |",
        f"| Reviewer (4-axis) | {len(findings)} | "
        f"{rev_verified} verified · {rev_rejected} rejected |",
        f"| Behavior monitor (ptrace) | - | {len(art.behavior_events)} syscall event(s) captured |",
        "",
    ]
    return "\n".join(lines)


def _render_orchestrator_section(art: _Artifacts) -> str:
    if not art.orchestrator_log:
        return ""
    # build a {plan_id → [finding]} index so each plan's section can list
    # the findings the follow-up subsystem hunt actually surfaced.
    # The Finding dataclass routes non-schema fields like
    # ``subsystem_plan_id`` through ``self.extra`` (findings/types.py:253-257).
    # When findings are reloaded from ``findings.json``, those fields land
    # nested under ``extra:`` rather than at the top level, so the plain
    # ``f.get("subsystem_plan_id")`` lookup always returned None.  Check
    # both locations so we pick up the value regardless of whether the
    # finding is a live ``Finding`` instance or a plain JSON-loaded dict.
    findings_by_plan: dict[str, list[Finding]] = {}
    for f in art.findings:
        pid = f.get("subsystem_plan_id") or (f.get("extra") or {}).get("subsystem_plan_id") or ""
        if pid:
            findings_by_plan.setdefault(pid, []).append(f)

    lines = [
        "## 2. Cross-file orchestrator plans",
        "",
        "Each plan represents one cross-file investigation the orchestrator "
        "asked for after seeing the per-file findings, callgraph, and "
        "structural map of the codebase.  Plans are executed (G5) as real "
        "subsystem hunts; emitted findings are tagged (J4) with the plan ID "
        "that asked for them.",
        "",
    ]
    for emission in art.orchestrator_log:
        plans = emission.get("plans") or []
        if not plans:
            continue
        for p in plans:
            pid = p.get("plan_id", "?")
            lines.append(f"### Plan `{pid}` - {p.get('hunt_focus', '?')}")
            lines.append("")
            lines.append(f"**Files:** {', '.join(f'`{f}`' for f in p.get('files', []))}")
            lines.append("")
            rationale = p.get("rationale", "")
            if rationale:
                lines.append(f"**Rationale:** {rationale}")
                lines.append("")
            # surface findings emitted under this plan_id
            plan_findings = findings_by_plan.get(pid, [])
            if plan_findings:
                lines.append(f"**Findings surfaced from this plan ({len(plan_findings)}):**")
                lines.append("")
                for pf in plan_findings:
                    fid = pf.get("id", "?")
                    pfile = pf.get("file", "?")
                    pline = pf.get("line_number", "?")
                    psev = (pf.get("severity_verified") or pf.get("severity", "info")).upper()
                    pdesc = (pf.get("description") or "").strip()
                    status = "✓ verified" if pf.get("verified") else "✗ rejected"
                    lines.append(
                        f"- `{fid}` [{psev}] `{pfile}:{pline}` {status} - {_md_esc(pdesc)}"
                    )
                lines.append("")
            else:
                lines.append(
                    "_No findings surfaced (follow-up hunt produced no new "
                    "verified bugs for this plan)._"
                )
                lines.append("")
        # Orchestrator's reasoning excerpt (one per emission)
        resp_excerpt = emission.get("llm_response_excerpt", "")
        if resp_excerpt:
            lines.append("**Orchestrator LLM reasoning:**")
            lines.append("")
            fence = _safe_code_fence(resp_excerpt)
            lines.append(fence)
            # render full excerpt (already bounded at 8 KB on the write
            # side; no double truncation here).  Variable-length fence
            # prevents nested ``` in the LLM response from closing the
            # outer wrapper.
            lines.append(resp_excerpt)
            lines.append(fence)
            lines.append("")
    return "\n".join(lines)


def _render_finding_debate(
    art: _Artifacts,
    f: Finding,
    trajectories_root: Path | None,
) -> str:
    fid = f.get("id", "?")
    file_path = f.get("file", "?")
    line = f.get("line_number", "?")
    cwe = f.get("cwe", "?")
    sev = (f.get("severity_verified") or f.get("severity") or "info").upper()
    desc = (f.get("description") or "").strip()
    evidence = f.get("evidence_level", "?")
    verified = bool(f.get("verified"))
    discovered_by = f.get("discovered_by", "analyzer")

    status_tag = "✓ verified" if verified else "✗ rejected/refuted"
    # Heading carries a SHORT title (first sentence or ~120 chars).  Long
    # multi-paragraph descriptions dumped into a heading crowded the
    # navigation pane and pushed every metadata bullet off-screen.  The
    # full description still appears verbatim in the body below.
    short_title = _short_title(desc)
    lines = [
        f"### Finding `{fid}` - {_md_esc(short_title)}",
        "",
        f"- **File:** `{file_path}:{line}`",
        f"- **CWE / severity:** {cwe} · {sev}",
        f"- **Evidence level:** `{evidence}`",
        f"- **Status:** {status_tag}",
        f"- **Discovered by:** `{discovered_by}`",
        "",
    ]
    # Full description as a paragraph.
    if desc:
        lines.append("**Description:**")
        lines.append("")
        lines.append(desc)
        lines.append("")

    # --- Analyzer trajectory section --------------------------------------
    # pass the Artifacts instance so the per-session trajectory index is
    # built once and reused across all findings.
    traj = _load_analyzer_trajectory(art, file_path, trajectories_root)
    lines.append("#### Analyzer (engaged)")
    lines.append("")
    if discovered_by == "critic":
        lines.append(
            "_This finding originated from the reflective critic, not the "
            "primary analyzer.  See the Critic section below._"
        )
        lines.append("")
    elif traj:
        thoughts = _top_analyzer_thoughts(traj)
        if thoughts:
            # J2 refinement: render every non-empty thought from the
            # trajectory.  Long trajectories (60+ steps) wrap in a
            # collapsed <details> block so the report stays scannable
            # while still containing the full analyzer reasoning chain.
            collapsible = len(thoughts) > 5
            if collapsible:
                lines.append(
                    f"<details><summary><b>Analyzer reasoning chain "
                    f"({len(thoughts)} thoughts, click to expand)</b></summary>"
                )
                lines.append("")
            else:
                lines.append(
                    f"**Analyzer reasoning chain ({len(thoughts)} thought"
                    f"{'s' if len(thoughts) != 1 else ''}):**"
                )
                lines.append("")
            for i, t in enumerate(thoughts, start=1):
                lines.append(f"**Thought {i}:**")
                lines.append("")
                # Render the thought as plain paragraphs.  The earlier
                # `> tline` per-line blockquote prefixed every paragraph
                # break with a lonely `> ` marker, which read as visual
                # static.  The `<details>` block already provides clear
                # visual containment for the whole reasoning chain.
                lines.append(t.strip())
                lines.append("")
            if collapsible:
                lines.append("</details>")
                lines.append("")
        else:
            lines.append("_Trajectory exists but no thought records were extractable._")
            lines.append("")
    else:
        lines.append("_No analyzer trajectory found on disk for this file._")
        lines.append("")

    # --- Skeptic section --------------------------------------------------
    lines.append("#### Skeptic")
    lines.append("")
    skeptic_rec = art.skeptic_log.get(fid)
    if skeptic_rec is None:
        skeptic_rec = art.skeptic_refuted_fallback.get(fid)
    if skeptic_rec:
        verdict = skeptic_rec.get("verdict") or (
            "refuted" if fid in art.skeptic_refuted_fallback else "?"
        )
        # three-way verdict - accepted / refuted / uncertain (passed
        # through with an unrefuted-doubt flag).
        glyph = {
            "accepted": "✓ accepted",
            "refuted": "✗ refuted",
            "uncertain": "~ uncertain (doubt, no code-cited refutation)",
        }.get(verdict, f"? {verdict}")
        conf = skeptic_rec.get("confidence")
        if conf is not None:
            glyph += f" · confidence {conf}"
        cfc_used = skeptic_rec.get("cross_file_context_used", False)
        lines.append(f"- **Verdict:** {glyph}")
        lines.append(f"- **Cross-file context shown:** {'yes' if cfc_used else 'no (legacy run)'}")
        reasoning = skeptic_rec.get("reasoning") or skeptic_rec.get("skeptic_reasoning", "")
        if reasoning:
            lines.append("- **Reasoning:**")
            lines.append("")
            # Multi-line reasoning: emit each line as its own blockquote so
            # paragraph breaks render correctly.  A single ``> reasoning``
            # over a multi-paragraph string collapses every newline and
            # leaves orphaned ``> `` markers between blocks.
            for rline in reasoning.split("\n"):
                lines.append(f"> {rline}" if rline.strip() else ">")
            lines.append("")
        resp = skeptic_rec.get("llm_response_excerpt", "")
        if resp:
            lines.append("<details><summary>Raw LLM response</summary>")
            lines.append("")
            fence = _safe_code_fence(resp)
            lines.append(fence)
            # render full skeptic response (already 8 KB-bounded on write).
            # Variable-length fence prevents nested ``` from breaking out.
            lines.append(resp)
            lines.append(fence)
            lines.append("</details>")
            lines.append("")
    else:
        lines.append("_No skeptic record (older run before G1a, or skeptic gate disabled)._")
        lines.append("")

    # --- Debate section (O2) ---------------------------------------------
    debate_rec = art.debate_log.get(fid)
    if debate_rec:
        outcome = (
            "overturned → finding reinstated"
            if debate_rec.get("reinstated")
            else ("analyst conceded" if debate_rec.get("conceded") else "refutation upheld")
        )
        lines.append("#### Debate (analyst rebuttal)")
        lines.append("")
        lines.append(f"- **Outcome:** {outcome}")
        if debate_rec.get("rebuttal"):
            lines.append(f"- **Analyst rebuttal:** {debate_rec['rebuttal']}")
        if debate_rec.get("reasoning"):
            lines.append(f"- **Skeptic final reasoning:** {debate_rec['reasoning']}")
        lines.append("")

    # --- Critic section ---------------------------------------------------
    if discovered_by == "critic":
        # Look up the critic_log entry that emitted this lead.  Match by file_path.
        critic_entry = None
        for rec in art.critic_log:
            if rec.get("file_path") == file_path:
                critic_entry = rec
                break
        lines.append("#### Critic (origin)")
        lines.append("")
        if critic_entry is not None:
            lines.append(
                f"- **Reflection on:** `{critic_entry.get('file_path')}` "
                f"({critic_entry.get('existing_findings_count', 0)} prior findings)"
            )
            lines.append(
                "- **Cross-file context used:** "
                f"{'yes' if critic_entry.get('cross_file_context_used') else 'no'}"
            )
            resp = critic_entry.get("llm_response_excerpt", "")
            if resp:
                lines.append("- **Critic LLM response:**")
                lines.append("")
                fence = _safe_code_fence(resp)
                lines.append(fence)
                # render full critic response.  Variable-length fence
                # prevents nested ``` from closing the outer wrapper.
                lines.append(resp)
                lines.append(fence)
                lines.append("")

    # --- Reviewer section -------------------------------------------------
    pro = f.get("verifier_pro_argument") or f.get("validator_pro_argument", "")
    counter = f.get("verifier_counter_argument") or f.get("validator_counter_argument", "")
    axes = f.get("validator_axes") or f.get("verifier_axes") or {}
    if pro or counter or axes:
        lines.append("#### Reviewer (4-axis validator)")
        lines.append("")
        if isinstance(axes, dict) and axes:
            for axis in ("REAL", "TRIGGERABLE", "IMPACTFUL", "GENERAL"):
                ax = axes.get(axis) or axes.get(axis.lower()) or {}
                if isinstance(ax, dict):
                    verdict = "yes" if ax.get("pass") else "no"
                    reasoning = (ax.get("reasoning") or "").strip()
                    lines.append(f"- **{axis}:** {verdict} - {reasoning}")
            lines.append("")
        if pro:
            lines.append(f"- **Pro argument:** {pro}")
            lines.append("")
        if counter:
            lines.append(f"- **Counter argument:** {counter}")
            lines.append("")

    # --- Exploit-dev section ---------------------------------------------
    exploit = _load_exploit_transcript(art.session_dir, fid)
    if exploit:
        lines.append("#### Exploit-dev")
        lines.append("")
        lines.append(
            f"- **Outcome:** {'✓ success' if exploit.get('success') else '✗ failed/partial'}"
        )
        impact = exploit.get("impact", "")
        if impact:
            lines.append(f"- **Impact:** {impact}")
        primitive = exploit.get("primitive_type", "")
        if primitive:
            lines.append(f"- **Primitive:** {primitive}")
        # render full exploit notes + PoC.  The exploit transcript is
        # already bounded by the agent's max_steps and tool budget, so the
        # values here are inherently size-limited at the source.
        notes = exploit.get("notes") or ""
        if notes:
            lines.append(f"- **Notes:** {notes}")
        exploit_code = exploit.get("exploit_code", "")
        if exploit_code:
            lines.append("- **PoC:**")
            lines.append("")
            code_str = str(exploit_code)
            fence = _safe_code_fence(code_str)
            lines.append(fence)
            lines.append(code_str)
            lines.append(fence)
        lines.append("")

    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _render_per_finding_debate(
    art: _Artifacts,
    trajectories_root: Path | None,
) -> str:
    if not art.findings:
        return "## 3. Per-finding debate\n\n_No findings in this session._\n"
    sorted_findings = sorted(art.findings, key=_severity_sort_key)
    lines = [
        "## 3. Per-finding debate",
        "",
        f"Showing all {len(sorted_findings)} finding(s) from the analyzer pool, "
        "sorted by verified-first then severity.  Verified findings carry the "
        "reviewer's 4-axis verdict; refuted findings carry the skeptic's "
        "reasoning instead.",
        "",
    ]
    for f in sorted_findings:
        lines.append(_render_finding_debate(art, f, trajectories_root))
    return "\n".join(lines)


def _render_refuted_appendix(art: _Artifacts) -> str:
    if not art.skeptic_log and not art.skeptic_refuted_fallback:
        return ""
    refuted_recs: list[dict] = []
    for rec in art.skeptic_log.values():
        if rec.get("verdict") == "refuted":
            refuted_recs.append(rec)
    if not refuted_recs:
        for rec in art.skeptic_refuted_fallback.values():
            refuted_recs.append({**rec, "verdict": "refuted"})
    if not refuted_recs:
        return ""
    # J2 (refined): switched from a Markdown table to a bulleted list so
    # each refuted finding's full skeptic reasoning renders without a
    # cell-size cap.  Markdown tables forbid newlines and unescaped pipes
    # in cells - the bulleted form has no such constraint.
    lines = [
        "## 4. Refuted findings appendix",
        "",
        f"The skeptic gate refuted {len(refuted_recs)} finding(s).  Each "
        "entry shows the finding's identity and the skeptic's complete "
        "refutation reasoning.",
        "",
    ]
    for rec in refuted_recs:
        fid = rec.get("finding_id", "?")
        file_path = rec.get("file", "?")
        line = rec.get("line_number", "?")
        cwe = rec.get("cwe", "?")
        reasoning = rec.get("reasoning") or rec.get("skeptic_reasoning") or ""
        lines.append(f"- **`{fid}`** - `{file_path}:{line}` ({cwe}) - refuted by skeptic")
        if reasoning:
            # Indent each line of the reasoning so it renders as a
            # continuation of the bullet rather than starting a new one.
            for rline in reasoning.split("\n"):
                lines.append(f"  > {rline}")
            lines.append("")
    lines.append("")
    return "\n".join(lines)


def _render_behavior_section(art: _Artifacts) -> str:
    if not art.behavior_events:
        return ""
    counts = Counter(ev.get("syscall", "?") for ev in art.behavior_events)
    by_severity = Counter(ev.get("severity", "?") for ev in art.behavior_events)
    lines = [
        "## 5. Behavior monitor (ptrace)",
        "",
        f"The real-time ptrace monitor captured {len(art.behavior_events)} "
        "syscall event(s) during sandboxed exploit attempts.",
        "",
        "**By syscall:** " + ", ".join(f"`{k}`×{v}" for k, v in counts.most_common(10)),
        "",
        "**By severity:** " + ", ".join(f"`{k}`×{v}" for k, v in by_severity.most_common()),
        "",
    ]
    # every captured event is kept, but rendered as ONE fenced code block
    # inside a collapsed <details> rather than a Markdown table. A large ptrace
    # capture is tens of thousands of rows; as a table it makes the whole
    # document hang/buffer in most viewers (each row is parsed into cells). A
    # code block is monospace, needs no per-cell parsing, and the <details>
    # wrapper keeps the section collapsed so the page loads fast and the reader
    # expands the raw trace only on demand. No rows are dropped; the path/arg
    # keeps a 200-char cap so one long argument doesn't bloat a line.
    lines.append(
        f"<details><summary>All {len(art.behavior_events)} syscall events "
        "(click to expand)</summary>"
    )
    lines.append("")
    lines.append("```text")
    for ev in art.behavior_events:
        ts = str(ev.get("timestamp", "?"))
        sev = str(ev.get("severity", "?"))
        sc = str(ev.get("syscall", "?"))
        arg = (ev.get("path") or ev.get("arg") or "").replace("\n", " ")[:200]
        arg = arg.replace("```", "'''")  # never let an arg close the fence
        lines.append(f"{ts}  {sev:<8} {sc:<18} {arg}")
    lines.append("```")
    lines.append("")
    lines.append("</details>")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def write_team_discussion_report(
    session_dir: str | Path,
    *,
    trajectories_root: Path | None = None,
) -> Path:
    """Render team_discussion.md for the given audit session.

    Parameters
    ----------
    session_dir : str | Path
        Path to ``results/scanner/<session-id>/`` - must contain at least
        ``findings.json``.  Missing G1 logs (skeptic / critic / orchestrator)
        are tolerated: the report degrades gracefully and notes the absence.
    trajectories_root : Path | None
        Override the default location of analyzer ReAct trajectories
        (defaults to ``~/.acuario/scanner/trajectories``).

    Returns
    -------
    Path
        Filesystem path of the written ``team_discussion.md``.
    """
    session_dir = Path(session_dir)
    if not session_dir.is_dir():
        raise FileNotFoundError(f"session dir not found: {session_dir}")

    art = _load_artifacts(session_dir)

    sections = [
        _render_header(art),
        _render_pipeline_activity(art),
        _render_orchestrator_section(art),
        _render_per_finding_debate(art, trajectories_root),
        _render_refuted_appendix(art),
        _render_behavior_section(art),
    ]
    # Drop empty sections so the table of contents stays clean.
    body = "\n\n".join(s for s in sections if s and s.strip())

    out = session_dir / "team_discussion.md"
    out.write_text(body + "\n", encoding="utf-8")
    return out
