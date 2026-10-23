"""Pipeline-aware narration layer for Acuario audit runs.

This module owns the run-surface vocabulary - it formats what the user sees
during and after an audit.  Two output channels:

- **Console (Rich)**: run-start header box, stage banners, end-of-run summary.
  These are printed via ``rich.console.Console``; they never reach ``audit.log``.

- **audit.log file**: a ``NarrationFormatter`` that converts
  ``logging`` records to the ``[stage] glyph message`` vocabulary.
  One event per line, grep-friendly.

Design rules
------------
- The narrator does *not* replace the logger.  Pipeline modules emit
  ``logger.info(...)`` as before; the ``NarrationFormatter`` transforms the
  text at the handler level.  Stage prefixes already added by lab agents
  (``[skeptic]``, ``[critic]``, etc.) pass through unchanged.
- Multi-line banners and summary blocks are console-only; ``audit.log``
  contains only single-line ``[stage] glyph message`` lines.
- No LLM calls; no I/O beyond ``sys.stdout`` and the log file.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from rich.text import Text

from acuario.observability.telemetry import CostTracker
from acuario.ui.theme import (
    GLYPH_ACCEPT,
    GLYPH_ALERT,
    GLYPH_COMPLETE,
    GLYPH_ENGAGE,
    GLYPH_EVENT,
    GLYPH_REFUTE,
    GLYPH_SNAP,
    SEVERITIES,
    SEVERITY_ORDER,
    escape,
    kv_table,
    normalize_severity,
    section_rule,
    severity_badge,
    supports_unicode,
)

# ---------------------------------------------------------------------------
# Stage vocabulary
# ---------------------------------------------------------------------------

# Maps logger-name fragment / message prefix → stage prefix for log output.
STAGE_PREFIXES: dict[str, str] = {
    "acuario.preprocess": "preprocess",
    "acuario.prioritize": "prioritize",
    "acuario.analyze": "analyze",
    "acuario.skeptic": "skeptic",
    "acuario.critic": "critic",
    "acuario.orchestrate": "orchestrate",
    "acuario.review": "review",
    "acuario.variant": "variant",
    "acuario.report": "report",
    "acuario.lab.sandbox": "lab/sandbox",
    # The regex behavior monitor (acuario/scanner/behavior_monitor.py)
    # scans agent transcripts for suspicious strings - NOT real syscalls.
    # Label its alerts [behavior] so users don't mistake them for actual
    # ptrace/strace kernel-level observations (which come from
    # acuario.lab.sandbox.behavior, prefixed [ptrace]).
    "acuario.scanner.behavior_monitor": "behavior",
    "acuario.scanner.mechanism_memory": "recall",
    "acuario.scanner.callgraph": "context",
}

# Glyphs used in log output come from acuario.ui.theme (imported above), the
# single source of truth, so the log-narration vocabulary and the themed console
# surface never drift.  They stay importable as
# `from acuario.ui.narration import GLYPH_*` for backward compatibility.

# Stage banner displayed on the console when the active stage changes.
_BANNER_WIDTH = 66
_STAGE_ORDER = [
    "preprocess",
    "prioritize",
    "analyze",
    "skeptic",
    "review",
    "orchestrate",
    "variant",
    "report",
]

# ---------------------------------------------------------------------------
# Message transformation rules
# ---------------------------------------------------------------------------

# Each rule is (compiled_regex, replacement_template) or callable.
# Applied in order against the raw log message.
_TRANSFORM_RULES: list[tuple] = [
    # Preprocessor
    (
        re.compile(r"Preprocessor(?:: )?enum\w+\s+(\d+)\s+files?", re.I),
        r"[preprocess] " + GLYPH_EVENT + r" enumerated \1 source files",
    ),
    (
        re.compile(r"Preprocessor\b.*enumerating", re.I),
        "[preprocess] " + GLYPH_EVENT + " enumerating source files",
    ),
    # Prioritizer
    (
        re.compile(r"Prioritizer chunk (\d+)/(\d+) completed in ([\d.]+)s", re.I),
        r"[prioritize] " + GLYPH_EVENT + r" ranked files (chunk \1/\2, \3s)",
    ),
    (
        re.compile(r"Prioritizer start\w+ on (\d+) files?", re.I),
        r"[prioritize] " + GLYPH_EVENT + r" scoring \1 files",
    ),
    (
        re.compile(r"Prioritizer completed", re.I),
        "[prioritize] " + GLYPH_EVENT + " scoring complete",
    ),
    # Analyzer dispatch / complete (HunterPool style)
    (re.compile(r"Analyzer start\w+ for (.+)", re.I), r"[analyze] " + GLYPH_ENGAGE + r" engage \1"),
    (
        re.compile(r"Analyzer finish\w* for (.+?) after (\d+) steps findings=(\d+)", re.I),
        r"[analyze] " + GLYPH_COMPLETE + r" \1 → \3 findings in \2 steps",
    ),
    (
        re.compile(r"Analyzer pool start\w+ on (\d+) files?", re.I),
        r"[analyze] " + GLYPH_EVENT + r" pool dispatching \1 investigations",
    ),
    (
        re.compile(r"Analyzer pool completed with (\d+) findings?", re.I),
        r"[analyze] " + GLYPH_COMPLETE + r" pool complete → \1 findings",
    ),
    # Reviewer / verifier
    (
        re.compile(r"Verified (\d+)/(\d+): ([\w-]+) \(verified=True\)", re.I),
        r"[review] " + GLYPH_ACCEPT + r" \3 (\1/\2)",
    ),
    (
        re.compile(r"Verified (\d+)/(\d+): ([\w-]+) \(verified=False\)", re.I),
        r"[review] " + GLYPH_REFUTE + r" \3 (\1/\2) insufficient evidence",
    ),
    # Behavior monitor (legacy regex → ptrace vocab)
    # Regex behavior monitor alerts get the [behavior] prefix.  Real
    # syscall-level events (when the ptrace monitor manages to capture
    # them) emit [ptrace] separately, so the two streams stay distinct.
    (
        re.compile(r"Behavior alert \[(critical|warning)\]: (.+)", re.I),
        r"[behavior] " + GLYPH_ALERT + r" \2 [\1]",
    ),
    # Mechanism recall
    (re.compile(r"\[recall\]", re.I), None),  # already formatted - pass through
    # Cross-file context
    (re.compile(r"\[context\]", re.I), None),  # already formatted - pass through
    # Lab agents - already use [skeptic], [critic], [orchestrate], [lab/sandbox]
    # [behavior] added so the regex monitor's already-formatted alerts
    # pass through unchanged (and aren't re-tagged as [ptrace]).
    (
        re.compile(
            r"^\[(skeptic|critic|orchestrate|lab/sandbox|ptrace|behavior|review|analyze|prioritize|preprocess|recall|context|variant|report|audit|sandbox)\]"
        ),
        None,
    ),  # pass through unchanged
]


def _transform_message(record: logging.LogRecord) -> str:
    """Apply vocabulary transforms to a log record's message.

    Already-formatted messages (those whose text starts with ``[stage]``)
    pass through unchanged.  Everything else gets pattern-matched.
    """
    msg = record.getMessage()

    # Detect already-formatted stage prefix → pass through
    if re.match(r"^\[[\w/:.]+\]", msg):
        return msg

    # Try transformation rules
    for pattern, replacement in _TRANSFORM_RULES:
        if replacement is None:
            # pass-through sentinel - only reached if the regex matched
            if pattern.search(msg):
                return msg
            continue
        new_msg = pattern.sub(replacement, msg, count=1)
        if new_msg != msg:
            return new_msg

    # Fallback: derive a stage prefix from the logger name
    stage = _stage_from_logger(record.name)
    if stage:
        return f"[{stage}] {GLYPH_EVENT} {msg}"

    return msg


def _stage_from_logger(logger_name: str) -> str:
    """Map a logger name to its stage prefix."""
    for key, stage in STAGE_PREFIXES.items():
        if logger_name.startswith(key):
            return stage
    return ""


# ---------------------------------------------------------------------------
# Helpers - stage extraction + ANSI coloring
# ---------------------------------------------------------------------------


# Match the bracketed stage prefix at the start of a transformed message.
# Captures the FULL stage identifier including any sub-tier (e.g.
# "analyze:surface", "lab/sandbox").
_STAGE_PREFIX_RE = re.compile(r"^\[([\w/:.]+)\]")


def _extract_top_stage(msg: str) -> str:
    """Return the top-level stage from a ``[stage] ...`` message.

    Strips any sub-tier so ``[analyze:surface]`` and ``[analyze:depth]``
    both return ``"analyze"`` - used for banner deduplication when the
    same major phase runs across multiple files.  Returns an empty
    string when the message has no recognizable stage prefix.
    """
    m = _STAGE_PREFIX_RE.match(msg)
    if not m:
        return ""
    return m.group(1).split(":", 1)[0].split("/", 1)[0]


def _extract_full_stage(msg: str) -> str:
    """Return the full stage identifier including any sub-tier."""
    m = _STAGE_PREFIX_RE.match(msg)
    if not m:
        return ""
    return m.group(1)


# ANSI escape codes - bare 8-color for broad terminal compatibility.
# Bright variants would render fine in modern terminals but the dim
# variants we use stay readable on both light and dark themes.
_ANSI_RESET = "\x1b[0m"
_ANSI_DIM = "\x1b[2m"
_ANSI_BOLD = "\x1b[1m"
_ANSI_RED = "\x1b[31m"
_ANSI_GREEN = "\x1b[32m"
_ANSI_YELLOW = "\x1b[33m"
_ANSI_BLUE = "\x1b[34m"
_ANSI_MAGENTA = "\x1b[35m"
_ANSI_CYAN = "\x1b[36m"
_ANSI_DIM_CYAN = "\x1b[2;36m"

# Stage prefix → ANSI color.  Most stages share dim cyan so the eye picks
# out the few semantically distinct ones (skeptic/critic/review/lab).
_STAGE_COLORS: dict[str, str] = {
    "analyze": _ANSI_DIM_CYAN,
    "preprocess": _ANSI_DIM_CYAN,
    "prioritize": _ANSI_DIM_CYAN,
    "recall": _ANSI_DIM_CYAN,
    "context": _ANSI_DIM_CYAN,
    "variant": _ANSI_DIM_CYAN,
    "report": _ANSI_DIM_CYAN,
    "sandbox": _ANSI_DIM_CYAN,
    "audit": _ANSI_DIM_CYAN,
    "skeptic": _ANSI_MAGENTA,
    "orchestrate": _ANSI_MAGENTA,
    "critic": _ANSI_BLUE,
    "review": _ANSI_BLUE,
    "lab/sandbox": _ANSI_YELLOW,
    "ptrace": _ANSI_YELLOW,
}

# Glyph → ANSI color (semantic meaning).
_GLYPH_COLORS: dict[str, str] = {
    GLYPH_ENGAGE: _ANSI_CYAN,  # ◐ engage
    GLYPH_COMPLETE: _ANSI_GREEN,  # ● complete
    GLYPH_ACCEPT: _ANSI_GREEN,  # ✓ accept
    GLYPH_REFUTE: _ANSI_RED,  # ✗ refute
    GLYPH_EVENT: _ANSI_DIM,  # ▸ event
    GLYPH_SNAP: _ANSI_MAGENTA,  # ◇ checkpoint
    GLYPH_ALERT: _ANSI_YELLOW,  # ⚠ alert
}


def _ansi_dim(text: str) -> str:
    return f"{_ANSI_DIM}{text}{_ANSI_RESET}"


def _colorize_message(msg: str) -> str:
    """Wrap stage prefix and known glyphs in ANSI escape codes.

    Returns the message unchanged when it lacks a recognizable stage
    prefix - every operation is best-effort and never raises.
    """
    # Color the [stage] prefix.
    m = _STAGE_PREFIX_RE.match(msg)
    if m:
        full_stage = m.group(1)
        # Look up by full stage first (so "lab/sandbox" wins over "lab"),
        # then by the top-level stage (so "analyze:surface" picks up the
        # "analyze" color).
        color = _STAGE_COLORS.get(full_stage)
        if color is None:
            top = full_stage.split(":", 1)[0].split("/", 1)[0]
            color = _STAGE_COLORS.get(top, _ANSI_DIM_CYAN)
        bracketed = m.group(0)
        msg = f"{color}{bracketed}{_ANSI_RESET}" + msg[len(bracketed) :]
    # Color the FIRST occurrence of each known glyph.  Skip duplicate
    # passes - the glyphs typically appear once per line.
    for glyph, color in _GLYPH_COLORS.items():
        if glyph in msg:
            msg = msg.replace(glyph, f"{color}{glyph}{_ANSI_RESET}", 1)
    return msg


# ---------------------------------------------------------------------------
# NarrationFormatter
# ---------------------------------------------------------------------------


class NarrationFormatter(logging.Formatter):
    """Formats log records as ``[stage] glyph message`` for audit.log.

    Replaces the default ``%(levelname)s: %(message)s`` format.
    One event per line; no multi-line output; ASCII-safe fallback when the
    terminal / file encoding doesn't support Unicode glyphs.

    Parameters
    ----------
    ascii_fallback : bool
        Replace Unicode glyphs with ASCII equivalents.
    show_level_for_warnings : bool
        When True (default for console handlers), prepend ``WARNING:`` /
        ``ERROR:`` for records at WARNING level or above so they stand out
        in the stream.  File handlers set this False for clean grep output.
    colorize : bool
        Wrap stage prefixes and glyphs in ANSI escape codes so
        a TTY reader can scan ✓/✗ verdicts and stage transitions at a
        glance.  Always False for file handlers (ANSI codes pollute
        ``audit.log``).  Auto-disabled when ``NO_COLOR`` is set in the
        environment.
    banner_on_stage_change : bool
        When the ``[stage]`` prefix of the message differs from
        the previous record, prepend a thin ``── stage ──...`` separator
        line so the eye snaps to phase transitions.  Console-only.
    indent_auxiliary_stages : bool
        Indent ``[recall]`` and ``[context]`` lines with two
        spaces so they read as nested under the preceding ``◐ engage``
        line.  Console-only (file handler keeps every line at column 0
        for grep-friendliness).
    """

    _FMT = "%(message)s"
    # Stages whose lines get a 2-space indent on the console - they're
    # auxiliary pre-seeding events that "belong to" an analyzer engage.
    _AUXILIARY_STAGES = frozenset({"recall", "context"})

    def __init__(
        self,
        *,
        ascii_fallback: bool = False,
        show_level_for_warnings: bool = True,
        colorize: bool = False,
        banner_on_stage_change: bool = False,
        indent_auxiliary_stages: bool = False,
    ):
        super().__init__(fmt=self._FMT)
        self._ascii = ascii_fallback
        self._show_level = show_level_for_warnings
        # Color is disabled automatically when NO_COLOR is set
        # (https://no-color.org/) so users who opted out get plain text.
        import os

        self._colorize = colorize and not os.environ.get("NO_COLOR")
        self._banner_on_stage_change = banner_on_stage_change
        self._indent_auxiliary = indent_auxiliary_stages
        self._last_stage: str = ""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        msg = _transform_message(record)
        if self._ascii:
            for glyph, ascii_eq in [
                (GLYPH_ENGAGE, "(engage)"),
                (GLYPH_COMPLETE, "(done)"),
                (GLYPH_ACCEPT, "(ok)"),
                (GLYPH_REFUTE, "(no)"),
                (GLYPH_EVENT, ">"),
                (GLYPH_SNAP, "(snap)"),
                (GLYPH_ALERT, "(!)"),
            ]:
                msg = msg.replace(glyph, ascii_eq)

        # Apply indent BEFORE coloring so the indent isn't
        # bracketed by ANSI codes (which would push it to non-zero column
        # in the byte stream and break visual alignment).
        stage = _extract_top_stage(msg)
        sub_stage = _extract_full_stage(msg)
        if self._indent_auxiliary and sub_stage in self._AUXILIARY_STAGES:
            msg = "  " + msg

        # Stage banner emission.  Track the top-level stage
        # (analyze:surface and analyze:depth both group under "analyze").
        # Auxiliary stages (`recall`, `context`) are intentionally NESTED
        # under their parent analyze line, so they must NOT trigger banners
        # and must NOT update _last_stage (otherwise the next analyze line
        # would re-banner unnecessarily).
        banner_prefix = ""
        is_auxiliary = sub_stage in self._AUXILIARY_STAGES
        if self._banner_on_stage_change and stage and not is_auxiliary:
            if stage != self._last_stage:
                if self._last_stage:
                    # Skip the banner before the first stage so the run-start
                    # header sits directly above the first line of work.
                    if self._colorize:
                        banner_prefix = _ansi_dim(f"\n── {stage} " + "─" * 30 + "\n")
                    else:
                        bar = "─" * 30
                        banner_prefix = f"\n── {stage} {bar}\n"
                self._last_stage = stage

        # ANSI color injection.
        if self._colorize:
            msg = _colorize_message(msg)

        if self._show_level and record.levelno >= logging.WARNING:
            return f"{banner_prefix}{record.levelname}: {msg}"
        return f"{banner_prefix}{msg}"


# ---------------------------------------------------------------------------
# AuditNarrator
# ---------------------------------------------------------------------------


@dataclass
class LabStats:
    skeptic_accepted: int = 0
    skeptic_refuted: int = 0
    critic_leads: int = 0
    critic_verified: int = 0
    orchestrator_plans: int = 0
    orchestrator_findings: int = 0
    snapshot_cycles: int = 0
    ptrace_events: int = 0


class AuditNarrator:
    """Owns all human-facing console output for an audit run.

    Parameters
    ----------
    console : rich.console.Console
        The Rich console to write to.  Imported lazily so callers without
        Rich can still instantiate this class.
    """

    def __init__(self, console: Any) -> None:
        self.console = console
        self._current_stage: str = ""

    # ------------------------------------------------------------------
    # Run-start header
    # ------------------------------------------------------------------

    def print_header(
        self,
        *,
        session_id: str,
        target: str,
        depth: str,
        endpoint_label: str = "unknown",
        budget_label: str = "unlimited",
        lab_flags: dict[str, bool] | None = None,
    ) -> None:
        """Print the structured run-start header box to the console.

        Uses ``rich.panel.Panel`` for the header.  The panel
        auto-fits its width to the longest content line and renders aligned
        rounded corners across all UTF-8 terminals.
        """
        lab = lab_flags or {}
        skeptic_flag = "ON" if lab.get("skeptic", True) else "OFF"
        critic_flag = "ON" if lab.get("critic", True) else "OFF"
        orch_flag = "ON" if lab.get("orchestrator", True) else "OFF"
        snap_flag = "ON" if lab.get("sandbox_snapshots", True) else "OFF"
        ptrace_flag = "ON" if lab.get("ptrace_monitor", True) else "OFF"

        # Truncate values that would push the panel wider than ~80 cols.
        target_short = (target[:62] + "…") if len(target) > 63 else target
        ep_short = (endpoint_label[:62] + "…") if len(endpoint_label) > 63 else endpoint_label

        # escape(): target + endpoint are free text (a repo path /repo/[x]/app or
        # an IPv6 endpoint http://[::1]:11434 would otherwise be parsed as markup
        # and crash the run header).
        body_lines = [
            f"[bold]target[/bold]    {escape(target_short)}",
            f"[bold]depth[/bold]     {depth:<14}  [bold]budget[/bold] {budget_label}",
            f"[bold]endpoint[/bold]  {escape(ep_short)}",
            "[bold]pipeline[/bold]  preprocess → prioritize → analyze →",
            # \[ escapes the bracket so the [skeptic]/[orchestrate] labels render
            # literally instead of being parsed (and eaten) as Rich markup tags.
            r"          \[skeptic] → review → \[orchestrate] → variant → report",
            f"[bold]lab[/bold]       skeptic [cyan]{skeptic_flag}[/cyan] · "
            f"critic [cyan]{critic_flag}[/cyan] · "
            f"orchestrator [cyan]{orch_flag}[/cyan]",
            f"          sandbox-snapshots [cyan]{snap_flag}[/cyan] · "
            f"ptrace-monitor [cyan]{ptrace_flag}[/cyan]",
        ]

        try:
            from rich.box import ROUNDED
            from rich.panel import Panel

            self.console.print()  # blank line before header
            self.console.print(
                Panel(
                    "\n".join(body_lines),
                    title=f"[bold]Acuario · session {escape(str(session_id))}[/bold]",
                    title_align="left",
                    border_style="cyan",
                    box=ROUNDED,
                    padding=(0, 1),
                    expand=False,
                )
            )
            self.console.print()  # blank line after header
        except Exception:
            # Fallback: plain text header for environments without Rich.
            self.console.print(f"\n=== Acuario · session {session_id} ===")
            for line in body_lines:
                # Strip Rich markup tags for the fallback path
                stripped = re.sub(r"\[/?[a-zA-Z][^\]]*\]", "", line)
                self.console.print(f"  {stripped}")
            self.console.print()

    # ------------------------------------------------------------------
    # Stage banners (console-only)
    # ------------------------------------------------------------------

    def stage_banner(self, stage: str) -> None:
        """Print a stage-transition banner to the console.

        Banners are NOT written to audit.log (console-only per plan spec).
        """
        if stage == self._current_stage:
            return
        self._current_stage = stage
        bar = "═" * ((_BANNER_WIDTH - len(stage) - 10) // 2)
        self.console.print(escape(f"\n{bar} stage: {stage} {bar}"), style="muted")

    # ------------------------------------------------------------------
    # End-of-run summary
    # ------------------------------------------------------------------

    def print_summary(
        self,
        *,
        result: Any,
        log_file_path: str = "",
        lab_stats: LabStats | None = None,
    ) -> None:
        """Print the structured end-of-run summary in labeled blocks."""
        lab = lab_stats or LabStats()
        sid = result.session_id
        dur = _format_duration(result.duration_seconds)

        self.console.print()
        self.console.print(section_rule(f"Audit complete · {sid} · {dur}"))

        # Severity-ramp strip (E26): one compact, CVD-safe line summarising the
        # run's findings across the full SEVERITY_ORDER (shape + count per rung,
        # each in its severity style), printed near the top so the headline risk
        # picture reads before the detail blocks.  ASCII-folds on a non-UTF-8
        # stream; omitted entirely when there are no findings.
        strip = _severity_ramp(getattr(result, "findings", None), console=self.console)
        if strip is not None:
            self.console.print()
            self.console.print(strip)

        # INVESTIGATION block - a borderless key/value readout (kv_table auto-wraps
        # every value in a Text, so nothing here can be markup-parsed).
        findings_val = Text(str(result.unique_finding_count))
        findings_val.append(f"   (verified {result.unique_verified_count})", style="muted")
        # Severity on both bases (total / verified), unique loci, so the readout
        # matches the report's Severity Breakdown table instead of showing a
        # single unlabeled number.  Built from internal counts via styled Text
        # appends (never an f-stringed markup span).
        sev_val = Text()
        sev_val.append(f"{result.total_critical_count} critical", style="sev.critical")
        sev_val.append(" · ")
        sev_val.append(f"{result.total_high_count} high", style="sev.high")
        sev_val.append(
            f"   (verified: {result.critical_count} · {result.high_count})", style="muted"
        )
        self.console.print()
        self.console.print(section_rule("INVESTIGATION"))
        self.console.print(
            kv_table(
                [
                    ("files ranked", str(result.files_ranked)),
                    ("files hunted", str(result.files_hunted)),
                    ("findings", findings_val),
                    ("severity", sev_val),
                ]
            )
        )

        # LAB block (only if any lab activity recorded)
        lab_pairs: list[tuple[str, Any]] = []
        if lab.skeptic_accepted or lab.skeptic_refuted:
            lab_pairs.append(
                (
                    "skeptic gate",
                    f"accepted {lab.skeptic_accepted} · refuted {lab.skeptic_refuted}",
                )
            )
        if lab.critic_leads:
            lab_pairs.append(
                (
                    "critic",
                    f"added {lab.critic_leads} low-confidence leads "
                    f"({lab.critic_verified} verified)",
                )
            )
        if lab.orchestrator_plans:
            lab_pairs.append(
                (
                    "orchestrator",
                    f"emitted {lab.orchestrator_plans} cross-file plans "
                    f"({lab.orchestrator_findings} surfaced findings)",
                )
            )
        if lab.snapshot_cycles or lab.ptrace_events:
            lab_pairs.append(
                (
                    "sandbox",
                    f"{lab.snapshot_cycles} snapshot/rollback cycles · "
                    f"{lab.ptrace_events} ptrace events",
                )
            )
        if lab_pairs:
            self.console.print()
            self.console.print(section_rule("LAB"))
            self.console.print(kv_table(lab_pairs))

        # LLM block
        if result.input_tokens or result.output_tokens:
            total = result.input_tokens + result.output_tokens
            llm_pairs: list[tuple[str, Any]] = []
            if result.endpoint_label:
                # endpoint may be an IPv6 URL http://[::1]:11434; kv_table wraps a
                # plain str value in a Text, so it is auto-escaped (never parsed).
                llm_pairs.append(("endpoint", str(result.endpoint_label)))
            llm_pairs.append(
                (
                    "tokens",
                    f"input {result.input_tokens:,} · output {result.output_tokens:,} "
                    f"(total {total / 1_000_000:.1f}M)",
                )
            )
            if result.is_self_hosted_endpoint:
                cost_val = Text("$0.00", style="success")
                cost_val.append("  (self-hosted)", style="muted")
                llm_pairs.append(("cost paid", cost_val))
                # Same-workload quote against the current frontier lineup,
                # priced from this run's token totals (one source of truth in
                # CostTracker.REFERENCE_MODELS - names never drift from rates).
                quotes = CostTracker.reference_quotes(result.input_tokens, result.output_tokens)
                for i, (label, usd) in enumerate(quotes):
                    llm_pairs.append(
                        ("reference" if i == 0 else "", f"{label:<26}~${usd:,.2f}")
                    )
            else:
                llm_pairs.append(("cost paid", f"${result.cost_usd:.4f}"))
            self.console.print()
            self.console.print(section_rule("LLM"))
            self.console.print(kv_table(llm_pairs))

        # OUTPUTS block - free-text paths stay escaped via escape() (the block's
        # filesystem walk is unchanged; only its header is now a section rule).
        if result.output_paths or log_file_path:
            self.console.print()
            self.console.print(section_rule("OUTPUTS"))
            for fmt, path in (result.output_paths or {}).items():
                self.console.print(f"  {fmt:<10} {escape(str(path))}")
            if log_file_path:
                self.console.print(f"  {'log':<10} {escape(str(log_file_path))}")
            # List each lab artifact that actually exists on disk.
            from pathlib import Path as _Path

            session_dir = None
            for _key in ("markdown", "json", "sarif", "manifest", "team_discussion"):
                p = (result.output_paths or {}).get(_key)
                if p:
                    session_dir = _Path(p).parent
                    break
            if session_dir is not None:
                for fname, gate in (
                    ("skeptic_log.jsonl", True),
                    ("skeptic_refuted.jsonl", bool(lab.skeptic_refuted)),
                    ("critic_log.jsonl", bool(lab.critic_leads)),
                    ("orchestrator_log.jsonl", bool(lab.orchestrator_plans)),
                    ("behavior_events.jsonl", bool(lab.ptrace_events)),
                ):
                    fpath = session_dir / fname
                    if gate and fpath.exists():
                        self.console.print(f"  {'lab':<10} {escape(str(fpath))}")

        # TOP FINDINGS block.  Severity is a CVD-safe badge (shape + LABEL +
        # colour); the file and description are appended as plain Text, so
        # bracketed paths / LLM descriptions render verbatim (never parsed as
        # markup) - the kit-wide replacement for the old hand-built markup.
        if result.findings:
            self.console.print()
            self.console.print(section_rule("TOP FINDINGS"))
            for f in result.findings[:5]:
                sev = f.get("severity_verified") or f.get("severity", "info")
                ffile = str(f.get("file", "?"))
                lineno = f.get("line_number", "?")
                desc = str(f.get("description", "") or "")[:72]
                row = Text("  ")
                row.append_text(severity_badge(sev, width=11, console=self.console))
                row.append("  ")
                row.append(f"{ffile}:{lineno}", style="path")
                row.append("  ")
                row.append(desc)
                self.console.print(row)

        # NEXT block - header unified to a section rule; the command + hint are
        # appended as styled Text so the session id is never markup-parsed.
        self.console.print()
        self.console.print(section_rule("NEXT"))
        nxt = Text("  ")
        nxt.append(f"acuario inspect {sid}", style="accent")
        nxt.append("   # chat with this audit", style="muted")
        self.console.print(nxt)
        self.console.print()

    # ------------------------------------------------------------------
    # Formatter factory
    # ------------------------------------------------------------------

    @staticmethod
    def get_log_formatter(
        *,
        ascii_fallback: bool = False,
        for_file: bool = False,
        colorize: bool | None = None,
        banner_on_stage_change: bool | None = None,
        indent_auxiliary_stages: bool | None = None,
    ) -> NarrationFormatter:
        """Return a NarrationFormatter ready to attach to a logging handler.

        Parameters
        ----------
        ascii_fallback:
            Replace Unicode glyphs with ASCII equivalents.
        for_file:
            When True, suppress the ``WARNING:`` / ``ERROR:`` level prefix so
            ``audit.log`` contains only clean ``[stage] glyph message`` lines.
            When False (default, for the console StreamHandler), WARNING and
            above records get a level prefix so they stand out.
        colorize, banner_on_stage_change, indent_auxiliary_stages:
            Console-side polish.  Each defaults to ``True`` for
            console handlers (``for_file=False``) and ``False`` for file
            handlers, but callers can override either way.  Useful for
            tests that want deterministic output regardless of the
            handler kind.
        """
        # Console-default = True, file-default = False, unless caller pins.
        default_polish = not for_file
        return NarrationFormatter(
            ascii_fallback=ascii_fallback,
            show_level_for_warnings=not for_file,
            colorize=default_polish if colorize is None else colorize,
            banner_on_stage_change=(
                default_polish if banner_on_stage_change is None else banner_on_stage_change
            ),
            indent_auxiliary_stages=(
                default_polish if indent_auxiliary_stages is None else indent_auxiliary_stages
            ),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_ramp(findings: Any, *, console: Any) -> Text | None:
    """Build the compact CVD-safe severity-ramp strip for the run summary (E26).

    Tallies ``findings`` across the full :data:`SEVERITY_ORDER` (skipping
    duplicate loci, exactly as ``ScanResult.unique_finding_count`` does, so the
    strip total matches the INVESTIGATION block) and renders each rung as
    ``shape count`` carried in its ``sev.<key>`` style.  The shape + count +
    colour redundancy means the ramp survives ``NO_COLOR`` / colour-blindness,
    and the shape ASCII-folds (``◆`` → ``!!`` …) on a non-UTF-8 stream.  Returns
    ``None`` when there is nothing to summarise, so the caller can omit the line.
    """
    counts: dict[str, int] = {key: 0 for key in SEVERITY_ORDER}
    for f in findings or []:
        try:
            if f.get("duplicate_of"):
                continue
            counts[normalize_severity(f.get("severity_verified") or f.get("severity"))] += 1
        except Exception:
            continue  # a malformed finding dict never breaks the summary
    if not any(counts.values()):
        return None

    ascii_only = not supports_unicode(console)
    strip = Text("  ")
    strip.append("severity  ", style="muted")
    for i, key in enumerate(SEVERITY_ORDER):
        if i:
            strip.append("   ")
        spec = SEVERITIES[key]
        shape = spec.ascii if ascii_only else spec.glyph
        strip.append(f"{shape} {counts[key]}", style=spec.style)
    return strip


def _format_duration(seconds: float) -> str:
    if seconds >= 3600:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h}h {m}m"
    if seconds >= 60:
        m = int(seconds // 60)
        s = int(seconds % 60)
        return f"{m}m {s}s"
    return f"{seconds:.1f}s"
