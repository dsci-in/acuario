"""Live audit-progress dashboard for ``acuario audit``.

A Rich :class:`~rich.live.Live` panel pinned at the bottom of the terminal while
the narrated log lines scroll *above* it - the glitch-free Rich pattern (log
output is printed through ``live.console``, which reflows the live region).  The
panel shows the pipeline stage, elapsed time, a live findings tally (CVD-safe
severity badges) and a spend / budget meter.

Design notes
------------
* **Read-only on the run.**  The dashboard never drives the scan; it *reads*
  live state - a findings-list snapshot (``get_findings``) and the running spend
  (``get_spend``) - and the stage from the log stream.  All reads are defensive
  (``list(...)`` snapshot under the GIL; broad ``except`` in the log handler), so
  a dashboard hiccup can never affect, slow, or crash the audit.
* **TTY-only.**  The caller gates this on an interactive, coloured console; the
  plain streaming path (today's behaviour) is used otherwise, so piped / CI /
  ``NO_COLOR`` output is unchanged.
* **Theme-driven.**  All colour comes from :mod:`acuario.ui.theme`.
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from acuario.ui import theme
from acuario.ui.narration import _STAGE_PREFIX_RE, _stage_from_logger

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# The pipeline, in RUNTIME order (which differs from narration's _STAGE_ORDER):
# the orchestrator emits its cross-file plans before the reviewer validates, and
# exploit-dev runs on the verified findings after review.  Ordering the markers
# this way keeps the ✓ done / ◐ current indicators honest.  `variant` (the
# off-by-default sibling-bug loop) and the auxiliary stages (sandbox, critic,
# behavior, recall, context) simply don't advance the bar - they scroll as log
# lines - which is fine.
STAGES: tuple[str, ...] = (
    "preprocess",
    "prioritize",
    "analyze",
    "skeptic",
    "orchestrate",
    "review",
    "exploit",
    "report",
)
_STAGE_INDEX: dict[str, int] = {s: i for i, s in enumerate(STAGES)}

# Friendlier labels for the stage as *shown* (E29).  Presentation only: the
# STAGES ids above - and `_STAGE_INDEX` / `note_stage` - stay the lowercase
# log-prefix keys that stage DETECTION matches against the audit stream.  This
# map only changes how a stage is DISPLAYED in the pipeline line and the panel
# title; an id with no entry falls back to itself, so adding a STAGE never
# silently blanks the label.
_STAGE_DISPLAY: dict[str, str] = {
    "preprocess": "Preprocess",
    "prioritize": "Prioritize",
    "analyze": "Analyze",
    "skeptic": "Skeptic gate",
    "orchestrate": "Orchestrate",
    "review": "Review",
    "exploit": "Exploit",
    "report": "Report",
}


def _stage_label(stage: str) -> str:
    """Friendly display name for a pipeline stage id (falls back to the id)."""
    return _STAGE_DISPLAY.get(stage, stage)


# Severity vocabulary is owned by the theme kit (single source of truth), so the
# dashboard never drifts from the rest of the CLI on a palette change.
_SEV_ORDER = theme.SEVERITY_ORDER


def _sev_glyph(severity: str, *, ascii_only: bool) -> str:
    spec = theme.SEVERITIES[severity]
    return spec.ascii if ascii_only else spec.glyph


def _stdout_is_tty() -> bool:
    try:
        return os.isatty(1)
    except OSError:
        return False


@dataclass
class DashboardState:
    """Live state the dashboard renders.  ``get_findings`` / ``get_spend`` are
    callables returning the current snapshot, so the panel always reflects the
    run without the dashboard holding scanner objects itself."""

    session_id: str
    depth: str
    get_findings: Callable[[], list]
    get_spend: Callable[[], float]
    budget: float | None = None
    is_self_hosted: bool = True
    started: float = field(default_factory=time.time)
    stage_idx: int = 0

    def note_stage(self, stage: str) -> None:
        """Advance the current stage (monotonic - never moves backwards)."""
        idx = _STAGE_INDEX.get(stage)
        if idx is not None and idx > self.stage_idx:
            self.stage_idx = idx

    def mark_complete(self) -> None:
        """Mark the whole pipeline finished so the final frozen frame reads as
        done - every stage ✓ and a success-tinted header - rather than freezing
        on whichever stage last emitted a catchable log line."""
        self.stage_idx = len(STAGES)


def _elapsed(state: DashboardState) -> str:
    s = max(0, int(time.time() - state.started))
    return f"{s // 60:02d}:{s % 60:02d}"


def _tally(state: DashboardState) -> tuple[dict[str, int], int]:
    """Count findings by severity + verified, from a defensive snapshot."""
    sev = {k: 0 for k in _SEV_ORDER}
    verified = 0
    try:
        findings = list(state.get_findings() or [])  # atomic copy under the GIL
    except Exception:
        return sev, 0
    for f in findings:
        try:
            if f.get("duplicate_of"):
                continue
            key = theme.normalize_severity(f.get("severity_verified") or f.get("severity"))
            sev[key] += 1
            if f.get("verified") or f.get("severity_verified"):
                verified += 1
        except Exception:
            continue
    return sev, verified


def _pipeline_line(state: DashboardState, *, ascii_only: bool = False) -> Text:
    done_g = theme.glyph("accept", ascii_only=ascii_only)
    cur_g = theme.glyph("engage", ascii_only=ascii_only)
    pend_g = theme.glyph("skip", ascii_only=ascii_only)
    arrow_g = theme.glyph("arrow", ascii_only=ascii_only)
    t = Text(no_wrap=True, overflow="ellipsis")
    for i, st in enumerate(STAGES):
        label = _stage_label(st)
        if i < state.stage_idx:
            t.append(f"{done_g} ", style="success")
            t.append(label, style="muted")
        elif i == state.stage_idx:
            t.append(f"{cur_g} ", style="accent.strong")
            t.append(label, style="accent.strong")
        else:
            t.append(f"{pend_g} ", style="faint")
            t.append(label, style="faint")
        if i < len(STAGES) - 1:
            t.append(f"  {arrow_g}  " if i == state.stage_idx else "  ", style="faint")
    return t


def _tally_line(state: DashboardState, *, ascii_only: bool = False) -> Text:
    sev, verified = _tally(state)
    total = sum(sev.values())
    t = Text(no_wrap=True, overflow="ellipsis")
    t.append("findings ", style="muted")
    t.append(str(total), style="metric")
    t.append("  (")
    if total:
        first = True
        for s in _SEV_ORDER:
            if sev[s]:
                if not first:
                    t.append(" ")
                t.append(f"{_sev_glyph(s, ascii_only=ascii_only)}{sev[s]}", style=f"sev.{s}")
                first = False
    else:
        t.append("none yet", style="faint")
    t.append(")   ")
    t.append("verified ", style="muted")
    t.append(str(verified), style="success")
    return t


def _spend_line(state: DashboardState, *, ascii_only: bool = False) -> Text:
    try:
        spend = float(state.get_spend())
    except Exception:
        spend = 0.0
    t = Text(no_wrap=True, overflow="ellipsis")
    t.append("spend ", style="muted")
    if state.is_self_hosted:
        t.append("$0.00", style="success")
        t.append("  (self-hosted)", style="faint")
        return t
    if not state.budget:
        t.append(f"${spend:,.2f}", style="metric")
        t.append("  / unlimited", style="muted")
        return t
    frac = min(spend / state.budget, 1.0)
    width = 24
    filled = int(frac * width)
    bar_style = "success" if frac < 0.75 else ("warn" if frac < 1.0 else "danger")
    fill_ch, empty_ch = ("#", "-") if ascii_only else ("█", "░")
    t.append(f"${spend:,.2f}", style="metric")
    t.append(f" / ${state.budget:,.0f}  ", style="muted")
    t.append("[", style="faint")
    t.append(fill_ch * filled, style=bar_style)
    t.append(empty_ch * (width - filled), style="faint")
    t.append("]", style="faint")
    t.append(f" {frac * 100:.0f}%", style=bar_style)
    return t


def build_dashboard(state: DashboardState, *, console: Console | None = None) -> Panel:
    """The dashboard panel for the current state (recomputed each refresh).

    ``console`` is the surface the panel will render on; its encoding decides
    whether the glyphs are drawn in Unicode or ASCII-folded, so the live region
    degrades cleanly on a non-UTF-8 terminal instead of mojibake-ing.
    """
    ascii_only = not theme.supports_unicode(console)
    done = state.stage_idx >= len(STAGES)
    stage = "Complete" if done else _stage_label(STAGES[state.stage_idx])
    body = Group(
        _pipeline_line(state, ascii_only=ascii_only),
        Text(),
        _tally_line(state, ascii_only=ascii_only),
        _spend_line(state, ascii_only=ascii_only),
    )
    head_g = theme.glyph("complete", ascii_only=ascii_only)
    title = Text(no_wrap=True, overflow="ellipsis")
    title.append(f"{head_g} ", style="success" if done else "accent.strong")
    title.append(stage, style="success" if done else "brand")
    title.append(f"   {state.session_id} · {state.depth} · {_elapsed(state)}", style="muted")
    border = "panel.success" if done else "panel.accent"
    return Panel(body, title=title, title_align="left", border_style=border, padding=(0, 1))


class DashboardLogHandler(logging.Handler):
    """Routes log records through the live console (so they scroll above the
    panel) and advances the dashboard's stage, then redraws the panel once.

    The panel is redrawn ONLY here, on a log event - there is NO background
    auto-refresh.  That is deliberate: a background refresh thread races with
    these prints and re-introduces stacked/partial panels.  Redrawing only on our
    own log events (serialised with the print) keeps the region glitch-free.  The
    elapsed clock therefore advances on the next log line rather than every tick -
    a deliberate trade-off for the glitch-free guarantee.
    """

    def __init__(self, live: Live, state: DashboardState, formatter: logging.Formatter) -> None:
        super().__init__()
        self._live = live
        self._state = state
        self._fmt = formatter

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self._fmt.format(record)
            if not msg:
                return
            # Stage from the bracketed prefix (ANSI-stripped, since a colourised
            # formatter prepends escapes), falling back to the logger name.
            plain = _ANSI_RE.sub("", msg)
            m = _STAGE_PREFIX_RE.match(plain)
            stage = m.group(1).split("/")[0].split(":")[0] if m else _stage_from_logger(record.name)
            if stage:
                self._state.note_stage(stage)
            # from_ansi preserves the narration formatter's colouring; plain text
            # (no escapes) round-trips unchanged.
            self._live.console.print(Text.from_ansi(msg))
            self._live.update(
                build_dashboard(self._state, console=self._live.console), refresh=True
            )
        except Exception:  # noqa: BLE001 - logging must never raise into the run
            pass


def _close_fd(fd: int | None) -> None:
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass


@contextmanager
def _terminal_console(console: Console) -> Iterator[Console]:
    """Yield a console that renders to the real terminal while OS-level
    stdout/stderr are redirected to ``/dev/null`` for the duration.

    This is what makes the live region glitch-free: a native extension writing
    to the terminal during a long call (e.g. genai_pyo3 streaming an LLM
    response) goes to ``/dev/null`` instead of moving the cursor and stacking
    copies of the panel.  Rich renders to ``term`` - a dup of the real terminal
    taken BEFORE the redirect.  The per-session ``FileHandler`` (audit.log) has
    its own fd and is unaffected.  On a non-tty (pipe / pytest capture) there is
    no cursor to desync, so the passed console is yielded unchanged; any failure
    falls back to it too, rather than breaking output.
    """
    if not _stdout_is_tty():
        yield console
        return

    saved1 = saved2 = devnull = None
    term = None
    live_console = console
    try:
        # Pin the width once, from the real console BEFORE the redirect.  Letting
        # Rich re-measure ``term`` on each redraw yields slightly different widths
        # between frames, and a width change breaks Rich's erase maths and leaves
        # partial panels.  Fixed width keeps every redraw glitch-free; the cost is
        # that the panel does not re-flow on a window resize.
        width = console.size.width
        saved1 = os.dup(1)
        saved2 = os.dup(2)
        term = os.fdopen(os.dup(1), "w", buffering=1)  # dup'd before redirect -> real terminal
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        live_console = theme.build_console(file=term, force_terminal=True, width=width)
    except Exception:  # noqa: BLE001 - redirect is best-effort
        live_console = console

    try:
        yield live_console
    finally:
        if saved1 is not None:
            try:
                os.dup2(saved1, 1)
            except OSError:
                pass
        if saved2 is not None:
            try:
                os.dup2(saved2, 2)
            except OSError:
                pass
        _close_fd(saved1)
        _close_fd(saved2)
        _close_fd(devnull)
        if term is not None:
            try:
                term.flush()
                term.close()
            except Exception:  # noqa: BLE001
                pass


@contextmanager
def live_dashboard(
    console: Console,
    state: DashboardState,
    *,
    formatter: logging.Formatter,
) -> Iterator[Live]:
    """Run the live dashboard around a blocking call (``runner.run()``).

    While active it swaps the root logger's console ``StreamHandler`` for a
    handler that prints through the live console, then restores it on exit (the
    per-session ``FileHandler`` is untouched, so ``audit.log`` is unaffected).

    ``auto_refresh=False``: the panel is redrawn only on log events (see
    :class:`DashboardLogHandler`), which avoids a background refresh thread
    racing with the log-line prints.  Combined with :func:`_terminal_console`'s
    fd redirect and its fixed render width, that is what keeps the region
    glitch-free (the cost is that the panel does not re-flow on a window resize).
    """
    root = logging.getLogger()
    # Detach the plain console StreamHandler(s) so raw writes can't corrupt the
    # live region; keep FileHandlers (audit.log) attached.
    detached: list[logging.Handler] = []
    for h in list(root.handlers):
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            root.removeHandler(h)
            detached.append(h)

    try:
        with _terminal_console(console) as live_console, Live(
            build_dashboard(state, console=live_console),
            console=live_console,
            auto_refresh=False,
            transient=False,  # keep the final frame; the caller prints the summary after
            vertical_overflow="visible",
        ) as live:
            handler = DashboardLogHandler(live, state, formatter)
            handler.setLevel(logging.INFO)
            root.addHandler(handler)
            try:
                yield live
            finally:
                root.removeHandler(handler)
                try:
                    live.update(
                        build_dashboard(state, console=live.console), refresh=True
                    )  # final frame
                except Exception:  # noqa: BLE001
                    pass
    finally:
        # Restore the original console handler(s) for the rest of the process.
        for h in detached:
            root.addHandler(h)
