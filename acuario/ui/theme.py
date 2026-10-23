"""Acuario shared terminal design kit - the single source of truth for the CLI look.

Philosophy
----------
One coherent, cyan/teal-forward palette (in the spirit of Nord frost, Tokyo
Night liveliness and Catppuccin balance, copied from none of them) lives in
exactly ONE place: a :class:`rich.theme.Theme` of *semantic* style names
(``accent``, ``muted``, ``success``, ``danger``, ``sev.critical`` ...).  Call
sites never carry a colour; they reference a semantic name, or - better - call a
helper that returns a ready Rich renderable.  Because the palette is authored
once and resolved by the shared Console at render time, the whole CLI can be
re-skinned from this file alone.

Three things make the kit trustworthy for a security tool:

* **CVD-safe severity.**  Severity is never colour alone - it is always
  ``shape glyph + UPPERCASE label + colour``, so it survives colour-blindness,
  ``NO_COLOR`` and monochrome logs (see :func:`severity_badge`).
* **Deterministic degradation.**  Colours are authored in truecolor hex; Rich
  down-samples to 256-colour automatically, and on a 16-colour terminal
  :func:`build_console` pushes a hand-tuned override so the brand and the
  severity ramp do NOT collapse onto a single ANSI slot.  ``NO_COLOR`` and
  non-TTY / piped / CI output drop to clean, escape-free plain text.
* **Markup-injection safe.**  Free text (file paths, finding descriptions, LLM
  output) is routed through :class:`rich.text.Text`, which never parses markup,
  so a stray ``[`` or ``[/]`` can neither crash the render nor silently eat
  text.  :func:`escape` is re-exported for the few sites that must build markup
  by hand.

Scope: this palette is tuned for DARK terminals (the common developer default);
Rich cannot detect the terminal background, so there is no light-mode auto-swap.
The neutrals are chosen to clear WCAG AA on typical dark backgrounds, and
severity meaning survives on any background via shape + label.

Rendering invariant
-------------------
The palette lives in the theme, so **everything is rendered on the one themed
Console** built by :func:`build_console` (installed once at ``cli.py`` and shared
as ``cli.console``).  The free-text helpers (:func:`success`, :func:`severity_badge`,
...) return :class:`~rich.text.Text` and degrade to plain text on any Console, but
the structural components (:func:`kv_table`, :func:`data_table`, :func:`section_rule`,
:func:`panel`) hand semantic style *names* to Rich's ``Table`` / ``Rule`` / ``Panel``
(which is what lets the 16-colour override reach them); those names only resolve on
a themed Console, so rendering a component on a bare ``Console()`` raises
``MissingStyle``.  Build consoles with :func:`build_console` (or :func:`apply_theme`
an existing one) - in tests too.

Import safety
-------------
Pure Python; imports only ``rich`` (already a dependency) and the stdlib.  It
never touches the scanner / provider / LLM stack, so it is safe to import on a
partial install (e.g. inside ``doctor`` before dependencies are verified).
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Literal

from rich.console import Console
from rich.markup import escape  # re-exported: the safe way to build markup by hand
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

__all__ = [
    # palette + theme + console
    "PALETTE",
    "TOKENS_256",
    "RICH_COLOR_NAMES",
    "STANDARD_16",
    "ACUARIO_THEME",
    "STANDARD_THEME",
    "build_console",
    "apply_theme",
    # environment probes (console-authoritative)
    "is_plain",
    "color_enabled",
    "console_tier",
    "supports_unicode",
    # severity
    "Severity",
    "SEVERITIES",
    "SEVERITY_ORDER",
    "normalize_severity",
    "resolve_severity",
    "severity_rank",
    "severity_style",
    "severity_badge",
    "severity_cell",
    "severity_tag",
    # status (doctor-style health marks)
    "STATUS",
    "status_style",
    "status_mark",
    # glyphs
    "GLYPH",
    "glyph",
    "escape",
    "GLYPH_ENGAGE",
    "GLYPH_COMPLETE",
    "GLYPH_ACCEPT",
    "GLYPH_REFUTE",
    "GLYPH_EVENT",
    "GLYPH_SNAP",
    "GLYPH_ALERT",
    "GLYPH_OK",
    "GLYPH_ERR",
    "GLYPH_DONE",
    "GLYPH_BULLET",
    "GLYPH_WARN",
    "GLYPH_SKIP",
    "GLYPH_ARROW",
    "GLYPH_EXPLOIT",
    "GLYPH_VERIFIED",
    # free-text helpers (auto-escaping)
    "success",
    "warn",
    "error",
    "info",
    "muted",
    "accent",
    "line",
    "field",
    "markup",
    # structural components
    "kv_table",
    "data_table",
    "framed_table",
    "section_rule",
    "panel",
    "brand_banner",
    "status_spinner",
]


# ---------------------------------------------------------------------------
# Palette - the ONE place a colour is ever written.
# ---------------------------------------------------------------------------
# Authored in 24-bit truecolor hex (always parses in Rich; Rich owns the
# down-sampling).  Tuned for dark backgrounds; the neutrals clear WCAG AA on
# typical dark terminals (#1a1b26 / #0d1117).

PALETTE: dict[str, str] = {
    # neutrals
    "fg": "#c8d3e0",            # primary foreground / values
    "muted": "#9aa5b8",         # secondary text (the tunable replacement for bare `dim`)
    "faint": "#6b7488",         # faint captions / scaffolding
    # brand / structure (teal-cyan forward)
    "accent": "#56c7d6",        # primary brand teal-cyan
    "accent_bright": "#7fe0ea", # headings / highlights / metrics
    "accent_deep": "#4c9fb0",   # deeper teal (secondary accent)
    "rule": "#3f7d8a",          # rule lines / panel borders (quiet teal)
    "sky": "#7dcfff",           # file paths / links
    "blue": "#7aa2f7",          # cool blue - low severity (kept distinct from accent)
    "lavender": "#b4befe",      # secondary emphasis / critic + snapshot stage
    # semantic status / severity hues
    "green": "#8fcf7e",         # success / verified / accept
    "amber": "#e0af68",         # warning / medium severity
    "orange": "#ff9e64",        # high severity
    "red": "#f7768e",           # danger / critical / refute
}

# Exact xterm-256 index Rich derives from each hex (verified with
# ``Color.parse(hex).downgrade(ColorSystem.EIGHT_BIT).number`` on rich 13.7.1),
# documented so the 256-colour fallback is auditable rather than mysterious.
TOKENS_256: dict[str, int] = {
    "fg": 188, "muted": 109, "faint": 243, "accent": 80, "accent_bright": 116,
    "accent_deep": 73, "rule": 66, "sky": 117, "blue": 111, "lavender": 147,
    "green": 114, "amber": 179, "orange": 215, "red": 210,
}


def _c(token: str) -> str:
    """Resolve a palette token to its hex value."""
    return PALETTE[token]


# ---------------------------------------------------------------------------
# Glyphs - one vocabulary, identical in value to acuario.ui.narration so the
# run surface and the audit.log stream never drift.  narration.py should import
# these names from here (this module has no heavy deps; narration does, so the
# dependency points this way).
# ---------------------------------------------------------------------------

# Process vocabulary (names match narration.py exactly for a drop-in import).
GLYPH_ENGAGE = "◐"    # work started
GLYPH_COMPLETE = "●"  # work finished
GLYPH_ACCEPT = "✓"    # accepted / verified
GLYPH_REFUTE = "✗"    # refuted / failed
GLYPH_EVENT = "▸"     # neutral event / list marker
GLYPH_SNAP = "◇"      # snapshot / checkpoint
GLYPH_ALERT = "⚠"     # alert

# UI aliases (same code points, call-site-friendly names).
GLYPH_OK = GLYPH_ACCEPT        # check
GLYPH_ERR = GLYPH_REFUTE       # ballot-x
GLYPH_DONE = GLYPH_COMPLETE    # filled circle
GLYPH_BULLET = GLYPH_EVENT     # small right triangle
GLYPH_WARN = "!"               # caution
GLYPH_SKIP = "·"          # skipped / not-run (middle dot)
GLYPH_ARROW = "→"         # hint / leads-to
GLYPH_EXPLOIT = "⚔"       # exploited (inspect findings table)
GLYPH_VERIFIED = GLYPH_ACCEPT  # check (alias)

# name -> unicode glyph (for glyph()).
GLYPH: dict[str, str] = {
    "engage": GLYPH_ENGAGE,
    "complete": GLYPH_COMPLETE,
    "accept": GLYPH_ACCEPT,
    "refute": GLYPH_REFUTE,
    "event": GLYPH_EVENT,
    "snap": GLYPH_SNAP,
    "alert": GLYPH_ALERT,
    "warn": GLYPH_WARN,
    "skip": GLYPH_SKIP,
    "arrow": GLYPH_ARROW,
    "exploit": GLYPH_EXPLOIT,
}

# ASCII fallbacks keyed by code point, for streams whose encoding can't carry
# the Unicode glyphs.  (The audit.log file formatter in narration.py keeps its
# own longer grep-friendly forms; this set is for the live console surface.)
_GLYPH_ASCII: dict[str, str] = {
    GLYPH_ENGAGE: "(o)",
    GLYPH_COMPLETE: "*",
    GLYPH_ACCEPT: "+",
    GLYPH_REFUTE: "x",
    GLYPH_EVENT: ">",
    GLYPH_SNAP: "<>",
    GLYPH_ALERT: "!",
    GLYPH_WARN: "!",
    GLYPH_SKIP: "-",
    GLYPH_ARROW: "->",
    GLYPH_EXPLOIT: "X",
}


def supports_unicode(console: Console | None = None) -> bool:
    """True when the target stream's encoding can carry the Unicode glyphs.

    Probes the given ``console``'s encoding when supplied (the correct source
    for an stderr or file-backed console); otherwise falls back to ``sys.stdout``
    - correct for Acuario's single shared stdout console.  Never raises.
    """
    if console is not None:
        enc = (getattr(console, "encoding", None) or "").lower()
    else:
        enc = (getattr(sys.stdout, "encoding", None) or "").lower()
    if "utf" in enc:
        return True
    try:
        "◆▲■▾·◐●✓✗▸◇⚠→⚔".encode(enc or "ascii")
        return True
    except (LookupError, UnicodeEncodeError, TypeError):
        return False


def _fold(ch: str, *, ascii_only: bool) -> str:
    """Return a glyph, or its ASCII fallback when ``ascii_only``."""
    return _GLYPH_ASCII.get(ch, ch) if ascii_only else ch


def glyph(name: str, *, console: Console | None = None, ascii_only: bool | None = None) -> str:
    """Return a process glyph by name, ASCII-folded when Unicode is unsafe."""
    g = GLYPH.get(name, "")
    if not g:
        return ""
    use_ascii = (not supports_unicode(console)) if ascii_only is None else ascii_only
    return _fold(g, ascii_only=use_ascii)


# ---------------------------------------------------------------------------
# Severity - triple-redundant (shape + UPPERCASE label + colour) encoding.
# ---------------------------------------------------------------------------
# No single channel is load-bearing, so meaning survives colour-blindness,
# NO_COLOR, monochrome logs and a 16-colour ramp collapse.  The up-triangle
# (high, points up = elevated) / down-triangle (low, points down) pair adds a
# redundant directional cue on top of the distinct shapes.


@dataclass(frozen=True)
class Severity:
    key: str       # canonical lowercase key, e.g. "critical"
    label: str     # UPPERCASE display label, e.g. "CRITICAL"
    glyph: str     # Unicode shape
    ascii: str     # ASCII fallback shape
    style: str     # theme style name, e.g. "sev.critical"
    rank: int      # 0 = most severe


# Canonical order, strongest first.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

SEVERITIES: dict[str, Severity] = {
    "critical": Severity("critical", "CRITICAL", "◆", "!!", "sev.critical", 0),
    "high": Severity("high", "HIGH", "▲", "^^", "sev.high", 1),
    "medium": Severity("medium", "MEDIUM", "■", "==", "sev.medium", 2),
    "low": Severity("low", "LOW", "▾", "vv", "sev.low", 3),
    "info": Severity("info", "INFO", "·", "..", "sev.info", 4),
}

# Aliases seen across findings.json / pipeline vocabulary.
_SEVERITY_ALIASES: dict[str, str] = {
    "crit": "critical",
    "blocker": "critical",
    "severe": "critical",
    "major": "high",
    "moderate": "medium",
    "med": "medium",
    "minor": "low",
    "informational": "info",
    "note": "info",
    "none": "info",
    "unknown": "info",
    "": "info",
}


def normalize_severity(severity: str | None) -> str:
    """Map any severity-ish string to one of :data:`SEVERITY_ORDER` (default info)."""
    s = (severity or "").strip().lower()
    if s in SEVERITIES:
        return s
    return _SEVERITY_ALIASES.get(s, "info")


def resolve_severity(severity: str | None) -> Severity:
    """Return the :class:`Severity` record for any severity string."""
    return SEVERITIES[normalize_severity(severity)]


def severity_rank(severity: str | None) -> int:
    """0 (critical) .. 4 (info).  Lower = more severe.  Unknown folds to info (4)."""
    return SEVERITIES[normalize_severity(severity)].rank


def severity_style(severity: str | None) -> str:
    """Return the theme style *name* for a severity, e.g. ``"sev.high"``.

    Drop-in for the old per-command ``_severity_color()``: a call site can keep
    doing ``f"[{severity_style(sev)}]{sev.upper()}[/]"`` - but prefer
    :func:`severity_badge`, which also carries the CVD-safe shape glyph.
    """
    return SEVERITIES[normalize_severity(severity)].style


def severity_badge(
    severity: str | None,
    *,
    label: bool = True,
    width: int = 0,
    console: Console | None = None,
) -> Text:
    """Build a CVD-safe severity badge as a styled :class:`rich.text.Text`.

    ``glyph + " " + UPPERCASE-LABEL`` (e.g. ``◆ CRITICAL``) carried in the
    severity's theme style.  The style is a *name* resolved by the shared themed
    Console at render time, so it automatically picks up the 16-colour override;
    on a non-themed Console it degrades to plain text and the glyph + label still
    carry the meaning.

    ``label=False`` emits only the shape (for dense columns with a "SEV" header);
    keep the label whenever colour may be unavailable.  ``width`` left-justifies
    the ``glyph LABEL`` body to that many columns so stacked badges align.
    """
    spec = resolve_severity(severity)
    use_ascii = not supports_unicode(console)
    shape = spec.ascii if use_ascii else spec.glyph
    if label:
        body = f"{shape} {spec.label}"
    else:
        body = shape
    if width:
        body = body.ljust(width)
    return Text(body, style=spec.style)


def severity_cell(severity: str | None, *, width: int = 0, console: Console | None = None) -> Text:
    """Compact severity badge for dense tables (shape + label)."""
    return severity_badge(severity, label=True, width=width, console=console)


def severity_tag(severity: str | None, *, label: bool = True, console: Console | None = None) -> str:
    """Markup-string form of :func:`severity_badge` for inline f-strings.

    Built only from internal constants (glyph + UPPERCASE label + style name),
    so it is markup-safe.  Example::

        console.print(f"{severity_tag(f['severity'])}  {escape(f['id'])}")
    """
    spec = resolve_severity(severity)
    use_ascii = not supports_unicode(console)
    shape = spec.ascii if use_ascii else spec.glyph
    body = f"{shape} {spec.label}" if label else shape
    return f"[{spec.style}]{body}[/{spec.style}]"


# ---------------------------------------------------------------------------
# Status - ok / warn / err / skip health marks (doctor, and anywhere a
# green/yellow/red mark is wanted).  Same redundant shape + colour idea.
# ---------------------------------------------------------------------------

# status -> (theme style name, unicode glyph, ascii glyph)
STATUS: dict[str, tuple[str, str, str]] = {
    "ok": ("success", GLYPH_ACCEPT, "+"),
    "warn": ("warn", GLYPH_WARN, "!"),
    "err": ("danger", GLYPH_REFUTE, "x"),
    "skip": ("muted", GLYPH_SKIP, "-"),
}


def status_style(status: str) -> str:
    """Return the theme style name for a doctor-style status token."""
    return STATUS.get(status, STATUS["skip"])[0]


def status_mark(status: str, *, console: Console | None = None) -> Text:
    """A single themed status glyph for ``ok`` / ``warn`` / ``err`` / ``skip``.

    Drop-in for doctor.py's ``_STATUS_GLYPHS`` markup strings - returns a Text,
    which Rich table cells accept directly.
    """
    style_name, uni, asc = STATUS.get(status, STATUS["skip"])
    use_ascii = not supports_unicode(console)
    return Text(asc if use_ascii else uni, style=style_name)


# ---------------------------------------------------------------------------
# The theme - semantic style names only, authored from the palette.
# ---------------------------------------------------------------------------
# inherit=True keeps every Rich default, and because NO bare colour/attribute
# token (red / cyan / green / yellow / blue / orange1 / dim / bold cyan) is
# registered as a style name, every existing ``[red]`` / ``[bold cyan]`` call
# site keeps resolving exactly as before - migration is additive and optional.
# A handful of Rich's own "chrome" styles are overridden so rules, tables,
# spinners, prompts and rendered Markdown adopt the palette with zero churn.


def _build_theme_styles() -> dict[str, str]:
    return {
        # --- brand / structure -------------------------------------------
        "accent": _c("accent"),
        "accent.strong": f"bold {_c('accent')}",
        "accent.bright": _c("accent_bright"),
        "accent.deep": _c("accent_deep"),
        "brand": f"bold {_c('accent')}",
        "secondary": _c("lavender"),
        # --- text hierarchy ----------------------------------------------
        "heading": f"bold {_c('accent_bright')}",
        "title": f"bold {_c('accent')}",
        "subtitle": _c("muted"),
        "muted": _c("muted"),
        "faint": _c("faint"),
        "strong": "bold",
        # --- status ------------------------------------------------------
        "success": _c("green"),
        "success.strong": f"bold {_c('green')}",
        "warn": _c("amber"),
        "warn.strong": f"bold {_c('amber')}",
        "danger": f"bold {_c('red')}",
        "info": _c("sky"),
        # --- data / code -------------------------------------------------
        "path": _c("sky"),
        "link": f"underline {_c('sky')}",
        "ident": "bold",
        "metric": f"bold {_c('accent_bright')}",
        "count": f"bold {_c('accent')}",
        "cost": _c("amber"),
        # --- pipeline stage accents (mirror narration's console intent) ---
        "stage": _c("accent_deep"),
        "stage.skeptic": _c("lavender"),
        "stage.orchestrate": _c("lavender"),
        "stage.critic": _c("blue"),
        "stage.review": _c("blue"),
        "stage.lab": _c("amber"),
        # --- severity ladder (always paired with glyph + LABEL) ----------
        "sev.critical": f"bold {_c('red')}",
        "sev.high": f"bold {_c('orange')}",
        "sev.medium": _c("amber"),
        "sev.low": _c("blue"),
        "sev.info": _c("muted"),
        # --- panel border kinds ------------------------------------------
        "panel.info": _c("rule"),
        "panel.accent": _c("accent"),
        "panel.success": _c("green"),
        "panel.warn": _c("amber"),
        "panel.danger": _c("red"),
        # --- overrides of Rich's built-in chrome (zero call-site churn) ---
        "rule.line": _c("rule"),
        "rule.text": f"bold {_c('accent')}",
        "table.header": f"bold {_c('accent_bright')}",
        "table.title": f"bold {_c('accent')}",
        "table.caption": _c("muted"),
        "table.footer": _c("muted"),
        "status.spinner": _c("accent"),
        "progress.spinner": _c("accent"),
        "progress.percentage": _c("accent"),
        "progress.elapsed": _c("muted"),
        "progress.remaining": _c("muted"),
        "prompt": _c("accent"),
        "prompt.choices": _c("accent"),
        "prompt.default": _c("muted"),
        "markdown.h1": f"bold {_c('accent')}",
        "markdown.h2": f"bold {_c('accent_bright')}",
        "markdown.h3": _c("accent"),
        "markdown.code": _c("amber"),
        "markdown.link": _c("sky"),
        "markdown.link_url": _c("sky"),
        "markdown.block_quote": _c("muted"),
        "markdown.item.bullet": _c("accent"),
    }


ACUARIO_THEME = Theme(_build_theme_styles(), inherit=True)


# ---------------------------------------------------------------------------
# 16-colour override - pushed only on a STANDARD / legacy-Windows terminal.
# ---------------------------------------------------------------------------
# On a true 16-colour terminal Rich's automatic matcher collapses the truecolor
# palette: green / blue / amber / lavender all fall onto ANSI white (7) and
# orange + red both fall onto red (9), erasing the brand AND the severity ramp.
# This hand-tuned map pins every semantic style to a DISTINCT valid 16-colour
# name so the ramp and the brand survive.  Verified distinct on rich 13.7.1.

STANDARD_16: dict[str, str] = {
    # token -> standard-16 name
    "fg": "default",
    "muted": "bright_black",
    "faint": "bright_black",
    "accent": "bright_cyan",
    "accent_bright": "bright_cyan",
    "accent_deep": "cyan",
    "rule": "cyan",
    "sky": "bright_cyan",
    "blue": "blue",
    "lavender": "magenta",
    "green": "green",
    "amber": "yellow",
    "orange": "red",
    "red": "bright_red",
}


def _s16(token: str) -> str:
    return STANDARD_16[token]


def _build_standard_styles() -> dict[str, str]:
    return {
        "accent": _s16("accent"),
        "accent.strong": f"bold {_s16('accent')}",
        "accent.bright": _s16("accent_bright"),
        "accent.deep": _s16("accent_deep"),
        "brand": f"bold {_s16('accent')}",
        "secondary": _s16("lavender"),
        "heading": f"bold {_s16('accent_bright')}",
        "title": f"bold {_s16('accent')}",
        "subtitle": _s16("muted"),
        "muted": _s16("muted"),
        "faint": _s16("faint"),
        "success": _s16("green"),
        "success.strong": f"bold {_s16('green')}",
        "warn": _s16("amber"),
        "warn.strong": f"bold {_s16('amber')}",
        "danger": f"bold {_s16('red')}",
        "info": _s16("sky"),
        "path": _s16("sky"),
        "link": f"underline {_s16('sky')}",
        "metric": f"bold {_s16('accent_bright')}",
        "count": f"bold {_s16('accent')}",
        "cost": _s16("amber"),
        "stage": _s16("accent_deep"),
        "stage.skeptic": _s16("lavender"),
        "stage.orchestrate": _s16("lavender"),
        "stage.critic": _s16("blue"),
        "stage.review": _s16("blue"),
        "stage.lab": _s16("amber"),
        "sev.critical": f"bold {_s16('red')}",   # bright_red
        "sev.high": f"bold {_s16('orange')}",    # red (distinct from bright_red)
        "sev.medium": _s16("amber"),             # yellow
        "sev.low": _s16("blue"),                 # blue
        "sev.info": _s16("muted"),               # bright_black
        "panel.info": _s16("rule"),
        "panel.accent": _s16("accent"),
        "panel.success": _s16("green"),
        "panel.warn": _s16("amber"),
        "panel.danger": _s16("red"),
        "rule.line": _s16("rule"),
        "rule.text": f"bold {_s16('accent')}",
        "table.header": f"bold {_s16('accent_bright')}",
        "table.title": f"bold {_s16('accent')}",
        "status.spinner": _s16("accent"),
        "markdown.h1": f"bold {_s16('accent')}",
        "markdown.h2": f"bold {_s16('accent_bright')}",
        "markdown.code": _s16("amber"),
    }


STANDARD_THEME = Theme(_build_standard_styles(), inherit=True)


# ---------------------------------------------------------------------------
# Console factory - the one place a themed Console is built.
# ---------------------------------------------------------------------------


def build_console(
    *,
    stderr: bool = False,
    highlight: bool = False,
    emoji: bool = False,
    force_terminal: bool | None = None,
    **kwargs: Any,
) -> Console:
    """Build the themed Console shared across the whole CLI.

    ``cli.py`` constructs this once instead of a bare ``Console()`` and every
    command uses it as ``cli.console``.

    Colour-system detection, ``NO_COLOR`` and TTY handling are left to Rich:
    ``NO_COLOR`` strips colour, a non-TTY stream emits zero escape codes,
    ``FORCE_COLOR`` keeps colour when redirected.  On a terminal that resolves
    to the 16-colour ``standard`` (or legacy ``windows``) system, the hand-tuned
    :data:`STANDARD_THEME` is pushed so the palette does not collapse.

    Defaults chosen for a security tool: ``highlight=False`` (no automatic
    number/path recolouring) and ``emoji=False`` (a literal ``:word:`` in a path
    is never swapped for an emoji).  Both remain overridable.  Extra keyword
    arguments pass straight through to ``rich.console.Console``.
    """
    console = Console(
        theme=ACUARIO_THEME,
        stderr=stderr,
        highlight=highlight,
        emoji=emoji,
        force_terminal=force_terminal,
        **kwargs,
    )
    if console_tier(console) == "standard":
        console.push_theme(STANDARD_THEME)
    return console


def apply_theme(console: Console) -> Console:
    """Install the Acuario theme (and the 16-colour override when relevant) onto
    an existing Console.  Prefer :func:`build_console`."""
    console.push_theme(ACUARIO_THEME)
    if console_tier(console) == "standard":
        console.push_theme(STANDARD_THEME)
    return console


# ---------------------------------------------------------------------------
# Environment probes - keyed off the built Console (the authoritative signal
# for what it will actually emit), never off a second env heuristic.
# ---------------------------------------------------------------------------


def color_enabled(console: Console) -> bool:
    """Whether ``console`` will actually emit colour (TTY + not no_color)."""
    return bool(console.is_terminal and not console.no_color)


def console_tier(console: Console) -> str:
    """The colour tier a built Console renders at: ``truecolor`` / ``256`` /
    ``standard`` / ``none``.  ``windows`` folds into ``standard``.

    Defensive by design: a console-like that doesn't implement the full Rich API
    (e.g. a test stub) reads as ``none`` rather than raising, so callers such as
    :func:`brand_banner` degrade to the flat tone instead of crashing.
    """
    if (
        getattr(console, "no_color", False)
        or not getattr(console, "is_terminal", False)
        or getattr(console, "color_system", None) is None
    ):
        return "none"
    cs = console.color_system
    if cs == "windows":
        return "standard"
    return cs  # "truecolor" | "256" | "standard"


def is_plain(console: Console | None = None) -> bool:
    """True when output should be plain (no colour): ``NO_COLOR`` or non-TTY.

    A convenience for *explicit* guards around interactive flourishes (spinners,
    live tables); colour itself is already handled by Rich.
    """
    if os.environ.get("NO_COLOR"):
        return True
    if console is not None:
        return not color_enabled(console)
    stream = getattr(sys, "stdout", None)
    isatty = getattr(stream, "isatty", None)
    return not (callable(isatty) and isatty())


# ---------------------------------------------------------------------------
# Free-text helpers - auto-escaping message lines.
# ---------------------------------------------------------------------------
# These take PLAIN text and build a Text (which never parses markup), so a
# description, path or LLM reply containing "[...]" is shown verbatim instead of
# vanishing or crashing the render.  The leading glyph carries the theme colour;
# the message body keeps the terminal foreground so long lines stay readable.


def _message(glyph_ch: str, msg: str, style_name: str, *, bold_glyph: bool = False) -> Text:
    out = Text()
    use_ascii = not supports_unicode()
    lead = _fold(glyph_ch, ascii_only=use_ascii)
    out.append(lead + " ", style=(f"bold {style_name}" if bold_glyph else style_name))
    out.append(msg)  # plain, escaped by virtue of being a Text append
    return out


def success(msg: str) -> Text:
    """``✓ msg`` - a passed / confirmed line."""
    return _message(GLYPH_ACCEPT, msg, "success")


def warn(msg: str) -> Text:
    """``! msg`` - a caution line."""
    return _message(GLYPH_WARN, msg, "warn")


def error(msg: str) -> Text:
    """``✗ msg`` - a failure line (glyph bold for emphasis)."""
    return _message(GLYPH_REFUTE, msg, "danger", bold_glyph=True)


def info(msg: str) -> Text:
    """``▸ msg`` - a neutral notice."""
    return _message(GLYPH_EVENT, msg, "info")


def muted(msg: str) -> Text:
    """Secondary / dim text (replaces bare ``[dim]...[/dim]``)."""
    return Text(msg, style="muted")


def accent(msg: str) -> Text:
    """Brand-accent text (replaces ``[cyan]`` / ``[bold cyan]`` emphasis)."""
    return Text(msg, style="accent.strong")


def line(msg: str, *, style: str = "") -> Text:
    """A plain (escaped) line in an arbitrary theme ``style`` and no glyph.

    The mechanical replacement for a bare ``[yellow]...[/yellow]`` (no leading
    glyph): ``line(text, style="warn")``.
    """
    return Text(msg, style=style)


def field(text: str, *, style: str = "") -> Text:
    """Wrap a single free-text value as an (escaped) styled Text for a cell."""
    return Text(text, style=style)


def markup(s: str) -> Text:
    """Opt-in: parse ``s`` as Rich markup into a Text.

    Use ONLY for trusted, developer-authored strings - never for findings data
    or LLM output (for those use :func:`field` / :func:`line`, or :func:`escape`
    the value first).
    """
    return Text.from_markup(s)


# ---------------------------------------------------------------------------
# Structural components.
# ---------------------------------------------------------------------------

_Row = Sequence[Any]
_Rows = Mapping[str, Any] | Sequence[_Row]


def _iter_rows(rows: _Rows) -> Iterator[tuple[Any, Any]]:
    if isinstance(rows, Mapping):
        yield from rows.items()
    else:
        for row in rows:
            key, value = row  # (key, value) pair
            yield key, value


def kv_table(
    rows: _Rows,
    *,
    title: str | None = None,
    key_style: str = "muted",
    value_style: str = "",
) -> Table:
    """A borderless key/value table (right-aligned muted keys, folding values).

    Replaces the hand-rolled ``f"  {key:<20} {val}"`` loops.  A value that is
    already a ``Text`` passes through styled; a plain value is wrapped in
    ``Text`` and therefore auto-escaped (never markup-parsed).
    """
    table = Table(
        box=None,
        show_header=False,
        title=title,
        title_style="table.title",
        title_justify="left",
        pad_edge=False,
        padding=(0, 1),
        expand=False,
    )
    table.add_column(justify="right", style=key_style, no_wrap=True)
    table.add_column(style=value_style, overflow="fold")
    for key, value in _iter_rows(rows):
        key_cell = key if isinstance(key, Text) else Text(str(key))
        value_cell = value if isinstance(value, Text) else Text(str(value))
        table.add_row(key_cell, value_cell)
    return table


def data_table(columns: Sequence[str], *, title: str | None = None, caption: str | None = None) -> Table:
    """A header-styled, borderless data table matching inspect.py's reference bar.

    Mirrors ``Table(show_header=True, header_style=..., box=None,
    pad_edge=False)``.  Column headers are constants; the caller adds rows
    (wrap any free-text cell in ``Text`` / :func:`field`).
    """
    table = Table(
        box=None,
        show_header=True,
        header_style="table.header",
        title=title,
        title_style="table.title",
        title_justify="left",
        caption=caption,
        caption_style="table.caption",
        pad_edge=False,
    )
    for col in columns:
        table.add_column(col)
    return table


def framed_table(
    columns: Sequence[str],
    *,
    title: str | None = None,
    caption: str | None = None,
    kind: str = "info",
) -> Table:
    """A rounded, brand-framed table for the surfaces you land on and scan
    (history/sessions, inspect findings, setup menus) - the structural
    counterpart to the borderless :func:`data_table` used for dense inline
    readouts.  The frame carves out a contained region that stays readable over
    transparent / busy terminal backgrounds.

    Same header / title / caption contract as :func:`data_table`; wrap every
    free-text cell in ``Text`` / :func:`field` (never markup-interpolated).
    ``rich.box.ROUNDED`` degrades to ASCII corners via ``safe_box`` on encodings
    that cannot draw them.  ``kind`` sets the border tone: ``info`` (the quiet
    teal rule, the Acuario default) / ``accent`` / ``success`` / ``warn`` /
    ``danger`` - a border that can encode state at decision moments.
    """
    from rich.box import ROUNDED

    border = f"panel.{kind}" if kind in ("info", "accent", "success", "warn", "danger") else "panel.info"
    table = Table(
        box=ROUNDED,
        show_header=True,
        header_style="table.header",
        title=title,
        title_style="table.title",
        title_justify="left",
        caption=caption,
        caption_style="table.caption",
        border_style=border,
        pad_edge=False,
        safe_box=True,
    )
    for col in columns:
        table.add_column(col)
    return table


def section_rule(title: str = "", *, align: Literal["left", "center", "right"] = "left") -> Rule:
    """A thin themed horizontal rule, optionally titled.

    Replaces the ``-- label --`` / ``=== ... ===`` separators hand-built in
    inspect and narration.  The title is wrapped in a Text (escaped).
    """
    label: Any = Text(title, style="rule.text") if title else ""
    return Rule(label, style="rule.line", align=align, characters="─")


def panel(
    body: Any,
    *,
    title: str | None = None,
    kind: str = "info",
    expand: bool = False,
) -> Any:
    """A rounded panel whose border colour encodes ``kind``.

    ``kind`` is one of ``info`` / ``accent`` / ``success`` / ``warn`` /
    ``danger``.  A ``str`` body is treated as PLAIN text (escaped); pass a
    renderable (``Text``, ``Table``, ``markup(...)``) for styled content.  Rich's
    ``safe_box`` substitutes ASCII box characters automatically on encodings that
    cannot render the rounded corners.
    """
    from rich.box import ROUNDED
    from rich.panel import Panel

    border = f"panel.{kind}" if kind in ("info", "accent", "success", "warn", "danger") else "panel.info"
    content = Text(body) if isinstance(body, str) else body
    title_text = Text(title, style="title") if title else None
    return Panel(
        content,
        title=title_text,
        title_align="left",
        border_style=border,
        box=ROUNDED,
        padding=(0, 1),
        expand=expand,
    )


def brand_banner(text: str, *, console: Console | None = None) -> Text:
    """The ACUARIO wordmark as a vertical teal gradient - the hero moment.

    On a truecolor console the art rows ramp accent_bright -> accent ->
    accent_deep and the tagline is muted, so the wordmark is recognizable on
    sight.  On 256 / 16 / none (or when no console is given) it falls back to the
    flat brand tone so the gradient never collapses into mud or leaks escapes.
    """
    if console is None or console_tier(console) != "truecolor":
        return Text(text, style="brand")

    lines = text.split("\n")
    art_rows = [i for i, ln in enumerate(lines) if any(ch in ln for ch in "█╗╔═║╝╚")]
    ramp = (_c("accent_bright"), _c("accent"), _c("accent_deep"))
    out = Text()
    for i, ln in enumerate(lines):
        if i:
            out.append("\n")
        if i in art_rows:
            band = ramp[min(len(ramp) - 1, art_rows.index(i) * len(ramp) // max(1, len(art_rows)))]
            out.append(ln, style=f"bold {band}")
        elif ln.strip():  # the tagline (or any non-art text) reads as a subtitle
            out.append(ln, style="muted")
        else:
            out.append(ln)
    return out


# ---------------------------------------------------------------------------
# Interactive flourish - TTY + NO_COLOR guarded spinner.
# ---------------------------------------------------------------------------


@contextmanager
def status_spinner(console: Console, message: str, *, spinner: str = "dots") -> Iterator[None]:
    """A themed ``console.status`` spinner, guarded for non-interactive output.

    On an interactive terminal with colour it shows an animated teal spinner with
    a muted message.  When stdout is piped / in CI / ``NO_COLOR`` is set it prints
    the message once and runs the body plainly - generalising inspect.py's
    ``sys.stdout.isatty()`` guard around ``_ask_llm``.
    """
    if color_enabled(console):
        with console.status(Text(message, style="muted"), spinner=spinner, spinner_style="accent"):
            yield
    else:
        console.print(Text(message, style="muted"))
        yield


# ---------------------------------------------------------------------------
# Audit surface: every Rich colour NAME this module emits (for validity audit).
# ---------------------------------------------------------------------------
# Truecolor hex (PALETTE values) always parse; the only NAMED colours are the
# 16-colour-tier overrides below, all valid Rich standard names.  Bare 'orange',
# 'teal' and 'lightblue' are INVALID in Rich and are deliberately never used.
RICH_COLOR_NAMES: tuple[str, ...] = (
    "default",
    "bright_black",
    "bright_red",
    "red",
    "blue",
    "bright_blue",
    "cyan",
    "bright_cyan",
    "magenta",
    "green",
    "yellow",
)
