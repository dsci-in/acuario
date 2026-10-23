"""Tests for acuario/ui/theme.py - the shared terminal design kit.

Covers the three properties the kit must guarantee: CVD-safe severity (shape +
label + colour), deterministic degradation (truecolor / 256 / 16 / none), and
markup-injection safety (free text never parsed as markup).  Component tests use
``build_console`` because the structural components resolve theme style names on
the themed console (the documented rendering invariant).
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console
from rich.text import Text

from acuario.ui import narration as N
from acuario.ui import theme as T


def _render(renderable, *, no_color: bool = False, color_system: str = "truecolor") -> str:
    """Render on a themed console and return the raw string (ANSI included)."""
    console = T.build_console(force_terminal=True, color_system=color_system, no_color=no_color)
    buf = io.StringIO()
    console.file = buf
    console.print(renderable)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Import safety
# ---------------------------------------------------------------------------


class TestImportSafety:
    def test_no_heavy_deps_pulled(self):
        """Importing the theme must not drag in the scanner / LLM stack.

        Run in a clean subprocess: a shared pytest process already has the heavy
        modules imported by other test files, so an in-process ``sys.modules``
        check would be meaningless.  The partial-install guarantee is about a
        *fresh* interpreter importing the theme on its own.
        """
        import subprocess
        import sys

        code = (
            "import acuario.ui.theme;import sys;"
            "bad=[m for m in sys.modules if m.startswith(('acuario.scanner','acuario.llm'))];"
            "print('HEAVY:'+','.join(bad))"
        )
        out = subprocess.run(
            [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
        ).stdout.strip()
        assert out == "HEAVY:", f"theme import pulled heavy modules: {out}"


# ---------------------------------------------------------------------------
# Severity - normalization, rank, and CVD-safe badge
# ---------------------------------------------------------------------------


class TestSeverity:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CRITICAL", "critical"),
            ("Critical", "critical"),
            ("crit", "critical"),
            ("blocker", "critical"),
            ("major", "high"),
            ("moderate", "medium"),
            ("med", "medium"),
            ("minor", "low"),
            ("informational", "info"),
            ("", "info"),
            (None, "info"),
            ("totally-unknown", "info"),
        ],
    )
    def test_normalize(self, raw, expected):
        assert T.normalize_severity(raw) == expected

    def test_rank_order(self):
        ranks = [T.severity_rank(s) for s in T.SEVERITY_ORDER]
        assert ranks == [0, 1, 2, 3, 4]

    def test_rank_unknown_folds_to_info(self):
        assert T.severity_rank("nonsense") == T.severity_rank("info") == 4

    def test_style_names(self):
        assert T.severity_style("critical") == "sev.critical"
        assert T.severity_style("high") == "sev.high"
        assert T.severity_style("bogus") == "sev.info"

    def test_badge_is_text_with_style(self):
        badge = T.severity_badge("critical")
        assert isinstance(badge, Text)
        assert badge.style == "sev.critical"
        assert "CRITICAL" in badge.plain
        assert "◆" in badge.plain  # shape glyph present

    def test_badge_cvd_triple_redundant(self):
        """Every severity carries a DISTINCT shape and an UPPERCASE label."""
        shapes = {T.severity_badge(s).plain.split()[0] for s in T.SEVERITY_ORDER}
        assert len(shapes) == len(T.SEVERITY_ORDER)  # shapes are distinct
        for s in T.SEVERITY_ORDER:
            assert s.upper() in T.severity_badge(s).plain

    def test_badge_width_ljust(self):
        badge = T.severity_badge("low", width=12)
        assert len(badge.plain) == 12

    def test_badge_label_false_is_shape_only(self):
        badge = T.severity_badge("high", label=False)
        assert "HIGH" not in badge.plain
        assert badge.plain.strip() == "▲"

    def test_badge_ascii_fallback_on_ascii_console(self):
        """A console whose encoding can't carry Unicode gets ASCII shapes."""
        ascii_file = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        c = Console(file=ascii_file)
        assert T.supports_unicode(c) is False
        badge = T.severity_badge("critical", console=c)
        assert badge.plain.startswith("!!")
        assert "◆" not in badge.plain

    def test_tag_is_markup_safe_string(self):
        tag = T.severity_tag("critical")
        assert tag == "[sev.critical]◆ CRITICAL[/sev.critical]"


# ---------------------------------------------------------------------------
# Glyphs - parity with narration (so the two surfaces never drift)
# ---------------------------------------------------------------------------


class TestGlyphParity:
    def test_process_glyphs_match_narration_exactly(self):
        pairs = [
            (T.GLYPH_ENGAGE, N.GLYPH_ENGAGE),
            (T.GLYPH_COMPLETE, N.GLYPH_COMPLETE),
            (T.GLYPH_ACCEPT, N.GLYPH_ACCEPT),
            (T.GLYPH_REFUTE, N.GLYPH_REFUTE),
            (T.GLYPH_EVENT, N.GLYPH_EVENT),
            (T.GLYPH_SNAP, N.GLYPH_SNAP),
            (T.GLYPH_ALERT, N.GLYPH_ALERT),
        ]
        for theme_glyph, narration_glyph in pairs:
            assert theme_glyph == narration_glyph

    def test_glyph_lookup_and_ascii_fold(self):
        assert T.glyph("accept", ascii_only=False) == "✓"
        assert T.glyph("accept", ascii_only=True) == "+"
        assert T.glyph("does-not-exist") == ""


# ---------------------------------------------------------------------------
# Console factory + environment probes (console-authoritative)
# ---------------------------------------------------------------------------


class TestConsoleFactory:
    def test_build_console_installs_theme(self):
        c = T.build_console(force_terminal=True, color_system="truecolor")
        # A semantic style name resolves on the themed console.
        assert c.get_style("sev.critical") is not None
        assert c.get_style("accent") is not None

    @pytest.mark.parametrize(
        "color_system,expected",
        [("truecolor", "truecolor"), ("256", "256"), ("standard", "standard")],
    )
    def test_console_tier(self, color_system, expected):
        c = T.build_console(force_terminal=True, color_system=color_system)
        assert T.console_tier(c) == expected

    def test_console_tier_none_when_not_terminal(self):
        c = T.build_console()  # no force_terminal -> not a tty under pytest
        assert T.console_tier(c) == "none"

    def test_standard_tier_pushes_16color_override(self):
        std = T.build_console(force_terminal=True, color_system="standard")
        tc = T.build_console(force_terminal=True, color_system="truecolor")
        # Observe the actual push: a semantic style resolves to a DIFFERENT
        # concrete colour on the standard-tier console (the 16-colour override)
        # than on truecolor - proving build_console pushed STANDARD_THEME.
        assert std.get_style("accent").color != tc.get_style("accent").color
        # And the override's severity ramp stays 5 distinct colours (no collapse).
        ramp = {str(std.get_style(f"sev.{k}").color) for k in T.SEVERITY_ORDER}
        assert len(ramp) == len(T.SEVERITY_ORDER)

    def test_color_enabled(self):
        on = T.build_console(force_terminal=True, color_system="truecolor")
        assert T.color_enabled(on) is True
        off = T.build_console(force_terminal=True, no_color=True)
        assert T.color_enabled(off) is False

    def test_is_plain_env(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert T.is_plain() is True
        monkeypatch.delenv("NO_COLOR", raising=False)


# ---------------------------------------------------------------------------
# Markup-injection safety - the crash class this kit exists to kill
# ---------------------------------------------------------------------------


class TestMarkupSafety:
    @pytest.mark.parametrize(
        "helper", [T.success, T.warn, T.error, T.info, T.muted, T.accent]
    )
    def test_helpers_return_text(self, helper):
        assert isinstance(helper("x"), Text)

    def test_bracketed_free_text_preserved(self):
        out = _render(T.error("Reads [/etc/passwd] via [bracket] injection"))
        assert "/etc/passwd" in out
        assert "[bracket]" in out

    def test_field_and_line_preserve_brackets(self):
        assert "[x]" in _render(T.field("buf[x]"))
        assert "[/]" in _render(T.line("close [/] tag"))

    def test_escape_is_reexported(self):
        assert T.escape("[red]") == r"\[red]"

    def test_kv_table_wraps_free_text(self):
        out = _render(T.kv_table([("path", "svc/[cfg]/x.py")]))
        assert "[cfg]" in out


# ---------------------------------------------------------------------------
# Structural components render on the themed console
# ---------------------------------------------------------------------------


class TestComponents:
    def test_kv_table_renders(self):
        out = _render(T.kv_table([("files", "12"), ("path", "a/b.py")]))
        assert "files" in out and "12" in out

    def test_data_table_renders(self):
        tbl = T.data_table(["ID", "SEV"])
        tbl.add_row(T.field("1"), T.severity_cell("high"))
        out = _render(tbl)
        assert "HIGH" in out

    def test_section_rule_renders_title(self):
        out = _render(T.section_rule("FINDINGS"))
        assert "FINDINGS" in out

    def test_panel_renders_each_kind(self):
        for kind in ("info", "accent", "success", "warn", "danger"):
            out = _render(T.panel("body", title=kind, kind=kind))
            assert "body" in out

    def test_status_mark_renders(self):
        for st in ("ok", "warn", "err", "skip"):
            mark = T.status_mark(st)
            assert isinstance(mark, Text)
        # Semantic style names are encoding-independent.
        assert T.status_mark("ok").style == "success"
        assert T.status_mark("err").style == "danger"

    def test_status_mark_ascii_fallback(self):
        """On a console whose encoding can't carry Unicode, marks fold to ASCII."""
        ascii_file = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        c = Console(file=ascii_file)
        assert T.supports_unicode(c) is False
        assert T.status_mark("ok", console=c).plain == "+"
        assert T.status_mark("err", console=c).plain == "x"
        assert T.status_mark("warn", console=c).plain == "!"

    def test_framed_table_has_rounded_frame(self):
        from rich import box

        tbl = T.framed_table(["SESSION", "SEV"], title="Audit sessions", caption="1 row")
        assert tbl.box is box.ROUNDED
        tbl.add_row(T.field("audit-x"), T.severity_cell("high"))
        out = _render(tbl)
        assert "Audit sessions" in out and "HIGH" in out

    def test_brand_banner_flat_without_truecolor(self):
        # No console (or a lower tier) -> flat brand tone; content preserved.
        b = T.brand_banner("ACUARIO\n  tagline")
        assert isinstance(b, Text)
        assert b.style == "brand"
        assert "ACUARIO" in b.plain

    def test_brand_banner_gradient_on_truecolor(self):
        c = T.build_console(force_terminal=True, color_system="truecolor")
        b = T.brand_banner("███\n██╗\n  tagline", console=c)
        # Gradient paints per-span styles (not one flat "brand"); content intact.
        assert b.style != "brand"
        assert "tagline" in b.plain
        assert len(b.spans) >= 2


# ---------------------------------------------------------------------------
# Colour-science: documented 256 indices are exact; names are valid
# ---------------------------------------------------------------------------


class TestColorScience:
    def test_tokens_256_exact(self):
        from rich.color import Color, ColorSystem

        for token, hexv in T.PALETTE.items():
            idx = Color.parse(hexv).downgrade(ColorSystem.EIGHT_BIT).number
            assert idx == T.TOKENS_256[token], f"{token}: Rich={idx} documented={T.TOKENS_256[token]}"

    def test_all_named_colors_are_valid_rich_colors(self):
        from rich.color import Color

        for name in T.RICH_COLOR_NAMES:
            Color.parse(name)  # raises if invalid

    def test_standard16_names_are_valid(self):
        from rich.color import Color

        for name in T.STANDARD_16.values():
            Color.parse(name)
