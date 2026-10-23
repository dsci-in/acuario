"""Tests for acuario/ui/narration.py (Phase F)."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

from acuario.ui.narration import (
    GLYPH_ACCEPT,
    GLYPH_ALERT,
    GLYPH_COMPLETE,
    GLYPH_ENGAGE,
    GLYPH_REFUTE,
    AuditNarrator,
    LabStats,
    NarrationFormatter,
    _format_duration,
    _stage_from_logger,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(msg: str, logger_name: str = "acuario.scanner.pool") -> logging.LogRecord:
    record = logging.LogRecord(
        name=logger_name,
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=msg,
        args=(),
        exc_info=None,
    )
    return record


def _fmt(msg: str, logger_name: str = "acuario.scanner.pool") -> str:
    formatter = NarrationFormatter()
    record = _make_record(msg, logger_name)
    return formatter.format(record)


# ---------------------------------------------------------------------------
# Tests: NarrationFormatter message transforms
# ---------------------------------------------------------------------------


class TestMessageTransforms:
    def test_analyzer_starting_becomes_engage(self):
        msg = "Analyzer starting for app/cart.php"
        result = _fmt(msg)
        assert GLYPH_ENGAGE in result
        assert "engage" in result
        assert "app/cart.php" in result

    def test_analyzer_completed_becomes_complete_with_findings(self):
        msg = "Analyzer finish for app/login.php after 18 steps findings=3"
        result = _fmt(msg)
        assert GLYPH_COMPLETE in result
        assert "app/login.php" in result
        assert "3 findings" in result
        assert "18 steps" in result

    def test_prioritizer_chunk_becomes_ranked(self):
        msg = "Prioritizer chunk 1/1 completed in 51.2s"
        result = _fmt(msg)
        assert "prioritize" in result
        assert "ranked" in result

    def test_preprocessor_enumerated_files(self):
        msg = "Preprocessor: enumerated 28 files"
        result = _fmt(msg)
        assert "preprocess" in result
        assert "28" in result

    def test_behavior_alert_becomes_ptrace_vocab(self):
        msg = "Behavior alert [warning]: /etc/passwd matched 'network_access_attempt'"
        result = _fmt(msg, logger_name="acuario.scanner.behavior_monitor")
        assert GLYPH_ALERT in result or "[ptrace]" in result or "ptrace" in result

    def test_verified_true_becomes_accept_glyph(self):
        msg = "Verified 3/97: analyzer-abc (verified=True)"
        result = _fmt(msg)
        assert GLYPH_ACCEPT in result
        assert "analyzer-abc" in result

    def test_verified_false_becomes_refute_glyph(self):
        msg = "Verified 5/97: analyzer-xyz (verified=False)"
        result = _fmt(msg)
        assert GLYPH_REFUTE in result
        assert "analyzer-xyz" in result

    def test_already_formatted_passes_through_unchanged(self):
        """Messages that already start with [stage] should not be double-wrapped."""
        msg = "[skeptic] ✓ accept analyzer-abc123"
        result = _fmt(msg)
        assert result == msg

    def test_lab_sandbox_prefix_passes_through(self):
        msg = "[lab/sandbox] ◇ snapshot 'pre-exploit' → acuario-snap-abc:xyz"
        result = _fmt(msg)
        assert result == msg

    def test_critic_prefix_passes_through(self):
        msg = "[critic] ▸ added 2 low-confidence leads from app/cart.php trajectory"
        result = _fmt(msg)
        assert result == msg

    def test_orchestrate_prefix_passes_through(self):
        msg = "[orchestrate] ▸ emitted 3 subsystem plans from findings pool"
        result = _fmt(msg)
        assert result == msg

    def test_unknown_message_gets_stage_prefix_from_logger(self):
        """Messages with no match should get a stage prefix derived from logger name."""
        msg = "Some random message in the analyzer pipeline"
        result = _fmt(msg, logger_name="acuario.analyze.pool")
        # Should still produce readable output, not crash
        assert isinstance(result, str)
        assert msg in result or "analyze" in result


# ---------------------------------------------------------------------------
# Tests: _stage_from_logger
# ---------------------------------------------------------------------------


class TestStageFromLogger:
    def test_preprocess_logger(self):
        assert _stage_from_logger("acuario.preprocess.preprocessor") == "preprocess"

    def test_analyze_logger(self):
        assert _stage_from_logger("acuario.analyze.pool") == "analyze"

    def test_skeptic_logger(self):
        assert _stage_from_logger("acuario.skeptic.gate") == "skeptic"

    def test_lab_sandbox_logger(self):
        assert _stage_from_logger("acuario.lab.sandbox.snapshot") == "lab/sandbox"

    def test_behavior_logger(self):
        # F3: the regex BehaviorMonitor's logger now maps to [behavior],
        # not [ptrace] - [ptrace] is reserved for real syscall events
        # from the PtraceBehaviorMonitor in acuario.lab.sandbox.behavior.
        assert _stage_from_logger("acuario.scanner.behavior_monitor") == "behavior"

    def test_recall_logger(self):
        assert _stage_from_logger("acuario.scanner.mechanism_memory") == "recall"

    def test_unknown_logger_returns_empty(self):
        assert _stage_from_logger("some.other.module") == ""


# ---------------------------------------------------------------------------
# Tests: ASCII fallback
# ---------------------------------------------------------------------------


class TestAsciiFallback:
    def test_glyphs_replaced_in_ascii_mode(self):
        formatter = NarrationFormatter(ascii_fallback=True)
        record = _make_record("[analyze:A] ◐ engage app.php")
        result = formatter.format(record)
        assert GLYPH_ENGAGE not in result
        assert "(engage)" in result

    def test_complete_glyph_replaced(self):
        formatter = NarrationFormatter(ascii_fallback=True)
        record = _make_record("[analyze:A] ● app.php → 3 findings")
        result = formatter.format(record)
        assert GLYPH_COMPLETE not in result
        assert "(done)" in result


# ---------------------------------------------------------------------------
# Tests: _format_duration
# ---------------------------------------------------------------------------


class TestFormatDuration:
    def test_seconds_only(self):
        assert _format_duration(45.0) == "45.0s"

    def test_minutes(self):
        result = _format_duration(125.0)
        assert "m" in result
        assert "2m" in result

    def test_hours(self):
        result = _format_duration(3661.0)
        assert "h" in result
        assert "1h" in result


# ---------------------------------------------------------------------------
# Tests: AuditNarrator.print_header
# ---------------------------------------------------------------------------


class TestPrintHeader:
    def _make_narrator(self):
        console = MagicMock()
        return AuditNarrator(console), console

    @staticmethod
    def _collect_text(console: MagicMock) -> str:
        """Pull all renderable text out of console.print() calls.

        Phase I prints the header as a single rich.panel.Panel instance
        whose body string lives at ``.renderable``.  Stringifying the
        MagicMock call_args yields ``"call(<Panel ...>)"`` - no body text.
        This helper extracts the body string from any Panel-shaped arg so
        tests can assert on its content the same way they could when each
        line was its own print() call.
        """
        out: list[str] = []
        for call in console.print.call_args_list:
            for arg in call.args:
                # rich.panel.Panel exposes `.title` (TextOrStr) and
                # `.renderable` (the body string we passed).
                title = getattr(arg, "title", None)
                renderable = getattr(arg, "renderable", None)
                if title is not None:
                    out.append(str(title))
                if renderable is not None:
                    out.append(str(renderable))
                if title is None and renderable is None:
                    out.append(str(arg))
        return "\n".join(out)

    def test_header_prints_session_id(self):
        narrator, console = self._make_narrator()
        narrator.print_header(
            session_id="audit-abc123",
            target="/home/user/project",
            depth="standard",
            endpoint_label="qwen3.6-coder via http://localhost:8000/v1",
        )
        text = self._collect_text(console)
        assert "audit-abc123" in text

    def test_header_shows_pipeline_stages(self):
        # Render on a real themed console (not the un-rendered Panel markup), so
        # this actually proves the [skeptic]/[orchestrate] labels survive to the
        # terminal instead of being eaten as Rich markup tags.
        from io import StringIO

        from acuario.ui.theme import build_console

        buf = StringIO()
        narrator = AuditNarrator(
            build_console(file=buf, force_terminal=True, no_color=True, width=100)
        )
        narrator.print_header(session_id="audit-xyz", target="/tmp/repo", depth="deep")
        text = buf.getvalue()
        assert "preprocess" in text
        # Brackets must render literally - before the escape fix they were parsed
        # away and these labels vanished from the rendered header.
        assert "[skeptic]" in text
        assert "[orchestrate]" in text

    def test_header_shows_lab_flags(self):
        narrator, console = self._make_narrator()
        narrator.print_header(
            session_id="audit-flags",
            target=".",
            depth="fast",
            lab_flags={
                "skeptic": True,
                "critic": False,
                "orchestrator": True,
                "sandbox_snapshots": False,
                "ptrace_monitor": True,
            },
        )
        text = self._collect_text(console)
        assert "ON" in text
        assert "OFF" in text


# ---------------------------------------------------------------------------
# Tests: AuditNarrator.stage_banner
# ---------------------------------------------------------------------------


class TestStageBanner:
    def test_banner_prints_stage_name(self):
        console = MagicMock()
        narrator = AuditNarrator(console)
        narrator.stage_banner("skeptic gate")
        calls = [str(c) for c in console.print.call_args_list]
        assert any("skeptic gate" in c for c in calls)

    def test_duplicate_banner_not_reprinted(self):
        console = MagicMock()
        narrator = AuditNarrator(console)
        narrator.stage_banner("analyze")
        narrator.stage_banner("analyze")
        # Only printed once
        assert console.print.call_count == 1


# ---------------------------------------------------------------------------
# Tests: AuditNarrator.print_summary
# ---------------------------------------------------------------------------


class TestPrintSummary:
    def _make_result(self, **kwargs):
        result = MagicMock()
        result.session_id = "audit-summary-test"
        result.duration_seconds = 3720.0
        result.files_ranked = 25
        result.files_hunted = 25
        result.findings = [
            {
                "id": "f1",
                "severity": "critical",
                "file": "a.php",
                "line_number": 1,
                "description": "sqli",
            }
        ]
        result.verified_findings = result.findings
        result.critical_count = 1
        result.high_count = 0
        result.input_tokens = 1_500_000
        result.output_tokens = 300_000
        result.is_self_hosted_endpoint = False
        result.endpoint_label = "test-model"
        result.cost_usd = 0.5
        result.reference_cost_opus_usd = 50.0
        result.reference_cost_gpt_usd = 15.0
        result.spent_per_tier = {}
        result.output_paths = {}
        for k, v in kwargs.items():
            setattr(result, k, v)
        return result

    def _render(self, result, **kw) -> str:
        """Render the summary to a real themed console and return plain text, so
        assertions see content that now lives inside kv_tables / section rules
        (a MagicMock's str() would hide text wrapped in Rich renderables)."""
        import io
        import re

        from acuario.ui import theme

        buf = io.StringIO()
        console = theme.build_console(file=buf, force_terminal=True, no_color=True, width=100)
        AuditNarrator(console).print_summary(result=result, **kw)
        return re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())

    def test_summary_shows_session_id(self):
        console = MagicMock()
        narrator = AuditNarrator(console)
        result = self._make_result()
        narrator.print_summary(result=result)
        calls = [str(c) for c in console.print.call_args_list]
        assert any("audit-summary-test" in c for c in calls)

    def test_summary_shows_investigation_block(self):
        out = self._render(self._make_result())
        assert "INVESTIGATION" in out
        assert "files ranked" in out

    def test_summary_shows_lab_block_when_stats_present(self):
        lab = LabStats(
            skeptic_accepted=73,
            skeptic_refuted=24,
            critic_leads=11,
            critic_verified=3,
            orchestrator_plans=4,
            orchestrator_findings=2,
        )
        out = self._render(self._make_result(), lab_stats=lab)
        assert "LAB" in out
        assert "73" in out  # skeptic accepted
        assert "24" in out  # skeptic refuted

    def test_summary_hides_lab_block_when_no_stats(self):
        out = self._render(self._make_result(), lab_stats=LabStats())
        assert "LAB" not in out

    def test_summary_shows_self_hosted_zero_cost(self):
        out = self._render(self._make_result(is_self_hosted_endpoint=True))
        assert "$0.00" in out

    def test_summary_shows_next_inspect_command(self):
        console = MagicMock()
        narrator = AuditNarrator(console)
        result = self._make_result()
        narrator.print_summary(result=result)
        calls = [str(c) for c in console.print.call_args_list]
        assert any("inspect" in c for c in calls)
        assert any("audit-summary-test" in c for c in calls)

    def test_summary_shows_top_findings(self):
        console = MagicMock()
        narrator = AuditNarrator(console)
        result = self._make_result()
        narrator.print_summary(result=result)
        calls = [str(c) for c in console.print.call_args_list]
        assert any("TOP FINDINGS" in c for c in calls)
        assert any("sqli" in c.lower() for c in calls)

    def test_summary_shows_duration_in_hours(self):
        console = MagicMock()
        narrator = AuditNarrator(console)
        result = self._make_result(duration_seconds=30780.0)  # ~8h 33m
        narrator.print_summary(result=result)
        calls = [str(c) for c in console.print.call_args_list]
        assert any("h" in c and "m" in c for c in calls)


# ---------------------------------------------------------------------------
# Tests: get_log_formatter
# ---------------------------------------------------------------------------


class TestGetLogFormatter:
    def test_returns_narration_formatter_instance(self):
        formatter = AuditNarrator.get_log_formatter()
        assert isinstance(formatter, NarrationFormatter)

    def test_returned_formatter_transforms_messages(self):
        formatter = AuditNarrator.get_log_formatter()
        record = _make_record("Analyzer starting for app.php")
        result = formatter.format(record)
        assert GLYPH_ENGAGE in result
        assert "engage" in result


# ---------------------------------------------------------------------------
# Phase I tests: colorize / banner_on_stage_change / indent_auxiliary_stages
# ---------------------------------------------------------------------------


class TestColorize:
    """Phase I - ANSI color wrapping of stage prefixes and glyphs."""

    def _make_colorized_formatter(self) -> NarrationFormatter:
        # Disable NO_COLOR for tests so the env doesn't suppress coloring.
        import os

        os.environ.pop("NO_COLOR", None)
        return NarrationFormatter(colorize=True, banner_on_stage_change=False)

    def test_colorize_wraps_stage_prefix_in_ansi(self):
        fmt = self._make_colorized_formatter()
        rec = _make_record("[analyze:surface] ◐ engage app.py")
        result = fmt.format(rec)
        # Stage prefix should be ANSI-wrapped
        assert "\x1b[" in result
        # Reset code present
        assert "\x1b[0m" in result
        # Content survives
        assert "[analyze:surface]" in result

    def test_colorize_colors_accept_glyph_green(self):
        fmt = self._make_colorized_formatter()
        rec = _make_record("[review] ✓ analyzer-abc (3/10)")
        result = fmt.format(rec)
        # Green ANSI \x1b[32m should wrap the ✓
        assert "\x1b[32m" in result
        assert GLYPH_ACCEPT in result

    def test_colorize_colors_refute_glyph_red(self):
        fmt = self._make_colorized_formatter()
        rec = _make_record("[review] ✗ analyzer-bad (4/10) insufficient")
        result = fmt.format(rec)
        assert "\x1b[31m" in result
        assert GLYPH_REFUTE in result

    def test_no_color_env_disables_colorization(self):
        import os

        os.environ["NO_COLOR"] = "1"
        try:
            # Construct AFTER setting NO_COLOR so __init__ picks it up
            fmt = NarrationFormatter(colorize=True)
            rec = _make_record("[analyze:surface] ◐ engage app.py")
            result = fmt.format(rec)
            assert "\x1b[" not in result, "ANSI codes leaked through NO_COLOR"
        finally:
            os.environ.pop("NO_COLOR", None)

    def test_file_handler_never_colorizes(self):
        """get_log_formatter(for_file=True) must produce plain output even
        when callers don't explicitly opt out of color."""
        fmt = AuditNarrator.get_log_formatter(for_file=True)
        rec = _make_record("[skeptic] ✗ refute analyzer-1")
        result = fmt.format(rec)
        assert "\x1b[" not in result


class TestBannerOnStageChange:
    """Phase I - formatter prepends a stage banner when the [stage]
    prefix changes between consecutive log records."""

    def _make_banner_formatter(self) -> NarrationFormatter:
        return NarrationFormatter(
            colorize=False,  # easier to assert without ANSI noise
            banner_on_stage_change=True,
        )

    def test_first_message_has_no_banner(self):
        fmt = self._make_banner_formatter()
        out = fmt.format(_make_record("[preprocess] ▸ enumerated 5 files"))
        # No banner before the very first stage transition
        assert "── preprocess ──" not in out

    def test_banner_emitted_when_stage_changes(self):
        fmt = self._make_banner_formatter()
        _ = fmt.format(_make_record("[preprocess] ▸ enumerated 5 files"))
        out = fmt.format(_make_record("[analyze:surface] ◐ engage a.py"))
        # The new stage triggers a banner
        assert "── analyze ──" in out

    def test_banner_dedupes_sub_tiers(self):
        """[analyze:surface] and [analyze:depth] should NOT trigger a fresh
        banner - they're the same top-level stage."""
        fmt = self._make_banner_formatter()
        _ = fmt.format(_make_record("[preprocess] ▸ start"))
        _ = fmt.format(_make_record("[analyze:surface] ◐ engage a.py"))
        out2 = fmt.format(_make_record("[analyze:depth] ◐ engage b.py"))
        # Already in analyze stage; no new banner
        assert "── analyze ──" not in out2

    def test_banner_omitted_for_messages_without_stage(self):
        fmt = self._make_banner_formatter()
        _ = fmt.format(_make_record("[preprocess] ▸ start"))
        out = fmt.format(_make_record("plain unbracketed line"))
        # Without a stage prefix the formatter can't infer a transition
        assert "── " not in out


class TestAuxiliaryIndent:
    """Phase I - recall/context lines get 2-space indent on the console."""

    def test_recall_line_indented(self):
        fmt = NarrationFormatter(
            colorize=False,
            indent_auxiliary_stages=True,
        )
        rec = _make_record("[recall] injected 3 prior mechanisms")
        result = fmt.format(rec)
        assert result.startswith("  [recall]")

    def test_context_line_indented(self):
        fmt = NarrationFormatter(
            colorize=False,
            indent_auxiliary_stages=True,
        )
        rec = _make_record("[context] pre-seeded with 1 section")
        result = fmt.format(rec)
        assert result.startswith("  [context]")

    def test_primary_stage_lines_not_indented(self):
        fmt = NarrationFormatter(
            colorize=False,
            indent_auxiliary_stages=True,
        )
        rec = _make_record("[analyze:surface] ◐ engage app.py")
        result = fmt.format(rec)
        assert result.startswith("[analyze:surface]")
        assert not result.startswith("  [")

    def test_file_handler_does_not_indent(self):
        """audit.log must keep every line at column 0 for grep-friendliness."""
        fmt = AuditNarrator.get_log_formatter(for_file=True)
        rec = _make_record("[recall] injected 3 mechanisms")
        result = fmt.format(rec)
        assert result.startswith("[recall]")
        assert not result.startswith("  ")


class TestPanelHeader:
    """Phase I - print_header() emits a rich.panel.Panel instance."""

    def test_header_emits_rich_panel(self):
        """The middle call (after the leading blank) should be a Panel."""
        from rich.panel import Panel

        console = MagicMock()
        narrator = AuditNarrator(console)
        narrator.print_header(
            session_id="audit-X",
            target="/tmp/r",
            depth="standard",
        )
        # At least one of the print() args is a Panel instance
        panel_calls = [
            call
            for call in console.print.call_args_list
            if call.args and isinstance(call.args[0], Panel)
        ]
        assert len(panel_calls) == 1, (
            f"expected exactly one Panel print call, got {len(panel_calls)}"
        )
        panel = panel_calls[0].args[0]
        # Panel title carries the session id
        assert "audit-X" in str(panel.title)


class TestSummaryMarkupSafety:
    """Regression - print_summary must not crash on finding text with brackets.

    Finding descriptions and file paths are attacker/LLM-influenced free text.
    Before the fix they were interpolated straight into a Rich markup string,
    so a description like ``Reads [/etc/passwd]`` raised ``MarkupError``.  The
    TOP FINDINGS block now renders severity via ``theme.severity_badge`` and
    appends the file/description as plain ``Text`` (never markup-parsed); these
    tests pin that free text survives verbatim and unknown severities fold
    safely.  They use ``build_console`` because the summary now renders theme
    style names, which only resolve on the themed console (the production path).
    """

    @staticmethod
    def _themed_narrator(buf):
        # Themed, but no_color so output is clean plain text for assertions
        # (styles still resolve, so no MissingStyle on rules/components).
        from acuario.ui.theme import build_console

        return AuditNarrator(
            build_console(file=buf, force_terminal=True, no_color=True, width=100)
        )

    @staticmethod
    def _result(findings):
        from types import SimpleNamespace

        return SimpleNamespace(
            session_id="audit-test",
            duration_seconds=12.0,
            files_ranked=3,
            files_hunted=3,
            unique_finding_count=len(findings),
            unique_verified_count=len(findings),
            total_critical_count=1,
            total_high_count=0,
            critical_count=1,
            high_count=0,
            input_tokens=0,
            output_tokens=0,
            endpoint_label="",
            is_self_hosted_endpoint=False,
            cost_usd=0.0,
            output_paths={},
            findings=findings,
        )

    def test_bracketed_description_does_not_crash(self):
        """Square brackets in description/file render as literal text, no raise."""
        from io import StringIO

        buf = StringIO()
        narrator = self._themed_narrator(buf)
        result = self._result(
            [
                {
                    "severity_verified": "critical",
                    "file": "svc/[config]/loader.py",
                    "line_number": 42,
                    "description": "Reads [/etc/passwd] via unescaped [bracket] path",
                }
            ]
        )

        # Would raise rich.errors.MarkupError before the fix.
        narrator.print_summary(result=result, log_file_path="")

        out = buf.getvalue()
        assert "TOP FINDINGS" in out
        # The literal bracketed text survives (not consumed as markup).
        assert "/etc/passwd" in out
        assert "[config]" in out
        # CVD-safe badge: the UPPERCASE label is present alongside the colour.
        assert "CRITICAL" in out

    def test_unknown_severity_folds_to_info(self):
        """A severity outside the ladder folds to INFO - no crash, no bad markup."""
        from io import StringIO

        buf = StringIO()
        narrator = self._themed_narrator(buf)
        result = self._result(
            [
                {
                    "severity": "WEIRD",
                    "file": "a.py",
                    "line_number": 1,
                    "description": "odd severity",
                }
            ]
        )

        narrator.print_summary(result=result, log_file_path="")
        out = buf.getvalue()
        # Unknown severity renders as the INFO badge (theme.normalize_severity).
        assert "INFO" in out
        assert "odd severity" in out
