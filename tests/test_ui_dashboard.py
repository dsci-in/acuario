"""Tests for acuario/ui/dashboard.py - the live audit-progress dashboard.

Covers the pure logic (stage advance, severity tally, spend meter), that the
panel renders on the themed console, that the log handler extracts the stage and
never raises into the run, and that the context manager swaps/restores the
console log handler.
"""

from __future__ import annotations

import io
import logging
import re

from rich.console import Console

from acuario.ui import dashboard as D
from acuario.ui import theme
from acuario.ui.narration import AuditNarrator

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _state(findings=None, *, spend=0.0, budget=None, self_hosted=True) -> D.DashboardState:
    fs = findings if findings is not None else []
    return D.DashboardState(
        session_id="audit-x",
        depth="standard",
        get_findings=lambda: fs,
        get_spend=lambda: spend,
        budget=budget,
        is_self_hosted=self_hosted,
    )


def _render(renderable) -> str:
    # Strip residual ANSI (no_color keeps bold), so content assertions see the
    # text contiguously (e.g. "findings 1" isn't split by a bold code).
    buf = io.StringIO()
    console = theme.build_console(file=buf, force_terminal=True, no_color=True, width=120)
    console.print(renderable)
    return _ANSI.sub("", buf.getvalue())


class TestState:
    def test_note_stage_is_monotonic(self):
        s = _state()
        assert s.stage_idx == 0
        s.note_stage("analyze")
        assert s.stage_idx == D.STAGES.index("analyze")
        s.note_stage("preprocess")  # earlier stage must not move it backwards
        assert s.stage_idx == D.STAGES.index("analyze")
        s.note_stage("report")
        assert s.stage_idx == D.STAGES.index("report")
        s.note_stage("not-a-stage")  # unknown is ignored
        assert s.stage_idx == D.STAGES.index("report")


class TestTally:
    def test_counts_by_severity_excludes_dups_counts_verified(self):
        findings = [
            {"severity": "critical", "verified": True},
            {"severity": "high"},
            {"severity": "high", "severity_verified": "medium"},  # verified -> medium
            {"severity": "low", "duplicate_of": "x"},  # excluded
        ]
        sev, verified = D._tally(_state(findings))
        assert sev["critical"] == 1
        assert sev["high"] == 1
        assert sev["medium"] == 1
        assert sev["low"] == 0
        assert verified == 2  # the verified=True one + the severity_verified one

    def test_tally_is_defensive_on_malformed_findings(self):
        # A None / non-dict entry must be skipped, not raise.
        sev, verified = D._tally(_state([None, {"severity": "high"}, "oops"]))
        assert sev["high"] == 1
        assert verified == 0

    def test_tally_on_raising_getter(self):
        def _boom():
            raise RuntimeError("snapshot unavailable")

        st = D.DashboardState("a", "standard", get_findings=_boom, get_spend=lambda: 0.0)
        sev, verified = D._tally(st)  # must swallow and return zeros
        assert sum(sev.values()) == 0 and verified == 0


class TestRender:
    def test_build_dashboard_renders(self):
        out = _render(D.build_dashboard(_state([{"severity": "critical", "verified": True}])))
        assert "preprocess" in out.lower()  # shown friendly-cased ("Preprocess")
        assert "findings 1" in out
        assert "CRITICAL".lower() in out.lower() or "◆1" in out
        assert "self-hosted" in out

    def test_self_hosted_shows_zero(self):
        assert "$0.00" in _render(D.build_dashboard(_state(spend=0.0, self_hosted=True)))

    def test_budget_bar_shows_percent(self):
        out = _render(D.build_dashboard(_state(spend=6.0, budget=12.0, self_hosted=False)))
        assert "$6.00" in out and "50%" in out

    def test_unlimited_budget(self):
        out = _render(D.build_dashboard(_state(spend=3.0, budget=None, self_hosted=False)))
        assert "unlimited" in out

    def test_pipeline_shows_current_stage(self):
        s = _state()
        s.note_stage("analyze")
        out = _render(D.build_dashboard(s))
        assert "analyze" in out.lower()  # shown friendly-cased ("Analyze")

    def test_mark_complete_lights_every_stage(self):
        # After a clean run the final frame must read "complete" with every stage
        # ticked - not freeze on whichever stage last logged (e.g. review while
        # exploit/report ran but logged under [ptrace]/[analyze]).
        s = _state()
        s.note_stage("review")
        s.mark_complete()
        out = _render(D.build_dashboard(s))
        assert "complete" in out.lower()  # title reads "Complete"
        assert out.count("✓") == len(D.STAGES)  # every stage ticked
        assert "◐" not in out  # nothing left "in progress"


class _FakeLive:
    def __init__(self, console):
        self.console = console
        self.updates = 0

    def update(self, renderable, *, refresh=False):
        self.updates += 1


class TestLogHandler:
    def _handler(self, state):
        buf = io.StringIO()
        console = theme.build_console(file=buf, force_terminal=True, no_color=True, width=120)
        fmt = AuditNarrator.get_log_formatter(colorize=False, banner_on_stage_change=False)
        return D.DashboardLogHandler(_FakeLive(console), state, fmt), buf

    def _record(self, name, msg):
        return logging.LogRecord(name, logging.INFO, "", 0, msg, (), None)

    def test_extracts_stage_and_prints_line(self):
        state = _state()
        handler, buf = self._handler(state)
        handler.emit(self._record("acuario.scanner.pool", "Analyzer pool completed with 3 findings"))
        assert state.stage_idx >= D.STAGES.index("analyze")
        assert "findings" in buf.getvalue()
        # The handler prints + advances the stage; the panel itself is redrawn by
        # Rich's auto-refresh, not by the handler.

    def test_never_raises_on_bad_record(self):
        state = _state()
        handler, _ = self._handler(state)
        # A record whose %-format args are broken must not raise out of emit().
        bad = logging.LogRecord("x", logging.INFO, "", 0, "bad %s %s", ("only-one",), None)
        handler.emit(bad)  # no exception


class TestLiveContext:
    def test_swaps_then_restores_console_handler(self):
        root = logging.getLogger()
        sh = logging.StreamHandler(io.StringIO())
        root.addHandler(sh)
        try:
            console = theme.build_console(file=io.StringIO(), force_terminal=True, no_color=True)
            fmt = AuditNarrator.get_log_formatter(colorize=False, banner_on_stage_change=False)
            with D.live_dashboard(console, _state(), formatter=fmt):
                # during: the plain StreamHandler is detached, ours is attached
                assert sh not in root.handlers
                assert any(isinstance(h, D.DashboardLogHandler) for h in root.handlers)
            # after: restored, ours removed
            assert sh in root.handlers
            assert not any(isinstance(h, D.DashboardLogHandler) for h in root.handlers)
        finally:
            root.removeHandler(sh)

    def test_file_handler_is_left_attached(self):
        root = logging.getLogger()
        fh = logging.FileHandler("/dev/null")
        root.addHandler(fh)
        try:
            console = theme.build_console(file=io.StringIO(), force_terminal=True, no_color=True)
            fmt = AuditNarrator.get_log_formatter(colorize=False, banner_on_stage_change=False)
            with D.live_dashboard(console, _state(), formatter=fmt):
                assert fh in root.handlers  # FileHandlers (audit.log) stay attached
        finally:
            root.removeHandler(fh)
            fh.close()


def test_console_import_available():
    # Guard the public surface the caller relies on.
    assert hasattr(D, "DashboardState")
    assert hasattr(D, "live_dashboard")
    assert isinstance(Console, type)
