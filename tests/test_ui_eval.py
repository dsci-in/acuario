"""Tests for the eval command's rendering: native scoreboard on a terminal,
raw markdown when piped (E13/E31/E32)."""

from __future__ import annotations

import io
import re

from acuario.scanner.eval import EvalReport
from acuario.ui import theme
from acuario.ui.commands import eval_cmd as E


class _CLI:
    def __init__(self, console):
        self.console = console


def _report(**kw):
    base = dict(
        session_id="audit-x",
        endpoint_label="qwen",
        total_findings=10,
        verified_findings=8,
        by_source={"analyzer": {"total": 8, "verified": 7}, "critic": {"total": 2, "verified": 1}},
        skeptic_distribution={"accepted": 8, "refuted": 2},
        debate={},
        agreement={},
        severity_recalibration={},
        evidence_levels={},
        labeled={},
    )
    base.update(kw)
    return EvalReport(**base)


def _plain(buf: io.StringIO) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())


def test_rate_style_bands():
    assert E._rate_style(0.9) == "success"
    assert E._rate_style(0.5) == "warn"
    assert E._rate_style(0.2) == "danger"


def test_render_native_shows_sections_and_rates():
    buf = io.StringIO()
    console = theme.build_console(file=buf, force_terminal=True, no_color=True, width=100)
    E._render_native(_CLI(console), _report())
    out = _plain(buf)
    assert "eval · audit-x" in out
    assert "verified-rate by source" in out
    assert "analyzer" in out and "87.5%" in out  # 7/8
    assert "skeptic gate" in out


def test_emit_report_native_on_terminal():
    buf = io.StringIO()
    console = theme.build_console(file=buf, force_terminal=True, no_color=True, width=100)
    E._emit_report(_CLI(console), _report())
    assert "verified-rate by source" in _plain(buf)  # framed render, not raw markdown


def test_emit_report_raw_markdown_when_piped(capsys):
    buf = io.StringIO()
    console = theme.build_console(file=buf, no_color=True)  # not a tty -> is_terminal False
    E._emit_report(_CLI(console), _report())
    out = capsys.readouterr().out  # raw markdown goes to stdout, not the console
    assert out.lstrip().startswith("#")  # markdown header, not box-art


def test_resolve_session_dir_db_fallback(tmp_path, monkeypatch):
    # Regression (QA): eval resolves a session from any cwd via the DB's recorded
    # repo path when the session predates the path index, and self-heals the index
    # so the next lookup is direct. Was: "Session directory not found".
    import sqlite3
    from pathlib import Path

    home = tmp_path / "home"
    (home / "scanner").mkdir(parents=True)
    monkeypatch.setenv("ACUARIO_HOME", str(home))

    repo = tmp_path / "myrepo"
    sid = "audit-fallback01"
    sess = repo / "results" / "scanner" / sid
    sess.mkdir(parents=True)
    (sess / "findings.json").write_text('{"findings": []}')

    db = home / "scanner" / "historical_findings.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE findings (campaign_session_id TEXT, repo_url TEXT, verified INT)")
    conn.execute("INSERT INTO findings VALUES (?, ?, 0)", (sid, str(repo)))
    conn.commit()
    conn.close()

    monkeypatch.chdir(tmp_path)  # a neutral cwd: no ./results, nothing in the index

    class _Args:
        results_dir = None

    resolved = E._resolve_session_dir(_Args(), sid)
    assert Path(resolved).resolve() == sess.resolve()

    from acuario.scanner.session_index import lookup_session_path

    assert lookup_session_path(sid).resolve() == sess.resolve()  # index self-healed
