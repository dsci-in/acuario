"""Tests for the session-path index: records where each audit's results live so
inspect/eval can find them from any cwd. All tests isolate the index to tmp."""

from __future__ import annotations

from acuario.scanner import session_index as SI


def _isolate(monkeypatch, tmp_path):
    idx = tmp_path / "session_paths.json"
    monkeypatch.setattr(SI, "_index_path", lambda: idx)
    return idx


def test_record_and_lookup(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    d = tmp_path / "results" / "sess1"
    d.mkdir(parents=True)
    SI.record_session_path("sess1", d)
    assert SI.lookup_session_path("sess1") == d.resolve()
    assert SI.lookup_session_path("missing") is None


def test_lookup_none_when_dir_gone(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    d = tmp_path / "gone"
    d.mkdir()
    SI.record_session_path("s", d)
    d.rmdir()
    assert SI.lookup_session_path("s") is None  # recorded, but no longer on disk


def test_record_best_effort_on_empty_id(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    SI.record_session_path("", tmp_path)  # no-op, must not raise
    assert SI.lookup_session_path("") is None


def test_corrupt_index_degrades(monkeypatch, tmp_path):
    idx = _isolate(monkeypatch, tmp_path)
    idx.write_text("{not valid json")
    assert SI.lookup_session_path("x") is None  # corrupt -> None, no raise
    d = tmp_path / "r"
    d.mkdir()
    SI.record_session_path("x", d)  # record still works (overwrites)
    assert SI.lookup_session_path("x") == d.resolve()
