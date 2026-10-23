"""Tests for the `acuario history` hub: numbered list + interactive navigation.

The hub walks into `acuario inspect` on a picked number and re-lists when the
inspector pops back (`..`); piped / --ids-only output stays plain for scripting.
"""

from __future__ import annotations

import io
import sys
import types

import acuario.ui.commands.inspect as I
from acuario.ui import theme
from acuario.ui.commands import history as H


class _CLI:
    def __init__(self):
        self.console = theme.build_console(
            file=io.StringIO(), force_terminal=True, no_color=True, width=120
        )


def _rows(n=3):
    return [
        {
            "sid": f"audit-{i}",
            "repo_url": f"/repo/app{i}",
            "total": i,
            "verified": 0,
            "judged": 0,
            "started": 0,
            "last_touched": 0,
        }
        for i in range(1, n + 1)
    ]


def _args(ids_only=False, limit=None):
    return types.SimpleNamespace(repo=None, ids_only=ids_only, limit=limit)


def test_ellipsize_tail_keeps_the_end():
    out = H._ellipsize_tail("/home/acuario1/targets/App_6", 12)
    assert out.startswith("…") and out.endswith("App_6") and len(out) == 12
    assert H._ellipsize_tail("short", 12) == "short"  # no change when it fits


def test_hub_opens_picked_session_then_quits(monkeypatch):
    monkeypatch.setattr(H, "_fetch_rows", lambda c, a: _rows(3))
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(I, "_resolve_results_dir", lambda d: "/tmp/nope")
    monkeypatch.setattr(H, "_render_table", lambda *a, **k: None)

    opened: list[str] = []

    def _fake_open(cli, sid, results_dir=None, from_hub=False):
        opened.append(sid)
        assert from_hub is True
        return "quit"

    monkeypatch.setattr(I, "open_session", _fake_open)
    picks = iter([2])
    monkeypatch.setattr(H, "_prompt_pick", lambda *a, **k: next(picks, None))

    H.handle(_CLI(), _args())
    assert opened == ["audit-2"]


def test_hub_relists_after_back(monkeypatch):
    monkeypatch.setattr(H, "_fetch_rows", lambda c, a: _rows(3))
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(I, "_resolve_results_dir", lambda d: "/tmp/nope")
    monkeypatch.setattr(I, "open_session", lambda *a, **k: "back")

    renders: list[int] = []
    monkeypatch.setattr(H, "_render_table", lambda *a, **k: renders.append(1))
    picks = iter([1, None])  # open #1 -> back -> quit
    monkeypatch.setattr(H, "_prompt_pick", lambda *a, **k: next(picks))

    H.handle(_CLI(), _args())
    assert len(renders) == 2  # initial + re-list after back


def test_noninteractive_renders_once_no_prompt(monkeypatch):
    monkeypatch.setattr(H, "_fetch_rows", lambda c, a: _rows(2))
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    monkeypatch.setattr(I, "_resolve_results_dir", lambda d: "/tmp/nope")

    renders: list[int] = []
    monkeypatch.setattr(H, "_render_table", lambda *a, **k: renders.append(1))
    prompted: list[int] = []
    monkeypatch.setattr(H, "_prompt_pick", lambda *a, **k: prompted.append(1))

    H.handle(_CLI(), _args())
    assert len(renders) == 1 and not prompted  # printed once, never prompted


def test_hub_pages_with_global_numbering(monkeypatch):
    # 20 rows, page size 15 -> 2 pages; `n` advances and numbers stay global.
    monkeypatch.setattr(H, "_fetch_rows", lambda c, a: _rows(20))
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(I, "_resolve_results_dir", lambda d: "/tmp/nope")

    seen: list[tuple] = []  # (offset, page, pages, window_len) per render

    def _rt(c, rows, rd, *, offset=0, total=None, page=1, pages=1, filter_text="", fleet=None):
        seen.append((offset, page, pages, len(rows)))

    monkeypatch.setattr(H, "_render_table", _rt)
    opened: list[str] = []
    monkeypatch.setattr(
        I, "open_session", lambda c, sid, **k: (opened.append(sid), "quit")[1]
    )
    actions = iter(["next", 16])  # page to 2, then open global #16
    monkeypatch.setattr(H, "_prompt_pick", lambda c, lo, hi, has_pages=False: next(actions))

    H.handle(_CLI(), _args())
    assert seen[0][:3] == (0, 1, 2)  # page 1 starts at offset 0
    assert seen[1][:3] == (15, 2, 2)  # page 2 starts at offset 15
    assert opened == ["audit-16"]  # global index 16 -> rows[15]


def test_fleet_totals_sums_findings_and_verified():
    rows = [
        {"total": 8, "verified": 7},
        {"total": 4, "verified": 1},
        {"total": None, "verified": None},  # tolerate NULLs
    ]
    assert H._fleet_totals(rows) == (12, 8)


def test_filter_rows_matches_repo_and_id():
    rows = _rows(3)  # sid audit-1..3, repo /repo/app1..3
    assert [r["sid"] for r in H._filter_rows(rows, "app2")] == ["audit-2"]
    assert len(H._filter_rows(rows, "")) == 3  # empty filter keeps all
    assert H._filter_rows(rows, "audit-3")[0]["sid"] == "audit-3"


def test_prompt_pick_accepts_hash_and_slash(monkeypatch):
    import rich.prompt

    inputs = iter(["#2", "/app", "n", ""])
    monkeypatch.setattr(rich.prompt.Prompt, "ask", staticmethod(lambda *a, **k: next(inputs)))
    cli = _CLI()
    assert H._prompt_pick(cli, 1, 3, has_pages=True) == 2  # "#2" tolerated
    assert H._prompt_pick(cli, 1, 3, has_pages=True) == ("filter", "app")  # "/app"
    assert H._prompt_pick(cli, 1, 3, has_pages=True) == "next"  # "n"
    assert H._prompt_pick(cli, 1, 3, has_pages=True) is None  # "" quits


def test_limit_caps_rows(monkeypatch):
    monkeypatch.setattr(H, "_fetch_rows", lambda c, a: _rows(10))
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    monkeypatch.setattr(I, "_resolve_results_dir", lambda d: "/tmp/nope")

    seen: dict = {}
    monkeypatch.setattr(H, "_render_table", lambda c, rows, rd, **k: seen.update(n=len(rows)))
    H.handle(_CLI(), _args(limit=3))
    assert seen["n"] == 3


def test_ids_only_stays_plain(monkeypatch, capsys):
    monkeypatch.setattr(H, "_fetch_rows", lambda c, a: _rows(2))
    H.handle(_CLI(), _args(ids_only=True))
    out = capsys.readouterr().out
    assert "audit-1" in out and "audit-2" in out


def test_reconcile_counts_prefers_findings_json(tmp_path, monkeypatch):
    # Regression (QA): history takes a session's finding/verified counts from the
    # report's findings.json (canonical, variant_loop excluded) when the artifacts
    # are on disk, so it agrees with inspect/eval instead of the DB cache count.
    import json

    repo = tmp_path / "repo"
    sid = "audit-recon01"
    sess = repo / "results" / "scanner" / sid
    sess.mkdir(parents=True)
    findings = [
        {"id": "a", "discovered_by": "analyzer:unconstrained", "verified": True},
        {"id": "b", "discovered_by": "critic", "verified": True},
        {"id": "c", "discovered_by": "source_analyzer", "verified": False},
        {"id": "v", "discovered_by": "variant_loop", "verified": False},  # excluded
    ]
    (sess / "findings.json").write_text(json.dumps({"findings": findings}))
    # no index entry -> resolves via repo_url (patch the source the helper imports)
    import acuario.scanner.session_index as _si

    monkeypatch.setattr(_si, "lookup_session_path", lambda s: None)

    row = {"sid": sid, "repo_url": str(repo), "total": 99, "verified": 1, "judged": 40}
    out = H._reconcile_counts(row)
    assert out["total"] == 3  # 4 minus the variant_loop seed
    assert out["verified"] == 2
    assert out["judged"] == 3  # clamped from DB's 40 to the canonical total


def test_reconcile_counts_falls_back_to_db_when_no_artifacts(tmp_path):
    # No resolvable findings.json -> the DB row counts stand (DB-only sessions).
    row = {"sid": "audit-gone", "repo_url": str(tmp_path / "nope"),
           "total": 7, "verified": 4, "judged": 5}
    out = H._reconcile_counts(row)
    assert (out["total"], out["verified"], out["judged"]) == (7, 4, 5)
