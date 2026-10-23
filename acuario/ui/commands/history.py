"""History subcommand - the hub for past audit sessions.

Reads directly from ``~/.acuario/scanner/historical_findings.db`` (the sqlite
store the audit pipeline already populates) so users can look back over previous
runs without a separate session ledger.

On an interactive terminal it is a *hub*: sessions are numbered and you can open
one by its number, which walks into ``acuario inspect`` for that session; `..`
inside the inspector pops you back here.  Piped or ``--ids-only`` output stays
plain for scripting.
"""

from __future__ import annotations

import datetime as _dt
import sqlite3
import sys
from pathlib import Path

from rich.text import Text

from acuario.core.config import acuario_home
from acuario.ui import theme


def add_list_args(parser):
    """Register the flags shared by `history` and its `sessions` alias, so the
    two never drift (they dispatch to the same handler)."""
    parser.add_argument(
        "--repo",
        help="Filter by repo URL or local path (substring match)",
    )
    parser.add_argument(
        "--ids-only",
        action="store_true",
        help="Print just session ids, one per line (for shell piping)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Show at most N most-recent sessions",
    )
    return parser


_HISTORY_EPILOG = """\
On a terminal, history is an interactive hub - sessions are numbered and you can:
  <n> / #<n>   open that audit in `inspect`        n, p   page through the list
  /text        filter by repo or session id        q      quit
Piped or --ids-only output stays plain, for scripting.
"""


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "history",
        help="List past audit sessions and their stats",
        epilog=_HISTORY_EPILOG,
    )
    return add_list_args(parser)


#: Sessions shown per page in the interactive hub (older pages reached with n/p).
_PAGE_SIZE = 15


def handle(cli, args):
    """List past audit sessions; on a TTY, act as a paged interactive hub."""
    rows = _fetch_rows(cli, args)
    if rows is None:
        return

    if getattr(args, "limit", None):
        rows = rows[: max(1, args.limit)]

    if args.ids_only:
        for r in rows:
            print(r["sid"])  # raw stdout - stays plain for shell piping
        return

    # Lazy import: inspect pulls the heavier artifact loaders only when needed.
    from acuario.ui.commands.inspect import _resolve_results_dir, open_session

    results_dir = _resolve_results_dir(None)
    if not sys.stdout.isatty():
        _render_table(cli, rows, results_dir, total=len(rows), fleet=_fleet_totals(rows))
        return

    # Interactive hub: one page of _PAGE_SIZE at a time, newest first.  Numbers
    # are GLOBAL within the current view (a session keeps its number across
    # pages); n/p walk the pages and `/text` filters by repo / id.
    all_rows = rows
    flt = ""
    page = 0
    while True:
        view = _filter_rows(all_rows, flt)
        pages = max(1, (len(view) + _PAGE_SIZE - 1) // _PAGE_SIZE)
        page = max(0, min(page, pages - 1))
        start = page * _PAGE_SIZE
        window = view[start : start + _PAGE_SIZE]
        _render_table(
            cli, window, results_dir, offset=start, total=len(view),
            page=page + 1, pages=pages, filter_text=flt, fleet=_fleet_totals(view),
        )
        action = _prompt_pick(cli, start + 1, start + len(window), has_pages=pages > 1)
        if action is None:
            return  # q / 0 / Enter at the hub exits the tool
        if action == "next":
            page += 1
            continue
        if action == "prev":
            page -= 1
            continue
        if isinstance(action, tuple) and action[0] == "filter":
            flt = action[1]  # `/text` (empty clears the filter)
            page = 0
            continue
        sid = view[action - 1]["sid"]  # action is a global 1-based index into the view
        # results_dir=None: let open_session resolve via the recorded session
        # path (then cwd default, then DB), not just this cwd's results dir.
        if open_session(cli, sid, from_hub=True) == "quit":
            return
        # "back" from the inspector: loop and re-render the current page.


def _first_run_panel():
    """The branded first-run welcome shown when no history DB exists yet.

    On a genuine first run (the audit pipeline hasn't created the findings DB)
    this is the onboarding moment, so it greets the user and points at the two
    commands that get a first audit going rather than emitting a bare caution
    line.  The body is a Text (never markup-interpolated), so it renders verbatim
    and degrades to a clean ASCII-boxed panel on NO_COLOR / non-UTF-8 terminals.
    """
    body = Text()
    body.append("No audit history yet. This looks like your first run.\n\n", style="muted")
    body.append("Get started in two steps:\n\n", style="muted")
    body.append("  1  ", style="accent.strong")
    body.append("acuario setup", style="accent")
    body.append("     configure your LLM provider\n", style="muted")
    body.append("  2  ", style="accent.strong")
    body.append("acuario audit .", style="accent")
    body.append("   audit the current directory", style="muted")
    return theme.panel(body, title="Welcome to Acuario", kind="accent")


def _fleet_totals(rows):
    """(total findings, total verified) across a set of session rows."""
    return (
        sum(int(r["total"] or 0) for r in rows),
        sum(int(r["verified"] or 0) for r in rows),
    )


def _fetch_rows(cli, args):
    """Return the session rows (newest first), or None after messaging an empty
    history / no matches."""
    db_path = acuario_home() / "scanner" / "historical_findings.db"
    if not db_path.exists():
        cli.console.print(_first_run_panel())
        return None

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    query = """
        SELECT campaign_session_id AS sid,
               repo_url,
               COUNT(*)                                                 AS total,
               SUM(CASE WHEN verified = 1 THEN 1 ELSE 0 END)            AS verified,
               SUM(CASE WHEN reviewed_at IS NOT NULL THEN 1 ELSE 0 END) AS judged,
               MIN(discovered_at)                                       AS started,
               MAX(COALESCE(reviewed_at, discovered_at))                AS last_touched
        FROM findings
        WHERE 1=1
    """
    params: list[str] = []
    if args.repo:
        query += " AND repo_url LIKE ?"
        params.append(f"%{args.repo}%")
    query += " GROUP BY campaign_session_id ORDER BY last_touched DESC"

    rows = conn.execute(query, params).fetchall()
    conn.close()
    if not rows:
        hint = f" matching {args.repo!r}" if args.repo else ""
        cli.console.print(theme.warn(f"No audit sessions found{hint}."))
        return None
    return [_reconcile_counts(r) for r in rows]


def _canonical_counts(sid, repo_url):
    """(total, verified) from the session's findings.json canonical set - the same
    set inspect / eval / the report show - or None when no findings.json is
    resolvable (then the DB's raw row counts stand). The historical DB is a
    cross-campaign dedup cache whose per-session COUNT(*) can drift from the final
    report (a stage ingested before dedup, or one that ran after the DB closed), so
    when the artifacts exist they are the source of truth for the count."""
    import json as _json

    from acuario.findings.types import canonical_findings
    from acuario.scanner.session_index import lookup_session_path

    rec = lookup_session_path(sid)
    base = rec if rec else (Path(repo_url) / "results" / "scanner" / sid if repo_url else None)
    if base is None:
        return None
    fp = Path(base) / "findings.json"
    if not fp.exists():
        return None
    try:
        raw = _json.loads(fp.read_text())
        items = raw if isinstance(raw, list) else raw.get("findings", [])
    except Exception:
        return None
    canon = canonical_findings(items)
    return len(canon), sum(1 for f in canon if f.get("verified"))


def _reconcile_counts(row):
    """A session row with its finding/verified counts taken from findings.json
    when the artifacts are on disk (so history agrees with the report), else the
    DB row as-is. Returns a plain dict (same ``r["key"]`` access as sqlite3.Row)."""
    d = dict(row)
    cc = _canonical_counts(d.get("sid"), d.get("repo_url"))
    if cc is not None:
        total, verified = cc
        d["total"] = total
        d["verified"] = verified
        d["judged"] = min(int(d.get("judged") or 0), total)  # keep N/total sane
    return d


def _ellipsize_tail(text: str, width: int) -> str:
    """Keep the END of a path/URL (the informative part - the repo/app name)
    rather than head-slicing it off."""
    text = str(text)
    return text if len(text) <= width else "…" + text[-(width - 1):]


def _filter_rows(rows, flt: str):
    """Rows whose repo URL or session id contains ``flt`` (case-insensitive).
    An empty filter returns every row."""
    if not flt:
        return rows
    needle = flt.lower()
    return [
        r
        for r in rows
        if needle in f"{r['repo_url'] or ''} {r['sid'] or ''}".lower()
    ]


def _render_table(
    cli, rows, results_dir, *, offset=0, total=None, page=1, pages=1, filter_text="", fleet=None
) -> None:
    """The framed, numbered session list (option C).  Every cell is a Text so a
    bracket in a repo URL renders verbatim.  ``offset`` makes the row numbers
    GLOBAL across pages; ``page``/``pages`` add a page marker; ``filter_text``
    notes an active ``/`` filter; ``fleet`` is a ``(findings, verified)`` total
    across the whole (filtered) view - a compact footer."""
    total = len(rows) if total is None else total
    caption = f"{total} session(s)"
    if fleet is not None:
        caption += f"  ·  {fleet[0]} findings · {fleet[1]} verified"
    if filter_text:
        caption += f"  ·  filter {filter_text!r}"
    if pages > 1:
        caption += f"  ·  page {page}/{pages}"
    if not rows:
        cli.console.print(theme.section_rule("Audit sessions"))
        cli.console.print(theme.muted(f"  No sessions match {filter_text!r}.  / to change, q to quit."))
        return
    table = theme.framed_table(
        ["#", "SESSION", "REPO", "FINDINGS", "VERIFIED", "JUDGED", "LAST TOUCHED"],
        title="Audit sessions",
        caption=caption,
    )
    table.columns[0].justify = "right"
    table.columns[1].style = "ident"
    table.columns[1].no_wrap = True
    table.columns[2].style = "path"
    table.columns[3].justify = "right"
    table.columns[4].justify = "right"
    table.columns[5].justify = "right"
    table.columns[6].style = "muted"
    table.columns[6].no_wrap = True  # keep the timestamp on one line (crop, don't wrap)
    for i, r in enumerate(rows, offset + 1):
        last = (
            _dt.datetime.fromtimestamp(r["last_touched"]).strftime("%Y-%m-%d %H:%M")
            if r["last_touched"]
            else "?"
        )
        verified = int(r["verified"] or 0)
        # Every listed session is openable: the inspector falls back to the
        # findings DB when its results directory is gone, so no row is dimmed.
        table.add_row(
            theme.field(str(i), style="accent"),
            theme.field(r["sid"] or "?", style="ident"),
            theme.field(_ellipsize_tail(r["repo_url"] or "(unknown)", 40)),
            theme.field(str(r["total"])),
            theme.field(str(verified), style="success" if verified else "faint"),
            theme.field(f"{r['judged'] or 0}/{r['total']}"),
            theme.field(last),
        )
    cli.console.print(table)


def _prompt_pick(cli, lo: int, hi: int, *, has_pages: bool = False):
    """Prompt for a session number in the visible range [lo, hi].

    Accepts a plain number or a ``#``-prefixed one (the column is labelled ``#``).
    Returns the global 1-based index, ``"next"`` / ``"prev"`` to page (when
    ``has_pages``), ``("filter", text)`` for a ``/text`` search, or ``None`` to
    quit the hub."""
    from rich.prompt import Prompt

    bits = ["open #"]
    if has_pages:
        bits += ["n next", "p prev"]
    bits += ["/ find", "q quit"]
    hint = " · ".join(bits)
    while True:
        try:
            raw = Prompt.ask(
                theme.muted(hint), console=cli.console, default="", show_default=False
            ).strip()
        except (EOFError, KeyboardInterrupt):
            cli.console.print()
            return None
        low = raw.lower()
        if low in ("", "q", "quit", "0"):
            return None
        if raw.startswith("/"):  # `/text` filters (bare `/` clears)
            return ("filter", raw[1:].strip())
        if has_pages and low in ("n", "next"):
            return "next"
        if has_pages and low in ("p", "prev"):
            return "prev"
        num = raw[1:] if raw.startswith("#") else raw  # tolerate a `#` prefix
        if num.isdigit() and lo <= int(num) <= hi:
            return int(num)
        if hi < lo:
            cli.console.print(theme.muted("No sessions here. / to find, or q to quit."))
        else:
            cli.console.print(theme.muted(f"Enter {lo}–{hi}, /text to find, or q to quit."))
