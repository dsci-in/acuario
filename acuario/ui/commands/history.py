"""History subcommand - list past audit sessions and their stats.

Reads directly from ``~/.acuario/scanner/historical_findings.db`` (the
sqlite store that the audit pipeline already populates) so users can
look back over their previous runs without us maintaining a separate
session ledger.
"""

from __future__ import annotations

import datetime as _dt
import sqlite3

from rich.table import Table

from acuario.core.config import acuario_home


def add_parser(subparsers):
    parser = subparsers.add_parser("history", help="List past audit sessions and their stats")
    parser.add_argument(
        "--repo",
        help="Filter by repo URL or local path (substring match)",
    )
    parser.add_argument(
        "--ids-only",
        action="store_true",
        help="Print just session ids, one per line (for shell piping)",
    )
    return parser


def handle(cli, args):
    """Print a table of past audit sessions, newest first."""
    db_path = acuario_home() / "scanner" / "historical_findings.db"
    if not db_path.exists():
        cli.console.print("[yellow]No audit history yet - run `acuario audit .`[/yellow]")
        return

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
        cli.console.print("[yellow]No audit sessions found.[/yellow]")
        return

    if args.ids_only:
        for r in rows:
            print(r["sid"])
        return

    table = Table(title="Audit Sessions")
    table.add_column("Session", style="cyan")
    table.add_column("Repo", style="magenta")
    table.add_column("Findings", justify="right")
    table.add_column("Verified", justify="right", style="green")
    table.add_column("Judged", justify="right")
    table.add_column("Last touched")
    for r in rows:
        last = (
            _dt.datetime.fromtimestamp(r["last_touched"]).strftime("%Y-%m-%d %H:%M")
            if r["last_touched"]
            else "?"
        )
        table.add_row(
            r["sid"],
            (r["repo_url"] or "(unknown)")[:50],
            str(r["total"]),
            str(r["verified"] or 0),
            f"{r['judged'] or 0}/{r['total']}",
            last,
        )
    cli.console.print(table)
