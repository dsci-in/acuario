"""eval subcommand - read the quality scoreboard for a past audit session.

    acuario eval <session-id>                  # proxy metrics for one run
    acuario eval <session-id> --compare <other># delta between two runs
    acuario eval <session-id> --annotations annotations.json  # true precision
    acuario eval <session-id> --format json    # machine-readable

Computes per-source verified-rate, skeptic↔validator agreement, debate
outcomes, and severity-recalibration deltas from artifacts that already exist
(findings.json, calibration.jsonl, skeptic_log.jsonl, debate_log.jsonl). No
ground-truth labels are required; an optional annotations.json overlay upgrades
the proxy metrics to true precision.
"""

from __future__ import annotations

import json
from pathlib import Path

from acuario.ui import theme

#: Cap the native scoreboard to a readable column, matching inspect's detail view,
#: so section rules don't span a wide terminal while the tables stay ~50 wide.
_DETAIL_WIDTH = 100

# Dispatch alias: the module is `eval_cmd` (avoids shadowing the `eval`
# builtin) but the user-facing subcommand is `eval`. cli.py dispatches on the
# module basename or an ALIASES entry, so `eval` must be declared here - else
# `acuario eval` parses but falls through to the top-level help.
ALIASES = ("eval",)


_EVAL_EPILOG = """\
Examples:
  acuario eval <session-id>                      proxy-metric scoreboard
  acuario eval <a> --compare <b>                 delta between two runs
  acuario eval <session-id> --annotations labels.json   true precision from labels
Scoreboard renders in the terminal; piped output (`> file.md`) stays raw markdown.
"""


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "eval",
        help="Quality scoreboard for a past audit session (proxy metrics)",
        epilog=_EVAL_EPILOG,
    )
    parser.add_argument("session_id", help="Audit session id (see `acuario history`)")
    parser.add_argument(
        "--compare",
        default=None,
        metavar="SESSION_ID",
        help="Second session to compare against (shows the delta)",
    )
    parser.add_argument(
        "--annotations",
        default=None,
        help="Optional annotations.json (finding_id -> {label: TP|FP}) for true precision",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--results-dir",
        default=None,
        help="Override the results directory (default: auto-detected)",
    )
    return parser


def _resolve_results_dir(args) -> str:
    if args.results_dir:
        return args.results_dir
    try:
        from acuario.core.config import default_results_dir

        return default_results_dir("scanner")
    except Exception:
        return "./results/scanner"


def _dir_from_db(session_id):
    """The audit's own results dir, located via the repo path the historical DB
    recorded for this session - so eval resolves a session from any cwd even when
    it predates the path index (``history`` / ``inspect`` already read that DB).
    Returns the dir only if it exists on disk, else None."""
    import sqlite3

    from acuario.core.config import acuario_home

    db = acuario_home() / "scanner" / "historical_findings.db"
    if not db.exists():
        return None
    try:
        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT repo_url FROM findings "
            "WHERE campaign_session_id = ? AND repo_url IS NOT NULL LIMIT 1",
            (session_id,),
        ).fetchone()
        conn.close()
    except Exception:
        return None
    if not row or not row["repo_url"]:
        return None
    cand = Path(row["repo_url"]) / "results" / "scanner" / session_id
    return cand if cand.exists() else None


def _resolve_session_dir(args, session_id):
    """The results dir for a session: an explicit --results-dir, else the path
    recorded at audit time, else the cwd default, else the audit's own dir located
    via the DB's repo path (so eval finds a session from any cwd, like history)."""
    if args.results_dir:
        return Path(args.results_dir) / session_id
    from acuario.scanner.session_index import lookup_session_path, record_session_path

    recorded = lookup_session_path(session_id)
    if recorded:
        return recorded
    default = Path(_resolve_results_dir(args)) / session_id
    if default.exists():
        return default
    from_db = _dir_from_db(session_id)
    if from_db is not None:
        record_session_path(session_id, from_db)  # self-heal the index for next time
        return from_db
    return default


def _error_with_path(label: str, path) -> theme.Text:
    """A themed error line: red label + the offending path (as free text, so a
    bracket in the path renders verbatim rather than being parsed as markup)."""
    msg = theme.error(f"{label} ")
    msg.append(str(path), style="path")
    return msg


def _rate_style(rate: float) -> str:
    """CVD-safe colour band for a 0..1 rate (the number itself also carries the
    value, so colour is redundant, not load-bearing)."""
    return "success" if rate >= 0.75 else ("warn" if rate >= 0.4 else "danger")


def _render_native(cli, report) -> None:
    """Render the eval scoreboard with the theme kit - framed tables, kv-tables,
    section rules, CVD-safe rate colouring - matching the rest of the CLI (E31/
    E32).  Used on a terminal; piped output stays raw markdown (E13)."""
    from rich.text import Text

    c = cli.console
    cap = min(c.width, _DETAIL_WIDTH)

    def _rule(title: str) -> None:
        c.print(theme.section_rule(title), width=cap)

    _rule(f"eval · {report.session_id}")

    summary = Text("  ")
    if report.endpoint_label:
        summary.append("model ", style="muted")
        summary.append(str(report.endpoint_label), style="accent")
        summary.append("    ")
    summary.append("findings ", style="muted")
    summary.append(str(report.total_findings), style="metric")
    summary.append(f"  ·  {report.verified_findings} verified  ", style="muted")
    summary.append(f"{report.verified_rate * 100:.1f}%", style=_rate_style(report.verified_rate))
    c.print(summary, width=cap)
    c.print(
        theme.muted(
            "  Proxy metrics from the run's own artifacts (the validator verdict is the "
            "reference, not human ground truth)."
        ),
        width=cap,
    )

    if report.by_source:
        _rule("verified-rate by source")
        table = theme.framed_table(["SOURCE", "FINDINGS", "VERIFIED", "RATE"], kind="info")
        table.columns[0].style = "ident"
        for i in (1, 2, 3):
            table.columns[i].justify = "right"
        for src, d in sorted(report.by_source.items(), key=lambda kv: -kv[1]["total"]):
            tot, ver = d["total"], d["verified"]
            rate = (ver / tot) if tot else 0.0
            table.add_row(
                theme.field(str(src)),
                theme.field(str(tot)),
                theme.field(str(ver)),
                theme.field(f"{rate * 100:.1f}%", style=_rate_style(rate)),
            )
        c.print(table)

    if report.skeptic_distribution:
        _rule("skeptic gate")
        pairs = [
            ("verdicts", " · ".join(f"{k}: {v}" for k, v in sorted(report.skeptic_distribution.items())))
        ]
        if report.debate:
            db = report.debate
            pairs.append(
                (
                    "debate",
                    f"overturned {db.get('overturned', 0)} · upheld {db.get('upheld', 0)} · "
                    f"conceded {db.get('conceded', 0)}",
                )
            )
        c.print(theme.kv_table(pairs))

    if report.agreement:
        ag = report.agreement
        _rule("skeptic ↔ validator agreement")
        c.print(
            theme.kv_table(
                [
                    ("accept · advance", str(ag.get("accept_advance", 0))),
                    ("accept · reject", f"{ag.get('accept_reject', 0)}  (let a likely-FP through)"),
                    ("refute · advance", f"{ag.get('refute_advance', 0)}  (may have killed a TP)"),
                    ("refute · reject", f"{ag.get('refute_reject', 0)}  (agreed kill)"),
                ]
            )
        )

    if report.severity_recalibration:
        sr = report.severity_recalibration
        _rule("severity recalibration")
        c.print(
            theme.kv_table(
                [
                    ("moved", str(sr.get("changed", 0))),
                    ("downgraded", str(sr.get("downgraded", 0))),
                    ("unchanged", str(sr.get("unchanged", 0))),
                ]
            )
        )

    if report.evidence_levels:
        _rule("evidence-level distribution")
        c.print(
            theme.kv_table(
                [
                    (str(lvl), str(n))
                    for lvl, n in sorted(report.evidence_levels.items(), key=lambda kv: -kv[1])
                ]
            )
        )

    if report.labeled:
        lab = report.labeled
        _rule("labeled precision (annotations overlay)")
        pairs = [("labeled", f"{lab.get('labeled', 0)}  (TP {lab.get('tp', 0)} · FP {lab.get('fp', 0)})")]
        if lab.get("precision") is not None:
            pairs.append(("precision", f"{lab['precision'] * 100:.1f}%"))
        c.print(theme.kv_table(pairs))


def _emit_report(cli, report) -> None:
    """A single scoreboard: native kit render on a terminal, raw markdown when
    piped/redirected (so `acuario eval … > report.md` stays clean markdown)."""
    if cli.console.is_terminal:
        _render_native(cli, report)
    else:
        print(report.to_markdown())


def _emit_markdown(cli, md: str) -> None:
    """Render a markdown scoreboard: as a formatted document on a terminal, but
    as RAW markdown when piped/redirected, so `acuario eval … > report.md` and
    pipelines get clean markdown instead of box-drawing art."""
    if cli.console.is_terminal:
        from rich.markdown import Markdown

        cli.console.print(Markdown(md))
    else:
        print(md)


def _emit_divider(cli, label: str) -> None:
    if cli.console.is_terminal:
        cli.console.print(theme.section_rule(label))
    else:
        print("\n---\n")


def handle(cli, args):
    from acuario.scanner.eval import analyze_session, compare_reports

    session_dir = _resolve_session_dir(args, args.session_id)
    if not session_dir.exists():
        cli.console.print(_error_with_path("Session directory not found:", session_dir))
        cli.console.print(theme.muted("Tip: run `acuario history` to list available sessions."))
        return

    annotations = None
    if args.annotations:
        ann_path = Path(args.annotations)
        if not ann_path.is_file():
            cli.console.print(_error_with_path("Annotations file not found:", ann_path))
            return
        try:
            annotations = json.loads(ann_path.read_text(encoding="utf-8"))
        except Exception as e:
            msg = theme.error("Could not parse annotations: ")
            msg.append(str(e))
            cli.console.print(msg)
            return

    report = analyze_session(session_dir, annotations=annotations)

    if args.compare:
        other_dir = _resolve_session_dir(args, args.compare)
        if not other_dir.exists():
            cli.console.print(_error_with_path("Compare session not found:", other_dir))
            return
        other = analyze_session(other_dir, annotations=annotations)
        if args.format == "json":
            # Machine-readable: exact bytes to stdout, never through the themed
            # console (which would parse the array brackets as markup).
            print(json.dumps({"a": report.to_dict(), "b": other.to_dict()}, indent=2))
        else:
            _emit_markdown(cli, compare_reports(report, other))
            _emit_divider(cli, f"{args.session_id}  (A)")
            _emit_markdown(cli, report.to_markdown())
            _emit_divider(cli, f"{args.compare}  (B)")
            _emit_markdown(cli, other.to_markdown())
        return

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _emit_report(cli, report)
