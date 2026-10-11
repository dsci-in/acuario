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

# Dispatch alias: the module is `eval_cmd` (avoids shadowing the `eval`
# builtin) but the user-facing subcommand is `eval`. cli.py dispatches on the
# module basename or an ALIASES entry, so `eval` must be declared here - else
# `acuario eval` parses but falls through to the top-level help.
ALIASES = ("eval",)


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "eval",
        help="Quality scoreboard for a past audit session (proxy metrics)",
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


def handle(cli, args):
    from acuario.scanner.eval import analyze_session, compare_reports

    results_dir = _resolve_results_dir(args)
    session_dir = Path(results_dir) / args.session_id
    if not session_dir.exists():
        cli.console.print(
            f"[red]Session directory not found:[/red] {session_dir}\n"
            "[dim]Tip: run `acuario history` to list available sessions.[/dim]"
        )
        return

    annotations = None
    if args.annotations:
        ann_path = Path(args.annotations)
        if not ann_path.is_file():
            cli.console.print(f"[red]Annotations file not found:[/red] {ann_path}")
            return
        try:
            annotations = json.loads(ann_path.read_text(encoding="utf-8"))
        except Exception as e:
            cli.console.print(f"[red]Could not parse annotations:[/red] {e}")
            return

    report = analyze_session(session_dir, annotations=annotations)

    if args.compare:
        other_dir = Path(results_dir) / args.compare
        if not other_dir.exists():
            cli.console.print(f"[red]Compare session not found:[/red] {other_dir}")
            return
        other = analyze_session(other_dir, annotations=annotations)
        if args.format == "json":
            cli.console.print(json.dumps({"a": report.to_dict(), "b": other.to_dict()}, indent=2))
        else:
            cli.console.print(compare_reports(report, other))
            cli.console.print("\n---\n")
            cli.console.print(report.to_markdown())
            cli.console.print("\n---\n")
            cli.console.print(other.to_markdown())
        return

    if args.format == "json":
        cli.console.print(json.dumps(report.to_dict(), indent=2))
    else:
        cli.console.print(report.to_markdown())
