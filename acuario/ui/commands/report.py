"""Report subcommand - render reports for a past audit session.

Piggy-backs on ``acuario.scanner.resume.resume_session`` (the same code
path that powers ``acuario audit --resume``). With ``verify=False`` it
just re-emits the SARIF / Markdown / JSON artifacts from saved findings;
with ``--verify`` it re-runs the reviewer pass first.
"""

from __future__ import annotations

from acuario.scanner.resume import resume_session


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "report",
        help="Render SARIF/Markdown/JSON reports for a past audit session",
    )
    parser.add_argument(
        "session_id",
        help="Audit session id (see `acuario history` for available ids)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Where to write reports (default: ~/.acuario/results/scanner/)",
    )
    parser.add_argument(
        "--repo-path",
        default=None,
        help="Local path to the audited repo (defaults to cwd; only used "
        "when --verify is set, to read file content for the reviewer).",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Re-run the reviewer pass on findings before rendering. "
        "Slow (LLM-bound). Without this, reports render in seconds.",
    )
    parser.add_argument(
        "--force-review",
        action="store_true",
        help="With --verify, re-review findings even if they already have a "
        "saved verdict. Bumps the per-finding review_revision counter.",
    )
    return parser


def handle(cli, args):
    cli.console.print(f"[bold cyan]Rendering report for session {args.session_id}[/bold cyan]")
    try:
        paths = resume_session(
            session_id=args.session_id,
            repo_path=args.repo_path,
            output_dir=args.output_dir,
            verify=args.verify,
            force_review=args.force_review,
            cli_config_section=cli.config.get_provider_section() or None,
        )
    except FileNotFoundError as exc:
        cli.console.print(f"[red]{exc}[/red]")
        return
    except ValueError as exc:
        cli.console.print(f"[red]{exc}[/red]")
        cli.console.print("[dim]Tip: list available sessions with `acuario history`.[/dim]")
        return
    cli.console.print("\n[bold green]Report written[/bold green]")
    for fmt, path in paths.items():
        cli.console.print(f"  [bold]{fmt:10s}[/bold]  {path}")
