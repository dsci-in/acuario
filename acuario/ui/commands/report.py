"""Report subcommand - render reports for a past audit session.

Piggy-backs on ``acuario.scanner.resume.resume_session`` (the same code
path that powers ``acuario audit --resume``). With ``verify=False`` it
just re-emits the SARIF / Markdown / JSON artifacts from saved findings;
with ``--verify`` it re-runs the reviewer pass first.
"""

from __future__ import annotations

from rich.text import Text

from acuario.ui import theme


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
        help="Where to write reports (default: beside the audit's own results directory)",
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
    # Lazy import: keeps the heavy scanner/LLM stack out of package import so
    # `acuario --help`, doctor, config and setup work even on a partial install.
    from acuario.scanner.resume import resume_session

    try:
        # With --verify this is LLM-bound and can run for minutes; the spinner
        # gives live feedback on a TTY and (being TTY/NO_COLOR guarded) prints the
        # message once then runs plainly when piped / in CI, so it never looks hung.
        # The session id lives in the spinner label, so this is the single progress
        # line (no separate "Rendering report for session …" above it).
        with theme.status_spinner(cli.console, f"Rendering report for session {args.session_id}…"):
            paths = resume_session(
                session_id=args.session_id,
                repo_path=args.repo_path,
                output_dir=args.output_dir,
                verify=args.verify,
                force_review=args.force_review,
                cli_config_section=cli.config.get_provider_section() or None,
            )
    except FileNotFoundError as exc:
        cli.console.print(theme.error(str(exc)))
        return
    except ValueError as exc:
        cli.console.print(theme.error(str(exc)))
        cli.console.print(theme.muted("Tip: list available sessions with `acuario history`."))
        return
    cli.console.print()
    cli.console.print(theme.success("Report written"))
    # Titled OUTPUTS block: a themed section rule over one aligned fmt→path row
    # per artifact.  Each row is a Text (styles applied directly), so a bracket in
    # a path renders verbatim instead of being parsed as Rich markup.
    cli.console.print(theme.section_rule("outputs"), width=min(cli.console.width, 100))
    for fmt, path in paths.items():
        row = Text("  ")
        row.append(f"{fmt:<10}", style="ident")
        row.append("  ")
        row.append(str(path), style="path")
        cli.console.print(row)
