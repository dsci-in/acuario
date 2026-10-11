"""Sessions subcommand - alias of ``history`` for past audit runs."""

from __future__ import annotations

from .history import handle as _history_handle


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "sessions",
        help="Alias of `history` - list past audit sessions",
    )
    parser.add_argument(
        "--repo",
        help="Filter by repo URL or local path (substring match)",
    )
    parser.add_argument(
        "--ids-only",
        action="store_true",
        help="Print just session ids, one per line",
    )
    return parser


# Reuse history's handler verbatim.
handle = _history_handle
