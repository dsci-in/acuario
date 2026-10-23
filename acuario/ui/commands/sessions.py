"""Sessions subcommand - alias of ``history`` for past audit runs."""

from __future__ import annotations

from .history import add_list_args
from .history import handle as _history_handle


def add_parser(subparsers):
    # Reuse history's flag registration so the alias never drifts from it.
    parser = subparsers.add_parser(
        "sessions",
        help="Alias of `history` - list past audit sessions",
    )
    return add_list_args(parser)


# Reuse history's handler verbatim.
handle = _history_handle
