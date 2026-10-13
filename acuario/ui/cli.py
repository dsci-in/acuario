"""Command-line interface for Acuario.

This module provides the thin dispatcher; each subcommand lives in its own
module under ``acuario.ui.commands``.
"""

import argparse
import logging
import sys

from rich.console import Console

from acuario import __version__

from ..core import Config
from .commands import ALL_COMMANDS

logger = logging.getLogger(__name__)


BANNER = r"""
 █████╗  ██████╗██╗   ██╗ █████╗ ██████╗ ██╗ ██████╗
██╔══██╗██╔════╝██║   ██║██╔══██╗██╔══██╗██║██╔═══██╗
███████║██║     ██║   ██║███████║██████╔╝██║██║   ██║
██╔══██║██║     ██║   ██║██╔══██║██╔══██╗██║██║   ██║
██║  ██║╚██████╗╚██████╔╝██║  ██║██║  ██║██║╚██████╔╝
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝
    Multi AI Agent Source Code Auditing Sandbox
"""


def _license_notice() -> str:
    """AGPL section 5(d) Appropriate Legal Notice (full form) for `--license`."""
    return (
        f"Acuario {__version__} - Multi AI Agent Source Code Auditing Sandbox\n"
        "Copyright (C) 2026 Data Security Council of India\n"
        "\n"
        "This program comes with ABSOLUTELY NO WARRANTY. This is free software,\n"
        "and you are welcome to redistribute it under the terms of the GNU Affero\n"
        "General Public License, either version 3 of the License, or (at your\n"
        "option) any later version.\n"
        "\n"
        "Acuario also incorporates MIT-licensed code by Eric Hartford; see\n"
        "THIRD-PARTY-NOTICES.md.\n"
        "\n"
        "The full license text is in the LICENSE file distributed with this\n"
        "program, or online at <https://www.gnu.org/licenses/agpl-3.0.html>.\n"
        "\n"
        "If you run a modified version of Acuario as a network service, AGPL\n"
        "section 13 requires you to offer its Corresponding Source to users\n"
        "interacting with it remotely."
    )


def _startup_notice() -> str:
    """AGPL section 5(d) short notice shown on the interactive startup screen."""
    return (
        f"Acuario {__version__} - Copyright (C) 2026 Data Security Council of "
        "India\n"
        "Free software under the GNU AGPL v3.0-or-later - with ABSOLUTELY NO "
        "WARRANTY.\n"
        "Run [bold]acuario --license[/bold] for the full notice."
    )


class _LicenseAction(argparse.Action):
    """`--license`: print the Appropriate Legal Notice and exit."""

    def __init__(self, option_strings, dest, **kwargs):
        kwargs.setdefault("nargs", 0)
        kwargs.setdefault("help", "show the license / legal notice and exit")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print(_license_notice())
        parser.exit()


class CLI:
    """Command-line interface for Acuario."""

    def __init__(self):
        self.console = Console()
        self.config = Config()

    def run(self, args: list | None = None) -> None:
        """Run the CLI."""
        parser = self._create_parser()

        # Print banner before argparse intercepts -h/--help (which calls
        # sys.exit, so we can't print after parse_args in that case).
        _argv = args if args is not None else sys.argv[1:]
        if not _argv or "-h" in _argv or "--help" in _argv:
            self.console.print(BANNER, style="bold cyan")
            self.console.print(_startup_notice(), style="dim")

        parsed_args = parser.parse_args(args)

        # Dispatch to the matching command module. A module's base name
        # matches the subcommand it registers; command modules may also
        # declare an `ALIASES` tuple so `acuario init` can route to
        # `setup`, etc.
        for cmd_module in ALL_COMMANDS:
            cmd_name = cmd_module.__name__.rsplit(".", 1)[-1]
            aliases = getattr(cmd_module, "ALIASES", ())
            if parsed_args.command == cmd_name or parsed_args.command in aliases:
                cmd_module.handle(self, parsed_args)
                return

        # No subcommand provided - banner already printed above; show help.
        parser.print_help()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser with subcommands from command modules."""
        parser = argparse.ArgumentParser(
            prog="acuario",
            description="Acuario - Multi AI Agent Source Code Auditing Sandbox",
        )
        parser.add_argument(
            "-V",
            "--version",
            action="version",
            version=f"acuario {__version__}",
        )
        parser.add_argument(
            "--license",
            action=_LicenseAction,
        )

        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        for cmd_module in ALL_COMMANDS:
            cmd_module.add_parser(subparsers)

        return parser
