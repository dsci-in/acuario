"""Command-line interface for Acuario.

This module provides the thin dispatcher; each subcommand lives in its own
module under ``acuario.ui.commands``.
"""

import argparse
import logging
import sys

from rich_argparse import RawDescriptionRichHelpFormatter, RichHelpFormatter

from acuario import __version__

from ..core import Config
from .commands import ALL_COMMANDS
from .theme import PALETTE, brand_banner, build_console


def _themed_help_formatter() -> type[RichHelpFormatter]:
    """A palette-styled help formatter (one source of truth for colours).

    rich-argparse renders help through its own Console, so the styles are set
    from the palette hexes directly rather than via theme style names.  The Raw
    variant preserves the Quickstart epilog's hand-aligned example lines instead
    of re-wrapping them into a paragraph.
    """
    RichHelpFormatter.styles.update(
        {
            "argparse.prog": f"bold {PALETTE['accent']}",
            "argparse.groups": f"bold {PALETTE['accent_bright']}",
            "argparse.args": PALETTE["sky"],
            "argparse.metavar": PALETTE["accent_deep"],
            "argparse.help": PALETTE["fg"],
            "argparse.text": PALETTE["muted"],
            "argparse.default": PALETTE["faint"],
            "argparse.syntax": PALETTE["amber"],
        }
    )
    return RawDescriptionRichHelpFormatter


# Worked examples shown at the foot of `acuario --help` - the fastest way for a
# newcomer to get from install to a first audit.
_HELP_EPILOG = """\
Quickstart:
  acuario setup                          configure an LLM provider (first run)
  acuario audit .                        audit the current directory
  acuario audit ./repo --depth deep      a deeper, multi-pass audit
  acuario history                        browse past audits, open one by number
  acuario inspect <session-id>           chat with a finished audit

Run 'acuario help <command>' or 'acuario <command> -h' for command details.
"""

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
        # One themed Console shared across every command (the design kit's single
        # source of truth for colour, severity, glyphs and components).  This one
        # line re-skins all Rich "chrome" - rules, tables, spinners, prompts and
        # rendered Markdown - with zero per-command churn; see acuario.ui.theme.
        self.console = build_console()
        self.config = Config()

    def run(self, args: list | None = None) -> None:
        """Run the CLI."""
        parser = self._create_parser()

        # Print banner before argparse intercepts -h/--help (which calls
        # sys.exit, so we can't print after parse_args in that case).  Scope it
        # to the top level: a bare `acuario` or `acuario -h/--help` - NOT every
        # `acuario <command> --help`, where the banner is just noise.
        _argv = list(args if args is not None else sys.argv[1:])
        # `acuario help [command]` is a friendly alias for -h / `<command> -h`
        # (git-style), so `help` is not a surprising "invalid choice".
        if _argv and _argv[0] == "help":
            _argv = [_argv[1], "--help"] if len(_argv) > 1 else ["--help"]

        if not _argv or _argv[0] in ("-h", "--help"):
            self.console.print(brand_banner(BANNER, console=self.console))
            self.console.print(_startup_notice(), style="muted")

        parsed_args = parser.parse_args(_argv)

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
        formatter = _themed_help_formatter()
        parser = argparse.ArgumentParser(
            prog="acuario",
            description="Acuario - Multi AI Agent Source Code Auditing Sandbox",
            epilog=_HELP_EPILOG,
            formatter_class=formatter,
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

        subparsers = parser.add_subparsers(
            dest="command",
            title="commands",
            metavar="<command>",
        )

        for cmd_module in ALL_COMMANDS:
            cmd_module.add_parser(subparsers)

        # argparse reads formatter_class lazily (at help time), so applying the
        # themed formatter to each subparser here re-skins every `acuario
        # <command> --help` without touching the 10 command modules.
        for sub in subparsers.choices.values():
            sub.formatter_class = formatter

        return parser
