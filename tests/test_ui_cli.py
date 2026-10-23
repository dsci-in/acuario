"""Tests for the top-level CLI: `acuario help` alias + the Quickstart epilog."""

from __future__ import annotations

import pytest

from acuario.ui.cli import CLI


def test_help_alias_shows_top_level_help(capsys):
    # `acuario help` is a friendly alias for -h (argparse --help exits 0).
    with pytest.raises(SystemExit):
        CLI().run(["help"])
    out = capsys.readouterr().out
    assert "Quickstart" in out  # the worked-examples epilog is present


def test_help_command_routes_to_subcommand(capsys):
    with pytest.raises(SystemExit):
        CLI().run(["help", "audit"])
    out = capsys.readouterr().out
    assert "acuario audit" in out
