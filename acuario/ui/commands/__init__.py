"""CLI subcommand modules."""

from . import audit, config, doctor, eval_cmd, history, inspect, report, sessions, setup

ALL_COMMANDS = [setup, doctor, config, audit, history, report, sessions, inspect, eval_cmd]
