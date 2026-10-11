"""Acuario - Multi AI Agent Source Code Auditing Sandbox."""

from .core.config import Config, ScanConfig

__all__ = ["Config", "ScanConfig"]
__version__ = "2.0.0"


def main():
    """Main entry point for Acuario."""
    from .ui.cli import CLI

    cli = CLI()
    cli.run()
