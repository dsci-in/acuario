#!/usr/bin/env python3
"""
Acuario - Comprehensive Vulnerability Scanner and ExploitDeveloper

A modular, extensible tool designed to identify and exploit vulnerabilities
in target systems.
"""

import sys
from acuario.ui.cli import CLI


def main():
    """Main entry point for Acuario."""
    cli = CLI()
    cli.run()


if __name__ == '__main__':
    main()
