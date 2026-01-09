#!/usr/bin/env python3
"""
MIESC - Entry point for python -m miesc

Enables running MIESC as a module:
    python -m miesc --help
    python -m miesc scan contract.sol
    python -m miesc audit quick contract.sol

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
"""

from miesc.cli.main import cli

if __name__ == "__main__":
    cli()
