"""MIESC CLI package."""

from __future__ import annotations

from typing import Any

__all__ = ["cli"]


def __getattr__(name: str) -> Any:
    """Load the Click entrypoint lazily.

    Avoid importing `miesc.cli.main` while Python is preparing to execute it via
    `python -m miesc.cli.main`, which otherwise triggers a runpy warning.
    """
    if name == "cli":
        from miesc.cli.main import cli

        return cli
    raise AttributeError(name)
