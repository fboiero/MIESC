"""MIESC CLI - Command Line Interface for Smart Contract Security Audits."""

try:
    from miesc.cli.main import cli
    __all__ = ["cli"]
except ImportError:
    # Allow package to be imported even if dependencies missing
    cli = None
    __all__ = []
