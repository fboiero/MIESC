"""
MIESC CLI - Config Commands

Commands for managing MIESC configuration.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import sys

import click

from miesc.cli.utils import (
    RICH_AVAILABLE,
    console,
    error,
    get_root_dir,
    load_config,
    print_banner,
    success,
    warning,
)

# Import Rich components if available
if RICH_AVAILABLE:
    from rich.tree import Tree

ROOT_DIR = get_root_dir()


@click.group()
def config():
    """Manage MIESC configuration."""
    pass


@config.command("show")
def config_show():
    """Display current configuration."""
    print_banner()

    cfg = load_config()
    if not cfg:
        warning("No configuration found at config/miesc.yaml")
        return

    if RICH_AVAILABLE:
        tree = Tree("[bold cyan]MIESC Configuration[/bold cyan]")

        def add_tree(parent, data, depth=0):
            if depth > 3:
                return
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, (dict, list)):
                        branch = parent.add(f"[yellow]{key}[/yellow]")
                        add_tree(branch, value, depth + 1)
                    else:
                        parent.add(f"[yellow]{key}[/yellow]: {value}")
            elif isinstance(data, list):
                for i, item in enumerate(data[:10]):
                    if isinstance(item, dict):
                        branch = parent.add(f"[dim][{i}][/dim]")
                        add_tree(branch, item, depth + 1)
                    else:
                        parent.add(f"[dim][{i}][/dim] {item}")

        add_tree(tree, cfg)
        console.print(tree)
    else:
        print(json.dumps(cfg, indent=2))  # noqa: T201


@config.command("validate")
def config_validate():
    """Validate configuration file."""
    print_banner()

    config_path = ROOT_DIR / "config" / "miesc.yaml"
    if not config_path.exists():
        error(f"Config file not found: {config_path}")
        sys.exit(1)

    try:
        cfg = load_config()

        required_sections = ["layers", "adapters"]
        for section in required_sections:
            if section in cfg:
                success(f"Section '{section}' found")
            else:
                warning(f"Section '{section}' missing (optional)")

        success("Configuration is valid YAML")

    except Exception as e:
        error(f"Config error: {e}")
        sys.exit(1)
