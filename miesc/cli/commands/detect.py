"""
MIESC CLI - Detect Command

Framework auto-detection for Solidity projects.

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
    info,
    print_banner,
    success,
    warning,
)


# =============================================================================
# Detect Command
# =============================================================================


@click.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--json", "-j", "as_json", is_flag=True, help="Output as JSON")
def detect(path, as_json):
    """Auto-detect Foundry/Hardhat/Truffle framework.

    Detects the Solidity development framework in use and extracts
    configuration like solc version, remappings, and paths.

    Supports:
      - Foundry (foundry.toml)
      - Hardhat (hardhat.config.js/ts)
      - Truffle (truffle-config.js)
      - Brownie (brownie-config.yaml)

    Examples:
      miesc detect                    # Detect in current directory
      miesc detect ./my-project       # Detect in specific path
      miesc detect . --json           # Output as JSON
    """
    if not as_json:
        print_banner()

    try:
        from src.core.framework_detector import Framework, detect_framework
    except ImportError:
        error("Framework detector module not available")
        sys.exit(1)

    config = detect_framework(path)

    if as_json:
        click.echo(json.dumps(config.to_dict(), indent=2))
        return

    if config.framework == Framework.UNKNOWN:
        warning(f"No supported framework detected in {path}")
        info("Supported frameworks: Foundry, Hardhat, Truffle, Brownie")
        info("\nLooking for:")
        info("  - foundry.toml        (Foundry)")
        info("  - hardhat.config.js   (Hardhat)")
        info("  - truffle-config.js   (Truffle)")
        info("  - brownie-config.yaml (Brownie)")
        return

    if RICH_AVAILABLE:
        from rich.panel import Panel

        # Build panel content
        content = f"""[bold cyan]Framework:[/bold cyan] {config.framework.value.upper()}
[bold cyan]Root Path:[/bold cyan] {config.root_path}
[bold cyan]Config File:[/bold cyan] {config.config_file}

[bold]Compiler Settings:[/bold]
  Solc Version: {config.solc_version or 'auto'}
  EVM Version: {config.evm_version or 'default'}
  Optimizer: {'enabled' if config.optimizer_enabled else 'disabled'}
  Optimizer Runs: {config.optimizer_runs}

[bold]Project Paths:[/bold]
  Source: {config.src_path or 'N/A'}
  Test: {config.test_path or 'N/A'}
  Output: {config.out_path or 'N/A'}
"""
        if config.remappings:
            content += f"""
[bold]Remappings:[/bold] ({len(config.remappings)} entries)
"""
            for remap in config.remappings[:5]:
                content += f"  {remap}\n"
            if len(config.remappings) > 5:
                content += f"  ... and {len(config.remappings) - 5} more\n"

        if config.lib_paths:
            content += """
[bold]Library Paths:[/bold]
"""
            for lib in config.lib_paths[:3]:
                content += f"  {lib}\n"

        console.print(Panel(content, title="Framework Detection", border_style="green"))
    else:
        print("\n=== Framework Detection ===")  # noqa: T201
        print(f"Framework: {config.framework.value.upper()}")  # noqa: T201
        print(f"Root Path: {config.root_path}")  # noqa: T201
        print(f"Config File: {config.config_file}")  # noqa: T201
        print("\nCompiler Settings:")  # noqa: T201
        print(f"  Solc Version: {config.solc_version or 'auto'}")  # noqa: T201
        print(f"  EVM Version: {config.evm_version or 'default'}")  # noqa: T201
        print(f"  Optimizer: {'enabled' if config.optimizer_enabled else 'disabled'}")  # noqa: T201
        print("\nProject Paths:")  # noqa: T201
        print(f"  Source: {config.src_path}")  # noqa: T201
        print(f"  Test: {config.test_path}")  # noqa: T201
        print(f"  Output: {config.out_path}")  # noqa: T201

        if config.remappings:
            print(f"\nRemappings: ({len(config.remappings)} entries)")  # noqa: T201
            for remap in config.remappings[:5]:
                print(f"  {remap}")  # noqa: T201

    success(f"Detected {config.framework.value.upper()} project")
