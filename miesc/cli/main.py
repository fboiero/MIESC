#!/usr/bin/env python3
"""
MIESC CLI - Unified Command Line Interface

A professional CLI for smart contract security audits targeting:
- Developers: Quick scans, CI/CD integration
- Security Researchers: Deep analysis, custom configurations
- Auditors: Full reports, compliance mapping

Integrates 50 security tools across 9 defense layers.

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
"""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

# Add src to path for imports
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR))

# Import version from package
from miesc import __version__ as VERSION  # noqa: E402

# Import from refactored modules
from miesc.cli.constants import (  # noqa: E402
    ADAPTER_MAP,
    AVAILABLE_PROFILES,
    BANNER,
    LAYERS,
    QUICK_TOOLS,
)
from miesc.cli.utils import (  # noqa: E402
    AdapterLoader,
    configure_logging,
    error,
    get_correlation_api,
    get_ml_orchestrator,
    get_profile,
    get_root_dir,
    info,
    load_config,
    load_profiles,
    print_banner,
    run_layer,
    run_tool,
    success,
    summarize_findings,
    warning,
)
from miesc.cli.utils import RICH_AVAILABLE, YAML_AVAILABLE  # noqa: E402
from miesc.cli.utils import console  # noqa: E402

# Import command modules (Phase 2 refactoring)
from miesc.cli.commands.audit import audit as audit_group  # noqa: E402
from miesc.cli.commands.benchmark import benchmark as benchmark_cmd  # noqa: E402
from miesc.cli.commands.config import config as config_group  # noqa: E402
from miesc.cli.commands.detect import detect as detect_cmd  # noqa: E402
from miesc.cli.commands.detectors import detectors as detectors_group  # noqa: E402
from miesc.cli.commands.doctor import doctor as doctor_cmd  # noqa: E402
from miesc.cli.commands.export import export as export_cmd  # noqa: E402
from miesc.cli.commands.init import init as init_group  # noqa: E402
from miesc.cli.commands.plugins import plugins as plugins_group  # noqa: E402
from miesc.cli.commands.poc import poc as poc_group  # noqa: E402
from miesc.cli.commands.report import report as report_cmd  # noqa: E402
from miesc.cli.commands.scan import scan as scan_cmd  # noqa: E402
from miesc.cli.commands.server import server as server_group  # noqa: E402
from miesc.cli.commands.tools import tools as tools_group  # noqa: E402

# Try to import Rich for beautiful output (needed for direct usage in this module)
try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
except ImportError:
    pass

# Try to import YAML for config (needed for direct usage in this module)
try:
    import yaml
except ImportError:
    pass

# Configure logging (will be reconfigured by setup_logging if available)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# Backward Compatibility Aliases (deprecated, use miesc.cli.utils instead)
# =============================================================================

# Keep _run_tool and _run_layer as aliases for backward compatibility
_run_tool = run_tool
_run_layer = run_layer
_summarize_findings = summarize_findings


# ============================================================================
# Main CLI Group
# ============================================================================


@click.group(invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show version and exit")
@click.option("--no-banner", is_flag=True, help="Suppress banner output")
@click.option("--debug", "-d", is_flag=True, help="Enable debug mode (verbose logging)")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
@click.pass_context
def cli(ctx, version, no_banner, debug, quiet):
    """
    MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

    A comprehensive blockchain security framework with 50 security tools
    across 9 defense layers.

    Quick Start:
      miesc audit quick contract.sol    # Fast 4-tool scan
      miesc audit full contract.sol     # Complete 9-layer audit
      miesc tools list                  # Show available tools
      miesc doctor                      # Check tool availability

    Environment Variables:
      MIESC_DEBUG=1        Enable debug mode
      MIESC_LOG_LEVEL      Set log level (DEBUG, INFO, WARNING, ERROR)
      MIESC_LOG_FORMAT     Set format (json, console)
      MIESC_LOG_FILE       Path to log file
    """
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug
    ctx.obj["quiet"] = quiet

    # Configure logging based on flags and environment
    configure_logging(debug=debug, quiet=quiet)

    # Note: Adapters are loaded lazily when needed, not at startup
    # This improves CLI startup time significantly

    if version:
        click.echo(f"MIESC version {VERSION}")
        return

    if ctx.invoked_subcommand is None:
        if not no_banner and not quiet:
            print_banner()
        click.echo(ctx.get_help())


# Register command groups from separate modules (Phase 2 refactoring)
cli.add_command(audit_group, name="audit")
cli.add_command(benchmark_cmd, name="benchmark")
cli.add_command(config_group, name="config")
cli.add_command(detect_cmd, name="detect")
cli.add_command(detectors_group, name="detectors")
cli.add_command(doctor_cmd, name="doctor")
cli.add_command(export_cmd, name="export")
cli.add_command(init_group, name="init")
cli.add_command(plugins_group, name="plugins")
cli.add_command(poc_group, name="poc")
cli.add_command(report_cmd, name="report")
cli.add_command(scan_cmd, name="scan")
cli.add_command(server_group, name="server")
cli.add_command(tools_group, name="tools")


# ============================================================================
# Watch Command
# ============================================================================


@cli.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option(
    "--profile",
    "-p",
    type=click.Choice(["quick", "fast", "balanced"]),
    default="quick",
    help="Scan profile to use",
)
@click.option("--debounce", "-d", type=float, default=1.0, help="Debounce time in seconds")
@click.option("--recursive", "-r", is_flag=True, default=True, help="Watch subdirectories")
def watch(directory, profile, debounce, recursive):
    """Watch directory for .sol changes and auto-scan.

    Real-time security scanning for Solidity developers.
    Monitors the specified directory and automatically runs
    a quick security scan when .sol files are modified.

    Examples:
      miesc watch ./contracts           # Watch contracts directory
      miesc watch . --profile fast      # Use fast profile
      miesc watch ./src -d 2.0          # 2 second debounce
    """
    print_banner()

    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        error("watchdog not installed. Install with: pip install watchdog")
        info("Run: pip install watchdog")
        sys.exit(1)

    import threading
    import time
    from collections import defaultdict

    # Debounce state
    last_scan_time = defaultdict(float)
    scan_lock = threading.Lock()

    # Determine tools based on profile
    profile_tools = {
        "quick": QUICK_TOOLS,
        "fast": ["slither", "aderyn"],
        "balanced": ["slither", "aderyn", "solhint", "mythril"],
    }
    tools_to_run = profile_tools.get(profile, QUICK_TOOLS)

    info(f"Watching {directory} for .sol changes")
    info(f"Profile: {profile} ({', '.join(tools_to_run)})")
    info(f"Debounce: {debounce}s | Recursive: {recursive}")
    info("Press Ctrl+C to stop\n")

    class SolidityHandler(FileSystemEventHandler):
        def on_modified(self, event):
            if event.is_directory:
                return

            if not event.src_path.endswith(".sol"):
                return

            current_time = time.time()
            file_path = event.src_path

            # Debounce: skip if recently scanned
            with scan_lock:
                if current_time - last_scan_time[file_path] < debounce:
                    return
                last_scan_time[file_path] = current_time

            # Run scan
            self.run_scan(file_path)

        def on_created(self, event):
            if not event.is_directory and event.src_path.endswith(".sol"):
                self.on_modified(event)

        def run_scan(self, file_path):
            file_name = Path(file_path).name
            timestamp = datetime.now().strftime("%H:%M:%S")

            if RICH_AVAILABLE:
                console.print(f"\n[dim][{timestamp}][/dim] [cyan]Scanning {file_name}...[/cyan]")
            else:
                print(f"\n[{timestamp}] Scanning {file_name}...")

            all_findings = []
            start_time = time.time()

            for tool in tools_to_run:
                result = _run_tool(tool, file_path, timeout=60)

                if result["status"] == "success":
                    findings = result.get("findings", [])
                    all_findings.extend(findings)

                    if findings:
                        if RICH_AVAILABLE:
                            console.print(f"  [green]{tool}[/green]: {len(findings)} findings")
                        else:
                            print(f"  {tool}: {len(findings)} findings")
                elif result["status"] == "not_available":
                    pass  # Silently skip unavailable tools
                else:
                    if RICH_AVAILABLE:
                        console.print(f"  [yellow]{tool}[/yellow]: error")

            elapsed = time.time() - start_time
            summary = _summarize_findings([{"findings": all_findings}])

            # Display summary
            if RICH_AVAILABLE:
                status_color = (
                    "green" if summary["CRITICAL"] == 0 and summary["HIGH"] == 0 else "red"
                )
                console.print(
                    f"[{status_color}]Result:[/{status_color}] "
                    f"Critical: {summary['CRITICAL']} | "
                    f"High: {summary['HIGH']} | "
                    f"Medium: {summary['MEDIUM']} | "
                    f"Low: {summary['LOW']} "
                    f"[dim]({elapsed:.1f}s)[/dim]"
                )
            else:
                print(
                    f"Result: Critical: {summary['CRITICAL']} | "
                    f"High: {summary['HIGH']} | "
                    f"Medium: {summary['MEDIUM']} | "
                    f"Low: {summary['LOW']} "
                    f"({elapsed:.1f}s)"
                )

    # Start observer
    observer = Observer()
    handler = SolidityHandler()
    observer.schedule(handler, directory, recursive=recursive)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        info("\nStopping watch mode...")
        observer.stop()

    observer.join()
    success("Watch mode stopped")


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    cli()
