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

import logging
import sys
from pathlib import Path

import click

# Add src to path for imports
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR))

# Import version from package
from miesc import __version__ as VERSION  # noqa: E402

# Import utilities needed for CLI setup
from miesc.cli.utils import configure_logging, print_banner  # noqa: E402

# Import command modules
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
from miesc.cli.commands.watch import watch as watch_cmd  # noqa: E402

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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

    if version:
        click.echo(f"MIESC version {VERSION}")
        return

    if ctx.invoked_subcommand is None:
        if not no_banner and not quiet:
            print_banner()
        click.echo(ctx.get_help())


# Register command groups
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
cli.add_command(watch_cmd, name="watch")


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    cli()
