"""
MIESC CLI - Command Line Interface

Provides unified CLI for MIESC security analysis framework.

Usage:
    miesc scan <contract.sol>       # Quick scan with static tools
    miesc audit <contract.sol>      # Full 7-layer audit
    miesc doctor                    # Check tool availability
    miesc version                   # Show version info
"""

import sys
import os
import json
import click
from pathlib import Path
from datetime import datetime

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from miesc import __version__


# ANSI Colors
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    """Print MIESC banner."""
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════╗
║  MIESC v{__version__} - Multi-layer Intelligent Evaluation      ║
║  for Smart Contracts                                      ║
║  Defense-in-Depth Security Analysis Framework             ║
╚═══════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    click.echo(banner)


def print_success(msg):
    click.echo(f"{Colors.GREEN}✓{Colors.RESET} {msg}")


def print_warning(msg):
    click.echo(f"{Colors.YELLOW}⚠{Colors.RESET} {msg}")


def print_error(msg):
    click.echo(f"{Colors.RED}✗{Colors.RESET} {msg}")


def print_info(msg):
    click.echo(f"{Colors.CYAN}ℹ{Colors.RESET} {msg}")


@click.group()
@click.version_option(version=__version__, prog_name="miesc")
def cli():
    """MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

    Defense-in-depth security analysis framework for Ethereum smart contracts.
    Orchestrates 25 specialized tools across 7 defense layers.

    Examples:

        miesc scan contract.sol        Quick static analysis

        miesc audit contract.sol       Full 7-layer audit

        miesc doctor                   Check tool availability
    """
    pass


@cli.command()
@click.argument('contract', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for results (JSON)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(contract, output, verbose):
    """Quick scan using static analysis tools (Slither, Aderyn, Solhint).

    Performs fast security analysis suitable for development workflow.
    Typical execution time: ~30 seconds.

    Example:
        miesc scan contracts/MyToken.sol
    """
    print_banner()
    print_info(f"Scanning: {contract}")

    try:
        # Import here to avoid slow startup
        from miesc.core.quick_scanner import QuickScanner

        scanner = QuickScanner()
        results = scanner.scan(contract, verbose=verbose)

        # Print summary
        findings = results.get('findings', [])
        critical = sum(1 for f in findings if f.get('severity') == 'critical')
        high = sum(1 for f in findings if f.get('severity') == 'high')
        medium = sum(1 for f in findings if f.get('severity') == 'medium')
        low = sum(1 for f in findings if f.get('severity') == 'low')

        click.echo(f"\n{Colors.BOLD}Results:{Colors.RESET}")
        if critical > 0:
            print_error(f"Critical: {critical}")
        if high > 0:
            print_warning(f"High: {high}")
        print_info(f"Medium: {medium}")
        print_info(f"Low: {low}")

        if output:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            print_success(f"Results saved to: {output}")

        # Exit code based on findings
        if critical > 0 or high > 0:
            sys.exit(1)

    except ImportError:
        # Fallback to basic implementation
        print_warning("Quick scanner not available, using basic scan...")
        _basic_scan(contract, output, verbose)
    except Exception as e:
        print_error(f"Scan failed: {e}")
        sys.exit(1)


def _basic_scan(contract, output, verbose):
    """Basic scan fallback using subprocess."""
    import subprocess

    results = {"contract": contract, "findings": [], "tools": []}

    # Try Slither
    try:
        result = subprocess.run(
            ['slither', contract, '--json', '-'],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0 or result.stdout:
            slither_output = json.loads(result.stdout) if result.stdout else {}
            results['tools'].append('slither')
            if verbose:
                print_success("Slither completed")
    except Exception as e:
        if verbose:
            print_warning(f"Slither not available: {e}")

    print_success(f"Scan completed with {len(results['tools'])} tools")

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)


@cli.command()
@click.argument('contract', type=click.Path(exists=True))
@click.option('--layers', '-l', multiple=True, help='Specific layers to run (1-7)')
@click.option('--tools', '-t', multiple=True, help='Specific tools to run')
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', 'fmt', type=click.Choice(['json', 'html', 'pdf']), default='json')
@click.option('--timeout', default=600, help='Timeout in seconds (default: 600)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def audit(contract, layers, tools, output, fmt, timeout, verbose):
    """Full 7-layer security audit.

    Performs comprehensive defense-in-depth analysis using all 25 tools
    across 7 security layers.

    Layers:
        1: Static Analysis (Slither, Aderyn, Solhint)
        2: Dynamic Testing (Echidna, Medusa, Foundry)
        3: Symbolic Execution (Mythril, Manticore, Halmos)
        4: Invariant Testing (Scribble)
        5: Formal Verification (SMTChecker, Certora)
        6: Property Testing (PropertyGPT)
        7: AI Analysis (SmartLLM, ThreatModel)

    Example:
        miesc audit contracts/MyToken.sol --output report.json
    """
    print_banner()
    print_info(f"Starting full audit: {contract}")
    print_info(f"Timeout: {timeout}s")

    if layers:
        print_info(f"Layers: {', '.join(layers)}")
    else:
        print_info("Layers: All (1-7)")

    try:
        from miesc.core.orchestrator import MIESCOrchestrator

        orchestrator = MIESCOrchestrator()
        results = orchestrator.audit(
            contract,
            layers=list(layers) if layers else None,
            tools=list(tools) if tools else None,
            timeout=timeout,
            verbose=verbose
        )

        # Save output
        if output:
            if fmt == 'json':
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2)
            print_success(f"Report saved to: {output}")
        else:
            click.echo(json.dumps(results, indent=2))

    except ImportError:
        print_warning("Full orchestrator not available")
        print_info("Run: python run_complete_multilayer_audit.py " + contract)
        sys.exit(1)
    except Exception as e:
        print_error(f"Audit failed: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
def doctor():
    """Check availability of security tools.

    Verifies which analysis tools are installed and accessible.
    """
    print_banner()
    print_info("Checking tool availability...\n")

    tools = [
        ("slither", "slither --version"),
        ("mythril", "myth version"),
        ("echidna", "echidna --version"),
        ("solhint", "solhint --version"),
        ("aderyn", "aderyn --version"),
        ("foundry", "forge --version"),
        ("halmos", "halmos --version"),
        ("medusa", "medusa --version"),
    ]

    available = 0
    for name, cmd in tools:
        try:
            import subprocess
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                print_success(f"{name}: available")
                available += 1
            else:
                print_warning(f"{name}: not working")
        except FileNotFoundError:
            print_error(f"{name}: not installed")
        except Exception as e:
            print_warning(f"{name}: error ({e})")

    click.echo(f"\n{Colors.BOLD}Summary:{Colors.RESET} {available}/{len(tools)} tools available")

    if available < 3:
        print_warning("Install more tools for comprehensive analysis")
        print_info("See: https://fboiero.github.io/MIESC/docs/02_SETUP_AND_USAGE/")


@cli.command()
def version():
    """Show version information."""
    click.echo(f"MIESC v{__version__}")
    click.echo(f"Python {sys.version.split()[0]}")
    click.echo(f"Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>")
    click.echo(f"License: AGPL-3.0")
    click.echo(f"Docs: https://fboiero.github.io/MIESC")


@cli.command()
def api():
    """Start the MCP REST API server.

    Starts a Flask server providing JSON-RPC endpoints for
    Model Context Protocol integration.

    Default port: 5001
    """
    print_banner()
    print_info("Starting MCP REST API server...")

    try:
        from miesc.api.mcp_rest import app, MIESC_VERSION
        print_success(f"Server starting on http://localhost:5001")
        print_info("Press Ctrl+C to stop")
        app.run(host='0.0.0.0', port=5001, debug=False)
    except ImportError:
        # Fallback to src version
        try:
            from src.miesc_mcp_rest import app
            print_success(f"Server starting on http://localhost:5001")
            app.run(host='0.0.0.0', port=5001, debug=False)
        except ImportError:
            print_error("MCP REST API module not found")
            sys.exit(1)


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()
