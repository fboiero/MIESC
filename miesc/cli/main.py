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
from miesc.cli.commands.config import config as config_group  # noqa: E402
from miesc.cli.commands.detectors import detectors as detectors_group  # noqa: E402
from miesc.cli.commands.init import init as init_group  # noqa: E402
from miesc.cli.commands.plugins import plugins as plugins_group  # noqa: E402
from miesc.cli.commands.poc import poc as poc_group  # noqa: E402
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


# =============================================================================
# Output Format Converters (unique to main.py)
# =============================================================================


def _to_sarif(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert results to SARIF 2.1.0 format for GitHub Code Scanning."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MIESC",
                        "version": VERSION,
                        "informationUri": "https://github.com/fboiero/MIESC",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    rule_ids = set()

    for result in results:
        tool_name = result.get("tool", "unknown")

        for finding in result.get("findings", []):
            rule_id = finding.get("type", finding.get("id", finding.get("title", "unknown")))

            # Add rule if not already added
            if rule_id not in rule_ids:
                sarif["runs"][0]["tool"]["driver"]["rules"].append(
                    {
                        "id": rule_id,
                        "name": finding.get("title", rule_id),
                        "shortDescription": {"text": finding.get("message", rule_id)},
                        "fullDescription": {"text": finding.get("description", "")},
                        "helpUri": (
                            finding.get("references", [""])[0] if finding.get("references") else ""
                        ),
                        "properties": {"tool": tool_name},
                    }
                )
                rule_ids.add(rule_id)

            # Map severity
            severity = str(finding.get("severity", "INFO")).upper()
            level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}.get(
                severity, "note"
            )

            # Get location
            location = finding.get("location", {})
            if isinstance(location, dict):
                file_path = location.get("file", result.get("contract", "unknown"))
                line = location.get("line", 1)
            else:
                file_path = result.get("contract", "unknown")
                line = 1

            sarif["runs"][0]["results"].append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": finding.get("description", finding.get("message", ""))},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_path},
                                "region": {"startLine": max(1, int(line))},
                            }
                        }
                    ],
                    "properties": {"tool": tool_name, "confidence": finding.get("confidence", 0.5)},
                }
            )

    return sarif


def _to_markdown(results: List[Dict[str, Any]], contract: str) -> str:
    """Convert results to Markdown report."""
    summary = _summarize_findings(results)
    total = sum(summary.values())

    # Count tools
    successful_tools = [r["tool"] for r in results if r.get("status") == "success"]
    failed_tools = [r["tool"] for r in results if r.get("status") != "success"]

    md = f"""# MIESC Security Audit Report

**Contract**: `{contract}`
**Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**MIESC Version**: {VERSION}

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {summary['CRITICAL']} |
| High | {summary['HIGH']} |
| Medium | {summary['MEDIUM']} |
| Low | {summary['LOW']} |
| Info | {summary['INFO']} |
| **Total** | **{total}** |

### Tools Executed

- **Successful**: {', '.join(successful_tools) if successful_tools else 'None'}
- **Failed/Unavailable**: {', '.join(failed_tools) if failed_tools else 'None'}

## Detailed Findings

"""

    for result in results:
        if result.get("findings"):
            tool_name = result.get("tool", "unknown").upper()
            md += f"### {tool_name}\n\n"

            for finding in result["findings"]:
                severity = finding.get("severity", "INFO")
                title = finding.get("title", finding.get("type", finding.get("id", "Unknown")))
                description = finding.get("description", finding.get("message", ""))

                md += f"**[{severity}]** {title}\n\n"
                md += f"{description}\n\n"

                # Location
                location = finding.get("location", {})
                if isinstance(location, dict) and location.get("file"):
                    md += f"- **Location**: `{location['file']}:{location.get('line', 0)}`\n"

                # Recommendation
                if finding.get("recommendation"):
                    md += f"- **Recommendation**: {finding['recommendation']}\n"

                # References
                if finding.get("swc_id"):
                    md += f"- **SWC**: {finding['swc_id']}\n"

                md += "\n---\n\n"

    md += """
## Appendix

### Tool Execution Details

| Tool | Status | Time (s) | Findings |
|------|--------|----------|----------|
"""

    for result in results:
        tool = result.get("tool", "unknown")
        status = result.get("status", "unknown")
        exec_time = result.get("execution_time", 0)
        findings_count = len(result.get("findings", []))
        md += f"| {tool} | {status} | {exec_time:.1f} | {findings_count} |\n"

    md += f"\n---\n\n*Generated by MIESC v{VERSION}*\n"

    return md


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
cli.add_command(config_group, name="config")
cli.add_command(detectors_group, name="detectors")
cli.add_command(init_group, name="init")
cli.add_command(plugins_group, name="plugins")
cli.add_command(poc_group, name="poc")
cli.add_command(server_group, name="server")
cli.add_command(tools_group, name="tools")


# ============================================================================
# Scan Command (Simplified Entry Point)
# ============================================================================


@cli.command()
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file for JSON report")
@click.option("--ci", is_flag=True, help="CI mode: exit 1 if critical/high issues found")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output, only show summary")
def scan(contract, output, ci, quiet):
    """Quick vulnerability scan for a Solidity contract.

    This is a simplified command for quick scans. For more options,
    use 'miesc audit quick' or 'miesc audit full'.

    \b
    Examples:
        miesc scan MyContract.sol
        miesc scan contracts/Token.sol --ci
        miesc scan MyContract.sol -o report.json

    \b
    Exit codes:
        0 - Success (no critical/high issues, or CI mode disabled)
        1 - Critical or high severity issues found (CI mode only)
    """
    if not quiet:
        print_banner()
        info(f"Scanning {contract}")
        info(f"Tools: {', '.join(QUICK_TOOLS)}")

    all_results = []

    if RICH_AVAILABLE and not quiet:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("Scanning...", total=len(QUICK_TOOLS))

            for tool in QUICK_TOOLS:
                progress.update(task, description=f"Running {tool}...")
                result = _run_tool(tool, contract, 300)
                all_results.append(result)
                progress.advance(task)
    else:
        for tool in QUICK_TOOLS:
            if not quiet:
                info(f"Running {tool}...")
            result = _run_tool(tool, contract, 300)
            all_results.append(result)

    summary = _summarize_findings(all_results)
    total = sum(summary.values())
    critical_high = summary.get("CRITICAL", 0) + summary.get("HIGH", 0)

    # Display summary
    if RICH_AVAILABLE:
        table = Table(title="Scan Results", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        colors = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }
        for sev, count in summary.items():
            if count > 0:  # Only show non-zero
                table.add_row(sev, str(count), style=colors.get(sev, "white"))
        table.add_row("TOTAL", str(total), style="bold")
        console.print(table)

        if critical_high > 0:
            console.print(
                f"\n[bold red]Found {critical_high} critical/high severity issues![/bold red]"
            )
        elif total > 0:
            console.print(f"\n[yellow]Found {total} issues to review[/yellow]")
        else:
            console.print("\n[green]No issues found![/green]")
    else:
        print("\n=== Scan Results ===")
        for sev, count in summary.items():
            if count > 0:
                print(f"{sev}: {count}")
        print(f"TOTAL: {total}")

    # Save output
    if output:
        data = {
            "contract": str(contract),
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "summary": summary,
            "total_findings": total,
            "results": all_results,
        }
        with open(output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")

    # CI mode exit
    if ci and critical_high > 0:
        error(f"CI check failed: {critical_high} critical/high issues")
        sys.exit(1)


# ============================================================================
# Audit Commands
# ============================================================================


@cli.group()
def audit():
    """Run security audits on smart contracts."""
    pass


@audit.command("quick")
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown"]), default="json"
)
@click.option("--ci", is_flag=True, help="CI mode: exit with error if critical/high issues found")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout per tool in seconds")
def audit_quick(contract, output, fmt, ci, timeout):
    """Quick 4-tool scan for fast feedback (slither, aderyn, solhint, mythril)."""
    print_banner()
    info(f"Quick scan of {contract}")
    info(f"Tools: {', '.join(QUICK_TOOLS)}")

    all_results = []

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("Scanning...", total=len(QUICK_TOOLS))

            for tool in QUICK_TOOLS:
                progress.update(task, description=f"Running {tool}...")
                result = _run_tool(tool, contract, timeout)
                all_results.append(result)

                if result["status"] == "success":
                    success(f"{tool}: {len(result.get('findings', []))} findings")
                elif result["status"] == "not_available":
                    warning(f"{tool}: not installed")
                else:
                    warning(f"{tool}: {result.get('error', 'error')}")

                progress.advance(task)
    else:
        for tool in QUICK_TOOLS:
            info(f"Running {tool}...")
            result = _run_tool(tool, contract, timeout)
            all_results.append(result)

    summary = _summarize_findings(all_results)
    total = sum(summary.values())

    # Display summary
    if RICH_AVAILABLE:
        table = Table(title="Quick Scan Summary", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        colors = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }
        for sev, count in summary.items():
            table.add_row(sev, str(count), style=colors.get(sev, "white"))
        table.add_row("TOTAL", str(total), style="bold")
        console.print(table)
    else:
        print("\n=== Summary ===")
        for sev, count in summary.items():
            print(f"{sev}: {count}")
        print(f"TOTAL: {total}")

    # Save output
    if output:
        if fmt == "sarif":
            data = _to_sarif(all_results)
            with open(output, "w") as f:
                json.dump(data, f, indent=2)
        elif fmt == "markdown":
            data = _to_markdown(all_results, contract)
            with open(output, "w") as f:
                f.write(data)
        else:
            data = {"results": all_results, "summary": summary, "version": VERSION}
            with open(output, "w") as f:
                json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")

    # CI mode exit
    if ci and (summary["CRITICAL"] > 0 or summary["HIGH"] > 0):
        error(f"Found {summary['CRITICAL']} critical and {summary['HIGH']} high issues")
        sys.exit(1)


@audit.command("full")
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown"]), default="json"
)
@click.option(
    "--layers", "-l", type=str, default="1,2,3,4,5,6,7", help="Layers to run (comma-separated)"
)
@click.option("--timeout", "-t", type=int, default=600, help="Timeout per tool in seconds")
@click.option("--skip-unavailable", is_flag=True, default=True, help="Skip unavailable tools")
@click.option(
    "--ml/--no-ml", default=True, help="Enable ML pipeline for FP filtering and correlation"
)
@click.option("--correlate/--no-correlate", default=True, help="Enable cross-tool correlation")
def audit_full(contract, output, fmt, layers, timeout, skip_unavailable, ml, correlate):
    """Complete 9-layer security audit with all 50 tools.

    By default uses ML pipeline for false positive filtering and
    cross-tool correlation for improved accuracy.

    \b
    Examples:
        miesc audit full contract.sol                    # Full audit with ML
        miesc audit full contract.sol --no-ml           # Without ML filtering
        miesc audit full contract.sol -l 1,2,3          # Only layers 1-3
        miesc audit full contract.sol -o report.json    # Save to file
    """
    print_banner()
    info(f"Full audit of {contract}")

    layer_list = [int(x.strip()) for x in layers.split(",") if x.strip().isdigit()]

    # Try to use ML Orchestrator for enhanced analysis
    ml_orchestrator = get_ml_orchestrator() if ml else None
    correlation_api = get_correlation_api() if correlate and not ml_orchestrator else None

    if ml_orchestrator:
        info(
            "[bold green]ML Pipeline enabled[/bold green] - FP filtering active"
            if RICH_AVAILABLE
            else "ML Pipeline enabled - FP filtering active"
        )
        _run_full_audit_with_ml(contract, output, fmt, layer_list, timeout, ml_orchestrator)
        return

    if correlation_api:
        info(
            "[cyan]Correlation enabled[/cyan] - Cross-tool validation active"
            if RICH_AVAILABLE
            else "Correlation enabled - Cross-tool validation active"
        )
        _run_full_audit_with_correlation(
            contract, output, fmt, layer_list, timeout, correlation_api
        )
        return

    # Fallback to basic mode
    if ml or correlate:
        warning("ML/Correlation modules not available, using basic mode")

    _run_full_audit_basic(contract, output, fmt, layer_list, timeout)


def _run_full_audit_with_ml(contract, output, fmt, layer_list, timeout, orchestrator):
    """Run full audit using ML Orchestrator."""
    # Determine tools from layers
    tools_to_run = []
    for layer in layer_list:
        if layer in LAYERS:
            tools_to_run.extend(LAYERS[layer]["tools"])

    info(f"Running {len(tools_to_run)} tools with ML enhancement...")

    # Progress callback for Rich
    def progress_callback(stage, message, progress):
        if RICH_AVAILABLE:
            console.print(f"[dim]{stage}:[/dim] {message}")

    # Run ML-enhanced analysis
    try:
        result = orchestrator.analyze(
            contract_path=contract,
            tools=tools_to_run,
            timeout=timeout,
            progress_callback=progress_callback if RICH_AVAILABLE else None,
        )

        # Display ML-enhanced summary
        summary_data = result.get_summary()

        if RICH_AVAILABLE:
            console.print("\n")

            # Main summary table
            table = Table(title="ML-Enhanced Audit Summary", box=box.ROUNDED)
            table.add_column("Metric", style="bold")
            table.add_column("Value", justify="right")

            table.add_row(
                "Risk Level",
                f"[{'red' if summary_data['risk_level'] in ['CRITICAL', 'HIGH'] else 'yellow'}]{summary_data['risk_level']}[/]",
            )
            table.add_row("Total Findings", str(summary_data["total_findings"]))
            table.add_row("Critical", f"[red]{summary_data['critical']}[/red]")
            table.add_row("High", f"[red]{summary_data['high']}[/red]")
            table.add_row("Medium", f"[yellow]{summary_data['medium']}[/yellow]")
            table.add_row("Low", f"[cyan]{summary_data['low']}[/cyan]")
            console.print(table)

            # ML metrics table
            ml_table = Table(title="ML Pipeline Metrics", box=box.SIMPLE)
            ml_table.add_column("Metric", style="dim")
            ml_table.add_column("Value", justify="right")

            ml_table.add_row("Raw Findings", str(result.total_raw_findings))
            ml_table.add_row(
                "False Positives Removed", f"[green]{result.false_positives_removed}[/green]"
            )
            ml_table.add_row("Reduction Rate", f"{summary_data['reduction_rate']:.1f}%")
            ml_table.add_row("Severity Adjustments", str(result.severity_adjustments))
            ml_table.add_row("Vulnerability Clusters", str(result.cluster_count))
            ml_table.add_row("Cross-Validated", str(result.cross_validated))
            console.print(ml_table)

            # Tools summary
            console.print(
                f"\n[dim]Tools: {len(result.tools_success)}/{len(result.tools_run)} successful[/dim]"
            )
            if result.tools_failed:
                console.print(f"[yellow]Failed: {', '.join(result.tools_failed)}[/yellow]")

            console.print(
                f"[dim]Execution time: {result.execution_time_ms/1000:.1f}s (ML: {result.ml_processing_time_ms/1000:.1f}s)[/dim]"
            )
        else:
            print("\n=== ML-Enhanced Audit Summary ===")
            print(f"Risk Level: {summary_data['risk_level']}")
            print(
                f"Total: {summary_data['total_findings']} (Critical: {summary_data['critical']}, High: {summary_data['high']})"
            )
            print(
                f"FPs Removed: {result.false_positives_removed} ({summary_data['reduction_rate']:.1f}% reduction)"
            )

        # Save output
        if output:
            if fmt == "json":
                data = result.to_dict()
                with open(output, "w") as f:
                    json.dump(data, f, indent=2, default=str)
            elif fmt == "markdown":
                data = _ml_result_to_markdown(result, contract)
                with open(output, "w") as f:
                    f.write(data)
            elif fmt == "sarif":
                # Convert ML result to SARIF format
                all_results = [
                    {"tool": t, "findings": result.ml_filtered_findings, "status": "success"}
                    for t in result.tools_success[:1]
                ]  # Use first tool as source
                data = _to_sarif(all_results)
                with open(output, "w") as f:
                    json.dump(data, f, indent=2)
            success(f"Report saved to {output}")

    except Exception as e:
        error(f"ML analysis failed: {e}")
        logger.exception("ML analysis error")
        info("Falling back to basic mode...")
        _run_full_audit_basic(contract, output, fmt, layer_list, timeout)


def _run_full_audit_with_correlation(contract, output, fmt, layer_list, timeout, api):
    """Run full audit using Correlation API."""
    all_results = []

    for layer in layer_list:
        if layer in LAYERS:
            layer_info = LAYERS[layer]
            if RICH_AVAILABLE:
                console.print(
                    f"\n[bold cyan]=== Layer {layer}: {layer_info['name']} ===[/bold cyan]"
                )
            else:
                print(f"\n=== Layer {layer}: {layer_info['name']} ===")

            results = _run_layer(layer, contract, timeout)
            all_results.extend(results)

            # Add to correlation API
            for result in results:
                if result.get("status") == "success" and result.get("findings"):
                    api.add_tool_results(result["tool"], result["findings"])

    # Run correlation analysis
    info("Running cross-tool correlation...")
    report = api.analyze(output_format="full")

    # Display correlated summary
    summary = report.get("summary", {})
    findings = report.get("findings", {})

    if RICH_AVAILABLE:
        console.print("\n")
        table = Table(title="Correlated Audit Summary", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Total Correlated", str(summary.get("total_correlated", 0)))
        table.add_row("Cross-Validated", str(summary.get("cross_validated", 0)))
        table.add_row("High Confidence", str(summary.get("high_confidence_count", 0)))
        table.add_row("Likely FPs Filtered", str(len(findings.get("likely_false_positives", []))))
        table.add_row("Dedup Rate", f"{summary.get('deduplication_rate', 0)*100:.1f}%")
        console.print(table)

        # Actionable findings
        actionable = findings.get("actionable", [])
        if actionable:
            console.print(f"\n[bold]Top Actionable Findings ({len(actionable)}):[/bold]")
            for f in actionable[:5]:
                sev = f.get("severity", "unknown").upper()
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
                console.print(
                    f"  [{color}][{sev}][/{color}] {f.get('type', 'unknown')} - {f.get('location', {}).get('file', '')}:{f.get('location', {}).get('line', 0)}"
                )
    else:
        print("\n=== Correlated Summary ===")
        print(f"Total: {summary.get('total_correlated', 0)}")
        print(f"Cross-validated: {summary.get('cross_validated', 0)}")

    if output:
        with open(output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        success(f"Report saved to {output}")


def _run_full_audit_basic(contract, output, fmt, layer_list, timeout):
    """Run full audit in basic mode (no ML/correlation)."""
    all_results = []

    for layer in layer_list:
        if layer in LAYERS:
            layer_info = LAYERS[layer]
            if RICH_AVAILABLE:
                console.print(
                    f"\n[bold cyan]=== Layer {layer}: {layer_info['name']} ===[/bold cyan]"
                )
                console.print(f"[dim]{layer_info['description']}[/dim]")
            else:
                print(f"\n=== Layer {layer}: {layer_info['name']} ===")

            results = _run_layer(layer, contract, timeout)
            all_results.extend(results)

    summary = _summarize_findings(all_results)
    total = sum(summary.values())

    # Display summary
    if RICH_AVAILABLE:
        console.print("\n")
        table = Table(title="Full Audit Summary (Basic Mode)", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        colors = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }
        for sev, count in summary.items():
            table.add_row(sev, str(count), style=colors.get(sev, "white"))
        table.add_row("TOTAL", str(total), style="bold")
        console.print(table)

        # Execution summary
        successful = len([r for r in all_results if r.get("status") == "success"])
        console.print(f"\n[dim]Tools executed: {successful}/{len(all_results)}[/dim]")
        console.print(
            "[yellow]Note: ML filtering disabled. Results may contain false positives.[/yellow]"
        )
    else:
        print("\n=== Full Audit Summary (Basic Mode) ===")
        for sev, count in summary.items():
            print(f"{sev}: {count}")
        print(f"TOTAL: {total}")

    if output:
        if fmt == "sarif":
            data = _to_sarif(all_results)
        elif fmt == "markdown":
            data = _to_markdown(all_results, contract)
        else:
            data = {
                "results": all_results,
                "summary": summary,
                "version": VERSION,
                "layers": layer_list,
                "ml_enabled": False,
            }

        with open(output, "w") as f:
            if fmt == "markdown":
                f.write(data)
            else:
                json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")


def _ml_result_to_markdown(result, contract: str) -> str:
    """Convert ML analysis result to Markdown report."""
    summary = result.get_summary()

    md = f"""# MIESC ML-Enhanced Security Audit Report

**Contract**: `{contract}`
**Date**: {result.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
**MIESC Version**: {VERSION}
**Risk Level**: {summary['risk_level']}

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Findings | {summary['total_findings']} |
| Critical | {summary['critical']} |
| High | {summary['high']} |
| Medium | {summary['medium']} |
| Low | {summary['low']} |
| False Positives Removed | {result.false_positives_removed} |
| Reduction Rate | {summary['reduction_rate']:.1f}% |

## ML Pipeline Metrics

- **Raw findings analyzed**: {result.total_raw_findings}
- **After FP filtering**: {len(result.ml_filtered_findings)}
- **Severity adjustments**: {result.severity_adjustments}
- **Vulnerability clusters**: {result.cluster_count}
- **Cross-validated findings**: {result.cross_validated}

## Tools Executed

- **Successful**: {', '.join(result.tools_success) if result.tools_success else 'None'}
- **Failed**: {', '.join(result.tools_failed) if result.tools_failed else 'None'}

## Detailed Findings

"""
    for finding in result.ml_filtered_findings[:20]:
        severity = finding.get("severity", "INFO").upper()
        title = finding.get("title", finding.get("type", finding.get("id", "Unknown")))
        description = finding.get("description", finding.get("message", ""))
        location = finding.get("location", {})

        md += f"### [{severity}] {title}\n\n"
        md += f"{description}\n\n"

        if isinstance(location, dict) and location.get("file"):
            md += f"- **Location**: `{location['file']}:{location.get('line', 0)}`\n"

        if finding.get("confidence"):
            md += f"- **Confidence**: {finding['confidence']:.2f}\n"

        if finding.get("tool"):
            md += f"- **Detected by**: {finding['tool']}\n"

        md += "\n---\n\n"

    if result.cluster_count > 0:
        md += "## Vulnerability Clusters\n\n"
        for i, cluster in enumerate(result.clusters[:5], 1):
            cluster_dict = cluster.to_dict() if hasattr(cluster, "to_dict") else {}
            md += f"### Cluster {i}: {cluster_dict.get('primary_type', 'Unknown')}\n"
            md += f"- Findings: {cluster_dict.get('count', 0)}\n"
            md += f"- Severity: {cluster_dict.get('max_severity', 'unknown')}\n\n"

    md += f"""
## Execution Details

- **Execution time**: {result.execution_time_ms/1000:.1f}s
- **ML processing time**: {result.ml_processing_time_ms/1000:.1f}s

---

*Generated by MIESC v{VERSION} with ML Pipeline*
"""
    return md


@audit.command("layer")
@click.argument("layer_num", type=int)
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout per tool in seconds")
def audit_layer(layer_num, contract, output, timeout):
    """Run a specific layer's tools (1-7)."""
    print_banner()

    if layer_num not in LAYERS:
        error(f"Invalid layer: {layer_num}. Valid layers: 1-7")
        for num, layer_info in LAYERS.items():
            info(f"  Layer {num}: {layer_info['name']}")
        sys.exit(1)

    layer_info = LAYERS[layer_num]
    info(f"Layer {layer_num}: {layer_info['name']}")
    info(f"Description: {layer_info['description']}")
    info(f"Tools: {', '.join(layer_info['tools'])}")

    results = _run_layer(layer_num, contract, timeout)
    summary = _summarize_findings(results)

    if RICH_AVAILABLE:
        table = Table(title=f"Layer {layer_num} Summary", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev, count in summary.items():
            table.add_row(sev, str(count))
        console.print(table)

    if output:
        with open(output, "w") as f:
            json.dump(
                {"layer": layer_num, "results": results, "summary": summary},
                f,
                indent=2,
                default=str,
            )
        success(f"Report saved to {output}")


@audit.command("smart")
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "markdown"]), default="json")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout per tool in seconds")
@click.option(
    "--llm-validate/--no-llm-validate", default=False, help="Use LLM to validate findings"
)
def audit_smart(contract, output, fmt, timeout, llm_validate):
    """Smart audit with ML filtering, correlation, and optional LLM validation.

    This is the recommended command for accurate security analysis:
    - Runs multiple tools (Slither, Aderyn, Mythril, etc.)
    - Applies ML-based false positive filtering
    - Correlates findings across tools
    - Optionally validates findings with local LLM

    \b
    Examples:
        miesc audit smart contract.sol                    # Smart audit
        miesc audit smart contract.sol --llm-validate    # With LLM validation
        miesc audit smart contract.sol -o report.json    # Save report
    """
    print_banner()
    info(f"Smart audit of {contract}")

    # Get ML orchestrator
    ml_orchestrator = get_ml_orchestrator()

    if not ml_orchestrator:
        error("ML Orchestrator not available. Please check installation.")
        info("Falling back to basic audit...")
        # Fall back to basic
        _run_full_audit_basic(contract, output, fmt, [1, 2, 3], timeout)
        return

    if RICH_AVAILABLE:
        console.print("[bold green]ML Pipeline[/bold green] enabled")
        console.print("[cyan]Cross-tool correlation[/cyan] enabled")
        if llm_validate:
            console.print("[magenta]LLM validation[/magenta] enabled")

    # Define smart tool selection (core reliable tools)
    smart_tools = ["slither", "aderyn", "mythril", "solhint"]

    info(f"Tools: {', '.join(smart_tools)}")

    # Progress display
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("Analyzing...", total=100)

            def progress_callback(stage, message, pct):
                progress.update(task, description=message, completed=int(pct * 100))

            result = ml_orchestrator.analyze(
                contract_path=contract,
                tools=smart_tools,
                timeout=timeout,
                progress_callback=progress_callback,
            )
    else:
        result = ml_orchestrator.analyze(
            contract_path=contract,
            tools=smart_tools,
            timeout=timeout,
        )

    # Optional LLM validation
    if llm_validate and result.ml_filtered_findings:
        info("Running LLM validation on findings...")
        try:
            from src.llm.finding_validator import LLMFindingValidator, ValidatorConfig

            validator_config = ValidatorConfig(
                min_severity_to_validate="medium",
                timeout_seconds=60,
            )
            validator = LLMFindingValidator(validator_config)

            import asyncio

            async def validate():
                validated, validations = await validator.validate_findings_batch(
                    result.ml_filtered_findings
                )
                await validator.close()
                return validated, validations

            validated_findings, validations = asyncio.run(validate())

            # Update result with LLM validation
            llm_fp_count = len(result.ml_filtered_findings) - len(validated_findings)
            if llm_fp_count > 0:
                info(f"LLM filtered {llm_fp_count} additional false positives")
                result.ml_filtered_findings = validated_findings
                result.false_positives_removed += llm_fp_count

        except Exception as e:
            warning(f"LLM validation failed: {e}")

    # Display results
    summary = result.get_summary()

    if RICH_AVAILABLE:
        console.print("\n")

        # Risk badge
        risk_colors = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        risk_color = risk_colors.get(summary["risk_level"], "white")
        console.print(
            Panel(
                f"[bold {risk_color}]{summary['risk_level']}[/bold {risk_color}]",
                title="Risk Level",
                border_style=risk_color,
            )
        )

        # Summary table
        table = Table(title="Smart Audit Results", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        table.add_row("Critical", f"[red]{summary['critical']}[/red]")
        table.add_row("High", f"[red]{summary['high']}[/red]")
        table.add_row("Medium", f"[yellow]{summary['medium']}[/yellow]")
        table.add_row("Low", f"[cyan]{summary['low']}[/cyan]")
        table.add_row("Total", f"[bold]{summary['total_findings']}[/bold]")
        console.print(table)

        # Effectiveness metrics
        console.print(f"\n[dim]Raw findings: {result.total_raw_findings}[/dim]")
        console.print(
            f"[green]FPs removed: {result.false_positives_removed} ({summary['reduction_rate']:.1f}% reduction)[/green]"
        )
        console.print(f"[dim]Cross-validated: {result.cross_validated}[/dim]")

        # Top findings
        if result.ml_filtered_findings:
            console.print("\n[bold]Top Findings:[/bold]")
            for f in result.ml_filtered_findings[:5]:
                sev = f.get("severity", "unknown").upper()
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "cyan")
                vtype = f.get("type", f.get("title", "unknown"))
                loc = f.get("location", {})
                console.print(
                    f"  [{color}][{sev}][/{color}] {vtype} - {loc.get('file', '')}:{loc.get('line', 0)}"
                )
    else:
        print("\n=== Smart Audit Results ===")
        print(f"Risk Level: {summary['risk_level']}")
        print(f"Total: {summary['total_findings']}")
        print(f"Critical: {summary['critical']}, High: {summary['high']}")
        print(f"FPs removed: {result.false_positives_removed}")

    # Save output
    if output:
        if fmt == "json":
            data = result.to_dict()
            data["llm_validated"] = llm_validate
            with open(output, "w") as f:
                json.dump(data, f, indent=2, default=str)
        else:
            md = _ml_result_to_markdown(result, contract)
            with open(output, "w") as f:
                f.write(md)
        success(f"Report saved to {output}")


@audit.command("profile")
@click.argument("profile_name", type=click.Choice(AVAILABLE_PROFILES + ["list"]))
@click.argument("contract", type=click.Path(exists=True), required=False)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown"]), default="json"
)
@click.option("--ci", is_flag=True, help="CI mode: exit with error if critical/high issues found")
def audit_profile(profile_name, contract, output, fmt, ci):
    """Run audit using a predefined profile (fast, balanced, thorough, security, ci, audit, defi, token)."""
    print_banner()

    # List profiles
    if profile_name == "list":
        profiles = load_profiles()
        if RICH_AVAILABLE:
            table = Table(title="Available Profiles", box=box.ROUNDED)
            table.add_column("Profile", style="bold cyan")
            table.add_column("Description")
            table.add_column("Layers")
            table.add_column("Timeout")

            for name, profile in profiles.items():
                layers_str = ", ".join(str(l) for l in profile.get("layers", []))
                table.add_row(
                    name,
                    profile.get("description", "")[:50],
                    layers_str,
                    f"{profile.get('timeout', 300)}s",
                )
            console.print(table)
        else:
            for name, profile in profiles.items():
                print(f"\n{name}: {profile.get('description', '')}")
                print(f"  Layers: {profile.get('layers', [])}")
                print(f"  Timeout: {profile.get('timeout', 300)}s")
        return

    if not contract:
        error("Contract path is required when running a profile")
        sys.exit(1)

    # Get profile configuration
    profile = get_profile(profile_name)
    if not profile:
        error(f"Profile '{profile_name}' not found")
        info(f"Available profiles: {', '.join(AVAILABLE_PROFILES)}")
        sys.exit(1)

    info(f"Running profile: {profile_name}")
    info(f"Description: {profile.get('description', 'N/A')}")

    # Extract profile settings
    layers = profile.get("layers", [1])
    timeout = profile.get("timeout", 300)
    tools_config = profile.get("tools", [])

    if tools_config == "all":
        # Use all tools from specified layers
        tools_to_run = []
        for layer in layers:
            if layer in LAYERS:
                tools_to_run.extend(LAYERS[layer]["tools"])
    elif isinstance(tools_config, list):
        tools_to_run = tools_config
    else:
        tools_to_run = QUICK_TOOLS

    info(f"Layers: {layers}")
    info(f"Tools: {', '.join(tools_to_run[:5])}{'...' if len(tools_to_run) > 5 else ''}")
    info(f"Timeout: {timeout}s per tool")

    all_results = []

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("Analyzing...", total=len(tools_to_run))

            for tool in tools_to_run:
                progress.update(task, description=f"Running {tool}...")
                result = _run_tool(tool, contract, timeout)
                all_results.append(result)

                if result["status"] == "success":
                    findings_count = len(result.get("findings", []))
                    success(f"{tool}: {findings_count} findings")
                elif result["status"] == "not_available":
                    warning(f"{tool}: not installed")
                else:
                    warning(f"{tool}: {result.get('error', 'error')[:50]}")

                progress.advance(task)
    else:
        for tool in tools_to_run:
            info(f"Running {tool}...")
            result = _run_tool(tool, contract, timeout)
            all_results.append(result)

    summary = _summarize_findings(all_results)
    total = sum(summary.values())

    # Display summary
    if RICH_AVAILABLE:
        table = Table(title=f"{profile_name.upper()} Profile Summary", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        colors = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }
        for sev, count in summary.items():
            table.add_row(sev, str(count), style=colors.get(sev, "white"))
        table.add_row("TOTAL", str(total), style="bold")
        console.print(table)
    else:
        print(f"\n=== {profile_name.upper()} Profile Summary ===")
        for sev, count in summary.items():
            print(f"{sev}: {count}")
        print(f"TOTAL: {total}")

    # Save output
    if output:
        if fmt == "sarif":
            data = _to_sarif(all_results)
            with open(output, "w") as f:
                json.dump(data, f, indent=2)
        elif fmt == "markdown":
            data = _to_markdown(all_results, contract)
            with open(output, "w") as f:
                f.write(data)
        else:
            data = {
                "profile": profile_name,
                "results": all_results,
                "summary": summary,
                "version": VERSION,
            }
            with open(output, "w") as f:
                json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")

    # CI mode exit
    if ci and (summary["CRITICAL"] > 0 or summary["HIGH"] > 0):
        error(f"Found {summary['CRITICAL']} critical and {summary['HIGH']} high issues")
        sys.exit(1)


@audit.command("single")
@click.argument("tool", type=str)
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout in seconds")
def audit_single(tool, contract, output, timeout):
    """Run a single security tool."""
    print_banner()

    # Validate tool exists
    available_tools = AdapterLoader.get_available_tools()
    all_tools = list(ADAPTER_MAP.keys())

    if tool not in all_tools:
        error(f"Unknown tool: {tool}")
        info(f"Available tools: {', '.join(all_tools)}")
        sys.exit(1)

    info(f"Running {tool} on {contract}")

    result = _run_tool(tool, contract, timeout)

    if result["status"] == "success":
        findings_count = len(result.get("findings", []))
        success(f"{findings_count} findings in {result.get('execution_time', 0):.1f}s")

        if RICH_AVAILABLE and result.get("findings"):
            table = Table(title=f"{tool.upper()} Findings", box=box.ROUNDED)
            table.add_column("Severity", width=10)
            table.add_column("Title", width=40)
            table.add_column("Location", width=30)

            for finding in result["findings"][:20]:
                location = finding.get("location", {})
                if isinstance(location, dict):
                    loc_str = f"{location.get('file', '')}:{location.get('line', 0)}"
                else:
                    loc_str = str(location)

                table.add_row(
                    str(finding.get("severity", "INFO")),
                    str(finding.get("title", finding.get("type", finding.get("id", ""))))[:40],
                    loc_str[:30],
                )

            if len(result["findings"]) > 20:
                table.add_row("...", f"({len(result['findings']) - 20} more)", "")

            console.print(table)
    else:
        error(f"Failed: {result.get('error', 'Unknown error')}")

    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        success(f"Report saved to {output}")


@audit.command("batch")
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown", "csv"]), default="json"
)
@click.option(
    "--profile",
    "-p",
    type=click.Choice(["quick", "fast", "balanced", "thorough"]),
    default="quick",
    help="Analysis profile",
)
@click.option("--parallel", "-j", type=int, default=4, help="Number of parallel workers")
@click.option("--recursive", "-r", is_flag=True, help="Recursively search for .sol files")
@click.option("--pattern", type=str, default="*.sol", help="File pattern to match")
@click.option(
    "--fail-on", type=str, default="", help="Fail on severity (comma-separated: critical,high)"
)
def audit_batch(path, output, fmt, profile, parallel, recursive, pattern, fail_on):
    """Batch analysis of multiple contracts.

    Analyze all .sol files in a directory with parallel execution.
    Aggregates results into a single comprehensive report.

    Examples:
      miesc audit batch ./contracts                     # Scan all contracts
      miesc audit batch ./src -r --profile balanced    # Recursive with balanced profile
      miesc audit batch . -j 8 -o report.json          # 8 parallel workers
      miesc audit batch ./contracts --fail-on critical,high  # CI mode
    """
    import concurrent.futures
    import glob as glob_module

    print_banner()

    # Find all Solidity files
    path_obj = Path(path)

    if path_obj.is_file():
        if path_obj.suffix == ".sol":
            sol_files = [str(path_obj)]
        else:
            error(f"Not a Solidity file: {path}")
            sys.exit(1)
    else:
        if recursive:
            sol_files = list(glob_module.glob(str(path_obj / "**" / pattern), recursive=True))
        else:
            sol_files = list(glob_module.glob(str(path_obj / pattern)))

    if not sol_files:
        warning(f"No {pattern} files found in {path}")
        sys.exit(0)

    info(f"Found {len(sol_files)} Solidity files")
    info(f"Profile: {profile} | Workers: {parallel}")

    # Select tools based on profile
    profile_tools = {
        "quick": QUICK_TOOLS,
        "fast": ["slither", "aderyn"],
        "balanced": ["slither", "aderyn", "solhint", "mythril"],
        "thorough": QUICK_TOOLS + ["echidna", "medusa"],
    }
    tools_to_run = profile_tools.get(profile, QUICK_TOOLS)
    info(f"Tools: {', '.join(tools_to_run)}")

    # Results storage
    all_contract_results = []
    aggregated_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    failed_contracts = []
    start_time = datetime.now()

    def analyze_contract(contract_path: str) -> Dict[str, Any]:
        """Analyze a single contract with all tools."""
        contract_results = []
        for tool in tools_to_run:
            result = _run_tool(tool, contract_path, timeout=120)
            contract_results.append(result)

        summary = _summarize_findings(contract_results)
        return {
            "contract": contract_path,
            "results": contract_results,
            "summary": summary,
            "total_findings": sum(summary.values()),
        }

    # Progress display
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
        ) as progress:
            task = progress.add_task("Analyzing contracts...", total=len(sol_files))

            with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
                future_to_contract = {executor.submit(analyze_contract, f): f for f in sol_files}

                for future in concurrent.futures.as_completed(future_to_contract):
                    contract = future_to_contract[future]
                    try:
                        result = future.result()
                        all_contract_results.append(result)

                        # Update aggregated summary
                        for sev, count in result["summary"].items():
                            aggregated_summary[sev] += count

                        # Show individual result
                        contract_name = Path(contract).name
                        findings = result["total_findings"]
                        crit = result["summary"]["CRITICAL"]
                        high = result["summary"]["HIGH"]

                        if crit > 0 or high > 0:
                            console.print(
                                f"  [red]{contract_name}[/red]: "
                                f"{crit} critical, {high} high, {findings} total"
                            )
                        elif findings > 0:
                            console.print(
                                f"  [yellow]{contract_name}[/yellow]: {findings} findings"
                            )

                    except Exception as e:
                        failed_contracts.append({"contract": contract, "error": str(e)})
                        console.print(f"  [red]{Path(contract).name}[/red]: error - {e}")

                    progress.advance(task)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
            future_to_contract = {executor.submit(analyze_contract, f): f for f in sol_files}

            completed = 0
            for future in concurrent.futures.as_completed(future_to_contract):
                contract = future_to_contract[future]
                completed += 1
                print(f"[{completed}/{len(sol_files)}] Processing {Path(contract).name}...")

                try:
                    result = future.result()
                    all_contract_results.append(result)

                    for sev, count in result["summary"].items():
                        aggregated_summary[sev] += count

                except Exception as e:
                    failed_contracts.append({"contract": contract, "error": str(e)})
                    print(f"  Error: {e}")

    elapsed = (datetime.now() - start_time).total_seconds()
    total_findings = sum(aggregated_summary.values())

    # Display summary
    if RICH_AVAILABLE:
        console.print("\n")
        table = Table(title="Batch Analysis Summary", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Contracts Analyzed", str(len(all_contract_results)))
        table.add_row("Failed", str(len(failed_contracts)))
        table.add_row("Execution Time", f"{elapsed:.1f}s")
        table.add_row("", "")

        colors = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }
        for sev, count in aggregated_summary.items():
            table.add_row(sev, str(count), style=colors.get(sev, "white"))

        table.add_row("TOTAL FINDINGS", str(total_findings), style="bold")
        console.print(table)

        # Show most vulnerable contracts
        sorted_contracts = sorted(
            all_contract_results,
            key=lambda x: (x["summary"]["CRITICAL"], x["summary"]["HIGH"], x["total_findings"]),
            reverse=True,
        )

        if sorted_contracts and total_findings > 0:
            console.print("\n[bold]Top Vulnerable Contracts:[/bold]")
            for result in sorted_contracts[:5]:
                if result["total_findings"] > 0:
                    console.print(
                        f"  {Path(result['contract']).name}: "
                        f"C:{result['summary']['CRITICAL']} H:{result['summary']['HIGH']} "
                        f"M:{result['summary']['MEDIUM']} L:{result['summary']['LOW']}"
                    )
    else:
        print("\n=== Batch Analysis Summary ===")
        print(f"Contracts: {len(all_contract_results)}")
        print(f"Failed: {len(failed_contracts)}")
        print(f"Time: {elapsed:.1f}s")
        print("\nFindings by severity:")
        for sev, count in aggregated_summary.items():
            print(f"  {sev}: {count}")
        print(f"  TOTAL: {total_findings}")

    # Build output data
    output_data = {
        "version": VERSION,
        "timestamp": datetime.now().isoformat(),
        "execution_time": elapsed,
        "profile": profile,
        "path": str(path),
        "contracts_analyzed": len(all_contract_results),
        "contracts_failed": len(failed_contracts),
        "aggregated_summary": aggregated_summary,
        "total_findings": total_findings,
        "contracts": all_contract_results,
        "failed": failed_contracts,
    }

    # Save output
    if output:
        if fmt == "sarif":
            # Flatten all results for SARIF
            all_results = []
            for contract_data in all_contract_results:
                for result in contract_data.get("results", []):
                    result["contract"] = contract_data["contract"]
                    all_results.append(result)
            data = _to_sarif(all_results)
            with open(output, "w") as f:
                json.dump(data, f, indent=2)
        elif fmt == "markdown":
            # Generate batch markdown report
            md = f"""# MIESC Batch Security Audit Report

**Path**: `{path}`
**Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**MIESC Version**: {VERSION}
**Profile**: {profile}

## Executive Summary

| Metric | Value |
|--------|-------|
| Contracts Analyzed | {len(all_contract_results)} |
| Contracts Failed | {len(failed_contracts)} |
| Execution Time | {elapsed:.1f}s |

### Findings by Severity

| Severity | Count |
|----------|-------|
| Critical | {aggregated_summary['CRITICAL']} |
| High | {aggregated_summary['HIGH']} |
| Medium | {aggregated_summary['MEDIUM']} |
| Low | {aggregated_summary['LOW']} |
| Info | {aggregated_summary['INFO']} |
| **Total** | **{total_findings}** |

## Contract Analysis

"""
            for contract_data in sorted_contracts:
                contract_name = Path(contract_data["contract"]).name
                summary = contract_data["summary"]
                md += f"""### {contract_name}

| Severity | Count |
|----------|-------|
| Critical | {summary['CRITICAL']} |
| High | {summary['HIGH']} |
| Medium | {summary['MEDIUM']} |
| Low | {summary['LOW']} |

"""
            md += f"\n---\n\n*Generated by MIESC v{VERSION}*\n"
            with open(output, "w") as f:
                f.write(md)
        elif fmt == "csv":
            import csv

            with open(output, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Contract", "Tool", "Severity", "Title", "Description", "Line"])
                for contract_data in all_contract_results:
                    for result in contract_data.get("results", []):
                        for finding in result.get("findings", []):
                            location = finding.get("location", {})
                            if isinstance(location, dict):
                                line = location.get("line", 0)
                            else:
                                line = 0
                            writer.writerow(
                                [
                                    Path(contract_data["contract"]).name,
                                    result.get("tool", ""),
                                    finding.get("severity", ""),
                                    finding.get("title", finding.get("type", ""))[:50],
                                    finding.get("description", finding.get("message", ""))[:100],
                                    line,
                                ]
                            )
        else:  # json
            with open(output, "w") as f:
                json.dump(output_data, f, indent=2, default=str)

        success(f"Report saved to {output}")

    # Fail-on check for CI
    if fail_on:
        severities = [s.strip().upper() for s in fail_on.split(",")]
        for sev in severities:
            if sev in aggregated_summary and aggregated_summary[sev] > 0:
                error(f"Found {aggregated_summary[sev]} {sev} issues (fail-on: {fail_on})")
                sys.exit(1)

    success(
        f"Batch analysis complete: {len(all_contract_results)} contracts, {total_findings} findings"
    )


# ============================================================================
# Detect Command (Framework Auto-Detection)
# ============================================================================


@cli.command()
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
        import json

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
        print("\n=== Framework Detection ===")
        print(f"Framework: {config.framework.value.upper()}")
        print(f"Root Path: {config.root_path}")
        print(f"Config File: {config.config_file}")
        print("\nCompiler Settings:")
        print(f"  Solc Version: {config.solc_version or 'auto'}")
        print(f"  EVM Version: {config.evm_version or 'default'}")
        print(f"  Optimizer: {'enabled' if config.optimizer_enabled else 'disabled'}")
        print("\nProject Paths:")
        print(f"  Source: {config.src_path}")
        print(f"  Test: {config.test_path}")
        print(f"  Output: {config.out_path}")

        if config.remappings:
            print(f"\nRemappings: ({len(config.remappings)} entries)")
            for remap in config.remappings[:5]:
                print(f"  {remap}")

    success(f"Detected {config.framework.value.upper()} project")


# ============================================================================
# Doctor Command
# ============================================================================


@cli.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed information")
def doctor(verbose):
    """Check tool availability and system health."""
    print_banner()
    info("Checking system health and tool availability...\n")

    # Check basic dependencies
    dependencies = {
        "python": "python3 --version",
        "solc": "solc --version",
        "node": "node --version",
        "npm": "npm --version",
    }

    if RICH_AVAILABLE:
        # Dependencies table
        dep_table = Table(title="Core Dependencies", box=box.ROUNDED)
        dep_table.add_column("Dependency", style="bold", width=15)
        dep_table.add_column("Status", width=10)
        dep_table.add_column("Version", width=40)

        for dep, cmd in dependencies.items():
            try:
                import subprocess

                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
                version = (
                    result.stdout.strip().split("\n")[0][:40]
                    or result.stderr.strip().split("\n")[0][:40]
                )
                dep_table.add_row(dep, "[green]OK[/green]", version)
            except Exception:
                dep_table.add_row(dep, "[yellow]MISSING[/yellow]", "Not installed")

        console.print(dep_table)
        console.print("")

        # Security tools table
        tools_table = Table(title="Security Tools (29 Total)", box=box.ROUNDED)
        tools_table.add_column("Layer", style="bold", width=8)
        tools_table.add_column("Tool", width=25)
        tools_table.add_column("Status", width=15)

        total_available = 0
        total_tools = 0

        for layer_num, layer_info in LAYERS.items():
            for tool in layer_info["tools"]:
                total_tools += 1
                status_info = AdapterLoader.check_tool_status(tool)

                if status_info.get("available"):
                    status_display = "[green]available[/green]"
                    total_available += 1
                elif status_info.get("status") == "not_installed":
                    status_display = "[yellow]not installed[/yellow]"
                elif status_info.get("status") == "no_adapter":
                    status_display = "[dim]pending[/dim]"
                else:
                    status_display = f"[red]{status_info.get('status', 'error')}[/red]"

                tools_table.add_row(str(layer_num), tool, status_display)

        console.print(tools_table)
        console.print(f"\n[bold]{total_available}/{total_tools}[/bold] tools available")

    else:
        print("=== Core Dependencies ===")
        for dep, cmd in dependencies.items():
            try:
                import subprocess

                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
                print(f"[OK] {dep}")
            except Exception:
                print(f"[MISSING] {dep}")

        print("\n=== Security Tools ===")
        total_available = 0
        total_tools = 0

        for layer_num, layer_info in LAYERS.items():
            print(f"\nLayer {layer_num}: {layer_info['name']}")
            for tool in layer_info["tools"]:
                total_tools += 1
                status_info = AdapterLoader.check_tool_status(tool)
                if status_info.get("available"):
                    print(f"  [OK] {tool}")
                    total_available += 1
                else:
                    print(f"  [MISSING] {tool}")

        print(f"\n{total_available}/{total_tools} tools available")


# ============================================================================
# Export Command
# ============================================================================


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["sarif", "markdown", "csv", "html"]), required=True
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def export(input_file, fmt, output):
    """Export JSON results to different formats."""
    print_banner()

    with open(input_file) as f:
        data = json.load(f)

    results = data.get("results", [data])
    contract = data.get("contract", input_file)

    if fmt == "sarif":
        output_data = _to_sarif(results)
        output_str = json.dumps(output_data, indent=2)
        ext = ".sarif.json"
    elif fmt == "markdown":
        output_str = _to_markdown(results, contract)
        ext = ".md"
    elif fmt == "csv":
        import csv
        import io

        output_io = io.StringIO()
        writer = csv.writer(output_io)
        writer.writerow(["Tool", "Severity", "Title", "Description", "Location", "Line"])
        for result in results:
            for finding in result.get("findings", []):
                location = finding.get("location", {})
                if isinstance(location, dict):
                    loc_file = location.get("file", "")
                    loc_line = location.get("line", 0)
                else:
                    loc_file = str(location)
                    loc_line = 0

                writer.writerow(
                    [
                        result.get("tool", ""),
                        finding.get("severity", ""),
                        finding.get("title", finding.get("type", "")),
                        finding.get("description", finding.get("message", ""))[:100],
                        loc_file,
                        loc_line,
                    ]
                )
        output_str = output_io.getvalue()
        ext = ".csv"
    elif fmt == "html":
        output_str = f"""<!DOCTYPE html>
<html>
<head>
    <title>MIESC Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        h1 {{ color: #1a73e8; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .finding {{ border-left: 4px solid #ccc; padding: 10px 20px; margin: 10px 0; }}
        .finding.critical {{ border-color: #dc3545; }}
        .finding.high {{ border-color: #fd7e14; }}
        .finding.medium {{ border-color: #ffc107; }}
        .finding.low {{ border-color: #28a745; }}
    </style>
</head>
<body>
    <h1>MIESC Security Report</h1>
    <div class="summary">
        <strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
        <strong>Contract:</strong> {contract}<br>
        <strong>MIESC Version:</strong> {VERSION}
    </div>
"""
        summary = _summarize_findings(results)
        output_str += f"""
    <h2>Summary</h2>
    <ul>
        <li>Critical: {summary['CRITICAL']}</li>
        <li>High: {summary['HIGH']}</li>
        <li>Medium: {summary['MEDIUM']}</li>
        <li>Low: {summary['LOW']}</li>
        <li>Info: {summary['INFO']}</li>
    </ul>
    <h2>Findings</h2>
"""
        for result in results:
            for finding in result.get("findings", []):
                severity = str(finding.get("severity", "info")).lower()
                output_str += f"""
    <div class="finding {severity}">
        <strong>[{finding.get("severity", "INFO")}] {finding.get("title", finding.get("type", "Finding"))}</strong>
        <p>{finding.get("description", finding.get("message", ""))}</p>
    </div>
"""
        output_str += "</body></html>"
        ext = ".html"
    else:
        error(f"Format {fmt} not supported")
        return

    # Determine output path
    if not output:
        output = str(Path(input_file).with_suffix(ext))

    with open(output, "w") as f:
        f.write(output_str)

    success(f"Exported to {output}")


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
# Report Command
# ============================================================================


def _get_impact_description(severity: str) -> str:
    """Get impact description based on severity."""
    impacts = {
        "critical": "Complete loss of funds or contract takeover possible. Immediate exploitation risk.",
        "high": "Significant financial loss or contract compromise possible under certain conditions.",
        "medium": "Limited financial impact or requires specific conditions to exploit.",
        "low": "Minor impact on contract functionality or gas efficiency.",
        "info": "Informational finding for code quality improvement.",
    }
    return impacts.get(severity, "Impact assessment pending.")


def _interactive_wizard(variables: dict, console) -> dict:
    """
    Interactive wizard for report metadata.
    Only asks for client and auditor info - everything else comes from audit data.
    """
    from rich.prompt import Prompt

    def is_missing(value):
        if value is None:
            return True
        if isinstance(value, str):
            return value.strip() == "" or value.lower() in ("n/a", "unknown", "none")
        return False

    fields_to_ask = []

    if is_missing(variables.get("client_name")):
        fields_to_ask.append(("client_name", "Client/Project Name"))

    if is_missing(variables.get("auditor_name")):
        fields_to_ask.append(("auditor_name", "Auditor Name"))

    if not fields_to_ask:
        console.print("[green]✓ Report metadata complete.[/green]")
        return variables

    console.print("\n[bold cyan]MIESC Report Wizard[/bold cyan]")
    console.print("[dim]Press Enter to skip.[/dim]\n")

    changes = 0
    for key, label in fields_to_ask:
        value = Prompt.ask(f"[yellow]{label}[/yellow]", default="")
        if value.strip():
            variables[key] = value.strip()
            changes += 1

    if changes:
        console.print(f"[green]✓ {changes} field(s) updated.[/green]\n")

    return variables


@cli.command()
@click.argument("results_file", type=click.Path(exists=True))
@click.option(
    "--template",
    "-t",
    type=click.Choice(
        ["professional", "executive", "technical", "github-pr", "simple", "profesional", "premium"]
    ),
    default="simple",
    help="Report template to use (premium/profesional include CVSS scores, attack scenarios, and deployment recommendations)",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["markdown", "html", "pdf"]),
    default="markdown",
    help="Output format",
)
@click.option("--client", type=str, help="Client name for the report")
@click.option("--auditor", type=str, help="Auditor name for the report")
@click.option("--title", type=str, help="Custom report title")
@click.option("--contract-name", type=str, help="Contract name (overrides auto-detected)")
@click.option("--repository", type=str, help="Repository URL or path")
@click.option("--commit", type=str, help="Commit hash for the audited code")
@click.option(
    "--network",
    type=str,
    default="Ethereum Mainnet",
    help="Target network (e.g., Ethereum Mainnet, Polygon)",
)
@click.option(
    "--classification",
    type=str,
    default="CONFIDENTIAL",
    help="Report classification (CONFIDENTIAL, PUBLIC, etc.)",
)
@click.option(
    "--llm-interpret",
    is_flag=True,
    default=False,
    help="Use LLM to interpret findings and generate executive insights (requires Ollama)",
)
@click.option(
    "--interactive",
    "-i",
    is_flag=True,
    default=False,
    help="Interactive wizard mode: prompt for missing/unknown values before generating report",
)
def report(
    results_file,
    template,
    output,
    output_format,
    client,
    auditor,
    title,
    contract_name,
    repository,
    commit,
    network,
    classification,
    llm_interpret,
    interactive,
):
    """Generate formatted security reports from audit results.

    Takes JSON audit results and applies a template to generate
    professional security reports.

    Examples:

      miesc report results.json -t professional -o report.md

      miesc report results.json -t executive --client "Acme" -o summary.md

      miesc report results.json -t premium --client "Acme Corp" --auditor "Security Team" \\
          --contract-name "TokenV2.sol" --repository "github.com/acme/token" \\
          --network "Polygon" -o audit.pdf -f pdf

      miesc report results.json -t premium -i  # Interactive wizard mode

      miesc report results.json -t github-pr  # Output to stdout
    """
    print_banner()

    # Load results
    try:
        with open(results_file, "r") as f:
            results = json.load(f)
    except json.JSONDecodeError as e:
        error(f"Invalid JSON in {results_file}: {e}")
        sys.exit(1)
    except Exception as e:
        error(f"Failed to read {results_file}: {e}")
        sys.exit(1)

    info(f"Loaded results from {results_file}")

    # Locate template
    templates_dir = ROOT_DIR / "docs" / "templates" / "reports"
    template_file = templates_dir / f"{template}.md"

    if not template_file.exists():
        error(f"Template not found: {template_file}")
        info("Available templates: professional, executive, technical, github-pr, simple, premium")
        sys.exit(1)

    # Load template
    template_content = template_file.read_text()

    # Extract data from results
    summary = results.get("summary", {})

    # For batch results, use aggregated_summary if available
    if not summary and "aggregated_summary" in results:
        summary = results.get("aggregated_summary", {})

    # Extract findings from results (can be at root level, within tool results, or in batch format)
    findings = results.get("findings", [])

    # Smart audit format: prefer ML-enhanced findings (adjusted severities) over raw
    if not findings:
        ml_enhanced = results.get("ml_enhanced", {})
        if (
            isinstance(ml_enhanced, dict)
            and isinstance(ml_enhanced.get("findings"), list)
            and ml_enhanced["findings"]
        ):
            findings = ml_enhanced["findings"]
        elif (
            isinstance(ml_enhanced, dict)
            and isinstance(ml_enhanced.get("top_findings"), list)
            and ml_enhanced["top_findings"]
        ):
            findings = ml_enhanced["top_findings"]
        elif "raw_findings" in results and results["raw_findings"].get("findings"):
            findings = results["raw_findings"]["findings"]

    if not findings:
        # Extract from tool results (single contract format)
        for tool_result in results.get("results", []):
            tool_findings = tool_result.get("findings", [])
            for f in tool_findings:
                f["tool"] = tool_result.get("tool", "unknown")
            findings.extend(tool_findings)

    if not findings:
        # Extract from batch format: contracts[].results[].findings
        for contract_data in results.get("contracts", []):
            contract_file = contract_data.get("contract", "unknown")
            for tool_result in contract_data.get("results", []):
                tool_findings = tool_result.get("findings", [])
                for f in tool_findings:
                    f["tool"] = tool_result.get("tool", "unknown")
                    f["source_contract"] = contract_file
                findings.extend(tool_findings)

    # Normalize summary keys (can be uppercase or lowercase)
    if summary:
        summary = {k.lower(): v for k, v in summary.items()}

    # Calculate severity counts from summary or from findings
    if summary:
        critical_count = summary.get("critical", 0)
        high_count = summary.get("high", 0)
        medium_count = summary.get("medium", 0)
        low_count = summary.get("low", 0)
        info_count = summary.get("info", summary.get("informational", 0))
    else:
        # Calculate from findings if summary is not available
        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        medium_count = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
        low_count = sum(1 for f in findings if f.get("severity", "").lower() == "low")
        info_count = sum(
            1 for f in findings if f.get("severity", "").lower() in ("info", "informational")
        )

    def get_status(count, severity):
        if count == 0:
            return "✅ None Found"
        elif severity in ("critical", "high"):
            return f"⚠️ {count} Issue{'s' if count > 1 else ''} - Action Required"
        else:
            return f"ℹ️ {count} Issue{'s' if count > 1 else ''}"

    # Get tools used per layer
    tools_by_layer = results.get("tools_by_layer", {})
    tool_list = results.get("tools", [])

    # Generate risk summary based on findings
    overall_risk = _calculate_risk_level(summary)
    risk_summaries = {
        "CRITICAL": "**CRITICAL RISK**: This contract contains critical vulnerabilities that could lead to complete loss of funds or contract takeover. Immediate remediation is required before deployment.",
        "HIGH": "**HIGH RISK**: Significant security issues were identified that could result in substantial financial loss or contract compromise. These issues should be addressed before deployment.",
        "MEDIUM": "**MEDIUM RISK**: Several security concerns were found that could potentially be exploited under certain conditions. Recommended to address before deployment.",
        "LOW": "**LOW RISK**: Minor issues were identified that should be addressed to improve code quality and security posture.",
        "MINIMAL": "**MINIMAL RISK**: No significant security issues were identified. The contract follows security best practices.",
    }

    # Prepare template variables
    # CLI parameters override auto-detected values from results
    # Support multiple JSON formats: contract, contract_path, path
    detected_contract = (
        results.get("contract") or results.get("contract_path") or results.get("path") or "Unknown"
    )
    # Extract just the filename from path
    if "/" in detected_contract:
        detected_contract = detected_contract.split("/")[-1]

    variables = {
        "contract_name": contract_name or detected_contract,
        "audit_date": results.get("timestamp", datetime.now().isoformat())[:10],
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "client_name": client or "Client",
        "auditor_name": auditor or "MIESC Security",
        "version": results.get("version", VERSION),
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "info_count": info_count,
        "total_findings": len(findings),
        "files_count": results.get("files_count", results.get("contracts_analyzed", 1)),
        "tools_count": len(tool_list),
        "overall_risk": overall_risk,
        "miesc_version": VERSION,
        # Additional fields for professional template
        "repository": repository or results.get("repository", "Local Analysis"),
        "commit_hash": commit or results.get("commit", "N/A"),
        "lines_of_code": results.get("lines_of_code", "N/A"),
        "audit_duration": results.get("duration", "N/A"),
        "critical_status": get_status(critical_count, "critical"),
        "high_status": get_status(high_count, "high"),
        "medium_status": get_status(medium_count, "medium"),
        "low_status": get_status(low_count, "low"),
        "info_status": get_status(info_count, "info"),
        "risk_summary": risk_summaries.get(overall_risk, "Risk assessment pending."),
        # Layer tools
        "layer1_tools": ", ".join(
            tools_by_layer.get("static_analysis", ["slither", "aderyn", "solhint"])
        ),
        "layer2_tools": ", ".join(
            tools_by_layer.get("dynamic_testing", ["echidna", "medusa", "foundry"])
        ),
        "layer3_tools": ", ".join(
            tools_by_layer.get("symbolic_execution", ["mythril", "manticore", "halmos"])
        ),
        "layer4_tools": ", ".join(
            tools_by_layer.get("formal_verification", ["certora", "smtchecker"])
        ),
        "layer5_tools": ", ".join(tools_by_layer.get("property_testing", ["propertygpt"])),
        "layer6_tools": ", ".join(
            tools_by_layer.get("ai_analysis", ["smartllm", "gptscan", "llmsmartaudit"])
        ),
        "layer7_tools": ", ".join(tools_by_layer.get("ml_detection", ["dagnn", "smartbugs_ml"])),
        "layer8_tools": ", ".join(tools_by_layer.get("defi", ["defi", "mev_detector"])),
        "layer9_tools": ", ".join(
            tools_by_layer.get("specialized", ["gas_analyzer", "threat_model"])
        ),
        # Empty lists for optional sections
        "swc_mappings": [],
        "owasp_mappings": [],
        "tool_outputs": [],
        "files_analyzed": [],  # Will be populated below
        "files_in_scope": [],  # Will be populated below
        # LLM interpretation placeholders (populated if --llm-interpret is used)
        "llm_executive_summary": "",
        "llm_risk_narrative": "",
        "llm_remediation_priority": [],
        "llm_critical_interpretations": [],
        "llm_enabled": False,
        # Profesional template variables (populated for profesional template)
        "cvss_scores": [],
        "risk_matrix": {},
        "overall_risk_score": 0,
        "deployment_recommendation": "CONDITIONAL",
        "deployment_justification": "",
        "deployment_recommendation_color": "#ff9800",
        "deployment_recommendation_bg": "#fff8e1",
        "quick_wins": [],
        "effort_impact_matrix": {},
        "attack_scenarios": [],
        "code_remediations": [],
        "category_summary": [],
        "exploitability_rating": "Medium",
        "business_impact": "Medium",
        "confidence_level": "High",
        "value_at_risk": None,
        "out_of_scope": [],
        "engagement_type": "Security Audit",
        "target_network": network,
        "classification": classification,
        "report_version": "1.0",
    }

    # =========================================================================
    # Generate Files Analyzed / Files In Scope
    # =========================================================================
    files_analyzed = []
    files_in_scope = []
    total_lines = 0

    # Check if batch audit (has "contracts" array)
    if "contracts" in results:
        for idx, contract_data in enumerate(results.get("contracts", []), 1):
            contract_path = contract_data.get("contract", "Unknown")
            contract_name_short = (
                Path(contract_path).name if contract_path != "Unknown" else f"Contract {idx}"
            )
            contract_findings = contract_data.get("total_findings", 0)

            # Try to get lines of code
            lines = "N/A"
            try:
                if contract_path and Path(contract_path).exists():
                    with open(contract_path, "r") as f:
                        lines = len(f.readlines())
                        total_lines += lines
            except Exception:
                pass

            files_analyzed.append(
                {
                    "path": contract_name_short,
                    "full_path": contract_path,
                    "lines": lines,
                    "findings": contract_findings,
                }
            )
            files_in_scope.append(
                {"path": contract_name_short, "lines": lines, "description": "Smart Contract"}
            )
    else:
        # Single contract - try multiple sources for contract path
        contract_path = results.get(
            "contract", results.get("contract_path", results.get("path", "Unknown"))
        )

        # If not found at root level, try to get from first result
        if contract_path == "Unknown" and results.get("results"):
            for r in results.get("results", []):
                if r.get("contract"):
                    contract_path = r.get("contract")
                    break

        contract_name_short = (
            Path(contract_path).name if contract_path and contract_path != "Unknown" else "Contract"
        )

        lines = 0
        functions_count = 0
        try:
            if contract_path and contract_path != "Unknown" and Path(contract_path).exists():
                with open(contract_path, "r") as f:
                    content = f.read()
                    lines = len(content.splitlines())
                    total_lines = lines
                    # Count functions
                    import re

                    functions_count = len(re.findall(r"\bfunction\s+\w+\s*\(", content))
        except Exception:
            lines = "N/A"

        files_analyzed.append(
            {
                "path": contract_name_short,
                "full_path": contract_path,
                "lines": lines,
                "functions": functions_count,
                "findings": len(findings),
            }
        )
        files_in_scope.append(
            {
                "path": contract_name_short,
                "lines": lines,
                "functions": functions_count,
                "description": "Smart Contract",
            }
        )

    variables["files_analyzed"] = files_analyzed
    variables["files_in_scope"] = files_in_scope
    variables["files_count"] = len(files_analyzed)
    if total_lines > 0:
        variables["lines_of_code"] = total_lines

    # =========================================================================
    # Enhanced Tool Execution Summary
    # =========================================================================
    # Get tool results - handle multiple audit formats
    tool_results = results.get("results", [])
    if not tool_results and "contracts" in results:
        # Batch audit format: aggregate results from all contracts
        for contract_data in results.get("contracts", []):
            tool_results.extend(contract_data.get("results", []))

    # Smart audit format: build tool_results from tools_run/success/failed
    if not tool_results and "tools_run" in results:
        tools_run = results.get("tools_run", [])
        tools_success = set(results.get("tools_success", []))
        tools_failed = set(results.get("tools_failed", []))
        raw_findings = results.get("raw_findings", {}).get("findings", [])
        ml_findings = results.get("ml_filtered", {}).get("findings", [])
        all_findings = ml_findings if ml_findings else raw_findings

        # Group findings by tool
        findings_by_tool = {}
        for f in all_findings:
            tool = f.get("tool", "unknown")
            if tool not in findings_by_tool:
                findings_by_tool[tool] = []
            findings_by_tool[tool].append(f)

        # Build tool_results from tools_run
        for tool in tools_run:
            tool_findings = findings_by_tool.get(tool, [])
            if tool in tools_success:
                status = "success"
            elif tool in tools_failed:
                status = "failed"
            else:
                status = "unknown"
            tool_results.append(
                {
                    "tool": tool,
                    "status": status,
                    "findings": tool_findings,
                    "duration": "N/A",
                }
            )
    tools_execution_summary = []
    layer_summary = {}

    # Layer name mapping
    layer_names = {
        "static_analysis": "Layer 1: Static Analysis",
        "dynamic_testing": "Layer 2: Dynamic Testing",
        "symbolic_execution": "Layer 3: Symbolic Execution",
        "formal_verification": "Layer 4: Formal Verification",
        "property_testing": "Layer 5: Property Testing",
        "ai_analysis": "Layer 6: AI/LLM Analysis",
        "ml_detection": "Layer 7: ML Detection",
        "defi": "Layer 8: DeFi Security",
        "specialized": "Layer 9: Specialized Analysis",
    }

    # Tool to layer mapping (when layer not specified by adapter)
    TOOL_LAYER_MAP = {
        # Layer 1: Static Analysis
        "slither": "static_analysis",
        "aderyn": "static_analysis",
        "solhint": "static_analysis",
        "semgrep": "static_analysis",
        "solc": "static_analysis",
        "wake": "static_analysis",
        # Layer 2: Dynamic Testing
        "echidna": "dynamic_testing",
        "foundry": "dynamic_testing",
        "hardhat": "dynamic_testing",
        "medusa": "dynamic_testing",
        "dogefuzz": "dynamic_testing",
        "vertigo": "dynamic_testing",
        # Layer 3: Symbolic Execution
        "mythril": "symbolic_execution",
        "manticore": "symbolic_execution",
        "halmos": "symbolic_execution",
        "hevm": "symbolic_execution",
        "oyente": "symbolic_execution",
        # Layer 4: Formal Verification
        "certora": "formal_verification",
        "scribble": "formal_verification",
        "pyrometer": "formal_verification",
        "smtchecker": "formal_verification",
        "propertygpt": "formal_verification",
        # Layer 5: AI Analysis
        "smartllm": "ai_analysis",
        "gptscan": "ai_analysis",
        "llmsmartaudit": "ai_analysis",
        "4naly3er": "ai_analysis",
        "gpt-4": "ai_analysis",
        # Layer 6: ML Detection
        "dagnn": "ml_detection",
        "smartbugs_ml": "ml_detection",
        "smartbugs_detector": "ml_detection",
        "smartguard": "ml_detection",
        "ml-detector": "ml_detection",
        # Layer 7: DeFi Security
        "defi": "defi",
        "defi-scanner": "defi",
        "mev_detector": "defi",
        # Layer 8: Specialized Analysis
        "threat_model": "specialized",
        "gas_analyzer": "specialized",
        "contract_clone_detector": "specialized",
        "advanced_detector": "specialized",
        "token-analyzer": "specialized",
    }

    for tool_result in tool_results:
        tool_name = tool_result.get("tool", "unknown")
        tool_status = tool_result.get("status", "unknown")
        tool_duration = tool_result.get("duration", "N/A")
        tool_findings = tool_result.get("findings", [])
        tool_layer = tool_result.get("layer") or TOOL_LAYER_MAP.get(tool_name.lower(), "unknown")
        tool_error = tool_result.get("error", "")

        # Map status to human-readable
        status_map = {
            "success": "Success",
            "failed": "Failed",
            "skipped": "Skipped",
            "timeout": "Timeout",
            "error": "Error",
        }
        display_status = status_map.get(
            tool_status, tool_status.capitalize() if isinstance(tool_status, str) else "Unknown"
        )

        tools_execution_summary.append(
            {
                "name": tool_name,
                "status": display_status,
                "status_icon": (
                    "✅"
                    if tool_status == "success"
                    else ("⚠️" if tool_status in ("failed", "error", "timeout") else "⏭️")
                ),
                "duration": (
                    f"{tool_duration}s"
                    if isinstance(tool_duration, (int, float))
                    else str(tool_duration)
                ),
                "findings_count": len(tool_findings),
                "layer": layer_names.get(tool_layer, tool_layer),
                "error": tool_error[:100] if tool_error else "",
            }
        )

        # Aggregate by layer
        layer_key = tool_layer if tool_layer else "unknown"
        if layer_key not in layer_summary:
            layer_summary[layer_key] = {
                "name": layer_names.get(layer_key, layer_key),
                "tools_executed": [],
                "tools_success": 0,
                "tools_failed": 0,
                "findings_count": 0,
            }
        layer_summary[layer_key]["tools_executed"].append(tool_name)
        layer_summary[layer_key]["findings_count"] += len(tool_findings)
        if tool_status == "success":
            layer_summary[layer_key]["tools_success"] += 1
        elif tool_status in ("failed", "error", "timeout"):
            layer_summary[layer_key]["tools_failed"] += 1

    # Convert layer_summary to list sorted by layer order
    layer_order = [
        "static_analysis",
        "dynamic_testing",
        "symbolic_execution",
        "formal_verification",
        "property_testing",
        "ai_analysis",
        "ml_detection",
        "defi",
        "specialized",
    ]
    layer_summary_list = []
    for layer_key in layer_order:
        if layer_key in layer_summary:
            ls = layer_summary[layer_key]
            layer_summary_list.append(
                {
                    "name": ls["name"],
                    "tools": ", ".join(ls["tools_executed"]) if ls["tools_executed"] else "None",
                    "success_count": ls["tools_success"],
                    "failed_count": ls["tools_failed"],
                    "findings_count": ls["findings_count"],
                    "coverage_status": (
                        "✅ Complete"
                        if ls["tools_success"] > 0 and ls["tools_failed"] == 0
                        else ("⚠️ Partial" if ls["tools_success"] > 0 else "❌ Not Executed")
                    ),
                }
            )

    variables["tools_execution_summary"] = tools_execution_summary
    variables["layer_summary"] = layer_summary_list
    variables["total_tools_executed"] = len(tools_execution_summary)

    # Populate tool_outputs for Appendix A (detailed tool execution)
    tool_outputs = []
    for tool_result in tool_results:
        tool_name = tool_result.get("tool", "unknown")
        tool_status = tool_result.get("status", "unknown")
        tool_duration = tool_result.get("execution_time", "N/A")
        tool_findings = tool_result.get("findings", [])
        tool_error = tool_result.get("error", "")
        tool_metadata = tool_result.get("metadata", {})

        # Build output summary
        output_lines = []
        if tool_status == "success":
            output_lines.append("Analysis completed successfully.")
            output_lines.append(f"Findings detected: {len(tool_findings)}")
            if tool_findings:
                output_lines.append("")
                output_lines.append("Findings summary:")
                for i, f in enumerate(tool_findings[:10], 1):
                    sev = f.get("severity", "unknown").upper()
                    ftype = f.get("type", f.get("title", "unknown"))
                    loc = f.get("location", {})
                    line = loc.get("line", "?")
                    output_lines.append(f"  {i}. [{sev}] {ftype} (line {line})")
                if len(tool_findings) > 10:
                    output_lines.append(f"  ... and {len(tool_findings) - 10} more")
        elif tool_error:
            output_lines.append(f"Error: {tool_error}")
        else:
            output_lines.append(f"Status: {tool_status}")

        tool_outputs.append(
            {
                "name": tool_name,
                "duration": (
                    f"{tool_duration}s"
                    if isinstance(tool_duration, (int, float))
                    else str(tool_duration)
                ),
                "exit_code": 0 if tool_status == "success" else 1,
                "findings_count": len(tool_findings),
                "output": "\n".join(output_lines),
            }
        )

    variables["tool_outputs"] = tool_outputs

    # Interactive wizard mode
    if interactive and RICH_AVAILABLE:
        variables = _interactive_wizard(variables, console)
    variables["tools_success_count"] = sum(
        1 for t in tools_execution_summary if t["status"] == "Success"
    )
    variables["tools_failed_count"] = sum(
        1 for t in tools_execution_summary if t["status"] in ("Failed", "Error", "Timeout")
    )

    # =========================================================================
    # LLM Interpretation (if enabled)
    # =========================================================================
    if llm_interpret:
        info("LLM interpretation enabled - generating AI-powered insights...")
        try:
            from src.reports.llm_interpreter import LLMReportInterpreter

            # Get contract code if available
            contract_path = results.get("contract_path") or results.get("contract")
            contract_code = ""
            if contract_path:
                try:
                    contract_file = Path(contract_path)
                    if contract_file.exists():
                        contract_code = contract_file.read_text()[:10000]  # Limit to 10k chars
                except Exception:
                    pass

            interpreter = LLMReportInterpreter()

            if interpreter.is_available():
                variables["llm_enabled"] = True
                variables["llm_model"] = interpreter.config.model

                # Generate executive interpretation
                info("Generating executive summary interpretation...")
                exec_summary = interpreter.generate_executive_interpretation(
                    findings=findings,
                    summary=summary,
                    contract_name=results.get("contract", "Unknown"),
                )
                variables["llm_executive_summary"] = exec_summary

                # Generate risk narrative
                info("Generating risk narrative...")
                risk_narrative = interpreter.generate_risk_narrative(
                    summary=summary, findings=findings
                )
                variables["llm_risk_narrative"] = risk_narrative

                # Interpret critical findings
                critical_high = [
                    f for f in findings if f.get("severity", "").lower() in ("critical", "high")
                ]
                if critical_high:
                    info(f"Interpreting {len(critical_high[:5])} critical/high findings...")
                    interpreted = interpreter.interpret_critical_findings(
                        critical_findings=critical_high[:5], contract_code=contract_code  # Top 5
                    )
                    variables["llm_critical_interpretations"] = interpreted

                # Generate remediation priority
                if findings:
                    info("Generating remediation priority recommendations...")
                    priority = interpreter.suggest_remediation_priority(
                        findings=findings[:10]  # Top 10
                    )
                    variables["llm_remediation_priority"] = priority

                success("LLM interpretation complete!")
            else:
                warning("Ollama not available - skipping LLM interpretation")
                warning("Start Ollama with: ollama serve && ollama pull deepseek-coder:6.7b")

        except ImportError as e:
            warning(f"LLM interpreter not available: {e}")
        except Exception as e:
            warning(f"LLM interpretation failed: {e}")

    # =========================================================================
    # Profesional Template Processing
    # =========================================================================
    if template in ("profesional", "premium"):
        info("Generating premium report data (CVSS scores, risk matrix, etc.)...")
        try:
            from src.reports.risk_calculator import calculate_premium_risk_data

            # Calculate risk data
            risk_data = calculate_premium_risk_data(findings)

            # Update variables with risk data
            variables.update(
                {
                    "cvss_scores": risk_data.get("cvss_scores", []),
                    "risk_matrix": risk_data.get("risk_matrix", {}),
                    "overall_risk_score": risk_data.get("overall_risk_score", 0),
                    "deployment_recommendation": risk_data.get(
                        "deployment_recommendation", "CONDITIONAL"
                    ),
                    "deployment_justification": risk_data.get("deployment_justification", ""),
                    "deployment_recommendation_color": risk_data.get(
                        "deployment_recommendation_color", "#ff9800"
                    ),
                    "deployment_recommendation_bg": risk_data.get(
                        "deployment_recommendation_bg", "#fff8e1"
                    ),
                    "quick_wins": risk_data.get("quick_wins", []),
                    "effort_impact_matrix": risk_data.get("effort_impact_matrix", {}),
                    "critical_percent": risk_data.get("critical_percent", 0),
                    "high_percent": risk_data.get("high_percent", 0),
                    "medium_percent": risk_data.get("medium_percent", 0),
                    "low_percent": risk_data.get("low_percent", 0),
                    "info_percent": risk_data.get("info_percent", 0),
                }
            )

            # Calculate category summary
            categories = {}
            for f in findings:
                cat = f.get("category") or f.get("type", "General")
                if cat not in categories:
                    categories[cat] = {"count": 0, "severities": []}
                categories[cat]["count"] += 1
                categories[cat]["severities"].append(f.get("severity", "unknown").lower())

            category_summary = []
            for cat, data in sorted(categories.items(), key=lambda x: -x[1]["count"]):
                sev_counts = {}
                for s in data["severities"]:
                    sev_counts[s] = sev_counts.get(s, 0) + 1
                breakdown = ", ".join([f"{v} {k}" for k, v in sorted(sev_counts.items())])
                category_summary.append(
                    {
                        "name": cat,
                        "count": data["count"],
                        "breakdown": breakdown,
                    }
                )
            variables["category_summary"] = category_summary

            # =================================================================
            # Generate SWC Registry Compliance
            # =================================================================
            SWC_MAPPING = {
                "reentrancy": ("SWC-107", "Reentrancy"),
                "reentrant": ("SWC-107", "Reentrancy"),
                "integer-overflow": ("SWC-101", "Integer Overflow and Underflow"),
                "overflow": ("SWC-101", "Integer Overflow and Underflow"),
                "underflow": ("SWC-101", "Integer Overflow and Underflow"),
                "unchecked-call": ("SWC-104", "Unchecked Call Return Value"),
                "unchecked-return": ("SWC-104", "Unchecked Call Return Value"),
                "tx-origin": ("SWC-115", "Authorization through tx.origin"),
                "tx.origin": ("SWC-115", "Authorization through tx.origin"),
                "access-control": ("SWC-105", "Unprotected Ether Withdrawal"),
                "delegatecall": ("SWC-112", "Delegatecall to Untrusted Callee"),
                "timestamp": ("SWC-116", "Block values as a proxy for time"),
                "block-timestamp": ("SWC-116", "Block values as a proxy for time"),
                "denial-of-service": ("SWC-113", "DoS with Failed Call"),
                "dos": ("SWC-113", "DoS with Failed Call"),
                "assembly": ("SWC-127", "Arbitrary Jump with Function Type Variable"),
                "uninitialized": ("SWC-109", "Uninitialized Storage Pointer"),
                "floating-pragma": ("SWC-103", "Floating Pragma"),
                "pragma": ("SWC-103", "Floating Pragma"),
                "outdated-compiler": ("SWC-102", "Outdated Compiler Version"),
                "solc-version": ("SWC-102", "Outdated Compiler Version"),
                "shadowing": ("SWC-119", "Shadowing State Variables"),
                "visibility": ("SWC-100", "Function Default Visibility"),
            }

            swc_found = {}
            for f in findings:
                f_type = (
                    (f.get("type") or f.get("check") or f.get("category") or "")
                    .lower()
                    .replace("_", "-")
                    .replace(" ", "-")
                )
                f_title = (f.get("title") or f.get("name") or "").lower()

                # Try to match by type or title
                for key, (swc_id, swc_title) in SWC_MAPPING.items():
                    if key in f_type or key in f_title:
                        if swc_id not in swc_found:
                            swc_found[swc_id] = {
                                "id": swc_id,
                                "title": swc_title,
                                "count": 0,
                                "status": "Found",
                                "status_icon": "⚠️",
                                "finding_ids": [],
                            }
                        swc_found[swc_id]["count"] += 1
                        swc_found[swc_id]["finding_ids"].append(
                            f"F{len(swc_found[swc_id]['finding_ids'])+1}"
                        )
                        break

            # Add common SWC entries that were checked but not found
            common_swc = [
                ("SWC-107", "Reentrancy"),
                ("SWC-101", "Integer Overflow and Underflow"),
                ("SWC-104", "Unchecked Call Return Value"),
                ("SWC-115", "Authorization through tx.origin"),
                ("SWC-103", "Floating Pragma"),
                ("SWC-102", "Outdated Compiler Version"),
            ]
            for swc_id, swc_title in common_swc:
                if swc_id not in swc_found:
                    swc_found[swc_id] = {
                        "id": swc_id,
                        "title": swc_title,
                        "count": 0,
                        "status": "Not Found",
                        "status_icon": "✅",
                        "finding_ids": "--",
                    }

            # Convert finding_ids list to string
            for swc in swc_found.values():
                if isinstance(swc["finding_ids"], list):
                    swc["finding_ids"] = (
                        ", ".join(swc["finding_ids"]) if swc["finding_ids"] else "--"
                    )

            variables["swc_mappings"] = sorted(swc_found.values(), key=lambda x: x["id"])

            # =================================================================
            # Generate OWASP Smart Contract Top 10 Compliance
            # =================================================================
            OWASP_MAPPING = {
                "reentrancy": (1, "SC01", "Reentrancy Attacks"),
                "access-control": (2, "SC02", "Access Control Vulnerabilities"),
                "arithmetic": (3, "SC03", "Arithmetic Issues"),
                "overflow": (3, "SC03", "Arithmetic Issues"),
                "unchecked": (4, "SC04", "Unchecked Return Values"),
                "dos": (5, "SC05", "Denial of Service"),
                "denial-of-service": (5, "SC05", "Denial of Service"),
                "randomness": (6, "SC06", "Bad Randomness"),
                "front-running": (7, "SC07", "Front-Running"),
                "timestamp": (8, "SC08", "Time Manipulation"),
                "short-address": (9, "SC09", "Short Address Attack"),
                "unknown-unknowns": (10, "SC10", "Unknown Unknowns"),
            }

            owasp_found = {}
            for f in findings:
                f_type = (
                    (f.get("type") or f.get("check") or f.get("category") or "")
                    .lower()
                    .replace("_", "-")
                )
                f_title = (f.get("title") or f.get("name") or "").lower()

                for key, (rank, owasp_id, owasp_category) in OWASP_MAPPING.items():
                    if key in f_type or key in f_title:
                        if owasp_id not in owasp_found:
                            owasp_found[owasp_id] = {
                                "rank": rank,
                                "id": owasp_id,
                                "category": owasp_category,
                                "count": 0,
                                "status": "Found",
                                "status_icon": "⚠️",
                            }
                        owasp_found[owasp_id]["count"] += 1
                        break

            # Add top OWASP entries that were checked
            top_owasp = [
                (1, "SC01", "Reentrancy Attacks"),
                (2, "SC02", "Access Control Vulnerabilities"),
                (3, "SC03", "Arithmetic Issues"),
                (4, "SC04", "Unchecked Return Values"),
                (5, "SC05", "Denial of Service"),
            ]
            for rank, owasp_id, owasp_category in top_owasp:
                if owasp_id not in owasp_found:
                    owasp_found[owasp_id] = {
                        "rank": rank,
                        "id": owasp_id,
                        "category": owasp_category,
                        "count": 0,
                        "status": "Not Found",
                        "status_icon": "✅",
                    }

            variables["owasp_mappings"] = sorted(owasp_found.values(), key=lambda x: x["rank"])

            # Add layer coverage bars
            for layer in variables.get("layer_summary", []):
                success_count = layer.get("success_count", 0)
                failed_count = layer.get("failed_count", 0)
                total = success_count + failed_count
                if total > 0:
                    percentage = int(success_count / total * 100)
                    bar = "█" * (percentage // 10) + "░" * (10 - percentage // 10)
                    layer["coverage_bar"] = f"{bar} {percentage}%"
                else:
                    layer["coverage_bar"] = "░░░░░░░░░░ N/A"

            # If LLM is enabled and premium, use premium insights
            if llm_interpret and variables.get("llm_enabled"):
                try:
                    from src.reports.llm_interpreter import generate_premium_report_insights

                    info(
                        "Generating premium LLM insights (attack scenarios, deployment recommendation)..."
                    )

                    # Get contract code if available
                    contract_path = results.get("contract_path") or results.get("contract")
                    contract_code = ""
                    if contract_path:
                        try:
                            contract_file = Path(contract_path)
                            if contract_file.exists():
                                contract_code = contract_file.read_text()[:10000]
                        except Exception:
                            pass

                    premium_insights = generate_premium_report_insights(
                        findings=findings,
                        summary=summary,
                        contract_name=results.get("contract", "Unknown"),
                        contract_code=contract_code,
                    )

                    if premium_insights.get("available"):
                        # LLM deployment recommendation - only allow stricter recommendations
                        # Severity order: NO-GO > CONDITIONAL > GO
                        if premium_insights.get("deployment_recommendation"):
                            llm_rec = premium_insights["deployment_recommendation"]
                            calc_rec = variables.get("deployment_recommendation", "GO")
                            severity_order = {"NO-GO": 3, "CONDITIONAL": 2, "GO": 1}

                            # Only use LLM recommendation if it's stricter (or equal)
                            llm_severity = severity_order.get(llm_rec, 1)
                            calc_severity = severity_order.get(calc_rec, 1)

                            if llm_severity >= calc_severity:
                                variables["deployment_recommendation"] = llm_rec
                                variables["deployment_justification"] = premium_insights.get(
                                    "deployment_justification", ""
                                )
                            else:
                                # Keep calculated recommendation, but add LLM justification as note
                                existing_just = variables.get("deployment_justification", "")
                                if existing_just:
                                    variables["deployment_justification"] = existing_just

                        # Add attack scenarios
                        if premium_insights.get("attack_scenarios"):
                            variables["attack_scenarios"] = premium_insights["attack_scenarios"]

                        # Add code remediations
                        if premium_insights.get("code_remediations"):
                            variables["code_remediations"] = premium_insights["code_remediations"]

                        # Update remediation priority with effort
                        if premium_insights.get("remediation_priority"):
                            variables["llm_remediation_priority"] = premium_insights[
                                "remediation_priority"
                            ]

                        success("Profesional LLM insights generated!")

                except Exception as e:
                    warning(f"Profesional LLM insights failed: {e}")

            success("Profesional report data generated!")

        except ImportError as e:
            warning(f"Risk calculator not available: {e}")
        except Exception as e:
            warning(f"Profesional report processing failed: {e}")

    # =========================================================================
    # Proof of Concept Generation (for Critical/High findings)
    # =========================================================================
    if template in ("profesional", "premium"):
        try:
            from src.poc.poc_generator import PoCGenerator

            poc_generator = PoCGenerator()
            contract_name_for_poc = (
                results.get("contract")
                or results.get("contract_path")
                or results.get("path")
                or "Unknown"
            )
            # For batch format, strip trailing slash from directory path
            if contract_name_for_poc.endswith("/"):
                contract_name_for_poc = "Unknown"

            critical_high_for_poc = [
                f
                for f in findings
                if f.get("severity", "").lower() in ("critical", "high") and f.get("type")
            ]

            if critical_high_for_poc:
                info(
                    f"Generating PoC exploits for {len(critical_high_for_poc)} critical/high findings..."
                )
                for finding in critical_high_for_poc:
                    try:
                        # Use per-finding source_contract (batch) or global contract name
                        target = finding.get("source_contract") or contract_name_for_poc
                        poc = poc_generator.generate(finding, target_contract=target)
                        finding["poc"] = poc.solidity_code
                        finding["poc_available"] = True
                        finding["poc_name"] = poc.name
                        finding["poc_prerequisites"] = poc.prerequisites
                        finding["poc_expected_outcome"] = poc.expected_outcome
                    except Exception as e:
                        logger.debug(f"PoC generation failed for {finding.get('type')}: {e}")

                poc_count = sum(1 for f in critical_high_for_poc if f.get("poc_available"))
                if poc_count:
                    success(f"Generated {poc_count} PoC exploit templates")
        except ImportError:
            logger.debug("PoCGenerator not available")
        except Exception as e:
            warning(f"PoC generation failed: {e}")

    # Prepare findings for template
    formatted_findings = []
    for i, finding in enumerate(findings, 1):
        # Handle location (can be string or dict)
        location = finding.get("location", {})
        if isinstance(location, dict):
            loc_str = f"{location.get('file', 'unknown')}:{location.get('line', '?')}"
            if location.get("function"):
                loc_str += f" ({location.get('function')})"
        else:
            loc_str = str(location) if location else "unknown"

        # Get title from various possible fields
        title = (
            finding.get("title") or finding.get("type") or finding.get("message", "Unknown")[:50]
        )

        # Get category from swc_id, owasp_category, or type
        category = (
            finding.get("category")
            or finding.get("owasp_category")
            or finding.get("swc_id")
            or finding.get("type", "general")
        )

        # Severity display helpers for premium template
        severity_lower = finding.get("severity", "unknown").lower()
        severity_badges = {
            "critical": "**CRITICAL**",
            "high": "**HIGH**",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
            "informational": "INFO",
        }
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
            "informational": "#17a2b8",
        }

        # Get CVSS score if available
        cvss_score = None
        for score in variables.get("cvss_scores", []):
            if score.get("title") == title or score.get("finding_id") == f"F-{i:03d}":
                cvss_score = score.get("base_score")
                break

        # Get attack scenario if available
        attack_scenario = None
        attack_steps = []
        for scenario in variables.get("attack_scenarios", []):
            if scenario.get("title") == title:
                attack_scenario = scenario.get("scenario_description")
                attack_steps = scenario.get("attack_steps", [])
                break

        # Get code remediation if available
        remediation_code = None
        remediation_effort = None
        fix_time = None
        for remediation in variables.get("code_remediations", []):
            if remediation.get("title") == title:
                remediation_code = remediation.get("diff")
                remediation_effort = remediation.get("effort")
                fix_time = remediation.get("fix_time")
                break

        formatted_findings.append(
            {
                "id": f"F-{i:03d}",
                "title": title,
                "severity": severity_lower,
                "severity_badge": severity_badges.get(severity_lower, severity_lower.upper()),
                "severity_color": severity_colors.get(severity_lower, "#6c757d"),
                "category": category,
                "location": loc_str,
                "description": finding.get("description", finding.get("message", "")),
                "recommendation": finding.get(
                    "recommendation", "Review and fix the vulnerability."
                ),
                "tool": finding.get("tool", "unknown"),
                "status": finding.get("status", "open"),
                "impact": finding.get("impact", _get_impact_description(severity_lower)),
                "poc": finding.get("poc", "// No PoC provided"),
                "vulnerable_code": finding.get(
                    "vulnerable_code", finding.get("poc", "// No code snippet")
                ),
                "references": finding.get("references", []),
                # Premium fields
                "cvss_score": cvss_score,
                "attack_scenario": attack_scenario,
                "attack_steps": attack_steps,
                "remediation_code": remediation_code,
                "remediation_effort": remediation_effort,
                "fix_time": fix_time,
                "llm_interpretation": finding.get("llm_interpretation", ""),
                # PoC fields
                "poc_available": finding.get("poc_available", False),
                "poc_name": finding.get("poc_name", ""),
                "poc_prerequisites": finding.get("poc_prerequisites", []),
                "poc_expected_outcome": finding.get("poc_expected_outcome", ""),
            }
        )

    variables["findings"] = formatted_findings
    variables["critical_high_findings"] = [
        f for f in formatted_findings if f["severity"] in ("critical", "high")
    ]
    variables["medium_low_findings"] = [
        f for f in formatted_findings if f["severity"] in ("medium", "low")
    ]

    # Simple template rendering (basic variable substitution)
    output_content = _render_template(template_content, variables)

    # Handle output
    if output:
        output_path = Path(output)

        if output_format == "html":
            output_content = _markdown_to_html(output_content, title or "MIESC Security Report")
        elif output_format == "pdf":
            # Generate PDF from HTML using weasyprint (preferred) or pandoc fallback
            html_content = _markdown_to_html(output_content, title or "MIESC Security Report")
            pdf_generated = False

            # Try weasyprint first (available in Docker image)
            try:
                from weasyprint import CSS, HTML
                from weasyprint.text.fonts import FontConfiguration

                info("Generating PDF with WeasyPrint...")
                font_config = FontConfiguration()

                # Load premium CSS if available
                css_path = ROOT_DIR / "docs" / "templates" / "reports" / "profesional.css"
                if css_path.exists():
                    css_content = css_path.read_text()
                    css = CSS(string=css_content, font_config=font_config)
                    HTML(string=html_content).write_pdf(
                        output_path, stylesheets=[css], font_config=font_config
                    )
                else:
                    HTML(string=html_content).write_pdf(output_path)

                pdf_generated = True
                success(f"PDF report saved to {output_path}")
                return
            except ImportError:
                info("WeasyPrint not available, trying pandoc...")
            except Exception as e:
                warning(f"WeasyPrint PDF generation failed: {e}")

            # Fallback to pandoc
            if not pdf_generated:
                try:
                    import subprocess

                    temp_html = output_path.with_suffix(".tmp.html")
                    temp_html.write_text(html_content)
                    subprocess.run(
                        [
                            "pandoc",
                            str(temp_html),
                            "-o",
                            str(output_path),
                            "--pdf-engine=wkhtmltopdf",
                        ],
                        check=True,
                        capture_output=True,
                    )
                    temp_html.unlink()
                    success(f"PDF report saved to {output_path}")
                    return
                except FileNotFoundError:
                    warning("pandoc not found, saving as HTML instead")
                    output_path = output_path.with_suffix(".html")
                    output_content = html_content
                except subprocess.CalledProcessError as e:
                    warning(f"PDF generation failed: {e}")
                    output_path = output_path.with_suffix(".html")
                    output_content = html_content

        output_path.write_text(output_content)
        success(f"Report saved to {output_path}")
    else:
        # Output to stdout
        print(output_content)

    # Summary
    if RICH_AVAILABLE and output:
        console.print(
            f"\n[bold]Report Summary:[/bold] "
            f"[red]{variables['critical_count']}[/red] critical, "
            f"[red]{variables['high_count']}[/red] high, "
            f"[yellow]{variables['medium_count']}[/yellow] medium, "
            f"[cyan]{variables['low_count']}[/cyan] low"
        )


def _calculate_risk_level(summary: dict) -> str:
    """Calculate overall risk level from summary."""
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)

    if critical > 0:
        return "CRITICAL"
    elif high > 2:
        return "HIGH"
    elif high > 0 or medium > 3:
        return "MEDIUM"
    elif medium > 0:
        return "LOW"
    return "MINIMAL"


def _render_template(template: str, variables: dict) -> str:
    """Render template using Jinja2 if available, otherwise simple replacement."""
    try:
        from jinja2 import BaseLoader, Environment, Template

        # Create Jinja2 environment with proper settings
        env = Environment(loader=BaseLoader())
        jinja_template = env.from_string(template)
        return jinja_template.render(**variables)
    except ImportError:
        # Fallback to simple rendering
        return _simple_render_template(template, variables)


def _simple_render_template(template: str, variables: dict) -> str:
    """Simple template rendering fallback without Jinja2."""
    import re

    output = template

    # Replace simple variables {{ var }}
    for key, value in variables.items():
        if not isinstance(value, (list, dict)):
            output = output.replace("{{ " + key + " }}", str(value))
            output = output.replace("{{" + key + "}}", str(value))

    # Handle generic for loops
    loop_pattern = r"\{% for (\w+) in (\w+) %\}(.*?)\{% endfor %\}"

    def replace_loop(match):
        item_name = match.group(1)
        list_name = match.group(2)
        loop_body = match.group(3)

        items = variables.get(list_name, [])
        if not items:
            return ""

        result = ""
        for item in items:
            item_output = loop_body
            if isinstance(item, dict):
                for key, value in item.items():
                    if isinstance(value, list):
                        value = ", ".join(str(v) for v in value)
                    item_output = item_output.replace(f"{{{{ {item_name}.{key} }}}}", str(value))
                    item_output = item_output.replace(f"{{{{{item_name}.{key}}}}}", str(value))
            else:
                item_output = item_output.replace(f"{{{{ {item_name} }}}}", str(item))
            result += item_output
        return result

    # Process all loops (may need multiple passes for nested loops)
    for _ in range(5):  # Max 5 passes for nested loops
        new_output = re.sub(loop_pattern, replace_loop, output, flags=re.DOTALL)
        if new_output == output:
            break
        output = new_output

    # Handle conditionals (simplified - remove unfilled ones)
    output = re.sub(r"\{% if [^%]+%\}.*?\{% endif %\}", "", output, flags=re.DOTALL)

    return output


def _markdown_to_html(markdown: str, title: str, use_premium_css: bool = True) -> str:
    """Convert markdown to HTML with professional styling."""
    try:
        import markdown as md

        html_body = md.markdown(markdown, extensions=["tables", "fenced_code", "toc", "attr_list"])
    except ImportError:
        # Fallback: wrap in pre tag
        html_body = f"<pre>{markdown}</pre>"

    # Try to load premium CSS
    css_content = ""
    if use_premium_css:
        css_path = ROOT_DIR / "docs" / "templates" / "reports" / "profesional.css"
        if css_path.exists():
            css_content = css_path.read_text()

    # Fallback to basic CSS if premium not available
    if not css_content:
        css_content = """
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 2rem; line-height: 1.6; }
        h1, h2, h3 { color: #1a1a2e; }
        table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #1a1a2e; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        code { background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
        pre { background-color: #f4f4f4; padding: 1rem; border-radius: 5px; overflow-x: auto; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .medium { color: #ffc107; }
        .low { color: #17a2b8; }
        """

    # Enhance HTML with severity badges
    html_body = _enhance_html_severity(html_body)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
{css_content}
    </style>
</head>
<body>
{html_body}
    <script>
        // Auto-enhance severity badges
        document.querySelectorAll('td, strong').forEach(el => {{
            const text = el.textContent.trim();
            if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(text)) {{
                el.innerHTML = '<span class="severity-' + text.toLowerCase() + '">' + text + '</span>';
            }}
        }});
    </script>
</body>
</html>"""


def _enhance_html_severity(html: str) -> str:
    """Add CSS classes to severity indicators in HTML."""
    import re

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        # Wrap **SEVERITY** in spans
        html = re.sub(
            rf"\*\*({sev})\*\*", rf'<span class="severity-{sev.lower()}">{sev}</span>', html
        )
        # Also handle plain text in tables
        html = re.sub(
            rf"<td>({sev})</td>",
            rf'<td><span class="severity-{sev.lower()}">{sev}</span></td>',
            html,
        )

    return html


# ============================================================================
# Benchmark Command
# ============================================================================


@cli.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("--save", is_flag=True, help="Save benchmark results for comparison")
@click.option("--compare", type=str, help="Compare with previous run (run ID or 'last')")
@click.option("--history", is_flag=True, help="Show benchmark history")
@click.option("--period", type=str, default="30d", help="Period for trend report (e.g., 7d, 30d)")
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
def benchmark(directory, save, compare, history, period, output):
    """Track security posture over time.

    Run security audits and track improvements across commits and versions.

    Examples:

      miesc benchmark ./contracts --save

      miesc benchmark ./contracts --compare last

      miesc benchmark ./contracts --history

      miesc benchmark ./contracts --period 30d -o trend.md
    """
    print_banner()

    benchmark_dir = Path.home() / ".miesc" / "benchmarks"
    benchmark_dir.mkdir(parents=True, exist_ok=True)

    directory_path = Path(directory).resolve()
    project_id = directory_path.name

    if history:
        _show_benchmark_history(benchmark_dir, project_id)
        return

    # Run audit to get current state
    info(f"Running security audit on {directory}...")

    try:
        from src.core.orchestrator import SecurityOrchestrator

        orchestrator = SecurityOrchestrator()
        # Quick audit for benchmark
        results = orchestrator.run_quick_audit(str(directory_path))
    except Exception as e:
        error(f"Audit failed: {e}")
        sys.exit(1)

    # Calculate metrics
    summary = results.get("summary", {})
    current_metrics = {
        "timestamp": datetime.now().isoformat(),
        "project": project_id,
        "directory": str(directory_path),
        "critical": summary.get("critical", 0),
        "high": summary.get("high", 0),
        "medium": summary.get("medium", 0),
        "low": summary.get("low", 0),
        "info": summary.get("info", 0),
        "total": sum(summary.values()) if summary else 0,
        "files": results.get("files_count", 0),
        "tools_run": len(results.get("tools", [])),
    }

    # Try to get git commit
    try:
        import subprocess

        commit = (
            subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=directory_path,
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )
        current_metrics["commit"] = commit
    except Exception:
        current_metrics["commit"] = "unknown"

    if save:
        # Save benchmark
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        benchmark_file = benchmark_dir / f"{project_id}_{run_id}.json"
        with open(benchmark_file, "w") as f:
            json.dump(current_metrics, f, indent=2)
        success(f"Benchmark saved: {run_id}")

    if compare:
        _compare_benchmarks(benchmark_dir, project_id, compare, current_metrics)
        return

    # Display current metrics
    if RICH_AVAILABLE:
        table = Table(title=f"Security Posture: {project_id}", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row(
            "Critical Issues",
            str(current_metrics["critical"]),
            style="red" if current_metrics["critical"] > 0 else "green",
        )
        table.add_row(
            "High Issues",
            str(current_metrics["high"]),
            style="red" if current_metrics["high"] > 0 else "green",
        )
        table.add_row(
            "Medium Issues",
            str(current_metrics["medium"]),
            style="yellow" if current_metrics["medium"] > 0 else "green",
        )
        table.add_row("Low Issues", str(current_metrics["low"]), style="cyan")
        table.add_row("Total Findings", str(current_metrics["total"]))
        table.add_row("Files Analyzed", str(current_metrics["files"]))
        table.add_row("Commit", current_metrics.get("commit", "N/A"))

        console.print(table)
    else:
        print(f"\n=== Security Posture: {project_id} ===")
        print(f"Critical: {current_metrics['critical']}")
        print(f"High: {current_metrics['high']}")
        print(f"Medium: {current_metrics['medium']}")
        print(f"Low: {current_metrics['low']}")
        print(f"Total: {current_metrics['total']}")

    if output:
        _generate_benchmark_report(current_metrics, output, period)


def _show_benchmark_history(benchmark_dir: Path, project_id: str):
    """Show benchmark history for a project."""
    benchmarks = sorted(benchmark_dir.glob(f"{project_id}_*.json"), reverse=True)

    if not benchmarks:
        warning(f"No benchmarks found for {project_id}")
        return

    if RICH_AVAILABLE:
        table = Table(title=f"Benchmark History: {project_id}", box=box.ROUNDED)
        table.add_column("Run ID", style="cyan")
        table.add_column("Date")
        table.add_column("Commit")
        table.add_column("Crit", justify="right")
        table.add_column("High", justify="right")
        table.add_column("Med", justify="right")
        table.add_column("Low", justify="right")
        table.add_column("Total", justify="right")

        for bf in benchmarks[:20]:
            with open(bf) as f:
                data = json.load(f)
            run_id = bf.stem.replace(f"{project_id}_", "")
            table.add_row(
                run_id,
                data.get("timestamp", "")[:10],
                data.get("commit", "N/A")[:7],
                str(data.get("critical", 0)),
                str(data.get("high", 0)),
                str(data.get("medium", 0)),
                str(data.get("low", 0)),
                str(data.get("total", 0)),
            )

        console.print(table)
    else:
        print(f"\n=== Benchmark History: {project_id} ===")
        for bf in benchmarks[:10]:
            with open(bf) as f:
                data = json.load(f)
            run_id = bf.stem.replace(f"{project_id}_", "")
            print(f"  {run_id}: {data.get('total', 0)} findings")

    success(f"{len(benchmarks)} benchmarks found")


def _compare_benchmarks(benchmark_dir: Path, project_id: str, compare_to: str, current: dict):
    """Compare current benchmark with a previous run."""
    if compare_to == "last":
        benchmarks = sorted(benchmark_dir.glob(f"{project_id}_*.json"), reverse=True)
        if not benchmarks:
            warning("No previous benchmarks to compare")
            return
        compare_file = benchmarks[0]
    else:
        compare_file = benchmark_dir / f"{project_id}_{compare_to}.json"

    if not compare_file.exists():
        error(f"Benchmark not found: {compare_to}")
        return

    with open(compare_file) as f:
        previous = json.load(f)

    # Calculate deltas
    deltas = {
        "critical": current["critical"] - previous.get("critical", 0),
        "high": current["high"] - previous.get("high", 0),
        "medium": current["medium"] - previous.get("medium", 0),
        "low": current["low"] - previous.get("low", 0),
        "total": current["total"] - previous.get("total", 0),
    }

    def format_delta(val):
        if val > 0:
            return f"+{val}"
        elif val < 0:
            return str(val)
        return "0"

    if RICH_AVAILABLE:
        table = Table(title="Security Posture Comparison", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Previous", justify="right")
        table.add_column("Current", justify="right")
        table.add_column("Change", justify="right")

        for metric in ["critical", "high", "medium", "low", "total"]:
            delta = deltas[metric]
            delta_style = "green" if delta < 0 else ("red" if delta > 0 else "dim")
            table.add_row(
                metric.title(),
                str(previous.get(metric, 0)),
                str(current[metric]),
                format_delta(delta),
                style=delta_style if metric in ("critical", "high") else None,
            )

        console.print(table)

        # Summary
        if deltas["total"] < 0:
            console.print(f"\n[green]Improved by {abs(deltas['total'])} findings[/green]")
        elif deltas["total"] > 0:
            console.print(f"\n[red]Regressed by {deltas['total']} findings[/red]")
        else:
            console.print("\n[dim]No change in total findings[/dim]")
    else:
        print("\n=== Comparison ===")
        print(
            f"Previous: {previous.get('total', 0)} | Current: {current['total']} | Change: {format_delta(deltas['total'])}"
        )


def _generate_benchmark_report(metrics: dict, output_path: str, period: str):
    """Generate a benchmark trend report."""
    report = f"""# Security Posture Report

**Project:** {metrics['project']}
**Date:** {metrics['timestamp'][:10]}
**Commit:** {metrics.get('commit', 'N/A')}

## Current Status

| Severity | Count |
|----------|-------|
| Critical | {metrics['critical']} |
| High | {metrics['high']} |
| Medium | {metrics['medium']} |
| Low | {metrics['low']} |
| **Total** | **{metrics['total']}** |

## Risk Level

{"**CRITICAL** - Immediate action required" if metrics['critical'] > 0 else ""}
{"**HIGH** - Address before deployment" if metrics['high'] > 0 and metrics['critical'] == 0 else ""}
{"**MEDIUM** - Review recommended" if metrics['medium'] > 0 and metrics['high'] == 0 and metrics['critical'] == 0 else ""}
{"**LOW** - Good security posture" if metrics['total'] == 0 or (metrics['critical'] == 0 and metrics['high'] == 0 and metrics['medium'] == 0) else ""}

---

*Generated by [MIESC](https://github.com/fboiero/MIESC) v{VERSION}*
"""

    Path(output_path).write_text(report)
    success(f"Report saved to {output_path}")


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    cli()
