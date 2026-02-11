"""
MIESC CLI - Audit Commands

Commands for running security audits on smart contracts.

Author: Fernando Boiero
License: AGPL-3.0
"""

import concurrent.futures
import glob as glob_module
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import click

from miesc import __version__ as VERSION
from miesc.cli.constants import ADAPTER_MAP, AVAILABLE_PROFILES, LAYERS, QUICK_TOOLS
from miesc.cli.utils import (
    RICH_AVAILABLE,
    AdapterLoader,
    console,
    error,
    get_correlation_api,
    get_ml_orchestrator,
    get_profile,
    info,
    load_profiles,
    print_banner,
    run_layer,
    run_tool,
    success,
    summarize_findings,
    warning,
)

# Import Rich components if available
if RICH_AVAILABLE:
    from rich import box
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table

logger = logging.getLogger(__name__)


# =============================================================================
# Output Format Converters
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
    summary = summarize_findings(results)
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


# =============================================================================
# Full Audit Helper Functions
# =============================================================================


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

            results = run_layer(layer, contract, timeout)
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

            results = run_layer(layer, contract, timeout)
            all_results.extend(results)

    summary = summarize_findings(all_results)
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


# =============================================================================
# Audit Command Group
# =============================================================================


@click.group()
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
                result = run_tool(tool, contract, timeout)
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
            result = run_tool(tool, contract, timeout)
            all_results.append(result)

    summary = summarize_findings(all_results)
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

    results = run_layer(layer_num, contract, timeout)
    summary = summarize_findings(results)

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
                result = run_tool(tool, contract, timeout)
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
            result = run_tool(tool, contract, timeout)
            all_results.append(result)

    summary = summarize_findings(all_results)
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

    result = run_tool(tool, contract, timeout)

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
            result = run_tool(tool, contract_path, timeout=120)
            contract_results.append(result)

        summary = summarize_findings(contract_results)
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
            sorted_contracts = sorted(
                all_contract_results,
                key=lambda x: (x["summary"]["CRITICAL"], x["summary"]["HIGH"], x["total_findings"]),
                reverse=True,
            )
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
