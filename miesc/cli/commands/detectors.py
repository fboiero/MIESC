"""
MIESC CLI - Detectors Commands

Commands for managing and running custom vulnerability detectors.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import click

from miesc import __version__ as VERSION
from miesc.cli.utils import (
    RICH_AVAILABLE,
    console,
    error,
    info,
    print_banner,
    success,
    warning,
)

# Import Rich components if available
if RICH_AVAILABLE:
    from rich import box
    from rich.panel import Panel
    from rich.table import Table


@click.group()
def detectors():
    """Manage and run custom vulnerability detectors."""
    pass


@detectors.command("list")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed information")
def detectors_list(verbose):
    """List all registered custom detectors."""
    print_banner()

    try:
        # Also load example detectors and local plugins
        from miesc.detectors import (
            examples,  # noqa: F401
            get_all_detectors,
            list_detectors,
            load_local_plugins,
        )

        # Load local plugins from ~/.miesc/plugins/
        load_local_plugins()
    except ImportError as e:
        error(f"Detector API not available: {e}")
        return

    detector_list = list_detectors()

    if not detector_list:
        warning("No custom detectors registered")
        info("Create detectors using miesc.detectors.BaseDetector")
        return

    if RICH_AVAILABLE:
        table = Table(title="Custom Detectors", box=box.ROUNDED)
        table.add_column("Name", style="bold cyan")
        table.add_column("Category", width=15)
        table.add_column("Severity", width=10)
        if verbose:
            table.add_column("Description", width=40)
            table.add_column("Author", width=20)

        for detector in sorted(detector_list, key=lambda x: x["name"]):
            row = [
                detector["name"],
                detector.get("category", "general"),
                detector.get("severity", "Medium"),
            ]
            if verbose:
                row.append(detector.get("description", "")[:40])
                row.append(detector.get("author", "")[:20])
            table.add_row(*row)

        console.print(table)
    else:
        print(f"\n=== Custom Detectors ({len(detector_list)}) ===")  # noqa: T201
        for detector in sorted(detector_list, key=lambda x: x["name"]):
            print(f"  - {detector['name']}: {detector.get('description', '')[:50]}")  # noqa: T201

    success(f"{len(detector_list)} detectors registered")


@detectors.command("run")
@click.argument("contract", type=click.Path(exists=True))
@click.option("--detector", "-d", multiple=True, help="Specific detectors to run (can repeat)")
@click.option("--output", "-o", type=click.Path(), help="Output file for JSON report")
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Minimum severity to report",
)
def detectors_run(contract, detector, output, severity):
    """Run custom detectors on a contract.

    Run all registered detectors or specific ones on a Solidity contract.

    Examples:
        miesc detectors run contract.sol
        miesc detectors run contract.sol -d flash-loan -d mev-detector
        miesc detectors run contract.sol --severity high -o report.json
    """
    print_banner()

    try:
        # Load example detectors and local plugins
        from miesc.detectors import (
            Severity,
            examples,  # noqa: F401
            get_all_detectors,
            load_local_plugins,
            run_all_detectors,
            run_detector,
        )

        # Load local plugins from ~/.miesc/plugins/
        load_local_plugins()
    except ImportError as e:
        error(f"Detector API not available: {e}")
        sys.exit(1)

    all_detectors = get_all_detectors()

    if not all_detectors:
        warning("No custom detectors registered")
        return

    # Read contract
    contract_path = Path(contract)
    with open(contract_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    info(f"Analyzing {contract_path.name}")

    # Filter detectors if specific ones requested
    detector_names = list(all_detectors.keys())
    if detector:
        detectors_to_run = [d for d in detector if d in detector_names]
        if not detectors_to_run:
            error(f"None of the specified detectors found: {', '.join(detector)}")
            info(f"Available: {', '.join(detector_names)}")
            sys.exit(1)
        info(f"Running: {', '.join(detectors_to_run)}")
    else:
        detectors_to_run = detector_names
        info(f"Running all {len(detectors_to_run)} detectors")

    # Run detectors
    all_findings = []
    start_time = datetime.now()

    for det_name in detectors_to_run:
        try:
            findings = run_detector(det_name, source_code, str(contract_path))
            all_findings.extend(findings)
            if findings:
                success(f"{det_name}: {len(findings)} findings")
            else:
                info(f"{det_name}: clean")
        except Exception as e:
            warning(f"{det_name}: error - {e}")

    elapsed = (datetime.now() - start_time).total_seconds()

    # Filter by severity if specified
    if severity:
        severity_order = ["critical", "high", "medium", "low", "info"]
        min_idx = severity_order.index(severity)
        all_findings = [
            f for f in all_findings if severity_order.index(f.severity.value) <= min_idx
        ]

    # Display results
    if RICH_AVAILABLE and all_findings:
        console.print("\n")
        table = Table(title="Custom Detector Findings", box=box.ROUNDED)
        table.add_column("Severity", width=10)
        table.add_column("Detector", width=15)
        table.add_column("Title", width=35)
        table.add_column("Line", width=6)

        colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim",
        }

        for finding in all_findings[:25]:
            line = str(finding.location.line) if finding.location else "-"
            table.add_row(
                finding.severity.value,
                finding.detector,
                finding.title[:35],
                line,
                style=colors.get(finding.severity.value.lower(), "white"),
            )

        if len(all_findings) > 25:
            table.add_row("...", f"({len(all_findings) - 25} more)", "", "")

        console.print(table)

    # Summary
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.severity.value.lower()
        if sev in summary:
            summary[sev] += 1

    if RICH_AVAILABLE:
        console.print(
            f"\n[bold]Summary:[/bold] "
            f"[red]{summary['critical']}[/red] critical, "
            f"[red]{summary['high']}[/red] high, "
            f"[yellow]{summary['medium']}[/yellow] medium, "
            f"[cyan]{summary['low']}[/cyan] low "
            f"[dim]({elapsed:.1f}s)[/dim]"
        )
    else:
        print(  # noqa: T201
            f"\nSummary: {summary['critical']} critical, {summary['high']} high, "
            f"{summary['medium']} medium, {summary['low']} low ({elapsed:.1f}s)"
        )

    # Save output
    if output:
        data = {
            "contract": str(contract),
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "detectors_run": detectors_to_run,
            "summary": summary,
            "total_findings": len(all_findings),
            "findings": [f.to_dict() for f in all_findings],
        }
        with open(output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")


@detectors.command("info")
@click.argument("detector_name", type=str)
def detectors_info(detector_name):
    """Show detailed information about a detector."""
    print_banner()

    try:
        from src.detectors.detector_api import get_registry
    except ImportError:
        error("Detector API not available")
        return

    registry = get_registry()
    detector = registry.get(detector_name)

    if not detector:
        error(f"Detector not found: {detector_name}")
        info(f"Available: {', '.join(registry.list_detectors())}")
        return

    if RICH_AVAILABLE:
        panel_content = f"""[bold cyan]Name:[/bold cyan] {detector.name}
[bold cyan]Description:[/bold cyan] {detector.description}
[bold cyan]Version:[/bold cyan] {detector.version}
[bold cyan]Author:[/bold cyan] {detector.author or 'N/A'}
[bold cyan]Category:[/bold cyan] {detector.category.value}
[bold cyan]Default Severity:[/bold cyan] {detector.default_severity.value}
[bold cyan]Enabled:[/bold cyan] {'Yes' if detector.enabled else 'No'}

[bold]Target Patterns:[/bold]
{', '.join(detector.target_patterns) if detector.target_patterns else 'All contracts'}
"""
        console.print(Panel(panel_content, title=f"Detector: {detector_name}", border_style="cyan"))
    else:
        print(f"\n=== {detector_name} ===")  # noqa: T201
        print(f"Description: {detector.description}")  # noqa: T201
        print(f"Category: {detector.category.value}")  # noqa: T201
        print(f"Severity: {detector.default_severity.value}")  # noqa: T201
