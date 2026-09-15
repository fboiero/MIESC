"""
MIESC CLI - X-Ray Command

Standalone pre-audit protocol map: risk profile, entry points classified by
permission level, attack surface score (git-activity weighted), the entry
points most worth auditing first (MEJORAS.md #4), and — in directory mode —
the cross-contract dependency graph: inheritance, external calls between
contracts, and a storage-risk heuristic (MEJORAS.md #5).

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import sys
from pathlib import Path

import click

from miesc.agents.xray_agent import run_xray
from miesc.cli.utils import RICH_AVAILABLE, console, error, info, print_banner

if RICH_AVAILABLE:
    from rich import box
    from rich.table import Table


@click.command()
@click.argument("contract", type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, help="Scan directories recursively")
@click.option("--output", "-o", type=click.Path(), help="Output file for JSON report")
def xray(contract: str, recursive: bool, output: str) -> None:
    """Pre-audit reconnaissance: risk profile, entry points, attack surface — no tools run yet."""
    contract_path = Path(contract)

    if contract_path.is_dir():
        glob_pattern = "**/*.sol" if recursive else "*.sol"
        sol_files = sorted(contract_path.glob(glob_pattern))
        if not sol_files:
            error(f"No .sol files found in {contract}" + (" (recursively)" if recursive else ""))
            sys.exit(1)
        paths = [str(f) for f in sol_files]
    else:
        paths = [str(contract_path)]

    print_banner()
    info(f"X-Ray: {len(paths)} file(s)")

    report = run_xray(paths)

    if output:
        Path(output).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        info(f"Report saved to {output}")

    if RICH_AVAILABLE:
        for file_report in report["files"]:
            table = Table(
                title=f"{Path(file_report['contract']).name}  —  {file_report['protocol_type']}",
                box=box.ROUNDED,
            )
            table.add_column("Metric", style="bold")
            table.add_column("Value")
            table.add_row("Framework", file_report["framework"])
            table.add_row("Attack surface score", f"{file_report['attack_surface_score']:.1f}/100")
            table.add_row("Git commits (history)", str(file_report["git_commits"]))
            for bucket, entries in file_report["entry_points"].items():
                names = ", ".join(e["name"] for e in entries) or "—"
                table.add_row(f"Entry points ({bucket})", names)
            console.print(table)
            console.print("")

        if report["hotspots"]:
            hot_table = Table(title="Top hotspots (git-activity ranked)", box=box.ROUNDED)
            hot_table.add_column("Contract")
            hot_table.add_column("Function")
            hot_table.add_column("Commits", justify="right")
            for h in report["hotspots"]:
                hot_table.add_row(h["contract"], h["function"], str(h["git_commits"]))
            console.print(hot_table)

        protocol = report.get("protocol")
        if protocol and (
            protocol["inheritance_edges"] or protocol["call_edges"] or protocol["storage_risk"]
        ):
            console.print("")
            graph_table = Table(title="Protocol Graph (cross-contract)", box=box.ROUNDED)
            graph_table.add_column("Relation")
            graph_table.add_column("From")
            graph_table.add_column("To / Detail")
            for derived, base in protocol["inheritance_edges"]:
                graph_table.add_row("inherits", derived, base)
            for caller, callee in protocol["call_edges"]:
                graph_table.add_row("calls", caller, callee)
            for risk in protocol["storage_risk"]:
                graph_table.add_row(
                    "[yellow]storage risk[/yellow]", risk["derived"], risk["reason"]
                )
            console.print(graph_table)
    else:
        console.print(json.dumps(report, indent=2, default=str))
