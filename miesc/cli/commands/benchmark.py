"""
MIESC CLI - Benchmark Commands

Commands for tracking security posture over time.

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
    from rich.table import Table


# =============================================================================
# Helper Functions
# =============================================================================


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
        print(f"\n=== Benchmark History: {project_id} ===")  # noqa: T201
        for bf in benchmarks[:10]:
            with open(bf) as f:
                data = json.load(f)
            run_id = bf.stem.replace(f"{project_id}_", "")
            print(f"  {run_id}: {data.get('total', 0)} findings")  # noqa: T201

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
        print("\n=== Comparison ===")  # noqa: T201
        print(  # noqa: T201
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


# =============================================================================
# Benchmark Command
# =============================================================================


@click.command()
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
        print(f"\n=== Security Posture: {project_id} ===")  # noqa: T201
        print(f"Critical: {current_metrics['critical']}")  # noqa: T201
        print(f"High: {current_metrics['high']}")  # noqa: T201
        print(f"Medium: {current_metrics['medium']}")  # noqa: T201
        print(f"Low: {current_metrics['low']}")  # noqa: T201
        print(f"Total: {current_metrics['total']}")  # noqa: T201

    if output:
        _generate_benchmark_report(current_metrics, output, period)
