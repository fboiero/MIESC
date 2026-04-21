"""
MIESC CLI - Scan Command

Simplified entry point for quick vulnerability scanning.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import sys
from datetime import datetime

import click

from miesc import __version__ as VERSION
from miesc.cli.constants import QUICK_TOOLS
from miesc.cli.utils import (
    RICH_AVAILABLE,
    console,
    error,
    info,
    print_banner,
    run_tool,
    success,
    summarize_findings,
)

# Import Rich components if available
if RICH_AVAILABLE:
    from rich import box
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table


# =============================================================================
# Scan Command
# =============================================================================


@click.command()
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file for JSON report")
@click.option("--ci", is_flag=True, help="CI mode: exit 1 if critical/high issues found")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output, only show summary")
@click.option(
    "--fp-strictness",
    type=click.Choice(["off", "low", "medium", "high"], case_sensitive=False),
    default="medium",
    help="False positive filter strictness: off=report everything, low=permissive, medium=balanced (default), high=aggressive for CI",
)
@click.option(
    "--llm-enhance",
    is_flag=True,
    help="Enhance top findings with AI insights (adds ~40s, requires Ollama)",
)
def scan(contract, output, ci, quiet, fp_strictness, llm_enhance):
    """Quick vulnerability scan for a Solidity contract.

    This is a simplified command for quick scans. For more options,
    use 'miesc audit quick' or 'miesc audit full'.

    \b
    Examples:
        miesc scan MyContract.sol
        miesc scan contracts/Token.sol --ci --fp-strictness high
        miesc scan MyContract.sol --fp-strictness off -o full_report.json
        miesc scan MyContract.sol --llm-enhance -o report.json

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
            task = progress.add_task(
                f"Running {len(QUICK_TOOLS)} tools in parallel...",
                total=len(QUICK_TOOLS),
            )

            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=len(QUICK_TOOLS)) as pool:
                futures = {
                    pool.submit(run_tool, tool, contract, 300, llm_enhance=llm_enhance): tool
                    for tool in QUICK_TOOLS
                }
                for future in as_completed(futures):
                    tool = futures[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                    except Exception as e:
                        all_results.append({"tool": tool, "status": "error", "error": str(e), "findings": []})
                    progress.update(task, description=f"Done: {tool}")
                    progress.advance(task)
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        if not quiet:
            info(f"Running {len(QUICK_TOOLS)} tools in parallel...")
        with ThreadPoolExecutor(max_workers=len(QUICK_TOOLS)) as pool:
            futures = {pool.submit(run_tool, tool, contract, 300): tool for tool in QUICK_TOOLS}
            for future in as_completed(futures):
                try:
                    all_results.append(future.result())
                except Exception as e:
                    all_results.append({"tool": futures[future], "status": "error", "error": str(e), "findings": []})

    # Apply FP filter based on strictness (v5.1.2+)
    if fp_strictness.lower() != "off":
        try:
            from src.ml.fp_filter import FalsePositiveFilter
            with open(contract) as f:
                code = f.read()
            fp_filter = FalsePositiveFilter(strictness=fp_strictness.lower(), use_rag=False)
            filtered_count = 0
            for result in all_results:
                kept = []
                for finding in result.get("findings", []):
                    fr = fp_filter.filter_finding(finding, code_context=code, file_path=contract)
                    if not fr.is_likely_fp:
                        kept.append(finding)
                    else:
                        filtered_count += 1
                result["findings"] = kept
            if not quiet and filtered_count > 0:
                info(f"FP filter ({fp_strictness}): removed {filtered_count} likely false positives")
        except Exception as e:
            if not quiet:
                info(f"FP filter skipped: {e}")

    # v5.2.0: Intelligence engine — cross-tool scoring, semantic dedup,
    # zero-recall pattern detection, context-aware FP suppression,
    # LLM↔static cross-validation, severity calibration.
    try:
        from src.core.intelligence import enhance_findings
        all_findings_flat = []
        for result in all_results:
            for f in result.get("findings", []):
                f.setdefault("tool", result.get("tool", "unknown"))
                all_findings_flat.append(f)
        if all_findings_flat:
            try:
                code_text = open(contract).read()
            except Exception:
                code_text = ""
            enhanced = enhance_findings(all_findings_flat, source_code=code_text, file_path=str(contract))
            # Replace all_results with a single synthetic result carrying enhanced findings
            non_suppressed = [f for f in enhanced if not f.get("fp_suppressed")]
            suppressed_count = sum(1 for f in enhanced if f.get("fp_suppressed"))
            all_results = [{"tool": "miesc-intelligence", "status": "success", "findings": non_suppressed}]
            if not quiet and suppressed_count > 0:
                info(f"Intelligence engine: suppressed {suppressed_count} likely false positives")
            if not quiet and len(non_suppressed) < len(all_findings_flat):
                deduped = len(all_findings_flat) - len(enhanced)
                if deduped > 0:
                    info(f"Intelligence engine: merged {deduped} duplicate findings across tools")
    except Exception as e:
        if not quiet:
            info(f"Intelligence engine skipped: {e}")

    # Detect tool failures — help users who installed miesc without slither/aderyn
    tools_succeeded = [r for r in all_results if r.get("status") != "error"]
    tools_errored = [r for r in all_results if r.get("status") == "error"]

    if tools_errored and not tools_succeeded and not quiet:
        error("All analysis tools failed. Check tool availability:")
        for r in tools_errored:
            info(f"  {r.get('tool', '?')}: {r.get('error', 'unknown error')}")
        info("")
        info("Run 'miesc doctor' to check which tools are installed.")
        info("Quick fix: pip install slither-analyzer  (most common)")

    summary = summarize_findings(all_results)
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
        elif tools_errored:
            console.print(
                f"\n[dim]0 findings — but {len(tools_errored)}/{len(all_results)} "
                f"tools errored. Run 'miesc doctor' to diagnose.[/dim]"
            )
        else:
            console.print("\n[green]No issues found![/green]")
    else:
        print("\n=== Scan Results ===")  # noqa: T201
        for sev, count in summary.items():
            if count > 0:
                print(f"{sev}: {count}")  # noqa: T201
        print(f"TOTAL: {total}")  # noqa: T201

    # Save output
    if output:
        # Consolidate all findings into a single list
        all_findings = []
        for r in all_results:
            for f in r.get("findings", []):
                f.setdefault("tool", r.get("tool", "unknown"))
                all_findings.append(f)

        data = {
            "contract": str(contract),
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "success": True,
            "summary": summary,
            "total_findings": total,
            "findings": all_findings,
            "results": all_results,
        }
        with open(output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")

    # CI mode exit
    if ci and critical_high > 0:
        error(f"CI check failed: {critical_high} critical/high issues")
        sys.exit(1)
