#!/usr/bin/env python3
"""
MIESC - Multi-Contract Project Analyzer
Analyzes entire projects from folders or GitHub repositories

Usage:
    python main_project.py <source> <tag> [options]

Examples:
    # Analyze local directory
    python main_project.py contracts/ myproject --strategy scan

    # Analyze GitHub repository
    python main_project.py https://github.com/user/repo myproject --strategy unified

    # Quick scan with Ollama
    python main_project.py contracts/ myproject --use-ollama --quick
"""

import sys
import os
import argparse
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.project_analyzer import ProjectAnalyzer
from src.graph_visualizer import GraphVisualizer

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='MIESC - Multi-Contract Project Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan all contracts individually
  python main_project.py contracts/ myproject --strategy scan

  # Analyze as unified contract
  python main_project.py contracts/ myproject --strategy unified

  # Analyze GitHub repository
  python main_project.py https://github.com/user/repo myproject

  # Quick analysis with Ollama
  python main_project.py contracts/ myproject --use-ollama --quick

  # Full analysis with visualization
  python main_project.py contracts/ myproject --use-ollama --visualize
        """
    )

    parser.add_argument('source', help='Contract file, directory, or GitHub URL')
    parser.add_argument('tag', help='Output tag/directory name')

    # Analysis strategy
    parser.add_argument('--strategy', choices=['scan', 'unified', 'both'], default='scan',
                        help='Analysis strategy: scan (individual contracts), unified (combined), both (default: scan)')

    # Visualization
    parser.add_argument('--visualize', action='store_true',
                        help='Generate dependency visualizations')

    # Tool selection (from main_ai.py)
    parser.add_argument('--use-slither', action='store_true', default=True,
                        help='Use Slither static analyzer (default: True)')
    parser.add_argument('--use-ollama', action='store_true',
                        help='Use Ollama local LLM (cost-free, private)')
    parser.add_argument('--ollama-model', default='codellama:13b',
                        help='Ollama model to use (default: codellama:13b)')
    parser.add_argument('--quick', action='store_true',
                        help='Quick analysis mode (uses codellama:7b)')

    # Project analysis options
    parser.add_argument('--max-contracts', type=int, default=None,
                        help='Maximum number of contracts to analyze (default: all)')
    parser.add_argument('--priority-filter', choices=['high', 'medium', 'low'], default=None,
                        help='Only analyze contracts with this priority or higher')

    return parser.parse_args()


def print_project_summary(analysis: dict):
    """Print project analysis summary"""
    stats = analysis['statistics']

    if RICH_AVAILABLE:
        table = Table(title="📊 Project Statistics", show_header=False)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold")

        table.add_row("Total Contracts", str(stats['total_files']))
        table.add_row("Total Lines of Code", f"{stats['total_lines']:,}")
        table.add_row("Total Functions", str(stats['total_functions']))
        table.add_row("├─ Contracts", str(stats['contracts']))
        table.add_row("├─ Interfaces", str(stats['interfaces']))
        table.add_row("└─ Libraries", str(stats['libraries']))
        table.add_row("Avg Lines per Contract", f"{stats['avg_lines_per_contract']:.1f}")
        table.add_row("Pragma Versions", ", ".join(stats['pragma_versions']))

        console.print(table)
    else:
        print("\n📊 Project Statistics:")
        print(f"  Total Contracts: {stats['total_files']}")
        print(f"  Total Lines: {stats['total_lines']:,}")
        print(f"  Total Functions: {stats['total_functions']}")
        print(f"  Contracts: {stats['contracts']}, Interfaces: {stats['interfaces']}, Libraries: {stats['libraries']}")


def print_scan_plan(scan_plan: list, max_show: int = 10):
    """Print scan plan"""
    if RICH_AVAILABLE:
        table = Table(title="📋 Scan Plan", show_header=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Contract", style="cyan")
        table.add_column("Priority", style="bold")
        table.add_column("Lines", justify="right")
        table.add_column("Est. Time", justify="right")
        table.add_column("Dependencies", style="dim")

        for item in scan_plan[:max_show]:
            priority_color = {
                'high': 'red',
                'medium': 'yellow',
                'low': 'green'
            }[item['priority']]

            table.add_row(
                str(item['order']),
                item['name'],
                f"[{priority_color}]{item['priority'].upper()}[/{priority_color}]",
                str(item['lines']),
                f"{item['estimated_time_seconds']}s",
                ", ".join(item['dependencies']) if item['dependencies'] else "-"
            )

        if len(scan_plan) > max_show:
            table.add_row(
                "...",
                f"and {len(scan_plan) - max_show} more",
                "", "", "", ""
            )

        console.print(table)
    else:
        print(f"\n📋 Scan Plan ({len(scan_plan)} contracts):")
        for item in scan_plan[:max_show]:
            deps = f" (depends on: {', '.join(item['dependencies'])})" if item['dependencies'] else ""
            print(f"  {item['order']}. {item['name']} - {item['priority']} priority - {item['estimated_time_seconds']}s{deps}")
        if len(scan_plan) > max_show:
            print(f"  ... and {len(scan_plan) - max_show} more")


def run_individual_scans(scan_plan: list, tag: str, args):
    """Run individual analysis for each contract"""
    import subprocess

    total_contracts = len(scan_plan)
    results = []

    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]🔍 Scanning {total_contracts} contracts individually...[/bold cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:

            task = progress.add_task(f"[cyan]Analyzing contracts...", total=total_contracts)

            for item in scan_plan:
                progress.update(task, description=f"[cyan]Analyzing {item['name']}...")

                # Run main_ai.py for this contract
                output_tag = f"{tag}/{item['name']}"
                cmd = [
                    sys.executable,
                    'main_ai.py',
                    item['path'],
                    output_tag
                ]

                # Add flags
                if args.use_ollama:
                    cmd.extend(['--use-ollama', '--ollama-model', args.ollama_model])
                if args.use_slither:
                    cmd.append('--use-slither')

                # Run analysis
                start_time = time.time()
                result = subprocess.run(cmd, capture_output=True, text=True)
                elapsed = time.time() - start_time

                results.append({
                    'contract': item['name'],
                    'success': result.returncode == 0,
                    'time': elapsed,
                    'output': output_tag
                })

                progress.advance(task)

    else:
        print(f"\n🔍 Scanning {total_contracts} contracts individually...\n")
        for i, item in enumerate(scan_plan, 1):
            print(f"[{i}/{total_contracts}] Analyzing {item['name']}...")

            output_tag = f"{tag}/{item['name']}"
            cmd = [sys.executable, 'main_ai.py', item['path'], output_tag]

            if args.use_ollama:
                cmd.extend(['--use-ollama', '--ollama-model', args.ollama_model])
            if args.use_slither:
                cmd.append('--use-slither')

            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True)
            elapsed = time.time() - start_time

            results.append({
                'contract': item['name'],
                'success': result.returncode == 0,
                'time': elapsed,
                'output': output_tag
            })

    return results


def run_unified_scan(unified_path: str, tag: str, args):
    """Run analysis on unified contract"""
    import subprocess

    if RICH_AVAILABLE:
        console.print("\n[bold cyan]🔍 Analyzing unified contract...[/bold cyan]")

    cmd = [
        sys.executable,
        'main_ai.py',
        unified_path,
        f"{tag}/unified"
    ]

    if args.use_ollama:
        cmd.extend(['--use-ollama', '--ollama-model', args.ollama_model])
    if args.use_slither:
        cmd.append('--use-slither')

    start_time = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - start_time

    return {
        'success': result.returncode == 0,
        'time': elapsed,
        'output': f"{tag}/unified"
    }


def print_results_summary(results: list, strategy: str):
    """Print analysis results summary"""
    if strategy == 'scan':
        successful = sum(1 for r in results if r['success'])
        failed = len(results) - successful
        total_time = sum(r['time'] for r in results)

        if RICH_AVAILABLE:
            table = Table(title="✅ Analysis Results", show_header=True)
            table.add_column("Contract", style="cyan")
            table.add_column("Status", justify="center")
            table.add_column("Time", justify="right")
            table.add_column("Output", style="dim")

            for r in results:
                status = "[green]✓ Success[/green]" if r['success'] else "[red]✗ Failed[/red]"
                table.add_row(
                    r['contract'],
                    status,
                    f"{r['time']:.1f}s",
                    r['output']
                )

            console.print(table)

            console.print(f"\n[bold]Summary:[/bold]")
            console.print(f"  ✓ Successful: {successful}/{len(results)}")
            console.print(f"  ✗ Failed: {failed}/{len(results)}")
            console.print(f"  ⏱️  Total time: {total_time:.1f}s")

        else:
            print("\n✅ Analysis Results:")
            for r in results:
                status = "✓" if r['success'] else "✗"
                print(f"  {status} {r['contract']}: {r['time']:.1f}s -> {r['output']}")
            print(f"\nSummary: {successful}/{len(results)} successful, {total_time:.1f}s total")

    else:  # unified
        result = results  # Single result for unified
        status = "✓ Success" if result['success'] else "✗ Failed"
        print(f"\n{status}: {result['time']:.1f}s -> {result['output']}")


def main():
    """Main entry point"""
    args = parse_arguments()

    # Print header
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            "[bold cyan]MIESC - Multi-Contract Project Analyzer[/bold cyan]\n\n"
            f"[white]Source:[/white] {args.source}\n"
            f"[white]Strategy:[/white] {args.strategy}\n"
            f"[white]Output:[/white] output/{args.tag}/",
            border_style="cyan"
        ))
    else:
        print("=" * 60)
        print("MIESC - Multi-Contract Project Analyzer")
        print("=" * 60)
        print(f"Source: {args.source}")
        print(f"Strategy: {args.strategy}")
        print(f"Output: output/{args.tag}/")

    # Quick mode
    if args.quick:
        args.use_ollama = True
        args.ollama_model = 'codellama:7b'

    # Step 1: Analyze project structure
    if RICH_AVAILABLE:
        console.print("\n[yellow]⚙️  Step 1/3: Analyzing project structure...[/yellow]")
    else:
        print("\n⚙️  Step 1/3: Analyzing project structure...")

    with ProjectAnalyzer(args.source) as analyzer:
        analysis = analyzer.analyze_project()

        # Print statistics
        print_project_summary(analysis)

        # Get scan plan
        scan_plan = analyzer.get_scan_plan()

        # Apply filters
        if args.priority_filter:
            priority_levels = {'high': 3, 'medium': 2, 'low': 1}
            min_priority = priority_levels[args.priority_filter]
            scan_plan = [p for p in scan_plan if priority_levels[p['priority']] >= min_priority]

        if args.max_contracts:
            scan_plan = scan_plan[:args.max_contracts]

        # Print scan plan
        print_scan_plan(scan_plan)

        # Step 2: Generate visualizations
        if args.visualize:
            if RICH_AVAILABLE:
                console.print("\n[yellow]📊 Step 2/3: Generating visualizations...[/yellow]")
            else:
                print("\n📊 Step 2/3: Generating visualizations...")

            viz = GraphVisualizer(analysis)
            viz_dir = f"output/{args.tag}/visualizations"
            viz_files = viz.save_all_formats(viz_dir)

            if RICH_AVAILABLE:
                console.print(f"[green]✓ Saved visualizations to {viz_dir}/[/green]")
                console.print(f"  - Interactive: {viz_files['html']}")
                console.print(f"  - Mermaid: {viz_files['mermaid']}")
                console.print(f"  - ASCII Tree: {viz_files['tree']}")
            else:
                print(f"✓ Visualizations saved to {viz_dir}/")

        # Step 3: Run analysis
        if RICH_AVAILABLE:
            console.print(f"\n[yellow]🔍 Step 3/3: Running {args.strategy} analysis...[/yellow]")
        else:
            print(f"\n🔍 Step 3/3: Running {args.strategy} analysis...")

        if args.strategy == 'scan':
            # Individual scans
            results = run_individual_scans(scan_plan, args.tag, args)
            print_results_summary(results, 'scan')

        elif args.strategy == 'unified':
            # Create unified contract
            unified_path = f"output/{args.tag}/unified_contract.sol"
            analyzer.create_unified_contract(unified_path)

            if RICH_AVAILABLE:
                console.print(f"[green]✓ Created unified contract: {unified_path}[/green]")
            else:
                print(f"✓ Created unified contract: {unified_path}")

            # Run unified scan
            result = run_unified_scan(unified_path, args.tag, args)
            print_results_summary(result, 'unified')

        elif args.strategy == 'both':
            # Run both strategies
            console.print("\n[bold cyan]Running BOTH strategies...[/bold cyan]")

            # Individual scans
            console.print("\n[yellow]Part 1: Individual scans[/yellow]")
            results_scan = run_individual_scans(scan_plan, f"{args.tag}/scan", args)

            # Unified scan
            console.print("\n[yellow]Part 2: Unified scan[/yellow]")
            unified_path = f"output/{args.tag}/unified_contract.sol"
            analyzer.create_unified_contract(unified_path)
            result_unified = run_unified_scan(unified_path, f"{args.tag}/unified", args)

            # Print both results
            console.print("\n[bold]Individual Scans:[/bold]")
            print_results_summary(results_scan, 'scan')
            console.print("\n[bold]Unified Scan:[/bold]")
            print_results_summary(result_unified, 'unified')

    # Generate enhanced reports
    if RICH_AVAILABLE:
        console.print("\n[yellow]📊 Generating enhanced reports...[/yellow]")
    else:
        print("\n📊 Generating enhanced reports...")

    try:
        from src.report_formatter import generate_project_report
        project_name = args.source.split('/')[-1] if args.source.startswith('http') else args.source
        reports_dir = generate_project_report(f"output/{args.tag}", project_name)

        if RICH_AVAILABLE:
            console.print(f"[green]✓ Enhanced reports generated: {reports_dir}/[/green]")
        else:
            print(f"✓ Enhanced reports generated: {reports_dir}/")
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[yellow]⚠️  Could not generate enhanced reports: {str(e)}[/yellow]")
        else:
            print(f"⚠️  Could not generate enhanced reports: {str(e)}")

    # Final message
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            f"[bold green]✅ Project Analysis Complete[/bold green]\n\n"
            f"[white]Results saved to:[/white] output/{args.tag}/\n"
            f"[white]Reports dashboard:[/white] output/{args.tag}/reports/dashboard.html\n"
            f"[white]Strategy:[/white] {args.strategy}",
            border_style="green"
        ))
        console.print("\n[cyan]To view dashboard:[/cyan]")
        console.print(f"[yellow]open output/{args.tag}/reports/dashboard.html[/yellow]")
    else:
        print("\n" + "=" * 60)
        print("✅ Project Analysis Complete")
        print("=" * 60)
        print(f"Results saved to: output/{args.tag}/")
        print(f"Dashboard: output/{args.tag}/reports/dashboard.html")
        print(f"\nTo view: open output/{args.tag}/reports/dashboard.html")


if __name__ == '__main__':
    main()
