#!/usr/bin/env python3
"""
Generate Enhanced Reports from MIESC Output
Reads existing analysis output and generates improved formatted reports

Usage:
    python generate_reports.py <output_dir> [project_name]

Example:
    python generate_reports.py output/uniswap_core_only "Uniswap V2 Core"
"""

import sys
import argparse
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

from src.report_formatter import generate_project_report


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='Generate enhanced reports from MIESC analysis output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate reports for a project
  python generate_reports.py output/uniswap_core_only

  # Specify custom project name
  python generate_reports.py output/myproject "My DeFi Project"
        """
    )

    parser.add_argument('output_dir', help='Path to MIESC output directory')
    parser.add_argument('project_name', nargs='?', default=None,
                        help='Project name (default: directory name)')

    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_arguments()

    # Validate output directory
    output_path = Path(args.output_dir)
    if not output_path.exists():
        print(f"❌ Error: Directory not found: {args.output_dir}")
        sys.exit(1)

    # Get project name
    project_name = args.project_name or output_path.name

    # Print header
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            "[bold cyan]📊 MIESC Report Generator[/bold cyan]\n\n"
            f"[white]Project:[/white] {project_name}\n"
            f"[white]Output Dir:[/white] {args.output_dir}",
            border_style="cyan"
        ))
    else:
        print("=" * 60)
        print("📊 MIESC Report Generator")
        print("=" * 60)
        print(f"Project: {project_name}")
        print(f"Output Dir: {args.output_dir}")
        print()

    # Generate reports
    try:
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Generating reports...", total=None)

                reports_dir = generate_project_report(args.output_dir, project_name)

                progress.update(task, completed=True)

            console.print(Panel.fit(
                "[bold green]✅ Reports Generated Successfully![/bold green]\n\n"
                f"[white]📁 Reports saved to:[/white] {reports_dir}\n\n"
                f"[white]📊 Dashboard:[/white] {reports_dir}/dashboard.html\n"
                f"[white]📝 Consolidated:[/white] {reports_dir}/consolidated_report.md",
                border_style="green"
            ))

            # Offer to open dashboard
            console.print("\n[cyan]To view the dashboard, run:[/cyan]")
            console.print(f"[yellow]open {reports_dir}/dashboard.html[/yellow]")

        else:
            print("⏳ Generating reports...")
            reports_dir = generate_project_report(args.output_dir, project_name)

            print("\n" + "=" * 60)
            print("✅ Reports Generated Successfully!")
            print("=" * 60)
            print(f"Reports saved to: {reports_dir}")
            print(f"Dashboard: {reports_dir}/dashboard.html")
            print(f"Consolidated: {reports_dir}/consolidated_report.md")
            print()
            print(f"To view: open {reports_dir}/dashboard.html")

    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[bold red]❌ Error generating reports:[/bold red] {str(e)}")
        else:
            print(f"❌ Error generating reports: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
