"""
MIESC CLI - Watch Command

Real-time file watching and auto-scanning for Solidity developers.

Author: Fernando Boiero
License: AGPL-3.0
"""

import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import click

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


# =============================================================================
# Watch Command
# =============================================================================


@click.command()
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
                print(f"\n[{timestamp}] Scanning {file_name}...")  # noqa: T201

            all_findings = []
            start_time = time.time()

            for tool in tools_to_run:
                result = run_tool(tool, file_path, timeout=60)

                if result["status"] == "success":
                    findings = result.get("findings", [])
                    all_findings.extend(findings)

                    if findings:
                        if RICH_AVAILABLE:
                            console.print(f"  [green]{tool}[/green]: {len(findings)} findings")
                        else:
                            print(f"  {tool}: {len(findings)} findings")  # noqa: T201
                elif result["status"] == "not_available":
                    pass  # Silently skip unavailable tools
                else:
                    if RICH_AVAILABLE:
                        console.print(f"  [yellow]{tool}[/yellow]: error")

            elapsed = time.time() - start_time
            summary = summarize_findings([{"findings": all_findings}])

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
                print(  # noqa: T201
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
