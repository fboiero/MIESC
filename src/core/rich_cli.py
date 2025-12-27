"""
MIESC Rich CLI - Interactive Command Line Interface

Beautiful terminal UI with progress bars, live updates, and rich formatting
using the Rich library.

Author: Fernando Boiero
License: GPL-3.0
"""

import sys
import time
import asyncio
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime
from enum import Enum

# Try to import Rich
try:
    from rich.console import Console, Group
    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
        BarColumn,
        TaskProgressColumn,
        TimeRemainingColumn,
        TimeElapsedColumn,
    )
    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.markdown import Markdown
    from rich.syntax import Syntax
    from rich.prompt import Prompt, Confirm
    from rich.rule import Rule
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class SeverityStyle(str, Enum):
    """Styling for severity levels."""
    CRITICAL = "bold red"
    HIGH = "red"
    MEDIUM = "yellow"
    LOW = "cyan"
    INFO = "dim"


class MIESCRichCLI:
    """
    Rich CLI interface for MIESC.

    Provides beautiful terminal output with:
    - Progress bars for audit execution
    - Live updates during analysis
    - Colored and formatted findings
    - Interactive prompts
    """

    BANNER = """
 ███╗   ███╗██╗███████╗███████╗ ██████╗
 ████╗ ████║██║██╔════╝██╔════╝██╔════╝
 ██╔████╔██║██║█████╗  ███████╗██║
 ██║╚██╔╝██║██║██╔══╝  ╚════██║██║
 ██║ ╚═╝ ██║██║███████╗███████║╚██████╗
 ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝
    """

    def __init__(self, verbose: bool = False):
        if not RICH_AVAILABLE:
            raise ImportError("Rich library not installed. Run: pip install rich")

        self.console = Console()
        self.verbose = verbose
        self._progress = None
        self._live = None

    def show_banner(self) -> None:
        """Display the MIESC banner."""
        banner_text = Text(self.BANNER, style="bold blue")
        version_text = Text("v4.2.0 - Multi-layer Intelligent Evaluation for Smart Contracts\n",
                           style="italic cyan")
        self.console.print(banner_text)
        self.console.print(version_text, justify="center")
        self.console.print(Rule(style="blue"))

    def show_welcome(self) -> None:
        """Display welcome message with system info."""
        self.show_banner()

        # System info table
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Author", "Fernando Boiero")
        table.add_row("Institution", "UNDEF - IUA Cordoba")
        table.add_row("License", "GPL-3.0")
        table.add_row("Layers", "7 (Defense in Depth)")
        table.add_row("Adapters", "25+")

        self.console.print(Panel(table, title="[bold]System Info[/bold]", border_style="blue"))

    def show_tools_status(self, tools: Dict[str, Dict[str, Any]]) -> None:
        """Display tool availability status."""
        table = Table(title="Security Tools Status", box=box.ROUNDED)
        table.add_column("Tool", style="cyan")
        table.add_column("Layer", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("Version")

        for tool_name, info in tools.items():
            available = info.get("available", False)
            status = "[green]Available[/green]" if available else "[red]Not Found[/red]"
            version = info.get("version", "N/A")
            layer = str(info.get("layer", "-"))
            table.add_row(tool_name, layer, status, version)

        self.console.print(table)

    def show_contract_info(self, path: str, code: Optional[str] = None) -> None:
        """Display contract information."""
        path_obj = Path(path)

        info_table = Table(show_header=False, box=box.SIMPLE)
        info_table.add_column("", style="cyan")
        info_table.add_column("")

        info_table.add_row("File", str(path_obj.name))
        info_table.add_row("Path", str(path_obj.parent))

        if path_obj.exists():
            size = path_obj.stat().st_size
            info_table.add_row("Size", f"{size:,} bytes")

            if code is None:
                code = path_obj.read_text()

            lines = len(code.splitlines())
            info_table.add_row("Lines", str(lines))

        self.console.print(Panel(info_table, title="[bold]Contract Info[/bold]", border_style="cyan"))

        # Show code preview if verbose
        if self.verbose and code:
            preview_lines = code.splitlines()[:20]
            preview = "\n".join(preview_lines)
            if len(code.splitlines()) > 20:
                preview += "\n..."

            syntax = Syntax(preview, "solidity", theme="monokai", line_numbers=True)
            self.console.print(Panel(syntax, title="[bold]Code Preview[/bold]", border_style="dim"))

    def create_progress(self) -> "Progress":
        """Create a progress bar instance."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
        )

    def run_with_progress(
        self,
        tasks: List[Dict[str, Any]],
        executor: Callable[[str, Callable], Any]
    ) -> List[Any]:
        """
        Run tasks with progress tracking.

        Args:
            tasks: List of task dicts with 'name', 'description', 'total'
            executor: Function(task_name, progress_callback) -> result

        Returns:
            List of results from each task
        """
        results = []

        with self.create_progress() as progress:
            task_ids = {}

            # Add all tasks
            for task in tasks:
                task_id = progress.add_task(
                    task["description"],
                    total=task.get("total", 100)
                )
                task_ids[task["name"]] = task_id

            # Execute tasks
            for task in tasks:
                task_name = task["name"]
                task_id = task_ids[task_name]

                def update_progress(completed: float, description: str = None):
                    progress.update(task_id, completed=completed)
                    if description:
                        progress.update(task_id, description=description)

                try:
                    result = executor(task_name, update_progress)
                    results.append(result)
                    progress.update(task_id, completed=task.get("total", 100))
                except Exception as e:
                    results.append({"error": str(e)})
                    progress.update(task_id, description=f"[red]Error: {task_name}[/red]")

        return results

    def run_audit_with_progress(
        self,
        contract_path: str,
        layers: List[Dict[str, Any]],
        audit_func: Callable
    ) -> Dict[str, Any]:
        """
        Run audit with visual progress for each layer.

        Args:
            contract_path: Path to the contract
            layers: List of layer configs with 'name', 'tools'
            audit_func: Function(layer_num, tool, progress_cb) -> findings

        Returns:
            Complete audit results
        """
        all_findings = []
        layer_results = {}

        self.console.print(Rule("[bold]Starting Security Audit[/bold]", style="green"))
        self.show_contract_info(contract_path)

        total_tools = sum(len(layer.get("tools", [])) for layer in layers)
        completed_tools = 0

        with self.create_progress() as progress:
            overall_task = progress.add_task(
                "[bold green]Overall Progress",
                total=total_tools
            )

            for layer in layers:
                layer_num = layer.get("number", 0)
                layer_name = layer.get("name", f"Layer {layer_num}")
                tools = layer.get("tools", [])

                self.console.print(f"\n[bold cyan]Layer {layer_num}:[/bold cyan] {layer_name}")

                layer_findings = []
                layer_task = progress.add_task(
                    f"  {layer_name}",
                    total=len(tools)
                )

                for i, tool in enumerate(tools):
                    tool_task = progress.add_task(
                        f"    Running {tool}...",
                        total=100
                    )

                    try:
                        def tool_progress(pct: float):
                            progress.update(tool_task, completed=pct)

                        findings = audit_func(layer_num, tool, tool_progress)
                        layer_findings.extend(findings)

                        progress.update(tool_task, completed=100)
                        finding_count = len(findings)
                        progress.update(
                            tool_task,
                            description=f"    [green]{tool}[/green]: {finding_count} findings"
                        )

                    except Exception as e:
                        progress.update(
                            tool_task,
                            description=f"    [red]{tool}: Error[/red]"
                        )

                    completed_tools += 1
                    progress.update(overall_task, completed=completed_tools)
                    progress.update(layer_task, completed=i + 1)

                layer_results[layer_num] = layer_findings
                all_findings.extend(layer_findings)

        return {
            "findings": all_findings,
            "by_layer": layer_results,
            "total": len(all_findings)
        }

    def show_findings_summary(self, findings: List[Dict[str, Any]]) -> None:
        """Display a summary of findings."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Summary table
        table = Table(title="Findings Summary", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        table.add_row("[bold red]Critical[/bold red]", str(severity_counts["critical"]))
        table.add_row("[red]High[/red]", str(severity_counts["high"]))
        table.add_row("[yellow]Medium[/yellow]", str(severity_counts["medium"]))
        table.add_row("[cyan]Low[/cyan]", str(severity_counts["low"]))
        table.add_row("[dim]Info[/dim]", str(severity_counts["info"]))
        table.add_row("─" * 10, "─" * 5)
        table.add_row("[bold]Total[/bold]", f"[bold]{len(findings)}[/bold]")

        self.console.print(table)

    def show_findings_detail(self, findings: List[Dict[str, Any]]) -> None:
        """Display detailed findings."""
        if not findings:
            self.console.print(Panel(
                "[green]No vulnerabilities found![/green]",
                title="Results",
                border_style="green"
            ))
            return

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev not in grouped:
                grouped[sev] = []
            grouped[sev].append(f)

        for severity in severity_order:
            if severity not in grouped:
                continue

            style = getattr(SeverityStyle, severity.upper(), SeverityStyle.INFO).value
            self.console.print(Rule(f"[{style}]{severity.upper()}[/{style}]"))

            for finding in grouped[severity]:
                self._show_finding(finding, style)

    def _show_finding(self, finding: Dict[str, Any], style: str) -> None:
        """Display a single finding."""
        title = finding.get("title", finding.get("type", "Unknown"))
        description = finding.get("description", "No description")
        tool = finding.get("tool", "unknown")
        location = finding.get("location", "")
        cwe = finding.get("cwe", "")
        swc = finding.get("swc", "")

        # Build finding content
        content = Table(show_header=False, box=None, padding=(0, 1))
        content.add_column("Key", style="cyan")
        content.add_column("Value")

        content.add_row("Tool", tool)
        if location:
            content.add_row("Location", location)
        if cwe:
            content.add_row("CWE", cwe)
        if swc:
            content.add_row("SWC", swc)
        content.add_row("", "")
        content.add_row("Description", Text(description, style="dim"))

        if finding.get("remediation"):
            content.add_row("", "")
            content.add_row("Remediation", Text(finding["remediation"], style="green"))

        self.console.print(Panel(
            content,
            title=f"[{style}]{title}[/{style}]",
            border_style=style.split()[-1] if style else "white"
        ))

    def show_findings_tree(self, findings: List[Dict[str, Any]]) -> None:
        """Display findings as a tree structure."""
        tree = Tree("[bold]Audit Findings[/bold]")

        # Group by layer
        by_layer = {}
        for f in findings:
            layer = f.get("layer", 0)
            if layer not in by_layer:
                by_layer[layer] = []
            by_layer[layer].append(f)

        for layer in sorted(by_layer.keys()):
            layer_branch = tree.add(f"[bold cyan]Layer {layer}[/bold cyan]")

            # Group by tool within layer
            by_tool = {}
            for f in by_layer[layer]:
                tool = f.get("tool", "unknown")
                if tool not in by_tool:
                    by_tool[tool] = []
                by_tool[tool].append(f)

            for tool, tool_findings in by_tool.items():
                tool_branch = layer_branch.add(f"[blue]{tool}[/blue] ({len(tool_findings)} findings)")

                for f in tool_findings:
                    severity = f.get("severity", "info").lower()
                    style = getattr(SeverityStyle, severity.upper(), SeverityStyle.INFO).value
                    title = f.get("title", f.get("type", "Unknown"))
                    tool_branch.add(f"[{style}]{title}[/{style}]")

        self.console.print(tree)

    def prompt_contract(self, default: str = "") -> str:
        """Prompt for contract path."""
        return Prompt.ask(
            "[cyan]Enter contract path[/cyan]",
            default=default
        )

    def prompt_tools(self, available: List[str]) -> List[str]:
        """Prompt for tool selection."""
        self.console.print("\n[bold]Available tools:[/bold]")
        for i, tool in enumerate(available, 1):
            self.console.print(f"  {i}. {tool}")

        selection = Prompt.ask(
            "\n[cyan]Select tools (comma-separated numbers or 'all')[/cyan]",
            default="all"
        )

        if selection.lower() == "all":
            return available

        try:
            indices = [int(x.strip()) - 1 for x in selection.split(",")]
            return [available[i] for i in indices if 0 <= i < len(available)]
        except (ValueError, IndexError):
            return available

    def prompt_confirm(self, message: str, default: bool = True) -> bool:
        """Prompt for confirmation."""
        return Confirm.ask(message, default=default)

    def show_export_options(self) -> str:
        """Show export format options and get selection."""
        table = Table(title="Export Formats", box=box.SIMPLE)
        table.add_column("#", style="cyan")
        table.add_column("Format")
        table.add_column("Description")

        formats = [
            ("sarif", "SARIF 2.1.0 - GitHub Code Scanning"),
            ("sonarqube", "SonarQube Generic Issue Import"),
            ("checkmarx", "Checkmarx XML Format"),
            ("markdown", "Markdown Report"),
            ("json", "JSON with metadata"),
        ]

        for i, (name, desc) in enumerate(formats, 1):
            table.add_row(str(i), name, desc)

        self.console.print(table)

        selection = Prompt.ask(
            "[cyan]Select format (1-5)[/cyan]",
            default="1"
        )

        try:
            idx = int(selection) - 1
            return formats[idx][0] if 0 <= idx < len(formats) else "sarif"
        except ValueError:
            return "sarif"

    def show_completion(self, duration: float, findings_count: int, output_path: str = None) -> None:
        """Show audit completion message."""
        content = Table(show_header=False, box=None)
        content.add_column("", style="cyan")
        content.add_column("")

        content.add_row("Duration", f"{duration:.2f} seconds")
        content.add_row("Total Findings", str(findings_count))
        if output_path:
            content.add_row("Report", output_path)

        self.console.print(Panel(
            content,
            title="[bold green]Audit Complete[/bold green]",
            border_style="green"
        ))

    def error(self, message: str) -> None:
        """Display error message."""
        self.console.print(Panel(
            f"[red]{message}[/red]",
            title="[bold red]Error[/bold red]",
            border_style="red"
        ))

    def warning(self, message: str) -> None:
        """Display warning message."""
        self.console.print(f"[yellow]Warning:[/yellow] {message}")

    def success(self, message: str) -> None:
        """Display success message."""
        self.console.print(f"[green]{message}[/green]")

    def info(self, message: str) -> None:
        """Display info message."""
        self.console.print(f"[cyan]{message}[/cyan]")


def create_cli(verbose: bool = False) -> Optional[MIESCRichCLI]:
    """Create a Rich CLI instance if available."""
    if RICH_AVAILABLE:
        return MIESCRichCLI(verbose=verbose)
    return None


# Example usage
if __name__ == "__main__":
    if not RICH_AVAILABLE:
        print("Rich library not installed. Run: pip install rich")
        sys.exit(1)

    cli = MIESCRichCLI(verbose=True)
    cli.show_welcome()

    # Demo findings
    demo_findings = [
        {
            "title": "Reentrancy Vulnerability",
            "severity": "critical",
            "tool": "slither",
            "layer": 1,
            "description": "External call before state update allows reentrancy attack.",
            "location": "VulnerableBank.sol:25",
            "cwe": "CWE-841",
            "swc": "SWC-107",
            "remediation": "Use checks-effects-interactions pattern or ReentrancyGuard."
        },
        {
            "title": "Unchecked Return Value",
            "severity": "high",
            "tool": "mythril",
            "layer": 3,
            "description": "Return value of external call not checked.",
            "location": "Token.sol:42",
        },
        {
            "title": "Missing Access Control",
            "severity": "medium",
            "tool": "aderyn",
            "layer": 1,
            "description": "Function lacks access control modifier.",
            "location": "Vault.sol:15",
        },
    ]

    cli.show_findings_summary(demo_findings)
    cli.show_findings_tree(demo_findings)
    cli.show_findings_detail(demo_findings)
