"""
MIESC CLI - Doctor Command

System health check and tool availability verification.

Author: Fernando Boiero
License: AGPL-3.0
"""

import subprocess

import click

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from miesc.cli.constants import LAYERS
from miesc.cli.utils import (
    RICH_AVAILABLE,
    AdapterLoader,
    console,
    info,
    print_banner,
)

# Import Rich components if available
if RICH_AVAILABLE:
    from rich import box
    from rich.table import Table


# =============================================================================
# Doctor Command
# =============================================================================


@click.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed information")
def doctor(verbose: bool) -> None:
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

        total_tools = sum(len(layer_info["tools"]) for layer_info in LAYERS.values())

        # Security tools table
        tools_table = Table(title=f"Security Tools ({total_tools} Total)", box=box.ROUNDED)
        tools_table.add_column("Layer", style="bold", width=8)
        tools_table.add_column("Tool", width=25)
        tools_table.add_column("Status", width=20)

        total_available = 0

        for layer_num, layer_info in LAYERS.items():
            for tool in layer_info["tools"]:
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

        # LLM Providers section
        console.print("")
        llm_table = Table(title="LLM Providers", box=box.ROUNDED)
        llm_table.add_column("Provider", style="bold", width=15)
        llm_table.add_column("Status", width=12)
        llm_table.add_column("Details", width=40)

        # Ollama
        try:
            import urllib.request

            req = urllib.request.Request("http://localhost:11434/api/tags")
            resp = urllib.request.urlopen(req, timeout=3)
            import json as _json

            models = [m["name"] for m in _json.loads(resp.read()).get("models", [])]
            coder_models = [m for m in models if "coder" in m or "qwen" in m or "codellama" in m]
            llm_table.add_row(
                "Ollama",
                "[green]running[/green]",
                f"{len(models)} models ({', '.join(coder_models[:3])})",
            )
        except Exception:
            llm_table.add_row(
                "Ollama",
                "[yellow]offline[/yellow]",
                "Install: https://ollama.com + ollama pull qwen2.5-coder:14b",
            )

        # Anthropic
        import os

        if os.environ.get("ANTHROPIC_API_KEY"):
            llm_table.add_row("Anthropic", "[green]configured[/green]", "ANTHROPIC_API_KEY set")
        else:
            llm_table.add_row("Anthropic", "[dim]not set[/dim]", "Set ANTHROPIC_API_KEY for Claude")

        # OpenAI
        if os.environ.get("OPENAI_API_KEY"):
            llm_table.add_row("OpenAI", "[green]configured[/green]", "OPENAI_API_KEY set")
        else:
            llm_table.add_row("OpenAI", "[dim]not set[/dim]", "Set OPENAI_API_KEY for GPT")

        # DeepSeek
        if os.environ.get("DEEPSEEK_API_KEY"):
            llm_table.add_row("DeepSeek", "[green]configured[/green]", "DEEPSEEK_API_KEY set")
        else:
            llm_table.add_row(
                "DeepSeek",
                "[dim]not set[/dim]",
                "Set DEEPSEEK_API_KEY for DeepSeek API",
            )

        console.print(llm_table)

        # Recommendations
        console.print("\n[bold]Quick Start:[/bold]")
        console.print(
            "  [cyan]miesc scan contract.sol[/cyan]              # Static only (95.8% recall)"
        )
        console.print(
            "  [cyan]miesc scan contract.sol --model ollama[/cyan]  # + Local LLM (97.9% recall)"
        )
        console.print(
            "  [cyan]miesc scan contract.sol --ensemble[/cyan]      # Multi-provider (92.5% EVMBench)"
        )

    else:
        print("=== Core Dependencies ===")  # noqa: T201
        for dep, cmd in dependencies.items():
            try:
                subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
                print(f"[OK] {dep}")  # noqa: T201
            except Exception:
                print(f"[MISSING] {dep}")  # noqa: T201

        print("\n=== Security Tools ===")  # noqa: T201
        total_available = 0
        total_tools = 0

        for layer_num, layer_info in LAYERS.items():
            print(f"\nLayer {layer_num}: {layer_info['name']}")  # noqa: T201
            for tool in layer_info["tools"]:
                total_tools += 1
                status_info = AdapterLoader.check_tool_status(tool)
                if status_info.get("available"):
                    print(f"  [OK] {tool}")  # noqa: T201
                    total_available += 1
                else:
                    print(f"  [MISSING] {tool}")  # noqa: T201

        print(f"\n{total_available}/{total_tools} tools available")  # noqa: T201
