"""
MIESC CLI - Doctor Command

System health check and tool availability verification.

Author: Fernando Boiero
License: AGPL-3.0
"""

import asyncio
import os
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

from src.llm.provider_health import fetch_openai_compatible_model_ids


def _deepseek_doctor_status() -> tuple[str, str]:
    """Return a human-readable DeepSeek status without exposing secrets."""
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        return "[dim]not set[/dim]", "Set DEEPSEEK_API_KEY for DeepSeek API"

    base_url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    configured_provider = os.environ.get("MIESC_LLM_PROVIDER", "").lower()
    configured_model = (
        os.environ.get("MIESC_LLM_MODEL") if configured_provider == "deepseek" else None
    )
    model = configured_model or "deepseek-v4-flash"

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        return "[yellow]configured[/yellow]", f"{model} configured; run outside active event loop"

    try:
        models = asyncio.run(
            fetch_openai_compatible_model_ids(
                base_url,
                api_key,
                timeout=3,
                provider_name="DeepSeek",
            )
        )
    except RuntimeError:
        return "[yellow]configured[/yellow]", f"{model} configured; run outside active event loop"

    if model in models:
        return "[green]ready[/green]", f"{model} available"
    if models:
        return "[yellow]model missing[/yellow]", f"{model} not listed ({len(models)} models)"
    return "[yellow]unavailable[/yellow]", "/v1/models unreachable or unauthorized"


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
        missing_installable: list[tuple[str, str]] = []  # (tool, install_cmd)

        for layer_num, layer_info in LAYERS.items():
            for tool in layer_info["tools"]:
                status_info = AdapterLoader.check_tool_status(tool)
                install_cmd = status_info.get("install_cmd", "") or ""

                if status_info.get("available"):
                    status_display = "[green]available[/green]"
                    total_available += 1
                elif status_info.get("status") == "not_installed":
                    status_display = "[yellow]not installed[/yellow]"
                    if install_cmd:
                        missing_installable.append((tool, install_cmd))
                elif status_info.get("status") == "no_adapter":
                    status_display = "[dim]pending[/dim]"
                else:
                    status_display = f"[red]{status_info.get('status', 'error')}[/red]"
                    if install_cmd:
                        missing_installable.append((tool, install_cmd))

                tools_table.add_row(str(layer_num), tool, status_display)

        console.print(tools_table)
        console.print(f"\n[bold]{total_available}/{total_tools}[/bold] tools available")

        # How to install missing tools (focused list — no column-width pressure)
        if missing_installable:
            console.print(
                "\n[bold]Install missing tools[/bold] "
                "[dim](all optional — MIESC degrades gracefully):[/dim]"
            )
            for tool, cmd in missing_installable:
                console.print(f"  [yellow]{tool:<22}[/yellow] [cyan]{cmd}[/cyan]")

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
        deepseek_status, deepseek_details = _deepseek_doctor_status()
        llm_table.add_row("DeepSeek", deepseek_status, deepseek_details)

        console.print(llm_table)

        # Recommendations
        console.print("\n[bold]Quick Start:[/bold]")
        console.print(
            "  [cyan]miesc scan contract.sol[/cyan]              # Static + intelligence (95.8% SmartBugs recall)"
        )
        console.print(
            "  [cyan]miesc scan contract.sol --model ollama[/cyan]  # + Local LLM (semantic coverage)"
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
                    hint = status_info.get("install_cmd", "") or ""
                    suffix = f" -> {hint}" if hint else ""
                    print(f"  [MISSING] {tool}{suffix}")  # noqa: T201

        print(f"\n{total_available}/{total_tools} tools available")  # noqa: T201
        print("Missing tools are optional; MIESC degrades gracefully.")  # noqa: T201
