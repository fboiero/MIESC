"""
MIESC CLI - Tools Commands

Commands for managing and exploring security tools.

Author: Fernando Boiero
License: AGPL-3.0
"""

import click

from miesc.cli.constants import ADAPTER_MAP, LAYERS
from miesc.cli.utils import (
    AdapterLoader,
    RICH_AVAILABLE,
    console,
    error,
    info,
    print_banner,
)

# Import Rich components if available
if RICH_AVAILABLE:
    from rich import box
    from rich.panel import Panel
    from rich.table import Table


@click.group()
def tools():
    """Manage and explore security tools."""
    pass


@tools.command("list")
@click.option("--layer", "-l", type=int, help="Filter by layer (1-9)")
@click.option("--available-only", "-a", is_flag=True, help="Show only installed tools")
def tools_list(layer, available_only):
    """List all 50 security tools."""
    print_banner()

    if layer and layer in LAYERS:
        layers_to_show = {layer: LAYERS[layer]}
    else:
        layers_to_show = LAYERS

    if RICH_AVAILABLE:
        for num, layer_info in layers_to_show.items():
            table = Table(
                title=f"Layer {num}: {layer_info['name']}", box=box.ROUNDED, show_header=True
            )
            table.add_column("Tool", style="bold cyan")
            table.add_column("Status", width=12)
            table.add_column("Category")

            for tool in layer_info["tools"]:
                status_info = AdapterLoader.check_tool_status(tool)

                if available_only and not status_info.get("available"):
                    continue

                status = status_info.get("status", "unknown")
                if status_info.get("available"):
                    status_display = "[green]available[/green]"
                elif status == "not_installed":
                    status_display = "[yellow]not installed[/yellow]"
                elif status == "no_adapter":
                    status_display = "[dim]no adapter[/dim]"
                else:
                    status_display = f"[red]{status}[/red]"

                table.add_row(tool, status_display, layer_info["description"])

            console.print(table)
            console.print("")
    else:
        for num, layer_info in layers_to_show.items():
            print(f"\n=== Layer {num}: {layer_info['name']} ===")  # noqa: T201
            for tool in layer_info["tools"]:
                status_info = AdapterLoader.check_tool_status(tool)
                status = "OK" if status_info.get("available") else "MISSING"
                if available_only and status != "OK":
                    continue
                print(f"  [{status}] {tool}")  # noqa: T201


@tools.command("info")
@click.argument("tool", type=str)
def tools_info(tool):
    """Show detailed information about a tool."""
    print_banner()

    adapter = AdapterLoader.get_adapter(tool)

    if not adapter:
        error(f"No adapter found for: {tool}")
        info(f"Available tools: {', '.join(ADAPTER_MAP.keys())}")
        return

    try:
        metadata = adapter.get_metadata()
        status = adapter.is_available()

        if RICH_AVAILABLE:
            panel_content = f"""
[bold cyan]Name:[/bold cyan] {metadata.name}
[bold cyan]Version:[/bold cyan] {metadata.version}
[bold cyan]Category:[/bold cyan] {metadata.category.value if hasattr(metadata.category, 'value') else metadata.category}
[bold cyan]Author:[/bold cyan] {metadata.author}
[bold cyan]License:[/bold cyan] {metadata.license}
[bold cyan]Status:[/bold cyan] {'[green]Available[/green]' if status.value == 'available' else f'[yellow]{status.value}[/yellow]'}

[bold]Links:[/bold]
- Homepage: {metadata.homepage}
- Repository: {metadata.repository}
- Documentation: {metadata.documentation}

[bold]Installation:[/bold]
{metadata.installation_cmd}

[bold]Capabilities:[/bold]
"""
            for cap in metadata.capabilities:
                panel_content += f"- {cap.name}: {cap.description}\n"
                panel_content += f"  Detection types: {', '.join(cap.detection_types[:5])}\n"

            console.print(Panel(panel_content, title=f"Tool: {tool}", border_style="blue"))
        else:
            print(f"\n=== {tool} ===")  # noqa: T201
            print(f"Version: {metadata.version}")  # noqa: T201
            print(f"Category: {metadata.category}")  # noqa: T201
            print(f"Status: {status.value}")  # noqa: T201
            print(f"Installation: {metadata.installation_cmd}")  # noqa: T201

    except Exception as e:
        error(f"Could not get info for {tool}: {e}")
