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

from miesc.llm.provider_health import fetch_openai_compatible_model_ids


def _provider_status(row: dict) -> tuple[str, str]:
    """Status cell and details for one registry provider, never exposing the key.

    Cloud providers with a key: OpenAI-compatible ones are probed on ``/v1/models`` (3 s)
    to say whether the default model is listed; Anthropic-kind ones report configured.
    """
    env_hint = " or ".join(row["api_key_env"]) or "no key needed"
    if not row["configured"]:
        return "[dim]not set[/dim]", f"Set {env_hint}"
    if row["kind"] != "openai":
        return "[green]configured[/green]", f"{row['default_model']} via {row['host']}"

    from miesc.core.llm_providers import api_key_for, get_provider

    spec = get_provider(row["name"])
    api_key = api_key_for(spec) or ""
    configured_provider = os.environ.get("MIESC_LLM_PROVIDER", "").lower()
    model = (
        os.environ.get("MIESC_LLM_MODEL") if configured_provider == row["name"] else None
    ) or spec.default_model
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        return "[yellow]configured[/yellow]", f"{model} configured; run outside active event loop"
    try:
        models = asyncio.run(
            fetch_openai_compatible_model_ids(
                spec.base_url or "https://api.openai.com/v1",
                api_key,
                timeout=3,
                provider_name=spec.display_name,
            )
        )
    except RuntimeError:
        return "[yellow]configured[/yellow]", f"{model} configured; run outside active event loop"
    if model in models:
        return "[green]ready[/green]", f"{model} available at {row['host']}"
    if models:
        return "[yellow]model missing[/yellow]", f"{model} not listed ({len(models)} models)"
    return (
        "[yellow]unavailable[/yellow]",
        f"/v1/models at {row['host']} unreachable or unauthorized",
    )


def _cairo_tool_rows() -> list[tuple[str, bool, str, str]]:
    """Status rows for the Cairo/Starknet tools: (name, available, version, note).

    Additive section — these tools live in ADAPTER_MAP but not in LAYERS (so they
    never alter EVM audit enumeration). Caracal is the external semantic analyzer;
    Scarb only supplies project metadata; the pattern adapter is the built-in
    correlation pair.
    """
    rows: list[tuple[str, bool, str, str]] = []

    # Caracal (external binary). is_available via the adapter (respects
    # CARACAL_BIN / ~/.cargo/bin / PATH); version via its version_command.
    caracal_status = AdapterLoader.check_tool_status("caracal")
    caracal_version = ""
    adapter = AdapterLoader.get_adapter("caracal")
    vcmd = getattr(adapter, "version_command", lambda: None)() if adapter else None
    if vcmd:
        try:
            res = subprocess.run(vcmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                caracal_version = (res.stdout or res.stderr).strip().split("\n")[0][:40]
        except Exception:
            caracal_version = ""
    rows.append(
        (
            "caracal",
            bool(caracal_status.get("available")),
            caracal_version or "—",
            "Cairo 2.x (bundled compiler 2.20); install: fork adrienlacombe/caracal",
        )
    )

    # Scarb — only needed to supply `scarb metadata` for Scarb projects; the
    # bundled Caracal compiler does the actual compiling, so any 2.x works.
    scarb_version = ""
    try:
        res = subprocess.run(["scarb", "--version"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            scarb_version = res.stdout.strip().split("\n")[0][:40]
    except Exception:
        scarb_version = ""
    rows.append(
        (
            "scarb",
            bool(scarb_version),
            scarb_version or "—",
            "Optional: supplies `scarb metadata` for Scarb projects (any 2.x)",
        )
    )

    # Built-in pattern adapter (always available).
    rows.append(
        (
            "cairo (patterns)",
            True,
            "built-in",
            "Experimental; low-confidence correlation pair for Caracal",
        )
    )
    return rows


def _ollama_online(timeout: int = 3) -> bool:
    """True iff a local Ollama server answers; used to label LLM-backed probes."""
    try:
        import urllib.request

        urllib.request.urlopen(  # noqa: S310 - fixed localhost URL
            "http://localhost:11434/api/tags", timeout=timeout
        )
        return True
    except Exception:
        return False


def _smoke_verdict_style(verdict: str) -> str:
    from miesc.cli import smoke_probe

    return {
        smoke_probe.FUNCTIONAL: "[green]functional[/green]",
        smoke_probe.DEGRADED: "[red]degraded[/red]",
        smoke_probe.SLOW: "[yellow]slow[/yellow]",
        smoke_probe.NEEDS_BACKEND: "[dim]needs-backend[/dim]",
        smoke_probe.NOT_APPLICABLE: "[dim]n/a[/dim]",
    }.get(verdict, verdict)


def _run_smoke(smoke_all: bool) -> None:
    """Run the functional probe over the available tools and print the result.

    This is opt-in and slow: it launches one short-lived subprocess per
    available tool. It reports whether each tool *runs* on a trivial contract,
    which is a stronger claim than ``doctor``'s "installed" — but a weaker one
    than "works on a real project".
    """
    import tempfile

    from miesc.cli import smoke_probe

    layers = smoke_probe.layers_for(smoke_all)
    timeout = smoke_probe.timeout_for(smoke_all)
    llm_tools = AdapterLoader.llm_tools()
    ollama_online = _ollama_online()

    # Which tools in the selected layers are installed (only those are probed).
    probed: list[tuple[int, str]] = []
    total = 0
    for layer in layers:
        for tool in LAYERS[layer]["tools"]:
            total += 1
            if AdapterLoader.check_tool_status(tool).get("available"):
                probed.append((layer, tool))

    skipped_layers = [n for n in smoke_probe.SLOW_LAYERS if not smoke_all]

    header = "Functional Probe (--smoke-all)" if smoke_all else "Functional Probe (--smoke)"
    rows: list[tuple[int, str, str, str]] = []
    with tempfile.TemporaryDirectory(prefix="miesc-smoke-") as tmp:
        from pathlib import Path

        fixture = str(smoke_probe.write_fixture(Path(tmp)))
        for layer, tool in probed:
            verdict, detail = smoke_probe.probe_tool(
                tool,
                fixture,
                timeout=timeout,
                llm_tools=llm_tools,
                ollama_online=ollama_online,
            )
            rows.append((layer, tool, verdict, detail))

    counts = smoke_probe.summarize(v for _, _, v, _ in rows)
    functional = counts[smoke_probe.FUNCTIONAL]
    # Tools that correctly declined this input (a .vy / circom analyzer handed a
    # .sol) are not defects and do not count against the functional gap.
    applicable = len(probed) - counts[smoke_probe.NOT_APPLICABLE]
    line = smoke_probe.headline(functional, applicable, len(probed), total)

    if RICH_AVAILABLE:
        console.print("")
        table = Table(title=header, box=box.ROUNDED)
        table.add_column("L", style="bold", width=3, no_wrap=True)
        table.add_column("Tool", width=20, no_wrap=True)
        table.add_column("Probe", width=14, no_wrap=True)
        table.add_column("Detail", width=36, overflow="fold")
        for layer, tool, verdict, detail in rows:
            table.add_row(str(layer), tool, _smoke_verdict_style(verdict), detail)
        console.print(table)
        console.print(f"\n[bold]{line}[/bold]")
        extras = (
            counts[smoke_probe.SLOW]
            + counts[smoke_probe.NEEDS_BACKEND]
            + counts[smoke_probe.NOT_APPLICABLE]
        )
        if extras:
            console.print(
                f"[dim]degraded {counts[smoke_probe.DEGRADED]} · "
                f"slow {counts[smoke_probe.SLOW]} · "
                f"needs-backend {counts[smoke_probe.NEEDS_BACKEND]} · "
                f"n/a {counts[smoke_probe.NOT_APPLICABLE]} "
                f"(n/a = correctly declined this file type)[/dim]"
            )
        if skipped_layers:
            names = ", ".join(f"L{n} {LAYERS[n]['name']}" for n in skipped_layers)
            console.print(f"[dim]Not probed (use --smoke-all): {names}[/dim]")
        console.print(
            "[dim]A probe runs each tool on a 15-line contract; "
            "'functional' means it runs, not that it works on a real project.[/dim]"
        )
    else:
        print(f"\n=== {header} ===")  # noqa: T201
        for layer, tool, verdict, detail in rows:
            print(f"  L{layer} {tool:<22} {verdict:<14} {detail}")  # noqa: T201
        print(f"\n{line}")  # noqa: T201
        if skipped_layers:
            names = ", ".join(f"L{n}" for n in skipped_layers)
            print(f"Not probed (use --smoke-all): {names}")  # noqa: T201


# =============================================================================
# Doctor Command
# =============================================================================


@click.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed information")
@click.option(
    "--smoke",
    is_flag=True,
    help="Functionally probe installed tools on a trivial contract (fast layers)",
)
@click.option(
    "--smoke-all",
    is_flag=True,
    help="Probe every layer, including slow ones (fuzzing, symbolic, formal, AI)",
)
def doctor(verbose: bool, smoke: bool, smoke_all: bool) -> None:
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

        # Cairo / Starknet section (experimental; separate from the EVM layers)
        console.print("")
        cairo_table = Table(title="Cairo / Starknet (experimental)", box=box.ROUNDED)
        cairo_table.add_column("Tool", style="bold", width=18)
        cairo_table.add_column("Status", width=16)
        cairo_table.add_column("Version", width=18)
        cairo_table.add_column("Notes", width=44)
        for name, available, version, note in _cairo_tool_rows():
            status_cell = "[green]available[/green]" if available else "[yellow]not installed[/yellow]"
            cairo_table.add_row(name, status_cell, version, note)
        console.print(cairo_table)
        console.print(
            "[dim]Cairo support is experimental. Run: "
            "miesc scan path/to/contract.cairo  (or a Scarb project directory)[/dim]"
        )

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

        # Cloud providers from the registry (built-ins plus llm.providers in the config)
        from miesc.core.llm_providers import describe_providers

        for row in describe_providers():
            if row["kind"] == "ollama":
                continue
            status, details = _provider_status(row)
            label = row["label"] if row["source"] == "builtin" else f"{row['label']} (config)"
            llm_table.add_row(label, status, details)

        console.print(llm_table)
        console.print(
            "[dim]Select with --model provider[:model], e.g. --model kimi, "
            "--model deepseek:deepseek-v4-pro, --model ollama:qwen2.5-coder:32b[/dim]"
        )

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

        print("\n=== Cairo / Starknet (experimental) ===")  # noqa: T201
        for name, available, version, note in _cairo_tool_rows():
            mark = "OK" if available else "MISSING"
            print(f"  [{mark}] {name} ({version}) - {note}")  # noqa: T201

    # Opt-in functional probe (runs after either render branch).
    if smoke or smoke_all:
        _run_smoke(smoke_all)
