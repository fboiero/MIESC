#!/usr/bin/env python3
"""
MIESC CLI - Unified Command Line Interface

A professional CLI for smart contract security audits targeting:
- Developers: Quick scans, CI/CD integration
- Security Researchers: Deep analysis, custom configurations
- Auditors: Full reports, compliance mapping

Integrates 32 security tools across 9 defense layers.

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
"""

import importlib
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

# Add src to path for imports
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR))

# Import version from package
from miesc import __version__ as VERSION  # noqa: E402

# Try to import Rich for beautiful output
try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree

    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# Try to import YAML for config
try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Lazy import for centralized logging (avoid heavy src.core imports at startup)
LOGGING_AVAILABLE = None  # Will be set on first use
_setup_logging = None

# Configure logging (will be reconfigured by setup_logging if available)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def configure_logging(debug: bool = False, quiet: bool = False):
    """Configure logging based on flags and environment variables."""
    global LOGGING_AVAILABLE, _setup_logging

    # Check environment variable
    env_debug = os.environ.get("MIESC_DEBUG", "").lower() in ("1", "true", "yes")
    env_level = os.environ.get("MIESC_LOG_LEVEL", "").upper()

    # Determine log level
    if debug or env_debug:
        level = "DEBUG"
    elif env_level:
        level = env_level
    else:
        level = "INFO"

    # Lazy import of centralized logging
    if LOGGING_AVAILABLE is None:
        try:
            from src.core.logging_config import setup_logging
            _setup_logging = setup_logging
            LOGGING_AVAILABLE = True
        except ImportError:
            LOGGING_AVAILABLE = False

    if LOGGING_AVAILABLE and _setup_logging:
        _setup_logging(level=level, quiet=quiet)
        logger.debug(f"Logging configured with level={level}")
    else:
        logging.basicConfig(level=getattr(logging, level, logging.INFO))
        logger.debug(f"Basic logging configured with level={level}")


# Version and banner
BANNER = r"""
  __  __ ___ _____ ____   ____
 |  \/  |_ _| ____/ ___| / ___|
 | |\/| || ||  _| \___ \| |
 | |  | || || |___ ___) | |___
 |_|  |_|___|_____|____/ \____|
"""


# ============================================================================
# Layer and Tool Definitions
# ============================================================================

# Complete 9-layer architecture with 32 tools
LAYERS = {
    1: {
        "name": "Static Analysis",
        "description": "Pattern-based code analysis",
        "tools": ["slither", "aderyn", "solhint", "wake"],
    },
    2: {
        "name": "Dynamic Testing",
        "description": "Fuzzing and property testing",
        "tools": ["echidna", "medusa", "foundry", "dogefuzz", "vertigo"],
    },
    3: {
        "name": "Symbolic Execution",
        "description": "Path exploration and constraint solving",
        "tools": ["mythril", "manticore", "halmos", "oyente"],
    },
    4: {
        "name": "Formal Verification",
        "description": "Mathematical proofs of correctness",
        "tools": ["certora", "smtchecker", "propertygpt"],
    },
    5: {
        "name": "AI Analysis",
        "description": "LLM-powered vulnerability detection",
        "tools": ["smartllm", "gptscan", "llmsmartaudit"],
    },
    6: {
        "name": "ML Detection",
        "description": "Machine learning classifiers",
        "tools": ["dagnn", "smartbugs_ml", "smartbugs_detector", "smartguard"],
    },
    7: {
        "name": "Specialized Analysis",
        "description": "Domain-specific security checks",
        "tools": [
            "threat_model",
            "gas_analyzer",
            "mev_detector",
            "contract_clone_detector",
            "defi",
            "advanced_detector",
        ],
    },
    8: {
        "name": "Cross-Chain & ZK Security",
        "description": "Bridge security and zero-knowledge circuit analysis",
        "tools": ["crosschain", "zk_circuit"],
    },
    9: {
        "name": "Advanced AI Ensemble",
        "description": "Multi-LLM ensemble with consensus-based detection",
        "tools": ["llmbugscanner"],
    },
}

# Quick scan tools (fast, high-value)
QUICK_TOOLS = ["slither", "aderyn", "solhint", "mythril"]

# Adapter class mapping (tool name -> adapter class name)
ADAPTER_MAP = {
    "slither": "SlitherAdapter",
    "aderyn": "AderynAdapter",
    "solhint": "SolhintAdapter",
    "wake": "WakeAdapter",
    "echidna": "EchidnaAdapter",
    "medusa": "MedusaAdapter",
    "foundry": "FoundryAdapter",
    "dogefuzz": "DogeFuzzAdapter",
    "vertigo": "VertigoAdapter",
    "mythril": "MythrilAdapter",
    "manticore": "ManticoreAdapter",
    "halmos": "HalmosAdapter",
    "oyente": "OyenteAdapter",
    "certora": "CertoraAdapter",
    "smtchecker": "SMTCheckerAdapter",
    "propertygpt": "PropertyGPTAdapter",
    "smartllm": "SmartLLMAdapter",
    "gptscan": "GPTScanAdapter",
    "llmsmartaudit": "LLMSmartAuditAdapter",
    "dagnn": "DAGNNAdapter",
    "smartbugs_ml": "SmartBugsMLAdapter",
    "smartbugs_detector": "SmartBugsDetectorAdapter",
    "smartguard": "SmartGuardAdapter",
    "threat_model": "ThreatModelAdapter",
    "gas_analyzer": "GasAnalyzerAdapter",
    "mev_detector": "MEVDetectorAdapter",
    "contract_clone_detector": "ContractCloneDetectorAdapter",
    "defi": "DeFiAdapter",
    "advanced_detector": "AdvancedDetectorAdapter",
    # Layer 8: Cross-Chain & ZK Security
    "crosschain": "CrossChainAdapter",
    "zk_circuit": "ZKCircuitAdapter",
    # Layer 9: Advanced AI Ensemble
    "llmbugscanner": "LLMBugScannerAdapter",
}


# ============================================================================
# Adapter Loader
# ============================================================================


class AdapterLoader:
    """Dynamic loader for tool adapters."""

    _adapters: Dict[str, Any] = {}
    _loaded = False

    @classmethod
    def load_all(cls) -> Dict[str, Any]:
        """Load all available adapters from src/adapters/."""
        if cls._loaded:
            return cls._adapters

        adapters_dir = ROOT_DIR / "src" / "adapters"

        for tool_name, class_name in ADAPTER_MAP.items():
            try:
                # Build module name
                module_name = f"src.adapters.{tool_name}_adapter"

                # Try to import module
                module = importlib.import_module(module_name)

                # Get adapter class
                adapter_class = getattr(module, class_name, None)

                if adapter_class:
                    # Instantiate adapter
                    cls._adapters[tool_name] = adapter_class()
                    logger.debug(f"Loaded adapter: {tool_name}")
                else:
                    logger.debug(f"Class {class_name} not found in {module_name}")

            except ImportError as e:
                logger.debug(f"Could not import {tool_name}: {e}")
            except Exception as e:
                logger.debug(f"Error loading {tool_name}: {e}")

        cls._loaded = True
        logger.info(f"Loaded {len(cls._adapters)} adapters")
        return cls._adapters

    @classmethod
    def get_adapter(cls, tool_name: str):
        """Get a specific adapter by name."""
        if not cls._loaded:
            cls.load_all()
        return cls._adapters.get(tool_name)

    @classmethod
    def get_available_tools(cls) -> List[str]:
        """Get list of tools with available adapters."""
        if not cls._loaded:
            cls.load_all()
        return list(cls._adapters.keys())

    @classmethod
    def check_tool_status(cls, tool_name: str) -> Dict[str, Any]:
        """Check if a tool is installed and available."""
        adapter = cls.get_adapter(tool_name)
        if not adapter:
            return {"status": "no_adapter", "available": False}

        try:
            # Import ToolStatus enum
            from src.core.tool_protocol import ToolStatus

            status = adapter.is_available()
            return {
                "status": status.value if hasattr(status, "value") else str(status),
                "available": status == ToolStatus.AVAILABLE,
            }
        except Exception as e:
            return {"status": "error", "available": False, "error": str(e)}


# ============================================================================
# Output Helpers
# ============================================================================


def print_banner():
    """Print the MIESC banner."""
    if RICH_AVAILABLE:
        console.print(Text(BANNER, style="bold blue"))
        console.print(
            f"[cyan]v{VERSION}[/cyan] - Multi-layer Intelligent Evaluation for Smart Contracts"
        )
        console.print("[dim]7 Defense Layers | 29 Security Tools | AI-Powered Analysis[/dim]\n")
    else:
        print(BANNER)
        print(f"v{VERSION} - Multi-layer Intelligent Evaluation for Smart Contracts")
        print("7 Defense Layers | 29 Security Tools | AI-Powered Analysis\n")


def success(msg: str):
    """Print success message."""
    if RICH_AVAILABLE:
        console.print(f"[green]OK[/green] {msg}")
    else:
        print(f"[OK] {msg}")


def error(msg: str):
    """Print error message."""
    if RICH_AVAILABLE:
        console.print(f"[red]ERR[/red] {msg}")
    else:
        print(f"[ERR] {msg}")


def warning(msg: str):
    """Print warning message."""
    if RICH_AVAILABLE:
        console.print(f"[yellow]WARN[/yellow] {msg}")
    else:
        print(f"[WARN] {msg}")


def info(msg: str):
    """Print info message."""
    if RICH_AVAILABLE:
        console.print(f"[cyan]INFO[/cyan] {msg}")
    else:
        print(f"[INFO] {msg}")


def load_config() -> Dict[str, Any]:
    """Load MIESC configuration from config/miesc.yaml."""
    config_path = ROOT_DIR / "config" / "miesc.yaml"
    if config_path.exists() and YAML_AVAILABLE:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def load_profiles() -> Dict[str, Any]:
    """Load analysis profiles from config/profiles.yaml."""
    profiles_path = ROOT_DIR / "config" / "profiles.yaml"
    if profiles_path.exists() and YAML_AVAILABLE:
        with open(profiles_path) as f:
            data = yaml.safe_load(f) or {}
            return data.get("profiles", {})
    return {}


def get_profile(name: str) -> Optional[Dict[str, Any]]:
    """Get a specific profile by name, handling aliases."""
    profiles = load_profiles()
    profiles_path = ROOT_DIR / "config" / "profiles.yaml"

    if profiles_path.exists() and YAML_AVAILABLE:
        with open(profiles_path) as f:
            data = yaml.safe_load(f) or {}
            aliases = data.get("aliases", {})
            # Resolve alias
            resolved_name = aliases.get(name, name)
            return profiles.get(resolved_name)

    return profiles.get(name)


# Available profiles for CLI help
AVAILABLE_PROFILES = ["fast", "balanced", "thorough", "security", "ci", "audit", "defi", "token"]


# ============================================================================
# Tool Execution
# ============================================================================


def _run_tool(tool: str, contract: str, timeout: int = 300, **kwargs) -> Dict[str, Any]:
    """
    Run a security tool using its adapter.

    Args:
        tool: Tool name (e.g., 'slither', 'mythril')
        contract: Path to Solidity contract
        timeout: Timeout in seconds
        **kwargs: Additional tool-specific parameters

    Returns:
        Normalized results dictionary
    """
    start_time = datetime.now()

    # Get adapter for tool
    adapter = AdapterLoader.get_adapter(tool)

    if not adapter:
        return {
            "tool": tool,
            "contract": contract,
            "status": "no_adapter",
            "findings": [],
            "execution_time": 0,
            "timestamp": datetime.now().isoformat(),
            "error": f"No adapter found for {tool}",
        }

    try:
        # Check if tool is available
        from src.core.tool_protocol import ToolStatus

        status = adapter.is_available()

        if status != ToolStatus.AVAILABLE:
            return {
                "tool": tool,
                "contract": contract,
                "status": "not_available",
                "findings": [],
                "execution_time": (datetime.now() - start_time).total_seconds(),
                "timestamp": datetime.now().isoformat(),
                "error": f"Tool {tool} not available: {status.value}",
            }

        # Run analysis
        result = adapter.analyze(contract, timeout=timeout, **kwargs)

        # Ensure consistent output format
        return {
            "tool": tool,
            "contract": contract,
            "status": result.get("status", "success"),
            "findings": result.get("findings", []),
            "execution_time": result.get(
                "execution_time", (datetime.now() - start_time).total_seconds()
            ),
            "timestamp": datetime.now().isoformat(),
            "metadata": result.get("metadata", {}),
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error running {tool}: {e}", exc_info=True)
        return {
            "tool": tool,
            "contract": contract,
            "status": "error",
            "findings": [],
            "execution_time": (datetime.now() - start_time).total_seconds(),
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
        }


def _run_layer(layer: int, contract: str, timeout: int = 300) -> List[Dict[str, Any]]:
    """Run all tools in a specific layer."""
    if layer not in LAYERS:
        return []

    results = []
    layer_info = LAYERS[layer]

    for tool in layer_info["tools"]:
        info(f"Running {tool}...")
        result = _run_tool(tool, contract, timeout)
        results.append(result)

        if result["status"] == "success":
            findings_count = len(result.get("findings", []))
            success(f"{tool}: {findings_count} findings in {result.get('execution_time', 0):.1f}s")
        elif result["status"] == "not_available":
            warning(f"{tool}: not installed")
        else:
            warning(f"{tool}: {result.get('error', 'Unknown error')}")

    return results


def _summarize_findings(all_results: List[Dict[str, Any]]) -> Dict[str, int]:
    """Summarize findings by severity."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for result in all_results:
        for finding in result.get("findings", []):
            sev = str(finding.get("severity", "INFO")).upper()
            # Normalize severity names
            if sev in ["CRITICAL", "CRIT"]:
                summary["CRITICAL"] += 1
            elif sev in ["HIGH", "HI"]:
                summary["HIGH"] += 1
            elif sev in ["MEDIUM", "MED"]:
                summary["MEDIUM"] += 1
            elif sev in ["LOW", "LO"]:
                summary["LOW"] += 1
            else:
                summary["INFO"] += 1

    return summary


def _to_sarif(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert results to SARIF 2.1.0 format for GitHub Code Scanning."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MIESC",
                        "version": VERSION,
                        "informationUri": "https://github.com/fboiero/MIESC",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    rule_ids = set()

    for result in results:
        tool_name = result.get("tool", "unknown")

        for finding in result.get("findings", []):
            rule_id = finding.get("type", finding.get("id", finding.get("title", "unknown")))

            # Add rule if not already added
            if rule_id not in rule_ids:
                sarif["runs"][0]["tool"]["driver"]["rules"].append(
                    {
                        "id": rule_id,
                        "name": finding.get("title", rule_id),
                        "shortDescription": {"text": finding.get("message", rule_id)},
                        "fullDescription": {"text": finding.get("description", "")},
                        "helpUri": (
                            finding.get("references", [""])[0] if finding.get("references") else ""
                        ),
                        "properties": {"tool": tool_name},
                    }
                )
                rule_ids.add(rule_id)

            # Map severity
            severity = str(finding.get("severity", "INFO")).upper()
            level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}.get(
                severity, "note"
            )

            # Get location
            location = finding.get("location", {})
            if isinstance(location, dict):
                file_path = location.get("file", result.get("contract", "unknown"))
                line = location.get("line", 1)
            else:
                file_path = result.get("contract", "unknown")
                line = 1

            sarif["runs"][0]["results"].append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": finding.get("description", finding.get("message", ""))},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_path},
                                "region": {"startLine": max(1, int(line))},
                            }
                        }
                    ],
                    "properties": {"tool": tool_name, "confidence": finding.get("confidence", 0.5)},
                }
            )

    return sarif


def _to_markdown(results: List[Dict[str, Any]], contract: str) -> str:
    """Convert results to Markdown report."""
    summary = _summarize_findings(results)
    total = sum(summary.values())

    # Count tools
    successful_tools = [r["tool"] for r in results if r.get("status") == "success"]
    failed_tools = [r["tool"] for r in results if r.get("status") != "success"]

    md = f"""# MIESC Security Audit Report

**Contract**: `{contract}`
**Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**MIESC Version**: {VERSION}

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {summary['CRITICAL']} |
| High | {summary['HIGH']} |
| Medium | {summary['MEDIUM']} |
| Low | {summary['LOW']} |
| Info | {summary['INFO']} |
| **Total** | **{total}** |

### Tools Executed

- **Successful**: {', '.join(successful_tools) if successful_tools else 'None'}
- **Failed/Unavailable**: {', '.join(failed_tools) if failed_tools else 'None'}

## Detailed Findings

"""

    for result in results:
        if result.get("findings"):
            tool_name = result.get("tool", "unknown").upper()
            md += f"### {tool_name}\n\n"

            for finding in result["findings"]:
                severity = finding.get("severity", "INFO")
                title = finding.get("title", finding.get("type", finding.get("id", "Unknown")))
                description = finding.get("description", finding.get("message", ""))

                md += f"**[{severity}]** {title}\n\n"
                md += f"{description}\n\n"

                # Location
                location = finding.get("location", {})
                if isinstance(location, dict) and location.get("file"):
                    md += f"- **Location**: `{location['file']}:{location.get('line', 0)}`\n"

                # Recommendation
                if finding.get("recommendation"):
                    md += f"- **Recommendation**: {finding['recommendation']}\n"

                # References
                if finding.get("swc_id"):
                    md += f"- **SWC**: {finding['swc_id']}\n"

                md += "\n---\n\n"

    md += """
## Appendix

### Tool Execution Details

| Tool | Status | Time (s) | Findings |
|------|--------|----------|----------|
"""

    for result in results:
        tool = result.get("tool", "unknown")
        status = result.get("status", "unknown")
        exec_time = result.get("execution_time", 0)
        findings_count = len(result.get("findings", []))
        md += f"| {tool} | {status} | {exec_time:.1f} | {findings_count} |\n"

    md += f"\n---\n\n*Generated by MIESC v{VERSION}*\n"

    return md


# ============================================================================
# Main CLI Group
# ============================================================================


@click.group(invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show version and exit")
@click.option("--no-banner", is_flag=True, help="Suppress banner output")
@click.option("--debug", "-d", is_flag=True, help="Enable debug mode (verbose logging)")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
@click.pass_context
def cli(ctx, version, no_banner, debug, quiet):
    """
    MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

    A comprehensive blockchain security framework with 29 integrated tools
    across 7 defense layers.

    Quick Start:
      miesc audit quick contract.sol    # Fast 4-tool scan
      miesc audit full contract.sol     # Complete 7-layer audit
      miesc tools list                  # Show available tools
      miesc doctor                      # Check tool availability

    Environment Variables:
      MIESC_DEBUG=1        Enable debug mode
      MIESC_LOG_LEVEL      Set log level (DEBUG, INFO, WARNING, ERROR)
      MIESC_LOG_FORMAT     Set format (json, console)
      MIESC_LOG_FILE       Path to log file
    """
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug
    ctx.obj["quiet"] = quiet

    # Configure logging based on flags and environment
    configure_logging(debug=debug, quiet=quiet)

    # Note: Adapters are loaded lazily when needed, not at startup
    # This improves CLI startup time significantly

    if version:
        click.echo(f"MIESC version {VERSION}")
        return

    if ctx.invoked_subcommand is None:
        if not no_banner and not quiet:
            print_banner()
        click.echo(ctx.get_help())


# ============================================================================
# Scan Command (Simplified Entry Point)
# ============================================================================


@cli.command()
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file for JSON report")
@click.option("--ci", is_flag=True, help="CI mode: exit 1 if critical/high issues found")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output, only show summary")
def scan(contract, output, ci, quiet):
    """Quick vulnerability scan for a Solidity contract.

    This is a simplified command for quick scans. For more options,
    use 'miesc audit quick' or 'miesc audit full'.

    \b
    Examples:
        miesc scan MyContract.sol
        miesc scan contracts/Token.sol --ci
        miesc scan MyContract.sol -o report.json

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
            task = progress.add_task("Scanning...", total=len(QUICK_TOOLS))

            for tool in QUICK_TOOLS:
                progress.update(task, description=f"Running {tool}...")
                result = _run_tool(tool, contract, 300)
                all_results.append(result)
                progress.advance(task)
    else:
        for tool in QUICK_TOOLS:
            if not quiet:
                info(f"Running {tool}...")
            result = _run_tool(tool, contract, 300)
            all_results.append(result)

    summary = _summarize_findings(all_results)
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
        else:
            console.print("\n[green]No issues found![/green]")
    else:
        print("\n=== Scan Results ===")
        for sev, count in summary.items():
            if count > 0:
                print(f"{sev}: {count}")
        print(f"TOTAL: {total}")

    # Save output
    if output:
        data = {
            "contract": str(contract),
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "summary": summary,
            "total_findings": total,
            "results": all_results,
        }
        with open(output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")

    # CI mode exit
    if ci and critical_high > 0:
        error(f"CI check failed: {critical_high} critical/high issues")
        sys.exit(1)


# ============================================================================
# Audit Commands
# ============================================================================


@cli.group()
def audit():
    """Run security audits on smart contracts."""
    pass


@audit.command("quick")
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown"]), default="json"
)
@click.option("--ci", is_flag=True, help="CI mode: exit with error if critical/high issues found")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout per tool in seconds")
def audit_quick(contract, output, fmt, ci, timeout):
    """Quick 4-tool scan for fast feedback (slither, aderyn, solhint, mythril)."""
    print_banner()
    info(f"Quick scan of {contract}")
    info(f"Tools: {', '.join(QUICK_TOOLS)}")

    all_results = []

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("Scanning...", total=len(QUICK_TOOLS))

            for tool in QUICK_TOOLS:
                progress.update(task, description=f"Running {tool}...")
                result = _run_tool(tool, contract, timeout)
                all_results.append(result)

                if result["status"] == "success":
                    success(f"{tool}: {len(result.get('findings', []))} findings")
                elif result["status"] == "not_available":
                    warning(f"{tool}: not installed")
                else:
                    warning(f"{tool}: {result.get('error', 'error')}")

                progress.advance(task)
    else:
        for tool in QUICK_TOOLS:
            info(f"Running {tool}...")
            result = _run_tool(tool, contract, timeout)
            all_results.append(result)

    summary = _summarize_findings(all_results)
    total = sum(summary.values())

    # Display summary
    if RICH_AVAILABLE:
        table = Table(title="Quick Scan Summary", box=box.ROUNDED)
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
            table.add_row(sev, str(count), style=colors.get(sev, "white"))
        table.add_row("TOTAL", str(total), style="bold")
        console.print(table)
    else:
        print("\n=== Summary ===")
        for sev, count in summary.items():
            print(f"{sev}: {count}")
        print(f"TOTAL: {total}")

    # Save output
    if output:
        if fmt == "sarif":
            data = _to_sarif(all_results)
            with open(output, "w") as f:
                json.dump(data, f, indent=2)
        elif fmt == "markdown":
            data = _to_markdown(all_results, contract)
            with open(output, "w") as f:
                f.write(data)
        else:
            data = {"results": all_results, "summary": summary, "version": VERSION}
            with open(output, "w") as f:
                json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")

    # CI mode exit
    if ci and (summary["CRITICAL"] > 0 or summary["HIGH"] > 0):
        error(f"Found {summary['CRITICAL']} critical and {summary['HIGH']} high issues")
        sys.exit(1)


@audit.command("full")
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown"]), default="json"
)
@click.option(
    "--layers", "-l", type=str, default="1,2,3,4,5,6,7", help="Layers to run (comma-separated)"
)
@click.option("--timeout", "-t", type=int, default=600, help="Timeout per tool in seconds")
@click.option("--skip-unavailable", is_flag=True, default=True, help="Skip unavailable tools")
def audit_full(contract, output, fmt, layers, timeout, skip_unavailable):
    """Complete 7-layer security audit with all 29 tools."""
    print_banner()
    info(f"Full audit of {contract}")

    layer_list = [int(x.strip()) for x in layers.split(",") if x.strip().isdigit()]
    all_results = []

    for layer in layer_list:
        if layer in LAYERS:
            layer_info = LAYERS[layer]
            if RICH_AVAILABLE:
                console.print(
                    f"\n[bold cyan]=== Layer {layer}: {layer_info['name']} ===[/bold cyan]"
                )
                console.print(f"[dim]{layer_info['description']}[/dim]")
            else:
                print(f"\n=== Layer {layer}: {layer_info['name']} ===")

            results = _run_layer(layer, contract, timeout)
            all_results.extend(results)

    summary = _summarize_findings(all_results)
    total = sum(summary.values())

    # Display summary
    if RICH_AVAILABLE:
        console.print("\n")
        table = Table(title="Full Audit Summary", box=box.ROUNDED)
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
            table.add_row(sev, str(count), style=colors.get(sev, "white"))
        table.add_row("TOTAL", str(total), style="bold")
        console.print(table)

        # Execution summary
        successful = len([r for r in all_results if r.get("status") == "success"])
        console.print(f"\n[dim]Tools executed: {successful}/{len(all_results)}[/dim]")

    if output:
        if fmt == "sarif":
            data = _to_sarif(all_results)
        elif fmt == "markdown":
            data = _to_markdown(all_results, contract)
        else:
            data = {
                "results": all_results,
                "summary": summary,
                "version": VERSION,
                "layers": layer_list,
            }

        with open(output, "w") as f:
            if fmt == "markdown":
                f.write(data)
            else:
                json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")


@audit.command("layer")
@click.argument("layer_num", type=int)
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout per tool in seconds")
def audit_layer(layer_num, contract, output, timeout):
    """Run a specific layer's tools (1-7)."""
    print_banner()

    if layer_num not in LAYERS:
        error(f"Invalid layer: {layer_num}. Valid layers: 1-7")
        for num, layer_info in LAYERS.items():
            info(f"  Layer {num}: {layer_info['name']}")
        sys.exit(1)

    layer_info = LAYERS[layer_num]
    info(f"Layer {layer_num}: {layer_info['name']}")
    info(f"Description: {layer_info['description']}")
    info(f"Tools: {', '.join(layer_info['tools'])}")

    results = _run_layer(layer_num, contract, timeout)
    summary = _summarize_findings(results)

    if RICH_AVAILABLE:
        table = Table(title=f"Layer {layer_num} Summary", box=box.ROUNDED)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev, count in summary.items():
            table.add_row(sev, str(count))
        console.print(table)

    if output:
        with open(output, "w") as f:
            json.dump(
                {"layer": layer_num, "results": results, "summary": summary},
                f,
                indent=2,
                default=str,
            )
        success(f"Report saved to {output}")


@audit.command("profile")
@click.argument("profile_name", type=click.Choice(AVAILABLE_PROFILES + ["list"]))
@click.argument("contract", type=click.Path(exists=True), required=False)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown"]), default="json"
)
@click.option("--ci", is_flag=True, help="CI mode: exit with error if critical/high issues found")
def audit_profile(profile_name, contract, output, fmt, ci):
    """Run audit using a predefined profile (fast, balanced, thorough, security, ci, audit, defi, token)."""
    print_banner()

    # List profiles
    if profile_name == "list":
        profiles = load_profiles()
        if RICH_AVAILABLE:
            table = Table(title="Available Profiles", box=box.ROUNDED)
            table.add_column("Profile", style="bold cyan")
            table.add_column("Description")
            table.add_column("Layers")
            table.add_column("Timeout")

            for name, profile in profiles.items():
                layers_str = ", ".join(str(l) for l in profile.get("layers", []))
                table.add_row(
                    name,
                    profile.get("description", "")[:50],
                    layers_str,
                    f"{profile.get('timeout', 300)}s",
                )
            console.print(table)
        else:
            for name, profile in profiles.items():
                print(f"\n{name}: {profile.get('description', '')}")
                print(f"  Layers: {profile.get('layers', [])}")
                print(f"  Timeout: {profile.get('timeout', 300)}s")
        return

    if not contract:
        error("Contract path is required when running a profile")
        sys.exit(1)

    # Get profile configuration
    profile = get_profile(profile_name)
    if not profile:
        error(f"Profile '{profile_name}' not found")
        info(f"Available profiles: {', '.join(AVAILABLE_PROFILES)}")
        sys.exit(1)

    info(f"Running profile: {profile_name}")
    info(f"Description: {profile.get('description', 'N/A')}")

    # Extract profile settings
    layers = profile.get("layers", [1])
    timeout = profile.get("timeout", 300)
    tools_config = profile.get("tools", [])

    if tools_config == "all":
        # Use all tools from specified layers
        tools_to_run = []
        for layer in layers:
            if layer in LAYERS:
                tools_to_run.extend(LAYERS[layer]["tools"])
    elif isinstance(tools_config, list):
        tools_to_run = tools_config
    else:
        tools_to_run = QUICK_TOOLS

    info(f"Layers: {layers}")
    info(f"Tools: {', '.join(tools_to_run[:5])}{'...' if len(tools_to_run) > 5 else ''}")
    info(f"Timeout: {timeout}s per tool")

    all_results = []

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("Analyzing...", total=len(tools_to_run))

            for tool in tools_to_run:
                progress.update(task, description=f"Running {tool}...")
                result = _run_tool(tool, contract, timeout)
                all_results.append(result)

                if result["status"] == "success":
                    findings_count = len(result.get("findings", []))
                    success(f"{tool}: {findings_count} findings")
                elif result["status"] == "not_available":
                    warning(f"{tool}: not installed")
                else:
                    warning(f"{tool}: {result.get('error', 'error')[:50]}")

                progress.advance(task)
    else:
        for tool in tools_to_run:
            info(f"Running {tool}...")
            result = _run_tool(tool, contract, timeout)
            all_results.append(result)

    summary = _summarize_findings(all_results)
    total = sum(summary.values())

    # Display summary
    if RICH_AVAILABLE:
        table = Table(title=f"{profile_name.upper()} Profile Summary", box=box.ROUNDED)
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
            table.add_row(sev, str(count), style=colors.get(sev, "white"))
        table.add_row("TOTAL", str(total), style="bold")
        console.print(table)
    else:
        print(f"\n=== {profile_name.upper()} Profile Summary ===")
        for sev, count in summary.items():
            print(f"{sev}: {count}")
        print(f"TOTAL: {total}")

    # Save output
    if output:
        if fmt == "sarif":
            data = _to_sarif(all_results)
            with open(output, "w") as f:
                json.dump(data, f, indent=2)
        elif fmt == "markdown":
            data = _to_markdown(all_results, contract)
            with open(output, "w") as f:
                f.write(data)
        else:
            data = {
                "profile": profile_name,
                "results": all_results,
                "summary": summary,
                "version": VERSION,
            }
            with open(output, "w") as f:
                json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")

    # CI mode exit
    if ci and (summary["CRITICAL"] > 0 or summary["HIGH"] > 0):
        error(f"Found {summary['CRITICAL']} critical and {summary['HIGH']} high issues")
        sys.exit(1)


@audit.command("single")
@click.argument("tool", type=str)
@click.argument("contract", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout in seconds")
def audit_single(tool, contract, output, timeout):
    """Run a single security tool."""
    print_banner()

    # Validate tool exists
    available_tools = AdapterLoader.get_available_tools()
    all_tools = list(ADAPTER_MAP.keys())

    if tool not in all_tools:
        error(f"Unknown tool: {tool}")
        info(f"Available tools: {', '.join(all_tools)}")
        sys.exit(1)

    info(f"Running {tool} on {contract}")

    result = _run_tool(tool, contract, timeout)

    if result["status"] == "success":
        findings_count = len(result.get("findings", []))
        success(f"{findings_count} findings in {result.get('execution_time', 0):.1f}s")

        if RICH_AVAILABLE and result.get("findings"):
            table = Table(title=f"{tool.upper()} Findings", box=box.ROUNDED)
            table.add_column("Severity", width=10)
            table.add_column("Title", width=40)
            table.add_column("Location", width=30)

            for finding in result["findings"][:20]:
                location = finding.get("location", {})
                if isinstance(location, dict):
                    loc_str = f"{location.get('file', '')}:{location.get('line', 0)}"
                else:
                    loc_str = str(location)

                table.add_row(
                    str(finding.get("severity", "INFO")),
                    str(finding.get("title", finding.get("type", finding.get("id", ""))))[:40],
                    loc_str[:30],
                )

            if len(result["findings"]) > 20:
                table.add_row("...", f"({len(result['findings']) - 20} more)", "")

            console.print(table)
    else:
        error(f"Failed: {result.get('error', 'Unknown error')}")

    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        success(f"Report saved to {output}")


@audit.command("batch")
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "sarif", "markdown", "csv"]), default="json"
)
@click.option(
    "--profile",
    "-p",
    type=click.Choice(["quick", "fast", "balanced", "thorough"]),
    default="quick",
    help="Analysis profile",
)
@click.option("--parallel", "-j", type=int, default=4, help="Number of parallel workers")
@click.option("--recursive", "-r", is_flag=True, help="Recursively search for .sol files")
@click.option("--pattern", type=str, default="*.sol", help="File pattern to match")
@click.option(
    "--fail-on", type=str, default="", help="Fail on severity (comma-separated: critical,high)"
)
def audit_batch(path, output, fmt, profile, parallel, recursive, pattern, fail_on):
    """Batch analysis of multiple contracts.

    Analyze all .sol files in a directory with parallel execution.
    Aggregates results into a single comprehensive report.

    Examples:
      miesc audit batch ./contracts                     # Scan all contracts
      miesc audit batch ./src -r --profile balanced    # Recursive with balanced profile
      miesc audit batch . -j 8 -o report.json          # 8 parallel workers
      miesc audit batch ./contracts --fail-on critical,high  # CI mode
    """
    import concurrent.futures
    import glob as glob_module

    print_banner()

    # Find all Solidity files
    path_obj = Path(path)

    if path_obj.is_file():
        if path_obj.suffix == ".sol":
            sol_files = [str(path_obj)]
        else:
            error(f"Not a Solidity file: {path}")
            sys.exit(1)
    else:
        if recursive:
            sol_files = list(glob_module.glob(str(path_obj / "**" / pattern), recursive=True))
        else:
            sol_files = list(glob_module.glob(str(path_obj / pattern)))

    if not sol_files:
        warning(f"No {pattern} files found in {path}")
        sys.exit(0)

    info(f"Found {len(sol_files)} Solidity files")
    info(f"Profile: {profile} | Workers: {parallel}")

    # Select tools based on profile
    profile_tools = {
        "quick": QUICK_TOOLS,
        "fast": ["slither", "aderyn"],
        "balanced": ["slither", "aderyn", "solhint", "mythril"],
        "thorough": QUICK_TOOLS + ["echidna", "medusa"],
    }
    tools_to_run = profile_tools.get(profile, QUICK_TOOLS)
    info(f"Tools: {', '.join(tools_to_run)}")

    # Results storage
    all_contract_results = []
    aggregated_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    failed_contracts = []
    start_time = datetime.now()

    def analyze_contract(contract_path: str) -> Dict[str, Any]:
        """Analyze a single contract with all tools."""
        contract_results = []
        for tool in tools_to_run:
            result = _run_tool(tool, contract_path, timeout=120)
            contract_results.append(result)

        summary = _summarize_findings(contract_results)
        return {
            "contract": contract_path,
            "results": contract_results,
            "summary": summary,
            "total_findings": sum(summary.values()),
        }

    # Progress display
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
        ) as progress:
            task = progress.add_task("Analyzing contracts...", total=len(sol_files))

            with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
                future_to_contract = {executor.submit(analyze_contract, f): f for f in sol_files}

                for future in concurrent.futures.as_completed(future_to_contract):
                    contract = future_to_contract[future]
                    try:
                        result = future.result()
                        all_contract_results.append(result)

                        # Update aggregated summary
                        for sev, count in result["summary"].items():
                            aggregated_summary[sev] += count

                        # Show individual result
                        contract_name = Path(contract).name
                        findings = result["total_findings"]
                        crit = result["summary"]["CRITICAL"]
                        high = result["summary"]["HIGH"]

                        if crit > 0 or high > 0:
                            console.print(
                                f"  [red]{contract_name}[/red]: "
                                f"{crit} critical, {high} high, {findings} total"
                            )
                        elif findings > 0:
                            console.print(
                                f"  [yellow]{contract_name}[/yellow]: {findings} findings"
                            )

                    except Exception as e:
                        failed_contracts.append({"contract": contract, "error": str(e)})
                        console.print(f"  [red]{Path(contract).name}[/red]: error - {e}")

                    progress.advance(task)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
            future_to_contract = {executor.submit(analyze_contract, f): f for f in sol_files}

            completed = 0
            for future in concurrent.futures.as_completed(future_to_contract):
                contract = future_to_contract[future]
                completed += 1
                print(f"[{completed}/{len(sol_files)}] Processing {Path(contract).name}...")

                try:
                    result = future.result()
                    all_contract_results.append(result)

                    for sev, count in result["summary"].items():
                        aggregated_summary[sev] += count

                except Exception as e:
                    failed_contracts.append({"contract": contract, "error": str(e)})
                    print(f"  Error: {e}")

    elapsed = (datetime.now() - start_time).total_seconds()
    total_findings = sum(aggregated_summary.values())

    # Display summary
    if RICH_AVAILABLE:
        console.print("\n")
        table = Table(title="Batch Analysis Summary", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Contracts Analyzed", str(len(all_contract_results)))
        table.add_row("Failed", str(len(failed_contracts)))
        table.add_row("Execution Time", f"{elapsed:.1f}s")
        table.add_row("", "")

        colors = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }
        for sev, count in aggregated_summary.items():
            table.add_row(sev, str(count), style=colors.get(sev, "white"))

        table.add_row("TOTAL FINDINGS", str(total_findings), style="bold")
        console.print(table)

        # Show most vulnerable contracts
        sorted_contracts = sorted(
            all_contract_results,
            key=lambda x: (x["summary"]["CRITICAL"], x["summary"]["HIGH"], x["total_findings"]),
            reverse=True,
        )

        if sorted_contracts and total_findings > 0:
            console.print("\n[bold]Top Vulnerable Contracts:[/bold]")
            for result in sorted_contracts[:5]:
                if result["total_findings"] > 0:
                    console.print(
                        f"  {Path(result['contract']).name}: "
                        f"C:{result['summary']['CRITICAL']} H:{result['summary']['HIGH']} "
                        f"M:{result['summary']['MEDIUM']} L:{result['summary']['LOW']}"
                    )
    else:
        print("\n=== Batch Analysis Summary ===")
        print(f"Contracts: {len(all_contract_results)}")
        print(f"Failed: {len(failed_contracts)}")
        print(f"Time: {elapsed:.1f}s")
        print("\nFindings by severity:")
        for sev, count in aggregated_summary.items():
            print(f"  {sev}: {count}")
        print(f"  TOTAL: {total_findings}")

    # Build output data
    output_data = {
        "version": VERSION,
        "timestamp": datetime.now().isoformat(),
        "execution_time": elapsed,
        "profile": profile,
        "path": str(path),
        "contracts_analyzed": len(all_contract_results),
        "contracts_failed": len(failed_contracts),
        "aggregated_summary": aggregated_summary,
        "total_findings": total_findings,
        "contracts": all_contract_results,
        "failed": failed_contracts,
    }

    # Save output
    if output:
        if fmt == "sarif":
            # Flatten all results for SARIF
            all_results = []
            for contract_data in all_contract_results:
                for result in contract_data.get("results", []):
                    result["contract"] = contract_data["contract"]
                    all_results.append(result)
            data = _to_sarif(all_results)
            with open(output, "w") as f:
                json.dump(data, f, indent=2)
        elif fmt == "markdown":
            # Generate batch markdown report
            md = f"""# MIESC Batch Security Audit Report

**Path**: `{path}`
**Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**MIESC Version**: {VERSION}
**Profile**: {profile}

## Executive Summary

| Metric | Value |
|--------|-------|
| Contracts Analyzed | {len(all_contract_results)} |
| Contracts Failed | {len(failed_contracts)} |
| Execution Time | {elapsed:.1f}s |

### Findings by Severity

| Severity | Count |
|----------|-------|
| Critical | {aggregated_summary['CRITICAL']} |
| High | {aggregated_summary['HIGH']} |
| Medium | {aggregated_summary['MEDIUM']} |
| Low | {aggregated_summary['LOW']} |
| Info | {aggregated_summary['INFO']} |
| **Total** | **{total_findings}** |

## Contract Analysis

"""
            for contract_data in sorted_contracts:
                contract_name = Path(contract_data["contract"]).name
                summary = contract_data["summary"]
                md += f"""### {contract_name}

| Severity | Count |
|----------|-------|
| Critical | {summary['CRITICAL']} |
| High | {summary['HIGH']} |
| Medium | {summary['MEDIUM']} |
| Low | {summary['LOW']} |

"""
            md += f"\n---\n\n*Generated by MIESC v{VERSION}*\n"
            with open(output, "w") as f:
                f.write(md)
        elif fmt == "csv":
            import csv

            with open(output, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Contract", "Tool", "Severity", "Title", "Description", "Line"])
                for contract_data in all_contract_results:
                    for result in contract_data.get("results", []):
                        for finding in result.get("findings", []):
                            location = finding.get("location", {})
                            if isinstance(location, dict):
                                line = location.get("line", 0)
                            else:
                                line = 0
                            writer.writerow(
                                [
                                    Path(contract_data["contract"]).name,
                                    result.get("tool", ""),
                                    finding.get("severity", ""),
                                    finding.get("title", finding.get("type", ""))[:50],
                                    finding.get("description", finding.get("message", ""))[:100],
                                    line,
                                ]
                            )
        else:  # json
            with open(output, "w") as f:
                json.dump(output_data, f, indent=2, default=str)

        success(f"Report saved to {output}")

    # Fail-on check for CI
    if fail_on:
        severities = [s.strip().upper() for s in fail_on.split(",")]
        for sev in severities:
            if sev in aggregated_summary and aggregated_summary[sev] > 0:
                error(f"Found {aggregated_summary[sev]} {sev} issues (fail-on: {fail_on})")
                sys.exit(1)

    success(
        f"Batch analysis complete: {len(all_contract_results)} contracts, {total_findings} findings"
    )


# ============================================================================
# Tools Command Group
# ============================================================================


@cli.group()
def tools():
    """Manage and explore security tools."""
    pass


@tools.command("list")
@click.option("--layer", "-l", type=int, help="Filter by layer (1-7)")
@click.option("--available-only", "-a", is_flag=True, help="Show only installed tools")
def tools_list(layer, available_only):
    """List all 29 security tools."""
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
            print(f"\n=== Layer {num}: {layer_info['name']} ===")
            for tool in layer_info["tools"]:
                status_info = AdapterLoader.check_tool_status(tool)
                status = "OK" if status_info.get("available") else "MISSING"
                if available_only and status != "OK":
                    continue
                print(f"  [{status}] {tool}")


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
            print(f"\n=== {tool} ===")
            print(f"Version: {metadata.version}")
            print(f"Category: {metadata.category}")
            print(f"Status: {status.value}")
            print(f"Installation: {metadata.installation_cmd}")

    except Exception as e:
        error(f"Could not get info for {tool}: {e}")


# ============================================================================
# Server Commands
# ============================================================================


@cli.group()
def server():
    """Start MIESC API servers."""
    pass


@server.command("rest")
@click.option("--port", "-p", type=int, default=5001, help="Port number")
@click.option("--host", "-h", type=str, default="0.0.0.0", help="Host address")
@click.option("--debug", is_flag=True, help="Enable debug mode")
def server_rest(port, host, debug):
    """Start the Django REST API server."""
    print_banner()
    info(f"Starting Django REST API on http://{host}:{port}")
    info("Endpoints:")
    info("  - POST /api/v1/analyze/quick/  - Quick 4-tool scan")
    info("  - POST /api/v1/analyze/full/   - Complete 7-layer audit")
    info("  - GET  /api/v1/tools/          - List available tools")
    info("  - GET  /api/v1/layers/         - Layer information")
    info("  - GET  /api/v1/health/         - System health check")

    try:
        from miesc.api.rest import run_server

        run_server(host, port, debug)
    except ImportError as e:
        error(f"Django REST Framework not available: {e}")
        info("Install with: pip install django djangorestframework django-cors-headers")
        sys.exit(1)
    except Exception as e:
        error(f"Server error: {e}")
        sys.exit(1)


@server.command("mcp")
@click.option("--port", "-p", type=int, default=8765, help="WebSocket port number")
@click.option("--host", "-h", type=str, default="localhost", help="Host to bind to")
def server_mcp(port, host):
    """Start the MCP WebSocket server for AI agent integration.

    The MCP (Model Context Protocol) server enables real-time communication
    with AI agents like Claude Desktop for collaborative security analysis.

    Example:
        miesc server mcp
        miesc server mcp --port 9000 --host 0.0.0.0
    """
    print_banner()
    info(f"Starting MCP WebSocket server on ws://{host}:{port}")
    info("Compatible with Claude Desktop and other MCP clients")

    try:
        import asyncio

        from src.mcp.websocket_server import run_server

        info("Press Ctrl+C to stop the server")
        asyncio.run(run_server(host=host, port=port))
    except ImportError as e:
        error(f"MCP dependencies not installed: {e}")
        info("Install with: pip install websockets")
        sys.exit(1)
    except KeyboardInterrupt:
        info("MCP server stopped")
    except Exception as e:
        error(f"MCP server error: {e}")
        sys.exit(1)


# ============================================================================
# Config Commands
# ============================================================================


@cli.group()
def config():
    """Manage MIESC configuration."""
    pass


@config.command("show")
def config_show():
    """Display current configuration."""
    print_banner()

    cfg = load_config()
    if not cfg:
        warning("No configuration found at config/miesc.yaml")
        return

    if RICH_AVAILABLE:
        tree = Tree("[bold cyan]MIESC Configuration[/bold cyan]")

        def add_tree(parent, data, depth=0):
            if depth > 3:
                return
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, (dict, list)):
                        branch = parent.add(f"[yellow]{key}[/yellow]")
                        add_tree(branch, value, depth + 1)
                    else:
                        parent.add(f"[yellow]{key}[/yellow]: {value}")
            elif isinstance(data, list):
                for i, item in enumerate(data[:10]):
                    if isinstance(item, dict):
                        branch = parent.add(f"[dim][{i}][/dim]")
                        add_tree(branch, item, depth + 1)
                    else:
                        parent.add(f"[dim][{i}][/dim] {item}")

        add_tree(tree, cfg)
        console.print(tree)
    else:
        print(json.dumps(cfg, indent=2))


@config.command("validate")
def config_validate():
    """Validate configuration file."""
    print_banner()

    config_path = ROOT_DIR / "config" / "miesc.yaml"
    if not config_path.exists():
        error(f"Config file not found: {config_path}")
        sys.exit(1)

    try:
        cfg = load_config()

        required_sections = ["layers", "adapters"]
        for section in required_sections:
            if section in cfg:
                success(f"Section '{section}' found")
            else:
                warning(f"Section '{section}' missing (optional)")

        success("Configuration is valid YAML")

    except Exception as e:
        error(f"Config error: {e}")
        sys.exit(1)


# ============================================================================
# Detect Command (Framework Auto-Detection)
# ============================================================================


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--json", "-j", "as_json", is_flag=True, help="Output as JSON")
def detect(path, as_json):
    """Auto-detect Foundry/Hardhat/Truffle framework.

    Detects the Solidity development framework in use and extracts
    configuration like solc version, remappings, and paths.

    Supports:
      - Foundry (foundry.toml)
      - Hardhat (hardhat.config.js/ts)
      - Truffle (truffle-config.js)
      - Brownie (brownie-config.yaml)

    Examples:
      miesc detect                    # Detect in current directory
      miesc detect ./my-project       # Detect in specific path
      miesc detect . --json           # Output as JSON
    """
    if not as_json:
        print_banner()

    try:
        from src.core.framework_detector import Framework, detect_framework
    except ImportError:
        error("Framework detector module not available")
        sys.exit(1)

    config = detect_framework(path)

    if as_json:
        import json

        click.echo(json.dumps(config.to_dict(), indent=2))
        return

    if config.framework == Framework.UNKNOWN:
        warning(f"No supported framework detected in {path}")
        info("Supported frameworks: Foundry, Hardhat, Truffle, Brownie")
        info("\nLooking for:")
        info("  - foundry.toml        (Foundry)")
        info("  - hardhat.config.js   (Hardhat)")
        info("  - truffle-config.js   (Truffle)")
        info("  - brownie-config.yaml (Brownie)")
        return

    if RICH_AVAILABLE:
        from rich.panel import Panel

        # Build panel content
        content = f"""[bold cyan]Framework:[/bold cyan] {config.framework.value.upper()}
[bold cyan]Root Path:[/bold cyan] {config.root_path}
[bold cyan]Config File:[/bold cyan] {config.config_file}

[bold]Compiler Settings:[/bold]
  Solc Version: {config.solc_version or 'auto'}
  EVM Version: {config.evm_version or 'default'}
  Optimizer: {'enabled' if config.optimizer_enabled else 'disabled'}
  Optimizer Runs: {config.optimizer_runs}

[bold]Project Paths:[/bold]
  Source: {config.src_path or 'N/A'}
  Test: {config.test_path or 'N/A'}
  Output: {config.out_path or 'N/A'}
"""
        if config.remappings:
            content += f"""
[bold]Remappings:[/bold] ({len(config.remappings)} entries)
"""
            for remap in config.remappings[:5]:
                content += f"  {remap}\n"
            if len(config.remappings) > 5:
                content += f"  ... and {len(config.remappings) - 5} more\n"

        if config.lib_paths:
            content += """
[bold]Library Paths:[/bold]
"""
            for lib in config.lib_paths[:3]:
                content += f"  {lib}\n"

        console.print(Panel(content, title="Framework Detection", border_style="green"))
    else:
        print("\n=== Framework Detection ===")
        print(f"Framework: {config.framework.value.upper()}")
        print(f"Root Path: {config.root_path}")
        print(f"Config File: {config.config_file}")
        print("\nCompiler Settings:")
        print(f"  Solc Version: {config.solc_version or 'auto'}")
        print(f"  EVM Version: {config.evm_version or 'default'}")
        print(f"  Optimizer: {'enabled' if config.optimizer_enabled else 'disabled'}")
        print("\nProject Paths:")
        print(f"  Source: {config.src_path}")
        print(f"  Test: {config.test_path}")
        print(f"  Output: {config.out_path}")

        if config.remappings:
            print(f"\nRemappings: ({len(config.remappings)} entries)")
            for remap in config.remappings[:5]:
                print(f"  {remap}")

    success(f"Detected {config.framework.value.upper()} project")


# ============================================================================
# Doctor Command
# ============================================================================


@cli.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed information")
def doctor(verbose):
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
                import subprocess

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

        # Security tools table
        tools_table = Table(title="Security Tools (29 Total)", box=box.ROUNDED)
        tools_table.add_column("Layer", style="bold", width=8)
        tools_table.add_column("Tool", width=25)
        tools_table.add_column("Status", width=15)

        total_available = 0
        total_tools = 0

        for layer_num, layer_info in LAYERS.items():
            for tool in layer_info["tools"]:
                total_tools += 1
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

    else:
        print("=== Core Dependencies ===")
        for dep, cmd in dependencies.items():
            try:
                import subprocess

                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
                print(f"[OK] {dep}")
            except Exception:
                print(f"[MISSING] {dep}")

        print("\n=== Security Tools ===")
        total_available = 0
        total_tools = 0

        for layer_num, layer_info in LAYERS.items():
            print(f"\nLayer {layer_num}: {layer_info['name']}")
            for tool in layer_info["tools"]:
                total_tools += 1
                status_info = AdapterLoader.check_tool_status(tool)
                if status_info.get("available"):
                    print(f"  [OK] {tool}")
                    total_available += 1
                else:
                    print(f"  [MISSING] {tool}")

        print(f"\n{total_available}/{total_tools} tools available")


# ============================================================================
# Export Command
# ============================================================================


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["sarif", "markdown", "csv", "html"]), required=True
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def export(input_file, fmt, output):
    """Export JSON results to different formats."""
    print_banner()

    with open(input_file) as f:
        data = json.load(f)

    results = data.get("results", [data])
    contract = data.get("contract", input_file)

    if fmt == "sarif":
        output_data = _to_sarif(results)
        output_str = json.dumps(output_data, indent=2)
        ext = ".sarif.json"
    elif fmt == "markdown":
        output_str = _to_markdown(results, contract)
        ext = ".md"
    elif fmt == "csv":
        import csv
        import io

        output_io = io.StringIO()
        writer = csv.writer(output_io)
        writer.writerow(["Tool", "Severity", "Title", "Description", "Location", "Line"])
        for result in results:
            for finding in result.get("findings", []):
                location = finding.get("location", {})
                if isinstance(location, dict):
                    loc_file = location.get("file", "")
                    loc_line = location.get("line", 0)
                else:
                    loc_file = str(location)
                    loc_line = 0

                writer.writerow(
                    [
                        result.get("tool", ""),
                        finding.get("severity", ""),
                        finding.get("title", finding.get("type", "")),
                        finding.get("description", finding.get("message", ""))[:100],
                        loc_file,
                        loc_line,
                    ]
                )
        output_str = output_io.getvalue()
        ext = ".csv"
    elif fmt == "html":
        output_str = f"""<!DOCTYPE html>
<html>
<head>
    <title>MIESC Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        h1 {{ color: #1a73e8; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .finding {{ border-left: 4px solid #ccc; padding: 10px 20px; margin: 10px 0; }}
        .finding.critical {{ border-color: #dc3545; }}
        .finding.high {{ border-color: #fd7e14; }}
        .finding.medium {{ border-color: #ffc107; }}
        .finding.low {{ border-color: #28a745; }}
    </style>
</head>
<body>
    <h1>MIESC Security Report</h1>
    <div class="summary">
        <strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
        <strong>Contract:</strong> {contract}<br>
        <strong>MIESC Version:</strong> {VERSION}
    </div>
"""
        summary = _summarize_findings(results)
        output_str += f"""
    <h2>Summary</h2>
    <ul>
        <li>Critical: {summary['CRITICAL']}</li>
        <li>High: {summary['HIGH']}</li>
        <li>Medium: {summary['MEDIUM']}</li>
        <li>Low: {summary['LOW']}</li>
        <li>Info: {summary['INFO']}</li>
    </ul>
    <h2>Findings</h2>
"""
        for result in results:
            for finding in result.get("findings", []):
                severity = str(finding.get("severity", "info")).lower()
                output_str += f"""
    <div class="finding {severity}">
        <strong>[{finding.get("severity", "INFO")}] {finding.get("title", finding.get("type", "Finding"))}</strong>
        <p>{finding.get("description", finding.get("message", ""))}</p>
    </div>
"""
        output_str += "</body></html>"
        ext = ".html"
    else:
        error(f"Format {fmt} not supported")
        return

    # Determine output path
    if not output:
        output = str(Path(input_file).with_suffix(ext))

    with open(output, "w") as f:
        f.write(output_str)

    success(f"Exported to {output}")


# ============================================================================
# Watch Command
# ============================================================================


@cli.command()
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

    import threading
    import time
    from collections import defaultdict

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
                print(f"\n[{timestamp}] Scanning {file_name}...")

            all_findings = []
            start_time = time.time()

            for tool in tools_to_run:
                result = _run_tool(tool, file_path, timeout=60)

                if result["status"] == "success":
                    findings = result.get("findings", [])
                    all_findings.extend(findings)

                    if findings:
                        if RICH_AVAILABLE:
                            console.print(f"  [green]{tool}[/green]: {len(findings)} findings")
                        else:
                            print(f"  {tool}: {len(findings)} findings")
                elif result["status"] == "not_available":
                    pass  # Silently skip unavailable tools
                else:
                    if RICH_AVAILABLE:
                        console.print(f"  [yellow]{tool}[/yellow]: error")

            elapsed = time.time() - start_time
            summary = _summarize_findings([{"findings": all_findings}])

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
                print(
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


# ============================================================================
# Detectors Command Group
# ============================================================================


@cli.group()
def detectors():
    """Manage and run custom vulnerability detectors."""
    pass


@detectors.command("list")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed information")
def detectors_list(verbose):
    """List all registered custom detectors."""
    print_banner()

    try:
        # Also load example detectors and local plugins
        from miesc.detectors import (
            examples,  # noqa: F401
            get_all_detectors,
            list_detectors,
            load_local_plugins,
        )
        # Load local plugins from ~/.miesc/plugins/
        load_local_plugins()
    except ImportError as e:
        error(f"Detector API not available: {e}")
        return

    detector_list = list_detectors()

    if not detector_list:
        warning("No custom detectors registered")
        info("Create detectors using miesc.detectors.BaseDetector")
        return

    if RICH_AVAILABLE:
        table = Table(title="Custom Detectors", box=box.ROUNDED)
        table.add_column("Name", style="bold cyan")
        table.add_column("Category", width=15)
        table.add_column("Severity", width=10)
        if verbose:
            table.add_column("Description", width=40)
            table.add_column("Author", width=20)

        for detector in sorted(detector_list, key=lambda x: x["name"]):
            row = [
                detector["name"],
                detector.get("category", "general"),
                detector.get("severity", "Medium"),
            ]
            if verbose:
                row.append(detector.get("description", "")[:40])
                row.append(detector.get("author", "")[:20])
            table.add_row(*row)

        console.print(table)
    else:
        print(f"\n=== Custom Detectors ({len(detector_list)}) ===")
        for detector in sorted(detector_list, key=lambda x: x["name"]):
            print(f"  - {detector['name']}: {detector.get('description', '')[:50]}")

    success(f"{len(detector_list)} detectors registered")


@detectors.command("run")
@click.argument("contract", type=click.Path(exists=True))
@click.option("--detector", "-d", multiple=True, help="Specific detectors to run (can repeat)")
@click.option("--output", "-o", type=click.Path(), help="Output file for JSON report")
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Minimum severity to report",
)
def detectors_run(contract, detector, output, severity):
    """Run custom detectors on a contract.

    Run all registered detectors or specific ones on a Solidity contract.

    Examples:
      miesc detectors run contract.sol
      miesc detectors run contract.sol -d flash-loan -d mev-detector
      miesc detectors run contract.sol --severity high -o report.json
    """
    print_banner()

    try:
        # Load example detectors and local plugins
        from miesc.detectors import (
            Severity,
            examples,  # noqa: F401
            get_all_detectors,
            load_local_plugins,
            run_all_detectors,
            run_detector,
        )
        # Load local plugins from ~/.miesc/plugins/
        load_local_plugins()
    except ImportError as e:
        error(f"Detector API not available: {e}")
        sys.exit(1)

    all_detectors = get_all_detectors()

    if not all_detectors:
        warning("No custom detectors registered")
        return

    # Read contract
    contract_path = Path(contract)
    with open(contract_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    info(f"Analyzing {contract_path.name}")

    # Filter detectors if specific ones requested
    detector_names = list(all_detectors.keys())
    if detector:
        detectors_to_run = [d for d in detector if d in detector_names]
        if not detectors_to_run:
            error(f"None of the specified detectors found: {', '.join(detector)}")
            info(f"Available: {', '.join(detector_names)}")
            sys.exit(1)
        info(f"Running: {', '.join(detectors_to_run)}")
    else:
        detectors_to_run = detector_names
        info(f"Running all {len(detectors_to_run)} detectors")

    # Run detectors
    all_findings = []
    start_time = datetime.now()

    for det_name in detectors_to_run:
        try:
            findings = run_detector(det_name, source_code, str(contract_path))
            all_findings.extend(findings)
            if findings:
                success(f"{det_name}: {len(findings)} findings")
            else:
                info(f"{det_name}: clean")
        except Exception as e:
            warning(f"{det_name}: error - {e}")

    elapsed = (datetime.now() - start_time).total_seconds()

    # Filter by severity if specified
    if severity:
        severity_order = ["critical", "high", "medium", "low", "info"]
        min_idx = severity_order.index(severity)
        all_findings = [
            f for f in all_findings if severity_order.index(f.severity.value) <= min_idx
        ]

    # Display results
    if RICH_AVAILABLE and all_findings:
        console.print("\n")
        table = Table(title="Custom Detector Findings", box=box.ROUNDED)
        table.add_column("Severity", width=10)
        table.add_column("Detector", width=15)
        table.add_column("Title", width=35)
        table.add_column("Line", width=6)

        colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim",
        }

        for finding in all_findings[:25]:
            line = str(finding.location.line) if finding.location else "-"
            table.add_row(
                finding.severity.value,
                finding.detector,
                finding.title[:35],
                line,
                style=colors.get(finding.severity.value.lower(), "white"),
            )

        if len(all_findings) > 25:
            table.add_row("...", f"({len(all_findings) - 25} more)", "", "")

        console.print(table)

    # Summary
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.severity.value.lower()
        if sev in summary:
            summary[sev] += 1

    if RICH_AVAILABLE:
        console.print(
            f"\n[bold]Summary:[/bold] "
            f"[red]{summary['critical']}[/red] critical, "
            f"[red]{summary['high']}[/red] high, "
            f"[yellow]{summary['medium']}[/yellow] medium, "
            f"[cyan]{summary['low']}[/cyan] low "
            f"[dim]({elapsed:.1f}s)[/dim]"
        )
    else:
        print(
            f"\nSummary: {summary['critical']} critical, {summary['high']} high, "
            f"{summary['medium']} medium, {summary['low']} low ({elapsed:.1f}s)"
        )

    # Save output
    if output:
        data = {
            "contract": str(contract),
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "detectors_run": detectors_to_run,
            "summary": summary,
            "total_findings": len(all_findings),
            "findings": [f.to_dict() for f in all_findings],
        }
        with open(output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        success(f"Report saved to {output}")


@detectors.command("info")
@click.argument("detector_name", type=str)
def detectors_info(detector_name):
    """Show detailed information about a detector."""
    print_banner()

    try:
        from src.detectors.detector_api import get_registry
    except ImportError:
        error("Detector API not available")
        return

    registry = get_registry()
    detector = registry.get(detector_name)

    if not detector:
        error(f"Detector not found: {detector_name}")
        info(f"Available: {', '.join(registry.list_detectors())}")
        return

    if RICH_AVAILABLE:
        panel_content = f"""[bold cyan]Name:[/bold cyan] {detector.name}
[bold cyan]Description:[/bold cyan] {detector.description}
[bold cyan]Version:[/bold cyan] {detector.version}
[bold cyan]Author:[/bold cyan] {detector.author or 'N/A'}
[bold cyan]Category:[/bold cyan] {detector.category.value}
[bold cyan]Default Severity:[/bold cyan] {detector.default_severity.value}
[bold cyan]Enabled:[/bold cyan] {'Yes' if detector.enabled else 'No'}

[bold]Target Patterns:[/bold]
{', '.join(detector.target_patterns) if detector.target_patterns else 'All contracts'}
"""
        console.print(Panel(panel_content, title=f"Detector: {detector_name}", border_style="cyan"))
    else:
        print(f"\n=== {detector_name} ===")
        print(f"Description: {detector.description}")
        print(f"Category: {detector.category.value}")
        print(f"Severity: {detector.default_severity.value}")


# ============================================================================
# Plugins Command Group
# ============================================================================


@cli.group()
def plugins():
    """Manage MIESC detector plugins."""
    pass


@plugins.command("list")
@click.option("--all", "-a", "show_all", is_flag=True, help="Show disabled plugins too")
def plugins_list(show_all):
    """List installed plugins."""
    print_banner()

    try:
        from miesc.plugins import PluginManager, CompatibilityStatus
    except ImportError:
        error("Plugin system not available")
        return

    manager = PluginManager()
    installed_plugins = manager.list_installed(include_disabled=show_all)

    if not installed_plugins:
        info("No plugins installed")
        info("Install plugins with: miesc plugins install <package>")
        return

    # Separate local and PyPI plugins for display
    local_plugins = [p for p in installed_plugins if p.local]
    pypi_plugins = [p for p in installed_plugins if not p.local]

    # Count compatibility issues
    incompatible_count = sum(
        1
        for p in installed_plugins
        if p.compatibility and p.compatibility.status == CompatibilityStatus.INCOMPATIBLE
    )

    if RICH_AVAILABLE:
        table = Table(title="Installed Plugins")
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Type")
        table.add_column("Status")
        table.add_column("Compat")
        table.add_column("Detectors", justify="right")
        table.add_column("Description")

        for plugin in installed_plugins:
            status = "[green]enabled[/green]" if plugin.enabled else "[red]disabled[/red]"
            plugin_type = "[yellow]local[/yellow]" if plugin.local else "PyPI"

            # Compatibility status
            if plugin.compatibility:
                if plugin.compatibility.status == CompatibilityStatus.COMPATIBLE:
                    compat_str = "[green]ok[/green]"
                elif plugin.compatibility.status == CompatibilityStatus.INCOMPATIBLE:
                    compat_str = "[red]incompatible[/red]"
                elif plugin.compatibility.status == CompatibilityStatus.WARNING:
                    compat_str = "[yellow]warning[/yellow]"
                else:
                    compat_str = "[dim]unknown[/dim]"
            else:
                compat_str = "[dim]-[/dim]"

            table.add_row(
                plugin.package,
                plugin.version,
                plugin_type,
                status,
                compat_str,
                str(plugin.detector_count),
                plugin.description[:30] + "..." if len(plugin.description) > 30 else plugin.description,
            )
        console.print(table)

        if local_plugins:
            info(f"Local plugins directory: {manager.LOCAL_PLUGINS_DIR}")

        if incompatible_count > 0:
            warning(f"{incompatible_count} plugin(s) may be incompatible with MIESC {manager._miesc_version}")
            info("Run 'miesc plugins info <name>' for compatibility details")
    else:
        print("\nInstalled Plugins:")
        for plugin in installed_plugins:
            status = "enabled" if plugin.enabled else "disabled"
            local_marker = " (local)" if plugin.local else ""
            compat_marker = ""
            if plugin.compatibility and plugin.compatibility.status == CompatibilityStatus.INCOMPATIBLE:
                compat_marker = " [INCOMPATIBLE]"
            elif plugin.compatibility and plugin.compatibility.status == CompatibilityStatus.WARNING:
                compat_marker = " [warning]"
            print(f"  {plugin.package} v{plugin.version}{local_marker}{compat_marker} - {status} ({plugin.detector_count} detectors)")

        if local_plugins:
            print(f"\nLocal plugins directory: {manager.LOCAL_PLUGINS_DIR}")

        if incompatible_count > 0:
            print(f"\nWarning: {incompatible_count} plugin(s) may be incompatible with MIESC {manager._miesc_version}")

    success(f"{len(installed_plugins)} plugins installed ({len(local_plugins)} local, {len(pypi_plugins)} PyPI)")


@plugins.command("install")
@click.argument("package")
@click.option("--upgrade", "-U", is_flag=True, help="Upgrade if already installed")
@click.option("--force", "-f", is_flag=True, help="Force install even if incompatible")
@click.option("--no-check", is_flag=True, help="Skip compatibility check")
def plugins_install(package, upgrade, force, no_check):
    """Install a plugin from PyPI.

    The package name can be with or without the 'miesc-' prefix.
    Compatibility with current MIESC version is checked before installation.

    Examples:

      miesc plugins install miesc-defi-detectors

      miesc plugins install defi-detectors

      miesc plugins install my-plugin -U

      miesc plugins install old-plugin --force
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager, CompatibilityStatus
    except ImportError:
        error("Plugin system not available")
        raise SystemExit(1)

    manager = PluginManager()

    # Check compatibility first if not skipped
    if not no_check and not force:
        info(f"Checking compatibility for {package}...")
        compat, version = manager.check_pypi_compatibility(package)

        if compat.status == CompatibilityStatus.INCOMPATIBLE:
            error(f"Plugin {package} is incompatible: {compat.message}")
            info("Use --force to install anyway, or --no-check to skip validation")
            raise SystemExit(1)
        elif compat.status == CompatibilityStatus.WARNING:
            warning(f"Compatibility warning: {compat.message}")
        elif compat.status == CompatibilityStatus.UNKNOWN and version is None:
            warning(f"Package {package} not found on PyPI")

    info(f"Installing {package}...")

    ok, message = manager.install(
        package,
        upgrade=upgrade,
        check_compatibility=False,  # Already checked above
        force=force,
    )

    if ok:
        success(message)
    else:
        error(message)
        raise SystemExit(1)


@plugins.command("uninstall")
@click.argument("package")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def plugins_uninstall(package, yes):
    """Uninstall a plugin.

    Examples:

      miesc plugins uninstall miesc-defi-detectors

      miesc plugins uninstall defi-detectors -y
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError:
        error("Plugin system not available")
        raise SystemExit(1)

    if not yes:
        if not click.confirm(f"Uninstall {package}?"):
            info("Cancelled")
            return

    manager = PluginManager()

    info(f"Uninstalling {package}...")

    ok, message = manager.uninstall(package)

    if ok:
        success(message)
    else:
        error(message)
        raise SystemExit(1)


@plugins.command("enable")
@click.argument("plugin_name")
def plugins_enable(plugin_name):
    """Enable a disabled plugin.

    Examples:

      miesc plugins enable miesc-defi-detectors
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError:
        error("Plugin system not available")
        raise SystemExit(1)

    manager = PluginManager()
    ok, message = manager.enable(plugin_name)

    if ok:
        success(message)
    else:
        error(message)
        raise SystemExit(1)


@plugins.command("disable")
@click.argument("plugin_name")
def plugins_disable(plugin_name):
    """Disable a plugin without uninstalling.

    Examples:

      miesc plugins disable miesc-defi-detectors
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError:
        error("Plugin system not available")
        raise SystemExit(1)

    manager = PluginManager()
    ok, message = manager.disable(plugin_name)

    if ok:
        success(message)
    else:
        error(message)
        raise SystemExit(1)


@plugins.command("info")
@click.argument("plugin_name")
def plugins_info(plugin_name):
    """Show detailed information about a plugin.

    Examples:

      miesc plugins info miesc-defi-detectors
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager, CompatibilityStatus
    except ImportError:
        error("Plugin system not available")
        raise SystemExit(1)

    manager = PluginManager()
    plugin = manager.get_plugin_info(plugin_name)

    if not plugin:
        error(f"Plugin not found: {plugin_name}")
        return

    # Compatibility display
    if plugin.compatibility:
        compat = plugin.compatibility
        if compat.status == CompatibilityStatus.COMPATIBLE:
            compat_str = "[green]Compatible[/green]"
            compat_plain = "Compatible"
        elif compat.status == CompatibilityStatus.INCOMPATIBLE:
            compat_str = f"[red]Incompatible[/red] - {compat.message}"
            compat_plain = f"Incompatible - {compat.message}"
        elif compat.status == CompatibilityStatus.WARNING:
            compat_str = f"[yellow]Warning[/yellow] - {compat.message}"
            compat_plain = f"Warning - {compat.message}"
        else:
            compat_str = "[dim]Unknown[/dim]"
            compat_plain = "Unknown"
    else:
        compat_str = "[dim]Not checked[/dim]"
        compat_plain = "Not checked"

    # Version requirements
    requires_miesc = plugin.requires_miesc or "any"
    requires_python = plugin.requires_python or "any"

    if RICH_AVAILABLE:
        panel_content = f"""[bold cyan]Package:[/bold cyan] {plugin.package}
[bold cyan]Version:[/bold cyan] {plugin.version}
[bold cyan]Status:[/bold cyan] {'[green]Enabled[/green]' if plugin.enabled else '[red]Disabled[/red]'}
[bold cyan]Author:[/bold cyan] {plugin.author or 'N/A'}
[bold cyan]Description:[/bold cyan] {plugin.description or 'N/A'}
[bold cyan]Detectors:[/bold cyan] {plugin.detector_count}
[bold cyan]Local:[/bold cyan] {'Yes' if plugin.local else 'No'}

[bold]Version Requirements:[/bold]
  MIESC: {requires_miesc}
  Python: {requires_python}

[bold]Compatibility:[/bold] {compat_str}
[dim](Current MIESC: {manager._miesc_version})[/dim]

[bold]Registered Detectors:[/bold]
{chr(10).join('  - ' + d for d in plugin.detectors) if plugin.detectors else '  (none)'}
"""
        console.print(Panel(panel_content, title=f"Plugin: {plugin.name}", border_style="cyan"))
    else:
        print(f"\n=== {plugin.name} ===")
        print(f"Package: {plugin.package}")
        print(f"Version: {plugin.version}")
        print(f"Status: {'Enabled' if plugin.enabled else 'Disabled'}")
        print(f"Author: {plugin.author or 'N/A'}")
        print(f"Detectors: {plugin.detector_count}")
        print(f"\nVersion Requirements:")
        print(f"  MIESC: {requires_miesc}")
        print(f"  Python: {requires_python}")
        print(f"\nCompatibility: {compat_plain}")
        print(f"(Current MIESC: {manager._miesc_version})")
        if plugin.detectors:
            print("\nRegistered Detectors:")
            for d in plugin.detectors:
                print(f"  - {d}")


@plugins.command("create")
@click.argument("name")
@click.option("--output", "-o", type=click.Path(), default=".", help="Output directory")
@click.option("--description", "-d", type=str, default="", help="Plugin description")
@click.option("--author", "-a", type=str, default="", help="Author name")
def plugins_create(name, output, description, author):
    """Create a new plugin project scaffold.

    Creates a complete plugin project structure with:
    - pyproject.toml with entry points
    - Detector class template
    - Test file template
    - README.md

    Examples:

      miesc plugins create my-detector

      miesc plugins create flash-loan-detector -o ./plugins -d "Flash loan detector"
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError:
        error("Plugin system not available")
        raise SystemExit(1)

    from pathlib import Path

    manager = PluginManager()

    info(f"Creating plugin scaffold for '{name}'...")

    try:
        plugin_path = manager.create_plugin_scaffold(
            name=name,
            output_dir=Path(output),
            description=description,
            author=author,
        )
        success(f"Created plugin at: {plugin_path}")
        info("")
        info("Next steps:")
        info(f"  cd {plugin_path}")
        info("  pip install -e .")
        info("  # Edit the detector in detectors.py")
        info("  miesc plugins list  # Verify plugin is registered")
    except Exception as e:
        error(f"Failed to create plugin: {e}")
        raise SystemExit(1)


@plugins.command("search")
@click.argument("query")
@click.option("--timeout", "-t", type=int, default=10, help="Request timeout in seconds")
def plugins_search(query, timeout):
    """Search PyPI for MIESC detector plugins.

    Searches the PyPI registry for packages matching the query.
    Results include package name, version, and description.

    Examples:

      miesc plugins search defi

      miesc plugins search flash-loan

      miesc plugins search reentrancy
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError:
        error("Plugin system not available")
        raise SystemExit(1)

    manager = PluginManager()

    info(f"Searching PyPI for MIESC plugins matching '{query}'...")

    results = manager.search_pypi(query, timeout=timeout)

    if not results:
        info(f"No plugins found matching '{query}'")
        info("")
        info("Tips:")
        info("  - Try a different search term")
        info("  - Check https://pypi.org/search/?q=miesc for all MIESC packages")
        info("  - Create your own plugin: miesc plugins create <name>")
        return

    if RICH_AVAILABLE:
        table = Table(title=f"Found {len(results)} plugin(s)")
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Description")

        for pkg in results:
            desc = pkg["description"]
            if len(desc) > 50:
                desc = desc[:47] + "..."
            table.add_row(pkg["name"], pkg["version"], desc)

        console.print(table)
        console.print("")
        info("Install with: miesc plugins install <package-name>")
    else:
        print(f"\nFound {len(results)} plugin(s) matching '{query}':\n")
        for pkg in results:
            desc = pkg["description"]
            if len(desc) > 50:
                desc = desc[:47] + "..."
            print(f"  {pkg['name']} (v{pkg['version']})")
            if desc:
                print(f"    {desc}")
            print()
        print("Install with: miesc plugins install <package-name>")


@plugins.command("path")
@click.option("--create", "-c", is_flag=True, help="Create the directory if it doesn't exist")
def plugins_path(create):
    """Show the local plugins directory path.

    Local plugins can be placed in this directory for automatic discovery
    without requiring PyPI installation.

    Examples:

      miesc plugins path

      miesc plugins path --create
    """
    print_banner()

    try:
        from miesc.plugins import PluginManager
    except ImportError:
        error("Plugin system not available")
        raise SystemExit(1)

    manager = PluginManager()
    plugins_dir = manager.LOCAL_PLUGINS_DIR

    if create:
        plugins_dir = manager.ensure_local_plugins_dir()
        success(f"Local plugins directory created: {plugins_dir}")
    else:
        info(f"Local plugins directory: {plugins_dir}")
        if plugins_dir.exists():
            success("Directory exists")
            # Count plugins
            plugin_count = sum(1 for d in plugins_dir.iterdir() if d.is_dir() and not d.name.startswith('.'))
            if plugin_count:
                info(f"Contains {plugin_count} plugin(s)")
        else:
            info("Directory does not exist yet")
            info("Use --create to create it, or it will be created automatically")

    info("")
    info("To add a local plugin:")
    info(f"  1. Copy your plugin to: {plugins_dir}/<plugin-name>/")
    info("  2. Ensure it has a detectors.py or <package>/detectors.py file")
    info("  3. Run 'miesc plugins list' to verify it's detected")


# ============================================================================
# Report Command
# ============================================================================


@cli.command()
@click.argument("results_file", type=click.Path(exists=True))
@click.option(
    "--template",
    "-t",
    type=click.Choice(["professional", "executive", "technical", "github-pr", "simple"]),
    default="simple",
    help="Report template to use",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["markdown", "html", "pdf"]),
    default="markdown",
    help="Output format",
)
@click.option("--client", type=str, help="Client name for the report")
@click.option("--auditor", type=str, help="Auditor name for the report")
@click.option("--title", type=str, help="Custom report title")
def report(results_file, template, output, output_format, client, auditor, title):
    """Generate formatted security reports from audit results.

    Takes JSON audit results and applies a template to generate
    professional security reports.

    Examples:

      miesc report results.json -t professional -o report.md

      miesc report results.json -t executive --client "Acme" -o summary.md

      miesc report results.json -t technical --auditor "Security Team"

      miesc report results.json -t github-pr  # Output to stdout
    """
    print_banner()

    # Load results
    try:
        with open(results_file, "r") as f:
            results = json.load(f)
    except json.JSONDecodeError as e:
        error(f"Invalid JSON in {results_file}: {e}")
        sys.exit(1)
    except Exception as e:
        error(f"Failed to read {results_file}: {e}")
        sys.exit(1)

    info(f"Loaded results from {results_file}")

    # Locate template
    templates_dir = ROOT_DIR / "docs" / "templates" / "reports"
    template_file = templates_dir / f"{template}.md"

    if not template_file.exists():
        error(f"Template not found: {template_file}")
        info("Available templates: professional, executive, technical, github-pr, simple")
        sys.exit(1)

    # Load template
    template_content = template_file.read_text()

    # Extract data from results
    summary = results.get("summary", {})
    findings = results.get("findings", [])

    # Prepare template variables
    variables = {
        "contract_name": results.get("contract", "Unknown"),
        "audit_date": results.get("timestamp", datetime.now().isoformat())[:10],
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "client_name": client or "Client",
        "auditor_name": auditor or "MIESC Security",
        "version": results.get("version", VERSION),
        "critical_count": summary.get("critical", 0),
        "high_count": summary.get("high", 0),
        "medium_count": summary.get("medium", 0),
        "low_count": summary.get("low", 0),
        "info_count": summary.get("info", 0),
        "total_findings": len(findings),
        "files_count": results.get("files_count", 1),
        "tools_count": len(results.get("tools", [])),
        "overall_risk": _calculate_risk_level(summary),
        "miesc_version": VERSION,
    }

    # Prepare findings for template
    formatted_findings = []
    for i, finding in enumerate(findings, 1):
        formatted_findings.append(
            {
                "id": f"F-{i:03d}",
                "title": finding.get("title", "Unknown"),
                "severity": finding.get("severity", "unknown"),
                "category": finding.get("category", "general"),
                "location": finding.get("location", "unknown"),
                "description": finding.get("description", ""),
                "recommendation": finding.get("recommendation", ""),
                "tool": finding.get("tool", "unknown"),
                "status": finding.get("status", "open"),
                "impact": finding.get("impact", ""),
                "poc": finding.get("poc", "// No PoC provided"),
                "references": finding.get("references", []),
            }
        )

    variables["findings"] = formatted_findings
    variables["critical_high_findings"] = [
        f for f in formatted_findings if f["severity"] in ("critical", "high")
    ]
    variables["medium_low_findings"] = [
        f for f in formatted_findings if f["severity"] in ("medium", "low")
    ]

    # Simple template rendering (basic variable substitution)
    output_content = _render_template(template_content, variables)

    # Handle output
    if output:
        output_path = Path(output)

        if output_format == "html":
            output_content = _markdown_to_html(output_content, title or "MIESC Security Report")
        elif output_format == "pdf":
            # Try to use pandoc for PDF
            html_content = _markdown_to_html(output_content, title or "MIESC Security Report")
            try:
                import subprocess

                temp_html = output_path.with_suffix(".tmp.html")
                temp_html.write_text(html_content)
                subprocess.run(
                    ["pandoc", str(temp_html), "-o", str(output_path), "--pdf-engine=wkhtmltopdf"],
                    check=True,
                    capture_output=True,
                )
                temp_html.unlink()
                success(f"PDF report saved to {output_path}")
                return
            except FileNotFoundError:
                warning("pandoc not found, saving as HTML instead")
                output_path = output_path.with_suffix(".html")
                output_content = html_content
            except subprocess.CalledProcessError as e:
                warning(f"PDF generation failed: {e}")
                output_path = output_path.with_suffix(".html")
                output_content = html_content

        output_path.write_text(output_content)
        success(f"Report saved to {output_path}")
    else:
        # Output to stdout
        print(output_content)

    # Summary
    if RICH_AVAILABLE and output:
        console.print(
            f"\n[bold]Report Summary:[/bold] "
            f"[red]{variables['critical_count']}[/red] critical, "
            f"[red]{variables['high_count']}[/red] high, "
            f"[yellow]{variables['medium_count']}[/yellow] medium, "
            f"[cyan]{variables['low_count']}[/cyan] low"
        )


def _calculate_risk_level(summary: dict) -> str:
    """Calculate overall risk level from summary."""
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)

    if critical > 0:
        return "CRITICAL"
    elif high > 2:
        return "HIGH"
    elif high > 0 or medium > 3:
        return "MEDIUM"
    elif medium > 0:
        return "LOW"
    return "MINIMAL"


def _render_template(template: str, variables: dict) -> str:
    """Simple template rendering with Jinja2-like syntax."""
    output = template

    # Replace simple variables {{ var }}
    for key, value in variables.items():
        if not isinstance(value, (list, dict)):
            output = output.replace("{{ " + key + " }}", str(value))
            output = output.replace("{{" + key + "}}", str(value))

    # Handle findings loop
    if "{% for finding in findings %}" in output:
        findings_section_start = output.find("{% for finding in findings %}")
        findings_section_end = output.find("{% endfor %}", findings_section_start)

        if findings_section_end > findings_section_start:
            loop_template = output[
                findings_section_start + len("{% for finding in findings %}") : findings_section_end
            ]

            findings_output = ""
            for finding in variables.get("findings", []):
                finding_text = loop_template
                for fkey, fvalue in finding.items():
                    if isinstance(fvalue, list):
                        fvalue = ", ".join(str(v) for v in fvalue)
                    finding_text = finding_text.replace("{{ finding." + fkey + " }}", str(fvalue))
                    finding_text = finding_text.replace("{{finding." + fkey + "}}", str(fvalue))
                findings_output += finding_text

            output = (
                output[:findings_section_start]
                + findings_output
                + output[findings_section_end + len("{% endfor %}") :]
            )

    # Handle critical_high_findings loop
    if "{% for finding in critical_high_findings %}" in output:
        section_start = output.find("{% for finding in critical_high_findings %}")
        section_end = output.find("{% endfor %}", section_start)

        if section_end > section_start:
            loop_template = output[
                section_start + len("{% for finding in critical_high_findings %}") : section_end
            ]

            findings_output = ""
            for finding in variables.get("critical_high_findings", []):
                finding_text = loop_template
                for fkey, fvalue in finding.items():
                    finding_text = finding_text.replace("{{ finding." + fkey + " }}", str(fvalue))
                findings_output += finding_text

            output = (
                output[:section_start]
                + findings_output
                + output[section_end + len("{% endfor %}") :]
            )

    # Handle conditionals (simplified)
    if "{% if " in output:
        # Remove unfilled conditionals
        import re

        output = re.sub(r"\{% if [^%]+%\}.*?\{% endif %\}", "", output, flags=re.DOTALL)

    return output


def _markdown_to_html(markdown: str, title: str) -> str:
    """Convert markdown to HTML with basic styling."""
    try:
        import markdown as md

        html_body = md.markdown(markdown, extensions=["tables", "fenced_code"])
    except ImportError:
        # Fallback: wrap in pre tag
        html_body = f"<pre>{markdown}</pre>"

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 2rem; line-height: 1.6; }}
        h1, h2, h3 {{ color: #1a1a2e; }}
        table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #1a1a2e; color: white; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        code {{ background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background-color: #f4f4f4; padding: 1rem; border-radius: 5px; overflow-x: auto; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #17a2b8; }}
    </style>
</head>
<body>
{html_body}
</body>
</html>"""


# ============================================================================
# Benchmark Command
# ============================================================================


@cli.command()
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
        print(f"\n=== Security Posture: {project_id} ===")
        print(f"Critical: {current_metrics['critical']}")
        print(f"High: {current_metrics['high']}")
        print(f"Medium: {current_metrics['medium']}")
        print(f"Low: {current_metrics['low']}")
        print(f"Total: {current_metrics['total']}")

    if output:
        _generate_benchmark_report(current_metrics, output, period)


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
        print(f"\n=== Benchmark History: {project_id} ===")
        for bf in benchmarks[:10]:
            with open(bf) as f:
                data = json.load(f)
            run_id = bf.stem.replace(f"{project_id}_", "")
            print(f"  {run_id}: {data.get('total', 0)} findings")

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
        print("\n=== Comparison ===")
        print(
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


# ============================================================================
# Init Command Group - Framework Integrations
# ============================================================================


@cli.group()
def init():
    """Initialize MIESC integrations for build frameworks."""
    pass


@init.command("foundry")
@click.option("--profile", default="default", help="Foundry profile to configure")
@click.option("--fail-on", default="high", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--hook-script", is_flag=True, help="Create full hook script instead of inline command")
def init_foundry(profile, fail_on, hook_script):
    """Initialize MIESC integration for Foundry projects.

    Adds post-build hook to foundry.toml and optionally creates a hook script.

    Examples:
      miesc init foundry                    # Add to default profile
      miesc init foundry --profile ci       # Add to CI profile
      miesc init foundry --hook-script      # Create full hook script
      miesc init foundry --fail-on critical # Only fail on critical
    """
    print_banner()

    foundry_toml = Path("foundry.toml")

    if not foundry_toml.exists():
        error("foundry.toml not found in current directory")
        info("Run this command from your Foundry project root")
        sys.exit(1)

    info(f"Configuring MIESC for Foundry project...")

    # Read current config
    content = foundry_toml.read_text()

    # Check if already configured
    if "miesc" in content.lower():
        warning("MIESC appears to already be configured in foundry.toml")
        if not click.confirm("Overwrite existing configuration?"):
            return

    if hook_script:
        # Create hook script
        scripts_dir = Path("scripts")
        scripts_dir.mkdir(exist_ok=True)

        hook_path = scripts_dir / "miesc-hook.sh"
        hook_content = f'''#!/bin/bash
# =============================================================================
# MIESC Foundry Post-Build Hook
# Generated by: miesc init foundry --hook-script
# =============================================================================

set -e

# Configuration
FAIL_ON="${{MIESC_FAIL_ON:-{fail_on}}}"
CONTRACTS="${{MIESC_CONTRACTS:-./src}}"
REPORT_FILE="miesc-report.json"

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[0;33m'
BLUE='\\033[0;34m'
NC='\\033[0m'

log_info() {{ echo -e "${{BLUE}}[MIESC]${{NC}} $1"; }}
log_success() {{ echo -e "${{GREEN}}[MIESC]${{NC}} $1"; }}
log_error() {{ echo -e "${{RED}}[MIESC]${{NC}} $1"; }}

# Check MIESC
if ! command -v miesc &> /dev/null; then
    log_error "MIESC not found. Install: pip install miesc"
    exit 1
fi

# Find contracts
if [ ! -d "$CONTRACTS" ]; then
    CONTRACTS="./contracts"
fi

SOL_COUNT=$(find "$CONTRACTS" -name "*.sol" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "$SOL_COUNT" -eq 0 ]; then
    log_info "No Solidity files found"
    exit 0
fi

log_info "Scanning $SOL_COUNT contracts..."

# Run audit
miesc audit quick "$CONTRACTS" --ci --output json > "$REPORT_FILE" 2>&1 || true

# Parse results
if command -v jq &> /dev/null && [ -f "$REPORT_FILE" ]; then
    CRITICAL=$(jq -r '.summary.critical // 0' "$REPORT_FILE")
    HIGH=$(jq -r '.summary.high // 0' "$REPORT_FILE")
    MEDIUM=$(jq -r '.summary.medium // 0' "$REPORT_FILE")
    LOW=$(jq -r '.summary.low // 0' "$REPORT_FILE")

    echo ""
    log_info "=== Audit Summary ==="
    echo -e "  ${{RED}}Critical:${{NC}} $CRITICAL"
    echo -e "  ${{YELLOW}}High:${{NC}}     $HIGH"
    echo -e "  ${{YELLOW}}Medium:${{NC}}   $MEDIUM"
    echo -e "  ${{BLUE}}Low:${{NC}}      $LOW"

    # Check threshold
    SHOULD_FAIL=false
    case "$FAIL_ON" in
        critical) [ "$CRITICAL" -gt 0 ] && SHOULD_FAIL=true ;;
        high) [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] && SHOULD_FAIL=true ;;
        medium) [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] || [ "$MEDIUM" -gt 0 ] && SHOULD_FAIL=true ;;
        low) [ "$((CRITICAL + HIGH + MEDIUM + LOW))" -gt 0 ] && SHOULD_FAIL=true ;;
    esac

    if [ "$SHOULD_FAIL" = true ]; then
        log_error "Issues found above threshold ($FAIL_ON)"
        exit 1
    fi

    log_success "Audit passed (threshold: $FAIL_ON)"
fi
'''
        hook_path.write_text(hook_content)
        hook_path.chmod(0o755)
        success(f"Created {hook_path}")

        post_build_cmd = f"./scripts/miesc-hook.sh"
    else:
        post_build_cmd = f"miesc audit quick ./src --ci --fail-on {fail_on}"

    # Update foundry.toml
    profile_section = f"[profile.{profile}]"

    if profile_section in content:
        # Add to existing profile
        lines = content.split("\n")
        new_lines = []
        in_target_profile = False
        added = False

        for line in lines:
            new_lines.append(line)

            if line.strip() == profile_section:
                in_target_profile = True
            elif line.strip().startswith("[") and in_target_profile:
                # End of target profile, insert before next section
                if not added:
                    new_lines.insert(-1, f'post_build_hook = "{post_build_cmd}"')
                    new_lines.insert(-1, "")
                    added = True
                in_target_profile = False

        # If we're still in target profile at end of file
        if in_target_profile and not added:
            new_lines.append(f'post_build_hook = "{post_build_cmd}"')

        content = "\n".join(new_lines)
    else:
        # Add new profile section
        content += f"""

{profile_section}
post_build_hook = "{post_build_cmd}"
"""

    foundry_toml.write_text(content)
    success(f"Updated foundry.toml with MIESC post-build hook")

    # Summary
    print("")
    info("Configuration complete!")
    print(f"  Profile: {profile}")
    print(f"  Fail on: {fail_on}")
    print(f"  Hook: {post_build_cmd}")
    print("")
    info("Usage:")
    print(f"  forge build                  # Triggers MIESC audit")
    print(f"  forge build --profile {profile}  # Uses configured profile")


@init.command("hardhat")
@click.option("--fail-on", default="high", type=click.Choice(["critical", "high", "medium", "low"]))
def init_hardhat(fail_on):
    """Initialize MIESC integration for Hardhat projects.

    Creates hardhat.config.js plugin configuration.

    Examples:
      miesc init hardhat
      miesc init hardhat --fail-on critical
    """
    print_banner()

    # Check for hardhat config
    config_files = ["hardhat.config.js", "hardhat.config.ts"]
    config_file = None
    for f in config_files:
        if Path(f).exists():
            config_file = Path(f)
            break

    if not config_file:
        error("hardhat.config.js/ts not found in current directory")
        info("Run this command from your Hardhat project root")
        sys.exit(1)

    info(f"Configuring MIESC for Hardhat project...")

    # Create miesc task file
    tasks_dir = Path("tasks")
    tasks_dir.mkdir(exist_ok=True)

    task_file = tasks_dir / "miesc.js"
    task_content = f'''// MIESC Security Audit Task for Hardhat
// Generated by: miesc init hardhat

const {{ task }} = require("hardhat/config");
const {{ exec }} = require("child_process");
const {{ promisify }} = require("util");
const execAsync = promisify(exec);

task("miesc", "Run MIESC security audit")
  .addOptionalParam("level", "Audit level: quick or full", "quick")
  .addOptionalParam("failOn", "Fail on severity: critical, high, medium, low", "{fail_on}")
  .addFlag("ci", "CI mode - exit with error code on issues")
  .setAction(async (taskArgs, hre) => {{
    const {{ level, failOn, ci }} = taskArgs;

    console.log("\\n[MIESC] Running security audit...\\n");

    const contractsDir = hre.config.paths.sources;
    let cmd = `miesc audit ${{level}} ${{contractsDir}}`;

    if (ci) {{
      cmd += ` --ci --fail-on ${{failOn}}`;
    }}

    try {{
      const {{ stdout, stderr }} = await execAsync(cmd);
      console.log(stdout);
      if (stderr) console.error(stderr);
    }} catch (error) {{
      console.error(error.stdout || error.message);
      if (ci) {{
        process.exit(1);
      }}
    }}
  }});

task("miesc:quick", "Run quick MIESC audit")
  .setAction(async (_, hre) => {{
    await hre.run("miesc", {{ level: "quick" }});
  }});

task("miesc:full", "Run full MIESC audit")
  .setAction(async (_, hre) => {{
    await hre.run("miesc", {{ level: "full" }});
  }});

// Hook into compile task
task("compile")
  .setAction(async (args, hre, runSuper) => {{
    await runSuper(args);

    if (process.env.MIESC_ON_COMPILE === "true") {{
      console.log("\\n[MIESC] Post-compile security check...\\n");
      await hre.run("miesc", {{ level: "quick" }});
    }}
  }});

module.exports = {{}};
'''
    task_file.write_text(task_content)
    success(f"Created {task_file}")

    # Show instructions
    print("")
    info("Add to your hardhat.config.js:")
    print('  require("./tasks/miesc");')
    print("")
    info("Usage:")
    print("  npx hardhat miesc              # Quick audit")
    print("  npx hardhat miesc --level full # Full audit")
    print("  npx hardhat miesc --ci         # CI mode with exit code")
    print("")
    info("Enable audit on compile:")
    print("  MIESC_ON_COMPILE=true npx hardhat compile")


@init.command("github")
@click.option("--workflow-name", default="security", help="Workflow file name")
def init_github(workflow_name):
    """Initialize GitHub Actions workflow for MIESC.

    Creates .github/workflows/security.yml

    Examples:
      miesc init github
      miesc init github --workflow-name audit
    """
    print_banner()

    workflows_dir = Path(".github/workflows")
    workflows_dir.mkdir(parents=True, exist_ok=True)

    workflow_file = workflows_dir / f"{workflow_name}.yml"

    workflow_content = '''# MIESC Security Audit Workflow
# Generated by: miesc init github

name: Security Audit

on:
  push:
    branches: [main, master, develop]
    paths:
      - '**.sol'
  pull_request:
    paths:
      - '**.sol'
  workflow_dispatch:

jobs:
  miesc-audit:
    name: MIESC Security Audit
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install MIESC
        run: |
          pip install miesc
          miesc --version

      - name: Run Security Audit
        run: |
          miesc audit quick . --ci --output sarif > miesc.sarif || true
          miesc audit quick . --output json > miesc.json || true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: miesc.sarif
        continue-on-error: true

      - name: Generate Summary
        if: always()
        run: |
          echo "## MIESC Security Audit" >> $GITHUB_STEP_SUMMARY
          if [ -f miesc.json ]; then
            echo "| Severity | Count |" >> $GITHUB_STEP_SUMMARY
            echo "|----------|-------|" >> $GITHUB_STEP_SUMMARY
            echo "| Critical | $(jq -r '.summary.critical // 0' miesc.json) |" >> $GITHUB_STEP_SUMMARY
            echo "| High | $(jq -r '.summary.high // 0' miesc.json) |" >> $GITHUB_STEP_SUMMARY
            echo "| Medium | $(jq -r '.summary.medium // 0' miesc.json) |" >> $GITHUB_STEP_SUMMARY
            echo "| Low | $(jq -r '.summary.low // 0' miesc.json) |" >> $GITHUB_STEP_SUMMARY
          fi

      - name: Upload Results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: miesc-results
          path: |
            miesc.json
            miesc.sarif
'''

    workflow_file.write_text(workflow_content)
    success(f"Created {workflow_file}")

    print("")
    info("GitHub Actions workflow created!")
    print(f"  File: {workflow_file}")
    print("")
    info("The workflow will:")
    print("  - Run on push/PR to main, master, develop")
    print("  - Upload results to GitHub Code Scanning")
    print("  - Generate summary in workflow run")


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    cli()
