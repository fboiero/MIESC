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

# Try to import centralized logging
try:
    from src.core.logging_config import get_logger, log_context, setup_logging

    LOGGING_AVAILABLE = True
except ImportError:
    LOGGING_AVAILABLE = False

# Configure logging (will be reconfigured by setup_logging if available)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def configure_logging(debug: bool = False, quiet: bool = False):
    """Configure logging based on flags and environment variables."""
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

    if LOGGING_AVAILABLE:
        setup_logging(level=level, quiet=quiet)
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

    # Pre-load adapters
    AdapterLoader.load_all()

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
@click.option("--port", "-p", type=int, default=8080, help="Port number")
def server_mcp(port):
    """Start the MCP server for AI integration."""
    print_banner()
    info(f"Starting MCP server on port {port}")

    mcp_script = ROOT_DIR / "src" / "miesc_mcp_rest.py"
    if mcp_script.exists():
        import subprocess

        subprocess.run([sys.executable, str(mcp_script), "--mcp", "--port", str(port)])
    else:
        error("MCP server script not found")
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
# Entry Point
# ============================================================================

if __name__ == "__main__":
    cli()
