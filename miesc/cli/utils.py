"""
MIESC CLI Utilities

Helper functions and classes for the MIESC CLI including
output formatting, configuration loading, and adapter management.

Author: Fernando Boiero
License: AGPL-3.0
"""

import importlib
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .constants import ADAPTER_MAP, LAYERS

# Root directory setup
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR))

# Try to import Rich for beautiful output
try:
    from rich.console import Console
    from rich.text import Text

    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None  # type: ignore

# Try to import YAML for config
try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)

# Lazy import holders
LOGGING_AVAILABLE: Optional[bool] = None
_setup_logging = None
ML_ORCHESTRATOR_AVAILABLE: Optional[bool] = None
_MLOrchestrator = None
_MIESCCorrelationAPI = None


def configure_logging(debug: bool = False, quiet: bool = False) -> None:
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


def get_ml_orchestrator() -> Any:
    """Lazy load MLOrchestrator for ML-enhanced analysis."""
    global ML_ORCHESTRATOR_AVAILABLE, _MLOrchestrator

    if ML_ORCHESTRATOR_AVAILABLE is None:
        try:
            from src.core.ml_orchestrator import MLOrchestrator

            _MLOrchestrator = MLOrchestrator
            ML_ORCHESTRATOR_AVAILABLE = True
            logger.debug("MLOrchestrator loaded successfully")
        except ImportError as e:
            logger.debug(f"MLOrchestrator not available: {e}")
            ML_ORCHESTRATOR_AVAILABLE = False

    if ML_ORCHESTRATOR_AVAILABLE and _MLOrchestrator:
        return _MLOrchestrator()
    return None


def get_correlation_api() -> Any:
    """Lazy load MIESCCorrelationAPI for intelligent correlation."""
    global _MIESCCorrelationAPI

    if _MIESCCorrelationAPI is None:
        try:
            from src.core.correlation_api import MIESCCorrelationAPI

            _MIESCCorrelationAPI = MIESCCorrelationAPI
            logger.debug("MIESCCorrelationAPI loaded successfully")
        except ImportError as e:
            logger.debug(f"MIESCCorrelationAPI not available: {e}")
            return None

    if _MIESCCorrelationAPI:
        return _MIESCCorrelationAPI()
    return None


# =============================================================================
# Output Helpers
# =============================================================================


def print_banner(version: str | None = None) -> None:
    """Print the MIESC banner."""
    from .constants import BANNER

    # Import VERSION if not provided
    if version is None:
        from miesc import __version__ as VERSION

        version = VERSION

    if RICH_AVAILABLE and console:
        console.print(Text(BANNER, style="bold blue"))
        console.print(
            f"[cyan]v{version}[/cyan] - Multi-layer Intelligent Evaluation for Smart Contracts"
        )
        console.print("[dim]9 Defense Layers | 50 Security Tools | AI-Powered Analysis[/dim]\n")
    else:
        print(BANNER)  # noqa: T201
        print(f"v{version} - Multi-layer Intelligent Evaluation for Smart Contracts")  # noqa: T201
        print("9 Defense Layers | 50 Security Tools | AI-Powered Analysis\n")  # noqa: T201


def success(msg: str) -> None:
    """Print success message."""
    if RICH_AVAILABLE and console:
        console.print(f"[green]OK[/green] {msg}")
    else:
        print(f"[OK] {msg}")  # noqa: T201


def error(msg: str) -> None:
    """Print error message."""
    if RICH_AVAILABLE and console:
        console.print(f"[red]ERR[/red] {msg}")
    else:
        print(f"[ERR] {msg}")  # noqa: T201


def warning(msg: str) -> None:
    """Print warning message."""
    if RICH_AVAILABLE and console:
        console.print(f"[yellow]WARN[/yellow] {msg}")
    else:
        print(f"[WARN] {msg}")  # noqa: T201


def info(msg: str) -> None:
    """Print info message."""
    if RICH_AVAILABLE and console:
        console.print(f"[cyan]INFO[/cyan] {msg}")
    else:
        print(f"[INFO] {msg}")  # noqa: T201


# =============================================================================
# Configuration
# =============================================================================


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


# =============================================================================
# Adapter Loader
# =============================================================================


class AdapterLoader:
    """Dynamic loader for tool adapters."""

    _adapters: Dict[str, Any] = {}
    _loaded = False

    @classmethod
    def load_all(cls) -> Dict[str, Any]:
        """Load all available adapters from src/adapters/."""
        if cls._loaded:
            return cls._adapters

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
    def get_adapter(cls, tool_name: str) -> Any:
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

    @classmethod
    def reset(cls) -> None:
        """Reset the loader state (useful for testing)."""
        cls._adapters = {}
        cls._loaded = False


# =============================================================================
# Tool Execution
# =============================================================================


def run_tool(tool: str, contract: str, timeout: int = 300, **kwargs: Any) -> Dict[str, Any]:
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


def run_layer(layer: int, contract: str, timeout: int = 300) -> List[Dict[str, Any]]:
    """Run all tools in a specific layer."""
    if layer not in LAYERS:
        return []

    results = []
    layer_info = LAYERS[layer]

    for tool in layer_info["tools"]:
        info(f"Running {tool}...")
        result = run_tool(tool, contract, timeout)
        results.append(result)

        if result["status"] == "success":
            findings_count = len(result.get("findings", []))
            success(f"{tool}: {findings_count} findings in {result.get('execution_time', 0):.1f}s")
        elif result["status"] == "not_available":
            warning(f"{tool}: not installed")
        else:
            warning(f"{tool}: {result.get('error', 'Unknown error')}")

    return results


def summarize_findings(all_results: List[Dict[str, Any]]) -> Dict[str, int]:
    """Summarize findings by severity."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for result in all_results:
        for finding in result.get("findings", []):
            severity = finding.get("severity", "INFO").upper()
            if severity in summary:
                summary[severity] += 1
            else:
                summary["INFO"] += 1

    return summary


def get_root_dir() -> Path:
    """Get the project root directory."""
    return ROOT_DIR
