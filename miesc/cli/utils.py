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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

from .constants import ADAPTER_MAP, LAYERS

# Root directory setup
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR))

# Package data directory (works both in dev and when installed via pip)
_PACKAGE_DATA_DIR = Path(__file__).parent.parent / "data"


def get_data_path(*parts: str) -> Path:
    """Resolve a data file path.

    Checks the package-internal data dir first (pip install), then falls back
    to the repo root layout (development).
    """
    pkg_path = _PACKAGE_DATA_DIR.joinpath(*parts)
    if pkg_path.exists():
        return pkg_path
    return ROOT_DIR.joinpath(*parts)


# Try to import Rich for beautiful output
try:
    from rich.console import Console
    from rich.text import Text

    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

    # Fallback: minimal Console-compatible object so existing
    # `console.print(...)` calls across 137 sites don't crash with
    # AttributeError: 'NoneType' object has no attribute 'print'.
    # rich is now a hard dependency in pyproject.toml, but this guard
    # keeps the CLI usable in stripped-down install scenarios.
    import re as _re

    class _PlainConsole:
        """Stdout fallback that strips rich markup."""

        _MARKUP_RE = _re.compile(r"\[/?[^\]]+\]")

        def print(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401, ARG002
            for a in args:
                text = self._MARKUP_RE.sub("", str(a))
                print(text)

        def log(self, *args: Any, **kwargs: Any) -> None:
            self.print(*args, **kwargs)

    console = _PlainConsole()  # type: ignore

# Try to import YAML for config
try:
    import yaml  # type: ignore[import-untyped]

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

    if _MIESCCorrelationAPI is not None:
        return _MIESCCorrelationAPI()
    return None


# =============================================================================
# Output Helpers
# =============================================================================


def print_banner(version: Optional[str] = None) -> None:
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
        console.print(
            "[dim]9 Defense Layers | Configured Adapter Stack | AI-Powered Analysis[/dim]\n"
        )
    else:
        print(BANNER)  # noqa: T201
        print(f"v{version} - Multi-layer Intelligent Evaluation for Smart Contracts")  # noqa: T201
        print("9 Defense Layers | Configured Adapter Stack | AI-Powered Analysis\n")  # noqa: T201


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
    config_path = get_data_path("config", "miesc.yaml")
    if config_path.exists() and YAML_AVAILABLE:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def load_profiles() -> Dict[str, Any]:
    """Load analysis profiles from config/profiles.yaml."""
    profiles_path = get_data_path("config", "profiles.yaml")
    if profiles_path.exists() and YAML_AVAILABLE:
        with open(profiles_path) as f:
            data = yaml.safe_load(f) or {}
            return cast(Dict[str, Any], data.get("profiles", {}))
    return {}


_CONFIG_CACHE: Optional[Dict[str, Any]] = None


def _get_config() -> Dict[str, Any]:
    """Return cached MIESC config."""
    global _CONFIG_CACHE
    if _CONFIG_CACHE is None:
        _CONFIG_CACHE = load_config()
    return _CONFIG_CACHE


def get_tool_timeout(tool: str, default: int = 300) -> int:
    """Get the configured timeout for a tool from miesc.yaml."""
    cfg = _get_config()
    adapters = cfg.get("adapters", {})
    tool_cfg = adapters.get(tool, {})
    return int(tool_cfg.get("timeout", default))


def get_max_workers(default: int = 4) -> int:
    """Get the configured max_workers from miesc.yaml global section."""
    cfg = _get_config()
    return int(cfg.get("global", {}).get("max_workers", default))


def get_profile(name: str) -> Optional[Dict[str, Any]]:
    """Get a specific profile by name, handling aliases."""
    profiles = load_profiles()
    profiles_path = get_data_path("config", "profiles.yaml")

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
        """Check if a tool is installed and available.

        Includes the adapter's ``install_cmd`` (best-effort) so callers like
        ``miesc doctor`` can tell users HOW to install a missing tool.
        """
        adapter = cls.get_adapter(tool_name)
        if not adapter:
            return {"status": "no_adapter", "available": False, "install_cmd": ""}

        # Best-effort install hint from the adapter metadata.
        install_cmd = ""
        try:
            meta = adapter.get_metadata()
            install_cmd = getattr(meta, "installation_cmd", "") or ""
        except Exception:
            install_cmd = ""

        try:
            # Import ToolStatus enum
            from src.core.tool_protocol import ToolStatus

            status = adapter.is_available()
            return {
                "status": status.value if hasattr(status, "value") else str(status),
                "available": status == ToolStatus.AVAILABLE,
                "install_cmd": install_cmd,
            }
        except Exception as e:
            return {"status": "error", "available": False, "error": str(e), "install_cmd": install_cmd}

    @classmethod
    def reset(cls) -> None:
        """Reset the loader state (useful for testing)."""
        cls._adapters = {}
        cls._loaded = False


# =============================================================================
# Tool Execution
# =============================================================================


def run_tool(tool: str, contract: str, timeout: int = 0, **kwargs: Any) -> Dict[str, Any]:
    """
    Run a security tool using its adapter.

    Args:
        tool: Tool name (e.g., 'slither', 'mythril')
        contract: Path to Solidity contract
        timeout: Timeout in seconds (0 = use config or default 300)
        **kwargs: Additional tool-specific parameters

    Returns:
        Normalized results dictionary
    """
    if timeout <= 0:
        timeout = get_tool_timeout(tool, default=300)
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

    layer_info = LAYERS[layer]
    tools = list(layer_info["tools"])
    max_workers = min(max(get_max_workers(default=4), 1), len(tools) or 1)

    if max_workers == 1 or len(tools) <= 1:
        results: List[Dict[str, Any]] = []
        for tool in tools:
            info(f"Running {tool}...")
            result = run_tool(tool, contract, timeout)
            results.append(result)
            _print_tool_result(tool, result)
        return results

    for tool in tools:
        info(f"Running {tool}...")

    results_by_index: Dict[int, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(run_tool, tool, contract, timeout): (index, tool)
            for index, tool in enumerate(tools)
        }
        for future in as_completed(futures):
            index, tool = futures[future]
            try:
                results_by_index[index] = future.result()
            except Exception as e:
                results_by_index[index] = {
                    "tool": tool,
                    "contract": contract,
                    "status": "error",
                    "findings": [],
                    "execution_time": 0,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                }

    results = [results_by_index[index] for index in range(len(tools))]
    for tool, result in zip(tools, results, strict=True):
        _print_tool_result(tool, result)

    return results


def _print_tool_result(tool: str, result: Dict[str, Any]) -> None:
    if result["status"] == "success":
        findings_count = len(result.get("findings", []))
        success(f"{tool}: {findings_count} findings in {result.get('execution_time', 0):.1f}s")
    elif result["status"] == "not_available":
        warning(f"{tool}: not installed")
    else:
        warning(f"{tool}: {result.get('error', 'Unknown error')}")


def run_plugins(contract: str, timeout: int = 300) -> List[Dict[str, Any]]:
    """Run all enabled plugin detectors on a contract.

    Discovers plugins via entry points (miesc.detectors group) and local
    plugins (~/.miesc/plugins/), then executes each enabled detector.

    Returns list of tool-result dicts compatible with run_layer output.
    """
    results: List[Dict[str, Any]] = []

    try:
        from miesc.plugins import PluginManager

        manager = PluginManager()
        enabled_detectors = manager.get_enabled_detectors()

        if not enabled_detectors:
            return results

        import inspect
        import time as _time

        try:
            source_code = Path(contract).read_text(encoding="utf-8")
        except Exception:
            source_code = contract

        for detector_name, detector_class in enabled_detectors:
            info(f"Running plugin: {detector_name}...")
            start = _time.perf_counter()
            try:
                detector = detector_class()
                analyze_sig = inspect.signature(detector.analyze)
                params = analyze_sig.parameters
                first_param = next(iter(params.values()), None)
                first_arg = (
                    contract
                    if first_param and first_param.name in {"contract", "contract_path", "path"}
                    else source_code
                )
                call_kwargs: Dict[str, Any] = {}
                if "file_path" in params:
                    call_kwargs["file_path"] = contract
                if "timeout" in params:
                    call_kwargs["timeout"] = timeout
                findings = detector.analyze(first_arg, **call_kwargs)
                elapsed = _time.perf_counter() - start

                # Normalize findings
                normalized: List[Dict[str, Any]] = []
                for f in findings or []:
                    if isinstance(f, dict):
                        f.setdefault("tool", f"plugin:{detector_name}")
                        normalized.append(f)
                    elif hasattr(f, "to_dict"):
                        item = f.to_dict()
                        item.setdefault("tool", f"plugin:{detector_name}")
                        normalized.append(item)
                    elif hasattr(f, "__dict__"):
                        item = dict(f.__dict__)
                        item.setdefault("tool", f"plugin:{detector_name}")
                        normalized.append(item)

                result = {
                    "tool": f"plugin:{detector_name}",
                    "status": "success",
                    "findings": normalized,
                    "execution_time": round(elapsed, 2),
                }
                results.append(result)
                success(f"plugin:{detector_name}: {len(normalized)} findings in {elapsed:.1f}s")

            except Exception as e:
                elapsed = _time.perf_counter() - start
                results.append(
                    {
                        "tool": f"plugin:{detector_name}",
                        "status": "error",
                        "findings": [],
                        "error": str(e),
                        "execution_time": round(elapsed, 2),
                    }
                )
                warning(f"plugin:{detector_name}: {e}")

    except ImportError:
        pass  # Plugin system not available

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


# ---------------------------------------------------------------------------
# Adapter loader — used by DeepAuditAgent for dynamic tool triggering
# ---------------------------------------------------------------------------

_ADAPTERS_CACHE: Optional[Dict[str, Any]] = None


def load_adapters(force_reload: bool = False) -> Dict[str, Any]:
    """
    Load all MIESC adapter instances keyed by tool name.

    Walks ADAPTER_MAP, imports each adapter module on demand, and instantiates
    the class. Broken imports / constructor failures are logged at debug level
    and the adapter is simply skipped — the caller receives a dict of whatever
    loaded successfully.

    Cached: the first call loads and caches; subsequent calls return the cached
    dict unless `force_reload=True`.

    Returns:
        {tool_name: adapter_instance} — e.g. {"slither": SlitherAdapter()}
    """
    global _ADAPTERS_CACHE
    if _ADAPTERS_CACHE is not None and not force_reload:
        return _ADAPTERS_CACHE

    result: Dict[str, Any] = {}
    logger = logging.getLogger(__name__)

    for tool_name, class_name in ADAPTER_MAP.items():
        try:
            module_name = f"src.adapters.{tool_name}_adapter"
            module = importlib.import_module(module_name)
            cls = getattr(module, class_name, None)
            if cls is None:
                logger.debug(f"load_adapters: {module_name} has no {class_name}")
                continue
            result[tool_name] = cls()
        except Exception as e:
            logger.debug(f"load_adapters: could not load {tool_name}: {e}")
            continue

    _ADAPTERS_CACHE = result
    return result
