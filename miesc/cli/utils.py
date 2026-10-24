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
from typing import Any, Dict, Iterable, List, Optional, Set, cast

from miesc.core.llm_budget import get_llm_timeout, set_llm_timeout  # noqa: F401
from miesc.core.rule_classes import apply_rule_class_caps

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
            from miesc.core.logging_config import setup_logging

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
            from miesc.core.ml_orchestrator import MLOrchestrator

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
            from miesc.core.correlation_api import MIESCCorrelationAPI

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
    """Load MIESC configuration from the packaged miesc/data/config/miesc.yaml."""
    config_path = get_data_path("config", "miesc.yaml")
    if config_path.exists() and YAML_AVAILABLE:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def load_profiles() -> Dict[str, Any]:
    """Load analysis profiles from the packaged miesc/data/config/profiles.yaml."""
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
    # Tool availability probed once per process (``reset_availability`` clears it).
    # Probing is expensive for some adapters (SmartGuard shells out to ``ollama list``
    # with a 5 s timeout) and the answer does not change between two contracts of
    # the same run.
    _availability: Dict[str, Any] = {}

    @classmethod
    def load_all(cls) -> Dict[str, Any]:
        """Load all available adapters from src/adapters/."""
        if cls._loaded:
            return cls._adapters

        for tool_name, class_name in ADAPTER_MAP.items():
            try:
                # Build module name
                module_name = f"miesc.adapters.{tool_name}_adapter"

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
            from miesc.core.tool_protocol import ToolStatus

            # Same per-process cache run_tool uses, so a probe made by an audit
            # and the count ``miesc doctor`` prints come from one answer.
            status = cls.get_availability(tool_name, adapter)
            return {
                "status": status.value if hasattr(status, "value") else str(status),
                "available": status == ToolStatus.AVAILABLE,
                "install_cmd": install_cmd,
            }
        except Exception as e:
            return {
                "status": "error",
                "available": False,
                "error": str(e),
                "install_cmd": install_cmd,
            }

    @classmethod
    def get_availability(cls, tool_name: str, adapter: Any) -> Any:
        """Return ``adapter.is_available()``, probing each tool at most once.

        The first call for a tool runs the adapter's probe and caches the resulting
        ``ToolStatus``; later calls return the cached value. ``reset_availability``
        drops the cache (the evaluator does so at the start of every run).
        """
        if tool_name not in cls._availability:
            cls._availability[tool_name] = adapter.is_available()
        return cls._availability[tool_name]

    @classmethod
    def reset_availability(cls) -> None:
        """Forget cached tool availability so the next ``run_tool`` probes again."""
        cls._availability = {}

    @classmethod
    def llm_tools(cls) -> Set[str]:
        """Names of the tools whose adapter declares ``requires_llm`` in its metadata.

        These are the adapters that call an LLM backend (local Ollama or a hosted
        API) to produce findings; ``miesc evaluate --no-llm`` skips them.
        """
        tools: Set[str] = set()
        for tool_name, adapter in cls.load_all().items():
            try:
                if getattr(adapter.get_metadata(), "requires_llm", False):
                    tools.add(tool_name)
            except Exception as e:  # pragma: no cover - defensive, metadata is static
                logger.debug(f"Could not read metadata for {tool_name}: {e}")
        return tools

    @classmethod
    def reset(cls) -> None:
        """Reset the loader state (useful for testing)."""
        cls._adapters = {}
        cls._loaded = False
        cls._availability = {}


# =============================================================================
# Tool Execution
# =============================================================================


# One status vocabulary for every tool result record, across scan, audit, evaluate
# and doctor:
#   success  - the tool ran and produced a (possibly empty) findings list;
#              ``fallback: True`` when a built-in heuristic stood in for the real tool
#   skipped  - deliberately not run; ``reason`` says why (not_installed,
#              configuration_error, license_required, no_adapter, no_llm,
#              unsupported_source)
#   timeout  - the tool was killed after the configured timeout
#   error    - the tool ran and failed; ``error`` carries the message
TOOL_STATUSES = ("success", "skipped", "timeout", "error")

_STATUS_ALIASES = {
    "success": "success",
    "ok": "success",
    "completed": "success",
    "done": "success",
    "skipped": "skipped",
    "skip": "skipped",
    "not_available": "skipped",
    "unavailable": "skipped",
    "no_adapter": "skipped",
    "timeout": "timeout",
    "timed_out": "timeout",
    "error": "error",
    "failed": "error",
    "failure": "error",
}


def normalize_tool_status(raw: Any) -> str:
    """Map whatever an adapter put in ``status`` onto :data:`TOOL_STATUSES`.

    Unknown labels are kept out of the vocabulary deliberately: a label we
    have never seen is reported as ``error`` so it is noticed, never as a
    silent success.
    """
    key = str(raw or "success").strip().lower()
    return _STATUS_ALIASES.get(key, "error")


def normalize_tool_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Rewrite ``result["status"]`` into the shared vocabulary in place and lift
    ``reason`` / ``fallback`` out of ``metadata`` when the adapter put them there."""
    raw = result.get("status")
    status = normalize_tool_status(raw)
    if status == "error" and raw and str(raw).lower() not in _STATUS_ALIASES:
        result.setdefault("reason", f"unknown_status:{raw}")
        result.setdefault("error", f"adapter returned unknown status {raw!r}")
    result["status"] = status
    metadata = result.get("metadata") or {}
    if isinstance(metadata, dict):
        if "reason" not in result and metadata.get("reason"):
            result["reason"] = metadata["reason"]
        if "fallback" not in result and metadata.get("fallback"):
            result["fallback"] = True
    if status == "skipped" and "reason" not in result and raw:
        result["reason"] = str(raw).lower()
    return result


def summarize_tool_statuses(results: Iterable[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Tool names per status: ``success`` (of which ``fallback``), ``skipped``,
    ``timeout``, ``error``. Pseudo-tools (``miesc-intelligence`` ...) are included
    only where they carry a status."""
    buckets: Dict[str, List[str]] = {
        k: [] for k in ("success", "fallback", "skipped", "timeout", "error")
    }
    for r in results:
        tool = str(r.get("tool") or "")
        if not tool:
            continue
        status = normalize_tool_status(r.get("status"))
        buckets[status].append(tool)
        if status == "success" and r.get("fallback"):
            buckets["fallback"].append(tool)
    return buckets


def format_tool_summary(results: Iterable[Dict[str, Any]]) -> str:
    """One line a reader can trust: ``ran 42/50 (2 fallback) · skipped 6 · timeout 0 · error 2``."""
    b = summarize_tool_statuses(results)
    total = len(b["success"]) + len(b["skipped"]) + len(b["timeout"]) + len(b["error"])
    ran = f"ran {len(b['success'])}/{total}"
    if b["fallback"]:
        ran += f" ({len(b['fallback'])} fallback)"
    return f"{ran} · skipped {len(b['skipped'])} · timeout {len(b['timeout'])} · error {len(b['error'])}"


def tool_availability(tools: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """``AdapterLoader.check_tool_status`` for each tool. ``miesc doctor`` and the
    audit summaries both go through here so they print the same denominator."""
    return {tool: AdapterLoader.check_tool_status(tool) for tool in tools}


def count_available(tools: Iterable[str]) -> tuple[int, int]:
    """(available, total) over ``tools`` — the number ``miesc doctor`` prints."""
    statuses = tool_availability(list(tools))
    return sum(1 for info in statuses.values() if info.get("available")), len(statuses)


# Wall-clock budget applied to LLM-backed adapters only (``--llm-timeout``).
# The state lives in miesc.core.llm_budget so the ML orchestrator shares it.


def effective_tool_timeout(tool: str, timeout: int) -> int:
    """Timeout to hand to ``tool``: the LLM budget when one is set and the
    adapter declares ``requires_llm``, otherwise ``timeout`` unchanged."""
    budget = get_llm_timeout()
    if budget and tool in AdapterLoader.llm_tools():
        return budget
    return timeout


def run_tool(tool: str, contract: str, timeout: int = 0, **kwargs: Any) -> Dict[str, Any]:
    """
    Run a security tool using its adapter.

    Args:
        tool: Tool name (e.g., 'slither', 'mythril')
        contract: Path to Solidity contract
        timeout: Timeout in seconds (0 = use config or default 300); LLM-backed
            tools use the ``--llm-timeout`` budget instead when one is set.
        **kwargs: Additional tool-specific parameters

    Returns:
        Normalized results dictionary
    """
    if timeout <= 0:
        timeout = get_tool_timeout(tool, default=300)
    timeout = effective_tool_timeout(tool, timeout)
    start_time = datetime.now()

    # Get adapter for tool
    adapter = AdapterLoader.get_adapter(tool)

    if not adapter:
        return {
            "tool": tool,
            "contract": contract,
            "status": "skipped",
            "reason": "no_adapter",
            "findings": [],
            "execution_time": 0,
            "timestamp": datetime.now().isoformat(),
            "error": f"No adapter found for {tool}",
        }

    try:
        # Skip tools that don't apply to this file type (e.g. Solidity-only
        # tools against a .vy file) before spending time on availability
        # checks or a doomed analyze() call. can_analyze defaults to .sol-only
        # (ToolAdapter.can_analyze) or is omitted entirely by duck-typed
        # adapters that accept anything — both are treated as "applies".
        can_analyze = getattr(adapter, "can_analyze", None)
        if callable(can_analyze) and not can_analyze(contract):
            return {
                "tool": tool,
                "contract": contract,
                "status": "skipped",
                "reason": "unsupported_source",
                "findings": [],
                "execution_time": 0,
                "timestamp": datetime.now().isoformat(),
                "error": f"{tool} does not support this file type",
            }

        # Check if tool is available
        from miesc.core.tool_protocol import ToolStatus

        status = AdapterLoader.get_availability(tool, adapter)

        if status != ToolStatus.AVAILABLE:
            return {
                "tool": tool,
                "contract": contract,
                "status": "skipped",
                "reason": status.value,
                "findings": [],
                "execution_time": (datetime.now() - start_time).total_seconds(),
                "timestamp": datetime.now().isoformat(),
                "error": f"Tool {tool} not available: {status.value}",
            }

        # Run analysis
        result = adapter.analyze(contract, timeout=timeout, **kwargs)

        findings = result.get("findings", [])
        for finding in findings:
            if isinstance(finding, dict):
                finding.setdefault("tool", tool)
        # Lint / informational rules are capped at their class ceiling here so
        # every CLI path (scan, audit, evaluate) reports the same severity.
        apply_rule_class_caps(findings)

        # Ensure consistent output format
        normalized = normalize_tool_result(dict(result))
        record = {
            "tool": tool,
            "contract": contract,
            "status": normalized["status"],
            "findings": findings,
            "execution_time": result.get(
                "execution_time", (datetime.now() - start_time).total_seconds()
            ),
            "timestamp": datetime.now().isoformat(),
            "metadata": result.get("metadata", {}),
            "error": normalized.get("error"),
            "timeout_budget_s": timeout,
        }
        if normalized.get("reason"):
            record["reason"] = normalized["reason"]
        if normalized.get("fallback"):
            record["fallback"] = True
        return record

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


def _skipped_tool_result(
    tool: str, contract: str, reason: str, *, reason_code: str = "no_llm"
) -> Dict[str, Any]:
    """Result record for a tool deliberately left out of a run (not probed, not run)."""
    return {
        "tool": tool,
        "contract": contract,
        "status": "skipped",
        "reason": reason_code,
        "findings": [],
        "execution_time": 0,
        "timestamp": datetime.now().isoformat(),
        "error": reason,
    }


def run_layer(
    layer: int,
    contract: str,
    timeout: int = 300,
    *,
    exclude_tools: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Run all tools in a specific layer.

    ``exclude_tools`` names tools to leave out entirely: they are neither probed
    for availability nor run, and appear in the result with status ``"skipped"``
    so callers that count tools per layer see the same shape either way.
    """
    if layer not in LAYERS:
        return []

    layer_info = LAYERS[layer]
    excluded = set(exclude_tools or ())
    tools = [tool for tool in layer_info["tools"] if tool not in excluded]
    skipped = [
        _skipped_tool_result(tool, contract, "skipped: LLM-dependent tool (--no-llm)")
        for tool in layer_info["tools"]
        if tool in excluded
    ]
    for result in skipped:
        _print_tool_result(result["tool"], result)
    max_workers = min(max(get_max_workers(default=4), 1), len(tools) or 1)

    if max_workers == 1 or len(tools) <= 1:
        results: List[Dict[str, Any]] = []
        for tool in tools:
            info(f"Running {tool}...")
            result = run_tool(tool, contract, timeout)
            results.append(result)
            _print_tool_result(tool, result)
        return results + skipped

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

    return results + skipped


def print_tool_timing(results: List[Dict[str, Any]], top: int = 8) -> None:
    """Show the slowest tools of a run so a slow adapter is visible, not hidden
    in the total. ``results`` are ``run_tool`` dicts (``execution_time`` in s,
    optional ``timeout_budget_s``). Skipped tools (0 s) are left out."""
    rows = []
    for r in results:
        if not isinstance(r, dict):
            continue
        try:
            secs = float(r.get("execution_time") or 0)
        except (TypeError, ValueError):
            continue
        if secs <= 0:
            continue
        status = describe_tool_status(r)
        cached = bool(r.get("from_cache") or (r.get("metadata") or {}).get("from_cache"))
        if cached:
            status += " (cached)"
        rows.append((secs, str(r.get("tool", "?")), status, r.get("timeout_budget_s"), cached))
    if not rows:
        return
    rows.sort(reverse=True)
    # Cached results carry the time of the run that produced them, not this one.
    total = sum(secs for secs, _t, _s, _b, cached in rows if not cached)
    shown = rows[:top]
    if RICH_AVAILABLE and console:
        from rich import box
        from rich.table import Table

        table = Table(
            title=f"Slowest tools (of {len(rows)}, {total:.1f}s tool time)", box=box.SIMPLE
        )
        table.add_column("Tool")
        table.add_column("Status")
        table.add_column("Time (s)", justify="right")
        table.add_column("Budget (s)", justify="right")
        for secs, tool, status, budget, _cached in shown:
            table.add_row(tool, status, f"{secs:.1f}", str(budget) if budget else "-")
        console.print(table)
    else:
        print(f"Slowest tools (of {len(rows)}, {total:.1f}s tool time):")  # noqa: T201
        for secs, tool, status, budget, _cached in shown:
            print(f"  {tool:<24} {status:<22} {secs:7.1f}s  budget={budget or '-'}")  # noqa: T201


def describe_tool_status(result: Dict[str, Any]) -> str:
    """Short human label for a tool result: ``success``, ``success (fallback)``,
    ``skipped (not_installed)``, ``timeout``, ``error``."""
    status = normalize_tool_status(result.get("status"))
    if status == "success":
        return "success (fallback)" if result.get("fallback") else "success"
    if status == "skipped":
        reason = result.get("reason") or "excluded"
        return f"skipped ({reason})"
    return status


def _print_tool_result(tool: str, result: Dict[str, Any]) -> None:
    status = normalize_tool_status(result.get("status"))
    if status == "success":
        findings_count = len(result.get("findings", []))
        tag = " (fallback)" if result.get("fallback") else ""
        success(f"{tool}: {findings_count} findings in {result.get('execution_time', 0):.1f}s{tag}")
    elif status == "skipped":
        reason = result.get("reason") or "excluded"
        detail = "not installed" if reason == "not_installed" else result.get("error") or reason
        info(f"{tool}: skipped ({detail})")
    elif status == "timeout":
        warning(f"{tool}: timeout after {result.get('execution_time', 0):.0f}s")
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


def finding_list(value: Any) -> List[Dict[str, Any]]:
    """Findings from either shape the result files use: a list of findings, or a
    dict with a ``findings`` key (``raw_findings`` is a dict in the audit JSON and a
    list in older files). Non-dict entries are dropped."""
    if isinstance(value, dict):
        value = value.get("findings", [])
    if not isinstance(value, list):
        return []
    return [f for f in value if isinstance(f, dict)]


def results_from_result_file(data: Dict[str, Any], contract: str) -> List[Dict[str, Any]]:
    """Per-tool ``{"tool", "findings"}`` results from any result file MIESC writes.

    ``miesc scan`` / ``audit`` write ``{"results": [...]}``; some older files put a
    flat ``findings`` list at the root; the ML orchestrator behind ``audit full``
    writes ``raw_findings`` (a dict capped to 20 entries) and ``ml_enhanced`` (the
    complete, severity-adjusted list) with no ``results`` key at all. ``report``
    reads all of them; the exporters consume the per-tool list, so the ML shape is
    regrouped by each finding's ``tool``. Unknown shapes degrade to ``[data]``.
    """
    results = data.get("results")
    if isinstance(results, list):
        return [r for r in results if isinstance(r, dict)]
    if isinstance(data.get("findings"), list):
        return [data]

    ml_enhanced = data.get("ml_enhanced")
    findings = finding_list(ml_enhanced)
    if not findings and isinstance(ml_enhanced, dict):
        findings = finding_list(ml_enhanced.get("top_findings"))
    if not findings:
        findings = finding_list(data.get("raw_findings"))
    if not findings:
        return [data]

    contract = str(data.get("contract") or data.get("contract_path") or contract)
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        grouped.setdefault(str(finding.get("tool") or "miesc"), []).append(finding)
    return [
        {"tool": tool, "contract": contract, "status": "success", "findings": tool_findings}
        for tool, tool_findings in grouped.items()
    ]


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
            module_name = f"miesc.adapters.{tool_name}_adapter"
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
