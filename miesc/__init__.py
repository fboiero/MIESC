"""
MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

A comprehensive blockchain security framework with 9 defense layers,
a configured adapter stack, and AI-powered correlation.

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
"""

import sys as _sys
from typing import Any, Optional, Sequence

# --- Python version guard (runs on `import miesc`, before any 3.12+ import) ---
# MIESC targets Python >= 3.12 (see pyproject `requires-python`). When the
# `miesc` console script is installed for an older interpreter, importing the
# package otherwise fails with a cryptic error far from the real cause — a
# runtime `TypeError` on PEP 604 `X | None` annotations under 3.9, or a
# `ModuleNotFoundError` for a dependency only installed for the newer
# interpreter. `import miesc` runs first in every entry path, so a fail-fast
# check here turns all of those into one clear, actionable message.
#
# This block uses only typing generics (`Optional`/`Tuple`), never a runtime
# `X | None`, so it stays importable and callable under Python < 3.10.
_MIN_PYTHON = (3, 12)


def _python_version_error(
    version_info: Sequence[int],
    executable: str = _sys.executable,
) -> Optional[str]:
    """Return an actionable error message if the interpreter is too old, else None.

    ``version_info`` is a sequence of the interpreter's ``(major, minor, ...)``
    version parts. Kept as a small pure function so the version policy can be
    unit-tested without spawning an unsupported interpreter.
    """
    if tuple(version_info[:2]) >= _MIN_PYTHON:
        return None
    detected = ".".join(str(part) for part in version_info[:3])
    minimum = ".".join(str(part) for part in _MIN_PYTHON)
    return (
        f"MIESC requires Python >= {minimum}, but is running under Python {detected} "
        f"({executable}). The 'miesc' console script was likely installed for an older "
        f"interpreter. Reinstall it under Python {minimum}+ (for example "
        f"'pipx install miesc' or 'uv tool install miesc'), or run it with a "
        f"{minimum}+ interpreter via 'python3 -m miesc'."
    )


# `sys.version_info` mixes ints and a str (releaselevel); pass just the numeric
# parts so the policy's type stays a clean Sequence[int].
_version_error = _python_version_error(tuple(int(_p) for _p in _sys.version_info[:3]))
if _version_error:  # pragma: no cover - exercised via subprocess test
    raise RuntimeError(_version_error)
# -----------------------------------------------------------------------------

__version__ = "6.8.0"
__author__ = "Fernando Boiero"
__email__ = "fboiero@frvm.utn.edu.ar"

# Lazy imports - heavy modules are only loaded when accessed
_lazy_imports = {
    # Core
    "ToolAdapter": ("miesc.core.tool_protocol", "ToolAdapter"),
    "ToolStatus": ("miesc.core.tool_protocol", "ToolStatus"),
    "CorrelationEngine": ("miesc.core.correlation_api", "SmartCorrelationEngine"),
    "ResultAggregator": ("miesc.core.result_aggregator", "ResultAggregator"),
    # ML
    "FalsePositiveFilter": ("miesc.ml", "FalsePositiveFilter"),
    "SeverityPredictor": ("miesc.ml", "SeverityPredictor"),
    "VulnerabilityClusterer": ("miesc.ml", "VulnerabilityClusterer"),
    "CodeEmbeddings": ("miesc.ml", "CodeEmbeddings"),
    # Security
    "InputValidator": ("miesc.security", "validate_contract_path"),
    "APIRateLimiter": ("miesc.security", "RateLimiter"),
    "SecureLogger": ("miesc.security", "SecureFormatter"),
    "ComplianceMapper": ("miesc.security.compliance_mapper", "ComplianceMapper"),
    "RemediationEngine": ("miesc.security", "RemediationEngine"),
}

_loaded_modules: dict[str, Any] = {}


def __getattr__(name: str) -> Any:
    """Lazy import handler for heavy modules."""
    if name in _lazy_imports:
        if name not in _loaded_modules:
            import sys
            from pathlib import Path

            # Ensure src is in path
            _src_path = Path(__file__).parent.parent / "src"
            if str(_src_path) not in sys.path:
                sys.path.insert(0, str(_src_path))

            module_path, attr_name = _lazy_imports[name]
            try:
                import importlib

                module = importlib.import_module(module_path)
                _loaded_modules[name] = getattr(module, attr_name)
            except (ImportError, AttributeError) as e:
                raise ImportError(f"Cannot import {name} from {module_path}: {e}") from e

        return _loaded_modules[name]

    raise AttributeError(f"module 'miesc' has no attribute '{name}'")


__all__ = [
    "__version__",
    "__author__",
    "__email__",
    # Core
    "ToolAdapter",
    "ToolStatus",
    "CorrelationEngine",
    "ResultAggregator",
    # ML
    "FalsePositiveFilter",
    "SeverityPredictor",
    "VulnerabilityClusterer",
    "CodeEmbeddings",
    # Security
    "InputValidator",
    "APIRateLimiter",
    "SecureLogger",
    "ComplianceMapper",
    "RemediationEngine",
]
