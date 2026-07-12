"""
MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

A comprehensive blockchain security framework with 9 defense layers,
a configured adapter stack, and AI-powered correlation.

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
"""

from typing import Any

__version__ = "5.4.3"
__author__ = "Fernando Boiero"
__email__ = "fboiero@frvm.utn.edu.ar"

# Lazy imports - heavy modules are only loaded when accessed
_lazy_imports = {
    # Core
    "ToolAdapter": ("src.core.tool_protocol", "ToolAdapter"),
    "ToolStatus": ("src.core.tool_protocol", "ToolStatus"),
    "CorrelationEngine": ("src.core.correlation_api", "SmartCorrelationEngine"),
    "ResultAggregator": ("src.core.result_aggregator", "ResultAggregator"),
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
