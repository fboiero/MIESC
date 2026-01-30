"""
MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

A comprehensive blockchain security framework with 9 defense layers,
32 security tools, and AI-powered correlation.

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
"""

__version__ = "4.5.3"
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
    "FalsePositiveFilter": ("src.ml", "FalsePositiveFilter"),
    "SeverityPredictor": ("src.ml", "SeverityPredictor"),
    "VulnerabilityClusterer": ("src.ml", "VulnerabilityClusterer"),
    "CodeEmbeddings": ("src.ml", "CodeEmbeddings"),
    # Security
    "InputValidator": ("src.security", "validate_contract_path"),
    "APIRateLimiter": ("src.security", "RateLimiter"),
    "SecureLogger": ("src.security", "SecureFormatter"),
    "ComplianceMapper": ("src.security.compliance_mapper", "ComplianceMapper"),
    "RemediationEngine": ("src.security", "RemediationEngine"),
}

_loaded_modules = {}


def __getattr__(name: str):
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
                raise ImportError(
                    f"Cannot import {name} from {module_path}: {e}"
                ) from e

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
