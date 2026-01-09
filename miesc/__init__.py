"""
MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

A comprehensive blockchain security framework with 9 defense layers,
32 security tools, and AI-powered correlation.

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
"""

__version__ = "4.3.2"
__author__ = "Fernando Boiero"
__email__ = "fboiero@frvm.utn.edu.ar"

# Re-export from src packages
import sys
from pathlib import Path

# Add src to path for re-exports
_src_path = Path(__file__).parent.parent / "src"
if str(_src_path) not in sys.path:
    sys.path.insert(0, str(_src_path))

# Import core modules from src/
try:
    from src.core.correlation_api import SmartCorrelationEngine as CorrelationEngine
    from src.core.result_aggregator import ResultAggregator
    from src.core.tool_protocol import ToolAdapter, ToolStatus
    from src.ml import (
        CodeEmbeddings,
        FalsePositiveFilter,
        SeverityPredictor,
        VulnerabilityClusterer,
    )
    from src.security import (
        RateLimiter as APIRateLimiter,
    )
    from src.security import (
        RemediationEngine,
    )
    from src.security import (
        SecureFormatter as SecureLogger,
    )
    from src.security import (
        validate_contract_path as InputValidator,
    )
    from src.security.compliance_mapper import ComplianceMapper
except ImportError:
    pass  # Optional - may not be available in all environments

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
