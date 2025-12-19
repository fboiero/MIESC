"""
MIESC Core Module

Re-exports core functionality from src/core/ for the miesc package.
This provides a clean public API while the actual implementation lives in src/.
"""

# Re-export from src/core
try:
    from src.core.optimized_orchestrator import OptimizedOrchestrator as MIESCOrchestrator
    from src.core.ml_orchestrator import MLOrchestrator
    from src.core.persistence import AuditPersistence
    from src.core.result_aggregator import ResultAggregator
    from src.core.config_loader import ConfigLoader
    from src.core.health_checker import HealthChecker
except ImportError:
    # Fallback for when src is not in path
    MIESCOrchestrator = None
    MLOrchestrator = None
    AuditPersistence = None
    ResultAggregator = None
    ConfigLoader = None
    HealthChecker = None

__all__ = [
    "MIESCOrchestrator",
    "MLOrchestrator",
    "AuditPersistence",
    "ResultAggregator",
    "ConfigLoader",
    "HealthChecker",
]
