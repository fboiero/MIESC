"""MIESC Core - Core functionality for security analysis."""

# Re-export from src/core
try:
    from src.core.correlation_api import CorrelatedFinding as CorrelationResult
    from src.core.correlation_api import SmartCorrelationEngine as CorrelationEngine
    from src.core.health_checker import HealthChecker
    from src.core.metrics import MetricsCollector
    from src.core.persistence import PersistenceLayer
    from src.core.result_aggregator import ResultAggregator
    from src.core.tool_discovery import ToolDiscovery

    __all__ = [
        "CorrelationEngine",
        "CorrelationResult",
        "ResultAggregator",
        "HealthChecker",
        "ToolDiscovery",
        "MetricsCollector",
        "PersistenceLayer",
    ]
except ImportError:
    __all__ = []
