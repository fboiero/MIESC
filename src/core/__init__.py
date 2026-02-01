"""
MIESC Core Module v4.1.0
Componentes centrales del sistema MIESC.
"""

from .config_loader import AdapterConfig, LayerConfig, MIESCConfig, get_config
from .exporters import (
    CheckmarxExporter,
    JSONExporter,
    MarkdownExporter,
    ReportExporter,
    SARIFExporter,
    SonarQubeExporter,
)
from .exporters import (
    Finding as ExportFinding,
)
from .framework_detector import (
    Framework,
    FrameworkConfig,
    FrameworkDetector,
    detect_framework,
    get_framework_name,
    is_foundry_project,
    is_hardhat_project,
)
from .health_checker import HealthChecker, HealthStatus, SystemHealth, ToolHealth
from .metrics import (
    InternalMetricsCollector,
    MIESCMetrics,
    get_metrics,
    reset_metrics,
    timed,
)
from .ml_orchestrator import MLAnalysisResult, MLOrchestrator, get_ml_orchestrator
from .optimized_orchestrator import AnalysisResult, OptimizedOrchestrator, ResultCache
from .persistence import (
    AuditRecord,
    AuditStatus,
    FindingRecord,
    MIESCDatabase,
    get_database,
    reset_database,
)
from .result_aggregator import AggregatedFinding, Finding, ResultAggregator
from .rich_cli import (
    RICH_AVAILABLE,
    MIESCRichCLI,
    SeverityStyle,
    create_cli,
)
from .tool_discovery import ToolDiscovery, ToolInfo, get_tool_discovery
from .websocket_api import (
    WEBSOCKET_AVAILABLE,
    AuditProgressTracker,
    ConnectionManager,
    EventType,
    WebSocketEvent,
    WebSocketServer,
    create_progress_tracker,
    create_websocket_app,
    get_connection_manager,
)

__all__ = [
    # Config
    "MIESCConfig",
    "get_config",
    "AdapterConfig",
    "LayerConfig",
    # Result Aggregation
    "ResultAggregator",
    "Finding",
    "AggregatedFinding",
    # Health Checks
    "HealthChecker",
    "HealthStatus",
    "ToolHealth",
    "SystemHealth",
    # Tool Discovery
    "ToolDiscovery",
    "ToolInfo",
    "get_tool_discovery",
    # Orchestrator
    "OptimizedOrchestrator",
    "AnalysisResult",
    "ResultCache",
    # ML Orchestrator
    "MLOrchestrator",
    "MLAnalysisResult",
    "get_ml_orchestrator",
    # Persistence
    "MIESCDatabase",
    "AuditRecord",
    "FindingRecord",
    "AuditStatus",
    "get_database",
    "reset_database",
    # Metrics
    "MIESCMetrics",
    "get_metrics",
    "reset_metrics",
    "InternalMetricsCollector",
    "timed",
    # Exporters
    "ExportFinding",
    "SARIFExporter",
    "SonarQubeExporter",
    "CheckmarxExporter",
    "MarkdownExporter",
    "JSONExporter",
    "ReportExporter",
    # WebSocket
    "EventType",
    "WebSocketEvent",
    "ConnectionManager",
    "AuditProgressTracker",
    "WebSocketServer",
    "create_websocket_app",
    "get_connection_manager",
    "create_progress_tracker",
    "WEBSOCKET_AVAILABLE",
    # Rich CLI
    "MIESCRichCLI",
    "SeverityStyle",
    "create_cli",
    "RICH_AVAILABLE",
    # Framework Detection
    "Framework",
    "FrameworkConfig",
    "FrameworkDetector",
    "detect_framework",
    "get_framework_name",
    "is_foundry_project",
    "is_hardhat_project",
]
