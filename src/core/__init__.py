"""
MIESC Core Module v4.1.0
Componentes centrales del sistema MIESC.
"""

from .config_loader import MIESCConfig, get_config, AdapterConfig, LayerConfig
from .result_aggregator import ResultAggregator, Finding, AggregatedFinding
from .health_checker import HealthChecker, HealthStatus, ToolHealth, SystemHealth
from .tool_discovery import ToolDiscovery, ToolInfo, get_tool_discovery
from .optimized_orchestrator import OptimizedOrchestrator, AnalysisResult, ResultCache
from .ml_orchestrator import MLOrchestrator, MLAnalysisResult, get_ml_orchestrator
from .persistence import (
    MIESCDatabase,
    AuditRecord,
    FindingRecord,
    AuditStatus,
    get_database,
    reset_database,
)
from .metrics import (
    MIESCMetrics,
    get_metrics,
    reset_metrics,
    InternalMetricsCollector,
    timed,
)
from .exporters import (
    Finding as ExportFinding,
    SARIFExporter,
    SonarQubeExporter,
    CheckmarxExporter,
    MarkdownExporter,
    JSONExporter,
    ReportExporter,
)
from .websocket_api import (
    EventType,
    WebSocketEvent,
    ConnectionManager,
    AuditProgressTracker,
    WebSocketServer,
    create_websocket_app,
    get_connection_manager,
    create_progress_tracker,
    WEBSOCKET_AVAILABLE,
)
from .rich_cli import (
    MIESCRichCLI,
    SeverityStyle,
    create_cli,
    RICH_AVAILABLE,
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

__all__ = [
    # Config
    'MIESCConfig',
    'get_config',
    'AdapterConfig',
    'LayerConfig',
    # Result Aggregation
    'ResultAggregator',
    'Finding',
    'AggregatedFinding',
    # Health Checks
    'HealthChecker',
    'HealthStatus',
    'ToolHealth',
    'SystemHealth',
    # Tool Discovery
    'ToolDiscovery',
    'ToolInfo',
    'get_tool_discovery',
    # Orchestrator
    'OptimizedOrchestrator',
    'AnalysisResult',
    'ResultCache',
    # ML Orchestrator
    'MLOrchestrator',
    'MLAnalysisResult',
    'get_ml_orchestrator',
    # Persistence
    'MIESCDatabase',
    'AuditRecord',
    'FindingRecord',
    'AuditStatus',
    'get_database',
    'reset_database',
    # Metrics
    'MIESCMetrics',
    'get_metrics',
    'reset_metrics',
    'InternalMetricsCollector',
    'timed',
    # Exporters
    'ExportFinding',
    'SARIFExporter',
    'SonarQubeExporter',
    'CheckmarxExporter',
    'MarkdownExporter',
    'JSONExporter',
    'ReportExporter',
    # WebSocket
    'EventType',
    'WebSocketEvent',
    'ConnectionManager',
    'AuditProgressTracker',
    'WebSocketServer',
    'create_websocket_app',
    'get_connection_manager',
    'create_progress_tracker',
    'WEBSOCKET_AVAILABLE',
    # Rich CLI
    'MIESCRichCLI',
    'SeverityStyle',
    'create_cli',
    'RICH_AVAILABLE',
    # Framework Detection
    'Framework',
    'FrameworkConfig',
    'FrameworkDetector',
    'detect_framework',
    'get_framework_name',
    'is_foundry_project',
    'is_hardhat_project',
]
