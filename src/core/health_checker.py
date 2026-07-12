"""
MIESC Health Checker
Sistema de health checks y observabilidad para todas las herramientas.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Estados de salud posibles."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ToolHealth:
    """Estado de salud de una herramienta."""

    name: str
    status: HealthStatus
    available: bool
    version: Optional[str] = None
    response_time_ms: float = 0.0
    last_check: Optional[datetime] = None
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "available": self.available,
            "version": self.version,
            "response_time_ms": round(self.response_time_ms, 2),
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "error_message": self.error_message,
            "details": self.details,
        }


@dataclass
class SystemHealth:
    """Estado de salud general del sistema."""

    status: HealthStatus
    total_tools: int
    healthy_tools: int
    degraded_tools: int
    unhealthy_tools: int
    tools: List[ToolHealth]
    check_duration_ms: float
    timestamp: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "summary": {
                "total": self.total_tools,
                "healthy": self.healthy_tools,
                "degraded": self.degraded_tools,
                "unhealthy": self.unhealthy_tools,
            },
            "tools": [t.to_dict() for t in self.tools],
            "check_duration_ms": round(self.check_duration_ms, 2),
            "timestamp": self.timestamp.isoformat(),
        }


class HealthChecker:
    """
    Verificador de salud para todas las herramientas MIESC.

    Proporciona:
    - Health checks individuales por herramienta
    - Health check global del sistema
    - Métricas de disponibilidad
    - Tiempos de respuesta
    """

    # Mapeo de adaptadores a sus clases
    ADAPTER_MAP = {
        "slither": ("miesc.adapters.slither_adapter", "SlitherAdapter"),
        "mythril": ("miesc.adapters.mythril_adapter", "MythrilAdapter"),
        "aderyn": ("miesc.adapters.aderyn_adapter", "AderynAdapter"),
        "solhint": ("miesc.adapters.solhint_adapter", "SolhintAdapter"),
        "echidna": ("miesc.adapters.echidna_adapter", "EchidnaAdapter"),
        "foundry": ("miesc.adapters.foundry_adapter", "FoundryAdapter"),
        "medusa": ("miesc.adapters.medusa_adapter", "MedusaAdapter"),
        "dogefuzz": ("miesc.adapters.dogefuzz_adapter", "DogeFuzzAdapter"),
        "manticore": ("miesc.adapters.manticore_adapter", "ManticoreAdapter"),
        "halmos": ("miesc.adapters.halmos_adapter", "HalmosAdapter"),
        "smtchecker": ("miesc.adapters.smtchecker_adapter", "SMTCheckerAdapter"),
        "certora": ("miesc.adapters.certora_adapter", "CertoraAdapter"),
        "wake": ("miesc.adapters.wake_adapter", "WakeAdapter"),
        "propertygpt": ("miesc.adapters.propertygpt_adapter", "PropertyGPTAdapter"),
        "smartllm": ("miesc.adapters.smartllm_adapter", "SmartLLMAdapter"),
        "gptscan": ("miesc.adapters.gptscan_adapter", "GPTScanAdapter"),
        "llmsmartaudit": ("miesc.adapters.llmsmartaudit_adapter", "LLMSmartAuditAdapter"),
        "gas_analyzer": ("miesc.adapters.gas_analyzer_adapter", "GasAnalyzerAdapter"),
        "mev_detector": ("miesc.adapters.mev_detector_adapter", "MEVDetectorAdapter"),
        "threat_model": ("miesc.adapters.threat_model_adapter", "ThreatModelAdapter"),
        "smartbugs_ml": ("miesc.adapters.smartbugs_ml_adapter", "SmartBugsMLAdapter"),
        "dagnn": ("miesc.adapters.dagnn_adapter", "DAGNNAdapter"),
        "contract_clone_detector": (
            "miesc.adapters.contract_clone_detector_adapter",
            "ContractCloneDetectorAdapter",
        ),
    }

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self._cache: Dict[str, ToolHealth] = {}
        self._cache_ttl = 60  # segundos

    def _load_adapter(self, tool_name: str) -> Any:
        """Carga dinámicamente un adaptador."""
        if tool_name not in self.ADAPTER_MAP:
            return None

        module_path, class_name = self.ADAPTER_MAP[tool_name]
        try:
            import importlib

            module = importlib.import_module(module_path)
            adapter_class = getattr(module, class_name)
            return adapter_class()
        except Exception as e:
            logger.debug(f"Could not load adapter {tool_name}: {e}")
            return None

    def check_tool(self, tool_name: str, use_cache: bool = True) -> ToolHealth:
        """
        Verifica la salud de una herramienta específica.
        """
        # Verificar caché
        if use_cache and tool_name in self._cache:
            cached = self._cache[tool_name]
            if cached.last_check:
                age = (datetime.now() - cached.last_check).total_seconds()
                if age < self._cache_ttl:
                    return cached

        start_time = time.time()

        try:
            adapter = self._load_adapter(tool_name)

            if adapter is None:
                return ToolHealth(
                    name=tool_name,
                    status=HealthStatus.UNKNOWN,
                    available=False,
                    last_check=datetime.now(),
                    error_message="Adapter not found",
                )

            # Verificar disponibilidad
            is_available = adapter.is_available()
            response_time = (time.time() - start_time) * 1000

            # Obtener metadata si está disponible
            version = None
            details = {}

            try:
                metadata = adapter.get_metadata()
                version = getattr(metadata, "version", None)
                details = {
                    "layer": getattr(metadata, "layer", "unknown"),
                    "category": getattr(metadata, "category", "unknown"),
                }
            except Exception:
                pass

            # Determinar estado
            if is_available:
                status = HealthStatus.HEALTHY
            else:
                status = HealthStatus.UNHEALTHY

            health = ToolHealth(
                name=tool_name,
                status=status,
                available=is_available,
                version=version,
                response_time_ms=response_time,
                last_check=datetime.now(),
                details=details,
            )

            # Actualizar caché
            self._cache[tool_name] = health
            return health

        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            health = ToolHealth(
                name=tool_name,
                status=HealthStatus.UNHEALTHY,
                available=False,
                response_time_ms=response_time,
                last_check=datetime.now(),
                error_message=str(e),
            )
            self._cache[tool_name] = health
            return health

    def check_all(self, tools: Optional[List[str]] = None) -> SystemHealth:
        """
        Verifica la salud de todas las herramientas.
        """
        start_time = time.time()

        if tools is None:
            tools = list(self.ADAPTER_MAP.keys())

        tool_healths: List[ToolHealth] = []

        # Ejecutar checks en paralelo
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_tool = {executor.submit(self.check_tool, tool, False): tool for tool in tools}

            for future in as_completed(future_to_tool):
                try:
                    health = future.result(timeout=30)
                    tool_healths.append(health)
                except Exception as e:
                    tool_name = future_to_tool[future]
                    tool_healths.append(
                        ToolHealth(
                            name=tool_name,
                            status=HealthStatus.UNHEALTHY,
                            available=False,
                            last_check=datetime.now(),
                            error_message=str(e),
                        )
                    )

        # Calcular estadísticas
        healthy = sum(1 for t in tool_healths if t.status == HealthStatus.HEALTHY)
        degraded = sum(1 for t in tool_healths if t.status == HealthStatus.DEGRADED)
        unhealthy = sum(1 for t in tool_healths if t.status == HealthStatus.UNHEALTHY)

        # Determinar estado general
        if unhealthy == 0:
            overall_status = HealthStatus.HEALTHY
        elif healthy > unhealthy:
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.UNHEALTHY

        check_duration = (time.time() - start_time) * 1000

        return SystemHealth(
            status=overall_status,
            total_tools=len(tool_healths),
            healthy_tools=healthy,
            degraded_tools=degraded,
            unhealthy_tools=unhealthy,
            tools=sorted(tool_healths, key=lambda x: x.name),
            check_duration_ms=check_duration,
            timestamp=datetime.now(),
        )

    def get_available_tools(self) -> List[str]:
        """Retorna lista de herramientas disponibles."""
        health = self.check_all()
        return [t.name for t in health.tools if t.available]

    def get_tools_by_layer(self) -> Dict[str, List[str]]:
        """Agrupa herramientas disponibles por capa."""
        health = self.check_all()
        layers: Dict[str, List[str]] = {}

        for tool in health.tools:
            if tool.available:
                layer = tool.details.get("layer", "other")
                if layer not in layers:
                    layers[layer] = []
                layers[layer].append(tool.name)

        return layers

    def clear_cache(self) -> None:
        """Limpia el caché de health checks."""
        self._cache.clear()


# FastAPI endpoints para health checks
def create_health_endpoints() -> Any:
    """Crea endpoints de health check para FastAPI."""
    from fastapi import APIRouter

    router = APIRouter(prefix="/health", tags=["health"])
    checker = HealthChecker()

    @router.get("/")
    async def health_check() -> Dict[str, Any]:
        """Health check básico."""
        return {"status": "healthy", "service": "MIESC"}

    @router.get("/tools")
    async def tools_health() -> Dict[str, Any]:
        """Health check de todas las herramientas."""
        health = checker.check_all()
        return health.to_dict()

    @router.get("/tools/{tool_name}")
    async def tool_health(tool_name: str) -> Dict[str, Any]:
        """Health check de una herramienta específica."""
        health = checker.check_tool(tool_name)
        return health.to_dict()

    @router.get("/available")
    async def available_tools() -> Dict[str, Any]:
        """Lista de herramientas disponibles."""
        return {"tools": checker.get_available_tools()}

    @router.get("/layers")
    async def tools_by_layer() -> Dict[str, Any]:
        """Herramientas agrupadas por capa."""
        return checker.get_tools_by_layer()

    return router
