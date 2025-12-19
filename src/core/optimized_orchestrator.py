"""
MIESC Optimized Orchestrator
Orquestador optimizado con caché, paralelismo mejorado y agregación inteligente.
"""

import os
import time
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from functools import lru_cache

from .config_loader import get_config, MIESCConfig
from .result_aggregator import ResultAggregator
from .tool_discovery import get_tool_discovery, ToolDiscovery

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Entrada de caché para resultados de análisis."""
    tool: str
    contract_hash: str
    results: Dict[str, Any]
    timestamp: datetime
    ttl_seconds: int = 3600

    def is_valid(self) -> bool:
        """Verifica si la entrada de caché sigue siendo válida."""
        age = (datetime.now() - self.timestamp).total_seconds()
        return age < self.ttl_seconds


@dataclass
class AnalysisResult:
    """Resultado de un análisis completo."""
    contract_path: str
    tools_run: List[str]
    tools_success: List[str]
    tools_failed: List[str]
    total_findings: int
    aggregated_findings: int
    cross_validated: int
    severity_counts: Dict[str, int]
    execution_time_ms: float
    timestamp: datetime
    raw_results: Dict[str, Any] = field(default_factory=dict)
    aggregated_results: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'contract_path': self.contract_path,
            'tools_run': self.tools_run,
            'tools_success': self.tools_success,
            'tools_failed': self.tools_failed,
            'total_findings': self.total_findings,
            'aggregated_findings': self.aggregated_findings,
            'cross_validated': self.cross_validated,
            'severity_counts': self.severity_counts,
            'execution_time_ms': round(self.execution_time_ms, 2),
            'timestamp': self.timestamp.isoformat(),
        }


class ResultCache:
    """Caché de resultados de análisis."""

    def __init__(self, cache_dir: Optional[str] = None, ttl_seconds: int = 3600):
        self.cache_dir = Path(cache_dir or os.path.expanduser("~/.miesc/cache"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds
        self._memory_cache: Dict[str, CacheEntry] = {}

    def _compute_hash(self, contract_path: str) -> str:
        """Computa hash del contrato."""
        try:
            with open(contract_path, 'rb') as f:
                content = f.read()
            return hashlib.sha256(content).hexdigest()[:16]
        except Exception:
            return hashlib.sha256(contract_path.encode()).hexdigest()[:16]

    def _get_cache_key(self, tool: str, contract_path: str) -> str:
        """Genera clave de caché."""
        contract_hash = self._compute_hash(contract_path)
        return f"{tool}_{contract_hash}"

    def get(self, tool: str, contract_path: str) -> Optional[Dict[str, Any]]:
        """Obtiene resultado del caché."""
        key = self._get_cache_key(tool, contract_path)

        # Primero verificar memoria
        if key in self._memory_cache:
            entry = self._memory_cache[key]
            if entry.is_valid():
                return entry.results
            else:
                del self._memory_cache[key]

        # Luego verificar disco
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                timestamp = datetime.fromisoformat(data['timestamp'])
                entry = CacheEntry(
                    tool=tool,
                    contract_hash=self._compute_hash(contract_path),
                    results=data['results'],
                    timestamp=timestamp,
                    ttl_seconds=self.ttl_seconds,
                )
                if entry.is_valid():
                    self._memory_cache[key] = entry
                    return entry.results
                else:
                    cache_file.unlink()
            except Exception:
                pass

        return None

    def set(self, tool: str, contract_path: str, results: Dict[str, Any]) -> None:
        """Guarda resultado en caché."""
        key = self._get_cache_key(tool, contract_path)
        entry = CacheEntry(
            tool=tool,
            contract_hash=self._compute_hash(contract_path),
            results=results,
            timestamp=datetime.now(),
            ttl_seconds=self.ttl_seconds,
        )

        # Guardar en memoria
        self._memory_cache[key] = entry

        # Guardar en disco
        cache_file = self.cache_dir / f"{key}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    'tool': tool,
                    'results': results,
                    'timestamp': entry.timestamp.isoformat(),
                }, f)
        except Exception as e:
            logger.warning(f"Failed to persist cache: {e}")

    def clear(self) -> None:
        """Limpia el caché."""
        self._memory_cache.clear()
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except Exception:
                pass


class OptimizedOrchestrator:
    """
    Orquestador optimizado para análisis de smart contracts.

    Características:
    - Caché de resultados con TTL configurable
    - Paralelismo con ThreadPoolExecutor y ProcessPoolExecutor
    - Agregación inteligente de resultados
    - Ejecución por capas con prioridad
    - Callbacks de progreso
    """

    def __init__(
        self,
        config: Optional[MIESCConfig] = None,
        cache_enabled: bool = True,
        max_workers: int = 4,
    ):
        self.config = config or get_config()
        self.discovery = get_tool_discovery()
        self.cache = ResultCache() if cache_enabled else None
        self.max_workers = max_workers
        self.aggregator = ResultAggregator()

    def _run_tool(
        self,
        tool_name: str,
        contract_path: str,
        timeout: int = 120,
    ) -> Dict[str, Any]:
        """Ejecuta una herramienta individual."""
        # Verificar caché
        if self.cache:
            cached = self.cache.get(tool_name, contract_path)
            if cached:
                logger.info(f"Cache hit for {tool_name}")
                return cached

        # Cargar y ejecutar adaptador
        try:
            adapter = self.discovery.load_adapter(tool_name)

            # Obtener timeout de configuración
            adapter_config = self.config.get_adapter_config(tool_name)
            effective_timeout = adapter_config.timeout or timeout

            # Ejecutar análisis
            result = adapter.analyze(contract_path, timeout=effective_timeout)

            # Guardar en caché
            if self.cache and result.get('status') != 'error':
                self.cache.set(tool_name, contract_path, result)

            return result

        except Exception as e:
            return {
                'tool': tool_name,
                'status': 'error',
                'error': str(e),
                'findings': [],
            }

    def analyze(
        self,
        contract_path: str,
        tools: Optional[List[str]] = None,
        layers: Optional[List[str]] = None,
        timeout: int = 120,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ) -> AnalysisResult:
        """
        Ejecuta análisis completo de un contrato.

        Args:
            contract_path: Ruta al contrato Solidity
            tools: Lista de herramientas a usar (opcional)
            layers: Lista de capas a ejecutar (opcional)
            timeout: Timeout por herramienta
            progress_callback: Callback(tool_name, status) para progreso

        Returns:
            AnalysisResult con todos los hallazgos
        """
        start_time = time.time()

        # Determinar herramientas a ejecutar
        tools_to_run = self._determine_tools(tools, layers)

        if not tools_to_run:
            return AnalysisResult(
                contract_path=contract_path,
                tools_run=[],
                tools_success=[],
                tools_failed=[],
                total_findings=0,
                aggregated_findings=0,
                cross_validated=0,
                severity_counts={},
                execution_time_ms=0,
                timestamp=datetime.now(),
            )

        # Ejecutar herramientas en paralelo
        raw_results: Dict[str, Dict[str, Any]] = {}
        tools_success: List[str] = []
        tools_failed: List[str] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_tool = {
                executor.submit(self._run_tool, tool, contract_path, timeout): tool
                for tool in tools_to_run
            }

            for future in as_completed(future_to_tool):
                tool = future_to_tool[future]
                try:
                    result = future.result(timeout=timeout + 30)
                    raw_results[tool] = result

                    if result.get('status') == 'error':
                        tools_failed.append(tool)
                    else:
                        tools_success.append(tool)

                    if progress_callback:
                        status = 'success' if tool in tools_success else 'failed'
                        progress_callback(tool, status)

                except Exception as e:
                    tools_failed.append(tool)
                    raw_results[tool] = {
                        'tool': tool,
                        'status': 'error',
                        'error': str(e),
                        'findings': [],
                    }
                    if progress_callback:
                        progress_callback(tool, 'failed')

        # Agregar resultados
        self.aggregator.clear()
        total_findings = 0

        for tool, result in raw_results.items():
            if result.get('status') != 'error':
                count = self.aggregator.add_tool_results(tool, result)
                total_findings += count

        aggregated = self.aggregator.aggregate()
        stats = self.aggregator.get_statistics()

        execution_time = (time.time() - start_time) * 1000

        return AnalysisResult(
            contract_path=contract_path,
            tools_run=tools_to_run,
            tools_success=tools_success,
            tools_failed=tools_failed,
            total_findings=total_findings,
            aggregated_findings=len(aggregated),
            cross_validated=stats.get('cross_validated', 0),
            severity_counts=stats.get('severity_distribution', {}),
            execution_time_ms=execution_time,
            timestamp=datetime.now(),
            raw_results=raw_results,
            aggregated_results=self.aggregator.to_report(),
        )

    def _determine_tools(
        self,
        tools: Optional[List[str]] = None,
        layers: Optional[List[str]] = None,
    ) -> List[str]:
        """Determina qué herramientas ejecutar."""
        if tools:
            # Filtrar solo herramientas disponibles
            available = {t.name for t in self.discovery.get_available_tools()}
            return [t for t in tools if t in available]

        if layers:
            # Obtener herramientas de las capas especificadas
            tools_by_layer = self.discovery.get_tools_by_layer()
            result = []
            for layer in layers:
                if layer in tools_by_layer:
                    for tool in tools_by_layer[layer]:
                        if tool.available:
                            result.append(tool.name)
            return result

        # Por defecto, usar herramientas habilitadas en configuración
        enabled = self.config.get_enabled_adapters()
        available = {t.name for t in self.discovery.get_available_tools()}
        return [t for t in enabled if t in available]

    def analyze_batch(
        self,
        contract_paths: List[str],
        tools: Optional[List[str]] = None,
        timeout: int = 120,
        progress_callback: Optional[Callable[[str, str, str], None]] = None,
        parallel_contracts: int = 2,
    ) -> Dict[str, AnalysisResult]:
        """
        Analiza múltiples contratos en paralelo.

        Args:
            contract_paths: Lista de rutas a contratos
            tools: Herramientas a usar
            timeout: Timeout por herramienta
            progress_callback: Callback(contract, tool, status)
            parallel_contracts: Número de contratos a analizar en paralelo

        Returns:
            Dict de contract_path -> AnalysisResult
        """
        results: Dict[str, AnalysisResult] = {}

        def analyze_contract(contract_path: str) -> tuple:
            """Wrapper para análisis de contrato individual."""
            def wrapped_callback(tool: str, status: str) -> None:
                if progress_callback:
                    progress_callback(contract_path, tool, status)

            result = self.analyze(
                contract_path=contract_path,
                tools=tools,
                timeout=timeout,
                progress_callback=wrapped_callback,
            )
            return contract_path, result

        # Procesar contratos en paralelo
        with ThreadPoolExecutor(max_workers=parallel_contracts) as executor:
            futures = [
                executor.submit(analyze_contract, path)
                for path in contract_paths
            ]

            for future in as_completed(futures):
                try:
                    contract_path, result = future.result(timeout=timeout * len(tools or []) + 60)
                    results[contract_path] = result
                except Exception as e:
                    # Si falla, crear resultado de error
                    contract_path = contract_paths[futures.index(future)]
                    results[contract_path] = AnalysisResult(
                        contract_path=contract_path,
                        tools_run=[],
                        tools_success=[],
                        tools_failed=['batch_error'],
                        total_findings=0,
                        aggregated_findings=0,
                        cross_validated=0,
                        severity_counts={},
                        execution_time_ms=0,
                        timestamp=datetime.now(),
                    )

        return results

    def quick_scan(self, contract_path: str, timeout: int = 60) -> AnalysisResult:
        """
        Escaneo rápido usando solo herramientas de análisis estático.
        """
        return self.analyze(
            contract_path=contract_path,
            layers=['static_analysis'],
            timeout=timeout,
        )

    def deep_scan(self, contract_path: str, timeout: int = 300) -> AnalysisResult:
        """
        Escaneo profundo usando todas las capas.
        """
        return self.analyze(
            contract_path=contract_path,
            timeout=timeout,
        )

    def clear_cache(self) -> None:
        """Limpia el caché de resultados."""
        if self.cache:
            self.cache.clear()

    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Obtiene métricas de rendimiento del orquestador.

        Returns:
            Dict con métricas de caché y ejecución
        """
        metrics = {
            'max_workers': self.max_workers,
            'cache_enabled': self.cache is not None,
            'available_tools': len(self.discovery.get_available_tools()),
        }

        if self.cache:
            metrics['cache'] = {
                'memory_entries': len(self.cache._memory_cache),
                'cache_dir': str(self.cache.cache_dir),
                'ttl_seconds': self.cache.ttl_seconds,
            }

        return metrics

    def warmup_cache(self, contract_path: str, tools: Optional[List[str]] = None) -> int:
        """
        Pre-calienta el caché ejecutando herramientas rápidas.

        Args:
            contract_path: Ruta al contrato
            tools: Herramientas específicas (default: static_analysis)

        Returns:
            Número de entradas de caché creadas
        """
        if not self.cache:
            return 0

        # Por defecto, solo calentar con análisis estático (rápido)
        target_tools = tools or ['slither', 'aderyn', 'solhint']
        available = {t.name for t in self.discovery.get_available_tools()}
        tools_to_run = [t for t in target_tools if t in available]

        cached = 0
        for tool in tools_to_run:
            if self.cache.get(tool, contract_path) is None:
                result = self._run_tool(tool, contract_path, timeout=30)
                if result.get('status') != 'error':
                    cached += 1

        return cached
