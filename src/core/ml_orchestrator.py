"""
MIESC ML-Enhanced Orchestrator
Orquestador con integración completa del pipeline ML.
"""

import os
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, TYPE_CHECKING
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

if TYPE_CHECKING:
    from ..ml import MLPipeline, VulnerabilityCluster

from .config_loader import get_config, MIESCConfig
from .result_aggregator import ResultAggregator
from .tool_discovery import get_tool_discovery
from .optimized_orchestrator import OptimizedOrchestrator, AnalysisResult, ResultCache

# ML components imported lazily to avoid circular imports
# from ..ml import MLPipeline, MLEnhancedResult, FeedbackType, VulnerabilityCluster, get_ml_pipeline

logger = logging.getLogger(__name__)


@dataclass
class MLAnalysisResult:
    """Resultado de análisis con mejoras ML."""
    # Base analysis
    contract_path: str
    contract_source: str
    tools_run: List[str]
    tools_success: List[str]
    tools_failed: List[str]

    # Raw findings
    total_raw_findings: int
    raw_findings: List[Dict[str, Any]]

    # ML-enhanced findings
    ml_filtered_findings: List[Dict[str, Any]]
    ml_filtered_out: List[Dict[str, Any]]
    false_positives_removed: int
    severity_adjustments: int

    # Clustering
    clusters: List[Any]  # VulnerabilityCluster - lazy import
    cluster_count: int

    # Remediation
    remediation_plan: List[Dict[str, Any]]

    # Pattern matching
    pattern_matches: List[Dict[str, Any]]

    # Metrics
    severity_distribution: Dict[str, int]
    cross_validated: int
    execution_time_ms: float
    ml_processing_time_ms: float
    timestamp: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Convierte resultado a diccionario."""
        return {
            'contract_path': self.contract_path,
            'tools_run': self.tools_run,
            'tools_success': self.tools_success,
            'tools_failed': self.tools_failed,
            'raw_findings': {
                'total': self.total_raw_findings,
                'findings': self.raw_findings[:20],  # Limit for output
            },
            'ml_enhanced': {
                'filtered_count': len(self.ml_filtered_findings),
                'findings': self.ml_filtered_findings,
                'false_positives_removed': self.false_positives_removed,
                'severity_adjustments': self.severity_adjustments,
                'top_findings': self.ml_filtered_findings[:10],
            },
            'clusters': {
                'count': self.cluster_count,
                'clusters': [c.to_dict() for c in self.clusters],
            },
            'remediation_plan': self.remediation_plan[:10],
            'pattern_matches': self.pattern_matches[:5],
            'metrics': {
                'severity_distribution': self.severity_distribution,
                'cross_validated': self.cross_validated,
                'execution_time_ms': round(self.execution_time_ms, 2),
                'ml_processing_time_ms': round(self.ml_processing_time_ms, 2),
            },
            'timestamp': self.timestamp.isoformat(),
        }

    def get_summary(self) -> Dict[str, Any]:
        """Obtiene resumen ejecutivo del análisis."""
        critical_count = self.severity_distribution.get('critical', 0)
        high_count = self.severity_distribution.get('high', 0)

        return {
            'risk_level': self._calculate_risk_level(),
            'total_findings': len(self.ml_filtered_findings),
            'critical': critical_count,
            'high': high_count,
            'medium': self.severity_distribution.get('medium', 0),
            'low': self.severity_distribution.get('low', 0),
            'clusters': self.cluster_count,
            'fp_removed': self.false_positives_removed,
            'reduction_rate': round(
                self.false_positives_removed / max(self.total_raw_findings, 1) * 100, 1
            ),
            'priority_actions': len([
                p for p in self.remediation_plan
                if p.get('severity') in ['critical', 'high']
            ]),
        }

    def _calculate_risk_level(self) -> str:
        """Calcula nivel de riesgo global."""
        critical = self.severity_distribution.get('critical', 0)
        high = self.severity_distribution.get('high', 0)

        if critical > 0:
            return 'CRITICAL'
        elif high > 2:
            return 'HIGH'
        elif high > 0:
            return 'MEDIUM'
        else:
            return 'LOW'


class MLOrchestrator:
    """
    Orquestador con integración ML completa.

    Características:
    - Ejecuta herramientas de análisis en paralelo
    - Aplica pipeline ML automáticamente
    - Filtra falsos positivos
    - Ajusta severidades
    - Agrupa en clusters
    - Genera plan de remediación
    - Soporta feedback de usuario

    Ejemplo de uso:
        orchestrator = MLOrchestrator()
        result = orchestrator.analyze('contract.sol')
        print(f"Risk: {result.get_summary()['risk_level']}")
        print(f"FPs removed: {result.false_positives_removed}")
    """

    def __init__(
        self,
        config: Optional[MIESCConfig] = None,
        cache_enabled: bool = True,
        max_workers: int = 4,
        ml_enabled: bool = True,
        fp_threshold: float = 0.6,
    ):
        self.config = config or get_config()
        self.discovery = get_tool_discovery()
        self.cache = ResultCache() if cache_enabled else None
        self.max_workers = max_workers
        self.aggregator = ResultAggregator()

        # ML components (lazy import to avoid circular imports)
        self.ml_enabled = ml_enabled
        self.ml_pipeline = None
        if ml_enabled:
            from ..ml import MLPipeline
            self.ml_pipeline = MLPipeline(
                fp_threshold=fp_threshold,
                enable_feedback=True,
            )

    def _read_contract_source(self, contract_path: str) -> str:
        """Lee código fuente del contrato."""
        try:
            with open(contract_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.warning(f"Could not read contract source: {e}")
            return ""

    def _build_code_context_map(
        self,
        contract_source: str,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, str]:
        """Construye mapa de contexto de código para cada hallazgo."""
        context_map = {}
        lines = contract_source.split('\n')

        for finding in findings:
            loc = finding.get('location', {})
            file_path = loc.get('file', '')
            line_num = loc.get('line') or 0  # Handle None values

            # Ensure line_num is an integer
            if not isinstance(line_num, int):
                try:
                    line_num = int(line_num)
                except (TypeError, ValueError):
                    line_num = 0

            if line_num > 0 and lines:
                # Extraer contexto (5 líneas antes y después)
                start = max(0, line_num - 6)
                end = min(len(lines), line_num + 5)
                context = '\n'.join(lines[start:end])

                key = f"{file_path}:{line_num}"
                context_map[key] = context

        return context_map

    def _run_tool(
        self,
        tool_name: str,
        contract_path: str,
        timeout: int = 120,
    ) -> Dict[str, Any]:
        """Ejecuta una herramienta individual."""
        # Check cache
        if self.cache:
            cached = self.cache.get(tool_name, contract_path)
            if cached:
                logger.info(f"Cache hit for {tool_name}")
                return cached

        try:
            adapter = self.discovery.load_adapter(tool_name)
            adapter_config = self.config.get_adapter_config(tool_name)
            effective_timeout = adapter_config.timeout or timeout

            result = adapter.analyze(contract_path, timeout=effective_timeout)

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
        progress_callback: Optional[Callable[[str, str, float], None]] = None,
    ) -> MLAnalysisResult:
        """
        Ejecuta análisis completo con mejoras ML.

        Args:
            contract_path: Ruta al contrato Solidity
            tools: Lista de herramientas a usar
            layers: Capas a ejecutar
            timeout: Timeout por herramienta
            progress_callback: Callback(stage, message, progress)

        Returns:
            MLAnalysisResult con hallazgos mejorados
        """
        start_time = time.time()

        # Read contract source
        contract_source = self._read_contract_source(contract_path)

        # Determine tools to run
        tools_to_run = self._determine_tools(tools, layers)

        if not tools_to_run:
            return self._empty_result(contract_path, contract_source)

        if progress_callback:
            progress_callback('init', f"Running {len(tools_to_run)} tools", 0.0)

        # Execute tools in parallel
        raw_results: Dict[str, Dict[str, Any]] = {}
        tools_success: List[str] = []
        tools_failed: List[str] = []
        all_findings: List[Dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_tool = {
                executor.submit(self._run_tool, tool, contract_path, timeout): tool
                for tool in tools_to_run
            }

            completed = 0
            for future in as_completed(future_to_tool):
                tool = future_to_tool[future]
                completed += 1

                try:
                    result = future.result(timeout=timeout + 30)
                    raw_results[tool] = result

                    if result.get('status') == 'error':
                        tools_failed.append(tool)
                    else:
                        tools_success.append(tool)
                        # Collect findings
                        for finding in result.get('findings', []):
                            finding['tool'] = tool
                            all_findings.append(finding)

                    if progress_callback:
                        progress = completed / len(tools_to_run) * 0.5
                        progress_callback('tools', f"Completed {tool}", progress)

                except Exception as e:
                    tools_failed.append(tool)
                    raw_results[tool] = {
                        'tool': tool,
                        'status': 'error',
                        'error': str(e),
                        'findings': [],
                    }

        tool_execution_time = (time.time() - start_time) * 1000

        if progress_callback:
            progress_callback('ml', "Applying ML pipeline", 0.5)

        # Apply ML pipeline
        ml_start = time.time()

        if self.ml_enabled and self.ml_pipeline and all_findings:
            code_context_map = self._build_code_context_map(contract_source, all_findings)

            ml_result = self.ml_pipeline.process(
                findings=all_findings,
                code_context_map=code_context_map,
                contract_source=contract_source,
            )

            ml_filtered_findings = ml_result.filtered_findings
            ml_filtered_out = ml_result.filtered_out
            clusters = ml_result.clusters
            remediation_plan = ml_result.remediation_plan
            pattern_matches = ml_result.pattern_matches
            severity_adjustments = ml_result.severity_adjustments
        else:
            ml_filtered_findings = all_findings
            ml_filtered_out = []
            clusters = []
            remediation_plan = []
            pattern_matches = []
            severity_adjustments = 0

        ml_processing_time = (time.time() - ml_start) * 1000

        if progress_callback:
            progress_callback('aggregation', "Aggregating results", 0.8)

        # Calculate severity distribution
        severity_dist = self._calculate_severity_distribution(ml_filtered_findings)

        # Count cross-validated
        cross_validated = sum(
            1 for f in ml_filtered_findings
            if f.get('_cross_validated', False) or
            len(set(ff.get('tool', '') for ff in all_findings
                   if self._is_same_location(f, ff))) > 1
        )

        total_time = (time.time() - start_time) * 1000

        if progress_callback:
            progress_callback('complete', "Analysis complete", 1.0)

        return MLAnalysisResult(
            contract_path=contract_path,
            contract_source=contract_source,
            tools_run=tools_to_run,
            tools_success=tools_success,
            tools_failed=tools_failed,
            total_raw_findings=len(all_findings),
            raw_findings=all_findings,
            ml_filtered_findings=ml_filtered_findings,
            ml_filtered_out=ml_filtered_out,
            false_positives_removed=len(ml_filtered_out),
            severity_adjustments=severity_adjustments,
            clusters=clusters,
            cluster_count=len(clusters),
            remediation_plan=remediation_plan,
            pattern_matches=pattern_matches,
            severity_distribution=severity_dist,
            cross_validated=cross_validated,
            execution_time_ms=total_time,
            ml_processing_time_ms=ml_processing_time,
            timestamp=datetime.now(),
        )

    def _is_same_location(self, f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
        """Verifica si dos hallazgos están en la misma ubicación."""
        loc1 = f1.get('location', {})
        loc2 = f2.get('location', {})
        line1 = loc1.get('line') or 0
        line2 = loc2.get('line') or 0
        return (
            loc1.get('file') == loc2.get('file') and
            abs(line1 - line2) <= 3
        )

    def _calculate_severity_distribution(
        self,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, int]:
        """Calcula distribución de severidad."""
        dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
        for f in findings:
            sev = f.get('severity', 'medium').lower()
            if sev in dist:
                dist[sev] += 1
            elif sev == 'info':
                dist['informational'] += 1
            else:
                dist['medium'] += 1
        return dist

    def _determine_tools(
        self,
        tools: Optional[List[str]] = None,
        layers: Optional[List[str]] = None,
    ) -> List[str]:
        """Determina qué herramientas ejecutar."""
        if tools:
            available = {t.name for t in self.discovery.get_available_tools()}
            return [t for t in tools if t in available]

        if layers:
            tools_by_layer = self.discovery.get_tools_by_layer()
            result = []
            for layer in layers:
                if layer in tools_by_layer:
                    for tool in tools_by_layer[layer]:
                        if tool.available:
                            result.append(tool.name)
            return result

        enabled = self.config.get_enabled_adapters()
        available = {t.name for t in self.discovery.get_available_tools()}
        return [t for t in enabled if t in available]

    def _empty_result(
        self,
        contract_path: str,
        contract_source: str,
    ) -> MLAnalysisResult:
        """Retorna resultado vacío."""
        return MLAnalysisResult(
            contract_path=contract_path,
            contract_source=contract_source,
            tools_run=[],
            tools_success=[],
            tools_failed=[],
            total_raw_findings=0,
            raw_findings=[],
            ml_filtered_findings=[],
            ml_filtered_out=[],
            false_positives_removed=0,
            severity_adjustments=0,
            clusters=[],
            cluster_count=0,
            remediation_plan=[],
            pattern_matches=[],
            severity_distribution={},
            cross_validated=0,
            execution_time_ms=0,
            ml_processing_time_ms=0,
            timestamp=datetime.now(),
        )

    def submit_feedback(
        self,
        finding: Dict[str, Any],
        feedback_type: Any,  # FeedbackType - lazy import
        user_id: str = "anonymous",
        notes: str = "",
    ) -> Dict[str, Any]:
        """Registra feedback de usuario."""
        if self.ml_pipeline:
            return self.ml_pipeline.submit_feedback(
                finding, feedback_type, user_id, notes
            )
        return {'status': 'ml_disabled'}

    def get_ml_report(self) -> Dict[str, Any]:
        """Obtiene reporte del estado ML."""
        if self.ml_pipeline:
            return self.ml_pipeline.get_ml_report()
        return {'status': 'ml_disabled'}

    def quick_scan(self, contract_path: str, timeout: int = 60) -> MLAnalysisResult:
        """Escaneo rápido usando solo análisis estático."""
        return self.analyze(
            contract_path=contract_path,
            layers=['static_analysis'],
            timeout=timeout,
        )

    def deep_scan(self, contract_path: str, timeout: int = 300) -> MLAnalysisResult:
        """Escaneo profundo usando todas las capas."""
        return self.analyze(
            contract_path=contract_path,
            timeout=timeout,
        )

    def clear_cache(self) -> None:
        """Limpia el caché."""
        if self.cache:
            self.cache.clear()


# Singleton instance
_ml_orchestrator: Optional[MLOrchestrator] = None


def get_ml_orchestrator() -> MLOrchestrator:
    """Obtiene instancia singleton del orquestador ML."""
    global _ml_orchestrator
    if _ml_orchestrator is None:
        _ml_orchestrator = MLOrchestrator()
    return _ml_orchestrator
