"""
MIESC Machine Learning Module
Componentes ML para mejora de análisis de smart contracts.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

from .false_positive_filter import FalsePositiveFilter, FindingFeatures
from .severity_predictor import SeverityPredictor, SeverityPrediction, SeverityLevel
from .vulnerability_clusterer import VulnerabilityClusterer, VulnerabilityCluster
from .code_embeddings import CodeEmbedder, CodeEmbedding, VulnerabilityPatternDB
from .feedback_loop import FeedbackLoop, FeedbackType, UserFeedback


@dataclass
class MLEnhancedResult:
    """Resultado de análisis mejorado con ML."""
    original_findings: List[Dict[str, Any]]
    filtered_findings: List[Dict[str, Any]]
    filtered_out: List[Dict[str, Any]]
    clusters: List[VulnerabilityCluster]
    severity_adjustments: int
    fp_filtered: int
    remediation_plan: List[Dict[str, Any]]
    pattern_matches: List[Dict[str, Any]]
    processing_time_ms: float
    timestamp: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            'original_count': len(self.original_findings),
            'filtered_count': len(self.filtered_findings),
            'filtered_out_count': len(self.filtered_out),
            'cluster_count': len(self.clusters),
            'severity_adjustments': self.severity_adjustments,
            'fp_filtered': self.fp_filtered,
            'clusters': [c.to_dict() for c in self.clusters],
            'remediation_plan': self.remediation_plan,
            'pattern_matches': self.pattern_matches[:10],  # Top 10
            'processing_time_ms': round(self.processing_time_ms, 2),
            'timestamp': self.timestamp.isoformat(),
        }


class MLPipeline:
    """
    Pipeline integrado de ML para análisis de smart contracts.

    Flujo:
    1. Filtrado de falsos positivos
    2. Ajuste de severidad
    3. Matching de patrones de vulnerabilidad
    4. Clustering de hallazgos
    5. Generación de plan de remediación
    6. Integración con feedback loop

    Ejemplo de uso:
        pipeline = MLPipeline()
        result = pipeline.process(findings, code_context_map)
        print(f"Filtered: {result.fp_filtered} FPs")
        print(f"Clusters: {len(result.clusters)}")
    """

    def __init__(
        self,
        fp_threshold: float = 0.6,
        similarity_threshold: float = 0.7,
        enable_feedback: bool = True,
    ):
        self.fp_filter = FalsePositiveFilter()
        self.severity_predictor = SeverityPredictor()
        self.clusterer = VulnerabilityClusterer(similarity_threshold)
        self.embedder = CodeEmbedder()
        self.pattern_db = VulnerabilityPatternDB(self.embedder)
        self.feedback_loop = FeedbackLoop() if enable_feedback else None

        self.fp_threshold = fp_threshold

    def process(
        self,
        findings: List[Dict[str, Any]],
        code_context_map: Optional[Dict[str, str]] = None,
        contract_source: Optional[str] = None,
    ) -> MLEnhancedResult:
        """
        Procesa hallazgos a través del pipeline ML completo.

        Args:
            findings: Lista de hallazgos de herramientas
            code_context_map: Mapa de file:line -> código contexto
            contract_source: Código fuente completo (para embeddings)

        Returns:
            MLEnhancedResult con hallazgos mejorados
        """
        import time
        start_time = time.time()

        code_context_map = code_context_map or {}
        original_count = len(findings)

        # 1. Filtrar falsos positivos
        true_positives, filtered_fps = self.fp_filter.filter_findings(
            findings,
            threshold=self.fp_threshold,
            code_context_map=code_context_map,
        )

        # 2. Ajustar severidad
        severity_adjusted = 0
        adjusted_findings = []

        for finding in true_positives:
            loc = f"{finding.get('location', {}).get('file', '')}:{finding.get('location', {}).get('line', 0)}"
            context = code_context_map.get(loc, "")

            prediction = self.severity_predictor.predict(finding, context)

            if prediction.adjusted:
                severity_adjusted += 1
                finding = finding.copy()
                finding['severity'] = prediction.predicted
                finding['_severity_prediction'] = {
                    'original': prediction.original,
                    'predicted': prediction.predicted,
                    'confidence': prediction.confidence,
                    'reasons': prediction.reasons,
                }

            # Aplicar ajuste de feedback si disponible
            if self.feedback_loop:
                finding = self.feedback_loop.adjust_finding_confidence(finding)

            adjusted_findings.append(finding)

        # 3. Matching de patrones de vulnerabilidad
        pattern_matches = []
        if contract_source:
            pattern_matches = self.pattern_db.match_patterns(
                contract_source,
                threshold=0.5,
            )

        # 4. Clustering
        clusters = self.clusterer.cluster(adjusted_findings)

        # 5. Generar plan de remediación
        remediation_plan = self.clusterer.get_remediation_plan()

        processing_time = (time.time() - start_time) * 1000

        return MLEnhancedResult(
            original_findings=findings,
            filtered_findings=adjusted_findings,
            filtered_out=filtered_fps,
            clusters=clusters,
            severity_adjustments=severity_adjusted,
            fp_filtered=len(filtered_fps),
            remediation_plan=remediation_plan,
            pattern_matches=pattern_matches,
            processing_time_ms=processing_time,
            timestamp=datetime.now(),
        )

    def submit_feedback(
        self,
        finding: Dict[str, Any],
        feedback_type: FeedbackType,
        user_id: str = "anonymous",
        notes: str = "",
    ) -> Dict[str, Any]:
        """Registra feedback de usuario sobre un hallazgo."""
        if self.feedback_loop:
            return self.feedback_loop.submit_feedback(
                finding, feedback_type, user_id, notes
            )
        return {'status': 'feedback_disabled'}

    def get_ml_report(self) -> Dict[str, Any]:
        """Genera reporte del estado del módulo ML."""
        report = {
            'fp_filter': self.fp_filter.get_statistics(),
            'clusterer': self.clusterer.get_summary(),
        }

        if self.feedback_loop:
            report['feedback'] = self.feedback_loop.generate_report()
            report['recommendations'] = self.feedback_loop.get_recommendations()

        return report


# Singleton instance
_ml_pipeline: Optional[MLPipeline] = None


def get_ml_pipeline() -> MLPipeline:
    """Obtiene instancia singleton del pipeline ML."""
    global _ml_pipeline
    if _ml_pipeline is None:
        _ml_pipeline = MLPipeline()
    return _ml_pipeline


__all__ = [
    # False Positive Filter
    'FalsePositiveFilter',
    'FindingFeatures',
    # Severity Predictor
    'SeverityPredictor',
    'SeverityPrediction',
    'SeverityLevel',
    # Vulnerability Clusterer
    'VulnerabilityClusterer',
    'VulnerabilityCluster',
    # Code Embeddings
    'CodeEmbedder',
    'CodeEmbedding',
    'VulnerabilityPatternDB',
    # Feedback Loop
    'FeedbackLoop',
    'FeedbackType',
    'UserFeedback',
    # Pipeline
    'MLPipeline',
    'MLEnhancedResult',
    'get_ml_pipeline',
]
