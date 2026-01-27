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

# v4.2.0+ Enhanced modules
from .fp_filter import (
    FalsePositiveFilter as EnhancedFPFilter,
    FilterResult,
    FPMatch,
    FPCategory,
    filter_false_positives,
)
from .correlation_engine import (
    SmartCorrelationEngine,
    CorrelatedFinding,
    ExploitChainAnalyzer,
    ExploitChain,
    correlate_findings,
)

# v4.3.0+ New ML Components (2025-2026 Improvements)
from .defi_patterns import (
    DeFiVulnType,
    DeFiVulnerabilityPattern,
    DeFiPatternMatch,
    DeFiPatternDetector,
    DEFI_VULNERABILITY_PATTERNS,
    detect_defi_vulnerabilities,
)

from .severity_classifier import (
    MLSeverityClassifier,
    SeverityLevel as MLSeverityLevel,
    SeverityFactors,
    SeverityPrediction as MLSeverityPrediction,
    ContractContext,
    ImpactLevel,
    ExploitabilityLevel,
    ScopeLevel,
    classify_severity,
)

from .classic_patterns import (
    ClassicVulnType,
    ClassicPatternDetector,
    PatternMatch as ClassicPatternMatch,
    PatternConfig,
    CLASSIC_PATTERNS,
    detect_classic_vulnerabilities,
)

# v4.5.0+ ML Invariant Synthesis (Sprint 4)
from .ml_invariant_synthesizer import (
    MLInvariantSynthesizer,
    FeatureExtractor,
    InvariantPredictor,
    ContractFeatures,
    InvariantPrediction,
    TrainingExample,
    extract_contract_features,
    predict_invariants,
    synthesize_with_ml,
)

from .invariant_validator import (
    InvariantValidator,
    InvariantTestGenerator,
    InvariantTestResult,
    ValidationReport,
    validate_invariants,
    quick_validate,
)

# v4.6.0+ New Analysis Modules
from .call_graph import (
    Visibility,
    Mutability,
    FunctionNode,
    CallEdge,
    CallPath,
    CallGraph,
    CallGraphBuilder,
    build_call_graph,
    analyze_reentrancy_risk,
)

from .taint_analysis import (
    TaintSource,
    TaintSink,
    SanitizerType,
    TaintedVariable,
    TaintedPath,
    TaintAnalyzer,
    analyze_taint,
    find_tainted_sinks,
)

from .slither_ir_parser import (
    IROpcode,
    IRVariable,
    IRInstruction,
    StateTransition,
    Call as IRCall,
    FunctionIR,
    SlitherIRParser,
    parse_slither_ir,
    get_function_state_transitions,
    get_external_calls,
)

# v4.6.0+ Enhanced FP Filter exports
from .false_positive_filter import (
    SLITHER_DETECTOR_FP_RATES,
    SemanticContextAnalyzer,
)

# v4.6.0+ Classic Pattern enhancements
from .classic_patterns import (
    AccessControlFinding,
    AccessControlSemanticDetector,
    DoSFinding,
    DoSCrossFunctionDetector,
    detect_semantic_vulnerabilities,
)

# v4.6.0+ Slither Validator for cross-validation
from .slither_validator import (
    SlitherValidator,
    SlitherFinding,
    ValidationResult,
    validate_with_slither,
    filter_unconfirmed,
)

# v4.7.0+ ML-based False Positive Classifier
from .fp_classifier import (
    FPClassifier,
    FeatureExtractor,
    FindingFeatures,
    FPPrediction,
    FeatureCategory,
    classify_false_positives,
    filter_likely_fps,
)


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
        enable_classic_patterns: bool = True,
    ):
        self.fp_filter = FalsePositiveFilter()
        self.severity_predictor = SeverityPredictor()
        self.clusterer = VulnerabilityClusterer(similarity_threshold)
        self.embedder = CodeEmbedder()
        self.pattern_db = VulnerabilityPatternDB(self.embedder)
        self.feedback_loop = FeedbackLoop() if enable_feedback else None

        # Classic pattern detector (81.2% recall on SmartBugs)
        self.classic_detector = ClassicPatternDetector() if enable_classic_patterns else None

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

        # 0. Run classic pattern detector for additional findings
        if self.classic_detector and contract_source:
            classic_findings = self._detect_classic_patterns(contract_source)
            findings = self._merge_findings(findings, classic_findings)

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

    def _detect_classic_patterns(self, source_code: str) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities using classic regex patterns.
        These complement tool-based detection with 81.2% recall.
        """
        if not self.classic_detector:
            return []

        matches = self.classic_detector.detect(source_code)
        findings = []

        for match in matches:
            findings.append({
                'id': f"pattern-{match.vuln_type.value}-{match.line}",
                'type': match.vuln_type.value,
                'severity': match.severity.capitalize(),
                'confidence': match.confidence,
                'location': {
                    'file': 'contract.sol',
                    'line': match.line,
                },
                'message': match.description,
                'description': match.description,
                'recommendation': match.recommendation,
                'swc_id': match.swc_id,
                'tool': 'classic-pattern-detector',
                '_pattern_match': True,
            })

        return findings

    def _merge_findings(
        self,
        tool_findings: List[Dict[str, Any]],
        pattern_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Merge tool findings with pattern-detected findings.
        Avoids duplicates by checking location and type overlap.
        """
        merged = list(tool_findings)
        existing_locations = set()

        # Index existing findings by location+type
        for f in tool_findings:
            loc = f.get('location', {})
            line = loc.get('line', 0)
            ftype = f.get('type', '').lower()
            existing_locations.add((line, ftype))

        # Add pattern findings that don't overlap
        for pf in pattern_findings:
            loc = pf.get('location', {})
            line = loc.get('line', 0)
            ftype = pf.get('type', '').lower()

            # Check for overlap (within 5 lines and same category)
            is_duplicate = False
            for (el, et) in existing_locations:
                # Skip if either line is None
                if el is None or line is None:
                    continue
                if abs(el - line) <= 5 and self._types_similar(et, ftype):
                    is_duplicate = True
                    break

            if not is_duplicate:
                merged.append(pf)
                existing_locations.add((line, ftype))

        return merged

    def _types_similar(self, type1: str, type2: str) -> bool:
        """Check if two vulnerability types are similar."""
        # Normalize types
        t1 = type1.lower().replace('-', '_').replace(' ', '_')
        t2 = type2.lower().replace('-', '_').replace(' ', '_')

        if t1 == t2:
            return True

        # Similar categories
        similar_groups = [
            {'reentrancy', 'reentrancy_eth', 'reentrancy_no_eth'},
            {'access_control', 'unprotected', 'arbitrary_send'},
            {'arithmetic', 'overflow', 'underflow', 'integer_overflow'},
            {'unchecked', 'unchecked_low_level_calls', 'unchecked_call'},
            {'timestamp', 'timestamp_dependence', 'block_timestamp'},
        ]

        for group in similar_groups:
            if any(t1 in g or g in t1 for g in group) and any(t2 in g or g in t2 for g in group):
                return True

        return False

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
    # v4.2.0+ Enhanced FP Filter
    'EnhancedFPFilter',
    'FilterResult',
    'FPMatch',
    'FPCategory',
    'filter_false_positives',
    # v4.2.0+ Smart Correlation Engine
    'SmartCorrelationEngine',
    'CorrelatedFinding',
    'ExploitChainAnalyzer',
    'ExploitChain',
    'correlate_findings',
    # v4.3.0+ DeFi Pattern Detector
    'DeFiVulnType',
    'DeFiVulnerabilityPattern',
    'DeFiPatternMatch',
    'DeFiPatternDetector',
    'DEFI_VULNERABILITY_PATTERNS',
    'detect_defi_vulnerabilities',
    # v4.3.0+ ML Severity Classifier
    'MLSeverityClassifier',
    'MLSeverityLevel',
    'SeverityFactors',
    'MLSeverityPrediction',
    'ContractContext',
    'ImpactLevel',
    'ExploitabilityLevel',
    'ScopeLevel',
    'classify_severity',
    # v4.3.0+ Classic Pattern Detector (81.2% recall)
    'ClassicVulnType',
    'ClassicPatternDetector',
    'ClassicPatternMatch',
    'PatternConfig',
    'CLASSIC_PATTERNS',
    'detect_classic_vulnerabilities',
    # v4.5.0+ ML Invariant Synthesis
    'MLInvariantSynthesizer',
    'FeatureExtractor',
    'InvariantPredictor',
    'ContractFeatures',
    'InvariantPrediction',
    'TrainingExample',
    'extract_contract_features',
    'predict_invariants',
    'synthesize_with_ml',
    # v4.5.0+ Invariant Validator
    'InvariantValidator',
    'InvariantTestGenerator',
    'InvariantTestResult',
    'ValidationReport',
    'validate_invariants',
    'quick_validate',
    # v4.6.0+ Call Graph
    'Visibility',
    'Mutability',
    'FunctionNode',
    'CallEdge',
    'CallPath',
    'CallGraph',
    'CallGraphBuilder',
    'build_call_graph',
    'analyze_reentrancy_risk',
    # v4.6.0+ Taint Analysis
    'TaintSource',
    'TaintSink',
    'SanitizerType',
    'TaintedVariable',
    'TaintedPath',
    'TaintAnalyzer',
    'analyze_taint',
    'find_tainted_sinks',
    # v4.6.0+ Slither IR Parser
    'IROpcode',
    'IRVariable',
    'IRInstruction',
    'StateTransition',
    'IRCall',
    'FunctionIR',
    'SlitherIRParser',
    'parse_slither_ir',
    'get_function_state_transitions',
    'get_external_calls',
    # v4.6.0+ Enhanced FP Filter
    'SLITHER_DETECTOR_FP_RATES',
    'SemanticContextAnalyzer',
    # v4.6.0+ Semantic Detectors
    'AccessControlFinding',
    'AccessControlSemanticDetector',
    'DoSFinding',
    'DoSCrossFunctionDetector',
    'detect_semantic_vulnerabilities',
    # v4.6.0+ Slither Validator
    'SlitherValidator',
    'SlitherFinding',
    'ValidationResult',
    'validate_with_slither',
    'filter_unconfirmed',
    # v4.7.0+ ML-based FP Classifier
    'FPClassifier',
    'FeatureExtractor',
    'FindingFeatures',
    'FPPrediction',
    'FeatureCategory',
    'classify_false_positives',
    'filter_likely_fps',
]
