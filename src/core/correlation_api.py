"""
MIESC Correlation API
API unificada para correlación inteligente de hallazgos de seguridad.

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ml.correlation_engine import SmartCorrelationEngine, CorrelatedFinding
from ml.false_positive_filter import FalsePositiveFilter
from ml.vulnerability_clusterer import VulnerabilityClusterer


class MIESCCorrelationAPI:
    """
    API unificada para análisis de seguridad con correlación inteligente.

    Integra:
    - SmartCorrelationEngine: Correlación ML multi-herramienta
    - FalsePositiveFilter: Filtrado de FPs
    - VulnerabilityClusterer: Agrupación semántica

    Ejemplo de uso:
        api = MIESCCorrelationAPI()
        api.add_tool_results('slither', slither_findings)
        api.add_tool_results('aderyn', aderyn_findings)
        report = api.analyze()
    """

    def __init__(
        self,
        min_tools_for_validation: int = 2,
        confidence_threshold: float = 0.5,
        fp_threshold: float = 0.6,
        enable_clustering: bool = True,
    ):
        """
        Inicializa la API de correlación.

        Args:
            min_tools_for_validation: Mínimo de herramientas para validación cruzada
            confidence_threshold: Umbral mínimo de confianza para reportar
            fp_threshold: Umbral de probabilidad FP para filtrar
            enable_clustering: Habilitar agrupación de vulnerabilidades
        """
        self.correlation_engine = SmartCorrelationEngine(
            min_tools_for_validation=min_tools_for_validation
        )
        self.fp_filter = FalsePositiveFilter()
        self.clusterer = VulnerabilityClusterer()

        self.confidence_threshold = confidence_threshold
        self.fp_threshold = fp_threshold
        self.enable_clustering = enable_clustering

        self._analysis_metadata: Dict[str, Any] = {
            'start_time': None,
            'end_time': None,
            'tools_used': [],
        }

    def add_tool_results(
        self,
        tool_name: str,
        findings: List[Dict[str, Any]],
        code_context: Optional[Dict[str, str]] = None,
    ) -> int:
        """
        Agrega resultados de una herramienta de análisis.

        Args:
            tool_name: Nombre de la herramienta
            findings: Lista de hallazgos en formato estándar MIESC
            code_context: Opcional - mapa de file:line -> código contexto

        Returns:
            Número de hallazgos agregados
        """
        if not self._analysis_metadata['start_time']:
            self._analysis_metadata['start_time'] = datetime.now().isoformat()

        count = self.correlation_engine.add_findings(tool_name, findings)

        if tool_name not in self._analysis_metadata['tools_used']:
            self._analysis_metadata['tools_used'].append(tool_name)

        return count

    def analyze(
        self,
        output_format: str = 'full',
    ) -> Dict[str, Any]:
        """
        Ejecuta análisis completo con correlación.

        Args:
            output_format: 'full', 'summary', 'actionable'

        Returns:
            Reporte de análisis
        """
        self._analysis_metadata['end_time'] = datetime.now().isoformat()

        # Paso 1: Correlación de hallazgos
        correlated = self.correlation_engine.correlate()

        # Paso 2: Filtrar por confianza y FP
        filtered_findings = []
        fp_filtered = []

        for finding in correlated:
            if finding.final_confidence >= self.confidence_threshold:
                if finding.false_positive_probability <= self.fp_threshold:
                    filtered_findings.append(finding)
                else:
                    fp_filtered.append(finding)

        # Paso 3: Clustering opcional
        clusters = None
        if self.enable_clustering and filtered_findings:
            finding_dicts = [f.to_dict() for f in filtered_findings]
            clusters = self.clusterer.cluster(finding_dicts)

        # Generar reporte según formato
        if output_format == 'summary':
            return self._generate_summary_report(
                filtered_findings, fp_filtered, clusters
            )
        elif output_format == 'actionable':
            return self._generate_actionable_report(
                filtered_findings, clusters
            )
        else:
            return self._generate_full_report(
                correlated, filtered_findings, fp_filtered, clusters
            )

    def _generate_full_report(
        self,
        all_findings: List[CorrelatedFinding],
        filtered: List[CorrelatedFinding],
        fp_filtered: List[CorrelatedFinding],
        clusters: Optional[List],
    ) -> Dict[str, Any]:
        """Genera reporte completo."""
        stats = self.correlation_engine.get_statistics()

        report = {
            'metadata': {
                **self._analysis_metadata,
                'configuration': {
                    'min_tools_for_validation': self.correlation_engine.min_tools_for_validation,
                    'confidence_threshold': self.confidence_threshold,
                    'fp_threshold': self.fp_threshold,
                },
            },
            'summary': {
                **stats,
                'filtered_count': len(filtered),
                'fp_filtered_count': len(fp_filtered),
                'filter_rate': round(len(fp_filtered) / max(len(all_findings), 1), 3),
            },
            'findings': {
                'actionable': [f.to_dict() for f in filtered],
                'likely_false_positives': [f.to_dict() for f in fp_filtered],
                'all': [f.to_dict() for f in all_findings],
            },
            'tool_analysis': self.correlation_engine.to_report()['tool_profiles'],
        }

        if clusters:
            report['clusters'] = self.clusterer.get_summary()
            report['remediation_plan'] = self.clusterer.get_remediation_plan()

        return report

    def _generate_summary_report(
        self,
        filtered: List[CorrelatedFinding],
        fp_filtered: List[CorrelatedFinding],
        clusters: Optional[List],
    ) -> Dict[str, Any]:
        """Genera reporte resumido."""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        type_counts: Dict[str, int] = {}
        cross_validated = 0

        for f in filtered:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            type_counts[f.canonical_type] = type_counts.get(f.canonical_type, 0) + 1
            if f.is_cross_validated:
                cross_validated += 1

        return {
            'total_findings': len(filtered),
            'filtered_as_fp': len(fp_filtered),
            'cross_validated': cross_validated,
            'by_severity': severity_counts,
            'by_type': type_counts,
            'tools_used': self._analysis_metadata['tools_used'],
            'top_issues': [
                {
                    'type': f.canonical_type,
                    'severity': f.severity,
                    'confidence': round(f.final_confidence, 2),
                    'location': f"{f.location.get('file', '')}:{f.location.get('line', 0)}",
                }
                for f in filtered[:5]
            ],
        }

    def _generate_actionable_report(
        self,
        filtered: List[CorrelatedFinding],
        clusters: Optional[List],
    ) -> Dict[str, Any]:
        """Genera reporte con acciones recomendadas."""
        # Priorizar por severidad y confianza
        prioritized = sorted(
            filtered,
            key=lambda f: (
                -{'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(f.severity, 0),
                -f.final_confidence,
            )
        )

        actions = []
        for i, finding in enumerate(prioritized[:20], 1):
            action = {
                'priority': i,
                'type': finding.canonical_type,
                'severity': finding.severity,
                'confidence': round(finding.final_confidence, 2),
                'location': {
                    'file': finding.location.get('file', ''),
                    'line': finding.location.get('line', 0),
                    'function': finding.location.get('function', ''),
                },
                'description': finding.message[:200],
                'validated_by': finding.confirming_tools,
                'swc_id': finding.swc_id,
            }
            actions.append(action)

        return {
            'total_actions': len(actions),
            'critical_count': sum(1 for f in filtered if f.severity == 'critical'),
            'high_count': sum(1 for f in filtered if f.severity == 'high'),
            'actions': actions,
            'remediation_plan': self.clusterer.get_remediation_plan() if clusters else [],
        }

    def get_findings_by_severity(
        self, severity: str
    ) -> List[Dict[str, Any]]:
        """Obtiene hallazgos filtrados por severidad."""
        return [
            f.to_dict()
            for f in self.correlation_engine._correlated
            if f.severity == severity and f.final_confidence >= self.confidence_threshold
        ]

    def get_findings_by_type(
        self, vuln_type: str
    ) -> List[Dict[str, Any]]:
        """Obtiene hallazgos filtrados por tipo."""
        return [
            f.to_dict()
            for f in self.correlation_engine._correlated
            if f.canonical_type == vuln_type
        ]

    def get_cross_validated_only(self) -> List[Dict[str, Any]]:
        """Obtiene solo hallazgos con validación cruzada."""
        return [
            f.to_dict()
            for f in self.correlation_engine.get_cross_validated_findings()
            if f.final_confidence >= self.confidence_threshold
        ]

    def clear(self) -> None:
        """Limpia todos los datos."""
        self.correlation_engine.clear()
        self.clusterer._clusters = []
        self._analysis_metadata = {
            'start_time': None,
            'end_time': None,
            'tools_used': [],
        }


def analyze_contract_with_correlation(
    tool_results: Dict[str, List[Dict[str, Any]]],
    confidence_threshold: float = 0.5,
    fp_threshold: float = 0.6,
) -> Dict[str, Any]:
    """
    Función de conveniencia para análisis rápido con correlación.

    Args:
        tool_results: Dict de {tool_name: [findings]}
        confidence_threshold: Umbral de confianza
        fp_threshold: Umbral de probabilidad FP

    Returns:
        Reporte de análisis
    """
    api = MIESCCorrelationAPI(
        confidence_threshold=confidence_threshold,
        fp_threshold=fp_threshold,
    )

    for tool_name, findings in tool_results.items():
        api.add_tool_results(tool_name, findings)

    return api.analyze()


# CLI interface
def main():
    """Demo del API de correlación."""
    import json

    print("\n" + "="*60)
    print("  MIESC Smart Correlation API Demo")
    print("="*60)

    # Crear datos de ejemplo
    slither_findings = [
        {
            'type': 'reentrancy-eth',
            'severity': 'high',
            'message': 'Reentrancy in Contract.withdraw()',
            'location': {'file': 'Contract.sol', 'line': 42, 'function': 'withdraw'},
            'swc_id': 'SWC-107',
            'confidence': 0.8,
        },
        {
            'type': 'arbitrary-send',
            'severity': 'high',
            'message': 'Contract sends ETH to arbitrary address',
            'location': {'file': 'Contract.sol', 'line': 45, 'function': 'withdraw'},
            'swc_id': 'SWC-105',
            'confidence': 0.7,
        },
    ]

    aderyn_findings = [
        {
            'type': 'reentrancy',
            'severity': 'high',
            'message': 'State change after external call in withdraw()',
            'location': {'file': 'Contract.sol', 'line': 42, 'function': 'withdraw'},
            'swc_id': 'SWC-107',
            'confidence': 0.85,
        },
    ]

    smartbugs_findings = [
        {
            'type': 'arithmetic',
            'severity': 'medium',
            'message': 'Possible integer overflow in balance calculation',
            'location': {'file': 'Contract.sol', 'line': 30},
            'swc_id': 'SWC-101',
            'confidence': 0.6,
        },
    ]

    # Crear API y agregar resultados
    api = MIESCCorrelationAPI(
        min_tools_for_validation=2,
        confidence_threshold=0.5,
        fp_threshold=0.7,
    )

    api.add_tool_results('slither', slither_findings)
    api.add_tool_results('aderyn', aderyn_findings)
    api.add_tool_results('smartbugs-detector', smartbugs_findings)

    # Ejecutar análisis
    report = api.analyze(output_format='full')

    print(f"\nHerramientas usadas: {report['metadata']['tools_used']}")
    print(f"\nResumen:")
    print(f"  - Total correlacionados: {report['summary']['total_correlated']}")
    print(f"  - Hallazgos originales: {report['summary']['original_findings']}")
    print(f"  - Tasa de deduplicación: {report['summary']['deduplication_rate']*100:.1f}%")
    print(f"  - Validación cruzada: {report['summary']['cross_validated']}")
    print(f"  - Alta confianza: {report['summary']['high_confidence_count']}")

    print(f"\nHallazgos accionables: {len(report['findings']['actionable'])}")
    for f in report['findings']['actionable']:
        print(f"  [{f['severity'].upper()}] {f['type']}")
        print(f"    Confianza: {f['confidence']['final']:.2f}")
        print(f"    Validado por: {', '.join(f['confirming_tools'])}")
        print(f"    Ubicación: {f['location']['file']}:{f['location']['line']}")

    print(f"\nFiltrados como FP: {len(report['findings']['likely_false_positives'])}")


if __name__ == "__main__":
    main()
