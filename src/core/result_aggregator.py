"""
MIESC Result Aggregator
Agrega, deduplica y correlaciona hallazgos de múltiples herramientas.
"""

import hashlib
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from collections import defaultdict


@dataclass
class Finding:
    """Representa un hallazgo normalizado."""
    id: str
    tool: str
    severity: str
    type: str
    message: str
    file: str = ""
    line: int = 0
    function: str = ""
    swc_id: Optional[str] = None
    cwe_id: Optional[str] = None
    confidence: float = 1.0
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'tool': self.tool,
            'severity': self.severity,
            'type': self.type,
            'message': self.message,
            'file': self.file,
            'line': self.line,
            'function': self.function,
            'swc_id': self.swc_id,
            'cwe_id': self.cwe_id,
            'confidence': self.confidence,
        }


@dataclass
class AggregatedFinding:
    """Hallazgo agregado de múltiples fuentes."""
    id: str
    severity: str
    type: str
    message: str
    file: str
    line: int
    function: str
    swc_id: Optional[str]
    cwe_id: Optional[str]
    confidence: float
    tools: List[str]
    confirmations: int
    original_findings: List[Finding]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'severity': self.severity,
            'type': self.type,
            'message': self.message,
            'location': {
                'file': self.file,
                'line': self.line,
                'function': self.function,
            },
            'swc_id': self.swc_id,
            'cwe_id': self.cwe_id,
            'confidence': round(self.confidence, 3),
            'confirmed_by': self.tools,
            'confirmations': self.confirmations,
            'cross_validated': self.confirmations >= 2,
        }


class ResultAggregator:
    """
    Agrega y correlaciona resultados de múltiples herramientas de análisis.

    Características:
    - Deduplicación basada en similitud
    - Correlación cruzada entre herramientas
    - Boost de confianza por confirmaciones múltiples
    - Normalización de severidades
    """

    # Mapeo de severidades a valores numéricos
    SEVERITY_MAP = {
        'critical': 10,
        'high': 8,
        'medium': 5,
        'low': 2,
        'informational': 1,
        'info': 1,
        'note': 1,
        'warning': 3,
        'optimization': 1,
    }

    # Mapeo de tipos similares entre herramientas
    TYPE_ALIASES = {
        'reentrancy': ['reentrancy', 'reentrant', 'reentrancy-eth', 'reentrancy-no-eth', 'reentrancy-benign'],
        'overflow': ['overflow', 'integer-overflow', 'arithmetic', 'integer-overflow-and-underflow'],
        'underflow': ['underflow', 'integer-underflow'],
        'access-control': ['access-control', 'unprotected-upgrade', 'arbitrary-send', 'suicidal'],
        'unchecked-call': ['unchecked-call', 'unchecked-lowlevel', 'unchecked-send', 'low-level-calls'],
        'dos': ['dos', 'denial-of-service', 'locked-ether'],
        'timestamp': ['timestamp', 'block-timestamp', 'weak-prng', 'timestamp-dependency'],
        'front-running': ['front-running', 'frontrunning', 'transaction-order-dependence'],
    }

    def __init__(
        self,
        similarity_threshold: float = 0.85,
        min_confirmations: int = 2,
        confidence_boost: float = 0.15,
    ):
        self.similarity_threshold = similarity_threshold
        self.min_confirmations = min_confirmations
        self.confidence_boost = confidence_boost
        self._findings: List[Finding] = []
        self._aggregated: List[AggregatedFinding] = []

    def add_tool_results(self, tool_name: str, results: Dict[str, Any]) -> int:
        """
        Agrega resultados de una herramienta.
        Retorna el número de hallazgos agregados.
        """
        findings = results.get('findings', [])
        count = 0

        for f in findings:
            finding = self._normalize_finding(tool_name, f)
            if finding:
                self._findings.append(finding)
                count += 1

        return count

    def _normalize_finding(self, tool: str, raw: Dict[str, Any]) -> Optional[Finding]:
        """Normaliza un hallazgo raw a formato estándar."""
        try:
            # Extraer campos con fallbacks
            severity = self._normalize_severity(
                raw.get('severity', raw.get('impact', 'medium'))
            )

            finding_type = raw.get('type', raw.get('check', raw.get('name', 'unknown')))
            message = raw.get('message', raw.get('description', raw.get('title', '')))

            # Ubicación
            location = raw.get('location', {})
            file = location.get('file', raw.get('filename', raw.get('file', '')))
            line = location.get('line', raw.get('lineno', raw.get('line', 0)))
            function = location.get('function', raw.get('function', ''))

            # IDs de vulnerabilidad
            swc_id = raw.get('swc_id', raw.get('swc', None))
            cwe_id = raw.get('cwe_id', raw.get('cwe', None))

            # Confianza base
            confidence = raw.get('confidence', 1.0)
            if isinstance(confidence, str):
                confidence = {'high': 0.9, 'medium': 0.7, 'low': 0.5}.get(confidence.lower(), 0.7)

            # Generar ID único
            finding_id = self._generate_finding_id(tool, finding_type, file, line, message)

            return Finding(
                id=finding_id,
                tool=tool,
                severity=severity,
                type=finding_type.lower(),
                message=message,
                file=file,
                line=int(line) if line else 0,
                function=function,
                swc_id=swc_id,
                cwe_id=cwe_id,
                confidence=float(confidence),
                raw_data=raw,
            )
        except Exception:
            return None

    def _normalize_severity(self, severity: str) -> str:
        """Normaliza severidad a valores estándar."""
        severity_lower = str(severity).lower()

        # Mapeo directo
        if severity_lower in self.SEVERITY_MAP:
            return severity_lower

        # Mapeo por contenido
        if 'critical' in severity_lower or 'crit' in severity_lower:
            return 'critical'
        if 'high' in severity_lower:
            return 'high'
        if 'medium' in severity_lower or 'med' in severity_lower:
            return 'medium'
        if 'low' in severity_lower:
            return 'low'
        if 'info' in severity_lower or 'note' in severity_lower:
            return 'informational'

        return 'medium'  # Default

    def _generate_finding_id(
        self, tool: str, finding_type: str, file: str, line: int, message: str
    ) -> str:
        """Genera un ID único para un hallazgo."""
        content = f"{tool}:{finding_type}:{file}:{line}:{message[:100]}"
        return hashlib.md5(content.encode()).hexdigest()[:12]

    def _are_similar(self, f1: Finding, f2: Finding) -> bool:
        """Determina si dos hallazgos son similares."""
        # Mismo archivo y línea cercana
        if f1.file and f2.file:
            if f1.file != f2.file:
                return False
            if abs(f1.line - f2.line) > 5:  # Tolerancia de 5 líneas
                return False

        # Tipo similar
        type1_normalized = self._normalize_type(f1.type)
        type2_normalized = self._normalize_type(f2.type)

        if type1_normalized != type2_normalized:
            # Verificar si los mensajes son similares
            msg_similarity = SequenceMatcher(None, f1.message.lower(), f2.message.lower()).ratio()
            if msg_similarity < self.similarity_threshold:
                return False

        return True

    def _normalize_type(self, finding_type: str) -> str:
        """Normaliza el tipo de vulnerabilidad."""
        type_lower = finding_type.lower()

        for canonical, aliases in self.TYPE_ALIASES.items():
            if type_lower in aliases or any(alias in type_lower for alias in aliases):
                return canonical

        return type_lower

    def aggregate(self) -> List[AggregatedFinding]:
        """
        Agrega todos los hallazgos, deduplicando y correlacionando.
        """
        if not self._findings:
            return []

        # Agrupar hallazgos similares
        groups: List[List[Finding]] = []
        used = set()

        for i, f1 in enumerate(self._findings):
            if i in used:
                continue

            group = [f1]
            used.add(i)

            for j, f2 in enumerate(self._findings[i+1:], start=i+1):
                if j not in used and self._are_similar(f1, f2):
                    group.append(f2)
                    used.add(j)

            groups.append(group)

        # Crear hallazgos agregados
        self._aggregated = []
        for group in groups:
            aggregated = self._merge_group(group)
            self._aggregated.append(aggregated)

        # Ordenar por severidad y confianza
        self._aggregated.sort(
            key=lambda x: (
                -self.SEVERITY_MAP.get(x.severity, 5),
                -x.confidence,
                -x.confirmations
            )
        )

        return self._aggregated

    def _merge_group(self, group: List[Finding]) -> AggregatedFinding:
        """Fusiona un grupo de hallazgos similares."""
        # Usar el hallazgo con mayor severidad como base
        base = max(group, key=lambda f: self.SEVERITY_MAP.get(f.severity, 5))

        # Recopilar herramientas
        tools = list(set(f.tool for f in group))
        confirmations = len(tools)

        # Calcular confianza con boost
        base_confidence = max(f.confidence for f in group)
        boosted_confidence = min(
            1.0,
            base_confidence + (confirmations - 1) * self.confidence_boost
        )

        # Combinar SWC/CWE IDs
        swc_ids = [f.swc_id for f in group if f.swc_id]
        cwe_ids = [f.cwe_id for f in group if f.cwe_id]

        # Mejor mensaje (más largo generalmente es más descriptivo)
        best_message = max((f.message for f in group), key=len, default=base.message)

        # Generar ID único para el grupo
        group_id = hashlib.md5(
            f"{base.type}:{base.file}:{base.line}".encode()
        ).hexdigest()[:8]

        return AggregatedFinding(
            id=f"AGG-{group_id}",
            severity=base.severity,
            type=self._normalize_type(base.type),
            message=best_message,
            file=base.file,
            line=base.line,
            function=base.function,
            swc_id=swc_ids[0] if swc_ids else None,
            cwe_id=cwe_ids[0] if cwe_ids else None,
            confidence=boosted_confidence,
            tools=tools,
            confirmations=confirmations,
            original_findings=group,
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Obtiene estadísticas de la agregación."""
        if not self._aggregated:
            self.aggregate()

        total = len(self._aggregated)
        cross_validated = sum(1 for f in self._aggregated if f.confirmations >= self.min_confirmations)

        severity_counts = defaultdict(int)
        for f in self._aggregated:
            severity_counts[f.severity] += 1

        tool_counts = defaultdict(int)
        for f in self._aggregated:
            for tool in f.tools:
                tool_counts[tool] += 1

        avg_confidence = (
            sum(f.confidence for f in self._aggregated) / total
            if total > 0 else 0
        )

        return {
            'total_findings': total,
            'original_count': len(self._findings),
            'deduplicated': len(self._findings) - total,
            'cross_validated': cross_validated,
            'cross_validation_rate': round(cross_validated / total, 3) if total > 0 else 0,
            'severity_distribution': dict(severity_counts),
            'findings_per_tool': dict(tool_counts),
            'average_confidence': round(avg_confidence, 3),
            'unique_tools': len(tool_counts),
        }

    def get_high_confidence_findings(self, min_confidence: float = 0.8) -> List[AggregatedFinding]:
        """Obtiene hallazgos con alta confianza."""
        if not self._aggregated:
            self.aggregate()
        return [f for f in self._aggregated if f.confidence >= min_confidence]

    def get_cross_validated_findings(self) -> List[AggregatedFinding]:
        """Obtiene hallazgos confirmados por múltiples herramientas."""
        if not self._aggregated:
            self.aggregate()
        return [f for f in self._aggregated if f.confirmations >= self.min_confirmations]

    def to_report(self) -> Dict[str, Any]:
        """Genera un reporte completo."""
        if not self._aggregated:
            self.aggregate()

        return {
            'summary': self.get_statistics(),
            'findings': [f.to_dict() for f in self._aggregated],
            'high_confidence': [f.to_dict() for f in self.get_high_confidence_findings()],
            'cross_validated': [f.to_dict() for f in self.get_cross_validated_findings()],
        }

    def clear(self) -> None:
        """Limpia todos los hallazgos."""
        self._findings = []
        self._aggregated = []
