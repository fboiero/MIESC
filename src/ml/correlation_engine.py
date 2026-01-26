"""
MIESC Smart Correlation Engine v4.6.0
Motor ML que correlaciona hallazgos entre herramientas, reduce FPs por consenso
y genera scores de confianza basados en múltiples señales.

v4.6.0 Enhancements:
- CROSS_VALIDATION_REQUIRED: Mandatory cross-validation for critical patterns
- Single-tool confidence cap at 0.6 for critical findings
- Detector-specific FP rate integration
- Improved cross-function analysis support

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import hashlib
import math
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
from difflib import SequenceMatcher


class CorrelationMethod(Enum):
    """Métodos de correlación disponibles."""
    EXACT = "exact"  # Mismo archivo, línea y tipo
    SEMANTIC = "semantic"  # Mismo tipo normalizado y ubicación cercana
    CONTEXTUAL = "contextual"  # Mismo contexto de código
    EMBEDDING = "embedding"  # Similitud de embeddings


@dataclass
class ExploitChain:
    """Represents a chain of vulnerabilities that together form an attack path."""
    id: str
    name: str
    description: str
    severity: str  # Combined severity (usually escalated)
    base_cvss: float  # Base CVSS-like score

    # Chain components
    vulnerabilities: List[str]  # List of vulnerability IDs in the chain
    vuln_types: List[str]  # Canonical types involved
    attack_vector: str  # e.g., "external", "internal", "privileged"

    # Analysis
    exploitability_score: float  # 0-1, how likely to be exploited
    impact_score: float  # 0-1, potential damage
    complexity: str  # "low", "medium", "high"

    # Evidence
    source_files: List[str]
    affected_functions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'base_cvss': round(self.base_cvss, 1),
            'chain': {
                'vulnerabilities': self.vulnerabilities,
                'vuln_types': self.vuln_types,
                'length': len(self.vulnerabilities),
            },
            'attack_vector': self.attack_vector,
            'scores': {
                'exploitability': round(self.exploitability_score, 3),
                'impact': round(self.impact_score, 3),
                'combined': round((self.exploitability_score + self.impact_score) / 2, 3),
            },
            'complexity': self.complexity,
            'affected': {
                'files': self.source_files,
                'functions': self.affected_functions,
            },
        }


@dataclass
class ToolProfile:
    """Perfil de confiabilidad de una herramienta."""
    name: str
    precision_history: float = 0.5  # Histórico de precisión
    recall_history: float = 0.5  # Histórico de recall
    false_positive_rate: float = 0.5  # Tasa de FPs observada
    specialty_categories: List[str] = field(default_factory=list)  # Categorías donde destaca
    weakness_categories: List[str] = field(default_factory=list)  # Categorías donde falla
    total_findings: int = 0
    confirmed_findings: int = 0

    @property
    def reliability_score(self) -> float:
        """Calcula score de confiabilidad general."""
        if self.total_findings == 0:
            return 0.5

        confirmation_rate = self.confirmed_findings / self.total_findings
        precision_weight = 0.4
        recall_weight = 0.2
        confirmation_weight = 0.4

        return (
            self.precision_history * precision_weight +
            self.recall_history * recall_weight +
            confirmation_rate * confirmation_weight
        )


@dataclass
class CorrelatedFinding:
    """Hallazgo correlacionado de múltiples fuentes."""
    id: str
    canonical_type: str
    severity: str
    message: str
    location: Dict[str, Any]
    swc_id: Optional[str]
    cwe_id: Optional[str]

    # Información de correlación
    source_findings: List[Dict[str, Any]]
    confirming_tools: List[str]
    correlation_method: CorrelationMethod

    # Scores de confianza
    base_confidence: float
    tool_agreement_score: float
    context_score: float
    ml_confidence: float
    final_confidence: float

    # Metadata
    is_cross_validated: bool
    false_positive_probability: float
    remediation_priority: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.canonical_type,
            'severity': self.severity,
            'message': self.message,
            'location': self.location,
            'swc_id': self.swc_id,
            'cwe_id': self.cwe_id,
            'confirming_tools': self.confirming_tools,
            'tool_count': len(self.confirming_tools),
            'correlation_method': self.correlation_method.value,
            'confidence': {
                'base': round(self.base_confidence, 3),
                'tool_agreement': round(self.tool_agreement_score, 3),
                'context': round(self.context_score, 3),
                'ml': round(self.ml_confidence, 3),
                'final': round(self.final_confidence, 3),
            },
            'is_cross_validated': self.is_cross_validated,
            'fp_probability': round(self.false_positive_probability, 3),
            'priority': self.remediation_priority,
        }


class SmartCorrelationEngine:
    """
    Motor de correlación inteligente para hallazgos de seguridad.

    Características principales:
    1. Correlación multi-método (exacta, semántica, contextual, embeddings)
    2. Voting por consenso ponderado por confiabilidad de herramientas
    3. Scoring de confianza multi-señal
    4. Reducción de falsos positivos por análisis de contexto
    5. Aprendizaje de patrones de herramientas
    6. Scoring ponderado por herramienta (v4.2.0+)
    """

    # =========================================================================
    # TOOL WEIGHTS - Pesos de confiabilidad por herramienta
    # =========================================================================
    # Basados en benchmarks de precision/recall en SmartBugs dataset y auditorías reales
    # Valores más altos = mayor confiabilidad y menor tasa de FP

    TOOL_WEIGHTS = {
        # Layer 1: Static Analysis
        "slither": 0.85,       # Alta precisión, bajo FP, estándar de la industria
        "aderyn": 0.80,        # Rust-based, buena precisión, complementa Slither
        "solhint": 0.70,       # Más enfocado en linting, algunos FPs
        "wake": 0.75,          # Buen balance precisión/recall

        # Layer 2: Dynamic Testing
        "echidna": 0.88,       # Fuzzer de confianza, muy bajo FP
        "foundry": 0.85,       # Forge fuzzing, alta confianza
        "medusa": 0.82,        # Buen fuzzer paralelo
        "dogefuzz": 0.75,      # Más experimental

        # Layer 3: Symbolic Execution
        "mythril": 0.70,       # Más FPs pero detecta cosas únicas
        "manticore": 0.72,     # Similar a Mythril
        "halmos": 0.78,        # Más preciso para invariantes

        # Layer 4: Formal Verification
        "smtchecker": 0.90,    # Muy alta precisión (pero bajo recall)
        "certora": 0.92,       # Estándar de oro para FV

        # Layer 5: AI Analysis
        "smartllm": 0.65,      # LLM puede alucinar, más FPs
        "gptscan": 0.68,       # Similar
        "llmsmartaudit": 0.65,

        # Layer 6: ML Detection
        "dagnn": 0.72,         # ML tiene tasa moderada de FP
        "smartbugs_ml": 0.70,
        "smartbugs_detector": 0.68,
        "smartguard": 0.70,

        # Layer 7: Specialized
        "advanced_detector": 0.65,  # Más FPs, detecta cosas novedosas
        "semgrep": 0.75,       # Bueno para patterns
        "4naly3er": 0.65,      # Más FPs
    }

    # Perfiles base de herramientas (basados en benchmarks conocidos)
    DEFAULT_TOOL_PROFILES = {
        'slither': ToolProfile(
            name='slither',
            precision_history=0.75,
            recall_history=0.85,
            false_positive_rate=0.25,
            specialty_categories=['reentrancy', 'access-control', 'unchecked-call'],
            weakness_categories=['arithmetic', 'front-running'],
        ),
        'aderyn': ToolProfile(
            name='aderyn',
            precision_history=0.80,
            recall_history=0.70,
            false_positive_rate=0.20,
            specialty_categories=['access-control', 'reentrancy'],
            weakness_categories=['arithmetic'],
        ),
        'mythril': ToolProfile(
            name='mythril',
            precision_history=0.65,
            recall_history=0.75,
            false_positive_rate=0.35,
            specialty_categories=['arithmetic', 'dos'],
            weakness_categories=['code-quality'],
        ),
        'smartbugs-detector': ToolProfile(
            name='smartbugs-detector',
            precision_history=0.60,
            recall_history=0.80,
            false_positive_rate=0.40,
            specialty_categories=['arithmetic', 'bad-randomness', 'front-running', 'dos'],
            weakness_categories=[],
        ),
        'advanced-detector': ToolProfile(
            name='advanced-detector',
            precision_history=0.70,
            recall_history=0.65,
            false_positive_rate=0.30,
            specialty_categories=['rug-pull', 'honeypot', 'centralization'],
            weakness_categories=['reentrancy'],
        ),
        'semgrep': ToolProfile(
            name='semgrep',
            precision_history=0.80,
            recall_history=0.60,
            false_positive_rate=0.20,
            specialty_categories=['access-control', 'input-validation'],
            weakness_categories=['arithmetic'],
        ),
        'solhint': ToolProfile(
            name='solhint',
            precision_history=0.90,
            recall_history=0.50,
            false_positive_rate=0.10,
            specialty_categories=['code-quality', 'best-practices'],
            weakness_categories=['reentrancy', 'arithmetic'],
        ),
    }

    # Normalización de tipos de vulnerabilidades
    TYPE_NORMALIZATION = {
        # Reentrancy
        'reentrancy': 'reentrancy',
        'reentrancy-eth': 'reentrancy',
        'reentrancy-no-eth': 'reentrancy',
        'reentrancy-benign': 'reentrancy',
        'reentrancy-events': 'reentrancy',
        'reentrant': 'reentrancy',
        'external-call-in-loop': 'reentrancy',

        # Arithmetic
        'arithmetic': 'arithmetic',
        'overflow': 'arithmetic',
        'underflow': 'arithmetic',
        'integer-overflow': 'arithmetic',
        'integer-underflow': 'arithmetic',
        'integer-overflow-and-underflow': 'arithmetic',
        'divide-before-multiply': 'arithmetic',

        # Access Control
        'access-control': 'access-control',
        'unprotected-upgrade': 'access-control',
        'arbitrary-send': 'access-control',
        'arbitrary-send-eth': 'access-control',
        'suicidal': 'access-control',
        'unprotected-selfdestruct': 'access-control',
        'tx-origin': 'access-control',
        'missing-authorization': 'access-control',

        # Unchecked Calls
        'unchecked-call': 'unchecked-call',
        'unchecked-lowlevel': 'unchecked-call',
        'unchecked-send': 'unchecked-call',
        'unchecked-transfer': 'unchecked-call',
        'low-level-calls': 'unchecked-call',

        # DoS
        'dos': 'dos',
        'denial-of-service': 'dos',
        'locked-ether': 'dos',
        'gas-limit': 'dos',
        'unbounded-loop': 'dos',

        # Front Running
        'front-running': 'front-running',
        'frontrunning': 'front-running',
        'transaction-order-dependence': 'front-running',
        'tod': 'front-running',

        # Bad Randomness
        'bad-randomness': 'bad-randomness',
        'weak-prng': 'bad-randomness',
        'timestamp-dependency': 'bad-randomness',
        'block-timestamp': 'bad-randomness',

        # Time Manipulation
        'time-manipulation': 'time-manipulation',
        'timestamp': 'time-manipulation',

        # Code Quality (bajo riesgo)
        'naming-convention': 'code-quality',
        'solc-version': 'code-quality',
        'pragma': 'code-quality',
        'unused-return': 'code-quality',
        'dead-code': 'code-quality',
    }

    # Pesos de severidad
    SEVERITY_WEIGHTS = {
        'critical': 1.0,
        'high': 0.8,
        'medium': 0.5,
        'low': 0.2,
        'informational': 0.1,
        'info': 0.1,
    }

    # =========================================================================
    # v4.6.0: CROSS-VALIDATION REQUIRED PATTERNS
    # =========================================================================
    # These vulnerability patterns REQUIRE confirmation from 2+ tools
    # Single-tool findings for these patterns get max confidence of 0.6
    # Based on high FP rates observed in SmartBugs benchmark

    CROSS_VALIDATION_REQUIRED = {
        # Reentrancy patterns - high FP rate from single tools
        "reentrancy",
        "reentrancy-eth",
        "reentrancy-no-eth",
        "reentrancy-benign",
        "reentrancy-events",

        # Access control - context dependent
        "arbitrary-send",
        "arbitrary-send-eth",
        "unprotected-upgrade",

        # Dangerous operations
        "suicidal",
        "selfdestruct",
        "delegatecall",
        "controlled-delegatecall",

        # Storage issues
        "uninitialized-state",
        "uninitialized-storage",

        # Critical patterns
        "backdoor",
        "tx-origin",
    }

    # Maximum confidence for single-tool findings on critical patterns
    SINGLE_TOOL_MAX_CONFIDENCE = 0.60

    def __init__(
        self,
        min_tools_for_validation: int = 2,
        similarity_threshold: float = 0.75,
        context_window: int = 5,  # Líneas de contexto
    ):
        self.min_tools_for_validation = min_tools_for_validation
        self.similarity_threshold = similarity_threshold
        self.context_window = context_window

        self.tool_profiles: Dict[str, ToolProfile] = dict(self.DEFAULT_TOOL_PROFILES)
        self._findings: List[Dict[str, Any]] = []
        self._correlated: List[CorrelatedFinding] = []
        self._code_context_cache: Dict[str, str] = {}

    def add_findings(self, tool_name: str, findings: List[Dict[str, Any]]) -> int:
        """
        Agrega hallazgos de una herramienta.

        Returns:
            Número de hallazgos agregados
        """
        count = 0
        for finding in findings:
            normalized = self._normalize_finding(tool_name, finding)
            if normalized:
                self._findings.append(normalized)
                count += 1

        # Actualizar perfil de herramienta
        if tool_name not in self.tool_profiles:
            self.tool_profiles[tool_name] = ToolProfile(name=tool_name)
        self.tool_profiles[tool_name].total_findings += count

        return count

    def _normalize_finding(self, tool: str, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normaliza un hallazgo a formato estándar."""
        try:
            # Extraer tipo y normalizarlo
            raw_type = raw.get('type', raw.get('check', raw.get('name', 'unknown')))
            canonical_type = self._normalize_type(raw_type)

            # Extraer severidad
            severity = self._normalize_severity(
                raw.get('severity', raw.get('impact', 'medium'))
            )

            # Extraer ubicación
            location = raw.get('location', {})
            if not location:
                location = {
                    'file': raw.get('filename', raw.get('file', '')),
                    'line': raw.get('lineno', raw.get('line', 0)),
                    'function': raw.get('function', ''),
                }

            # Extraer mensaje
            message = raw.get('message', raw.get('description', raw.get('title', '')))

            # Extraer IDs de vulnerabilidad
            swc_id = raw.get('swc_id', raw.get('swc', None))
            cwe_id = raw.get('cwe_id', raw.get('cwe', None))

            # Confianza base
            confidence = raw.get('confidence', 0.7)
            if isinstance(confidence, str):
                confidence = {'high': 0.9, 'medium': 0.7, 'low': 0.5}.get(
                    confidence.lower(), 0.7
                )

            return {
                'tool': tool,
                'raw_type': raw_type,
                'canonical_type': canonical_type,
                'severity': severity,
                'message': message,
                'location': {
                    'file': str(location.get('file', '')),
                    'line': int(location.get('line') or 0),
                    'function': str(location.get('function', '')),
                    'snippet': str(location.get('snippet', '')),
                },
                'swc_id': swc_id,
                'cwe_id': cwe_id,
                'confidence': float(confidence),
                'raw': raw,
            }
        except Exception:
            return None

    def _normalize_type(self, vuln_type: str) -> str:
        """Normaliza tipo de vulnerabilidad a forma canónica."""
        type_lower = vuln_type.lower().strip()

        # Búsqueda directa
        if type_lower in self.TYPE_NORMALIZATION:
            return self.TYPE_NORMALIZATION[type_lower]

        # Búsqueda por contenido
        for key, canonical in self.TYPE_NORMALIZATION.items():
            if key in type_lower or type_lower in key:
                return canonical

        return type_lower

    def _normalize_severity(self, severity: str) -> str:
        """Normaliza severidad."""
        severity_lower = str(severity).lower().strip()

        if severity_lower in self.SEVERITY_WEIGHTS:
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

        return 'medium'

    def correlate(self) -> List[CorrelatedFinding]:
        """
        Ejecuta correlación completa de hallazgos.

        Returns:
            Lista de hallazgos correlacionados
        """
        if not self._findings:
            return []

        # Paso 1: Agrupar hallazgos similares
        groups = self._group_similar_findings()

        # Paso 2: Crear hallazgos correlacionados
        self._correlated = []
        for group in groups:
            correlated = self._create_correlated_finding(group)
            self._correlated.append(correlated)

        # Paso 3: Ordenar por prioridad
        self._correlated.sort(
            key=lambda x: (
                -self.SEVERITY_WEIGHTS.get(x.severity, 0.5),
                -x.final_confidence,
                -len(x.confirming_tools),
            )
        )

        # Paso 4: Asignar prioridades
        for i, finding in enumerate(self._correlated):
            finding.remediation_priority = i + 1

        return self._correlated

    def _group_similar_findings(self) -> List[List[Dict[str, Any]]]:
        """Agrupa hallazgos similares usando múltiples métodos."""
        groups: List[List[Dict[str, Any]]] = []
        used: Set[int] = set()

        for i, f1 in enumerate(self._findings):
            if i in used:
                continue

            group = [f1]
            used.add(i)

            for j, f2 in enumerate(self._findings[i+1:], start=i+1):
                if j in used:
                    continue

                method = self._find_correlation_method(f1, f2)
                if method:
                    group.append(f2)
                    used.add(j)

            groups.append(group)

        return groups

    def _find_correlation_method(
        self, f1: Dict[str, Any], f2: Dict[str, Any]
    ) -> Optional[CorrelationMethod]:
        """
        Determina el método de correlación entre dos hallazgos.

        Returns:
            CorrelationMethod si están correlacionados, None si no
        """
        loc1 = f1['location']
        loc2 = f2['location']

        # Correlación exacta: mismo archivo, línea exacta y tipo
        if (loc1['file'] == loc2['file'] and
            loc1['line'] == loc2['line'] and
            f1['canonical_type'] == f2['canonical_type']):
            return CorrelationMethod.EXACT

        # Correlación semántica: mismo tipo y ubicación cercana
        if f1['canonical_type'] == f2['canonical_type']:
            if loc1['file'] == loc2['file']:
                line_diff = abs(loc1['line'] - loc2['line'])
                if line_diff <= self.context_window:
                    return CorrelationMethod.SEMANTIC

        # Correlación contextual: mismo archivo, misma función, tipos relacionados
        if (loc1['file'] == loc2['file'] and
            loc1['function'] and loc1['function'] == loc2['function']):
            # Verificar si los tipos están relacionados
            if self._are_types_related(f1['canonical_type'], f2['canonical_type']):
                return CorrelationMethod.CONTEXTUAL

        # Correlación por similitud de mensaje
        msg_similarity = SequenceMatcher(
            None,
            f1['message'].lower()[:200],
            f2['message'].lower()[:200]
        ).ratio()

        if msg_similarity >= self.similarity_threshold:
            if loc1['file'] == loc2['file']:
                return CorrelationMethod.EMBEDDING

        return None

    def _are_types_related(self, type1: str, type2: str) -> bool:
        """Determina si dos tipos de vulnerabilidad están relacionados."""
        related_groups = [
            {'reentrancy', 'unchecked-call'},
            {'arithmetic', 'overflow', 'underflow'},
            {'access-control', 'tx-origin'},
            {'time-manipulation', 'bad-randomness'},
            {'dos', 'gas-limit'},
        ]

        for group in related_groups:
            if type1 in group and type2 in group:
                return True

        return type1 == type2

    def _create_correlated_finding(
        self, group: List[Dict[str, Any]]
    ) -> CorrelatedFinding:
        """Crea un hallazgo correlacionado desde un grupo."""
        # Usar el hallazgo con mayor severidad como base
        base = max(
            group,
            key=lambda f: self.SEVERITY_WEIGHTS.get(f['severity'], 0.5)
        )

        # Recopilar herramientas confirmantes
        tools = list(set(f['tool'] for f in group))

        # Determinar método de correlación predominante
        if len(group) > 1:
            methods = [
                self._find_correlation_method(group[0], f)
                for f in group[1:]
            ]
            method_counts = defaultdict(int)
            for m in methods:
                if m:
                    method_counts[m] += 1

            if method_counts:
                correlation_method = max(method_counts, key=method_counts.get)
            else:
                correlation_method = CorrelationMethod.SEMANTIC
        else:
            correlation_method = CorrelationMethod.EXACT

        # Calcular scores de confianza
        base_confidence = max(f['confidence'] for f in group)
        tool_agreement_score = self._calculate_tool_agreement(tools, base['canonical_type'])
        context_score = self._calculate_context_score(group)
        ml_confidence = self._calculate_ml_confidence(group)

        # Calcular confianza final ponderada
        # v4.6.0: Pass vuln_type for cross-validation enforcement
        final_confidence = self._calculate_final_confidence(
            base_confidence,
            tool_agreement_score,
            context_score,
            ml_confidence,
            len(tools),
            vuln_type=base['canonical_type'],
        )

        # Calcular probabilidad de FP
        fp_probability = self._calculate_fp_probability(group, final_confidence)

        # Combinar SWC/CWE IDs
        swc_ids = [f['swc_id'] for f in group if f.get('swc_id')]
        cwe_ids = [f['cwe_id'] for f in group if f.get('cwe_id')]

        # Mejor mensaje
        best_message = max(
            (f['message'] for f in group),
            key=len,
            default=base['message']
        )

        # Generar ID único
        group_id = hashlib.md5(
            f"{base['canonical_type']}:{base['location']['file']}:{base['location']['line']}".encode()
        ).hexdigest()[:8]

        return CorrelatedFinding(
            id=f"CORR-{group_id}",
            canonical_type=base['canonical_type'],
            severity=base['severity'],
            message=best_message,
            location=base['location'],
            swc_id=swc_ids[0] if swc_ids else None,
            cwe_id=cwe_ids[0] if cwe_ids else None,
            source_findings=group,
            confirming_tools=tools,
            correlation_method=correlation_method,
            base_confidence=base_confidence,
            tool_agreement_score=tool_agreement_score,
            context_score=context_score,
            ml_confidence=ml_confidence,
            final_confidence=final_confidence,
            is_cross_validated=len(tools) >= self.min_tools_for_validation,
            false_positive_probability=fp_probability,
            remediation_priority=0,  # Se asigna después
        )

    def _calculate_tool_agreement(
        self, tools: List[str], vuln_type: str
    ) -> float:
        """
        Calcula score de acuerdo entre herramientas.

        Considera:
        - Número de herramientas que reportan
        - Confiabilidad de cada herramienta
        - Especialidad de herramientas para el tipo de vulnerabilidad
        """
        if not tools:
            return 0.0

        # Número de herramientas (normalizado)
        count_score = min(len(tools) / 4.0, 1.0)

        # Confiabilidad ponderada
        reliability_sum = 0.0
        specialty_bonus = 0.0

        for tool in tools:
            profile = self.tool_profiles.get(tool, ToolProfile(name=tool))
            reliability_sum += profile.reliability_score

            # Bonus si la herramienta es especialista en este tipo
            if vuln_type in profile.specialty_categories:
                specialty_bonus += 0.1
            elif vuln_type in profile.weakness_categories:
                specialty_bonus -= 0.05

        avg_reliability = reliability_sum / len(tools)
        specialty_bonus = min(specialty_bonus, 0.3)  # Cap bonus

        # Combinación ponderada
        agreement_score = (
            count_score * 0.4 +
            avg_reliability * 0.4 +
            specialty_bonus * 0.2
        )

        return min(agreement_score, 1.0)

    def calculate_weighted_confidence(
        self,
        finding: Dict[str, Any],
        tools_reporting: List[str],
    ) -> float:
        """
        Calcula confianza ponderada basada en herramientas que reportan.

        Usa TOOL_WEIGHTS para ponderar la confianza según la confiabilidad
        histórica de cada herramienta. Herramientas más confiables (como
        Slither, Echidna) tienen mayor peso que las experimentales.

        Args:
            finding: El hallazgo a evaluar
            tools_reporting: Lista de herramientas que reportan este hallazgo

        Returns:
            Confianza ponderada entre 0.0 y 1.0
        """
        if not tools_reporting:
            return finding.get('confidence', 0.5)

        # Obtener peso total y ponderado
        total_weight = 0.0
        weighted_confidence = 0.0
        base_confidence = finding.get('confidence', 0.7)

        for tool in tools_reporting:
            tool_weight = self.TOOL_WEIGHTS.get(tool.lower(), 0.50)
            total_weight += tool_weight
            weighted_confidence += tool_weight * base_confidence

        if total_weight == 0:
            return base_confidence

        # Normalizar
        normalized_confidence = weighted_confidence / total_weight

        # Boost por múltiples herramientas de alta confianza
        high_confidence_tools = sum(
            1 for t in tools_reporting
            if self.TOOL_WEIGHTS.get(t.lower(), 0.5) >= 0.80
        )

        if high_confidence_tools >= 2:
            # Dos o más herramientas confiables confirman = boost significativo
            normalized_confidence += 0.10
        elif high_confidence_tools == 1 and len(tools_reporting) >= 2:
            # Una herramienta confiable + otra = boost moderado
            normalized_confidence += 0.05

        return min(normalized_confidence, 0.99)

    def get_tool_weight(self, tool_name: str) -> float:
        """
        Obtiene el peso de confiabilidad de una herramienta.

        Args:
            tool_name: Nombre de la herramienta

        Returns:
            Peso de confiabilidad (0.0-1.0), default 0.50 si no conocida
        """
        return self.TOOL_WEIGHTS.get(tool_name.lower(), 0.50)

    def requires_cross_validation(self, vuln_type: str) -> bool:
        """
        Check if a vulnerability type requires cross-validation (2+ tools).

        v4.6.0: Critical patterns need confirmation from multiple tools
        to reduce false positives.

        Args:
            vuln_type: Vulnerability type (e.g., "reentrancy-eth")

        Returns:
            True if cross-validation is required
        """
        vuln_lower = vuln_type.lower()
        return any(
            pattern in vuln_lower
            for pattern in self.CROSS_VALIDATION_REQUIRED
        )

    def apply_cross_validation_penalty(
        self,
        finding: Dict[str, Any],
        tool_count: int,
    ) -> Dict[str, Any]:
        """
        Apply cross-validation penalty to single-tool critical findings.

        If a finding requires cross-validation but only has one tool,
        cap its confidence at SINGLE_TOOL_MAX_CONFIDENCE.

        Args:
            finding: The finding to evaluate
            tool_count: Number of tools that reported this finding

        Returns:
            Finding with potentially adjusted confidence
        """
        vuln_type = finding.get('type', finding.get('canonical_type', ''))

        if tool_count < 2 and self.requires_cross_validation(vuln_type):
            finding = finding.copy()
            original_confidence = finding.get('confidence', 0.7)

            if original_confidence > self.SINGLE_TOOL_MAX_CONFIDENCE:
                finding['confidence'] = self.SINGLE_TOOL_MAX_CONFIDENCE
                finding['_cross_validation'] = {
                    'required': True,
                    'tool_count': tool_count,
                    'original_confidence': original_confidence,
                    'capped_confidence': self.SINGLE_TOOL_MAX_CONFIDENCE,
                    'reason': 'Critical pattern requires 2+ tools for confirmation',
                }

        return finding

    def _calculate_context_score(self, group: List[Dict[str, Any]]) -> float:
        """
        Calcula score basado en contexto del código.

        Considera:
        - Presencia de patrones de seguridad
        - Ubicación en código de producción vs test
        - Complejidad del contexto
        """
        context_signals = []

        for finding in group:
            snippet = finding['location'].get('snippet', '')
            file_path = finding['location'].get('file', '')

            # Señales positivas (probable TP)
            positive_signals = 0

            # Patrones peligrosos en el snippet
            dangerous_patterns = [
                r'\.(call|delegatecall|staticcall)\s*\(',
                r'tx\.origin',
                r'selfdestruct',
                r'assembly\s*\{',
            ]
            for pattern in dangerous_patterns:
                if re.search(pattern, snippet, re.I):
                    positive_signals += 0.15

            # Señales negativas (probable FP)
            negative_signals = 0

            # Archivos de test
            if re.search(r'test[s]?[/\\]|\.t\.sol$|Test\.sol$|Mock', file_path, re.I):
                negative_signals += 0.25

            # Protecciones en snippet
            safe_patterns = [
                r'require\s*\(',
                r'onlyOwner',
                r'nonReentrant',
                r'SafeMath',
            ]
            for pattern in safe_patterns:
                if re.search(pattern, snippet, re.I):
                    negative_signals += 0.1

            context_score = 0.5 + positive_signals - negative_signals
            context_signals.append(max(0.1, min(0.95, context_score)))

        return sum(context_signals) / len(context_signals) if context_signals else 0.5

    def _calculate_ml_confidence(self, group: List[Dict[str, Any]]) -> float:
        """
        Calcula confianza usando features ML.

        Features consideradas:
        - Consistencia de severidad entre reportes
        - Presencia de SWC/CWE IDs
        - Longitud y calidad de mensajes
        - Diversidad de herramientas
        """
        features = []

        # Feature 1: Consistencia de severidad
        severities = [f['severity'] for f in group]
        unique_severities = len(set(severities))
        severity_consistency = 1.0 - (unique_severities - 1) * 0.2
        features.append(max(0, severity_consistency))

        # Feature 2: Presencia de IDs estándar
        has_swc = any(f.get('swc_id') for f in group)
        has_cwe = any(f.get('cwe_id') for f in group)
        id_score = (0.4 if has_swc else 0) + (0.3 if has_cwe else 0) + 0.3
        features.append(id_score)

        # Feature 3: Calidad de mensajes
        avg_msg_len = sum(len(f['message']) for f in group) / len(group)
        msg_quality = min(avg_msg_len / 200.0, 1.0)
        features.append(msg_quality)

        # Feature 4: Diversidad de herramientas
        unique_tools = len(set(f['tool'] for f in group))
        tool_diversity = min(unique_tools / 3.0, 1.0)
        features.append(tool_diversity)

        # Feature 5: Consistencia de ubicación
        lines = [f['location']['line'] for f in group if f['location']['line'] > 0]
        if lines:
            line_variance = max(lines) - min(lines)
            location_consistency = 1.0 - min(line_variance / 10.0, 0.5)
        else:
            location_consistency = 0.5
        features.append(location_consistency)

        # Combinación simple (simulando modelo ML)
        weights = [0.2, 0.25, 0.15, 0.25, 0.15]
        ml_score = sum(f * w for f, w in zip(features, weights))

        return min(ml_score, 0.95)

    def _calculate_final_confidence(
        self,
        base: float,
        tool_agreement: float,
        context: float,
        ml: float,
        tool_count: int,
        vuln_type: str = "",
    ) -> float:
        """
        Calcula confianza final combinando todas las señales.

        v4.6.0: Added cross-validation enforcement for critical patterns.
        Single-tool findings for patterns in CROSS_VALIDATION_REQUIRED
        are capped at SINGLE_TOOL_MAX_CONFIDENCE (0.60).
        """
        # Pesos adaptativos basados en número de herramientas
        if tool_count >= 3:
            # Alta validación cruzada - confiar más en consenso
            weights = {
                'base': 0.15,
                'tool_agreement': 0.40,
                'context': 0.20,
                'ml': 0.25,
            }
        elif tool_count == 2:
            # Validación moderada
            weights = {
                'base': 0.20,
                'tool_agreement': 0.30,
                'context': 0.25,
                'ml': 0.25,
            }
        else:
            # Una sola herramienta - confiar más en contexto y ML
            weights = {
                'base': 0.30,
                'tool_agreement': 0.15,
                'context': 0.30,
                'ml': 0.25,
            }

        final = (
            base * weights['base'] +
            tool_agreement * weights['tool_agreement'] +
            context * weights['context'] +
            ml * weights['ml']
        )

        # Bonus por múltiples herramientas
        if tool_count >= 2:
            final += 0.05 * min(tool_count - 1, 3)

        # v4.6.0: Cross-validation enforcement for critical patterns
        if tool_count < 2:
            # Check if this vulnerability type requires cross-validation
            vuln_lower = vuln_type.lower()
            requires_cv = any(
                pattern in vuln_lower
                for pattern in self.CROSS_VALIDATION_REQUIRED
            )

            if requires_cv:
                # Cap confidence for single-tool critical findings
                final = min(final, self.SINGLE_TOOL_MAX_CONFIDENCE)

        return min(final, 0.99)

    def _calculate_fp_probability(
        self, group: List[Dict[str, Any]], confidence: float
    ) -> float:
        """
        Calcula probabilidad de ser falso positivo.
        """
        fp_signals = []

        # Inversa de confianza
        fp_signals.append(1.0 - confidence)

        # FP rate histórica de herramientas
        for finding in group:
            tool = finding['tool']
            profile = self.tool_profiles.get(tool, ToolProfile(name=tool))
            fp_signals.append(profile.false_positive_rate)

        # Tipos con alto FP rate conocido
        high_fp_types = {'code-quality', 'naming-convention', 'solc-version'}
        canonical_type = group[0]['canonical_type']
        if canonical_type in high_fp_types:
            fp_signals.append(0.6)

        # Una sola herramienta
        unique_tools = len(set(f['tool'] for f in group))
        if unique_tools == 1:
            fp_signals.append(0.3)

        # Promedio ponderado
        return sum(fp_signals) / len(fp_signals) if fp_signals else 0.5

    def get_high_confidence_findings(
        self, min_confidence: float = 0.7
    ) -> List[CorrelatedFinding]:
        """Obtiene hallazgos con alta confianza."""
        return [f for f in self._correlated if f.final_confidence >= min_confidence]

    def get_cross_validated_findings(self) -> List[CorrelatedFinding]:
        """Obtiene hallazgos validados por múltiples herramientas."""
        return [f for f in self._correlated if f.is_cross_validated]

    def get_likely_true_positives(
        self, fp_threshold: float = 0.4
    ) -> List[CorrelatedFinding]:
        """Obtiene hallazgos con baja probabilidad de FP."""
        return [f for f in self._correlated if f.false_positive_probability <= fp_threshold]

    def get_statistics(self) -> Dict[str, Any]:
        """Genera estadísticas de la correlación."""
        if not self._correlated:
            return {'total': 0, 'no_data': True}

        total = len(self._correlated)
        cross_validated = sum(1 for f in self._correlated if f.is_cross_validated)
        high_confidence = sum(1 for f in self._correlated if f.final_confidence >= 0.7)
        likely_tp = sum(1 for f in self._correlated if f.false_positive_probability <= 0.4)

        severity_dist = defaultdict(int)
        type_dist = defaultdict(int)
        tool_dist = defaultdict(int)

        for f in self._correlated:
            severity_dist[f.severity] += 1
            type_dist[f.canonical_type] += 1
            for tool in f.confirming_tools:
                tool_dist[tool] += 1

        avg_confidence = sum(f.final_confidence for f in self._correlated) / total
        avg_tools = sum(len(f.confirming_tools) for f in self._correlated) / total

        return {
            'total_correlated': total,
            'original_findings': len(self._findings),
            'deduplication_rate': round(1 - total / max(len(self._findings), 1), 3),
            'cross_validated': cross_validated,
            'cross_validation_rate': round(cross_validated / total, 3),
            'high_confidence_count': high_confidence,
            'high_confidence_rate': round(high_confidence / total, 3),
            'likely_true_positives': likely_tp,
            'likely_tp_rate': round(likely_tp / total, 3),
            'average_confidence': round(avg_confidence, 3),
            'average_tools_per_finding': round(avg_tools, 2),
            'by_severity': dict(severity_dist),
            'by_type': dict(type_dist),
            'by_tool': dict(tool_dist),
        }

    def to_report(self) -> Dict[str, Any]:
        """Genera reporte completo."""
        return {
            'summary': self.get_statistics(),
            'all_findings': [f.to_dict() for f in self._correlated],
            'high_confidence': [f.to_dict() for f in self.get_high_confidence_findings()],
            'cross_validated': [f.to_dict() for f in self.get_cross_validated_findings()],
            'likely_true_positives': [f.to_dict() for f in self.get_likely_true_positives()],
            'tool_profiles': {
                name: {
                    'reliability': round(p.reliability_score, 3),
                    'precision': p.precision_history,
                    'recall': p.recall_history,
                    'fp_rate': p.false_positive_rate,
                    'specialties': p.specialty_categories,
                }
                for name, p in self.tool_profiles.items()
            },
        }

    def update_tool_profile(
        self,
        tool_name: str,
        confirmed_count: int,
        total_count: int,
    ) -> None:
        """
        Actualiza perfil de herramienta basado en feedback.

        Args:
            tool_name: Nombre de la herramienta
            confirmed_count: Número de hallazgos confirmados como TP
            total_count: Número total de hallazgos
        """
        if tool_name not in self.tool_profiles:
            self.tool_profiles[tool_name] = ToolProfile(name=tool_name)

        profile = self.tool_profiles[tool_name]
        profile.confirmed_findings += confirmed_count
        profile.total_findings += total_count

        # Actualizar tasa de FP
        if total_count > 0:
            new_precision = confirmed_count / total_count
            # Promedio móvil con historial
            alpha = 0.3  # Peso de nuevos datos
            profile.precision_history = (
                alpha * new_precision + (1 - alpha) * profile.precision_history
            )
            profile.false_positive_rate = (
                alpha * (1 - new_precision) + (1 - alpha) * profile.false_positive_rate
            )

    def clear(self) -> None:
        """Limpia todos los hallazgos."""
        self._findings = []
        self._correlated = []
        self._code_context_cache = {}

    # =========================================================================
    # SEMANTIC DEDUPLICATION - Deduplicación Semántica Avanzada
    # =========================================================================

    def _calculate_semantic_hash(self, finding: Dict[str, Any]) -> str:
        """
        Calcula un hash semántico para un hallazgo.

        El hash está basado en:
        - Tipo de vulnerabilidad (normalizado)
        - Archivo fuente
        - Rango de líneas (con tolerancia de ±3 líneas)
        - Función afectada (si disponible)

        Esto permite agrupar hallazgos que reportan el mismo problema
        desde diferentes herramientas con ligeras variaciones en ubicación.

        Args:
            finding: Hallazgo normalizado

        Returns:
            Hash semántico como string
        """
        vuln_type = finding.get('canonical_type', finding.get('type', 'unknown'))
        location = finding.get('location', {})
        file_path = location.get('file', '')
        line = location.get('line', 0)
        function = location.get('function', '')

        # Normalizar línea a rango (agrupamos líneas cercanas)
        line_bucket = (line // 5) * 5  # Bucket de 5 líneas

        # Construir componentes del hash
        components = [
            vuln_type.lower(),
            Path(file_path).name if file_path else 'unknown',
            str(line_bucket),
            function.lower() if function else '',
        ]

        # Crear hash
        hash_input = '|'.join(components)
        return hashlib.md5(hash_input.encode()).hexdigest()[:12]

    def deduplicate_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Agrupa y deduplica hallazgos que reportan el mismo problema.

        Hallazgos similares de múltiples herramientas se fusionan en uno,
        combinando evidencia y aumentando la confianza.

        Args:
            findings: Lista de hallazgos a deduplicar

        Returns:
            Lista de hallazgos deduplicados con metadata de fusión
        """
        if not findings:
            return []

        # Agrupar por hash semántico
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for finding in findings:
            semantic_hash = self._calculate_semantic_hash(finding)
            groups[semantic_hash].append(finding)

        # Fusionar cada grupo
        deduplicated = []
        for semantic_hash, group in groups.items():
            if len(group) == 1:
                # Un solo hallazgo, no hay fusión
                merged = group[0].copy()
                merged['_dedup'] = {
                    'merged_count': 1,
                    'tools': [group[0].get('tool', 'unknown')],
                    'semantic_hash': semantic_hash,
                }
                deduplicated.append(merged)
            else:
                # Múltiples hallazgos, fusionar
                merged = self._merge_finding_group(group, semantic_hash)
                deduplicated.append(merged)

        logger.info(
            f"Deduplication: {len(findings)} -> {len(deduplicated)} "
            f"({len(findings) - len(deduplicated)} merged)"
        )

        return deduplicated

    def _merge_finding_group(
        self,
        group: List[Dict[str, Any]],
        semantic_hash: str,
    ) -> Dict[str, Any]:
        """
        Fusiona un grupo de hallazgos similares en uno.

        La fusión:
        - Usa la severidad más alta
        - Combina evidencia de todas las herramientas
        - Aumenta la confianza basándose en confirmaciones múltiples
        - Preserva el mejor mensaje/descripción

        Args:
            group: Lista de hallazgos a fusionar
            semantic_hash: Hash semántico del grupo

        Returns:
            Hallazgo fusionado
        """
        # Ordenar por severidad (usar el más severo como base)
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        sorted_group = sorted(
            group,
            key=lambda f: severity_order.get(f.get('severity', '').lower(), 0),
            reverse=True
        )

        # Usar el hallazgo más severo como base
        base = sorted_group[0].copy()

        # Recopilar herramientas
        tools = list(set(f.get('tool', 'unknown') for f in group))

        # Recopilar evidencia (mensajes únicos)
        evidence = []
        seen_messages = set()
        for f in group:
            msg = f.get('message', f.get('description', ''))[:200]
            if msg and msg not in seen_messages:
                evidence.append({
                    'tool': f.get('tool', 'unknown'),
                    'message': msg,
                    'severity': f.get('severity', 'unknown'),
                })
                seen_messages.add(msg)

        # Calcular boost de confianza por múltiples confirmaciones
        base_confidence = max(f.get('confidence', 0.5) for f in group)
        confidence_boost = min(len(tools) * 0.12, 0.35)  # Max 35% boost

        # Aplicar pesos de herramientas
        weighted_boost = 0.0
        for tool in tools:
            tool_weight = self.TOOL_WEIGHTS.get(tool.lower(), 0.5)
            weighted_boost += tool_weight * 0.05

        final_confidence = min(base_confidence + confidence_boost + weighted_boost, 0.99)

        # Mejor descripción (la más larga suele ser más informativa)
        best_description = max(
            (f.get('description', '') for f in group),
            key=len,
            default=base.get('description', '')
        )

        # Combinar SWC/CWE IDs
        swc_ids = [f.get('swc_id') for f in group if f.get('swc_id')]
        cwe_ids = [f.get('cwe_id') for f in group if f.get('cwe_id')]

        # Actualizar hallazgo fusionado
        base['confidence'] = final_confidence
        base['description'] = best_description
        base['swc_id'] = swc_ids[0] if swc_ids else base.get('swc_id')
        base['cwe_id'] = cwe_ids[0] if cwe_ids else base.get('cwe_id')

        # Metadata de deduplicación
        base['_dedup'] = {
            'merged_count': len(group),
            'tools': tools,
            'semantic_hash': semantic_hash,
            'evidence': evidence,
            'confidence_boost': round(confidence_boost + weighted_boost, 3),
            'is_cross_validated': len(tools) >= 2,
        }

        return base

    def get_deduplication_stats(
        self,
        original: List[Dict[str, Any]],
        deduplicated: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Genera estadísticas de deduplicación.

        Args:
            original: Lista original de hallazgos
            deduplicated: Lista deduplicada

        Returns:
            Estadísticas de la deduplicación
        """
        merged_count = len(original) - len(deduplicated)
        dedup_rate = merged_count / max(len(original), 1)

        # Contar cross-validated
        cross_validated = sum(
            1 for f in deduplicated
            if f.get('_dedup', {}).get('is_cross_validated', False)
        )

        # Promedio de herramientas por hallazgo
        avg_tools = sum(
            len(f.get('_dedup', {}).get('tools', []))
            for f in deduplicated
        ) / max(len(deduplicated), 1)

        return {
            'original_count': len(original),
            'deduplicated_count': len(deduplicated),
            'merged_count': merged_count,
            'deduplication_rate': round(dedup_rate, 3),
            'cross_validated_count': cross_validated,
            'cross_validation_rate': round(cross_validated / max(len(deduplicated), 1), 3),
            'average_tools_per_finding': round(avg_tools, 2),
        }


# =============================================================================
# EXPLOIT CHAIN ANALYZER
# =============================================================================

class ExploitChainAnalyzer:
    """
    Analyzes correlated findings to detect exploit chains.

    An exploit chain is a combination of vulnerabilities that together
    create a more severe attack path than individual vulnerabilities.

    Examples:
    - Reentrancy + Unchecked Call = Fund Drain
    - Access Control + Selfdestruct = Contract Destruction
    - Front-Running + Price Oracle = Sandwich Attack
    - tx.origin + External Call = Phishing Attack
    """

    # Known exploit chain patterns
    # Format: (required_types, chain_name, description, severity_escalation, base_cvss)
    KNOWN_CHAINS = [
        # Critical Chains (CVSS 9.0+)
        (
            {'reentrancy', 'unchecked-call'},
            'Fund Drain Attack',
            'Reentrancy combined with unchecked call enables complete fund drainage. '
            'Attacker can recursively call withdraw and drain all contract funds.',
            'critical', 9.8
        ),
        (
            {'access-control', 'selfdestruct'},
            'Contract Destruction',
            'Missing access control on selfdestruct allows anyone to destroy the contract '
            'and steal remaining funds.',
            'critical', 10.0
        ),
        (
            {'reentrancy', 'access-control'},
            'Privileged Reentrancy',
            'Reentrancy in privileged function allows attacker to bypass access controls '
            'through recursive calls.',
            'critical', 9.5
        ),

        # High Chains (CVSS 7.0-8.9)
        (
            {'front-running', 'bad-randomness'},
            'Predictable Outcome Manipulation',
            'Weak randomness combined with transaction ordering allows attacker to '
            'predict and manipulate outcomes (gambling, NFT mints, etc.).',
            'high', 8.5
        ),
        (
            {'access-control', 'arithmetic'},
            'Privileged Overflow',
            'Arithmetic overflow in privileged function allows unauthorized balance manipulation.',
            'high', 8.2
        ),
        (
            {'tx-origin', 'reentrancy'},
            'Phishing Reentrancy',
            'tx.origin authentication combined with reentrancy enables phishing attacks '
            'that drain user funds through malicious contracts.',
            'high', 8.0
        ),
        (
            {'unchecked-call', 'dos'},
            'Griefing Attack',
            'Unchecked external call combined with DoS pattern allows attacker to '
            'permanently lock contract functionality.',
            'high', 7.5
        ),
        (
            {'front-running', 'access-control'},
            'Front-Run Access Bypass',
            'Front-running can be used to bypass access control checks by manipulating '
            'transaction ordering.',
            'high', 7.8
        ),

        # Medium Chains (CVSS 4.0-6.9)
        (
            {'arithmetic', 'unchecked-call'},
            'Silent Overflow',
            'Arithmetic overflow combined with unchecked call may silently fail '
            'without proper error handling.',
            'medium', 6.5
        ),
        (
            {'time-manipulation', 'access-control'},
            'Time-Based Access Bypass',
            'Timestamp manipulation can bypass time-locked access controls.',
            'medium', 6.0
        ),
        (
            {'bad-randomness', 'arithmetic'},
            'Predictable Lottery',
            'Weak randomness with arithmetic operations makes lottery/game outcomes predictable.',
            'medium', 5.5
        ),
    ]

    def __init__(self):
        self._chains: List[ExploitChain] = []

    def analyze(self, correlated_findings: List[CorrelatedFinding]) -> List[ExploitChain]:
        """
        Analyze correlated findings to detect exploit chains.

        Args:
            correlated_findings: List of CorrelatedFinding from SmartCorrelationEngine

        Returns:
            List of detected exploit chains, sorted by severity
        """
        self._chains = []

        if len(correlated_findings) < 2:
            return self._chains

        # Extract vulnerability types present
        vuln_types_present = set()
        type_to_findings: Dict[str, List[CorrelatedFinding]] = defaultdict(list)

        for finding in correlated_findings:
            vuln_types_present.add(finding.canonical_type)
            type_to_findings[finding.canonical_type].append(finding)

        # Check each known chain pattern
        for required_types, name, description, severity, base_cvss in self.KNOWN_CHAINS:
            if required_types.issubset(vuln_types_present):
                chain = self._build_chain(
                    required_types, name, description, severity, base_cvss,
                    type_to_findings
                )
                if chain:
                    self._chains.append(chain)

        # Also detect custom chains based on proximity
        custom_chains = self._detect_proximity_chains(correlated_findings)
        self._chains.extend(custom_chains)

        # Sort by CVSS score (descending)
        self._chains.sort(key=lambda c: -c.base_cvss)

        return self._chains

    def _build_chain(
        self,
        required_types: Set[str],
        name: str,
        description: str,
        severity: str,
        base_cvss: float,
        type_to_findings: Dict[str, List[CorrelatedFinding]],
    ) -> Optional[ExploitChain]:
        """Build an exploit chain from matched pattern."""
        chain_vulns = []
        chain_types = []
        files = set()
        functions = set()

        for vuln_type in required_types:
            findings = type_to_findings.get(vuln_type, [])
            if findings:
                # Use highest confidence finding for each type
                best = max(findings, key=lambda f: f.final_confidence)
                chain_vulns.append(best.id)
                chain_types.append(vuln_type)
                files.add(best.location.get('file', 'unknown'))
                if best.location.get('function'):
                    functions.add(best.location['function'])

        if len(chain_vulns) < 2:
            return None

        # Calculate exploitability based on involved findings
        avg_confidence = sum(
            type_to_findings[t][0].final_confidence
            for t in required_types if type_to_findings.get(t)
        ) / len(required_types)

        # Determine attack vector
        attack_vector = self._determine_attack_vector(required_types)

        # Determine complexity
        complexity = self._determine_complexity(required_types, len(chain_vulns))

        # Calculate impact score
        impact_score = self._calculate_impact_score(severity, base_cvss)

        # Generate chain ID
        chain_id = hashlib.md5(
            f"{name}:{':'.join(sorted(chain_types))}:{':'.join(sorted(files))}".encode()
        ).hexdigest()[:8]

        return ExploitChain(
            id=f"CHAIN-{chain_id}",
            name=name,
            description=description,
            severity=severity,
            base_cvss=base_cvss,
            vulnerabilities=chain_vulns,
            vuln_types=chain_types,
            attack_vector=attack_vector,
            exploitability_score=avg_confidence * 0.9,  # Slightly reduce for chain complexity
            impact_score=impact_score,
            complexity=complexity,
            source_files=list(files),
            affected_functions=list(functions),
        )

    def _detect_proximity_chains(
        self, findings: List[CorrelatedFinding]
    ) -> List[ExploitChain]:
        """Detect chains based on code proximity (same function/file)."""
        proximity_chains = []

        # Group by file
        by_file: Dict[str, List[CorrelatedFinding]] = defaultdict(list)
        for f in findings:
            file_path = f.location.get('file', '')
            if file_path:
                by_file[file_path].append(f)

        # Check each file for potential chains
        for file_path, file_findings in by_file.items():
            if len(file_findings) < 2:
                continue

            # Group by function
            by_func: Dict[str, List[CorrelatedFinding]] = defaultdict(list)
            for f in file_findings:
                func = f.location.get('function', '_global_')
                by_func[func].append(f)

            # Detect function-level chains
            for func, func_findings in by_func.items():
                if len(func_findings) >= 2:
                    chain = self._build_proximity_chain(func_findings, file_path, func)
                    if chain:
                        proximity_chains.append(chain)

        return proximity_chains

    def _build_proximity_chain(
        self,
        findings: List[CorrelatedFinding],
        file_path: str,
        function: str,
    ) -> Optional[ExploitChain]:
        """Build a chain from findings in same function."""
        # Only build if we have different vulnerability types
        types = set(f.canonical_type for f in findings)
        if len(types) < 2:
            return None

        # Skip if it matches a known chain (already detected)
        for required_types, _, _, _, _ in self.KNOWN_CHAINS:
            if required_types.issubset(types):
                return None  # Already handled

        # Calculate combined severity
        severities = [f.severity for f in findings]
        severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}
        max_severity = max(severities, key=lambda s: severity_scores.get(s, 0))

        # Escalate if multiple high-severity findings
        high_count = sum(1 for s in severities if s in ['critical', 'high'])
        if high_count >= 2 and max_severity == 'high':
            combined_severity = 'critical'
            base_cvss = 9.0
        elif high_count >= 1:
            combined_severity = 'high'
            base_cvss = 7.5
        else:
            combined_severity = 'medium'
            base_cvss = 5.5

        avg_confidence = sum(f.final_confidence for f in findings) / len(findings)

        chain_id = hashlib.md5(
            f"proximity:{file_path}:{function}:{':'.join(sorted(types))}".encode()
        ).hexdigest()[:8]

        return ExploitChain(
            id=f"CHAIN-{chain_id}",
            name=f"Combined Vulnerabilities in {function or 'contract'}",
            description=f"Multiple vulnerabilities ({', '.join(types)}) found in the same "
                       f"{'function' if function else 'contract'} may be chained for exploitation.",
            severity=combined_severity,
            base_cvss=base_cvss,
            vulnerabilities=[f.id for f in findings],
            vuln_types=list(types),
            attack_vector='external',
            exploitability_score=avg_confidence * 0.8,
            impact_score=base_cvss / 10.0,
            complexity='medium',
            source_files=[file_path],
            affected_functions=[function] if function else [],
        )

    def _determine_attack_vector(self, vuln_types: Set[str]) -> str:
        """Determine attack vector based on vulnerability types."""
        # External (anyone can trigger)
        external_types = {'reentrancy', 'front-running', 'arithmetic', 'dos', 'bad-randomness'}
        if vuln_types & external_types:
            return 'external'

        # Privileged (requires special access)
        privileged_types = {'access-control'}
        if vuln_types & privileged_types:
            return 'privileged'

        return 'internal'

    def _determine_complexity(self, vuln_types: Set[str], chain_length: int) -> str:
        """Determine attack complexity."""
        # Simple attacks
        simple_types = {'arithmetic', 'unchecked-call'}
        if vuln_types.issubset(simple_types):
            return 'low'

        # Complex attacks
        complex_types = {'front-running', 'time-manipulation', 'bad-randomness'}
        if vuln_types & complex_types:
            return 'high' if chain_length > 2 else 'medium'

        return 'medium'

    def _calculate_impact_score(self, severity: str, base_cvss: float) -> float:
        """Calculate impact score from severity and CVSS."""
        severity_multiplier = {
            'critical': 1.0,
            'high': 0.85,
            'medium': 0.6,
            'low': 0.3,
        }
        return (base_cvss / 10.0) * severity_multiplier.get(severity, 0.5)

    def get_critical_chains(self) -> List[ExploitChain]:
        """Get chains with critical severity."""
        return [c for c in self._chains if c.severity == 'critical']

    def get_high_impact_chains(self, min_impact: float = 0.7) -> List[ExploitChain]:
        """Get chains with high impact score."""
        return [c for c in self._chains if c.impact_score >= min_impact]

    def get_summary(self) -> Dict[str, Any]:
        """Generate summary of detected chains."""
        if not self._chains:
            return {'total': 0, 'no_chains_detected': True}

        severity_dist = defaultdict(int)
        for chain in self._chains:
            severity_dist[chain.severity] += 1

        return {
            'total_chains': len(self._chains),
            'by_severity': dict(severity_dist),
            'critical_count': severity_dist.get('critical', 0),
            'high_count': severity_dist.get('high', 0),
            'average_cvss': round(
                sum(c.base_cvss for c in self._chains) / len(self._chains), 1
            ),
            'max_cvss': max(c.base_cvss for c in self._chains),
            'chain_names': [c.name for c in self._chains],
        }


# Convenience function for quick analysis
def correlate_findings(
    tool_results: Dict[str, List[Dict[str, Any]]],
    min_confidence: float = 0.5,
    detect_chains: bool = True,
) -> Dict[str, Any]:
    """
    Función de conveniencia para correlacionar hallazgos rápidamente.

    Args:
        tool_results: Dict de {tool_name: [findings]}
        min_confidence: Umbral mínimo de confianza
        detect_chains: Whether to run exploit chain analysis

    Returns:
        Reporte con hallazgos correlacionados
    """
    engine = SmartCorrelationEngine()

    for tool_name, findings in tool_results.items():
        engine.add_findings(tool_name, findings)

    correlated = engine.correlate()
    report = engine.to_report()

    # Filtrar por confianza mínima
    report['filtered_findings'] = [
        f for f in report['all_findings']
        if f['confidence']['final'] >= min_confidence
    ]

    # Run exploit chain analysis
    if detect_chains and correlated:
        chain_analyzer = ExploitChainAnalyzer()
        chains = chain_analyzer.analyze(correlated)
        report['exploit_chains'] = {
            'summary': chain_analyzer.get_summary(),
            'chains': [c.to_dict() for c in chains],
            'critical_chains': [c.to_dict() for c in chain_analyzer.get_critical_chains()],
        }

    return report
