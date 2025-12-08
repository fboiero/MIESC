"""
MIESC Severity Predictor
Predice la severidad real de vulnerabilidades basándose en contexto y patrones.
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class SeverityLevel(Enum):
    """Niveles de severidad."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class SeverityPrediction:
    """Resultado de predicción de severidad."""
    original: str
    predicted: str
    confidence: float
    adjusted: bool
    reasons: List[str]
    impact_factors: Dict[str, float]


class SeverityPredictor:
    """
    Predice la severidad real de vulnerabilidades basándose en:
    1. Tipo de vulnerabilidad y patrones conocidos
    2. Contexto del código (modificadores, require, etc.)
    3. Posición en el contrato (función pública vs interna)
    4. Interacción con fondos (ETH transfers, token operations)
    5. Patrones de explotación conocidos
    """

    # Patrones que aumentan severidad
    CRITICAL_PATTERNS = [
        (r'selfdestruct|suicide', 0.9, "Self-destruct capability"),
        (r'delegatecall.*user', 0.85, "Delegatecall with user input"),
        (r'tx\.origin', 0.7, "tx.origin authentication"),
        (r'transfer\s*\(.*msg\.value', 0.8, "ETH transfer with msg.value"),
    ]

    HIGH_PATTERNS = [
        (r'\.call\{value:', 0.75, "Low-level call with value"),
        (r'reentrancy|reentrant', 0.8, "Reentrancy pattern"),
        (r'approve.*type\(uint256\)\.max', 0.7, "Infinite approval"),
        (r'unchecked\s*\{', 0.6, "Unchecked arithmetic"),
    ]

    # Patrones que reducen severidad
    MITIGATING_PATTERNS = [
        (r'nonReentrant', -0.3, "Has reentrancy guard"),
        (r'onlyOwner|onlyAdmin', -0.2, "Access controlled"),
        (r'require\s*\([^)]*msg\.sender', -0.15, "Sender validation"),
        (r'whenNotPaused', -0.1, "Pausable contract"),
        (r'SafeMath|SafeERC20', -0.2, "Using safe libraries"),
        (r'OpenZeppelin', -0.15, "Using audited libraries"),
    ]

    # Mapeo de tipos de vulnerabilidad a severidad base
    VULN_BASE_SEVERITY = {
        # Critical
        'reentrancy': SeverityLevel.HIGH,
        'reentrancy-eth': SeverityLevel.CRITICAL,
        'arbitrary-send': SeverityLevel.CRITICAL,
        'suicidal': SeverityLevel.CRITICAL,
        'unprotected-upgrade': SeverityLevel.CRITICAL,

        # High
        'unchecked-send': SeverityLevel.HIGH,
        'controlled-delegatecall': SeverityLevel.HIGH,
        'msg-value-loop': SeverityLevel.HIGH,
        'shadowing-state': SeverityLevel.HIGH,
        'weak-prng': SeverityLevel.HIGH,

        # Medium
        'reentrancy-no-eth': SeverityLevel.MEDIUM,
        'reentrancy-benign': SeverityLevel.LOW,
        'timestamp': SeverityLevel.MEDIUM,
        'assembly': SeverityLevel.MEDIUM,
        'low-level-calls': SeverityLevel.MEDIUM,
        'calls-loop': SeverityLevel.MEDIUM,

        # Low
        'solc-version': SeverityLevel.LOW,
        'naming-convention': SeverityLevel.INFORMATIONAL,
        'unused-return': SeverityLevel.LOW,
        'dead-code': SeverityLevel.INFORMATIONAL,
        'too-many-digits': SeverityLevel.INFORMATIONAL,
    }

    # Pesos de severidad
    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 1.0,
        SeverityLevel.HIGH: 0.8,
        SeverityLevel.MEDIUM: 0.5,
        SeverityLevel.LOW: 0.2,
        SeverityLevel.INFORMATIONAL: 0.1,
    }

    def __init__(self):
        self._adjustment_history: List[Dict[str, Any]] = []

    def predict(
        self,
        finding: Dict[str, Any],
        code_context: str = "",
        contract_value_locked: Optional[float] = None,
    ) -> SeverityPrediction:
        """
        Predice la severidad real de un hallazgo.

        Args:
            finding: Hallazgo de la herramienta
            code_context: Código fuente alrededor del hallazgo
            contract_value_locked: TVL del contrato en USD (si conocido)

        Returns:
            SeverityPrediction con severidad ajustada
        """
        original_severity = finding.get('severity', 'medium').lower()
        vuln_type = finding.get('type', finding.get('check', '')).lower()
        message = finding.get('message', '')

        impact_factors: Dict[str, float] = {}
        reasons: List[str] = []

        # 1. Obtener severidad base del tipo de vulnerabilidad
        base_severity = self._get_base_severity(vuln_type)
        base_score = self.SEVERITY_WEIGHTS.get(base_severity, 0.5)
        impact_factors['base_type'] = base_score

        # 2. Analizar patrones críticos
        critical_boost = self._check_patterns(
            code_context + message,
            self.CRITICAL_PATTERNS,
            impact_factors,
            reasons,
        )

        # 3. Analizar patrones de alto riesgo
        high_boost = self._check_patterns(
            code_context + message,
            self.HIGH_PATTERNS,
            impact_factors,
            reasons,
        )

        # 4. Analizar patrones mitigantes
        mitigation = self._check_patterns(
            code_context,
            self.MITIGATING_PATTERNS,
            impact_factors,
            reasons,
        )

        # 5. Ajustar por TVL
        tvl_factor = 0.0
        if contract_value_locked:
            if contract_value_locked > 10_000_000:  # >$10M
                tvl_factor = 0.2
                reasons.append(f"High TVL (>${contract_value_locked/1e6:.1f}M): +0.20")
            elif contract_value_locked > 1_000_000:  # >$1M
                tvl_factor = 0.1
                reasons.append(f"Medium TVL (>${contract_value_locked/1e6:.1f}M): +0.10")
            impact_factors['tvl'] = tvl_factor

        # 6. Ajustar por función pública/externa
        location = finding.get('location', {})
        func_name = location.get('function', '')
        visibility_factor = self._get_visibility_factor(func_name, code_context)
        impact_factors['visibility'] = visibility_factor
        if visibility_factor != 0:
            reasons.append(f"Function visibility: {visibility_factor:+.2f}")

        # 7. Calcular score final
        final_score = base_score + critical_boost + high_boost + mitigation + tvl_factor + visibility_factor
        final_score = max(0.1, min(1.0, final_score))  # Clamp [0.1, 1.0]

        # 8. Convertir score a severidad
        predicted_severity = self._score_to_severity(final_score)

        # 9. Calcular confianza
        confidence = self._calculate_confidence(
            original_severity,
            predicted_severity.value,
            len(reasons),
        )

        return SeverityPrediction(
            original=original_severity,
            predicted=predicted_severity.value,
            confidence=round(confidence, 3),
            adjusted=original_severity != predicted_severity.value,
            reasons=reasons,
            impact_factors=impact_factors,
        )

    def _get_base_severity(self, vuln_type: str) -> SeverityLevel:
        """Obtiene severidad base para un tipo de vulnerabilidad."""
        vuln_type_lower = vuln_type.lower().replace('-', '_').replace(' ', '_')

        # Búsqueda exacta
        if vuln_type_lower in self.VULN_BASE_SEVERITY:
            return self.VULN_BASE_SEVERITY[vuln_type_lower]

        # Búsqueda parcial
        for key, severity in self.VULN_BASE_SEVERITY.items():
            if key in vuln_type_lower or vuln_type_lower in key:
                return severity

        return SeverityLevel.MEDIUM

    def _check_patterns(
        self,
        text: str,
        patterns: List[Tuple[str, float, str]],
        impact_factors: Dict[str, float],
        reasons: List[str],
    ) -> float:
        """Verifica patrones y acumula impacto."""
        total_impact = 0.0

        for pattern, impact, description in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                total_impact += impact
                reasons.append(f"{description}: {impact:+.2f}")
                impact_factors[pattern[:20]] = impact

        return total_impact

    def _get_visibility_factor(self, func_name: str, code_context: str) -> float:
        """Calcula factor de visibilidad de función."""
        if not func_name and not code_context:
            return 0.0

        # Buscar declaración de función
        func_pattern = rf'function\s+{re.escape(func_name)}\s*\([^)]*\)\s*(public|external|internal|private)?'
        match = re.search(func_pattern, code_context, re.IGNORECASE)

        if match:
            visibility = match.group(1) or 'public'
            visibility = visibility.lower()

            if visibility in ['public', 'external']:
                return 0.1  # Más expuesto
            elif visibility == 'internal':
                return -0.05
            elif visibility == 'private':
                return -0.1

        return 0.0

    def _score_to_severity(self, score: float) -> SeverityLevel:
        """Convierte score numérico a nivel de severidad."""
        if score >= 0.85:
            return SeverityLevel.CRITICAL
        elif score >= 0.65:
            return SeverityLevel.HIGH
        elif score >= 0.4:
            return SeverityLevel.MEDIUM
        elif score >= 0.2:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFORMATIONAL

    def _calculate_confidence(
        self,
        original: str,
        predicted: str,
        num_reasons: int,
    ) -> float:
        """Calcula confianza de la predicción."""
        base_confidence = 0.7

        # Más razones = más confianza
        reason_boost = min(num_reasons * 0.05, 0.2)

        # Si no cambió, más confianza
        if original == predicted:
            base_confidence += 0.1

        return min(base_confidence + reason_boost, 0.95)

    def batch_predict(
        self,
        findings: List[Dict[str, Any]],
        code_context_map: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Predice severidad para múltiples hallazgos.
        Retorna hallazgos con severidad ajustada.
        """
        code_context_map = code_context_map or {}
        results = []

        for finding in findings:
            loc = f"{finding.get('location', {}).get('file', '')}:{finding.get('location', {}).get('line', 0)}"
            context = code_context_map.get(loc, "")

            prediction = self.predict(finding, context)

            # Crear copia con severidad ajustada
            adjusted_finding = finding.copy()
            adjusted_finding['original_severity'] = finding.get('severity')
            adjusted_finding['severity'] = prediction.predicted
            adjusted_finding['_severity_prediction'] = {
                'confidence': prediction.confidence,
                'adjusted': prediction.adjusted,
                'reasons': prediction.reasons,
            }

            results.append(adjusted_finding)

        return results
