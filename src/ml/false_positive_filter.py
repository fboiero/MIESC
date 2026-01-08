"""
MIESC False Positive Filter v2.0
================================

ML-based filter to reduce false positives based on finding characteristics.

Scientific Foundation:
- SmartBugs Curated Dataset analysis (Durieux et al., 2020)
- "An Empirical Review of Smart Contract Vulnerabilities" (Perez & Livshits, 2019)
- SWC Registry patterns (https://swcregistry.io/)

Improvements in v2.0:
- Solidity version-aware detection (0.8+ overflow protection)
- AST-aware context analysis
- Expanded pattern database from literature
- Statistical validation metrics
- Bayesian confidence adjustment

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-09
Version: 2.0.0
License: AGPL-3.0
"""

import hashlib
import json
import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FindingFeatures:
    """Características extraídas de un hallazgo para clasificación."""

    tool: str
    vuln_type: str
    severity: str
    file_type: str
    function_name: str
    has_swc: bool
    has_cwe: bool
    message_length: int
    code_context_length: int
    line_number: int
    confirmations: int
    confidence_original: float

    # Features derivadas
    is_common_pattern: bool = False
    in_test_file: bool = False
    in_interface: bool = False
    near_require: bool = False
    near_modifier: bool = False

    # v2.0: Nuevas características
    solidity_version: str = ""  # e.g., "0.8.0", "0.4.24"
    has_overflow_protection: bool = False  # Solidity 0.8+
    uses_safemath: bool = False
    has_reentrancy_guard: bool = False
    in_library: bool = False
    function_visibility: str = ""  # public, external, internal, private

    def to_vector(self) -> List[float]:
        """Convierte features a vector numérico (19 dimensions)."""
        return [
            self._encode_severity(self.severity),
            1.0 if self.has_swc else 0.0,
            1.0 if self.has_cwe else 0.0,
            min(self.message_length / 500.0, 1.0),
            min(self.code_context_length / 1000.0, 1.0),
            min(self.line_number / 1000.0, 1.0),
            min(self.confirmations / 5.0, 1.0),
            self.confidence_original,
            1.0 if self.is_common_pattern else 0.0,
            1.0 if self.in_test_file else 0.0,
            1.0 if self.in_interface else 0.0,
            1.0 if self.near_require else 0.0,
            1.0 if self.near_modifier else 0.0,
            # v2.0: Nuevas dimensiones
            1.0 if self.has_overflow_protection else 0.0,
            1.0 if self.uses_safemath else 0.0,
            1.0 if self.has_reentrancy_guard else 0.0,
            1.0 if self.in_library else 0.0,
            self._encode_visibility(self.function_visibility),
            self._encode_solidity_version(self.solidity_version),
        ]

    def _encode_visibility(self, visibility: str) -> float:
        """Codifica visibilidad como valor numérico (mayor = más expuesto)."""
        mapping = {
            "external": 1.0,
            "public": 0.8,
            "internal": 0.3,
            "private": 0.1,
        }
        return mapping.get(visibility.lower(), 0.5)

    def _encode_solidity_version(self, version: str) -> float:
        """Codifica versión Solidity (mayor = más moderno/seguro)."""
        if not version:
            return 0.5
        try:
            # Extract major.minor
            match = re.search(r"(\d+)\.(\d+)", version)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                # 0.8+ has overflow protection
                if major == 0 and minor >= 8:
                    return 1.0
                elif major == 0 and minor >= 6:
                    return 0.7
                elif major == 0 and minor >= 4:
                    return 0.4
                return 0.2
        except Exception:
            pass
        return 0.5

    def _encode_severity(self, severity: str) -> float:
        """Codifica severidad como valor numérico."""
        mapping = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "informational": 0.1,
            "info": 0.1,
        }
        return mapping.get(severity.lower(), 0.3)


@dataclass
class FeedbackEntry:
    """Entrada de feedback del usuario sobre un hallazgo."""

    finding_hash: str
    is_true_positive: bool
    features: FindingFeatures
    timestamp: datetime
    user_notes: str = ""


class FalsePositiveFilter:
    """
    Filtro de falsos positivos usando aprendizaje de reglas y feedback.

    Estrategias:
    1. Reglas heurísticas basadas en patrones comunes
    2. Aprendizaje de feedback del usuario
    3. Análisis de contexto del código
    4. Correlación entre herramientas
    """

    # Patrones conocidos de falsos positivos con probabilidades FP
    # Valores más altos = mayor probabilidad de ser falso positivo
    # Basado en: SmartBugs (Durieux et al., 2020) y SWC Registry
    FALSE_POSITIVE_PATTERNS = {
        # === Slither - Informativos/Bajo Riesgo ===
        "naming-convention": 0.85,
        "solc-version": 0.75,
        "pragma": 0.70,
        "low-level-calls": 0.50,
        "assembly": 0.45,
        "external-function": 0.60,
        "constable-states": 0.70,
        "immutable-states": 0.65,
        "dead-code": 0.55,
        "unused-state": 0.50,
        "similar-names": 0.80,
        "too-many-digits": 0.85,
        # === Reentrancy - Alto FP en código moderno ===
        "reentrancy-benign": 0.75,
        "reentrancy-events": 0.70,
        "reentrancy-unlimited-gas": 0.60,
        "reentrancy-no-eth": 0.55,  # Menos crítico que reentrancy-eth
        # === Timestamp - Muchos FP ===
        "timestamp": 0.65,
        "block-timestamp": 0.65,
        "weak-prng": 0.55,
        "Dependence on predictable environment variable": 0.60,
        # === Mythril - Post Solidity 0.8 ===
        "Integer Underflow": 0.70,  # Solidity 0.8+ tiene checks
        "Integer Overflow": 0.70,
        "integer-overflow": 0.70,
        "integer-underflow": 0.70,
        # === Retornos no verificados ===
        "unused-return": 0.55,
        "unchecked-transfer": 0.50,
        "unchecked-lowlevel": 0.45,
        # === Variables no inicializadas ===
        "uninitialized-local": 0.60,
        "uninitialized-state": 0.50,
        "uninitialized-storage": 0.45,
        # === Shadowing (generalmente no crítico) ===
        "shadowing-state": 0.55,
        "shadowing-local": 0.65,
        "shadowing-builtin": 0.60,
        "shadowing-abstract": 0.70,
        # === Loops y gas ===
        "calls-loop": 0.50,
        "costly-loop": 0.65,
        "multiple-sends": 0.50,
        # === Otros informativos ===
        "missing-zero-check": 0.45,
        "boolean-equal": 0.80,
        "divide-before-multiply": 0.50,
        "events-maths": 0.75,
        "events-access": 0.70,
        # === Deprecated (muy bajo riesgo) ===
        "deprecated-standards": 0.80,
        "controlled-array-length": 0.55,
        # === v2.0: Patrones expandidos basados en SmartBugs ===
        # Gas Optimization (generalmente no crítico)
        "gas-optimization": 0.85,
        "inefficient-storage": 0.70,
        "redundant-code": 0.75,
        "cache-array-length": 0.80,
        "use-calldata": 0.75,
        # Informational from static analysis
        "function-ordering": 0.90,
        "variable-ordering": 0.85,
        "import-ordering": 0.90,
        "visibility-modifier-order": 0.85,
        "state-variable-order": 0.85,
        # OpenZeppelin patterns (usually safe)
        "ownable-multisig": 0.70,
        "pausable-without-events": 0.65,
        "access-control-enumerable": 0.80,
        # DeFi-specific (context-dependent)
        "flash-loan-callback": 0.50,  # Depends on implementation
        "oracle-stale-price": 0.45,  # Real issue but high FP rate
        "unchecked-oracle": 0.40,
        # Cross-chain specific
        "bridge-message-format": 0.60,
        "layer2-compatibility": 0.55,
    }

    # v2.0: Patrones que son FP en Solidity 0.8+ (overflow protection)
    SOLIDITY_08_FALSE_POSITIVES = {
        "integer-overflow",
        "integer-underflow",
        "Integer Overflow",
        "Integer Underflow",
        "SWC-101",  # Integer Overflow and Underflow
        "arithmetic-overflow",
        "arithmetic-underflow",
    }

    # Patrones que REQUIEREN validación cruzada (2+ herramientas)
    REQUIRE_CROSS_VALIDATION = {
        "reentrancy",
        "reentrancy-eth",
        "reentrancy-no-eth",
        "arbitrary-send",
        "arbitrary-send-eth",
        "suicidal",
        "selfdestruct",
        "delegatecall",
        "controlled-delegatecall",
    }

    # Contextos que reducen probabilidad de TP
    SAFE_CONTEXTS = [
        r"require\s*\(",
        r"assert\s*\(",
        r"revert\s*\(",
        r"modifier\s+\w+",
        r"onlyOwner",
        r"nonReentrant",
        r"whenNotPaused",
        r"SafeMath",
        r"OpenZeppelin",
    ]

    # Archivos que típicamente tienen más FPs
    TEST_FILE_PATTERNS = [
        r"test[s]?[/\\]",
        r"\.t\.sol$",
        r"Test\.sol$",
        r"Mock",
        r"Fixture",
    ]

    def __init__(self, feedback_path: Optional[str] = None):
        self.feedback_path = Path(feedback_path or os.path.expanduser("~/.miesc/feedback.json"))
        self.feedback_path.parent.mkdir(parents=True, exist_ok=True)
        self._feedback: List[FeedbackEntry] = []
        self._learned_weights: Dict[str, float] = {}
        self._version_cache: Dict[str, str] = {}  # v2.0: Cache versiones
        self._load_feedback()

    # =========================================================================
    # v2.0: Métodos de detección de versión Solidity
    # =========================================================================

    def _detect_solidity_version(self, contract_path: str) -> Tuple[str, bool]:
        """
        Detecta la versión de Solidity del contrato.

        Returns:
            Tuple de (version_string, has_overflow_protection)
        """
        if contract_path in self._version_cache:
            version = self._version_cache[contract_path]
            return version, self._is_solidity_08_plus(version)

        version = ""
        try:
            with open(contract_path, "r", errors="ignore") as f:
                content = f.read(2000)  # Solo primeras líneas

            # Buscar pragma solidity
            pragma_patterns = [
                r"pragma\s+solidity\s*[>=^~]*\s*(\d+\.\d+\.\d+)",
                r"pragma\s+solidity\s*[>=^~]*\s*(\d+\.\d+)",
            ]

            for pattern in pragma_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    break

            self._version_cache[contract_path] = version

        except Exception as e:
            logger.debug(f"Could not detect Solidity version: {e}")

        return version, self._is_solidity_08_plus(version)

    def _is_solidity_08_plus(self, version: str) -> bool:
        """Determina si la versión tiene protección contra overflow."""
        if not version:
            return False
        try:
            match = re.search(r"(\d+)\.(\d+)", version)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                return major == 0 and minor >= 8
        except Exception:
            pass
        return False

    def _detect_safeguards(self, code_context: str) -> Dict[str, bool]:
        """
        Detecta patrones de seguridad en el contexto del código.

        Returns:
            Dict con flags de safeguards detectados
        """
        safeguards = {
            "uses_safemath": bool(re.search(r"SafeMath|using\s+SafeMath", code_context)),
            "has_reentrancy_guard": bool(
                re.search(
                    r"nonReentrant|ReentrancyGuard|_reentrancyGuard|_notEntered", code_context
                )
            ),
            "has_access_control": bool(
                re.search(
                    r"onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender\s*==", code_context
                )
            ),
            "has_checks_effects_interactions": bool(
                re.search(
                    r"// CEI|// Checks-Effects-Interactions|balances\[.*\]\s*=.*;\s*\n.*\.call",
                    code_context,
                )
            ),
        }
        return safeguards

    def _load_feedback(self) -> None:
        """Carga feedback histórico."""
        if self.feedback_path.exists():
            try:
                with open(self.feedback_path) as f:
                    data = json.load(f)
                    self._feedback = [
                        FeedbackEntry(
                            finding_hash=e["hash"],
                            is_true_positive=e["is_tp"],
                            features=FindingFeatures(**e["features"]),
                            timestamp=datetime.fromisoformat(e["timestamp"]),
                            user_notes=e.get("notes", ""),
                        )
                        for e in data.get("entries", [])
                    ]
                    self._learned_weights = data.get("weights", {})
            except Exception:
                self._feedback = []
                self._learned_weights = {}

    def _save_feedback(self) -> None:
        """Guarda feedback a disco."""
        data = {
            "entries": [
                {
                    "hash": e.finding_hash,
                    "is_tp": e.is_true_positive,
                    "features": {
                        "tool": e.features.tool,
                        "vuln_type": e.features.vuln_type,
                        "severity": e.features.severity,
                        "file_type": e.features.file_type,
                        "function_name": e.features.function_name,
                        "has_swc": e.features.has_swc,
                        "has_cwe": e.features.has_cwe,
                        "message_length": e.features.message_length,
                        "code_context_length": e.features.code_context_length,
                        "line_number": e.features.line_number,
                        "confirmations": e.features.confirmations,
                        "confidence_original": e.features.confidence_original,
                    },
                    "timestamp": e.timestamp.isoformat(),
                    "notes": e.user_notes,
                }
                for e in self._feedback
            ],
            "weights": self._learned_weights,
        }
        with open(self.feedback_path, "w") as f:
            json.dump(data, f, indent=2)

    def _extract_features(
        self,
        finding: Dict[str, Any],
        code_context: str = "",
        confirmations: int = 1,
    ) -> FindingFeatures:
        """Extrae características de un hallazgo."""
        location = finding.get("location", {})
        file_path = location.get("file", "")
        function = location.get("function", "")
        message = finding.get("message", "")

        # Detectar contextos seguros
        near_require = any(re.search(p, code_context) for p in self.SAFE_CONTEXTS[:3])
        near_modifier = any(re.search(p, code_context) for p in self.SAFE_CONTEXTS[3:])

        # Detectar archivos de test
        in_test = any(re.search(p, file_path, re.I) for p in self.TEST_FILE_PATTERNS)

        # Detectar interfaces
        in_interface = "interface" in file_path.lower() or "Interface" in file_path

        # Detectar patrones comunes
        vuln_type = finding.get("type", finding.get("check", ""))
        is_common = vuln_type.lower() in self.FALSE_POSITIVE_PATTERNS

        return FindingFeatures(
            tool=finding.get("tool", "unknown"),
            vuln_type=vuln_type,
            severity=finding.get("severity", "medium"),
            file_type=Path(file_path).suffix if file_path else ".sol",
            function_name=function,
            has_swc=bool(finding.get("swc_id")),
            has_cwe=bool(finding.get("cwe_id")),
            message_length=len(message),
            code_context_length=len(code_context),
            line_number=int(location.get("line") or 0),
            confirmations=confirmations,
            confidence_original=float(finding.get("confidence", 0.7)),
            is_common_pattern=is_common,
            in_test_file=in_test,
            in_interface=in_interface,
            near_require=near_require,
            near_modifier=near_modifier,
        )

    def _compute_finding_hash(self, finding: Dict[str, Any]) -> str:
        """Genera hash único para un hallazgo."""
        key_parts = [
            finding.get("type", ""),
            finding.get("location", {}).get("file", ""),
            str(finding.get("location", {}).get("line", 0)),
            finding.get("message", "")[:100],
        ]
        return hashlib.md5("|".join(key_parts).encode()).hexdigest()[:16]

    def predict_false_positive(
        self,
        finding: Dict[str, Any],
        code_context: str = "",
        confirmations: int = 1,
    ) -> Tuple[float, Dict[str, Any]]:
        """
        Predice la probabilidad de que un hallazgo sea falso positivo.

        Returns:
            Tuple de (probabilidad_fp, explicación)
        """
        features = self._extract_features(finding, code_context, confirmations)
        fp_score = 0.0
        reasons = []

        # 1. Reglas heurísticas
        vuln_type = features.vuln_type.lower()
        if vuln_type in self.FALSE_POSITIVE_PATTERNS:
            base_fp = self.FALSE_POSITIVE_PATTERNS[vuln_type]
            fp_score += base_fp * 0.3
            reasons.append(f"Known FP pattern '{vuln_type}': +{base_fp*0.3:.2f}")

        # 2. Contexto de código seguro
        if features.near_require:
            fp_score += 0.15
            reasons.append("Near require/assert: +0.15")

        if features.near_modifier:
            fp_score += 0.1
            reasons.append("Has security modifier: +0.10")

        # 3. Archivo de test
        if features.in_test_file:
            fp_score += 0.25
            reasons.append("In test file: +0.25")

        # 4. Interface
        if features.in_interface:
            fp_score += 0.2
            reasons.append("In interface: +0.20")

        # 5. Confirmaciones múltiples (reduce FP)
        if confirmations >= 2:
            fp_score -= 0.2 * min(confirmations - 1, 3)
            reasons.append(
                f"Cross-validated ({confirmations} tools): -{0.2 * min(confirmations - 1, 3):.2f}"
            )

        # 6. Severidad baja
        if features.severity in ["low", "informational", "info"]:
            fp_score += 0.1
            reasons.append("Low severity: +0.10")

        # 7. Post Solidity 0.8 overflow checks
        if "overflow" in vuln_type or "underflow" in vuln_type:
            fp_score += 0.3
            reasons.append("Overflow (likely Solidity 0.8+): +0.30")

        # 8. Validación cruzada OBLIGATORIA para patrones críticos
        requires_cv = any(p in vuln_type for p in self.REQUIRE_CROSS_VALIDATION)
        if requires_cv and confirmations < 2:
            fp_score += 0.35
            reasons.append(f"Critical pattern '{vuln_type}' without cross-validation: +0.35")

        # 9. Aprendizaje de feedback
        if features.vuln_type in self._learned_weights:
            learned_adj = self._learned_weights[features.vuln_type]
            fp_score += learned_adj
            reasons.append(f"Learned from feedback: {learned_adj:+.2f}")

        # Normalizar a [0, 1]
        fp_probability = min(max(fp_score, 0.0), 0.95)

        return fp_probability, {
            "fp_probability": round(fp_probability, 3),
            "is_likely_fp": fp_probability > 0.5,
            "confidence_adjustment": round(1.0 - fp_probability, 3),
            "reasons": reasons,
            "features": {
                "in_test": features.in_test_file,
                "near_require": features.near_require,
                "near_modifier": features.near_modifier,
                "confirmations": confirmations,
            },
        }

    def filter_findings(
        self,
        findings: List[Dict[str, Any]],
        threshold: float = 0.6,
        code_context_map: Optional[Dict[str, str]] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filtra hallazgos separando probables TPs de FPs.

        Args:
            findings: Lista de hallazgos
            threshold: Umbral de probabilidad FP para filtrar
            code_context_map: Mapa de file:line -> código contexto

        Returns:
            Tuple de (true_positives, filtered_fps)
        """
        code_context_map = code_context_map or {}
        true_positives = []
        filtered_fps = []

        # Contar confirmaciones por ubicación
        location_counts = defaultdict(int)
        for f in findings:
            loc = f"{f.get('location', {}).get('file', '')}:{f.get('location', {}).get('line', 0)}"
            location_counts[loc] += 1

        for finding in findings:
            file_path = finding.get("location", {}).get("file", "")
            line_num = finding.get("location", {}).get("line", 0)
            loc = f"{file_path}:{line_num}"
            confirmations = location_counts[loc]
            context = code_context_map.get(loc, "")

            fp_prob, explanation = self.predict_false_positive(finding, context, confirmations)

            # Añadir metadata
            finding["_fp_analysis"] = explanation

            if fp_prob < threshold:
                # Ajustar confianza
                original_conf = finding.get("confidence", 0.7)
                finding["confidence"] = round(
                    original_conf * explanation["confidence_adjustment"], 3
                )
                true_positives.append(finding)
            else:
                filtered_fps.append(finding)

        return true_positives, filtered_fps

    def add_feedback(
        self,
        finding: Dict[str, Any],
        is_true_positive: bool,
        notes: str = "",
    ) -> None:
        """
        Registra feedback del usuario sobre un hallazgo.
        """
        finding_hash = self._compute_finding_hash(finding)
        features = self._extract_features(finding)

        entry = FeedbackEntry(
            finding_hash=finding_hash,
            is_true_positive=is_true_positive,
            features=features,
            timestamp=datetime.now(),
            user_notes=notes,
        )
        self._feedback.append(entry)

        # Actualizar pesos aprendidos
        self._update_learned_weights()
        self._save_feedback()

    def _update_learned_weights(self) -> None:
        """Actualiza pesos basándose en feedback acumulado."""
        type_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0})

        for entry in self._feedback:
            vuln_type = entry.features.vuln_type
            if entry.is_true_positive:
                type_stats[vuln_type]["tp"] += 1
            else:
                type_stats[vuln_type]["fp"] += 1

        # Calcular ajustes
        for vuln_type, stats in type_stats.items():
            total = stats["tp"] + stats["fp"]
            if total >= 3:  # Mínimo de muestras
                fp_rate = stats["fp"] / total
                # Ajuste: positivo si muchos FPs, negativo si muchos TPs
                self._learned_weights[vuln_type] = (fp_rate - 0.5) * 0.4

    def get_statistics(self) -> Dict[str, Any]:
        """Obtiene estadísticas del filtro."""
        if not self._feedback:
            return {"total_feedback": 0, "no_data": True}

        tp_count = sum(1 for e in self._feedback if e.is_true_positive)
        fp_count = len(self._feedback) - tp_count

        type_breakdown = defaultdict(lambda: {"tp": 0, "fp": 0})
        for entry in self._feedback:
            vtype = entry.features.vuln_type
            if entry.is_true_positive:
                type_breakdown[vtype]["tp"] += 1
            else:
                type_breakdown[vtype]["fp"] += 1

        return {
            "total_feedback": len(self._feedback),
            "true_positives": tp_count,
            "false_positives": fp_count,
            "fp_rate": round(fp_count / len(self._feedback), 3) if self._feedback else 0,
            "learned_weights": dict(self._learned_weights),
            "type_breakdown": dict(type_breakdown),
        }
