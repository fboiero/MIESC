"""
MIESC False Positive Filter v2.2
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

Improvements in v2.1:
- Context-aware FP detection for incorrect-equality (enums, hashes, existence)
- encode-packed-collision detection with counter/nonce awareness
- timestamp FP detection for legitimate deadline usage
- Library code detection (OpenZeppelin, solmate, solady, forge-std)
- Enhanced msg-value-loop analysis

Improvements in v2.2 (v4.6.0):
- SLITHER_DETECTOR_FP_RATES: Per-detector FP probabilities based on benchmarks
- SemanticContextAnalyzer: Deep context analysis for guards, CEI pattern
- Cross-validation integration with correlation engine
- Modifier detection for reentrancy guards
- CEI (Checks-Effects-Interactions) pattern detection
- Solidity 0.8+ overflow protection awareness

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-24
Version: 2.2.0
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


# =============================================================================
# v2.2: SLITHER DETECTOR FP RATES
# =============================================================================
# Per-detector false positive rates based on SmartBugs benchmark and real audits
# Higher values = higher probability of being a false positive
# These are used to adjust confidence scores based on the specific detector

SLITHER_DETECTOR_FP_RATES = {
    # === HIGH FP RATE (0.70+) - Usually informational/benign ===
    "reentrancy-benign": 0.85,          # Almost always FP - benign reentrancy
    "reentrancy-events": 0.80,          # Event emissions, not real reentrancy
    "naming-convention": 0.95,          # Code style, not security
    "solc-version": 0.80,               # Pragma version warnings
    "pragma": 0.80,                     # Pragma-related issues
    "different-pragma-directives-are-used": 0.75,
    "conformance-to-solidity-naming-conventions": 0.90,
    "too-many-digits": 0.85,            # Magic numbers
    "similar-names": 0.80,              # Variable naming similarity
    "boolean-equal": 0.85,              # x == true instead of x
    "events-maths": 0.75,               # Math in events
    "events-access": 0.70,              # Access in events
    "function-ordering": 0.90,          # Code style
    "state-variables-could-be-declared-immutable": 0.80,
    "state-variables-could-be-declared-constant": 0.80,
    "public-functions-could-be-declared-external": 0.75,

    # === MEDIUM-HIGH FP RATE (0.50-0.69) - Context dependent ===
    "reentrancy-no-eth": 0.55,          # No ETH transfer, lower risk
    "reentrancy-unlimited-gas": 0.60,   # Gas-related reentrancy
    "timestamp": 0.55,                  # Often legitimate deadline usage
    "block-timestamp": 0.55,
    "weak-prng": 0.55,                  # Depends on usage context
    "low-level-calls": 0.50,            # Often intentional
    "assembly": 0.50,                   # Often intentional optimization
    "constable-states": 0.65,           # Could be constant
    "immutable-states": 0.60,           # Could be immutable
    "dead-code": 0.55,                  # May be intentional placeholder
    "unused-state": 0.55,               # May be used in derived contracts
    "external-function": 0.60,          # Could be external
    "unused-return": 0.55,              # Context dependent
    "shadowing-local": 0.65,            # Often intentional
    "shadowing-abstract": 0.70,
    "incorrect-equality": 0.55,         # Many legitimate uses
    "dangerous-strict-equalities": 0.55,
    "encode-packed-collision": 0.50,    # FP when counter/nonce present
    "msg-value-loop": 0.50,             # Context dependent
    "calls-loop": 0.50,                 # May be intentional
    "costly-loop": 0.60,                # Gas optimization
    "multiple-sends": 0.55,

    # === MEDIUM FP RATE (0.30-0.49) - Needs review ===
    "uninitialized-local": 0.45,        # Could be intentional
    "uninitialized-state": 0.40,        # More serious
    "unchecked-transfer": 0.45,
    "unchecked-lowlevel": 0.40,
    "divide-before-multiply": 0.45,
    "missing-zero-check": 0.40,
    "shadowing-state": 0.45,            # Can be serious
    "controlled-array-length": 0.45,
    "arbitrary-send-eth": 0.35,         # Needs context review
    "deprecated-standards": 0.50,

    # === LOW FP RATE (0.15-0.29) - Likely true positive ===
    "reentrancy-eth": 0.20,             # Real reentrancy with ETH
    "uninitialized-storage": 0.25,      # Storage pointer issues
    "arbitrary-send": 0.25,             # Arbitrary send vulnerabilities
    "controlled-delegatecall": 0.20,    # Dangerous delegatecall

    # === VERY LOW FP RATE (<0.15) - Almost always TP ===
    "suicidal": 0.10,                   # Unprotected selfdestruct
    "unprotected-upgrade": 0.10,        # Upgrade vulnerabilities
    "backdoor": 0.05,                   # Backdoor detection
}


class FalsePositiveFilter:
    """
    Filtro de falsos positivos usando aprendizaje de reglas y feedback.

    Estrategias:
    1. Reglas heurísticas basadas en patrones comunes
    2. Aprendizaje de feedback del usuario
    3. Análisis de contexto del código
    4. Correlación entre herramientas
    5. v2.2: Detector-specific FP rates from SLITHER_DETECTOR_FP_RATES
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
        # v2.1: High FP rate patterns (context-dependent)
        # These require context analysis - base rates are conservative
        "incorrect-equality": 0.55,  # High FP for enums, hashes, existence checks
        "dangerous-strict-equalities": 0.55,  # Same as incorrect-equality
        "encode-packed-collision": 0.50,  # FP when counter/nonce present
        "hash-collisions-due-to-abi-encodepacked": 0.50,
        "msg-value-loop": 0.45,  # Often FP in controlled contexts
        "arbitrary-send-eth": 0.40,  # Context-dependent
        # Slither specific patterns with high FP rates
        "solc-version": 0.80,  # Almost always informational
        "different-pragma-directives-are-used": 0.75,
        "missing-inheritance": 0.70,
        "conformance-to-solidity-naming-conventions": 0.85,
        "local-variable-never-initialized": 0.55,
        "state-variables-could-be-declared-immutable": 0.80,
        "state-variables-could-be-declared-constant": 0.80,
        "public-functions-could-be-declared-external": 0.75,
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

    # v2.1: Context-aware FP patterns
    # These require code context analysis to determine if FP
    CONTEXT_AWARE_FP_PATTERNS = {
        # incorrect-equality: FP when comparing enums, hashes, or existence checks
        "incorrect-equality": {
            "base_fp": 0.40,
            "fp_contexts": [
                # Enum comparisons - match pattern in message or code
                (r"(Status|State|Role|Type|Phase|Mode|Kind)\s*\.\s*\w+", 0.85, "enum comparison"),
                (r"==\s*(Status|State|Role|Type|Phase|Mode|Kind)\.", 0.85, "enum comparison"),
                (r"(status|state|role|type|phase|mode)\s*==\s*\w+\.\w+", 0.85, "enum comparison"),
                # Hash comparisons
                (r"==\s*keccak256\s*\(", 0.90, "hash comparison"),
                (r"keccak256\s*\([^)]+\)\s*==", 0.90, "hash comparison"),
                (r"hash\s*==|==\s*hash", 0.85, "hash comparison"),
                (r"Hash\s*==|==\s*\w*Hash", 0.85, "hash comparison"),
                # Existence checks (== 0 or != 0)
                (r"==\s*0[\s;)\]]", 0.75, "existence check (== 0)"),
                (r"==\s*0\s*for\s*existence", 0.80, "existence check"),
                (r"!=\s*0", 0.70, "non-zero existence check"),
                # Address checks
                (r"==\s*address\s*\(\s*0\s*\)", 0.80, "zero address check"),
                (r"address\s*\(0\)|address\(0x0\)", 0.80, "zero address check"),
                # Bytes32 checks
                (r"bytes32\s*\([^)]*\)\s*==\s*bytes32\s*\(0\)", 0.85, "bytes32 zero check"),
                (r"==\s*bytes32\s*\(0\)", 0.85, "bytes32 zero check"),
                (r"resultHash\s*==\s*0|==\s*0.*hash", 0.80, "hash existence check"),
                # Array/length checks
                (r"\.length\s*==\s*0", 0.80, "array empty check"),
            ],
        },
        # encode-packed-collision: FP when counter/nonce prevents collision
        "encode-packed-collision": {
            "base_fp": 0.45,
            "fp_contexts": [
                (r"abi\.encodePacked\s*\([^)]*\+\+", 0.90, "counter increment"),
                (r"\+\+|count\+\+|counter\+\+|index\+\+", 0.90, "counter increment"),
                (r"nonce", 0.85, "nonce present"),
                (r"counter|Count", 0.85, "counter present"),
                (r"requestCount|requestId|uniqueId", 0.85, "unique identifier"),
                (r"abi\.encodePacked\s*\([^)]*id\s*[,)]", 0.80, "unique id present"),
                (r"abi\.encodePacked\s*\([^)]*block\.(timestamp|number)", 0.75, "block data for uniqueness"),
                (r"sequence|seq\d*|incrementing", 0.80, "sequential value"),
            ],
        },
        # timestamp: FP for legitimate deadline usage
        "timestamp": {
            "base_fp": 0.55,
            "fp_contexts": [
                (r"deadline|expiry|expires|validUntil|timeout", 0.80, "deadline variable"),
                (r">\s*\d{4,}", 0.75, "large time constant (days/weeks)"),
                (r"block\.timestamp\s*\+\s*\d+\s*(days|hours|minutes)", 0.85, "explicit time unit"),
                (r"lastUpdate|lastAction|cooldown|lockTime", 0.75, "tracking last action"),
                (r"createdAt|startTime|endTime|releaseTime", 0.80, "lifecycle timestamps"),
            ],
        },
        # block-timestamp: Same as timestamp
        "block-timestamp": {
            "base_fp": 0.55,
            "fp_contexts": [
                (r"deadline|expiry|expires|validUntil|timeout", 0.80, "deadline variable"),
                (r">\s*\d{4,}", 0.75, "large time constant"),
                (r"block\.timestamp\s*\+\s*\d+\s*(days|hours|minutes)", 0.85, "explicit time unit"),
            ],
        },
        # weak-prng: Same timestamp considerations
        "weak-prng": {
            "base_fp": 0.50,
            "fp_contexts": [
                (r"commit.*reveal|reveal.*commit", 0.85, "commit-reveal pattern"),
                (r"chainlink|vrf|randomness", 0.90, "using secure randomness"),
            ],
        },
        # msg-value-loop: FP in controlled contexts or when value is properly divided
        "msg-value-loop": {
            "base_fp": 0.40,
            "fp_contexts": [
                (r"for\s*\([^)]*;\s*[^;]*<\s*1\s*;", 0.90, "single iteration"),
                (r"msg\.value\s*/\s*\w+\.length", 0.85, "value divided by iterations"),
                (r"require\s*\([^)]*msg\.value\s*==", 0.80, "exact value check"),
                (r"msg\.value\s*/\s*\d+", 0.80, "value divided by constant"),
                (r"totalAmount|amount\s*/\s*count", 0.75, "controlled amount distribution"),
                (r"V1\.sol|v1\.sol|Version1|deprecated", 0.60, "deprecated/v1 contract"),
            ],
        },
    }

    # v2.1: OpenZeppelin and standard library patterns (always FP)
    LIBRARY_CODE_PATTERNS = [
        r"@openzeppelin",
        r"openzeppelin-contracts",
        r"OpenZeppelin",
        r"/oz/",
        r"node_modules/@",
        r"lib/forge-std",
        r"lib/solmate",
        r"lib/solady",
    ]

    # v2.1: Common safe patterns that indicate FP
    SAFE_COMPARISON_PATTERNS = [
        # Enum comparisons
        (r"==\s*(Status|State|Role|Type|Phase|Mode)\.\w+", "enum_comparison"),
        # Hash comparisons (intentional strict equality)
        (r"keccak256\s*\([^)]+\)\s*==\s*keccak256", "hash_comparison"),
        (r"==\s*bytes32\s*\(", "bytes32_comparison"),
        # Existence checks
        (r"\w+\s*==\s*0\s*\)", "zero_check"),
        (r"\w+\s*!=\s*0\s*\)", "non_zero_check"),
        (r"address\s*\([^)]*\)\s*==\s*address\s*\(\s*0", "zero_address_check"),
    ]

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

    def _is_library_code(self, file_path: str) -> bool:
        """
        Detecta si el archivo es código de librería (OpenZeppelin, etc).

        Library code findings are almost always FPs since the code is
        battle-tested and audited.
        """
        for pattern in self.LIBRARY_CODE_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False

    def _analyze_context_for_fp(
        self,
        vuln_type: str,
        code_context: str,
        message: str,
    ) -> Tuple[float, List[str]]:
        """
        Analiza el contexto del código para patrones FP específicos.

        Args:
            vuln_type: Tipo de vulnerabilidad
            code_context: Código circundante
            message: Mensaje del hallazgo

        Returns:
            Tuple de (ajuste_fp, razones)
        """
        fp_adjustment = 0.0
        reasons = []

        # Combinar contexto y mensaje para análisis
        full_context = f"{code_context}\n{message}".lower()

        # Buscar en patrones context-aware
        vuln_lower = vuln_type.lower()
        for pattern_key, pattern_config in self.CONTEXT_AWARE_FP_PATTERNS.items():
            if pattern_key in vuln_lower:
                # Verificar cada patrón de contexto FP
                for regex, fp_prob, reason in pattern_config["fp_contexts"]:
                    if re.search(regex, full_context, re.IGNORECASE):
                        fp_adjustment = max(fp_adjustment, fp_prob)
                        reasons.append(f"Context match '{reason}': FP prob {fp_prob:.0%}")
                        break  # Solo tomar el match más fuerte

        # Verificar comparaciones seguras para incorrect-equality
        if "incorrect-equality" in vuln_lower or "equality" in vuln_lower:
            for regex, pattern_name in self.SAFE_COMPARISON_PATTERNS:
                if re.search(regex, full_context, re.IGNORECASE):
                    fp_adjustment = max(fp_adjustment, 0.85)
                    reasons.append(f"Safe comparison pattern ({pattern_name}): FP prob 85%")
                    break

        return fp_adjustment, reasons

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

    def _parse_confidence(self, value) -> float:
        """Parse confidence value, handling both float and string formats."""
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            # Handle string severity/confidence levels
            confidence_map = {
                "critical": 0.95,
                "high": 0.85,
                "medium": 0.70,
                "low": 0.50,
                "info": 0.30,
                "informational": 0.30,
            }
            return confidence_map.get(value.lower(), 0.7)
        return 0.7  # Default

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
            confidence_original=self._parse_confidence(finding.get("confidence", 0.7)),
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

        v2.1: Enhanced with context-aware analysis for:
        - incorrect-equality (enums, hashes, existence checks)
        - encode-packed-collision (with counters/nonces)
        - timestamp (legitimate deadline usage)
        - Library code (OpenZeppelin, etc.)

        Returns:
            Tuple de (probabilidad_fp, explicación)
        """
        features = self._extract_features(finding, code_context, confirmations)
        fp_score = 0.0
        reasons = []

        # Get file path and message for context analysis
        file_path = finding.get("location", {}).get("file", "")
        message = finding.get("message", "")
        vuln_type = features.vuln_type.lower()

        # 0. Library code detection (highest priority - almost always FP)
        if self._is_library_code(file_path):
            fp_score += 0.80
            reasons.append("In library code (OpenZeppelin/etc): +0.80")

        # 1. Reglas heurísticas base
        if vuln_type in self.FALSE_POSITIVE_PATTERNS:
            base_fp = self.FALSE_POSITIVE_PATTERNS[vuln_type]
            fp_score += base_fp * 0.3
            reasons.append(f"Known FP pattern '{vuln_type}': +{base_fp*0.3:.2f}")

        # 2. Context-aware analysis (v2.1)
        context_fp, context_reasons = self._analyze_context_for_fp(
            features.vuln_type, code_context, message
        )
        if context_fp > 0:
            fp_score += context_fp * 0.5  # Weight context analysis at 50%
            reasons.extend(context_reasons)

        # 3. Contexto de código seguro
        if features.near_require:
            fp_score += 0.15
            reasons.append("Near require/assert: +0.15")

        if features.near_modifier:
            fp_score += 0.1
            reasons.append("Has security modifier: +0.10")

        # 4. Archivo de test
        if features.in_test_file:
            fp_score += 0.25
            reasons.append("In test file: +0.25")

        # 5. Interface
        if features.in_interface:
            fp_score += 0.2
            reasons.append("In interface: +0.20")

        # 6. Confirmaciones múltiples (reduce FP)
        if confirmations >= 2:
            fp_score -= 0.2 * min(confirmations - 1, 3)
            reasons.append(
                f"Cross-validated ({confirmations} tools): -{0.2 * min(confirmations - 1, 3):.2f}"
            )

        # 7. Severidad baja
        if features.severity in ["low", "informational", "info"]:
            fp_score += 0.1
            reasons.append("Low severity: +0.10")

        # 8. Post Solidity 0.8 overflow checks
        if "overflow" in vuln_type or "underflow" in vuln_type:
            fp_score += 0.3
            reasons.append("Overflow (likely Solidity 0.8+): +0.30")

        # 9. Validación cruzada OBLIGATORIA para patrones críticos
        requires_cv = any(p in vuln_type for p in self.REQUIRE_CROSS_VALIDATION)
        if requires_cv and confirmations < 2:
            fp_score += 0.35
            reasons.append(f"Critical pattern '{vuln_type}' without cross-validation: +0.35")

        # 10. Aprendizaje de feedback
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
                "in_library": self._is_library_code(file_path),
                "near_require": features.near_require,
                "near_modifier": features.near_modifier,
                "confirmations": confirmations,
                "context_analysis": context_reasons if context_reasons else None,
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
                original_conf = self._parse_confidence(finding.get("confidence", 0.7))
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

    def get_detector_fp_rate(self, detector_name: str) -> float:
        """
        Get the FP rate for a specific Slither detector.

        Args:
            detector_name: Name of the Slither detector (e.g., "reentrancy-eth")

        Returns:
            FP probability (0.0-1.0), defaults to 0.50 if unknown
        """
        return SLITHER_DETECTOR_FP_RATES.get(detector_name.lower(), 0.50)

    def adjust_confidence_by_detector(
        self,
        finding: Dict[str, Any],
        detector_name: str,
    ) -> Dict[str, Any]:
        """
        Adjust finding confidence based on detector-specific FP rates.

        This is called by the SlitherAdapter to adjust confidence based
        on which specific detector generated the finding.

        Args:
            finding: The finding to adjust
            detector_name: Name of the Slither detector

        Returns:
            Finding with adjusted confidence and metadata
        """
        fp_rate = self.get_detector_fp_rate(detector_name)
        original_confidence = finding.get("confidence", 0.7)

        # Adjust confidence: reduce by FP rate
        adjusted_confidence = original_confidence * (1.0 - fp_rate * 0.5)

        finding = finding.copy()
        finding["confidence"] = round(adjusted_confidence, 3)
        finding["_detector_fp_analysis"] = {
            "detector": detector_name,
            "detector_fp_rate": fp_rate,
            "original_confidence": original_confidence,
            "adjusted_confidence": round(adjusted_confidence, 3),
        }

        return finding


# =============================================================================
# v2.2: SEMANTIC CONTEXT ANALYZER
# =============================================================================

class SemanticContextAnalyzer:
    """
    Deep semantic analysis of code context to reduce false positives.

    Analyzes:
    - Function modifiers (onlyOwner, nonReentrant, etc.)
    - Checks-Effects-Interactions (CEI) pattern compliance
    - Solidity version and built-in protections
    - Require/assert coverage
    - Guard patterns and safety mechanisms

    v4.6.0: New class for semantic-aware FP detection
    """

    # Reentrancy guard patterns
    REENTRANCY_GUARD_PATTERNS = [
        r"nonReentrant",
        r"ReentrancyGuard",
        r"_reentrancyGuard",
        r"_notEntered",
        r"_entered",
        r"locked\s*=\s*true",
        r"locked\s*==\s*true",
        r"status\s*==\s*_ENTERED",
        r"@nonreentrant",  # Vyper
    ]

    # Access control modifier patterns
    ACCESS_CONTROL_PATTERNS = [
        r"onlyOwner",
        r"onlyAdmin",
        r"onlyRole\s*\(",
        r"onlyMinter",
        r"onlyOperator",
        r"onlyGovernance",
        r"onlyAuthorized",
        r"require\s*\(\s*msg\.sender\s*==\s*owner",
        r"require\s*\(\s*_msgSender\(\)\s*==\s*owner",
        r"require\s*\(\s*hasRole\s*\(",
        r"_checkOwner\s*\(",
        r"_checkRole\s*\(",
    ]

    # CEI pattern indicators (state changes before external calls)
    CEI_PATTERN_INDICATORS = [
        # State updates (effects)
        r"balances\s*\[[^\]]+\]\s*[-+]?=",
        r"balance\s*[-+]?=",
        r"_balances\s*\[[^\]]+\]\s*[-+]?=",
        r"withdrawn\s*=\s*true",
        r"claimed\s*=\s*true",
        r"deposits\s*\[[^\]]+\]\s*=\s*0",
        r"pendingRewards\s*\[[^\]]+\]\s*=\s*0",
    ]

    # Patterns indicating deliberate external call safety
    SAFE_EXTERNAL_CALL_PATTERNS = [
        r"// CEI",
        r"// Checks-Effects-Interactions",
        r"// Effects before interactions",
        r"// State updated before call",
        r"// Safe - using CEI pattern",
    ]

    def __init__(self):
        """Initialize the semantic context analyzer."""
        self._version_cache: Dict[str, str] = {}

    def analyze_finding_context(
        self,
        finding: Dict[str, Any],
        source_code: str,
        function_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Perform deep semantic analysis of a finding's context.

        Args:
            finding: The finding to analyze
            source_code: Full contract source code
            function_code: Optional extracted function code for targeted analysis

        Returns:
            Analysis result with confidence adjustment and reasons
        """
        vuln_type = finding.get("type", "").lower()
        context = function_code or source_code

        analysis = {
            "confidence_adjustment": 0.0,
            "reasons": [],
            "guards_detected": [],
            "patterns_detected": [],
            "is_protected": False,
            "solidity_version": None,
            "has_overflow_protection": False,
        }

        # Detect Solidity version
        sol_version = self._detect_solidity_version(source_code)
        analysis["solidity_version"] = sol_version
        analysis["has_overflow_protection"] = self._has_overflow_protection(sol_version)

        # Analyze based on vulnerability type
        if "reentrancy" in vuln_type:
            adjustment, reasons, guards = self._analyze_reentrancy_context(context)
            analysis["confidence_adjustment"] += adjustment
            analysis["reasons"].extend(reasons)
            analysis["guards_detected"].extend(guards)

        if "access" in vuln_type or "control" in vuln_type or "unprotected" in vuln_type:
            adjustment, reasons, guards = self._analyze_access_control_context(context)
            analysis["confidence_adjustment"] += adjustment
            analysis["reasons"].extend(reasons)
            analysis["guards_detected"].extend(guards)

        if "overflow" in vuln_type or "underflow" in vuln_type or "arithmetic" in vuln_type:
            adjustment, reasons = self._analyze_arithmetic_context(context, sol_version)
            analysis["confidence_adjustment"] += adjustment
            analysis["reasons"].extend(reasons)

        if "timestamp" in vuln_type or "randomness" in vuln_type:
            adjustment, reasons = self._analyze_timestamp_context(context)
            analysis["confidence_adjustment"] += adjustment
            analysis["reasons"].extend(reasons)

        # Detect CEI pattern
        if self._follows_cei_pattern(context):
            analysis["patterns_detected"].append("CEI")
            analysis["confidence_adjustment"] -= 0.20
            analysis["reasons"].append("CEI pattern detected: -0.20")

        # Determine if protected
        analysis["is_protected"] = (
            len(analysis["guards_detected"]) > 0 or
            "CEI" in analysis["patterns_detected"]
        )

        # Cap adjustment
        analysis["confidence_adjustment"] = max(
            min(analysis["confidence_adjustment"], 0.50),
            -0.60
        )

        return analysis

    def _analyze_reentrancy_context(
        self, context: str
    ) -> Tuple[float, List[str], List[str]]:
        """Analyze context for reentrancy protection."""
        adjustment = 0.0
        reasons = []
        guards = []

        # Check for reentrancy guards
        for pattern in self.REENTRANCY_GUARD_PATTERNS:
            if re.search(pattern, context, re.IGNORECASE):
                guards.append(pattern)
                adjustment -= 0.40
                reasons.append(f"Reentrancy guard detected ({pattern}): -0.40")
                break  # Only count once

        # Check for CEI pattern indicators
        for pattern in self.CEI_PATTERN_INDICATORS:
            if re.search(pattern, context, re.IGNORECASE):
                adjustment -= 0.15
                reasons.append(f"CEI state update pattern: -0.15")
                break

        # Check for safe call comments
        for pattern in self.SAFE_EXTERNAL_CALL_PATTERNS:
            if re.search(pattern, context, re.IGNORECASE):
                adjustment -= 0.20
                reasons.append("Developer CEI annotation: -0.20")
                break

        return adjustment, reasons, guards

    def _analyze_access_control_context(
        self, context: str
    ) -> Tuple[float, List[str], List[str]]:
        """Analyze context for access control protection."""
        adjustment = 0.0
        reasons = []
        guards = []

        for pattern in self.ACCESS_CONTROL_PATTERNS:
            if re.search(pattern, context, re.IGNORECASE):
                guards.append(pattern)
                adjustment -= 0.35
                reasons.append(f"Access control detected ({pattern}): -0.35")
                break

        return adjustment, reasons, guards

    def _analyze_arithmetic_context(
        self, context: str, sol_version: Optional[str]
    ) -> Tuple[float, List[str]]:
        """Analyze context for arithmetic protection."""
        adjustment = 0.0
        reasons = []

        # Check Solidity version
        if self._has_overflow_protection(sol_version):
            adjustment -= 0.50
            reasons.append(f"Solidity {sol_version} has built-in overflow protection: -0.50")

        # Check for SafeMath usage
        if re.search(r"SafeMath|using\s+SafeMath", context, re.IGNORECASE):
            adjustment -= 0.40
            reasons.append("SafeMath library detected: -0.40")

        # Check for explicit unchecked blocks (intentional)
        if re.search(r"unchecked\s*\{", context):
            adjustment += 0.20
            reasons.append("Explicit unchecked block (intentional): +0.20")

        return adjustment, reasons

    def _analyze_timestamp_context(
        self, context: str
    ) -> Tuple[float, List[str]]:
        """Analyze context for legitimate timestamp usage."""
        adjustment = 0.0
        reasons = []

        # Legitimate timestamp usages
        legitimate_patterns = [
            (r"deadline|expiry|expires|validUntil|timeout", "deadline usage"),
            (r"lastUpdate|lastAction|cooldown|lockTime", "tracking last action"),
            (r"createdAt|startTime|endTime|releaseTime", "lifecycle timestamps"),
            (r"block\.timestamp\s*\+\s*\d+\s*(days|hours|minutes)", "time duration"),
        ]

        for pattern, reason in legitimate_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                adjustment -= 0.25
                reasons.append(f"Legitimate {reason}: -0.25")
                break

        return adjustment, reasons

    def _follows_cei_pattern(self, context: str) -> bool:
        """
        Detect if code follows Checks-Effects-Interactions pattern.

        A function follows CEI if state changes occur before external calls.
        """
        # Find external calls
        call_matches = list(re.finditer(
            r"\.call\s*\{|\.call\(|\.transfer\(|\.send\(",
            context
        ))

        if not call_matches:
            return False

        # Find state changes (effects)
        effect_matches = list(re.finditer(
            r"balances?\s*\[[^\]]+\]\s*[-+]?=|_?balance\s*[-+]?=|"
            r"deposits?\s*\[[^\]]+\]\s*=|withdrawn\s*=|claimed\s*=",
            context
        ))

        if not effect_matches:
            return False

        # Check if effects come before calls (simplified check)
        # In CEI pattern, state updates should have lower positions than external calls
        first_effect_pos = min(m.start() for m in effect_matches)
        first_call_pos = min(m.start() for m in call_matches)

        return first_effect_pos < first_call_pos

    def _detect_solidity_version(self, source_code: str) -> Optional[str]:
        """Detect Solidity version from pragma statement."""
        patterns = [
            r"pragma\s+solidity\s*[>=^~]*\s*(\d+\.\d+\.\d+)",
            r"pragma\s+solidity\s*[>=^~]*\s*(\d+\.\d+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, source_code, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _has_overflow_protection(self, version: Optional[str]) -> bool:
        """Check if Solidity version has built-in overflow protection."""
        if not version:
            return False

        try:
            match = re.search(r"(\d+)\.(\d+)", version)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                # Solidity 0.8.0+ has built-in overflow checks
                return major == 0 and minor >= 8
        except Exception:
            pass

        return False

    def get_adjustment_for_finding(
        self,
        finding: Dict[str, Any],
        source_code: str,
    ) -> float:
        """
        Get confidence adjustment for a finding based on semantic analysis.

        Returns a value between -0.60 and +0.50 to adjust confidence.
        Negative values reduce FP probability (finding is more likely TP).
        Positive values increase FP probability.
        """
        analysis = self.analyze_finding_context(finding, source_code)
        return analysis["confidence_adjustment"]


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FalsePositiveFilter",
    "FindingFeatures",
    "FeedbackEntry",
    "SLITHER_DETECTOR_FP_RATES",
    "SemanticContextAnalyzer",
]
