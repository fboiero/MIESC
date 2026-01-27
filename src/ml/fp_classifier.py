"""
False Positive Classifier for MIESC v4.7.0
==========================================

ML-based classifier to predict whether a finding is a false positive
based on code context and finding characteristics.

This helps improve precision by filtering out likely false positives
while maintaining high recall.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class FeatureCategory(Enum):
    """Categories of features for FP classification."""
    FINDING_METADATA = "finding_metadata"
    CODE_CONTEXT = "code_context"
    SEMANTIC_GUARDS = "semantic_guards"
    SOLIDITY_VERSION = "solidity_version"
    CONTRACT_PATTERNS = "contract_patterns"


@dataclass
class FindingFeatures:
    """Feature vector for a finding."""
    # Finding metadata
    confidence: float = 0.5
    severity_score: float = 0.5  # 0=info, 0.25=low, 0.5=medium, 0.75=high, 1=critical
    tool_count: int = 1
    has_swc_id: bool = False

    # Code context
    line_count: int = 0
    function_complexity: int = 0  # Approximate cyclomatic complexity
    has_external_call: bool = False
    has_state_change: bool = False
    has_ether_transfer: bool = False

    # Semantic guards
    has_require_check: bool = False
    has_modifier: bool = False
    has_reentrancy_guard: bool = False
    has_access_control: bool = False
    follows_cei_pattern: bool = False

    # Solidity version
    is_solidity_08_plus: bool = False
    uses_safemath: bool = False

    # Contract patterns
    is_proxy_contract: bool = False
    is_upgradeable: bool = False
    has_initializer: bool = False

    def to_vector(self) -> List[float]:
        """Convert features to numeric vector."""
        return [
            self.confidence,
            self.severity_score,
            min(self.tool_count / 5.0, 1.0),  # Normalize to 0-1
            1.0 if self.has_swc_id else 0.0,
            min(self.line_count / 100.0, 1.0),
            min(self.function_complexity / 20.0, 1.0),
            1.0 if self.has_external_call else 0.0,
            1.0 if self.has_state_change else 0.0,
            1.0 if self.has_ether_transfer else 0.0,
            1.0 if self.has_require_check else 0.0,
            1.0 if self.has_modifier else 0.0,
            1.0 if self.has_reentrancy_guard else 0.0,
            1.0 if self.has_access_control else 0.0,
            1.0 if self.follows_cei_pattern else 0.0,
            1.0 if self.is_solidity_08_plus else 0.0,
            1.0 if self.uses_safemath else 0.0,
            1.0 if self.is_proxy_contract else 0.0,
            1.0 if self.is_upgradeable else 0.0,
            1.0 if self.has_initializer else 0.0,
        ]

    @staticmethod
    def feature_names() -> List[str]:
        """Get feature names for interpretation."""
        return [
            "confidence",
            "severity_score",
            "tool_count_norm",
            "has_swc_id",
            "line_count_norm",
            "function_complexity_norm",
            "has_external_call",
            "has_state_change",
            "has_ether_transfer",
            "has_require_check",
            "has_modifier",
            "has_reentrancy_guard",
            "has_access_control",
            "follows_cei_pattern",
            "is_solidity_08_plus",
            "uses_safemath",
            "is_proxy_contract",
            "is_upgradeable",
            "has_initializer",
        ]


@dataclass
class FPPrediction:
    """Prediction result from the FP classifier."""
    is_false_positive: bool
    fp_probability: float
    confidence: float
    contributing_factors: List[str] = field(default_factory=list)

    @property
    def adjusted_confidence(self) -> float:
        """Get confidence adjusted by FP probability."""
        if self.is_false_positive:
            return max(0.1, self.confidence * (1 - self.fp_probability))
        return min(0.95, self.confidence * (1 + (1 - self.fp_probability) * 0.2))


class FeatureExtractor:
    """Extracts features from findings and source code."""

    # Patterns for feature extraction
    REENTRANCY_GUARD_PATTERNS = [
        r"ReentrancyGuard",
        r"nonReentrant",
        r"_status\s*=",
        r"locked\s*=\s*true",
    ]

    ACCESS_CONTROL_PATTERNS = [
        r"onlyOwner",
        r"onlyAdmin",
        r"onlyRole",
        r"require\s*\(\s*msg\.sender\s*==",
        r"require\s*\(\s*hasRole",
        r"_checkOwner\(\)",
        r"Ownable",
        r"AccessControl",
    ]

    CEI_VIOLATION_PATTERN = re.compile(
        r"\.call\{[^}]*\}\s*\([^)]*\)[^;]*;[^}]*"
        r"(?:balances|_balances|balance)\s*\[",
        re.MULTILINE | re.DOTALL
    )

    EXTERNAL_CALL_PATTERNS = [
        r"\.call\s*\{",
        r"\.call\s*\(",
        r"\.delegatecall\s*\(",
        r"\.staticcall\s*\(",
        r"\.transfer\s*\(",
        r"\.send\s*\(",
    ]

    STATE_CHANGE_PATTERNS = [
        r"\w+\s*=\s*[^=]",
        r"\w+\s*\+=",
        r"\w+\s*-=",
        r"\w+\s*\*=",
        r"\+\+\w+",
        r"--\w+",
        r"\w+\+\+",
        r"\w+--",
    ]

    def extract_features(
        self,
        finding: Dict[str, Any],
        source_code: str,
        function_code: Optional[str] = None,
    ) -> FindingFeatures:
        """
        Extract features from a finding and its context.

        Args:
            finding: The finding dictionary
            source_code: Full contract source code
            function_code: Code of the specific function (optional)

        Returns:
            FindingFeatures object
        """
        features = FindingFeatures()

        # Extract finding metadata
        features.confidence = finding.get("confidence", 0.5)
        features.severity_score = self._severity_to_score(
            finding.get("severity", "medium")
        )
        features.tool_count = len(finding.get("_tools", [finding.get("tool", "unknown")]))
        features.has_swc_id = bool(finding.get("swc_id"))

        # Get function context
        if not function_code:
            function_code = self._extract_function_context(
                source_code,
                finding.get("location", {}).get("line", 0)
            )

        # Extract code context features
        if function_code:
            features.line_count = len(function_code.split("\n"))
            features.function_complexity = self._estimate_complexity(function_code)
            features.has_external_call = any(
                re.search(p, function_code) for p in self.EXTERNAL_CALL_PATTERNS
            )
            features.has_state_change = any(
                re.search(p, function_code) for p in self.STATE_CHANGE_PATTERNS
            )
            features.has_ether_transfer = bool(
                re.search(r"\.transfer\(|\.send\(|\.call\{value:", function_code)
            )
            features.has_require_check = bool(
                re.search(r"require\s*\(|assert\s*\(", function_code)
            )
            features.has_modifier = bool(
                re.search(r"modifier\s+\w+|function\s+\w+[^{]*\)\s+\w+", function_code)
            )

        # Extract semantic guard features from full source
        features.has_reentrancy_guard = any(
            re.search(p, source_code, re.IGNORECASE)
            for p in self.REENTRANCY_GUARD_PATTERNS
        )
        features.has_access_control = any(
            re.search(p, source_code)
            for p in self.ACCESS_CONTROL_PATTERNS
        )
        features.follows_cei_pattern = not bool(
            self.CEI_VIOLATION_PATTERN.search(function_code or source_code)
        )

        # Solidity version features
        features.is_solidity_08_plus = bool(
            re.search(r"pragma\s+solidity\s*[\^>=]*\s*0\.[89]", source_code)
        )
        features.uses_safemath = bool(
            re.search(r"using\s+SafeMath|\.add\(|\.sub\(|\.mul\(", source_code)
        )

        # Contract pattern features
        features.is_proxy_contract = bool(
            re.search(r"delegatecall|Proxy|_implementation", source_code)
        )
        features.is_upgradeable = bool(
            re.search(r"Upgradeable|UUPS|TransparentProxy|initializer", source_code)
        )
        features.has_initializer = bool(
            re.search(r"function\s+initialize|initializer\s+", source_code)
        )

        return features

    def _severity_to_score(self, severity: str) -> float:
        """Convert severity string to numeric score."""
        severity_map = {
            "informational": 0.0,
            "info": 0.0,
            "low": 0.25,
            "medium": 0.5,
            "high": 0.75,
            "critical": 1.0,
        }
        return severity_map.get(severity.lower(), 0.5)

    def _extract_function_context(
        self,
        source_code: str,
        line_number: int,
        context_lines: int = 30,
    ) -> str:
        """Extract function code around a line number."""
        if not source_code or line_number <= 0:
            return ""

        lines = source_code.split("\n")
        if line_number > len(lines):
            return ""

        # Find function boundaries
        start = max(0, line_number - context_lines)
        end = min(len(lines), line_number + context_lines)

        # Look backwards for function start
        for i in range(line_number - 1, max(0, line_number - 50), -1):
            if re.search(r"function\s+\w+", lines[i]):
                start = i
                break

        # Look forwards for function end (matching braces)
        brace_count = 0
        in_function = False
        for i in range(start, min(len(lines), start + 100)):
            brace_count += lines[i].count("{") - lines[i].count("}")
            if "{" in lines[i]:
                in_function = True
            if in_function and brace_count <= 0:
                end = i + 1
                break

        return "\n".join(lines[start:end])

    def _estimate_complexity(self, code: str) -> int:
        """Estimate cyclomatic complexity of code."""
        complexity = 1  # Base complexity

        # Count decision points
        patterns = [
            r"\bif\s*\(",
            r"\belse\s+if\s*\(",
            r"\bwhile\s*\(",
            r"\bfor\s*\(",
            r"\brequire\s*\(",
            r"\bassert\s*\(",
            r"\?\s*[^:]+\s*:",  # Ternary
            r"\|\|",  # Logical OR
            r"&&",  # Logical AND
        ]

        for pattern in patterns:
            complexity += len(re.findall(pattern, code))

        return complexity


class FPClassifier:
    """
    ML-based classifier for false positive detection.

    Uses a rule-based approach with learned weights to predict
    whether a finding is likely a false positive.

    Usage:
        classifier = FPClassifier()

        prediction = classifier.predict(finding, source_code)

        if prediction.is_false_positive:
            print(f"Likely FP ({prediction.fp_probability:.0%})")
            print(f"Reasons: {prediction.contributing_factors}")
    """

    # Rule weights (learned from benchmark data)
    # Positive = increases FP probability (more likely FP)
    # Negative = decreases FP probability (more likely TP)
    #
    # NOTE: These weights are conservative to avoid filtering real vulnerabilities.
    # The goal is to filter OBVIOUS false positives while preserving recall.
    FEATURE_WEIGHTS = {
        # Strong guards that INCREASE FP probability (code is protected)
        "has_reentrancy_guard": 0.35,  # Strong indicator - actual guard present

        # Moderate guards - less reliable indicators
        "has_access_control": 0.1,  # May still have vulns elsewhere
        "follows_cei_pattern": 0.05,  # CEI detection can be unreliable
        "is_solidity_08_plus": 0.1,  # Only affects arithmetic, not reentrancy
        "uses_safemath": 0.15,

        # Weak indicators - don't heavily weight these
        "has_require_check": 0.02,  # Almost all code has requires
        "has_modifier": 0.02,  # Common pattern

        # Indicators that also increase FP probability
        "is_proxy_contract": 0.1,  # Proxy patterns often flagged incorrectly
        "is_upgradeable": 0.05,
        "has_initializer": 0.02,

        # Context indicators
        "high_confidence": -0.1,  # High confidence -> less likely FP
        "low_confidence": 0.05,  # Low confidence -> more likely FP
        "multi_tool": -0.15,  # Multiple tools agree -> less likely FP
        "single_tool": 0.02,  # Single tool -> slightly more likely FP
        "has_swc_id": -0.05,  # Has SWC -> slightly less likely FP
    }

    # Vulnerability-specific adjustments (override base weights)
    # Only apply strong adjustments for DEFINITIVE indicators
    VULN_TYPE_ADJUSTMENTS = {
        "reentrancy": {
            "has_reentrancy_guard": 0.45,  # Strong indicator - actual guard
            "follows_cei_pattern": 0.1,  # Weak - CEI detection unreliable
        },
        "arithmetic": {
            "is_solidity_08_plus": 0.4,  # Strong - 0.8+ has built-in checks
            "uses_safemath": 0.35,
        },
        "integer_overflow": {
            "is_solidity_08_plus": 0.4,
            "uses_safemath": 0.35,
        },
        "integer_underflow": {
            "is_solidity_08_plus": 0.4,
            "uses_safemath": 0.35,
        },
        "access_control": {
            "has_access_control": 0.15,  # Moderate - may still have issues
            "has_modifier": 0.1,
        },
        "timestamp": {
            # Timestamp issues often benign but still report them
            "default_fp_boost": 0.1,
        },
    }

    def __init__(self, fp_threshold: float = 0.5):
        """
        Initialize the classifier.

        Args:
            fp_threshold: Threshold above which to classify as FP
        """
        self.fp_threshold = fp_threshold
        self.extractor = FeatureExtractor()

    def predict(
        self,
        finding: Dict[str, Any],
        source_code: str,
        function_code: Optional[str] = None,
    ) -> FPPrediction:
        """
        Predict whether a finding is a false positive.

        Args:
            finding: The finding dictionary
            source_code: Full contract source code
            function_code: Code of the specific function (optional)

        Returns:
            FPPrediction with probability and contributing factors
        """
        # Extract features
        features = self.extractor.extract_features(
            finding, source_code, function_code
        )

        # Calculate base FP probability
        # Start at 0.3 (slightly below neutral) - most findings start as likely TPs
        fp_score = 0.3
        contributing_factors = []

        # Apply feature weights
        feature_dict = {
            "has_reentrancy_guard": features.has_reentrancy_guard,
            "has_access_control": features.has_access_control,
            "follows_cei_pattern": features.follows_cei_pattern,
            "is_solidity_08_plus": features.is_solidity_08_plus,
            "uses_safemath": features.uses_safemath,
            "has_require_check": features.has_require_check,
            "has_modifier": features.has_modifier,
            "is_proxy_contract": features.is_proxy_contract,
            "is_upgradeable": features.is_upgradeable,
            "has_initializer": features.has_initializer,
            "high_confidence": features.confidence > 0.8,
            "low_confidence": features.confidence < 0.4,
            "multi_tool": features.tool_count > 1,
            "single_tool": features.tool_count == 1,
            "has_swc_id": features.has_swc_id,
        }

        # Get vulnerability type for specific adjustments
        vuln_type = finding.get("type", "").lower().replace("-", "_")
        vuln_adjustments = self.VULN_TYPE_ADJUSTMENTS.get(vuln_type, {})

        # Apply default boost if present
        if "default_fp_boost" in vuln_adjustments:
            fp_score += vuln_adjustments["default_fp_boost"]
            contributing_factors.append(f"vuln_type_{vuln_type}_bias")

        for feature_name, is_present in feature_dict.items():
            if is_present:
                # Get weight (with vuln-specific override if available)
                weight = vuln_adjustments.get(
                    feature_name,
                    self.FEATURE_WEIGHTS.get(feature_name, 0)
                )

                if weight != 0:
                    fp_score += weight
                    direction = "reduces" if weight < 0 else "increases"
                    contributing_factors.append(
                        f"{feature_name} ({direction} FP probability)"
                    )

        # Clamp to valid probability range
        fp_probability = max(0.0, min(1.0, fp_score))

        # Determine if FP
        is_fp = fp_probability >= self.fp_threshold

        return FPPrediction(
            is_false_positive=is_fp,
            fp_probability=fp_probability,
            confidence=features.confidence,
            contributing_factors=contributing_factors,
        )

    def filter_findings(
        self,
        findings: List[Dict[str, Any]],
        source_code: str,
        remove_fps: bool = True,
        adjust_confidence: bool = True,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filter findings using FP classification.

        Args:
            findings: List of findings to filter
            source_code: Contract source code
            remove_fps: Whether to remove likely FPs
            adjust_confidence: Whether to adjust confidence scores

        Returns:
            Tuple of (kept_findings, removed_findings)
        """
        kept = []
        removed = []

        for finding in findings:
            prediction = self.predict(finding, source_code)

            updated = finding.copy()
            updated["_fp_probability"] = prediction.fp_probability
            updated["_fp_factors"] = prediction.contributing_factors

            if adjust_confidence:
                updated["confidence"] = prediction.adjusted_confidence

            if prediction.is_false_positive and remove_fps:
                updated["_filtered_reason"] = "likely_false_positive"
                removed.append(updated)
            else:
                kept.append(updated)

        return kept, removed


def classify_false_positives(
    findings: List[Dict[str, Any]],
    source_code: str,
    fp_threshold: float = 0.5,
) -> List[Dict[str, Any]]:
    """
    Convenience function to classify and filter false positives.

    Args:
        findings: List of findings
        source_code: Contract source code
        fp_threshold: Threshold for FP classification

    Returns:
        Findings with FP probability and adjusted confidence
    """
    classifier = FPClassifier(fp_threshold=fp_threshold)
    kept, _ = classifier.filter_findings(
        findings, source_code, remove_fps=False, adjust_confidence=True
    )
    return kept


def filter_likely_fps(
    findings: List[Dict[str, Any]],
    source_code: str,
    fp_threshold: float = 0.6,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Filter out likely false positives.

    Args:
        findings: List of findings
        source_code: Contract source code
        fp_threshold: Threshold for FP classification

    Returns:
        Tuple of (kept_findings, filtered_fps)
    """
    classifier = FPClassifier(fp_threshold=fp_threshold)
    return classifier.filter_findings(
        findings, source_code, remove_fps=True, adjust_confidence=True
    )
