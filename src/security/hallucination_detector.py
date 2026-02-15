"""
Hallucination Detection Module for LLM Outputs

Provides cross-validation of LLM findings against static analysis results
to detect and mitigate AI hallucinations.

Strategies:
1. Cross-tool validation: Compare LLM findings with Slither/Aderyn results
2. Code pattern matching: Verify claimed vulnerabilities exist in code
3. Confidence calibration: Adjust confidence based on validation results
4. Anomaly detection: Flag suspicious or unlikely findings

Usage:
    from src.security.hallucination_detector import (
        HallucinationDetector,
        validate_llm_findings,
        cross_validate_finding,
    )

    # Cross-validate LLM findings
    detector = HallucinationDetector()
    validated = detector.validate_findings(
        llm_findings=llm_results,
        static_findings=slither_results,
        contract_code=code
    )
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ValidationStatus(Enum):
    """Status of hallucination validation."""

    VALIDATED = "validated"  # Confirmed by other tools
    PARTIAL = "partial"  # Partially confirmed
    UNVALIDATED = "unvalidated"  # Not confirmed but plausible
    SUSPICIOUS = "suspicious"  # Likely hallucination
    HALLUCINATION = "hallucination"  # Confirmed hallucination


@dataclass
class ValidationResult:
    """Result of hallucination validation for a finding."""

    status: ValidationStatus
    original_confidence: float
    adjusted_confidence: float
    validation_sources: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    code_evidence: Optional[str] = None

    @property
    def confidence_penalty(self) -> float:
        """Calculate confidence penalty applied."""
        return self.original_confidence - self.adjusted_confidence


@dataclass
class ValidatedFinding:
    """A finding with hallucination validation applied."""

    finding: Dict[str, Any]
    validation: ValidationResult
    is_reliable: bool

    @property
    def adjusted_confidence(self) -> float:
        return self.validation.adjusted_confidence


# Patterns that indicate real code constructs
CODE_PATTERNS = {
    "reentrancy": [
        r"\.call\s*\{",
        r"\.call\s*\(",
        r"\.transfer\s*\(",
        r"\.send\s*\(",
        r"external\s+\w+\s*\(",
    ],
    "access_control": [
        r"onlyOwner",
        r"require\s*\(\s*msg\.sender",
        r"modifier\s+only",
        r"owner\s*==\s*msg\.sender",
        r"hasRole\s*\(",
    ],
    "integer_overflow": [
        r"\+\+",
        r"\+=",
        r"\*=",
        r"\+\s*\d+",
        r"uint\d*\s+\w+\s*=",
    ],
    "unchecked_return": [
        r"\.call\s*\(",
        r"\.delegatecall\s*\(",
        r"\.staticcall\s*\(",
        r"\.transfer\s*\(",
    ],
    "oracle_manipulation": [
        r"getPrice",
        r"latestAnswer",
        r"getReserves",
        r"price\s*=",
        r"oracle",
    ],
    "flash_loan": [
        r"flashLoan",
        r"flashBorrow",
        r"executeOperation",
        r"onFlashLoan",
    ],
    "delegatecall": [
        r"\.delegatecall\s*\(",
        r"delegatecall\s*\(",
    ],
    "selfdestruct": [
        r"selfdestruct\s*\(",
        r"suicide\s*\(",
    ],
}

# Vulnerability type aliases for matching
VULN_TYPE_ALIASES = {
    "reentrancy": ["reentrancy", "reentrant", "re-entrancy", "re-entrant"],
    "access_control": ["access-control", "access_control", "authorization", "permission"],
    "integer_overflow": ["overflow", "underflow", "arithmetic", "integer-overflow"],
    "unchecked_return": ["unchecked-return", "unchecked-call", "return-value", "low-level-call"],
    "oracle_manipulation": ["oracle", "price-manipulation", "spot-price"],
    "flash_loan": ["flash-loan", "flashloan", "flash_loan"],
    "delegatecall": ["delegatecall", "delegate-call", "proxy"],
    "selfdestruct": ["selfdestruct", "suicide", "self-destruct"],
}


class HallucinationDetector:
    """
    Detector for LLM hallucinations in security findings.

    Cross-validates LLM outputs against:
    - Static analysis tool results (Slither, Aderyn, etc.)
    - Actual code patterns
    - Known vulnerability signatures
    """

    def __init__(
        self,
        confidence_penalty_unvalidated: float = 0.3,
        confidence_penalty_suspicious: float = 0.5,
        min_confidence_threshold: float = 0.1,
    ):
        """
        Initialize hallucination detector.

        Args:
            confidence_penalty_unvalidated: Penalty for findings not validated by other tools
            confidence_penalty_suspicious: Penalty for suspicious findings
            min_confidence_threshold: Minimum confidence to keep a finding
        """
        self.confidence_penalty_unvalidated = confidence_penalty_unvalidated
        self.confidence_penalty_suspicious = confidence_penalty_suspicious
        self.min_confidence_threshold = min_confidence_threshold

    def validate_findings(
        self,
        llm_findings: List[Dict[str, Any]],
        static_findings: Optional[List[Dict[str, Any]]] = None,
        contract_code: Optional[str] = None,
    ) -> List[ValidatedFinding]:
        """
        Validate LLM findings against static analysis and code patterns.

        Args:
            llm_findings: Findings from LLM analysis
            static_findings: Findings from static analysis tools
            contract_code: Original contract source code

        Returns:
            List of validated findings with adjusted confidence
        """
        validated_findings = []
        static_finding_types = self._extract_finding_types(static_findings or [])

        for finding in llm_findings:
            validation = self._validate_single_finding(
                finding,
                static_finding_types,
                static_findings or [],
                contract_code,
            )

            is_reliable = (
                validation.adjusted_confidence >= self.min_confidence_threshold
                and validation.status != ValidationStatus.HALLUCINATION
            )

            validated_findings.append(
                ValidatedFinding(
                    finding=finding,
                    validation=validation,
                    is_reliable=is_reliable,
                )
            )

        # Log summary
        reliable_count = sum(1 for f in validated_findings if f.is_reliable)
        logger.info(
            f"Hallucination detection: {reliable_count}/{len(validated_findings)} "
            f"findings validated as reliable"
        )

        return validated_findings

    def _validate_single_finding(
        self,
        finding: Dict[str, Any],
        static_types: Set[str],
        static_findings: List[Dict[str, Any]],
        code: Optional[str],
    ) -> ValidationResult:
        """Validate a single finding."""
        vuln_type = self._normalize_type(finding.get("type", "") or finding.get("category", ""))
        original_confidence = float(finding.get("confidence", 0.75))
        reasons = []
        sources = []

        # Check 1: Cross-validation with static analysis
        is_confirmed = self._is_type_in_static(vuln_type, static_types)
        if is_confirmed:
            sources.append("static_analysis")
            reasons.append("Confirmed by static analysis tools")

        # Check 2: Location matching with static findings
        location_match = self._check_location_match(finding, static_findings)
        if location_match:
            sources.append("location_match")
            reasons.append("Location matches static analysis finding")

        # Check 3: Code pattern verification
        code_evidence = None
        if code:
            pattern_match, evidence = self._verify_code_pattern(finding, code)
            if pattern_match:
                sources.append("code_pattern")
                reasons.append("Vulnerability pattern found in code")
                code_evidence = evidence
            else:
                reasons.append("No matching code pattern found")

        # Check 4: Anomaly detection
        anomalies = self._detect_anomalies(finding)
        if anomalies:
            reasons.extend(anomalies)

        # Determine status and adjust confidence
        status, adjusted_confidence = self._calculate_status_and_confidence(
            original_confidence,
            len(sources),
            bool(anomalies),
            code_evidence is not None if code else True,  # Skip code check if no code provided
        )

        return ValidationResult(
            status=status,
            original_confidence=original_confidence,
            adjusted_confidence=adjusted_confidence,
            validation_sources=sources,
            reasons=reasons,
            code_evidence=code_evidence,
        )

    def _normalize_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type for comparison."""
        vuln_type = vuln_type.lower().strip()
        vuln_type = re.sub(r"[_-]", "", vuln_type)
        return vuln_type

    def _is_type_in_static(self, llm_type: str, static_types: Set[str]) -> bool:
        """Check if LLM finding type matches any static analysis finding."""
        llm_normalized = self._normalize_type(llm_type)

        # Direct match
        if llm_normalized in static_types:
            return True

        # Check aliases
        for _canonical, aliases in VULN_TYPE_ALIASES.items():
            normalized_aliases = [self._normalize_type(a) for a in aliases]
            if llm_normalized in normalized_aliases:
                # Check if any alias is in static findings
                for alias in normalized_aliases:
                    if alias in static_types:
                        return True

        return False

    def _extract_finding_types(self, findings: List[Dict[str, Any]]) -> Set[str]:
        """Extract normalized vulnerability types from findings."""
        types = set()
        for f in findings:
            vuln_type = f.get("type") or f.get("category") or f.get("check") or ""
            if vuln_type:
                types.add(self._normalize_type(vuln_type))
        return types

    def _check_location_match(
        self,
        llm_finding: Dict[str, Any],
        static_findings: List[Dict[str, Any]],
    ) -> bool:
        """Check if LLM finding location matches any static finding."""
        llm_location = llm_finding.get("location", {})
        if isinstance(llm_location, str):
            llm_line = self._extract_line_from_string(llm_location)
        else:
            llm_line = llm_location.get("line") or llm_location.get("line_start")

        if not llm_line:
            return False

        for static in static_findings:
            static_location = static.get("location", {})
            if isinstance(static_location, dict):
                static_line = static_location.get("line") or static_location.get("line_start")
            else:
                static_line = self._extract_line_from_string(str(static_location))

            if static_line and abs(int(llm_line) - int(static_line)) <= 5:
                return True

        return False

    def _extract_line_from_string(self, location_str: str) -> Optional[int]:
        """Extract line number from location string."""
        match = re.search(r"line\s*:?\s*(\d+)", location_str, re.IGNORECASE)
        if match:
            return int(match.group(1))
        match = re.search(r":(\d+)", location_str)
        if match:
            return int(match.group(1))
        return None

    def _verify_code_pattern(
        self,
        finding: Dict[str, Any],
        code: str,
    ) -> Tuple[bool, Optional[str]]:
        """Verify that the claimed vulnerability pattern exists in code."""
        vuln_type = finding.get("type") or finding.get("category") or ""
        vuln_type = self._normalize_type(vuln_type)

        # Find matching patterns
        for canonical, aliases in VULN_TYPE_ALIASES.items():
            normalized_aliases = [self._normalize_type(a) for a in aliases]
            if vuln_type in normalized_aliases or vuln_type == canonical.replace("_", ""):
                patterns = CODE_PATTERNS.get(canonical, [])
                for pattern in patterns:
                    match = re.search(pattern, code, re.IGNORECASE)
                    if match:
                        # Extract surrounding context
                        start = max(0, match.start() - 50)
                        end = min(len(code), match.end() + 50)
                        evidence = code[start:end]
                        return True, evidence

        return False, None

    def _detect_anomalies(self, finding: Dict[str, Any]) -> List[str]:
        """Detect anomalies that suggest hallucination."""
        anomalies = []

        # Check for suspiciously high confidence with vague description
        confidence = float(finding.get("confidence", 0.75))
        description = str(finding.get("description", ""))

        if confidence > 0.9 and len(description) < 50:
            anomalies.append("High confidence with minimal description")

        # Check for generic/template-like content
        generic_phrases = [
            "this vulnerability allows",
            "an attacker could",
            "may lead to",
            "could potentially",
        ]
        generic_count = sum(1 for p in generic_phrases if p in description.lower())
        if generic_count >= 2 and len(description) < 200:
            anomalies.append("Description appears generic/template-like")

        # Check for missing critical fields
        if not finding.get("location"):
            anomalies.append("Missing location information")

        # Check for implausible severity claims
        severity = str(finding.get("severity", "")).lower()
        if severity == "critical" and not finding.get("attack_scenario"):
            anomalies.append("Critical severity without attack scenario")

        return anomalies

    def _calculate_status_and_confidence(
        self,
        original_confidence: float,
        validation_sources: int,
        has_anomalies: bool,
        has_code_evidence: bool,
    ) -> Tuple[ValidationStatus, float]:
        """Calculate validation status and adjusted confidence."""
        adjusted = original_confidence

        if validation_sources >= 2:
            # Multiple sources confirm - validated
            status = ValidationStatus.VALIDATED
            # Slight boost for validated findings
            adjusted = min(1.0, adjusted + 0.1)

        elif validation_sources == 1:
            # Single source confirms - partial
            status = ValidationStatus.PARTIAL
            # No penalty for partial validation

        elif has_code_evidence:
            # No tool confirmation but code pattern exists
            status = ValidationStatus.UNVALIDATED
            adjusted -= self.confidence_penalty_unvalidated

        elif has_anomalies:
            # Anomalies detected - suspicious
            status = ValidationStatus.SUSPICIOUS
            adjusted -= self.confidence_penalty_suspicious

        else:
            # No validation, no anomalies - unvalidated
            status = ValidationStatus.UNVALIDATED
            adjusted -= self.confidence_penalty_unvalidated

        # Apply additional penalty for anomalies
        if has_anomalies and status != ValidationStatus.SUSPICIOUS:
            adjusted -= 0.1

        # Clamp confidence
        adjusted = max(0.0, min(1.0, adjusted))

        # Mark as hallucination if confidence drops too low
        if adjusted < 0.1:
            status = ValidationStatus.HALLUCINATION

        return status, adjusted


def validate_llm_findings(
    llm_findings: List[Dict[str, Any]],
    static_findings: Optional[List[Dict[str, Any]]] = None,
    contract_code: Optional[str] = None,
) -> List[ValidatedFinding]:
    """
    Convenience function for validating LLM findings.

    Args:
        llm_findings: Findings from LLM analysis
        static_findings: Findings from static tools (Slither, Aderyn, etc.)
        contract_code: Contract source code

    Returns:
        List of validated findings

    Example:
        >>> validated = validate_llm_findings(
        ...     llm_findings=smartllm_results,
        ...     static_findings=slither_results,
        ...     contract_code=contract_source
        ... )
        >>> reliable = [f for f in validated if f.is_reliable]
    """
    detector = HallucinationDetector()
    return detector.validate_findings(llm_findings, static_findings, contract_code)


def cross_validate_finding(
    finding: Dict[str, Any],
    static_findings: List[Dict[str, Any]],
    contract_code: Optional[str] = None,
) -> ValidationResult:
    """
    Cross-validate a single LLM finding.

    Args:
        finding: Single LLM finding
        static_findings: Static analysis results
        contract_code: Contract source

    Returns:
        ValidationResult with status and adjusted confidence
    """
    detector = HallucinationDetector()
    results = detector.validate_findings([finding], static_findings, contract_code)
    return (
        results[0].validation
        if results
        else ValidationResult(
            status=ValidationStatus.UNVALIDATED,
            original_confidence=float(finding.get("confidence", 0.5)),
            adjusted_confidence=0.3,
            reasons=["Validation failed"],
        )
    )


def filter_reliable_findings(
    validated_findings: List[ValidatedFinding],
    min_confidence: float = 0.3,
) -> List[Dict[str, Any]]:
    """
    Filter to only reliable findings above confidence threshold.

    Args:
        validated_findings: List of validated findings
        min_confidence: Minimum adjusted confidence

    Returns:
        List of reliable finding dictionaries with adjusted confidence
    """
    reliable = []
    for vf in validated_findings:
        if vf.is_reliable and vf.adjusted_confidence >= min_confidence:
            # Update finding with adjusted confidence
            finding = vf.finding.copy()
            finding["confidence"] = vf.adjusted_confidence
            finding["validation_status"] = vf.validation.status.value
            finding["validation_sources"] = vf.validation.validation_sources
            reliable.append(finding)

    return reliable
