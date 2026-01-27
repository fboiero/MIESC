"""
Slither Cross-Validator for MIESC v4.6.0
=========================================

Integrates real Slither execution to validate pattern-based findings
and improve precision through cross-validation.

The core idea:
- Pattern detectors have high recall but low precision (many FPs)
- Slither has high precision but may miss some vulnerabilities
- Cross-validation: findings confirmed by both have high confidence

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import logging
import os
import subprocess
import tempfile
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# Mapping from pattern types to Slither detector names
PATTERN_TO_SLITHER_DETECTORS = {
    # Reentrancy patterns
    "reentrancy": [
        "reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign",
        "reentrancy-events", "reentrancy-unlimited-gas"
    ],
    "reentrancy_path": ["reentrancy-eth", "reentrancy-no-eth"],

    # Arithmetic patterns
    "arithmetic": ["divide-before-multiply", "tautology"],
    "integer_overflow": [],  # Slither doesn't detect overflow in 0.8+
    "integer_underflow": [],

    # Access control patterns
    "access_control": [
        "arbitrary-send-eth", "arbitrary-send-erc20", "suicidal",
        "protected-vars", "unprotected-upgrade"
    ],
    "unprotected_function": ["arbitrary-send-eth", "suicidal"],
    "missing_access_control": ["arbitrary-send-eth", "protected-vars"],

    # Unchecked patterns
    "unchecked_low_level_calls": [
        "unchecked-lowlevel", "unchecked-send", "low-level-calls"
    ],
    "unchecked_send": ["unchecked-send", "unchecked-lowlevel"],

    # Timestamp patterns
    "timestamp_dependence": ["timestamp", "weak-prng"],
    "bad_randomness": ["weak-prng"],

    # Front-running patterns
    "front_running": ["incorrect-equality", "weak-prng"],
    "permit_frontrun": [],

    # DoS patterns
    "denial_of_service": ["calls-loop", "costly-loop"],
    "unbounded_loop": ["calls-loop", "costly-loop"],
    "push_payment": ["calls-loop"],

    # tx.origin
    "tx_origin": ["tx-origin"],
    "tx.origin": ["tx-origin"],
}

# Slither detectors that indicate high-confidence issues
HIGH_CONFIDENCE_DETECTORS = {
    "reentrancy-eth",
    "arbitrary-send-eth",
    "suicidal",
    "controlled-delegatecall",
    "unprotected-upgrade",
}


@dataclass
class SlitherFinding:
    """A finding from Slither analysis."""
    detector: str
    impact: str
    confidence: str
    description: str
    lines: List[int] = field(default_factory=list)
    elements: List[Dict] = field(default_factory=list)


@dataclass
class ValidationResult:
    """Result of cross-validating a pattern finding with Slither."""
    pattern_type: str
    pattern_line: int
    slither_confirmed: bool
    slither_detectors_matched: List[str] = field(default_factory=list)
    confidence_adjustment: float = 0.0
    final_confidence: float = 0.0
    notes: str = ""


class SlitherValidator:
    """
    Validates pattern-based findings using real Slither execution.

    Usage:
        validator = SlitherValidator()

        # Validate a single finding
        result = validator.validate_finding(
            source_code=code,
            pattern_type="reentrancy",
            pattern_line=42,
            pattern_confidence=0.7
        )

        # Batch validate findings
        results = validator.validate_findings(
            source_code=code,
            findings=[
                {"type": "reentrancy", "line": 42, "confidence": 0.7},
                {"type": "access_control", "line": 100, "confidence": 0.6},
            ]
        )
    """

    def __init__(self, slither_binary: Optional[str] = None, timeout: int = 60):
        """
        Initialize the validator.

        Args:
            slither_binary: Path to slither binary (auto-detected if None)
            timeout: Timeout for Slither execution in seconds
        """
        self.slither_binary = slither_binary or self._find_slither()
        self.timeout = timeout
        self._slither_available = self._check_slither()

    def _find_slither(self) -> str:
        """Find the slither binary."""
        import shutil

        # Check common locations
        paths = [
            os.path.expanduser("~/.local/bin/slither"),
            "/usr/local/bin/slither",
        ]

        for path in paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path

        return shutil.which("slither") or "slither"

    def _check_slither(self) -> bool:
        """Check if Slither is available."""
        try:
            result = subprocess.run(
                [self.slither_binary, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    @property
    def is_available(self) -> bool:
        """Check if Slither validation is available."""
        return self._slither_available

    def run_slither(self, source_code: str, solc_version: str = "0.8.20") -> List[SlitherFinding]:
        """
        Run Slither on source code and return findings.

        Args:
            source_code: Solidity source code
            solc_version: Solidity compiler version to use

        Returns:
            List of SlitherFinding objects
        """
        if not self._slither_available:
            logger.warning("Slither not available, skipping validation")
            return []

        findings = []

        # Create temporary file
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.sol', delete=False
        ) as f:
            f.write(source_code)
            temp_path = f.name

        try:
            # Detect solc version from pragma
            detected_version = self._detect_solc_version(source_code)
            if detected_version:
                solc_version = detected_version

            # Run Slither
            cmd = [
                self.slither_binary,
                temp_path,
                "--json", "-",
                "--solc-disable-warnings",
            ]

            # Add solc version if not 0.8+
            if solc_version.startswith("0.4") or solc_version.startswith("0.5"):
                cmd.extend(["--solc-solcs-select", solc_version])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Parse JSON output
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    detectors = data.get("results", {}).get("detectors", [])

                    for det in detectors:
                        lines = []
                        for elem in det.get("elements", []):
                            src = elem.get("source_mapping", {})
                            if src.get("lines"):
                                lines.extend(src["lines"])

                        findings.append(SlitherFinding(
                            detector=det.get("check", ""),
                            impact=det.get("impact", ""),
                            confidence=det.get("confidence", ""),
                            description=det.get("description", ""),
                            lines=sorted(set(lines)),
                            elements=det.get("elements", []),
                        ))

                except json.JSONDecodeError:
                    logger.debug("Failed to parse Slither JSON output")

        except subprocess.TimeoutExpired:
            logger.warning(f"Slither timed out after {self.timeout}s")
        except Exception as e:
            logger.debug(f"Slither execution failed: {e}")
        finally:
            # Clean up
            try:
                os.unlink(temp_path)
            except Exception:
                pass

        return findings

    def _detect_solc_version(self, source_code: str) -> Optional[str]:
        """Detect Solidity version from pragma."""
        import re

        # Check for address payable (requires 0.5+)
        has_address_payable = "address payable" in source_code

        match = re.search(r"pragma\s+solidity\s*[\^>=<]*\s*(\d+\.\d+)", source_code)
        if match:
            version = match.group(1)

            # If contract uses 0.5+ features but pragma allows 0.4, use 0.5
            if version.startswith("0.4") and has_address_payable:
                return "0.5.17"

            # Map to closest available solc version
            version_map = {
                "0.4": "0.4.26",
                "0.5": "0.5.17",
                "0.6": "0.6.12",
                "0.7": "0.7.6",
                "0.8": "0.8.20",
            }
            for prefix, full_version in version_map.items():
                if version.startswith(prefix):
                    return full_version
        return None

    def validate_finding(
        self,
        source_code: str,
        pattern_type: str,
        pattern_line: int,
        pattern_confidence: float = 0.7,
        line_tolerance: int = 10,
    ) -> ValidationResult:
        """
        Validate a single pattern finding against Slither.

        Args:
            source_code: Solidity source code
            pattern_type: Type of vulnerability detected by pattern
            pattern_line: Line number of pattern detection
            pattern_confidence: Initial confidence from pattern detector
            line_tolerance: Lines to consider as matching

        Returns:
            ValidationResult with adjusted confidence
        """
        result = ValidationResult(
            pattern_type=pattern_type,
            pattern_line=pattern_line,
            slither_confirmed=False,
            final_confidence=pattern_confidence,
        )

        if not self._slither_available:
            result.notes = "Slither not available"
            return result

        # Run Slither
        slither_findings = self.run_slither(source_code)

        if not slither_findings:
            # No Slither findings - reduce confidence slightly
            result.confidence_adjustment = -0.1
            result.final_confidence = max(0.1, pattern_confidence - 0.1)
            result.notes = "No Slither findings"
            return result

        # Get relevant Slither detectors for this pattern type
        relevant_detectors = PATTERN_TO_SLITHER_DETECTORS.get(
            pattern_type.lower().replace("-", "_"), []
        )

        # Check for matches
        matched_detectors = []
        for finding in slither_findings:
            detector_name = finding.detector.lower().replace("_", "-")

            # Check if detector is relevant
            detector_match = any(
                det.lower().replace("_", "-") == detector_name
                for det in relevant_detectors
            ) if relevant_detectors else True  # If no mapping, consider any finding

            # Check line proximity
            line_match = any(
                abs(line - pattern_line) <= line_tolerance
                for line in finding.lines
            ) if finding.lines else False

            if detector_match and line_match:
                matched_detectors.append(finding.detector)

        if matched_detectors:
            # Slither confirmed the finding!
            result.slither_confirmed = True
            result.slither_detectors_matched = matched_detectors

            # Boost confidence
            if any(det in HIGH_CONFIDENCE_DETECTORS for det in matched_detectors):
                result.confidence_adjustment = 0.25
                result.final_confidence = min(1.0, pattern_confidence + 0.25)
                result.notes = "High-confidence Slither detector matched"
            else:
                result.confidence_adjustment = 0.15
                result.final_confidence = min(0.95, pattern_confidence + 0.15)
                result.notes = "Slither detector matched"
        else:
            # No Slither match - this might be a false positive
            result.confidence_adjustment = -0.2
            result.final_confidence = max(0.2, pattern_confidence - 0.2)
            result.notes = "Not confirmed by Slither"

        return result

    def validate_findings(
        self,
        source_code: str,
        findings: List[Dict[str, Any]],
        line_tolerance: int = 10,
    ) -> List[ValidationResult]:
        """
        Validate multiple findings efficiently (single Slither run).

        Args:
            source_code: Solidity source code
            findings: List of findings with 'type', 'line', 'confidence' keys
            line_tolerance: Lines to consider as matching

        Returns:
            List of ValidationResult objects
        """
        results = []

        if not self._slither_available:
            for f in findings:
                results.append(ValidationResult(
                    pattern_type=f.get("type", ""),
                    pattern_line=f.get("line", 0),
                    slither_confirmed=False,
                    final_confidence=f.get("confidence", 0.5),
                    notes="Slither not available",
                ))
            return results

        # Run Slither once
        slither_findings = self.run_slither(source_code)

        # Validate each finding
        for f in findings:
            pattern_type = f.get("type", "").lower().replace("-", "_")
            pattern_line = f.get("line", 0)
            pattern_confidence = f.get("confidence", 0.5)

            result = ValidationResult(
                pattern_type=pattern_type,
                pattern_line=pattern_line,
                slither_confirmed=False,
                final_confidence=pattern_confidence,
            )

            # Get relevant detectors
            relevant_detectors = PATTERN_TO_SLITHER_DETECTORS.get(pattern_type, [])

            # Check for matches
            matched = []
            for sf in slither_findings:
                detector_name = sf.detector.lower().replace("_", "-")

                detector_match = any(
                    det.lower().replace("_", "-") == detector_name
                    for det in relevant_detectors
                ) if relevant_detectors else True

                line_match = any(
                    abs(line - pattern_line) <= line_tolerance
                    for line in sf.lines
                ) if sf.lines else False

                if detector_match and line_match:
                    matched.append(sf.detector)

            if matched:
                result.slither_confirmed = True
                result.slither_detectors_matched = matched
                result.confidence_adjustment = 0.2
                result.final_confidence = min(0.95, pattern_confidence + 0.2)
                result.notes = f"Confirmed by: {', '.join(matched)}"
            elif slither_findings:
                # Slither found issues but not at this location
                result.confidence_adjustment = -0.15
                result.final_confidence = max(0.2, pattern_confidence - 0.15)
                result.notes = "Not at this location"
            else:
                result.confidence_adjustment = -0.1
                result.final_confidence = max(0.3, pattern_confidence - 0.1)
                result.notes = "No Slither findings"

            results.append(result)

        return results


def validate_with_slither(
    source_code: str,
    findings: List[Dict[str, Any]],
    timeout: int = 60,
) -> List[Dict[str, Any]]:
    """
    Convenience function to validate findings with Slither.

    Args:
        source_code: Solidity source code
        findings: List of findings to validate
        timeout: Slither timeout in seconds

    Returns:
        Findings with adjusted confidence values
    """
    validator = SlitherValidator(timeout=timeout)

    if not validator.is_available:
        return findings

    results = validator.validate_findings(source_code, findings)

    # Update findings with new confidence
    validated_findings = []
    for f, r in zip(findings, results):
        updated = f.copy()
        updated["confidence"] = r.final_confidence
        updated["_slither_validated"] = r.slither_confirmed
        updated["_slither_detectors"] = r.slither_detectors_matched
        updated["_validation_notes"] = r.notes
        validated_findings.append(updated)

    return validated_findings


def filter_unconfirmed(
    findings: List[Dict[str, Any]],
    min_confidence: float = 0.4,
) -> List[Dict[str, Any]]:
    """
    Filter out findings that weren't confirmed and have low confidence.

    Args:
        findings: Validated findings
        min_confidence: Minimum confidence to keep

    Returns:
        Filtered findings
    """
    return [
        f for f in findings
        if f.get("confidence", 0) >= min_confidence
        or f.get("_slither_validated", False)
    ]
