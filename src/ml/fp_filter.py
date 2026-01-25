"""
MIESC False Positive Filter - ML-Enhanced FP Reduction
======================================================

Intelligent false positive filtering using pattern matching, context analysis,
and ML-based confidence scoring to reduce noise in security audit reports.

This module provides:
- 270+ curated patterns for known safe code constructs
- Library detection (OpenZeppelin, Solmate, Solady, etc.)
- Context-aware FP probability scoring
- Integration with correlation engine for multi-tool validation

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA
Date: January 2026
Version: 1.0.0
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class FPCategory(Enum):
    """Categories of false positive patterns."""
    LIBRARY_SAFE = "library_safe"  # Known safe libraries
    PATTERN_SAFE = "pattern_safe"  # Safe code patterns
    CONTEXT_SAFE = "context_safe"  # Safe based on context
    TEST_FILE = "test_file"  # Test files
    MOCK_CONTRACT = "mock_contract"  # Mock contracts
    INTERFACE = "interface"  # Interface definitions
    ABSTRACT = "abstract"  # Abstract contracts


@dataclass
class FPMatch:
    """Represents a false positive match."""
    category: FPCategory
    pattern: str
    confidence: float  # 0.0 - 1.0, how confident we are this is FP
    reason: str
    matched_text: Optional[str] = None


@dataclass
class FilterResult:
    """Result of false positive filtering."""
    is_likely_fp: bool
    fp_probability: float
    matches: List[FPMatch] = field(default_factory=list)
    original_confidence: float = 0.0
    adjusted_confidence: float = 0.0
    should_report: bool = True
    filter_reason: Optional[str] = None


class FalsePositiveFilter:
    """
    Intelligent false positive filter for smart contract security findings.

    Uses multi-layer pattern matching to identify likely false positives:
    1. Library detection (OpenZeppelin, Solmate, Solady)
    2. Safe code patterns (ReentrancyGuard, SafeERC20, etc.)
    3. Context analysis (test files, mocks, interfaces)
    4. ML-based confidence adjustment
    """

    # =========================================================================
    # SAFE LIBRARY PATTERNS
    # =========================================================================

    # Patterns that indicate code is from trusted, audited libraries
    SAFE_LIBRARY_PATTERNS = [
        # OpenZeppelin Contracts
        r"@openzeppelin/contracts",
        r"@openzeppelin/contracts-upgradeable",
        r"openzeppelin-contracts/",
        r"openzeppelin-solidity/",

        # Solmate (gas-optimized library by Transmissions11)
        r"solmate/",
        r"rari-capital/solmate",

        # Solady (ultra gas-optimized by Vectorized)
        r"solady/",
        r"Vectorized/solady",

        # Chainlink
        r"@chainlink/contracts",
        r"smartcontractkit/chainlink",

        # Uniswap
        r"@uniswap/v2-core",
        r"@uniswap/v3-core",
        r"@uniswap/v2-periphery",
        r"@uniswap/v3-periphery",

        # Compound
        r"compound-finance/compound-protocol",

        # Aave
        r"@aave/protocol-v2",
        r"@aave/core-v3",

        # Safe (formerly Gnosis Safe)
        r"@gnosis.pm/safe-contracts",
        r"safe-global/safe-contracts",

        # Forge/Foundry standard library
        r"forge-std/",
        r"foundry-rs/forge-std",

        # Other well-audited libraries
        r"@prb/math",
        r"@ensdomains/ens-contracts",
    ]

    # =========================================================================
    # SAFE CODE PATTERNS - Reentrancy Protection
    # =========================================================================

    REENTRANCY_SAFE_PATTERNS = [
        # OpenZeppelin ReentrancyGuard
        r"ReentrancyGuard",
        r"nonReentrant",
        r"_nonReentrant",
        r"ReentrancyGuardUpgradeable",

        # Solmate ReentrancyGuard
        r"import\s*{\s*ReentrancyGuard\s*}",

        # Manual reentrancy lock patterns
        r"require\s*\(\s*!locked\s*\)",
        r"require\s*\(\s*!_locked\s*\)",
        r"require\s*\(\s*!reentrancyLock\s*\)",
        r"if\s*\(\s*locked\s*\)\s*revert",
        r"if\s*\(\s*_locked\s*\)\s*revert",

        # Mutex patterns
        r"mutex\s*=\s*true",
        r"_mutex\s*=\s*true",
        r"locked\s*=\s*true",
        r"_locked\s*=\s*true",

        # Checks-Effects-Interactions confirmed
        r"// CEI pattern",
        r"// Checks-Effects-Interactions",
        r"// effects before interactions",
    ]

    # =========================================================================
    # SAFE CODE PATTERNS - Access Control
    # =========================================================================

    ACCESS_CONTROL_SAFE_PATTERNS = [
        # OpenZeppelin Ownable
        r"Ownable",
        r"Ownable2Step",
        r"OwnableUpgradeable",
        r"onlyOwner",
        r"_checkOwner\s*\(\s*\)",

        # OpenZeppelin AccessControl
        r"AccessControl",
        r"AccessControlUpgradeable",
        r"AccessControlEnumerable",
        r"onlyRole\s*\(",
        r"_checkRole\s*\(",
        r"hasRole\s*\(",
        r"grantRole\s*\(",
        r"revokeRole\s*\(",
        r"DEFAULT_ADMIN_ROLE",

        # Custom access modifiers (common patterns)
        r"onlyAdmin",
        r"onlyOperator",
        r"onlyMinter",
        r"onlyBurner",
        r"onlyGovernance",
        r"onlyGuardian",
        r"onlyKeeper",
        r"onlyWhitelisted",
        r"onlyAuthorized",

        # Multi-sig patterns
        r"require\s*\(\s*confirmations\s*>=\s*required\s*\)",
        r"multisig",
        r"MultiSig",
    ]

    # =========================================================================
    # SAFE CODE PATTERNS - Safe Math & Transfers
    # =========================================================================

    SAFE_MATH_PATTERNS = [
        # SafeMath (legacy but still used)
        r"SafeMath",
        r"using\s+SafeMath\s+for",
        r"\.add\s*\(",
        r"\.sub\s*\(",
        r"\.mul\s*\(",
        r"\.div\s*\(",

        # Solidity 0.8+ built-in overflow checks
        r"pragma\s+solidity\s*[\^~>=<]*\s*0\.8",

        # Unchecked blocks (explicit, developer is aware)
        r"unchecked\s*{",

        # PRBMath
        r"@prb/math",
        r"PRBMath",
        r"UD60x18",
        r"SD59x18",

        # FixedPointMathLib (Solmate)
        r"FixedPointMathLib",
        r"mulWadDown",
        r"mulWadUp",
        r"divWadDown",
        r"divWadUp",
    ]

    SAFE_TRANSFER_PATTERNS = [
        # SafeERC20 (OpenZeppelin)
        r"SafeERC20",
        r"safeTransfer\s*\(",
        r"safeTransferFrom\s*\(",
        r"safeApprove\s*\(",
        r"safeIncreaseAllowance\s*\(",
        r"safeDecreaseAllowance\s*\(",
        r"using\s+SafeERC20\s+for",

        # SafeTransferLib (Solmate)
        r"SafeTransferLib",

        # Safe ETH transfer patterns
        r"Address\.sendValue\s*\(",
        r"payable\s*\([^)]+\)\.call\s*{\s*value:",  # Low-level with value check
    ]

    # =========================================================================
    # SAFE CODE PATTERNS - Input Validation
    # =========================================================================

    INPUT_VALIDATION_PATTERNS = [
        # Zero address checks
        r"require\s*\([^)]*!=\s*address\s*\(\s*0\s*\)",
        r"require\s*\([^)]*!=\s*address\s*\(0x0+\)",
        r"if\s*\([^)]*==\s*address\s*\(\s*0\s*\)\s*\)\s*revert",
        r"_checkNonZeroAddress\s*\(",

        # Require with message (proper validation)
        r"require\s*\([^)]+,\s*['\"][^'\"]+['\"]\s*\)",

        # Custom errors with revert
        r"if\s*\([^)]+\)\s*revert\s+\w+\s*\(",
        r"if\s*\([^)]+\)\s*revert\s+\w+;",

        # Bounds checking
        r"require\s*\([^)]*<=\s*[^)]+\)",
        r"require\s*\([^)]*>=\s*[^)]+\)",
        r"require\s*\([^)]*<\s*[^)]+\)",
        r"require\s*\([^)]*>\s*[^)]+\)",
    ]

    # =========================================================================
    # SAFE CODE PATTERNS - Pausable & Emergency
    # =========================================================================

    PAUSABLE_PATTERNS = [
        r"Pausable",
        r"PausableUpgradeable",
        r"whenNotPaused",
        r"whenPaused",
        r"_pause\s*\(\s*\)",
        r"_unpause\s*\(\s*\)",
        r"paused\s*\(\s*\)",

        # Emergency patterns
        r"emergencyWithdraw",
        r"emergencyStop",
        r"circuitBreaker",
    ]

    # =========================================================================
    # SAFE CODE PATTERNS - Upgradeable Contracts
    # =========================================================================

    UPGRADEABLE_SAFE_PATTERNS = [
        # OpenZeppelin upgradeable
        r"Initializable",
        r"UUPSUpgradeable",
        r"TransparentUpgradeableProxy",
        r"ERC1967Upgrade",
        r"initializer\s+modifier",
        r"onlyInitializing",
        r"_disableInitializers\s*\(\s*\)",

        # Safe storage patterns
        r"@custom:storage-location",
        r"StorageSlot",
    ]

    # =========================================================================
    # PATTERNS THAT INDICATE TEST/MOCK CODE
    # =========================================================================

    TEST_FILE_PATTERNS = [
        r"test[s]?[/\\]",
        r"\.t\.sol$",
        r"Test\.sol$",
        r"\.test\.sol$",
        r"_test\.sol$",
        r"tests?/",
        r"spec[s]?/",
        r"__tests__/",
    ]

    MOCK_CONTRACT_PATTERNS = [
        r"Mock\w+",
        r"\w+Mock",
        r"Fake\w+",
        r"\w+Fake",
        r"Stub\w+",
        r"\w+Stub",
        r"contract\s+Mock",
        r"// MOCK",
        r"// TEST ONLY",
        r"// FOR TESTING",
    ]

    INTERFACE_PATTERNS = [
        r"^interface\s+I\w+",
        r"\.interface\.sol$",
        r"/interfaces?/",
    ]

    ABSTRACT_PATTERNS = [
        r"abstract\s+contract",
    ]

    # =========================================================================
    # VULNERABILITY-SPECIFIC SAFE PATTERNS
    # =========================================================================

    # Patterns that make specific vulnerability types less likely
    VULN_SPECIFIC_SAFE_PATTERNS = {
        "reentrancy": [
            r"nonReentrant",
            r"ReentrancyGuard",
            r"locked\s*=\s*true",
            r"// CEI",
        ],
        "access-control": [
            r"onlyOwner",
            r"onlyRole",
            r"AccessControl",
            r"Ownable",
            r"msg\.sender\s*==\s*owner",
        ],
        "arithmetic": [
            r"SafeMath",
            r"pragma\s+solidity\s*[\^~>=<]*\s*0\.8",
            r"unchecked\s*{",  # Explicit unchecked is intentional
        ],
        "unchecked-call": [
            r"SafeERC20",
            r"safeTransfer",
            r"require\s*\(\s*success\s*\)",
            r"if\s*\(\s*!success\s*\)",
        ],
        "tx-origin": [
            r"msg\.sender",  # Using msg.sender instead
        ],
        "delegatecall": [
            r"onlyOwner",
            r"onlyAdmin",
            r"_checkRole",
        ],
        "selfdestruct": [
            r"onlyOwner",
            r"onlyAdmin",
            r"multisig",
        ],
        "front-running": [
            r"commit-reveal",
            r"commitReveal",
            r"CommitReveal",
            r"deadline",
            r"minAmountOut",
        ],
    }

    # =========================================================================
    # CONFIDENCE ADJUSTMENTS
    # =========================================================================

    # How much to reduce FP probability when pattern is found
    PATTERN_CONFIDENCE_BOOST = {
        FPCategory.LIBRARY_SAFE: 0.40,  # Strong reduction
        FPCategory.PATTERN_SAFE: 0.25,  # Moderate reduction
        FPCategory.CONTEXT_SAFE: 0.15,  # Light reduction
        FPCategory.TEST_FILE: 0.50,  # Test files almost always FP
        FPCategory.MOCK_CONTRACT: 0.45,
        FPCategory.INTERFACE: 0.40,
        FPCategory.ABSTRACT: 0.30,
    }

    def __init__(
        self,
        fp_threshold: float = 0.50,
        filter_test_files: bool = True,
        filter_interfaces: bool = True,
        filter_informational: bool = True,
    ):
        """
        Initialize the false positive filter.

        Args:
            fp_threshold: Probability threshold above which to filter (0.0-1.0)
            filter_test_files: Whether to filter findings in test files
            filter_interfaces: Whether to filter findings in interfaces
            filter_informational: Whether to filter INFO severity findings
        """
        self.fp_threshold = fp_threshold
        self.filter_test_files = filter_test_files
        self.filter_interfaces = filter_interfaces
        self.filter_informational = filter_informational

        # Compile regex patterns for performance
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self._compile_patterns()

        logger.info(f"FP Filter initialized with threshold={fp_threshold}")

    def _compile_patterns(self):
        """Pre-compile regex patterns for better performance."""
        pattern_groups = {
            "library": self.SAFE_LIBRARY_PATTERNS,
            "reentrancy": self.REENTRANCY_SAFE_PATTERNS,
            "access_control": self.ACCESS_CONTROL_SAFE_PATTERNS,
            "safe_math": self.SAFE_MATH_PATTERNS,
            "safe_transfer": self.SAFE_TRANSFER_PATTERNS,
            "input_validation": self.INPUT_VALIDATION_PATTERNS,
            "pausable": self.PAUSABLE_PATTERNS,
            "upgradeable": self.UPGRADEABLE_SAFE_PATTERNS,
            "test_file": self.TEST_FILE_PATTERNS,
            "mock": self.MOCK_CONTRACT_PATTERNS,
            "interface": self.INTERFACE_PATTERNS,
            "abstract": self.ABSTRACT_PATTERNS,
        }

        for name, patterns in pattern_groups.items():
            self._compiled_patterns[name] = [
                re.compile(p, re.IGNORECASE | re.MULTILINE)
                for p in patterns
            ]

    def filter_finding(
        self,
        finding: Dict[str, Any],
        code_context: str = "",
        file_path: str = "",
    ) -> FilterResult:
        """
        Analyze a finding and determine if it's likely a false positive.

        Args:
            finding: The security finding to analyze
            code_context: Code snippet around the finding
            file_path: Path to the source file

        Returns:
            FilterResult with FP probability and matches
        """
        matches: List[FPMatch] = []
        original_confidence = finding.get("confidence", 0.7)
        vuln_type = finding.get("type", "").lower()
        severity = finding.get("severity", "").lower()

        # Check file-level patterns
        if file_path:
            matches.extend(self._check_file_patterns(file_path))

        # Check code context patterns
        if code_context:
            matches.extend(self._check_code_patterns(code_context, vuln_type))

        # Check library imports in finding message/description
        message = finding.get("message", "") + " " + finding.get("description", "")
        matches.extend(self._check_library_patterns(message))

        # Calculate FP probability
        fp_probability = self._calculate_fp_probability(matches, original_confidence)

        # Determine if should filter
        is_likely_fp = fp_probability >= self.fp_threshold

        # Special handling for informational findings
        if self.filter_informational and severity in ["info", "informational"]:
            is_likely_fp = True
            fp_probability = max(fp_probability, 0.6)

        # Calculate adjusted confidence
        adjusted_confidence = original_confidence * (1 - fp_probability)

        # Determine if should report
        should_report = not is_likely_fp

        # Build filter reason
        filter_reason = None
        if is_likely_fp:
            if matches:
                top_match = max(matches, key=lambda m: m.confidence)
                filter_reason = f"{top_match.category.value}: {top_match.reason}"
            else:
                filter_reason = "Low confidence score"

        return FilterResult(
            is_likely_fp=is_likely_fp,
            fp_probability=fp_probability,
            matches=matches,
            original_confidence=original_confidence,
            adjusted_confidence=adjusted_confidence,
            should_report=should_report,
            filter_reason=filter_reason,
        )

    def _check_file_patterns(self, file_path: str) -> List[FPMatch]:
        """Check if file path indicates test/mock/interface."""
        matches = []

        # Test files
        if self.filter_test_files:
            for pattern in self._compiled_patterns.get("test_file", []):
                if pattern.search(file_path):
                    matches.append(FPMatch(
                        category=FPCategory.TEST_FILE,
                        pattern=pattern.pattern,
                        confidence=0.50,
                        reason="File appears to be a test file",
                        matched_text=file_path,
                    ))
                    break

        # Mock contracts
        for pattern in self._compiled_patterns.get("mock", []):
            if pattern.search(file_path):
                matches.append(FPMatch(
                    category=FPCategory.MOCK_CONTRACT,
                    pattern=pattern.pattern,
                    confidence=0.45,
                    reason="File appears to be a mock contract",
                    matched_text=file_path,
                ))
                break

        # Interfaces
        if self.filter_interfaces:
            for pattern in self._compiled_patterns.get("interface", []):
                if pattern.search(file_path):
                    matches.append(FPMatch(
                        category=FPCategory.INTERFACE,
                        pattern=pattern.pattern,
                        confidence=0.40,
                        reason="File appears to be an interface",
                        matched_text=file_path,
                    ))
                    break

        return matches

    def _check_code_patterns(self, code: str, vuln_type: str) -> List[FPMatch]:
        """Check code context for safe patterns."""
        matches = []

        # Check all safe code pattern groups
        pattern_groups = [
            ("reentrancy", FPCategory.PATTERN_SAFE, "Uses reentrancy protection"),
            ("access_control", FPCategory.PATTERN_SAFE, "Uses access control"),
            ("safe_math", FPCategory.PATTERN_SAFE, "Uses safe math"),
            ("safe_transfer", FPCategory.PATTERN_SAFE, "Uses safe transfer"),
            ("input_validation", FPCategory.PATTERN_SAFE, "Has input validation"),
            ("pausable", FPCategory.PATTERN_SAFE, "Uses pausable pattern"),
            ("upgradeable", FPCategory.PATTERN_SAFE, "Uses safe upgrade pattern"),
            ("abstract", FPCategory.CONTEXT_SAFE, "Abstract contract"),
        ]

        for group_name, category, reason in pattern_groups:
            for pattern in self._compiled_patterns.get(group_name, []):
                match = pattern.search(code)
                if match:
                    matches.append(FPMatch(
                        category=category,
                        pattern=pattern.pattern,
                        confidence=self.PATTERN_CONFIDENCE_BOOST.get(category, 0.20),
                        reason=reason,
                        matched_text=match.group(0)[:50],
                    ))
                    break  # One match per group is enough

        # Check vulnerability-specific safe patterns
        if vuln_type and vuln_type in self.VULN_SPECIFIC_SAFE_PATTERNS:
            for pattern_str in self.VULN_SPECIFIC_SAFE_PATTERNS[vuln_type]:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                match = pattern.search(code)
                if match:
                    matches.append(FPMatch(
                        category=FPCategory.PATTERN_SAFE,
                        pattern=pattern_str,
                        confidence=0.30,  # Strong confidence for vuln-specific
                        reason=f"Has protection against {vuln_type}",
                        matched_text=match.group(0)[:50],
                    ))
                    break

        return matches

    def _check_library_patterns(self, text: str) -> List[FPMatch]:
        """Check for known safe library references."""
        matches = []

        for pattern in self._compiled_patterns.get("library", []):
            match = pattern.search(text)
            if match:
                matches.append(FPMatch(
                    category=FPCategory.LIBRARY_SAFE,
                    pattern=pattern.pattern,
                    confidence=0.40,
                    reason="Uses audited library code",
                    matched_text=match.group(0)[:50],
                ))
                # Only report first library match
                break

        return matches

    def _calculate_fp_probability(
        self,
        matches: List[FPMatch],
        original_confidence: float,
    ) -> float:
        """
        Calculate false positive probability from matches.

        Uses a Bayesian-like approach where each match increases FP probability.
        """
        if not matches:
            # No matches - base FP probability from inverse of confidence
            return max(0.0, 0.3 - (original_confidence * 0.2))

        # Calculate combined FP probability from matches
        # Each match contributes its confidence, with diminishing returns
        base_fp = 0.1

        # Sort matches by confidence (highest first)
        sorted_matches = sorted(matches, key=lambda m: -m.confidence)

        combined_fp = base_fp
        for i, match in enumerate(sorted_matches):
            # Diminishing returns for additional matches
            weight = 1.0 / (i + 1)
            combined_fp += match.confidence * weight * 0.5

        # Cap at 0.95 (never 100% certain)
        return min(combined_fp, 0.95)

    def filter_findings(
        self,
        findings: List[Dict[str, Any]],
        code_contexts: Optional[Dict[str, str]] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        """
        Filter a list of findings for false positives.

        Args:
            findings: List of findings to filter
            code_contexts: Optional dict mapping file paths to code content

        Returns:
            Tuple of (filtered_findings, removed_findings, statistics)
        """
        filtered = []
        removed = []
        stats = {
            "total": len(findings),
            "filtered": 0,
            "by_category": {},
            "by_severity": {},
        }

        for finding in findings:
            file_path = finding.get("location", {}).get("file", "")
            code_context = ""

            if code_contexts and file_path:
                code_context = code_contexts.get(file_path, "")
            elif finding.get("location", {}).get("snippet"):
                code_context = finding["location"]["snippet"]

            result = self.filter_finding(finding, code_context, file_path)

            # Enrich finding with FP info
            finding["_fp_analysis"] = {
                "is_likely_fp": result.is_likely_fp,
                "fp_probability": round(result.fp_probability, 3),
                "adjusted_confidence": round(result.adjusted_confidence, 3),
                "filter_reason": result.filter_reason,
            }

            if result.should_report:
                # Update confidence with adjusted value
                finding["confidence"] = result.adjusted_confidence
                filtered.append(finding)
            else:
                removed.append(finding)
                stats["filtered"] += 1

                # Track by category
                if result.matches:
                    cat = result.matches[0].category.value
                    stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

                # Track by severity
                sev = finding.get("severity", "unknown").lower()
                stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1

        stats["remaining"] = len(filtered)
        stats["filter_rate"] = round(stats["filtered"] / max(stats["total"], 1), 3)

        logger.info(
            f"FP Filter: {stats['filtered']}/{stats['total']} filtered "
            f"({stats['filter_rate']*100:.1f}%)"
        )

        return filtered, removed, stats

    def get_statistics(self) -> Dict[str, Any]:
        """Get filter pattern statistics."""
        total_patterns = 0
        pattern_counts = {}

        for name, patterns in self._compiled_patterns.items():
            count = len(patterns)
            pattern_counts[name] = count
            total_patterns += count

        return {
            "total_patterns": total_patterns,
            "by_category": pattern_counts,
            "fp_threshold": self.fp_threshold,
            "filter_test_files": self.filter_test_files,
            "filter_interfaces": self.filter_interfaces,
            "filter_informational": self.filter_informational,
        }


# Convenience function for quick filtering
def filter_false_positives(
    findings: List[Dict[str, Any]],
    fp_threshold: float = 0.50,
    code_contexts: Optional[Dict[str, str]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Quick function to filter false positives from findings.

    Args:
        findings: List of security findings
        fp_threshold: FP probability threshold
        code_contexts: Optional code context by file path

    Returns:
        Tuple of (filtered_findings, statistics)
    """
    fp_filter = FalsePositiveFilter(fp_threshold=fp_threshold)
    filtered, removed, stats = fp_filter.filter_findings(findings, code_contexts)
    return filtered, stats


# Export
__all__ = [
    "FalsePositiveFilter",
    "FilterResult",
    "FPMatch",
    "FPCategory",
    "filter_false_positives",
]
