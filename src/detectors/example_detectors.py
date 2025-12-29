#!/usr/bin/env python3
"""
MIESC v4.3 - Example Custom Detectors

Demonstrates how to create custom vulnerability detectors using the MIESC API.
These examples can be used as templates for your own detectors.

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

from pathlib import Path
from typing import List, Optional

from .detector_api import (
    BaseDetector,
    PatternDetector,
    Finding,
    Severity,
    Category,
    register_detector,
)


# =============================================================================
# EXAMPLE 1: Pattern-Based Detector (Simplest)
# =============================================================================

class UncheckedCallDetector(PatternDetector):
    """
    Detects unchecked low-level calls.

    This is the simplest way to create a detector - just define patterns.
    """

    name = "unchecked-call"
    description = "Detects unchecked low-level calls that may silently fail"
    version = "1.0.0"
    category = Category.UNCHECKED_RETURN
    default_severity = Severity.HIGH

    # Pattern format: (regex, description, severity)
    PATTERNS = [
        (r'\.call\{[^}]*\}\s*\([^)]*\)\s*;',
         "Unchecked call - return value not verified", Severity.HIGH),
        (r'\.send\s*\([^)]*\)\s*;',
         "Unchecked send - can fail silently", Severity.MEDIUM),
        (r'\.transfer\s*\([^)]*\)\s*;',
         "Transfer may revert - consider call with check", Severity.LOW),
    ]


# =============================================================================
# EXAMPLE 2: Flash Loan Attack Detector (Full Implementation)
# =============================================================================

class FlashLoanDetector(BaseDetector):
    """
    Detects potential flash loan attack vulnerabilities.

    Checks for:
    - Price oracle manipulation risks
    - Balance-based access control
    - Missing TWAP protections
    """

    name = "flash-loan"
    description = "Detects flash loan attack patterns"
    version = "1.0.0"
    author = "MIESC Team"
    category = Category.FLASH_LOAN
    default_severity = Severity.HIGH

    # Only run on DeFi contracts
    target_patterns = ["swap", "pool", "oracle", "price", "liquidity"]

    # Oracle manipulation patterns
    ORACLE_PATTERNS = [
        (r'getPrice\s*\(\s*\)',
         "Direct price fetch without validation - oracle manipulation risk"),
        (r'balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)',
         "Contract balance used for pricing - flash loan vulnerable"),
        (r'\.getReserves\s*\(\s*\)',
         "Direct reserve query - may be manipulated in same block"),
    ]

    # Voting/governance with balance
    VOTING_PATTERNS = [
        (r'balanceOf\s*\([^)]*\)\s*[><=]',
         "Balance-based check - vulnerable to flash loan voting"),
        (r'require\s*\([^)]*balanceOf',
         "Balance requirement - can be bypassed with flash loan"),
    ]

    def analyze(self, source_code: str, file_path: Optional[Path] = None) -> List[Finding]:
        """Analyze contract for flash loan vulnerabilities."""
        if not self.should_run(source_code):
            return []

        findings = []

        # Check oracle patterns
        for pattern, desc in self.ORACLE_PATTERNS:
            for match, line, code in self.find_pattern(source_code, pattern):
                # Check if TWAP protection exists
                has_twap = self._has_twap_protection(source_code, line)
                if not has_twap:
                    findings.append(self.create_finding(
                        title="Flash Loan Oracle Manipulation",
                        description=f"{desc}. No TWAP protection found.",
                        severity=Severity.CRITICAL,
                        line=line,
                        code_snippet=code,
                        recommendation="Implement time-weighted average price (TWAP) "
                                      "or use Chainlink oracles with freshness checks.",
                        references=[
                            "https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest"
                        ],
                        swc_id="SWC-136",
                    ))

        # Check voting patterns
        for pattern, desc in self.VOTING_PATTERNS:
            for match, line, code in self.find_pattern(source_code, pattern):
                findings.append(self.create_finding(
                    title="Flash Loan Voting Attack",
                    description=desc,
                    severity=Severity.HIGH,
                    line=line,
                    code_snippet=code,
                    recommendation="Use checkpointed voting tokens (ERC20Votes) "
                                  "to prevent flash loan governance attacks.",
                ))

        return findings

    def _has_twap_protection(self, source_code: str, line: int) -> bool:
        """Check if TWAP protection exists near the line."""
        lines = source_code.split('\n')
        # Check surrounding 20 lines
        start = max(0, line - 10)
        end = min(len(lines), line + 10)
        context = '\n'.join(lines[start:end])

        twap_indicators = [
            'twap', 'timeWeighted', 'observe', 'consult',
            'period', 'window', 'average', 'cumulative'
        ]
        return any(ind.lower() in context.lower() for ind in twap_indicators)


# =============================================================================
# EXAMPLE 3: MEV Protection Detector
# =============================================================================

class MEVDetector(BaseDetector):
    """
    Detects MEV (Maximal Extractable Value) vulnerabilities.

    Identifies:
    - Sandwich attack risks
    - Front-running opportunities
    - Missing slippage protection
    """

    name = "mev-detector"
    description = "Detects MEV and front-running vulnerabilities"
    version = "1.0.0"
    category = Category.FRONT_RUNNING
    default_severity = Severity.MEDIUM

    target_patterns = ["swap", "trade", "exchange", "dex", "amm"]

    def analyze(self, source_code: str, file_path: Optional[Path] = None) -> List[Finding]:
        if not self.should_run(source_code):
            return []

        findings = []

        # Check for missing slippage protection
        swap_matches = self.find_pattern(source_code, r'function\s+\w*[Ss]wap\w*\s*\([^)]*\)')
        for match, line, code in swap_matches:
            # Check if function has minAmountOut parameter
            if 'min' not in code.lower() and 'slippage' not in code.lower():
                findings.append(self.create_finding(
                    title="Missing Slippage Protection",
                    description="Swap function without minimum output amount parameter. "
                               "Vulnerable to sandwich attacks.",
                    severity=Severity.HIGH,
                    line=line,
                    code_snippet=code,
                    recommendation="Add minAmountOut parameter and enforce it with require().",
                ))

        # Check for deadline
        if 'swap' in source_code.lower():
            if not self.find_pattern(source_code, r'deadline|expiry|validUntil'):
                findings.append(self.create_finding(
                    title="Missing Transaction Deadline",
                    description="Swap functions without deadline parameter. "
                               "Transactions can be held and executed at unfavorable prices.",
                    severity=Severity.MEDIUM,
                    recommendation="Add deadline parameter and check block.timestamp < deadline.",
                ))

        # Check for commit-reveal
        commit_patterns = self.find_pattern(source_code, r'commit|reveal|hash.*secret')
        if not commit_patterns and 'auction' in source_code.lower():
            findings.append(self.create_finding(
                title="Missing Commit-Reveal Pattern",
                description="Auction without commit-reveal scheme. Bids can be front-run.",
                severity=Severity.MEDIUM,
                recommendation="Implement commit-reveal pattern for auctions.",
            ))

        return findings


# =============================================================================
# EXAMPLE 4: Access Control Detector
# =============================================================================

class AccessControlDetector(PatternDetector):
    """
    Detects access control issues.

    Simpler pattern-based approach for common access control mistakes.
    """

    name = "access-control"
    description = "Detects access control vulnerabilities"
    version = "1.0.0"
    category = Category.ACCESS_CONTROL
    default_severity = Severity.HIGH

    PATTERNS = [
        # Missing access control
        (r'function\s+\w*[Ss]et(?:Owner|Admin|Role)\w*\s*\([^)]*\)\s*(?:external|public)(?![^{]*onlyOwner)',
         "Admin function without access control", Severity.CRITICAL),
        (r'selfdestruct\s*\(\s*\w+\s*\)',
         "Selfdestruct detected - verify access control", Severity.CRITICAL),

        # tx.origin misuse
        (r'require\s*\([^)]*tx\.origin',
         "tx.origin for authentication - vulnerable to phishing", Severity.HIGH),

        # Unprotected initialization
        (r'function\s+initialize\s*\([^)]*\)\s*(?:external|public)(?![^{]*initializer)',
         "Initialize without initializer modifier", Severity.CRITICAL),
    ]


# =============================================================================
# REGISTER EXAMPLE DETECTORS
# =============================================================================

def register_example_detectors():
    """Register all example detectors with MIESC."""
    register_detector(UncheckedCallDetector())
    register_detector(FlashLoanDetector())
    register_detector(MEVDetector())
    register_detector(AccessControlDetector())


# Export classes for direct import
__all__ = [
    'UncheckedCallDetector',
    'FlashLoanDetector',
    'MEVDetector',
    'AccessControlDetector',
    'register_example_detectors',
]
