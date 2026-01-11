"""
Example Custom Detectors for MIESC
==================================

This module provides example implementations of custom detectors
to demonstrate how to use the MIESC detector API.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

import re
from typing import List

from . import BaseDetector, Finding, Severity, register_detector


@register_detector
class FlashLoanDetector(BaseDetector):
    """
    Detect potential flash loan vulnerabilities.

    Checks for:
    - External price oracle calls without TWAP protection
    - Single-block price manipulation risks
    - Unprotected callback functions
    """

    name = "flash-loan-attack"
    description = "Detects flash loan attack patterns and price manipulation risks"
    category = "defi"
    severity_default = Severity.HIGH
    version = "1.0.0"
    author = "MIESC Team"
    references = [
        "https://swcregistry.io/docs/SWC-116",
        "https://consensys.github.io/smart-contract-best-practices/attacks/oracle-manipulation/",
    ]

    # Patterns that indicate price oracle usage
    ORACLE_PATTERNS = [
        r"\.getPrice\s*\(",
        r"\.latestAnswer\s*\(",
        r"\.latestRoundData\s*\(",
        r"getAmountOut\s*\(",
        r"getReserves\s*\(",
        r"slot0\s*\(",
    ]

    # Patterns that indicate TWAP protection
    TWAP_PATTERNS = [
        r"twap",
        r"TWAP",
        r"timeWeightedAverage",
        r"observe\s*\(",
        r"consult\s*\(",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for oracle usage
            for pattern in self.ORACLE_PATTERNS:
                if re.search(pattern, line):
                    # Check if TWAP protection exists nearby
                    context_start = max(0, i - 20)
                    context_end = min(len(lines), i + 20)
                    context = "\n".join(lines[context_start:context_end])

                    has_twap = any(re.search(p, context, re.IGNORECASE) for p in self.TWAP_PATTERNS)

                    if not has_twap:
                        findings.append(
                            self.create_finding(
                                title="Flash Loan Oracle Manipulation Risk",
                                description="Price oracle call without TWAP protection detected. "
                                "This could be exploited in a flash loan attack.",
                                line=i,
                                file_path=file_path or "",
                                recommendation="Use time-weighted average price (TWAP) instead of "
                                "spot price. Consider using Chainlink or Uniswap TWAP oracles.",
                            )
                        )

        return findings


@register_detector
class ReentrancyPatternDetector(BaseDetector):
    """
    Detect reentrancy vulnerabilities using pattern matching.

    This is a lightweight detector that complements Slither's
    reentrancy detection with additional patterns.
    """

    name = "reentrancy-patterns"
    description = "Detects reentrancy vulnerability patterns"
    category = "security"
    severity_default = Severity.CRITICAL
    version = "1.0.0"
    references = [
        "https://swcregistry.io/docs/SWC-107",
        "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
    ]

    # Patterns for external calls
    EXTERNAL_CALL_PATTERNS = [
        r"\.call\{value:",
        r"\.call\(",
        r"\.send\(",
        r"\.transfer\(",
        r"safeTransfer\(",
        r"safeTransferFrom\(",
    ]

    # Patterns for state changes
    STATE_CHANGE_PATTERNS = [
        r"\w+\s*=\s*",
        r"\w+\s*\+=",
        r"\w+\s*-=",
        r"delete\s+\w+",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        # Find functions and analyze them
        in_function = False
        function_name = ""
        brace_count = 0

        for i, line in enumerate(lines, 1):
            # Detect function start
            func_match = re.search(r"function\s+(\w+)", line)
            if func_match:
                in_function = True
                function_name = func_match.group(1)
                brace_count = line.count("{") - line.count("}")
                continue

            if in_function:
                brace_count += line.count("{") - line.count("}")

                # Function ended
                if brace_count <= 0:
                    in_function = False
                    continue

                # Check for external call
                for pattern in self.EXTERNAL_CALL_PATTERNS:
                    if re.search(pattern, line):
                        # Check for state changes AFTER the external call
                        remaining_lines = lines[i : i + 10]
                        for _idx, next_line in enumerate(remaining_lines):
                            for state_pattern in self.STATE_CHANGE_PATTERNS:
                                if re.search(state_pattern, next_line):
                                    # Potential reentrancy!
                                    desc = (
                                        f"External call followed by state change "
                                        f"in function '{function_name}'. State is "
                                        f"modified after external call."
                                    )
                                    rec = (
                                        "Apply checks-effects-interactions pattern. "
                                        "Consider using OpenZeppelin's ReentrancyGuard."
                                    )
                                    findings.append(
                                        self.create_finding(
                                            title="Potential Reentrancy Vulnerability",
                                            description=desc,
                                            line=i,
                                            file_path=file_path or "",
                                            function=function_name,
                                            severity=Severity.CRITICAL,
                                            recommendation=rec,
                                        )
                                    )
                                    break

        return findings


@register_detector
class AccessControlDetector(BaseDetector):
    """
    Detect missing or weak access control.
    """

    name = "access-control"
    description = "Detects missing or weak access control patterns"
    category = "security"
    severity_default = Severity.HIGH
    version = "1.0.0"
    references = [
        "https://swcregistry.io/docs/SWC-105",
    ]

    # Sensitive functions that should have access control
    SENSITIVE_PATTERNS = [
        r"function\s+withdraw",
        r"function\s+transfer",
        r"function\s+mint",
        r"function\s+burn",
        r"function\s+pause",
        r"function\s+unpause",
        r"function\s+set\w+",
        r"function\s+update\w+",
        r"selfdestruct\s*\(",
        r"delegatecall\s*\(",
    ]

    # Access control modifiers
    ACCESS_MODIFIERS = [
        r"onlyOwner",
        r"onlyAdmin",
        r"onlyRole",
        r"onlyMinter",
        r"onlyGovernance",
        r"require\s*\(\s*msg\.sender\s*==",
        r"require\s*\(\s*hasRole",
        r"_checkOwner",
        r"_checkRole",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            for pattern in self.SENSITIVE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Get the function context (next 5 lines)
                    context_end = min(len(lines), i + 5)
                    context = "\n".join(lines[i - 1 : context_end])

                    # Check for access control
                    has_access_control = any(
                        re.search(mod, context) for mod in self.ACCESS_MODIFIERS
                    )

                    # Check for visibility - internal/private don't need access control
                    if re.search(r"\b(internal|private)\b", line):
                        continue

                    if not has_access_control:
                        func_match = re.search(r"function\s+(\w+)", line)
                        func_name = func_match.group(1) if func_match else "unknown"

                        desc = (
                            f"Sensitive function '{func_name}' may lack proper "
                            f"access control. Public/external functions that "
                            f"modify state should have access restrictions."
                        )
                        rec = (
                            "Add access control modifier like 'onlyOwner' or "
                            "implement role-based access control."
                        )
                        findings.append(
                            self.create_finding(
                                title="Missing Access Control",
                                description=desc,
                                line=i,
                                file_path=file_path or "",
                                function=func_name,
                                recommendation=rec,
                            )
                        )

        return findings


@register_detector
class TxOriginDetector(BaseDetector):
    """
    Detect usage of tx.origin for authentication.
    """

    name = "tx-origin"
    description = "Detects tx.origin usage for authentication"
    category = "security"
    severity_default = Severity.MEDIUM
    version = "1.0.0"
    references = [
        "https://swcregistry.io/docs/SWC-115",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            if re.search(r"tx\.origin", line):
                # Check if it's used for authorization
                auth_pattern = r"require.*tx\.origin|tx\.origin\s*=="
                if re.search(auth_pattern, line):
                    desc = (
                        "tx.origin is used for authentication. "
                        "This can be exploited by a malicious contract."
                    )
                    findings.append(
                        self.create_finding(
                            title="tx.origin Used for Authentication",
                            description=desc,
                            line=i,
                            file_path=file_path or "",
                            severity=Severity.MEDIUM,
                            recommendation="Use msg.sender instead of tx.origin.",
                        )
                    )

        return findings


@register_detector
class UncheckedReturnDetector(BaseDetector):
    """
    Detect unchecked return values from external calls.
    """

    name = "unchecked-return"
    description = "Detects unchecked return values from low-level calls"
    category = "security"
    severity_default = Severity.MEDIUM
    version = "1.0.0"
    references = [
        "https://swcregistry.io/docs/SWC-104",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for low-level calls without return value handling
            low_level = r"\.call\(|\.delegatecall\(|\.staticcall\("
            if re.search(low_level, line):
                # Check if return is captured
                if not re.search(r"\(\s*bool\s+\w+|success|result", line):
                    rec = (
                        "Always check the return value: "
                        "(bool success, ) = addr.call(...); require(success);"
                    )
                    findings.append(
                        self.create_finding(
                            title="Unchecked Return Value",
                            description="Low-level call return value is not checked.",
                            line=i,
                            file_path=file_path or "",
                            severity=Severity.MEDIUM,
                            recommendation=rec,
                        )
                    )

            # Check for send without return check
            has_send = re.search(r"\.send\(", line)
            has_check = re.search(r"require.*\.send|if.*\.send", line)
            if has_send and not has_check:
                findings.append(
                    self.create_finding(
                        title="Unchecked send() Return Value",
                        description="send() return value is not checked.",
                        line=i,
                        file_path=file_path or "",
                        severity=Severity.MEDIUM,
                        recommendation="Use transfer() or require(addr.send(amount));",
                    )
                )

        return findings


# List all example detectors for documentation
EXAMPLE_DETECTORS = [
    FlashLoanDetector,
    ReentrancyPatternDetector,
    AccessControlDetector,
    TxOriginDetector,
    UncheckedReturnDetector,
]
