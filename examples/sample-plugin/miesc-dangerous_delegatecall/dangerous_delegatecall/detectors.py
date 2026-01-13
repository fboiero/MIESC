"""MIESC Detector Plugin: Detects dangerous delegatecall patterns in smart contracts

This module provides custom vulnerability detectors for MIESC.
Delegatecall is dangerous because it executes code in the context of the calling
contract, which can lead to storage corruption or unauthorized access.
"""

import re
from miesc.detectors import BaseDetector, Finding, Severity, Location, Confidence


class DangerousDelegatecallDetector(BaseDetector):
    """Detects dangerous delegatecall patterns in smart contracts.

    This detector identifies several dangerous delegatecall patterns:
    1. Delegatecall to user-controlled addresses (high severity)
    2. Delegatecall in proxy patterns without proper checks
    3. Delegatecall with msg.data forwarding
    """

    name = "dangerous_delegatecall"
    description = "Detects dangerous delegatecall patterns that could lead to contract takeover"
    version = "0.1.0"
    author = "MIESC Team"
    category = "security"
    severity_default = Severity.HIGH

    # Patterns to detect
    PATTERNS = [
        # Delegatecall to function parameter (user-controlled)
        (
            r"\.delegatecall\s*\(\s*abi\.encode",
            "Delegatecall with encoded data",
            Severity.MEDIUM,
            "Delegatecall with abi.encode can be dangerous if the target is user-controlled"
        ),
        # Delegatecall to arbitrary address
        (
            r"(\w+)\.delegatecall\s*\(",
            "Delegatecall detected",
            Severity.HIGH,
            "Delegatecall executes code in the caller's context, risking storage corruption"
        ),
        # Low-level delegatecall with assembly
        (
            r"delegatecall\s*\(\s*gas\s*\(\s*\)",
            "Low-level delegatecall in assembly",
            Severity.HIGH,
            "Assembly delegatecall bypasses Solidity safety checks"
        ),
    ]

    # Dangerous patterns that indicate user-controlled delegatecall target
    DANGEROUS_PATTERNS = [
        # Function parameter used as delegatecall target
        (
            r"function\s+\w+\s*\([^)]*address\s+(\w+)[^)]*\)[^{]*\{[^}]*\1\.delegatecall",
            "Delegatecall to user-supplied address",
            Severity.CRITICAL,
            "Delegatecall target comes from function parameter - attacker can execute arbitrary code"
        ),
        # Storage variable used as delegatecall target (proxy pattern)
        (
            r"(implementation|_implementation|impl)\s*\.delegatecall",
            "Proxy delegatecall pattern",
            Severity.MEDIUM,
            "Proxy pattern detected - ensure implementation address is properly protected"
        ),
    ]

    def analyze(self, source_code: str, file_path: str | None = None) -> list[Finding]:
        """Analyze source code for dangerous delegatecall patterns.

        Args:
            source_code: Solidity source code to analyze
            file_path: Optional path to the source file

        Returns:
            List of Finding objects for detected vulnerabilities
        """
        findings: list[Finding] = []
        lines = source_code.split('\n')

        # Check for basic delegatecall patterns
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('//') or line.strip().startswith('*'):
                continue

            for pattern, title, severity, description in self.PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        detector=self.name,
                        title=title,
                        description=description,
                        severity=severity,
                        location=Location(file=file_path, line=line_num),
                        confidence=Confidence.HIGH,
                        recommendation="Review delegatecall usage and ensure target address is trusted",
                    ))

        # Check for dangerous patterns (multi-line)
        for pattern, title, severity, description in self.DANGEROUS_PATTERNS:
            matches = re.finditer(pattern, source_code, re.IGNORECASE | re.DOTALL)
            for match in matches:
                # Find line number
                line_num = source_code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    detector=self.name,
                    title=title,
                    description=description,
                    severity=severity,
                    location=Location(file=file_path, line=line_num),
                    confidence=Confidence.HIGH,
                    recommendation="Restrict delegatecall targets to trusted addresses only",
                ))

        # Check for missing access control on functions with delegatecall
        self._check_access_control(source_code, file_path, findings)

        return findings

    def _check_access_control(
        self, source_code: str, file_path: str | None, findings: list[Finding]
    ) -> None:
        """Check if functions with delegatecall have proper access control."""
        # Find functions containing delegatecall
        func_pattern = r"function\s+(\w+)\s*\([^)]*\)\s*(public|external)[^{]*\{([^}]+delegatecall[^}]+)\}"

        for match in re.finditer(func_pattern, source_code, re.IGNORECASE | re.DOTALL):
            func_name = match.group(1)
            visibility = match.group(2)

            # Check for access control modifiers
            has_access_control = any(
                modifier in source_code[max(0, match.start()-200):match.start()]
                for modifier in ['onlyOwner', 'onlyAdmin', 'require(msg.sender', 'require(owner']
            )

            if not has_access_control and visibility in ('public', 'external'):
                line_num = source_code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    detector=self.name,
                    title=f"Unprotected delegatecall in {func_name}",
                    description=f"Function '{func_name}' contains delegatecall without access control. "
                               f"Any user can call this function and potentially corrupt contract storage.",
                    severity=Severity.CRITICAL,
                    location=Location(file=file_path, line=line_num),
                    confidence=Confidence.MEDIUM,
                    recommendation=f"Add access control modifier (e.g., onlyOwner) to function {func_name}",
                ))
