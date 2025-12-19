#!/usr/bin/env python3
"""
MIESC v4.1 - SmartBugs-Specific Detectors

Detectors targeting SmartBugs vulnerability categories with 0% recall:
- Arithmetic (overflow/underflow)
- Bad Randomness
- Denial of Service
- Front Running
- Short Addresses

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


@dataclass
class SmartBugsFinding:
    """Represents a SmartBugs-category finding."""
    title: str
    description: str
    severity: Severity
    category: str  # SmartBugs category name
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    swc_id: str = ""
    confidence: str = "high"


# =============================================================================
# ARITHMETIC OVERFLOW/UNDERFLOW DETECTOR
# =============================================================================

class ArithmeticDetector:
    """
    Detects arithmetic overflow/underflow vulnerabilities.

    Targets Solidity < 0.8.0 contracts without SafeMath.
    SWC-101: Integer Overflow and Underflow
    """

    name = "arithmetic-detector"
    category = "arithmetic"
    swc_id = "SWC-101"

    # Arithmetic operations without SafeMath
    # Patterns match variables, array access, and mapping access
    ARITHMETIC_PATTERNS = [
        # Direct arithmetic without SafeMath
        (r'[\w\[\]\.]+\s*=\s*[\w\[\]\.]+\s*\+\s*[\w\[\]\.]+', "Addition without overflow check"),
        (r'[\w\[\]\.]+\s*=\s*[\w\[\]\.]+\s*-\s*[\w\[\]\.]+', "Subtraction without underflow check"),
        (r'[\w\[\]\.]+\s*=\s*[\w\[\]\.]+\s*\*\s*[\w\[\]\.]+', "Multiplication without overflow check"),
        (r'[\w\[\]\.]+\s*\+=\s*[\w\[\]\.]+', "Addition assignment without overflow check"),
        (r'[\w\[\]\.]+\s*-=\s*[\w\[\]\.]+', "Subtraction assignment without underflow check"),
        (r'[\w\[\]\.]+\s*\*=\s*[\w\[\]\.]+', "Multiplication assignment without overflow check"),
    ]

    # SafeMath line-level patterns (exclude specific lines)
    SAFEMATH_LINE_PATTERNS = [
        r'\.add\s*\(',
        r'\.sub\s*\(',
        r'\.mul\s*\(',
        r'\.div\s*\(',
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[SmartBugsFinding]:
        findings = []
        lines = source_code.split('\n')

        # Check if Solidity 0.8+ (has built-in overflow checks)
        is_solidity_08 = bool(re.search(r'pragma\s+solidity\s*[\^>=]*\s*0\.8', source_code))
        if is_solidity_08:
            return findings  # Solidity 0.8+ has built-in checks

        # Look for arithmetic operations
        for i, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('//') or line.strip().startswith('*'):
                continue

            # Skip lines that use SafeMath methods (protected)
            if any(re.search(p, line) for p in self.SAFEMATH_LINE_PATTERNS):
                continue

            for pattern, desc in self.ARITHMETIC_PATTERNS:
                if re.search(pattern, line):
                    # Check it's not a constant or safe context
                    confidence = self._get_confidence(line, source_code)
                    if confidence:
                        findings.append(SmartBugsFinding(
                            title="Integer Overflow/Underflow",
                            description=f"{desc} at line {i}. Solidity < 0.8 without SafeMath.",
                            severity=Severity.HIGH,
                            category=self.category,
                            line=i,
                            code_snippet=line.strip(),
                            swc_id=self.swc_id,
                            confidence=confidence
                        ))
                        break  # One finding per line

        return findings

    def _get_confidence(self, line: str, source: str) -> Optional[str]:
        """
        Determine confidence level for arithmetic finding.
        Returns: 'high', 'medium', 'low', or None (skip)
        """
        line_lower = line.lower().strip()

        # === SKIP CONDITIONS (return None) ===

        # Skip if it's just array indexing
        if re.search(r'\[\s*\w+\s*\+\s*\d+\s*\]', line):
            return None

        # Skip string concatenation contexts
        if 'string' in line_lower:
            return None

        # Skip if inside require/assert
        if 'require' in line_lower or 'assert' in line_lower:
            return None

        # Skip loop counter increments (i++, ++i, i += 1, etc.)
        if re.search(r'\b[ijk]\s*\+\+', line) or re.search(r'\+\+\s*[ijk]\b', line):
            return None
        if re.search(r'\b[ijk]\s*\+=\s*1\b', line):
            return None
        if re.search(r'\b[ijk]\s*=\s*[ijk]\s*\+\s*1\b', line):
            return None

        # Skip loop counter decrements
        if re.search(r'\b[ijk]\s*--', line) or re.search(r'--\s*[ijk]\b', line):
            return None
        if re.search(r'\b[ijk]\s*-=\s*1\b', line):
            return None

        # Skip if it's a simple counter variable being incremented/decremented by 1
        # But DON'T skip if it's modified by a variable (potential overflow with user input)
        counter_vars = ['counter', 'index', 'idx', 'num', 'len', 'length', 'size']
        for cv in counter_vars:
            # Only skip if incrementing/decrementing by constant 1
            if re.search(rf'\b{cv}\w*\s*[\+\-]=\s*1\s*[;\n]', line_lower):
                return None
            if re.search(rf'\b{cv}\w*\s*=\s*{cv}\w*\s*[\+\-]\s*1\s*[;\n]', line_lower):
                return None
        # Note: 'count' removed - often used as public state variable (e.g., BEC token exploit)

        # Skip view/pure function contexts
        if 'view' in line_lower or 'pure' in line_lower:
            return None

        # Skip constant assignments
        if 'constant' in line_lower or 'immutable' in line_lower:
            return None

        # Skip if not an actual assignment
        if not re.search(r'[+\-*]=|=\s*\w+\s*[+\-*]', line):
            return None

        # === CONFIDENCE LEVELS ===

        # HIGH: State variables (mappings, arrays) with financial terms
        high_confidence_patterns = [
            r'balance', r'amount', r'total', r'supply', r'credit',
            r'debit', r'deposit', r'withdraw', r'reward', r'stake',
            r'token', r'fund', r'price', r'fee', r'collateral'
        ]
        is_high_confidence = any(re.search(p, line_lower) for p in high_confidence_patterns)
        is_state_var = bool(re.search(r'\w+\s*\[\s*[^\]]+\s*\]', line))

        if is_high_confidence and is_state_var:
            return "high"

        # MEDIUM: State variables OR financial terms
        if is_high_confidence or is_state_var:
            return "medium"

        # LOW: Any other arithmetic assignment
        return "low"


# =============================================================================
# BAD RANDOMNESS DETECTOR
# =============================================================================

class BadRandomnessDetector:
    """
    Detects weak randomness sources.

    SWC-120: Weak Sources of Randomness from Chain Attributes
    """

    name = "bad-randomness-detector"
    category = "bad_randomness"
    swc_id = "SWC-120"

    WEAK_RANDOMNESS_PATTERNS = [
        (r'block\.timestamp', "block.timestamp is predictable by miners"),
        (r'block\.difficulty', "block.difficulty is predictable (and deprecated)"),
        (r'block\.number', "block.number is predictable"),
        (r'blockhash\s*\(', "blockhash is predictable and limited to last 256 blocks"),
        (r'block\.coinbase', "block.coinbase is predictable"),
        (r'now\b', "'now' (alias for block.timestamp) is predictable"),
        (r'keccak256\s*\([^)]*block\.', "Hashing block attributes doesn't add entropy"),
        (r'sha3\s*\([^)]*block\.', "Hashing block attributes doesn't add entropy"),
    ]

    # Context patterns that indicate randomness usage
    RANDOMNESS_CONTEXT = [
        r'random',
        r'lottery',
        r'winner',
        r'seed',
        r'shuffle',
        r'pick',
        r'select',
        r'chance',
        r'dice',
        r'bet',
        r'gambling',
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[SmartBugsFinding]:
        findings = []
        lines = source_code.split('\n')
        reported_lines = set()  # Track already reported lines

        # Check if contract uses randomness-related concepts
        uses_randomness = any(
            re.search(p, source_code, re.IGNORECASE)
            for p in self.RANDOMNESS_CONTEXT
        )

        for i, line in enumerate(lines, 1):
            if i in reported_lines:
                continue  # Already reported this line
            for pattern, desc in self.WEAK_RANDOMNESS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = Severity.HIGH if uses_randomness else Severity.MEDIUM
                    findings.append(SmartBugsFinding(
                        title="Weak Randomness Source",
                        description=f"{desc}. Found at line {i}.",
                        severity=severity,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        swc_id=self.swc_id
                    ))
                    reported_lines.add(i)
                    break  # One finding per line

        return findings


# =============================================================================
# DENIAL OF SERVICE DETECTOR
# =============================================================================

class DenialOfServiceDetector:
    """
    Detects Denial of Service vulnerabilities.

    SWC-113: DoS with Failed Call
    SWC-128: DoS with Block Gas Limit
    """

    name = "dos-detector"
    category = "denial_of_service"
    swc_id = "SWC-113"

    # Patterns that indicate potential DoS (require context check)
    DOS_PATTERNS = [
        # Selfdestruct DoS (high confidence)
        (r'require\s*\([^)]*balance\s*==\s*0', "Zero balance requirement - can be DoS'd with selfdestruct"),
        # Require with send/transfer - single failure can DoS
        (r'require\s*\([^)]*\.send\s*\(', "require() with send() - single failure can block function"),
        (r'require\s*\([^)]*\.transfer\s*\(', "require() with transfer() - single failure can block function"),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[SmartBugsFinding]:
        findings = []
        lines = source_code.split('\n')
        reported_lines = set()
        in_loop = False
        loop_depth = 0
        loop_start_line = 0

        # First pass: detect basic patterns and track loops
        for i, line in enumerate(lines, 1):
            if i in reported_lines:
                continue

            # Track if we're inside a loop (with depth tracking)
            if re.search(r'\bfor\s*\(', line) or re.search(r'\bwhile\s*\(', line):
                if not in_loop:
                    loop_start_line = i
                in_loop = True
                loop_depth += line.count('{')

            if in_loop:
                loop_depth += line.count('{') - line.count('}')
                if loop_depth <= 0:
                    in_loop = False
                    loop_depth = 0

            for pattern, desc in self.DOS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(SmartBugsFinding(
                        title="Denial of Service Vulnerability",
                        description=f"{desc}. Found at line {i}.",
                        severity=Severity.HIGH,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        swc_id=self.swc_id
                    ))
                    reported_lines.add(i)
                    break

            # Check for transfer/send inside loop (high risk DoS)
            if in_loop:
                if re.search(r'\.transfer\s*\(', line) or re.search(r'\.send\s*\(', line):
                    findings.append(SmartBugsFinding(
                        title="Denial of Service - Transfer in Loop",
                        description=f"External transfer inside loop at line {i}. If one call fails, entire function reverts.",
                        severity=Severity.HIGH,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        swc_id="SWC-113"
                    ))
                    reported_lines.add(i)

                # Check for .push() inside loop (gas limit DoS)
                if re.search(r'\.push\s*\(', line):
                    findings.append(SmartBugsFinding(
                        title="Denial of Service - Array Push in Loop",
                        description=f"Array push() inside loop at line {i}. Can cause gas limit DoS.",
                        severity=Severity.HIGH,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        swc_id="SWC-128"
                    ))
                    reported_lines.add(i)

                # Check for array length modification in loop
                if re.search(r'\.length\s*[\+\-]?=', line):
                    findings.append(SmartBugsFinding(
                        title="Denial of Service - Array Length Modification in Loop",
                        description=f"Array length modification inside loop at line {i}. Can cause gas limit DoS.",
                        severity=Severity.HIGH,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        swc_id="SWC-128"
                    ))
                    reported_lines.add(i)

        # Check for unbounded array growth with loop (common DoS pattern)
        if '.push' in source_code and re.search(r'for\s*\([^)]*\.length', source_code):
            findings.append(SmartBugsFinding(
                title="Unbounded Array Growth DoS",
                description="Contract uses push() and loops over array length. "
                           "Array can grow unbounded causing gas limit DoS.",
                severity=Severity.HIGH,
                category=self.category,
                swc_id="SWC-128"
            ))

        return findings


# =============================================================================
# FRONT RUNNING DETECTOR
# =============================================================================

class FrontRunningDetector:
    """
    Detects front-running vulnerabilities.

    SWC-114: Transaction Order Dependence
    """

    name = "front-running-detector"
    category = "front_running"
    swc_id = "SWC-114"

    FRONT_RUNNING_PATTERNS = [
        # State-dependent rewards with clear front-running risk
        (r'if\s*\([^)]*==\s*\w+\s*\)[^{]*reward', "Conditional reward - front-running target"),
        (r'if\s*\([^)]*==\s*\w+\s*\)[^{]*winner', "Winner determination - front-running target"),

        # Price oracle without time delay (high risk)
        (r'getPrice\s*\(\s*\)\s*;', "Price oracle call - front-running/sandwich risk"),

        # ERC20 approve front-running (classic vulnerability)
        (r'function\s+approve\s*\([^)]*spender[^)]*value', "ERC20 approve - front-running vulnerable"),
        (r'_allowed\s*\[[^\]]+\]\s*\[[^\]]+\]\s*=\s*\w+', "Allowance assignment - approve front-running"),

        # Hash-based puzzle/reveal (miner can front-run solution)
        (r'sha3\s*\([^)]+\)\s*\)|keccak256\s*\([^)]+\)', "Hash comparison - solution can be front-run"),

        # Transfer based on state variable (TOD)
        (r'\.transfer\s*\(\s*reward\s*\)', "Transfer of reward variable - TOD vulnerable"),
        (r'msg\.sender\.transfer\s*\(\s*\w*reward', "Transfer to sender based on reward - TOD"),

        # Games with user input affecting outcome
        (r'players\s*\[\s*\w+\s*\]\s*=.*msg\.sender', "Player registration - can be front-run"),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[SmartBugsFinding]:
        findings = []
        lines = source_code.split('\n')
        reported_lines = set()

        # Check for hash-then-transfer pattern (commit-reveal needed)
        has_hash_check = re.search(r'(sha3|keccak256)\s*\([^)]+\)', source_code)
        has_transfer = re.search(r'\.transfer\s*\(', source_code)
        if has_hash_check and has_transfer:
            # Find the hash line
            for i, line in enumerate(lines, 1):
                if re.search(r'(sha3|keccak256)\s*\([^)]+\)', line):
                    findings.append(SmartBugsFinding(
                        title="Front-Running - Hash Puzzle",
                        description=f"Hash check followed by transfer. Solution visible in mempool can be front-run. Line {i}.",
                        severity=Severity.HIGH,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        swc_id=self.swc_id
                    ))
                    reported_lines.add(i)
                    break

        # Check for ERC20 approve pattern
        if 'function approve' in source_code and '_allowed' in source_code:
            for i, line in enumerate(lines, 1):
                if 'function approve' in line:
                    findings.append(SmartBugsFinding(
                        title="Front-Running - ERC20 Approve",
                        description=f"ERC20 approve function without increaseAllowance pattern. Line {i}.",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        swc_id=self.swc_id
                    ))
                    reported_lines.add(i)
                    break

        # Check for TOD pattern (state-dependent transfer)
        reward_vars = re.findall(r'\b(reward|prize|bounty|payout)\s*[=;]', source_code, re.I)
        if reward_vars and re.search(r'\.transfer\s*\(', source_code):
            for i, line in enumerate(lines, 1):
                if i not in reported_lines and re.search(r'\.transfer\s*\(', line):
                    findings.append(SmartBugsFinding(
                        title="Front-Running - Transaction Order Dependence",
                        description=f"Transfer based on state variable. Transaction order can affect outcome. Line {i}.",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        swc_id=self.swc_id
                    ))
                    reported_lines.add(i)

        # Standard pattern matching
        for i, line in enumerate(lines, 1):
            if i in reported_lines:
                continue
            for pattern, desc in self.FRONT_RUNNING_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(SmartBugsFinding(
                        title="Front-Running Vulnerability",
                        description=f"{desc}. Found at line {i}.",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        swc_id=self.swc_id
                    ))
                    reported_lines.add(i)
                    break

        return findings


# =============================================================================
# SHORT ADDRESS DETECTOR
# =============================================================================

class ShortAddressDetector:
    """
    Detects short address attack vulnerabilities.

    SWC-129: Typographical Error (related to address validation)

    The short address attack exploits how the EVM pads calldata. When a user
    provides a short address (missing trailing bytes), the EVM pads from the
    right, causing subsequent uint parameters to be shifted and multiplied.

    Vulnerable pattern: function(address, uint) without msg.data.length check
    """

    name = "short-address-detector"
    category = "short_addresses"
    swc_id = "SWC-129"

    # Patterns for functions vulnerable to short address attack
    # Any function taking (address, uint) parameters
    VULNERABLE_FUNCTION_PATTERNS = [
        # Standard token transfer patterns
        r'function\s+transfer\s*\(\s*address\s+\w+\s*,\s*uint',
        r'function\s+transferFrom\s*\(\s*address',
        r'function\s+approve\s*\(\s*address\s+\w+\s*,\s*uint',
        # Generic patterns: any function with (address, uint) signature
        r'function\s+\w+\s*\(\s*address\s+\w+\s*,\s*uint\d*\s+\w+\s*\)',
        r'function\s+\w+\s*\(\s*address\s+\w+\s*,\s*uint\d*\s+\w+\s*,',
        # Common naming patterns for token operations
        r'function\s+send\w*\s*\(\s*address',
        r'function\s+mint\s*\(\s*address\s+\w+\s*,\s*uint',
        r'function\s+burn\s*\(\s*address\s+\w+\s*,\s*uint',
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[SmartBugsFinding]:
        findings = []
        lines = source_code.split('\n')

        # Check for msg.data.length validation (protection against short address)
        has_length_check = re.search(
            r'msg\.data\.length|require\s*\([^)]*\.length|assert\s*\([^)]*\.length',
            source_code
        )

        # If contract has length check, it's protected
        if has_length_check:
            return findings

        # Look for vulnerable function patterns
        for i, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('//') or line.strip().startswith('*'):
                continue

            for pattern in self.VULNERABLE_FUNCTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Extract function name for better reporting
                    func_match = re.search(r'function\s+(\w+)', line)
                    func_name = func_match.group(1) if func_match else "unknown"

                    findings.append(SmartBugsFinding(
                        title="Short Address Attack Vulnerability",
                        description=f"Function '{func_name}' takes (address, uint) parameters without "
                                   f"msg.data.length validation. Vulnerable to short address attack. Line {i}.",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        swc_id=self.swc_id
                    ))
                    break  # One finding per line

        return findings


# =============================================================================
# REENTRANCY DETECTOR
# =============================================================================

class ReentrancyDetector:
    """
    Detects reentrancy vulnerabilities.

    SWC-107: Reentrancy
    Patterns: external calls followed by state changes
    """

    name = "reentrancy-detector"
    category = "reentrancy"
    swc_id = "SWC-107"

    # External call patterns
    EXTERNAL_CALL_PATTERNS = [
        r'\.call\.value\s*\(',          # OLD syntax: .call.value(...)()
        r'\.call\s*\{[^}]*value',       # NEW syntax: .call{value: ...}
        r'\.call\s*\(\s*\)',            # .call() empty
        r'\.send\s*\(',                 # .send(...)
        r'\.transfer\s*\(',             # .transfer(...)
        r'\.delegatecall\s*\(',         # delegatecall
        r'\.staticcall\s*\(',           # staticcall
    ]

    # State change patterns (after external call = vulnerability)
    STATE_CHANGE_PATTERNS = [
        r'[\w\[\]\.\(\)]+\s*=\s*[^=]',  # Assignment (including arrays/mappings)
        r'[\w\[\]\.\(\)]+\s*\+=',        # +=
        r'[\w\[\]\.\(\)]+\s*-=',         # -=
        r'[\w\[\]\.\(\)]+\s*\+\+',       # ++
        r'[\w\[\]\.\(\)]+\s*--',         # --
        r'delete\s+[\w\[\]\.\(\)]+',     # delete
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[SmartBugsFinding]:
        findings = []
        lines = source_code.split('\n')

        # Check for ReentrancyGuard
        has_guard = re.search(r'nonReentrant|ReentrancyGuard|_locked|mutex', source_code, re.I)
        if has_guard:
            return findings

        # Find functions with external calls
        in_function = False
        function_body_started = False
        function_start = 0
        function_lines = []
        brace_count = 0

        for i, line in enumerate(lines, 1):
            # Track function boundaries
            if re.search(r'function\s+\w+', line):
                in_function = True
                function_body_started = False
                function_start = i
                function_lines = []
                brace_count = 0

            if in_function:
                open_braces = line.count('{')
                close_braces = line.count('}')

                if open_braces > 0:
                    function_body_started = True

                brace_count += open_braces - close_braces
                function_lines.append((i, line))

                # Only end function after body started and braces balanced
                if function_body_started and brace_count == 0:
                    # End of function - analyze
                    self._analyze_function(function_lines, findings)
                    in_function = False
                    function_body_started = False

        return findings

    def _analyze_function(self, function_lines: List, findings: List):
        """Analyze a function for reentrancy patterns."""
        external_call_line = None
        external_call_code = None

        for line_num, line in function_lines:
            # Skip comments
            if line.strip().startswith('//') or line.strip().startswith('*'):
                continue

            # Look for external calls
            for pattern in self.EXTERNAL_CALL_PATTERNS:
                if re.search(pattern, line):
                    external_call_line = line_num
                    external_call_code = line.strip()
                    break

            # If we found an external call, look for state changes after it
            if external_call_line and line_num > external_call_line:
                for pattern in self.STATE_CHANGE_PATTERNS:
                    if re.search(pattern, line):
                        # Skip require/assert
                        if 'require' in line or 'assert' in line:
                            continue
                        # Skip return statements
                        if re.match(r'\s*return\s+', line):
                            continue

                        findings.append(SmartBugsFinding(
                            title="Reentrancy Vulnerability",
                            description=f"State change after external call. External call at line {external_call_line}, "
                                       f"state change at line {line_num}. Use checks-effects-interactions pattern.",
                            severity=Severity.HIGH,
                            category=self.category,
                            line=external_call_line,
                            code_snippet=external_call_code,
                            swc_id=self.swc_id,
                            confidence="high"
                        ))
                        return  # One finding per function


# =============================================================================
# ACCESS CONTROL DETECTOR
# =============================================================================

class AccessControlDetector:
    """
    Detects access control vulnerabilities.

    SWC-105: Unprotected Ether Withdrawal
    SWC-106: Unprotected SELFDESTRUCT
    """

    name = "access-control-detector"
    category = "access_control"
    swc_id = "SWC-105"

    # Critical functions that need access control
    CRITICAL_FUNCTIONS = [
        (r'function\s+withdraw', 'withdraw', "Unprotected withdrawal function"),
        (r'function\s+transfer\s*\([^)]*\)\s*(?:external|public)', 'transfer', "Unprotected transfer function"),
        (r'function\s+setOwner', 'setOwner', "Unprotected setOwner function"),
        (r'function\s+changeOwner', 'changeOwner', "Unprotected owner change function"),
        (r'function\s+kill', 'kill', "Unprotected kill function"),
        (r'function\s+destroy', 'destroy', "Unprotected destroy function"),
        (r'selfdestruct\s*\(', 'selfdestruct', "Unprotected selfdestruct"),
        (r'suicide\s*\(', 'suicide', "Unprotected suicide (deprecated selfdestruct)"),
    ]

    # Access control modifiers/patterns
    ACCESS_CONTROL_PATTERNS = [
        r'onlyOwner',
        r'onlyAdmin',
        r'onlyRole',
        r'require\s*\(\s*msg\.sender\s*==\s*owner',
        r'require\s*\(\s*owner\s*==\s*msg\.sender',
        r'require\s*\(\s*msg\.sender\s*==\s*admin',
        r'require\s*\(\s*isOwner\[msg\.sender\]',
        r'modifier\s+only',
        r'internal\b',  # internal functions are protected
        r'private\b',   # private functions are protected
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[SmartBugsFinding]:
        findings = []
        lines = source_code.split('\n')

        # Check each critical function
        for pattern, func_name, desc in self.CRITICAL_FUNCTIONS:
            matches = list(re.finditer(pattern, source_code, re.I))

            for match in matches:
                # Get line number
                line_num = source_code[:match.start()].count('\n') + 1

                # Get the function context (next 10 lines)
                start_idx = match.start()
                end_idx = min(len(source_code), start_idx + 500)
                context = source_code[start_idx:end_idx]

                # Check if protected
                is_protected = any(re.search(p, context, re.I) for p in self.ACCESS_CONTROL_PATTERNS)

                if not is_protected:
                    findings.append(SmartBugsFinding(
                        title="Missing Access Control",
                        description=f"{desc}. Function '{func_name}' at line {line_num} has no access control.",
                        severity=Severity.HIGH if func_name in ['withdraw', 'selfdestruct', 'suicide'] else Severity.MEDIUM,
                        category=self.category,
                        line=line_num,
                        code_snippet=lines[line_num-1].strip() if line_num <= len(lines) else "",
                        swc_id="SWC-106" if func_name in ['selfdestruct', 'suicide', 'kill', 'destroy'] else "SWC-105",
                        confidence="high"
                    ))

        # Check for tx.origin authentication (always bad)
        tx_origin_matches = re.finditer(r'require\s*\([^)]*tx\.origin', source_code)
        for match in tx_origin_matches:
            line_num = source_code[:match.start()].count('\n') + 1
            findings.append(SmartBugsFinding(
                title="tx.origin Authentication",
                description=f"Using tx.origin for authentication at line {line_num}. Use msg.sender instead.",
                severity=Severity.HIGH,
                category=self.category,
                line=line_num,
                code_snippet=lines[line_num-1].strip() if line_num <= len(lines) else "",
                swc_id="SWC-115",
                confidence="high"
            ))

        return findings


# =============================================================================
# UNCHECKED LOW LEVEL CALLS DETECTOR
# =============================================================================

class UncheckedLowLevelCallsDetector:
    """
    Detects unchecked low-level call return values.

    SWC-104: Unchecked Call Return Value
    """

    name = "unchecked-calls-detector"
    category = "unchecked_low_level_calls"
    swc_id = "SWC-104"

    # Low level call patterns
    LOW_LEVEL_CALLS = [
        (r'\.call\s*\{?[^}]*\}?\s*\([^)]*\)', 'call'),
        (r'\.send\s*\([^)]*\)', 'send'),
        (r'\.delegatecall\s*\([^)]*\)', 'delegatecall'),
        (r'\.staticcall\s*\([^)]*\)', 'staticcall'),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[SmartBugsFinding]:
        findings = []
        lines = source_code.split('\n')

        for i, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('//') or line.strip().startswith('*'):
                continue

            for pattern, call_type in self.LOW_LEVEL_CALLS:
                if re.search(pattern, line):
                    # Check if return value is checked
                    is_checked = self._is_return_checked(line, lines, i)

                    if not is_checked:
                        findings.append(SmartBugsFinding(
                            title="Unchecked Low-Level Call",
                            description=f"Return value of {call_type}() not checked at line {i}. "
                                       "Always verify the success of low-level calls.",
                            severity=Severity.MEDIUM,
                            category=self.category,
                            line=i,
                            code_snippet=line.strip(),
                            swc_id=self.swc_id,
                            confidence="high"
                        ))
                    break

        return findings

    def _is_return_checked(self, line: str, all_lines: List[str], line_num: int) -> bool:
        """Check if the return value is being checked."""
        # Check for assignment with bool
        if re.search(r'\(\s*bool\s+\w+\s*,', line):
            # Check next few lines for require
            for j in range(line_num, min(line_num + 3, len(all_lines))):
                if 'require' in all_lines[j] or 'if' in all_lines[j]:
                    return True

        # Check for direct require
        if 'require' in line:
            return True

        # Check for if statement
        if re.search(r'if\s*\([^)]*\.(?:call|send)', line):
            return True

        # Check for assignment to success variable
        if re.search(r'(?:success|ok|result)\s*=.*\.(?:call|send)', line, re.I):
            # Check next lines for require/if
            for j in range(line_num, min(line_num + 3, len(all_lines))):
                if re.search(r'require\s*\(\s*(?:success|ok|result)', all_lines[j], re.I):
                    return True
                if re.search(r'if\s*\(\s*(?:!)?(?:success|ok|result)', all_lines[j], re.I):
                    return True

        return False


# =============================================================================
# TIME MANIPULATION DETECTOR
# =============================================================================

class TimeManipulationDetector:
    """
    Detects timestamp/block number dependency vulnerabilities.

    SWC-116: Block values as a proxy for time
    """

    name = "time-manipulation-detector"
    category = "time_manipulation"
    swc_id = "SWC-116"

    TIME_PATTERNS = [
        (r'block\.timestamp', "block.timestamp", "Block timestamp can be manipulated by miners"),
        (r'block\.number', "block.number", "Block number is predictable"),
        (r'now\b', "now (alias for block.timestamp)", "Using 'now' which is alias for block.timestamp"),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[SmartBugsFinding]:
        findings = []
        lines = source_code.split('\n')
        reported = set()

        for i, line in enumerate(lines, 1):
            if i in reported:
                continue

            # Skip comments
            if line.strip().startswith('//') or line.strip().startswith('*'):
                continue

            for pattern, name, desc in self.TIME_PATTERNS:
                if re.search(pattern, line):
                    # Check if used in critical context
                    critical_context = self._is_critical_context(line, source_code, i)

                    if critical_context:
                        findings.append(SmartBugsFinding(
                            title="Timestamp Dependency",
                            description=f"Using {name} in {critical_context} at line {i}. {desc}.",
                            severity=Severity.MEDIUM,
                            category=self.category,
                            line=i,
                            code_snippet=line.strip(),
                            swc_id=self.swc_id,
                            confidence="medium"
                        ))
                        reported.add(i)
                        break

        return findings

    def _is_critical_context(self, line: str, source: str, line_num: int) -> Optional[str]:
        """Check if timestamp is used in a critical context."""
        line_lower = line.lower()

        # Randomness generation
        if 'keccak256' in line_lower or 'random' in line_lower:
            return "randomness generation"

        # Conditionals
        if re.search(r'if\s*\([^)]*block\.(timestamp|number)', line) or re.search(r'if\s*\([^)]*now', line):
            return "conditional logic"

        # Require statements
        if 'require' in line_lower:
            return "require condition"

        # Winner selection
        if 'winner' in line_lower or 'prize' in line_lower:
            return "winner selection"

        # Lottery/gambling
        if 'lottery' in source.lower() or 'gambl' in source.lower():
            if re.search(r'block\.(timestamp|number)|now', line):
                return "gambling logic"

        # Time locks
        if 'lock' in line_lower or 'unlock' in line_lower:
            return "time lock"

        return None


# =============================================================================
# SMARTBUGS DETECTOR ENGINE
# =============================================================================

class SmartBugsDetectorEngine:
    """Engine to run all SmartBugs-specific detectors."""

    def __init__(self):
        self.detectors = [
            ArithmeticDetector(),
            BadRandomnessDetector(),
            DenialOfServiceDetector(),
            FrontRunningDetector(),
            ShortAddressDetector(),
            ReentrancyDetector(),
            AccessControlDetector(),
            UncheckedLowLevelCallsDetector(),
            TimeManipulationDetector(),
        ]

    def analyze(self, source_code: str, file_path: Optional[Path] = None) -> List[SmartBugsFinding]:
        """Run all detectors on source code."""
        all_findings = []
        for detector in self.detectors:
            findings = detector.detect(source_code, file_path)
            all_findings.extend(findings)
        return all_findings

    def analyze_file(self, file_path: Path) -> List[SmartBugsFinding]:
        """Analyze a Solidity file."""
        with open(file_path, 'r') as f:
            source_code = f.read()
        return self.analyze(source_code, file_path)

    def get_summary(self, findings: List[SmartBugsFinding]) -> Dict:
        """Generate summary statistics."""
        summary = {
            'total': len(findings),
            'by_severity': {},
            'by_category': {},
        }

        for finding in findings:
            sev = finding.severity.value
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1

            cat = finding.category
            summary['by_category'][cat] = summary['by_category'].get(cat, 0) + 1

        return summary


def main():
    """Test with SmartBugs samples."""
    from pathlib import Path

    engine = SmartBugsDetectorEngine()

    # Test contracts
    test_files = [
        ("arithmetic", '''
        pragma solidity ^0.4.24;
        contract Overflow {
            uint256 public count;
            function add(uint256 value) public {
                count = count + value;  // Overflow!
            }
            function sub(uint256 value) public {
                count -= value;  // Underflow!
            }
        }
        '''),
        ("bad_randomness", '''
        pragma solidity ^0.4.24;
        contract Lottery {
            function random() public view returns (uint) {
                return uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
            }
            function pickWinner() public {
                uint winner = random() % players.length;
            }
        }
        '''),
        ("denial_of_service", '''
        pragma solidity ^0.4.24;
        contract Vulnerable {
            address[] public investors;
            function refundAll() public {
                for (uint i = 0; i < investors.length; i++) {
                    investors[i].transfer(balances[investors[i]]);
                }
            }
        }
        '''),
    ]

    print("\n" + "="*60)
    print("  MIESC SmartBugs-Specific Detectors")
    print("="*60)

    for category, code in test_files:
        findings = engine.analyze(code)
        print(f"\n[{category}] Findings: {len(findings)}")
        for f in findings:
            print(f"  - [{f.severity.value}] {f.title}")
            if f.line:
                print(f"    Line {f.line}: {f.code_snippet}")

    summary = engine.get_summary(engine.analyze(test_files[0][1] + test_files[1][1] + test_files[2][1]))
    print("\n" + "-"*60)
    print(f"Total: {summary['total']}")
    print(f"By Category: {summary['by_category']}")


if __name__ == "__main__":
    main()
