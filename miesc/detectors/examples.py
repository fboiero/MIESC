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


# =============================================================================
# DeFi-Specific Vulnerability Detectors
# =============================================================================


@register_detector
class SlippageProtectionDetector(BaseDetector):
    """
    Detect missing slippage protection in DeFi swaps.

    Checks for:
    - Swap calls without minAmountOut parameter
    - Hardcoded 0 as minimum output
    - Missing deadline parameters
    """

    name = "slippage-protection"
    description = "Detects missing slippage protection in token swaps"
    category = "defi"
    severity_default = Severity.HIGH
    version = "1.0.0"
    author = "MIESC Team"
    references = [
        "https://dacian.me/defi-slippage-attacks",
        "https://defihacklabs.substack.com/p/slippage-attacks",
    ]

    SWAP_PATTERNS = [
        r"swap\w*\s*\(",
        r"exchange\s*\(",
        r"swapExact\w+\s*\(",
        r"\.swap\s*\(",
    ]

    PROTECTION_PATTERNS = [
        r"minAmount",
        r"amountOutMin",
        r"minReturn",
        r"slippage",
        r"deadline",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            for pattern in self.SWAP_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check surrounding context for protection
                    ctx_start = max(0, i - 5)
                    ctx_end = min(len(lines), i + 5)
                    context = "\n".join(lines[ctx_start:ctx_end])

                    has_protection = any(
                        re.search(p, context, re.IGNORECASE)
                        for p in self.PROTECTION_PATTERNS
                    )

                    # Check for hardcoded 0 as min amount
                    has_zero_min = re.search(r",\s*0\s*[,)]", line)

                    if not has_protection or has_zero_min:
                        desc = (
                            "Token swap without proper slippage protection. "
                            "Users may receive less tokens than expected."
                        )
                        rec = (
                            "Add minAmountOut parameter calculated from expected "
                            "output with acceptable slippage tolerance (e.g., 0.5-1%)."
                        )
                        findings.append(
                            self.create_finding(
                                title="Missing Slippage Protection",
                                description=desc,
                                line=i,
                                file_path=file_path or "",
                                recommendation=rec,
                            )
                        )
                        break

        return findings


@register_detector
class RugPullDetector(BaseDetector):
    """
    Detect common rug pull patterns in token contracts.

    Checks for:
    - Owner can disable trading/transfers
    - Unlimited minting by owner
    - Hidden fee mechanisms
    - Blacklist functions without transparency
    """

    name = "rug-pull-patterns"
    description = "Detects potential rug pull patterns in token contracts"
    category = "defi"
    severity_default = Severity.CRITICAL
    version = "1.0.0"
    author = "MIESC Team"
    references = [
        "https://rugdoc.io/education/",
        "https://www.certik.com/resources/blog/rug-pull-warning-signs",
    ]

    RUG_PATTERNS = [
        (r"function\s+disableTrading", "Trading can be disabled by owner"),
        (r"function\s+pauseTrading", "Trading can be paused by owner"),
        (r"function\s+setTradingEnabled", "Trading can be controlled by owner"),
        (r"function\s+blacklist", "Blacklist function can block users"),
        (r"function\s+addToBlacklist", "Blacklist function can block users"),
        (r"_isExcludedFromFee\[", "Hidden fee exclusion mechanism"),
        (r"function\s+setFee.*100", "Fees can be set to 100%"),
        (r"function\s+setMaxTx.*0", "MaxTx can be set to 0, blocking trades"),
        (r"maxWallet\s*=\s*0", "MaxWallet set to 0 blocks holding"),
        (r"require\s*\(\s*!isBot", "Hidden bot protection can block users"),
    ]

    MINT_PATTERNS = [
        r"function\s+mint\s*\([^)]*\)\s*(public|external)",
        r"_mint\s*\(\s*\w+\s*,",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for rug pull patterns
            for pattern, desc_suffix in self.RUG_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        self.create_finding(
                            title="Potential Rug Pull Pattern",
                            description=f"Suspicious pattern detected: {desc_suffix}",
                            line=i,
                            file_path=file_path or "",
                            severity=Severity.HIGH,
                            recommendation="Review this function for potential abuse.",
                        )
                    )

            # Check for unlimited minting
            for pattern in self.MINT_PATTERNS:
                if re.search(pattern, line):
                    # Check if there's a cap
                    ctx_start = max(0, i - 10)
                    ctx_end = min(len(lines), i + 10)
                    context = "\n".join(lines[ctx_start:ctx_end])

                    has_cap = re.search(
                        r"maxSupply|MAX_SUPPLY|totalSupply\s*<|cap", context
                    )
                    if not has_cap:
                        findings.append(
                            self.create_finding(
                                title="Unlimited Token Minting",
                                description="Mint function without supply cap.",
                                line=i,
                                file_path=file_path or "",
                                severity=Severity.CRITICAL,
                                recommendation="Add a maximum supply cap to prevent "
                                "infinite minting and token devaluation.",
                            )
                        )

        return findings


@register_detector
class TimestampDependenceDetector(BaseDetector):
    """
    Detect dangerous reliance on block.timestamp.

    Miners can manipulate block.timestamp within ~15 seconds,
    which can affect time-sensitive logic.
    """

    name = "timestamp-dependence"
    description = "Detects dangerous reliance on block.timestamp"
    category = "security"
    severity_default = Severity.MEDIUM
    version = "1.0.0"
    references = [
        "https://swcregistry.io/docs/SWC-116",
        "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/timestamp-dependence/",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for timestamp usage in comparisons
            if re.search(r"block\.timestamp", line):
                # Check if used in critical comparisons
                critical_patterns = [
                    r"block\.timestamp\s*[<>=]",
                    r"[<>=]\s*block\.timestamp",
                    r"require.*block\.timestamp",
                    r"if\s*\(.*block\.timestamp",
                ]

                for pattern in critical_patterns:
                    if re.search(pattern, line):
                        # Check if it's for deadline (acceptable use)
                        if re.search(r"deadline|expir", line, re.IGNORECASE):
                            continue

                        desc = (
                            "block.timestamp used in critical logic. "
                            "Miners can manipulate timestamp by ~15 seconds."
                        )
                        findings.append(
                            self.create_finding(
                                title="Timestamp Dependence",
                                description=desc,
                                line=i,
                                file_path=file_path or "",
                                recommendation="Avoid using block.timestamp for "
                                "critical comparisons. Use block.number or "
                                "commit-reveal schemes for randomness.",
                            )
                        )
                        break

            # Check for now keyword (alias for block.timestamp)
            if re.search(r"\bnow\b", line):
                if re.search(r"now\s*[<>=]|[<>=]\s*now|require.*now", line):
                    findings.append(
                        self.create_finding(
                            title="Timestamp Dependence (now)",
                            description="'now' (block.timestamp) used in comparison.",
                            line=i,
                            file_path=file_path or "",
                            severity=Severity.LOW,
                            recommendation="Use block.number for time-based logic.",
                        )
                    )

        return findings


@register_detector
class ApprovalRaceDetector(BaseDetector):
    """
    Detect ERC20 approval race condition vulnerability.

    The approve() function is vulnerable to front-running attacks
    when changing allowance from non-zero to non-zero.
    """

    name = "approval-race"
    description = "Detects ERC20 approval race condition patterns"
    category = "defi"
    severity_default = Severity.MEDIUM
    version = "1.0.0"
    references = [
        "https://swcregistry.io/docs/SWC-114",
        "https://docs.google.com/document/d/1YLPtQxZu1UAvO9cZ1O2RPXBbT0mooh4DYKjA_jp-RLM/",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        has_approve = False
        has_safe_approve = False

        for i, line in enumerate(lines, 1):
            # Check for standard approve
            if re.search(r"\.approve\s*\(", line):
                has_approve = True

                # Check if it's setting to 0 first (safe pattern)
                ctx_start = max(0, i - 3)
                context = "\n".join(lines[ctx_start:i])
                if re.search(r"\.approve\s*\([^,]+,\s*0\s*\)", context):
                    continue

                findings.append(
                    self.create_finding(
                        title="ERC20 Approval Race Condition",
                        description="Direct approve() call may be vulnerable to "
                        "front-running when changing allowance.",
                        line=i,
                        file_path=file_path or "",
                        recommendation="Use increaseAllowance/decreaseAllowance "
                        "or set approval to 0 before setting new value.",
                    )
                )

            # Check for safe alternatives
            if re.search(r"increaseAllowance|decreaseAllowance|safeApprove", line):
                has_safe_approve = True

        return findings


@register_detector
class UnboundedLoopDetector(BaseDetector):
    """
    Detect unbounded loops that could cause DoS.

    Loops over dynamic arrays without bounds can exceed
    the block gas limit, causing transactions to fail.
    """

    name = "unbounded-loop"
    description = "Detects unbounded loops that could cause DoS"
    category = "security"
    severity_default = Severity.MEDIUM
    version = "1.0.0"
    references = [
        "https://swcregistry.io/docs/SWC-128",
        "https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for loops over arrays
            loop_patterns = [
                r"for\s*\([^;]+;\s*\w+\s*<\s*(\w+)\.length",
                r"for\s*\([^;]+;\s*\w+\s*<\s*(\w+)\s*;",
                r"while\s*\(\s*\w+\s*<\s*(\w+)\.length",
            ]

            for pattern in loop_patterns:
                match = re.search(pattern, line)
                if match:
                    array_name = match.group(1)

                    # Check if there's a limit
                    ctx_start = max(0, i - 10)
                    ctx_end = min(len(lines), i + 5)
                    context = "\n".join(lines[ctx_start:ctx_end])

                    has_limit = re.search(
                        r"require.*length\s*[<]|maxLength|MAX_|limit",
                        context,
                        re.IGNORECASE,
                    )

                    if not has_limit:
                        desc = (
                            f"Loop over '{array_name}' without bounds check. "
                            f"Could exceed gas limit with large arrays."
                        )
                        findings.append(
                            self.create_finding(
                                title="Unbounded Loop - Potential DoS",
                                description=desc,
                                line=i,
                                file_path=file_path or "",
                                recommendation="Add a maximum iteration limit or "
                                "use pagination for large arrays.",
                            )
                        )
                        break

        return findings


@register_detector
class HardcodedAddressDetector(BaseDetector):
    """
    Detect hardcoded addresses that reduce flexibility.

    Hardcoded addresses make contracts inflexible and may
    point to incorrect addresses on different networks.
    """

    name = "hardcoded-address"
    description = "Detects hardcoded Ethereum addresses"
    category = "security"
    severity_default = Severity.LOW
    version = "1.0.0"
    references = [
        "https://swcregistry.io/docs/SWC-125",
    ]

    # Known safe addresses (can be hardcoded)
    SAFE_ADDRESSES = [
        "0x0000000000000000000000000000000000000000",  # Zero address
        "0x000000000000000000000000000000000000dEaD",  # Dead address
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            # Find Ethereum addresses (0x followed by 40 hex chars)
            addresses = re.findall(r"0x[a-fA-F0-9]{40}", line)

            for addr in addresses:
                # Skip safe addresses
                if addr.lower() in [a.lower() for a in self.SAFE_ADDRESSES]:
                    continue

                # Skip if it's in a comment
                if re.search(r"//.*" + addr, line) or re.search(r"/\*.*" + addr, line):
                    continue

                # Check if it's a constant (acceptable)
                if re.search(r"constant.*" + addr, line, re.IGNORECASE):
                    findings.append(
                        self.create_finding(
                            title="Hardcoded Address",
                            description=f"Hardcoded address {addr[:10]}...{addr[-4:]} "
                            f"may cause issues across different networks.",
                            line=i,
                            file_path=file_path or "",
                            severity=Severity.INFO,
                            recommendation="Consider using constructor parameters "
                            "or configuration for network-specific addresses.",
                        )
                    )
                else:
                    findings.append(
                        self.create_finding(
                            title="Hardcoded Address",
                            description=f"Non-constant hardcoded address detected.",
                            line=i,
                            file_path=file_path or "",
                            recommendation="Use immutable variables set in "
                            "constructor for flexibility across networks.",
                        )
                    )

        return findings


@register_detector
class MEVVulnerabilityDetector(BaseDetector):
    """
    Detect patterns vulnerable to MEV extraction.

    Checks for:
    - Large swaps without private mempool
    - Liquidation calls without protection
    - Arbitrage-susceptible patterns
    """

    name = "mev-vulnerability"
    description = "Detects patterns vulnerable to MEV extraction"
    category = "defi"
    severity_default = Severity.MEDIUM
    version = "1.0.0"
    author = "MIESC Team"
    references = [
        "https://ethereum.org/en/developers/docs/mev/",
        "https://www.flashbots.net/",
    ]

    MEV_PATTERNS = [
        (r"liquidate\s*\(", "Liquidation call vulnerable to MEV"),
        (r"flashLoan\s*\(", "Flash loan callback may be sandwiched"),
        (r"arbitrage", "Arbitrage function exposed to MEV"),
        (r"getAmountsOut.*swap", "Price check before swap is sandwichable"),
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            for pattern, desc in self.MEV_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check for MEV protection
                    ctx_start = max(0, i - 10)
                    ctx_end = min(len(lines), i + 10)
                    context = "\n".join(lines[ctx_start:ctx_end])

                    has_protection = re.search(
                        r"flashbots|private.*mempool|commit.*reveal|deadline",
                        context,
                        re.IGNORECASE,
                    )

                    if not has_protection:
                        findings.append(
                            self.create_finding(
                                title="MEV Vulnerability",
                                description=desc + ". Transaction may be "
                                "front-run or sandwiched.",
                                line=i,
                                file_path=file_path or "",
                                recommendation="Consider using Flashbots, "
                                "private mempools, or commit-reveal schemes.",
                            )
                        )
                        break

        return findings


@register_detector
class DelegateCallDetector(BaseDetector):
    """
    Detect dangerous delegatecall usage.

    delegatecall preserves msg.sender and msg.value,
    which can lead to unexpected behavior if misused.
    """

    name = "delegatecall-danger"
    description = "Detects dangerous delegatecall patterns"
    category = "security"
    severity_default = Severity.HIGH
    version = "1.0.0"
    references = [
        "https://swcregistry.io/docs/SWC-112",
        "https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack-405a8c12e8f7/",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            if re.search(r"\.delegatecall\s*\(", line):
                # Check if target is user-controlled
                ctx_start = max(0, i - 15)
                context = "\n".join(lines[ctx_start:i])

                # Check for input validation
                has_validation = re.search(
                    r"require.*address|whitelist|allowed|trusted", context, re.IGNORECASE
                )

                if not has_validation:
                    findings.append(
                        self.create_finding(
                            title="Dangerous delegatecall",
                            description="delegatecall to potentially untrusted "
                            "address. Attacker could execute malicious code.",
                            line=i,
                            file_path=file_path or "",
                            severity=Severity.CRITICAL,
                            recommendation="Validate delegatecall targets against "
                            "a whitelist. Never delegatecall to user input.",
                        )
                    )
                else:
                    findings.append(
                        self.create_finding(
                            title="delegatecall Usage",
                            description="delegatecall detected. Ensure target "
                            "contract is thoroughly audited.",
                            line=i,
                            file_path=file_path or "",
                            severity=Severity.MEDIUM,
                            recommendation="Audit the target contract and ensure "
                            "storage layout compatibility.",
                        )
                    )

        return findings


@register_detector
class SelfdestructDetector(BaseDetector):
    """
    Detect selfdestruct usage which can be dangerous.

    selfdestruct permanently destroys a contract and sends
    remaining ETH to the target address.
    """

    name = "selfdestruct-usage"
    description = "Detects selfdestruct usage in contracts"
    category = "security"
    severity_default = Severity.HIGH
    version = "1.0.0"
    references = [
        "https://swcregistry.io/docs/SWC-106",
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            if re.search(r"selfdestruct\s*\(|suicide\s*\(", line):
                # Check for access control
                ctx_start = max(0, i - 10)
                context = "\n".join(lines[ctx_start:i])

                has_protection = re.search(
                    r"onlyOwner|require.*msg\.sender|onlyAdmin", context
                )

                if not has_protection:
                    findings.append(
                        self.create_finding(
                            title="Unprotected selfdestruct",
                            description="selfdestruct without access control. "
                            "Anyone could destroy this contract.",
                            line=i,
                            file_path=file_path or "",
                            severity=Severity.CRITICAL,
                            recommendation="Add strict access control or "
                            "remove selfdestruct entirely.",
                        )
                    )
                else:
                    findings.append(
                        self.create_finding(
                            title="selfdestruct Present",
                            description="Contract contains selfdestruct. "
                            "This permanently destroys the contract.",
                            line=i,
                            file_path=file_path or "",
                            severity=Severity.MEDIUM,
                            recommendation="Consider if selfdestruct is necessary. "
                            "It can disrupt dependent contracts.",
                        )
                    )

        return findings


@register_detector
class WeakRandomnessDetector(BaseDetector):
    """
    Detect weak sources of randomness.

    On-chain randomness using blockhash, timestamp, or other
    predictable values can be manipulated by miners.
    """

    name = "weak-randomness"
    description = "Detects weak randomness sources"
    category = "security"
    severity_default = Severity.HIGH
    version = "1.0.0"
    references = [
        "https://swcregistry.io/docs/SWC-120",
    ]

    WEAK_SOURCES = [
        (r"blockhash\s*\(", "blockhash is predictable"),
        (r"block\.difficulty", "block.difficulty is predictable"),
        (r"block\.timestamp.*random", "timestamp for randomness is manipulable"),
        (r"block\.number.*random", "block.number for randomness is predictable"),
        (r"keccak256.*block\.", "Hashing block variables is not secure randomness"),
    ]

    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        findings = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            for pattern, desc in self.WEAK_SOURCES:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check for VRF or Chainlink
                    ctx_start = max(0, i - 20)
                    ctx_end = min(len(lines), i + 20)
                    context = "\n".join(lines[ctx_start:ctx_end])

                    has_vrf = re.search(
                        r"VRF|chainlink|randomness.*oracle|commit.*reveal",
                        context,
                        re.IGNORECASE,
                    )

                    if not has_vrf:
                        findings.append(
                            self.create_finding(
                                title="Weak Randomness Source",
                                description=f"Weak randomness: {desc}. "
                                "Miners can manipulate this value.",
                                line=i,
                                file_path=file_path or "",
                                recommendation="Use Chainlink VRF or commit-reveal "
                                "scheme for secure randomness.",
                            )
                        )
                        break

        return findings


# List all example detectors for documentation
EXAMPLE_DETECTORS = [
    # Security detectors
    FlashLoanDetector,
    ReentrancyPatternDetector,
    AccessControlDetector,
    TxOriginDetector,
    UncheckedReturnDetector,
    # DeFi-specific detectors
    SlippageProtectionDetector,
    RugPullDetector,
    TimestampDependenceDetector,
    ApprovalRaceDetector,
    UnboundedLoopDetector,
    HardcodedAddressDetector,
    MEVVulnerabilityDetector,
    DelegateCallDetector,
    SelfdestructDetector,
    WeakRandomnessDetector,
]
