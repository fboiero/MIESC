#!/usr/bin/env python3
"""
MIESC v4.1 - DeFi Vulnerability Detectors

Specialized detectors for modern DeFi attack patterns:
- Flash loan attacks
- Oracle manipulation
- Price manipulation
- Sandwich attacks
- MEV exposure

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class DeFiCategory(Enum):
    FLASH_LOAN = "flash_loan"
    ORACLE_MANIPULATION = "oracle_manipulation"
    PRICE_MANIPULATION = "price_manipulation"
    SANDWICH_ATTACK = "sandwich_attack"
    MEV_EXPOSURE = "mev_exposure"
    SLIPPAGE = "slippage"
    LIQUIDITY = "liquidity"
    ROUNDING = "rounding"
    FEE_ON_TRANSFER = "fee_on_transfer"
    ERC4626 = "erc4626"
    BUSINESS_LOGIC = "business_logic"


@dataclass
class DeFiFinding:
    """Represents a DeFi vulnerability finding."""

    title: str
    description: str
    severity: Severity
    category: DeFiCategory
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    confidence: str = "high"


class DeFiDetector(ABC):
    """Base class for DeFi vulnerability detectors."""

    name: str = "base"
    description: str = ""
    category: DeFiCategory = DeFiCategory.FLASH_LOAN

    @abstractmethod
    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        """Detect vulnerabilities in source code."""
        pass  # pragma: no cover - abstract base method


class FlashLoanDetector(DeFiDetector):
    """
    Detects flash loan vulnerability patterns.

    Flash loans allow attackers to borrow large amounts without collateral
    and exploit price differences or vulnerabilities in a single transaction.

    Patterns detected:
    - Callback functions without proper validation
    - Single-transaction price manipulation
    - Unchecked loan repayment
    """

    name = "flash-loan-detector"
    description = "Detects flash loan attack vulnerabilities"
    category = DeFiCategory.FLASH_LOAN

    # Flash loan callback patterns
    CALLBACK_PATTERNS = [
        r"function\s+(executeOperation|onFlashLoan|flashLoanCallback|uniswapV2Call|pancakeCall)\s*\(",
        r"IFlashLoan\w*\.flash",
        r"IERC3156FlashBorrower",
        r"flashLoan\s*\(",
    ]

    # Dangerous patterns in flash loan callbacks
    DANGER_PATTERNS = [
        (r"\.swap\(", "Swap operation in flash loan context - potential price manipulation"),
        (r"\.getReserves\(\)", "Reading reserves without validation - oracle manipulation risk"),
        (r"balanceOf\([^)]*\)\s*[<>=]", "Balance comparison - potential flash loan bypass"),
        (r"totalSupply\(\)", "Total supply check - may be manipulated via flash mint"),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings: List[DeFiFinding] = []
        lines = source_code.split("\n")

        # Check for flash loan interfaces
        has_flash_loan = any(
            re.search(pattern, source_code, re.IGNORECASE) for pattern in self.CALLBACK_PATTERNS
        )

        if has_flash_loan:
            # Check for dangerous patterns within flash loan context
            for i, line in enumerate(lines, 1):
                for pattern, description in self.DANGER_PATTERNS:
                    if re.search(pattern, line):
                        findings.append(
                            DeFiFinding(
                                title="Flash Loan Attack Vector",
                                description=f"{description}. Found at line {i}.",
                                severity=Severity.HIGH,
                                category=self.category,
                                line=i,
                                code_snippet=line.strip(),
                                recommendation="Implement checks-effects-interactions pattern. "
                                "Validate state before and after flash loan execution.",
                                references=[
                                    "https://www.paradigm.xyz/2020/11/so-you-want-to-use-a-flash-loan",
                                    "SWC-136: Unencrypted Private Data On-Chain",
                                ],
                            )
                        )

            # Check for missing repayment validation
            if not re.search(
                r"require\s*\([^)]*repay|assert\s*\([^)]*return", source_code, re.IGNORECASE
            ):
                findings.append(
                    DeFiFinding(
                        title="Missing Flash Loan Repayment Validation",
                        description="Flash loan callback does not explicitly validate loan repayment.",
                        severity=Severity.CRITICAL,
                        category=self.category,
                        recommendation="Add explicit repayment validation and ensure atomicity.",
                        references=["https://eips.ethereum.org/EIPS/eip-3156"],
                    )
                )

        return findings


class OracleManipulationDetector(DeFiDetector):
    """
    Detects oracle manipulation vulnerabilities.

    Patterns detected:
    - Direct spot price usage without TWAP
    - Single-source price feeds
    - Missing staleness checks
    - Chainlink feed issues
    """

    name = "oracle-manipulation-detector"
    description = "Detects price oracle manipulation vulnerabilities"
    category = DeFiCategory.ORACLE_MANIPULATION

    # Oracle patterns
    ORACLE_PATTERNS = {
        "spot_price": [
            r"getReserves\s*\(\)",
            r"slot0\s*\(\)",
            r"\.price\d*\(\)",
            r"getAmountOut\s*\(",
        ],
        "chainlink": [
            r"latestRoundData\s*\(\)",
            r"AggregatorV\d*Interface",
            r"\.answer\b",
        ],
        "uniswap_twap": [
            r"observe\s*\(",
            r"consult\s*\(",
            r"TWAP",
        ],
    }

    STALENESS_CHECK = r"(updatedAt|timestamp|roundId)\s*[<>=!]"
    DEVIATION_CHECK = r"(deviation|delta|diff)\s*[<>=]"

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings: List[DeFiFinding] = []
        lines = source_code.split("\n")

        # Check for spot price usage
        uses_spot_price = any(
            re.search(pattern, source_code) for pattern in self.ORACLE_PATTERNS["spot_price"]
        )

        uses_twap = any(
            re.search(pattern, source_code) for pattern in self.ORACLE_PATTERNS["uniswap_twap"]
        )

        if uses_spot_price and not uses_twap:
            for i, line in enumerate(lines, 1):
                for pattern in self.ORACLE_PATTERNS["spot_price"]:
                    if re.search(pattern, line):
                        findings.append(
                            DeFiFinding(
                                title="Spot Price Oracle Manipulation Risk",
                                description=f"Using spot price without TWAP protection at line {i}. "
                                "Spot prices can be manipulated within a single block.",
                                severity=Severity.HIGH,
                                category=self.category,
                                line=i,
                                code_snippet=line.strip(),
                                recommendation="Use Time-Weighted Average Price (TWAP) instead of spot prices. "
                                "Consider Uniswap V3 oracle or Chainlink price feeds.",
                                references=[
                                    "https://blog.chain.link/flash-loans-and-the-importance-of-tamper-proof-oracles/",
                                    "SWC-120: Weak Sources of Randomness from Chain Attributes",
                                ],
                            )
                        )
                        break

        # Check Chainlink usage
        uses_chainlink = any(
            re.search(pattern, source_code) for pattern in self.ORACLE_PATTERNS["chainlink"]
        )

        if uses_chainlink:
            # Check for staleness validation
            has_staleness_check = re.search(self.STALENESS_CHECK, source_code)
            if not has_staleness_check:
                findings.append(
                    DeFiFinding(
                        title="Missing Oracle Staleness Check",
                        description="Chainlink oracle usage without staleness validation. "
                        "Stale prices could lead to incorrect valuations.",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        recommendation="Validate that (updatedAt > 0) and the price is not stale "
                        "(block.timestamp - updatedAt < MAX_STALENESS).",
                        references=["https://docs.chain.link/data-feeds/price-feeds"],
                    )
                )

            # Check for price deviation validation
            has_deviation_check = re.search(self.DEVIATION_CHECK, source_code)
            if not has_deviation_check:
                findings.append(
                    DeFiFinding(
                        title="Missing Oracle Price Deviation Check",
                        description="No validation for abnormal price deviations. "
                        "Large price swings could indicate manipulation.",
                        severity=Severity.LOW,
                        category=self.category,
                        recommendation="Implement circuit breakers for abnormal price movements.",
                        references=[
                            "https://blog.openzeppelin.com/secure-smart-contract-guidelines"
                        ],
                    )
                )

        return findings


class SandwichAttackDetector(DeFiDetector):
    """
    Detects sandwich attack vulnerabilities.

    Sandwich attacks occur when an attacker:
    1. Front-runs a victim's trade with a buy
    2. Victim's trade executes at worse price
    3. Attacker back-runs with a sell

    Patterns detected:
    - Missing slippage protection
    - Hardcoded slippage values
    - Public pending transactions
    """

    name = "sandwich-attack-detector"
    description = "Detects sandwich attack vulnerabilities"
    category = DeFiCategory.SANDWICH_ATTACK

    # DEX swap patterns
    SWAP_PATTERNS = [
        r"swapExactTokensFor",
        r"swapTokensForExact",
        r"exactInput\w*\(",
        r"exactOutput\w*\(",
        r"\.swap\s*\(",
    ]

    # Slippage patterns
    SLIPPAGE_PATTERNS = {
        "no_slippage": r"amountOutMin\s*[=:]\s*0",
        "hardcoded": r"slippage\s*[=:]\s*\d+",
        "percentage": r"minAmountOut\s*=\s*amount\s*\*\s*\d+\s*/\s*\d+",
    }

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings: List[DeFiFinding] = []
        lines = source_code.split("\n")

        # Check for swap operations
        has_swaps = any(re.search(pattern, source_code) for pattern in self.SWAP_PATTERNS)

        if not has_swaps:
            return findings

        # Check for zero slippage protection
        if re.search(self.SLIPPAGE_PATTERNS["no_slippage"], source_code):
            for i, line in enumerate(lines, 1):
                if re.search(self.SLIPPAGE_PATTERNS["no_slippage"], line):
                    findings.append(
                        DeFiFinding(
                            title="Zero Slippage Protection - Sandwich Attack Risk",
                            description=f"Swap with amountOutMin = 0 at line {i}. "
                            "This allows MEV bots to extract maximum value.",
                            severity=Severity.CRITICAL,
                            category=self.category,
                            line=i,
                            code_snippet=line.strip(),
                            recommendation="Always set a reasonable amountOutMin based on expected output. "
                            "Use DEX aggregators with MEV protection (Flashbots, MEV Blocker).",
                            references=[
                                "https://www.mev.wiki/attack-examples/sandwich-attack",
                                "SWC-114: Transaction Order Dependence",
                            ],
                        )
                    )

        # Check for missing deadline
        has_deadline = re.search(r"deadline\s*[=:]|block\.timestamp\s*\+", source_code)
        if not has_deadline and has_swaps:
            findings.append(
                DeFiFinding(
                    title="Missing Transaction Deadline",
                    description="Swap operation without deadline parameter. "
                    "Transaction could be held and executed at unfavorable time.",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    recommendation="Include deadline parameter to prevent delayed execution attacks.",
                    references=["https://uniswap.org/docs/v2/smart-contracts/router02/"],
                )
            )

        return findings


class MEVExposureDetector(DeFiDetector):
    """
    Detects MEV (Maximal Extractable Value) exposure.

    MEV includes:
    - Front-running opportunities
    - Back-running opportunities
    - Transaction reordering vulnerabilities
    """

    name = "mev-exposure-detector"
    description = "Detects MEV extraction vulnerabilities"
    category = DeFiCategory.MEV_EXPOSURE

    # MEV-susceptible patterns
    MEV_PATTERNS = [
        (r"(liquidat\w+|repay)\s*\(", "Liquidation function - MEV bots actively monitor these"),
        (r"arbitrage|arb\s*\(", "Arbitrage function - direct MEV target"),
        (r"commit.*reveal|reveal.*commit", "Commit-reveal pattern - timing attacks possible"),
        (r"pendingRewards|claimRewards", "Reward claiming - front-running target"),
        # \b required: without it this matched any *Withdraw substring (e.g.
        # "emergencyWithdraw", admin-gated - not front-runnable by anyone).
        (r"\bwithdraw\s*\([^)]*\)\s*public", "Public withdrawal - can be front-run"),
    ]

    # Protection patterns
    PROTECTION_PATTERNS = [
        r"onlyRelayer",
        r"Flashbots",
        r"MEVBlocker",
        r"private\s+(mempool|transaction)",
        r"commit.*reveal",
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings: List[DeFiFinding] = []
        lines = source_code.split("\n")

        # Check for protection mechanisms
        has_protection = any(
            re.search(pattern, source_code, re.IGNORECASE) for pattern in self.PROTECTION_PATTERNS
        )

        # Check for MEV-susceptible patterns
        for i, line in enumerate(lines, 1):
            for pattern, description in self.MEV_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = Severity.MEDIUM if has_protection else Severity.HIGH
                    findings.append(
                        DeFiFinding(
                            title="MEV Exposure Detected",
                            description=f"{description}. Found at line {i}.",
                            severity=severity,
                            category=self.category,
                            line=i,
                            code_snippet=line.strip(),
                            recommendation="Consider using private mempools (Flashbots Protect), "
                            "MEV-aware DEXs, or commit-reveal schemes.",
                            references=[
                                "https://www.flashbots.net/",
                                "https://docs.cow.fi/overview/mev-protection",
                            ],
                        )
                    )

        return findings


class PriceManipulationDetector(DeFiDetector):
    """
    Detects price manipulation vulnerabilities.

    Patterns detected:
    - Single block price checks
    - Balance-based pricing
    - Missing price sanity checks
    """

    name = "price-manipulation-detector"
    description = "Detects price manipulation vulnerabilities"
    category = DeFiCategory.PRICE_MANIPULATION

    PRICE_CALC_PATTERNS = [
        (r"reserve\d?\s*/\s*reserve\d?", "Direct reserve ratio - manipulable in single tx"),
        (
            r"balanceOf\s*\([^)]*\)\s*/\s*totalSupply",
            "Balance/supply ratio - LP token price manipulation",
        ),
        (r"getAmountsOut\s*\([^)]*,\s*\d+\s*\)", "Single-hop quote - no multi-hop validation"),
    ]

    SANITY_CHECK_PATTERNS = [
        r"require\s*\([^)]*price\s*[<>]",
        r"assert\s*\([^)]*price",
        r"revert.*price",
        r"if\s*\([^)]*price.*revert",
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings: List[DeFiFinding] = []
        lines = source_code.split("\n")

        has_sanity_check = any(
            re.search(pattern, source_code, re.IGNORECASE) for pattern in self.SANITY_CHECK_PATTERNS
        )

        for i, line in enumerate(lines, 1):
            for pattern, description in self.PRICE_CALC_PATTERNS:
                if re.search(pattern, line):
                    severity = Severity.HIGH if not has_sanity_check else Severity.MEDIUM
                    findings.append(
                        DeFiFinding(
                            title="Price Manipulation Vulnerability",
                            description=f"{description}. Found at line {i}.",
                            severity=severity,
                            category=self.category,
                            line=i,
                            code_snippet=line.strip(),
                            recommendation="Use TWAP oracles, implement price sanity checks, "
                            "and consider multi-source price aggregation.",
                            references=[
                                "https://samczsun.com/so-you-want-to-use-a-price-oracle/",
                                "SWC-120: Weak Sources of Randomness",
                            ],
                        )
                    )

        return findings


class RoundingErrorDetector(DeFiDetector):
    """
    Detects divide-then-multiply rounding errors via fixed-point library
    method chains (e.g. solmate's `x.divWadDown(y).mulDivDown(z, w)`).

    Slither's own divide-before-multiply detector catches the raw-operator
    form (`(a / b) * c`) but not this one: a `div*`-named method call chained
    straight into a `mul*`-named method call truncates in the division step
    before the multiplication ever sees the lost precision. A *single*
    combined call like `a.mulDivDown(b, c)` is the correct, safe pattern
    (multiply first, divide once) and is not flagged.
    """

    name = "rounding-error-detector"
    description = "Detects divide-before-multiply rounding errors in fixed-point math chains"
    category = DeFiCategory.ROUNDING

    DIV_THEN_MUL_CHAIN = re.compile(r"\.\w*[Dd]iv\w*\s*\([^()]*\)\s*\.\w*[Mm]ul\w*\s*\(")

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings: List[DeFiFinding] = []
        lines = source_code.split("\n")

        for i, line in enumerate(lines, 1):
            if self.DIV_THEN_MUL_CHAIN.search(line):
                findings.append(
                    DeFiFinding(
                        title="Divide-Before-Multiply in Fixed-Point Math Chain",
                        description=f"A division method is chained directly into a "
                        f"multiplication method at line {i}, truncating precision in the "
                        "division step before the multiplication runs.",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        recommendation="Combine into a single call that multiplies before "
                        "dividing (e.g. mulDivDown/mulDivUp) instead of chaining separate "
                        "div then mul calls.",
                        references=["https://swcregistry.io/docs/SWC-101"],
                    )
                )

        return findings


class FeeOnTransferDetector(DeFiDetector):
    """
    Detects missing balance-before/after checks around token transfers-in.

    A function that pulls tokens via `transferFrom`/`safeTransferFrom` and
    then mints/credits shares based on the requested amount (instead of the
    actual balance delta) silently over-credits the depositor whenever the
    token charges a transfer fee or rebases.
    """

    name = "fee-on-transfer-detector"
    description = "Detects missing balance-before/after checks on token transfers-in"
    category = DeFiCategory.FEE_ON_TRANSFER

    TRANSFER_IN_PATTERN = re.compile(r"\.(safeTransferFrom|transferFrom)\s*\(")
    BALANCE_CHECK_PATTERN = re.compile(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)")
    # ERC721/ERC1155 also expose safeTransferFrom/transferFrom (moving a
    # tokenId, not an amount) — fee-on-transfer is an ERC20-only concept, so a
    # call cast through one of these NFT/multi-token interfaces is not a hit.
    NFT_TRANSFER_MARKER = re.compile(r"\bI?ERC(721|1155)\b")

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings: List[DeFiFinding] = []
        lines = source_code.split("\n")

        transfer_in_lines = [
            i
            for i, line in enumerate(lines, 1)
            if self.TRANSFER_IN_PATTERN.search(line) and not self.NFT_TRANSFER_MARKER.search(line)
        ]
        has_balance_check = self.BALANCE_CHECK_PATTERN.search(source_code)

        if transfer_in_lines and not has_balance_check:
            for i in transfer_in_lines:
                line = lines[i - 1]
                findings.append(
                    DeFiFinding(
                        title="Fee-on-Transfer Token Risk: Missing Balance-Before/After Check",
                        description=f"transferFrom at line {i} pulls tokens in but no "
                        "balanceOf(address(this)) check anywhere in this file measures the "
                        "actual amount received. A fee-on-transfer or rebasing token would "
                        "credit shares/accounting based on the requested amount, not what "
                        "actually arrived.",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        recommendation="Measure balanceOf(address(this)) before and after "
                        "the transfer and use the delta for any shares/accounting "
                        "calculation, instead of the requested transfer amount.",
                        references=["https://github.com/d-xo/weird-erc20#fee-on-transfer"],
                    )
                )

        return findings


class ERC4626ComplianceDetector(DeFiDetector):
    """
    Detects vault-accounting contracts (deposit/withdraw/totalAssets) whose
    function signatures don't match the EIP-4626 standard's mandated arity.

    EIP-4626 fixes the exact parameter count for its accounting functions:
    `deposit(assets, receiver)` and `mint(shares, receiver)` take 2 params,
    `withdraw(assets, receiver, owner)` and `redeem(shares, receiver, owner)`
    take 3, `totalAssets()` takes 0, `convertToShares(assets)` takes 1. A
    contract that implements the full vault accounting API but adds extra
    parameters (e.g. an `id` for a multi-vault/ERC1155-backed design) cannot
    be integrated by any EIP-4626-aware caller, no matter how correct its
    internal accounting is — every mandated function signature is broken.
    """

    name = "erc4626-compliance-detector"
    description = (
        "Detects vault-accounting functions whose signatures don't match the EIP-4626 standard"
    )
    category = DeFiCategory.ERC4626

    CANONICAL_ARITY = {
        "deposit": 2,
        "mint": 2,
        "withdraw": 3,
        "redeem": 3,
        "totalAssets": 0,
        "convertToShares": 1,
    }
    # Gate: only judge signature shape on contracts that already look like a
    # vault (has the core accounting trio together) - deposit/withdraw alone
    # are far too common (staking, escrow, ...) to use as the sole signal.
    VAULT_CORE_FUNCTIONS = {"deposit", "withdraw", "totalAssets"}
    FUNC_SIG = re.compile(
        r"function\s+(deposit|mint|withdraw|redeem|totalAssets|convertToShares)\s*\(([^)]*)\)"
    )

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings: List[DeFiFinding] = []
        matches = list(self.FUNC_SIG.finditer(source_code))
        names_present = {m.group(1) for m in matches}
        if not self.VAULT_CORE_FUNCTIONS.issubset(names_present):
            return findings

        for m in matches:
            name = m.group(1)
            params_raw = m.group(2).strip()
            param_count = (
                0 if not params_raw else len([p for p in params_raw.split(",") if p.strip()])
            )
            expected = self.CANONICAL_ARITY[name]
            if param_count == expected:
                continue

            line = source_code[: m.start()].count("\n") + 1
            findings.append(
                DeFiFinding(
                    title=f"EIP-4626 Signature Mismatch: {name}()",
                    description=f"`{name}` at line {line} takes {param_count} parameter(s), but "
                    f"EIP-4626 mandates exactly {expected} for this function. A contract exposing "
                    "the vault accounting API (deposit/withdraw/totalAssets) with a signature that "
                    "doesn't match the standard cannot be integrated by any EIP-4626-aware caller "
                    "(aggregators, other vaults composing on top of it), even though it may behave "
                    "correctly as a vault internally.",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    line=line,
                    code_snippet=f"function {name}(...)",
                    recommendation="If EIP-4626 compatibility is required, expose a compliant "
                    f"single-asset `{name}` with the standard signature, or document explicitly "
                    "that this is a vault-like contract, not an EIP-4626 vault.",
                    references=["https://eips.ethereum.org/EIPS/eip-4626"],
                )
            )

        return findings


class UnrefundedExcessPaymentDetector(DeFiDetector):
    """
    Detects `payable` functions that accept overpayment (`msg.value >= cost`)
    but never refund the difference back to the caller.

    Real case (NextGen M-12, ground truth): MinterContract's mint()/
    burnToMint()/burnOrSwapExternalToMint() all `require(msg.value >= price)`
    (explicitly allowing overpayment) then credit the *full* msg.value to
    internal accounting - any amount paid above the actual price is silently
    kept by the contract, never returned. A contract that instead requires
    exact payment (`msg.value == cost`) has no excess to refund and is not
    flagged - the risk is specifically in accepting *more* than required
    without giving the difference back.

    Gated on the comparison's right-hand side looking like a computed price
    (a function call or a multiplication, e.g. `getPrice(id) * qty`) rather
    than a bare threshold constant/variable (`MinDeposit`, `0.02 ether`,
    `autoBirthFee`). Verified against smartbugs-curated: several real
    "deposit if msg.value >= minimum" functions credit the *entire*
    msg.value to the sender's own balance - correct behavior, no excess to
    refund - and would be false positives without this gate.
    """

    name = "unrefunded-excess-payment-detector"
    description = (
        "Detects payable functions with a 'msg.value >=' overpayment check "
        "that never refund the excess"
    )
    category = DeFiCategory.BUSINESS_LOGIC

    MSG_VALUE_OVERPAY_CHECK = re.compile(r"msg\.value\s*>=")
    COMPUTED_PRICE = re.compile(r"\w\s*\(|\*")
    REFUND_PATTERNS = [
        re.compile(r"msg\.sender\s*\.\s*(?:call\s*\{|transfer\s*\(|send\s*\()"),
        re.compile(r"payable\s*\(\s*msg\.sender\s*\)\s*\.\s*(?:call\s*\{|transfer\s*\(|send\s*\()"),
        re.compile(r"\brefund\w*\s*\("),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings: List[DeFiFinding] = []
        try:
            from miesc.ml.call_graph import CallGraphBuilder

            graph = CallGraphBuilder().build_from_source(source_code)
        except Exception:
            return findings

        lines = source_code.split("\n")
        for func in graph.nodes.values():
            if not func.is_payable or not func.start_line:
                continue
            end_line = self._function_body_end(lines, func.start_line)
            body = "\n".join(lines[func.start_line - 1 : end_line])

            match = self.MSG_VALUE_OVERPAY_CHECK.search(body)
            if not match:
                continue
            condition = self._enclosing_call(body, match.start())
            if not condition or not self.COMPUTED_PRICE.search(condition):
                continue
            if any(pattern.search(body) for pattern in self.REFUND_PATTERNS):
                continue

            findings.append(
                DeFiFinding(
                    title="Unrefunded Excess Payment",
                    description=f"`{func.name}` at line {func.start_line} accepts "
                    "overpayment (`msg.value >=` a required amount) but never refunds "
                    "the difference back to the caller - any ETH sent above the "
                    "required amount is silently kept by the contract.",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    line=func.start_line,
                    code_snippet=f"function {func.name}(...) payable",
                    recommendation="Either require exact payment (`msg.value == cost`) "
                    "or refund the excess (`msg.value - cost`) back to msg.sender "
                    "before returning.",
                )
            )

        return findings

    @staticmethod
    def _function_body_end(lines: List[str], start_line: int) -> int:
        """1-indexed last line of the function starting at `start_line`.

        Same regex-based rigor as the rest of this codebase's Solidity
        parsing (not a real compiler) - brace-count from the function
        header to its matching close.
        """
        depth = 0
        started = False
        end_idx = start_line - 1
        for i in range(start_line - 1, len(lines)):
            depth += lines[i].count("{") - lines[i].count("}")
            if "{" in lines[i]:
                started = True
            end_idx = i
            if started and depth <= 0:
                break
        return end_idx + 1

    @staticmethod
    def _enclosing_call(text: str, pos: int) -> Optional[str]:
        """The nearest `require(...)`/`if(...)` (or any `foo(...)`) span
        enclosing `pos`, via paren balance - not just "next 40 chars", so a
        nested call like `getPrice(col)` inside the condition doesn't get
        mistaken for the end of the whole require(...)."""
        depth = 0
        start = None
        i = pos
        while i > 0:
            i -= 1
            c = text[i]
            if c == ")":
                depth += 1
            elif c == "(":
                if depth == 0:
                    start = i
                    break
                depth -= 1
        if start is None:
            return None
        depth = 0
        for j in range(start, len(text)):
            c = text[j]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return text[start : j + 1]
        return None


class DeFiDetectorEngine:
    """Engine to run all DeFi detectors."""

    def __init__(self) -> None:
        self.detectors: List[DeFiDetector] = [
            FlashLoanDetector(),
            OracleManipulationDetector(),
            SandwichAttackDetector(),
            MEVExposureDetector(),
            PriceManipulationDetector(),
            RoundingErrorDetector(),
            FeeOnTransferDetector(),
            ERC4626ComplianceDetector(),
            UnrefundedExcessPaymentDetector(),
        ]

    def analyze(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        """Run all detectors on source code."""
        all_findings = []
        for detector in self.detectors:
            findings = detector.detect(source_code, file_path)
            all_findings.extend(findings)
        return all_findings

    def analyze_file(self, file_path: Path) -> List[DeFiFinding]:
        """Analyze a Solidity file."""
        with open(file_path, "r") as f:
            source_code = f.read()
        return self.analyze(source_code, file_path)

    def get_summary(self, findings: List[DeFiFinding]) -> Dict:
        """Generate summary statistics."""
        summary: Dict[str, Any] = {
            "total": len(findings),
            "by_severity": {},
            "by_category": {},
        }

        for finding in findings:
            # Count by severity
            sev = finding.severity.value
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

            # Count by category
            cat = finding.category.value
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

        return summary


def main() -> None:  # pragma: no cover - manual demo harness, not shipped logic
    """Example usage."""
    # Example vulnerable contract
    test_contract = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    import "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";
    import "@aave/protocol-v2/contracts/flashloan/base/FlashLoanReceiverBase.sol";

    contract VulnerableDeFi is FlashLoanReceiverBase {
        IUniswapV2Router02 public router;

        function executeOperation(
            address[] calldata assets,
            uint256[] calldata amounts,
            uint256[] calldata premiums,
            address initiator,
            bytes calldata params
        ) external override returns (bool) {
            // Get current price from pool - VULNERABLE
            (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(pair).getReserves();
            uint256 price = reserve0 / reserve1;

            // Swap with no slippage protection - CRITICAL
            router.swapExactTokensForTokens(
                amount,
                0,  // amountOutMin = 0 is dangerous!
                path,
                address(this),
                block.timestamp
            );

            return true;
        }

        function liquidate(address user) public {
            // Liquidation without MEV protection
            _liquidate(user);
        }
    }
    """

    engine = DeFiDetectorEngine()
    findings = engine.analyze(test_contract)

    print("\n" + "=" * 60)  # noqa: T201
    print("  MIESC DeFi Vulnerability Scanner Results")  # noqa: T201
    print("=" * 60 + "\n")  # noqa: T201

    for i, finding in enumerate(findings, 1):
        print(f"{i}. [{finding.severity.value.upper()}] {finding.title}")  # noqa: T201
        print(f"   Category: {finding.category.value}")  # noqa: T201
        if finding.line:
            print(f"   Line: {finding.line}")  # noqa: T201
        print(f"   {finding.description}")  # noqa: T201
        print(f"   Recommendation: {finding.recommendation}")  # noqa: T201
        print()  # noqa: T201

    summary = engine.get_summary(findings)
    print("-" * 60)  # noqa: T201
    print(f"Total Findings: {summary['total']}")  # noqa: T201
    print(f"By Severity: {summary['by_severity']}")  # noqa: T201
    print(f"By Category: {summary['by_category']}")  # noqa: T201


if __name__ == "__main__":
    main()
