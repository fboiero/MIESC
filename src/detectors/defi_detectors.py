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
from typing import List, Dict, Optional, Set, Tuple
from enum import Enum
from pathlib import Path


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
        pass


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
        r'function\s+(executeOperation|onFlashLoan|flashLoanCallback|uniswapV2Call|pancakeCall)\s*\(',
        r'IFlashLoan\w*\.flash',
        r'IERC3156FlashBorrower',
        r'flashLoan\s*\(',
    ]

    # Dangerous patterns in flash loan callbacks
    DANGER_PATTERNS = [
        (r'\.swap\(', "Swap operation in flash loan context - potential price manipulation"),
        (r'\.getReserves\(\)', "Reading reserves without validation - oracle manipulation risk"),
        (r'balanceOf\([^)]*\)\s*[<>=]', "Balance comparison - potential flash loan bypass"),
        (r'totalSupply\(\)', "Total supply check - may be manipulated via flash mint"),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings = []
        lines = source_code.split('\n')

        # Check for flash loan interfaces
        has_flash_loan = any(
            re.search(pattern, source_code, re.IGNORECASE)
            for pattern in self.CALLBACK_PATTERNS
        )

        if has_flash_loan:
            # Check for dangerous patterns within flash loan context
            for i, line in enumerate(lines, 1):
                for pattern, description in self.DANGER_PATTERNS:
                    if re.search(pattern, line):
                        findings.append(DeFiFinding(
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
                                "SWC-136: Unencrypted Private Data On-Chain"
                            ]
                        ))

            # Check for missing repayment validation
            if not re.search(r'require\s*\([^)]*repay|assert\s*\([^)]*return', source_code, re.IGNORECASE):
                findings.append(DeFiFinding(
                    title="Missing Flash Loan Repayment Validation",
                    description="Flash loan callback does not explicitly validate loan repayment.",
                    severity=Severity.CRITICAL,
                    category=self.category,
                    recommendation="Add explicit repayment validation and ensure atomicity.",
                    references=["https://eips.ethereum.org/EIPS/eip-3156"]
                ))

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
        'spot_price': [
            r'getReserves\s*\(\)',
            r'slot0\s*\(\)',
            r'\.price\d*\(\)',
            r'getAmountOut\s*\(',
        ],
        'chainlink': [
            r'latestRoundData\s*\(\)',
            r'AggregatorV\d*Interface',
            r'\.answer\b',
        ],
        'uniswap_twap': [
            r'observe\s*\(',
            r'consult\s*\(',
            r'TWAP',
        ]
    }

    STALENESS_CHECK = r'(updatedAt|timestamp|roundId)\s*[<>=!]'
    DEVIATION_CHECK = r'(deviation|delta|diff)\s*[<>=]'

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings = []
        lines = source_code.split('\n')

        # Check for spot price usage
        uses_spot_price = any(
            re.search(pattern, source_code)
            for pattern in self.ORACLE_PATTERNS['spot_price']
        )

        uses_twap = any(
            re.search(pattern, source_code)
            for pattern in self.ORACLE_PATTERNS['uniswap_twap']
        )

        if uses_spot_price and not uses_twap:
            for i, line in enumerate(lines, 1):
                for pattern in self.ORACLE_PATTERNS['spot_price']:
                    if re.search(pattern, line):
                        findings.append(DeFiFinding(
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
                                "SWC-120: Weak Sources of Randomness from Chain Attributes"
                            ]
                        ))
                        break

        # Check Chainlink usage
        uses_chainlink = any(
            re.search(pattern, source_code)
            for pattern in self.ORACLE_PATTERNS['chainlink']
        )

        if uses_chainlink:
            # Check for staleness validation
            has_staleness_check = re.search(self.STALENESS_CHECK, source_code)
            if not has_staleness_check:
                findings.append(DeFiFinding(
                    title="Missing Oracle Staleness Check",
                    description="Chainlink oracle usage without staleness validation. "
                               "Stale prices could lead to incorrect valuations.",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    recommendation="Validate that (updatedAt > 0) and the price is not stale "
                                 "(block.timestamp - updatedAt < MAX_STALENESS).",
                    references=["https://docs.chain.link/data-feeds/price-feeds"]
                ))

            # Check for price deviation validation
            has_deviation_check = re.search(self.DEVIATION_CHECK, source_code)
            if not has_deviation_check:
                findings.append(DeFiFinding(
                    title="Missing Oracle Price Deviation Check",
                    description="No validation for abnormal price deviations. "
                               "Large price swings could indicate manipulation.",
                    severity=Severity.LOW,
                    category=self.category,
                    recommendation="Implement circuit breakers for abnormal price movements.",
                    references=["https://blog.openzeppelin.com/secure-smart-contract-guidelines"]
                ))

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
        r'swapExactTokensFor',
        r'swapTokensForExact',
        r'exactInput\w*\(',
        r'exactOutput\w*\(',
        r'\.swap\s*\(',
    ]

    # Slippage patterns
    SLIPPAGE_PATTERNS = {
        'no_slippage': r'amountOutMin\s*[=:]\s*0',
        'hardcoded': r'slippage\s*[=:]\s*\d+',
        'percentage': r'minAmountOut\s*=\s*amount\s*\*\s*\d+\s*/\s*\d+',
    }

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings = []
        lines = source_code.split('\n')

        # Check for swap operations
        has_swaps = any(
            re.search(pattern, source_code)
            for pattern in self.SWAP_PATTERNS
        )

        if not has_swaps:
            return findings

        # Check for zero slippage protection
        if re.search(self.SLIPPAGE_PATTERNS['no_slippage'], source_code):
            for i, line in enumerate(lines, 1):
                if re.search(self.SLIPPAGE_PATTERNS['no_slippage'], line):
                    findings.append(DeFiFinding(
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
                            "SWC-114: Transaction Order Dependence"
                        ]
                    ))

        # Check for missing deadline
        has_deadline = re.search(r'deadline\s*[=:]|block\.timestamp\s*\+', source_code)
        if not has_deadline and has_swaps:
            findings.append(DeFiFinding(
                title="Missing Transaction Deadline",
                description="Swap operation without deadline parameter. "
                           "Transaction could be held and executed at unfavorable time.",
                severity=Severity.MEDIUM,
                category=self.category,
                recommendation="Include deadline parameter to prevent delayed execution attacks.",
                references=["https://uniswap.org/docs/v2/smart-contracts/router02/"]
            ))

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
        (r'(liquidat\w+|repay)\s*\(', "Liquidation function - MEV bots actively monitor these"),
        (r'arbitrage|arb\s*\(', "Arbitrage function - direct MEV target"),
        (r'commit.*reveal|reveal.*commit', "Commit-reveal pattern - timing attacks possible"),
        (r'pendingRewards|claimRewards', "Reward claiming - front-running target"),
        (r'withdraw\s*\([^)]*\)\s*public', "Public withdrawal - can be front-run"),
    ]

    # Protection patterns
    PROTECTION_PATTERNS = [
        r'onlyRelayer',
        r'Flashbots',
        r'MEVBlocker',
        r'private\s+(mempool|transaction)',
        r'commit.*reveal',
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings = []
        lines = source_code.split('\n')

        # Check for protection mechanisms
        has_protection = any(
            re.search(pattern, source_code, re.IGNORECASE)
            for pattern in self.PROTECTION_PATTERNS
        )

        # Check for MEV-susceptible patterns
        for i, line in enumerate(lines, 1):
            for pattern, description in self.MEV_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = Severity.MEDIUM if has_protection else Severity.HIGH
                    findings.append(DeFiFinding(
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
                            "https://docs.cow.fi/overview/mev-protection"
                        ]
                    ))

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
        (r'reserve\d?\s*/\s*reserve\d?', "Direct reserve ratio - manipulable in single tx"),
        (r'balanceOf\s*\([^)]*\)\s*/\s*totalSupply', "Balance/supply ratio - LP token price manipulation"),
        (r'getAmountsOut\s*\([^)]*,\s*\d+\s*\)', "Single-hop quote - no multi-hop validation"),
    ]

    SANITY_CHECK_PATTERNS = [
        r'require\s*\([^)]*price\s*[<>]',
        r'assert\s*\([^)]*price',
        r'revert.*price',
        r'if\s*\([^)]*price.*revert',
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[DeFiFinding]:
        findings = []
        lines = source_code.split('\n')

        has_sanity_check = any(
            re.search(pattern, source_code, re.IGNORECASE)
            for pattern in self.SANITY_CHECK_PATTERNS
        )

        for i, line in enumerate(lines, 1):
            for pattern, description in self.PRICE_CALC_PATTERNS:
                if re.search(pattern, line):
                    severity = Severity.HIGH if not has_sanity_check else Severity.MEDIUM
                    findings.append(DeFiFinding(
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
                            "SWC-120: Weak Sources of Randomness"
                        ]
                    ))

        return findings


class DeFiDetectorEngine:
    """Engine to run all DeFi detectors."""

    def __init__(self):
        self.detectors: List[DeFiDetector] = [
            FlashLoanDetector(),
            OracleManipulationDetector(),
            SandwichAttackDetector(),
            MEVExposureDetector(),
            PriceManipulationDetector(),
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
        with open(file_path, 'r') as f:
            source_code = f.read()
        return self.analyze(source_code, file_path)

    def get_summary(self, findings: List[DeFiFinding]) -> Dict:
        """Generate summary statistics."""
        summary = {
            'total': len(findings),
            'by_severity': {},
            'by_category': {},
        }

        for finding in findings:
            # Count by severity
            sev = finding.severity.value
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1

            # Count by category
            cat = finding.category.value
            summary['by_category'][cat] = summary['by_category'].get(cat, 0) + 1

        return summary


def main():
    """Example usage."""
    # Example vulnerable contract
    test_contract = '''
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
    '''

    engine = DeFiDetectorEngine()
    findings = engine.analyze(test_contract)

    print("\n" + "="*60)
    print("  MIESC DeFi Vulnerability Scanner Results")
    print("="*60 + "\n")

    for i, finding in enumerate(findings, 1):
        print(f"{i}. [{finding.severity.value.upper()}] {finding.title}")
        print(f"   Category: {finding.category.value}")
        if finding.line:
            print(f"   Line: {finding.line}")
        print(f"   {finding.description}")
        print(f"   Recommendation: {finding.recommendation}")
        print()

    summary = engine.get_summary(findings)
    print("-"*60)
    print(f"Total Findings: {summary['total']}")
    print(f"By Severity: {summary['by_severity']}")
    print(f"By Category: {summary['by_category']}")


if __name__ == "__main__":
    main()
