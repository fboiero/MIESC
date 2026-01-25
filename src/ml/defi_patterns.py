"""
DeFi Vulnerability Pattern Detector
====================================

Specialized patterns for detecting vulnerabilities in DeFi protocols.
Covers common attack vectors in modern decentralized finance.

Attack Categories:
- Flash loan attacks
- Sandwich/MEV attacks
- Governance attacks
- Bridge vulnerabilities
- Oracle manipulation
- Liquidity pool attacks

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA
Date: January 2026
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class DeFiVulnType(Enum):
    """DeFi-specific vulnerability types."""
    FLASH_LOAN_ATTACK = "flash_loan_attack"
    SANDWICH_ATTACK = "sandwich_attack"
    GOVERNANCE_ATTACK = "governance_attack"
    BRIDGE_VULNERABILITY = "bridge_vulnerability"
    ORACLE_MANIPULATION = "oracle_manipulation"
    LIQUIDITY_DRAIN = "liquidity_drain"
    PRICE_MANIPULATION = "price_manipulation"
    REWARD_MANIPULATION = "reward_manipulation"
    FRONT_RUNNING = "front_running"
    MEV_EXTRACTION = "mev_extraction"
    DONATION_ATTACK = "donation_attack"
    INFLATION_ATTACK = "inflation_attack"


@dataclass
class DeFiVulnerabilityPattern:
    """Pattern definition for DeFi vulnerabilities."""
    vuln_type: DeFiVulnType
    name: str
    severity: str  # critical, high, medium, low
    indicators: List[str]  # Regex patterns to match
    anti_patterns: List[str]  # Patterns that indicate safety
    description: str
    attack_example: str
    real_exploits: List[str]  # Real-world exploit examples
    remediation: str
    swc_id: Optional[str] = None
    estimated_loss_usd: Optional[str] = None


@dataclass
class DeFiPatternMatch:
    """Result of a DeFi pattern match."""
    pattern: DeFiVulnerabilityPattern
    matched_indicators: List[Tuple[str, str]]  # (pattern, matched_text)
    matched_anti_patterns: List[Tuple[str, str]]
    confidence: float
    location: Dict[str, Any]
    code_snippet: str
    is_vulnerable: bool
    recommendation: str


# =============================================================================
# DEFI VULNERABILITY PATTERNS DATABASE
# =============================================================================

DEFI_VULNERABILITY_PATTERNS: Dict[DeFiVulnType, DeFiVulnerabilityPattern] = {
    # =========================================================================
    # FLASH LOAN ATTACK
    # =========================================================================
    DeFiVulnType.FLASH_LOAN_ATTACK: DeFiVulnerabilityPattern(
        vuln_type=DeFiVulnType.FLASH_LOAN_ATTACK,
        name="Flash Loan Price Manipulation",
        severity="critical",
        indicators=[
            # Price calculated from reserves (spot price)
            r"getReserves\s*\(\s*\)",
            r"reserve[01]\s*/\s*reserve[01]",
            r"balanceOf\s*\([^)]+\)\s*/\s*balanceOf\s*\(",
            # Single-block oracle
            r"slot0\s*\(\s*\)",
            r"getAmountOut\s*\(",
            # No TWAP
            r"price\s*=\s*[^;]*reserve",
            # Borrow/repay in same tx
            r"flashLoan\s*\(",
            r"flash\s*\(",
            r"executeOperation\s*\(",
        ],
        anti_patterns=[
            # TWAP usage
            r"TWAP",
            r"twap",
            r"observe\s*\(",
            r"consult\s*\(",
            # Time-weighted
            r"timeWeighted",
            r"cumulativePrice",
            # Chainlink oracle
            r"latestRoundData\s*\(",
            r"AggregatorV3Interface",
        ],
        description=(
            "The contract calculates prices using spot reserves which can be "
            "manipulated within a single transaction using flash loans. An attacker "
            "can borrow large amounts, manipulate the price, execute the vulnerable "
            "function, then repay the loan in the same block."
        ),
        attack_example=(
            "1. Flash loan $100M\n"
            "2. Swap to manipulate pool reserves\n"
            "3. Call vulnerable function (uses manipulated price)\n"
            "4. Swap back\n"
            "5. Repay flash loan + profit"
        ),
        real_exploits=["bZx ($8M, 2020)", "Harvest Finance ($34M, 2020)", "Warp Finance ($7.7M, 2020)"],
        remediation=(
            "Use time-weighted average prices (TWAP) from Uniswap V3 or "
            "Chainlink oracles. Implement price deviation checks. "
            "Add flash loan guards or multi-block confirmation."
        ),
        swc_id="SWC-133",
        estimated_loss_usd="$100M+",
    ),

    # =========================================================================
    # SANDWICH ATTACK
    # =========================================================================
    DeFiVulnType.SANDWICH_ATTACK: DeFiVulnerabilityPattern(
        vuln_type=DeFiVulnType.SANDWICH_ATTACK,
        name="Sandwich Attack Vulnerability",
        severity="high",
        indicators=[
            # No slippage protection
            r"amountOutMin\s*:\s*0",
            r"minAmountOut\s*=\s*0",
            r"amountOutMinimum\s*:\s*0",
            r"swapExactTokensForTokens\s*\([^,]+,\s*0",
            r"swap\s*\([^)]*0\s*,",  # minOut = 0
            # Deadline far in future or not used
            r"deadline\s*:\s*type\s*\(\s*uint256\s*\)\s*\.max",
            r"deadline\s*:\s*\d{10,}",  # Very large deadline
            r"deadline\s*=\s*block\.timestamp\s*\+\s*\d{5,}",  # Hours/days
            # No deadline at all
            r"swap\s*\([^)]*\)\s*(?!.*deadline)",
        ],
        anti_patterns=[
            # Proper slippage
            r"amountOutMin\s*>\s*0",
            r"_slippage",
            r"slippageProtection",
            r"minReturn\s*>\s*0",
            # Reasonable deadline
            r"deadline\s*=\s*block\.timestamp\s*\+\s*(30|60|120|300)",
            # MEV protection
            r"Flashbots",
            r"privateTransaction",
        ],
        description=(
            "Swap operations without slippage protection or with excessive deadlines "
            "are vulnerable to sandwich attacks. MEV bots can front-run and back-run "
            "the transaction to extract value."
        ),
        attack_example=(
            "1. User submits swap tx with 0 slippage\n"
            "2. MEV bot front-runs with large buy\n"
            "3. User's tx executes at worse price\n"
            "4. MEV bot back-runs with sell\n"
            "5. User loses ~1-5% to slippage"
        ),
        real_exploits=["Daily MEV extraction (~$1M/day)", "BadgerDAO governance vote manipulation"],
        remediation=(
            "Always set reasonable slippage tolerance (0.5-3%). "
            "Use short deadlines (30 seconds to 5 minutes). "
            "Consider private mempools (Flashbots) for large trades."
        ),
        swc_id="SWC-114",
        estimated_loss_usd="$1M+/day network-wide",
    ),

    # =========================================================================
    # GOVERNANCE ATTACK
    # =========================================================================
    DeFiVulnType.GOVERNANCE_ATTACK: DeFiVulnerabilityPattern(
        vuln_type=DeFiVulnType.GOVERNANCE_ATTACK,
        name="Governance Flash Loan Attack",
        severity="critical",
        indicators=[
            # Flash loan + voting
            r"castVote\s*\(",
            r"propose\s*\(",
            r"queue\s*\(",
            r"execute\s*\(",
            # No time lock
            r"executeProposal\s*\([^)]*\)\s*(?!.*timelock)",
            # Low quorum
            r"quorum\s*=\s*[1-9]\s*\*\s*10\s*\*\*\s*(16|17)",  # < 1%
            r"minimumQuorum\s*=\s*\d{1,2}",  # Very low number
            # Snapshot at proposal
            r"getPriorVotes\s*\(\s*[^,]+,\s*proposalSnapshot",
            # No vote delegation lock
            r"delegate\s*\(",
        ],
        anti_patterns=[
            # Time lock
            r"TimelockController",
            r"timelock",
            r"delay\s*>=\s*\d+\s*days",
            # Vote escrow
            r"voteEscrow",
            r"veToken",
            r"lockTime",
            # Snapshot before proposal
            r"getPriorVotes\s*\(\s*[^,]+,\s*block\.number\s*-",
        ],
        description=(
            "Governance mechanism vulnerable to flash loan attacks. An attacker can "
            "borrow governance tokens, vote, and return them in the same block. "
            "Low quorum or missing timelock makes exploitation easier."
        ),
        attack_example=(
            "1. Flash loan governance tokens\n"
            "2. Delegate voting power to self\n"
            "3. Create malicious proposal\n"
            "4. Vote with borrowed tokens\n"
            "5. Execute proposal immediately\n"
            "6. Drain treasury or change protocol"
        ),
        real_exploits=[
            "Beanstalk ($182M, 2022)",
            "Build Finance ($470K, 2022)",
            "Fortress Protocol ($3M, 2022)",
        ],
        remediation=(
            "Implement time-locked governance with minimum 2-day delay. "
            "Take voting snapshots before proposal creation. "
            "Require vote-escrow (veTOKEN) for governance participation. "
            "Set reasonable quorum (>4% of supply)."
        ),
        swc_id=None,
        estimated_loss_usd="$200M+",
    ),

    # =========================================================================
    # BRIDGE VULNERABILITY
    # =========================================================================
    DeFiVulnType.BRIDGE_VULNERABILITY: DeFiVulnerabilityPattern(
        vuln_type=DeFiVulnType.BRIDGE_VULNERABILITY,
        name="Cross-Chain Bridge Vulnerability",
        severity="critical",
        indicators=[
            # Message without validation
            r"onMessageReceived\s*\(",
            r"xReceive\s*\(",
            r"receiveMessage\s*\(",
            r"executeMessage\s*\(",
            # Replay possible
            r"processedMessages\[",
            r"usedNonces\[",
            # No source chain validation
            r"msg\.sender\s*==\s*bridge",  # Only checks local sender
            # Signature issues
            r"ecrecover\s*\(",
            r"signature\s*\)",
        ],
        anti_patterns=[
            # Nonce/replay protection
            r"require\s*\(\s*!processed\[",
            r"require\s*\(\s*nonce\s*==",
            # Multi-sig validation
            r"threshold",
            r"signaturesRequired",
            # Source validation
            r"require\s*\(\s*sourceChain\s*==",
            r"trustedRemote\[",
        ],
        description=(
            "Cross-chain bridge with insufficient message validation. "
            "Missing replay protection, source chain verification, or "
            "signature validation can lead to catastrophic fund loss."
        ),
        attack_example=(
            "1. Craft fake message claiming deposit on Chain A\n"
            "2. Submit to Bridge on Chain B\n"
            "3. Bridge mints/releases funds without proper verification\n"
            "4. Repeat (replay attack)"
        ),
        real_exploits=[
            "Ronin Bridge ($624M, 2022)",
            "Wormhole ($326M, 2022)",
            "Nomad Bridge ($190M, 2022)",
            "BNB Bridge ($568M, 2022)",
        ],
        remediation=(
            "Implement strict replay protection with nonces. "
            "Validate source chain and sender addresses. "
            "Use multi-signature validation with threshold (e.g., 3/5). "
            "Add rate limiting and pause mechanisms. "
            "Consider optimistic bridge design with fraud proofs."
        ),
        swc_id=None,
        estimated_loss_usd="$2B+",
    ),

    # =========================================================================
    # ORACLE MANIPULATION
    # =========================================================================
    DeFiVulnType.ORACLE_MANIPULATION: DeFiVulnerabilityPattern(
        vuln_type=DeFiVulnType.ORACLE_MANIPULATION,
        name="Oracle Price Manipulation",
        severity="critical",
        indicators=[
            # Spot price usage
            r"getReserves\s*\(\s*\)",
            r"slot0\s*\(",
            r"token[01]\.balanceOf\s*\(",
            # No staleness check
            r"latestAnswer\s*\(",  # Without staleness check
            r"latestRoundData\s*\([^)]*\)[^;]*price\s*=",  # Not checking updatedAt
            # Single oracle
            r"oracle\.",
            r"priceFeed\.",
        ],
        anti_patterns=[
            # Staleness check
            r"require\s*\(\s*block\.timestamp\s*-\s*updatedAt\s*<",
            r"updatedAt\s*>\s*block\.timestamp\s*-",
            # Multiple oracles
            r"oracles\[",
            r"primaryOracle.*secondaryOracle",
            # TWAP
            r"TWAP",
            r"observe\s*\(",
            r"consult\s*\(",
        ],
        description=(
            "Price oracle can be manipulated or return stale data. "
            "Spot prices from AMMs are vulnerable to flash loan attacks. "
            "Missing staleness checks can use outdated prices during volatility."
        ),
        attack_example=(
            "1. Oracle reports stale price (market moved 20%)\n"
            "2. Attacker borrows at favorable rate\n"
            "3. Liquidation threshold never reached due to stale price\n"
            "4. Protocol loses collateral"
        ),
        real_exploits=[
            "Mango Markets ($114M, 2022)",
            "Cream Finance ($130M, 2021)",
            "Compound ($80M, 2021)",
        ],
        remediation=(
            "Use Chainlink oracles with staleness checks (< 1 hour). "
            "Implement TWAP for DEX-based pricing. "
            "Use multiple oracle sources with median/average. "
            "Add price deviation circuit breakers. "
            "Consider optimistic oracle designs for complex assets."
        ),
        swc_id="SWC-133",
        estimated_loss_usd="$400M+",
    ),

    # =========================================================================
    # LIQUIDITY DRAIN
    # =========================================================================
    DeFiVulnType.LIQUIDITY_DRAIN: DeFiVulnerabilityPattern(
        vuln_type=DeFiVulnType.LIQUIDITY_DRAIN,
        name="Liquidity Pool Drain Attack",
        severity="critical",
        indicators=[
            # Skim function exposed
            r"function\s+skim\s*\(",
            r"function\s+sync\s*\(",
            # Unprotected withdrawal
            r"function\s+withdraw\s*\([^)]*\)\s*external\s*(?!.*onlyOwner)",
            r"function\s+removeLiquidity\s*\(",
            # Reserve manipulation
            r"reserve0\s*=\s*",
            r"reserve1\s*=\s*",
            # K invariant issues
            r"k\s*=\s*reserve0\s*\*\s*reserve1",
        ],
        anti_patterns=[
            # K invariant check
            r"require\s*\(\s*newK\s*>=\s*k\s*\)",
            r"require\s*\(\s*balance0\s*\*\s*balance1\s*>=",
            # Access control
            r"onlyOwner",
            r"onlyRouter",
            r"onlyFactory",
        ],
        description=(
            "Liquidity pool vulnerable to drain attacks through "
            "invariant manipulation, skim function abuse, or "
            "unprotected withdrawal mechanisms."
        ),
        attack_example=(
            "1. Manipulate token balance (donation/skim)\n"
            "2. Break K invariant assumption\n"
            "3. Withdraw more than deposited\n"
            "4. Drain pool reserves"
        ),
        real_exploits=[
            "Pancake Bunny ($45M, 2021)",
            "ValueDeFi ($10M, 2020)",
        ],
        remediation=(
            "Verify K invariant after every swap/deposit/withdraw. "
            "Protect skim/sync with access control or remove entirely. "
            "Add deposit/withdrawal delays for large amounts. "
            "Implement circuit breakers for unusual activity."
        ),
        swc_id=None,
        estimated_loss_usd="$100M+",
    ),

    # =========================================================================
    # REWARD MANIPULATION (Token Distribution Attack)
    # =========================================================================
    DeFiVulnType.REWARD_MANIPULATION: DeFiVulnerabilityPattern(
        vuln_type=DeFiVulnType.REWARD_MANIPULATION,
        name="Staking Reward Manipulation",
        severity="high",
        indicators=[
            # Reward per token calculation
            r"rewardPerToken\s*=\s*",
            r"reward\s*/\s*totalSupply",
            r"accRewardPerShare\s*\+\s*",
            # No minimum stake time
            r"stake\s*\([^)]*\).*unstake",
            r"deposit\s*\([^)]*\).*withdraw",
            # Same-block operations
            r"block\.timestamp",
            r"block\.number",
        ],
        anti_patterns=[
            # Lock period
            r"lockPeriod",
            r"unstakeLockTime",
            r"require\s*\(\s*block\.timestamp\s*>\s*stakeTime\s*\+",
            # Rate limiting
            r"cooldown",
            r"lastClaimTime",
        ],
        description=(
            "Staking/farming mechanism vulnerable to flash stake attacks. "
            "An attacker can stake large amounts just before rewards distribute, "
            "claim disproportionate rewards, then unstake immediately."
        ),
        attack_example=(
            "1. Wait for reward distribution block\n"
            "2. Flash loan large amount of stake tokens\n"
            "3. Stake (increases total supply)\n"
            "4. Trigger reward distribution\n"
            "5. Claim rewards (based on % of pool)\n"
            "6. Unstake and repay flash loan"
        ),
        real_exploits=[
            "Multiple yield farms (various amounts)",
            "Compound (bad debt from token distribution)",
        ],
        remediation=(
            "Implement minimum staking period (24-72 hours). "
            "Use checkpoints for reward calculation. "
            "Add cooldown between stake and reward claim. "
            "Consider streaming rewards (per-second distribution)."
        ),
        swc_id=None,
        estimated_loss_usd="$50M+",
    ),

    # =========================================================================
    # DONATION ATTACK (ERC4626 Vault Attack)
    # =========================================================================
    DeFiVulnType.DONATION_ATTACK: DeFiVulnerabilityPattern(
        vuln_type=DeFiVulnType.DONATION_ATTACK,
        name="Vault Donation/Inflation Attack",
        severity="high",
        indicators=[
            # ERC4626 without protection
            r"convertToShares\s*\(",
            r"convertToAssets\s*\(",
            r"totalAssets\s*\(\s*\)",
            r"asset\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
            # Share calculation
            r"shares\s*=\s*assets\s*\*\s*totalSupply\s*/\s*totalAssets",
            r"assets\s*\*\s*_totalSupply\s*/",
        ],
        anti_patterns=[
            # Virtual shares/assets offset
            r"virtualAssets",
            r"virtualShares",
            r"DECIMALS_OFFSET",
            r"\+\s*1\s*\)",  # Adding 1 to prevent rounding
            # Initial deposit
            r"if\s*\(\s*totalSupply\s*==\s*0\s*\)",
            r"_initialConvertToShares",
        ],
        description=(
            "ERC4626 vault vulnerable to first-depositor donation attack. "
            "Attacker can donate assets to inflate share price, then "
            "steal from subsequent depositors through rounding."
        ),
        attack_example=(
            "1. Be first depositor with 1 wei\n"
            "2. Donate 1e18 tokens to vault directly\n"
            "3. Share price = 1e18 + 1\n"
            "4. Next user deposits 2e18 tokens\n"
            "5. They get 1 share (rounds down from 1.99)\n"
            "6. Attacker withdraws, gets ~1.5e18\n"
            "7. Victim lost ~0.5e18"
        ),
        real_exploits=[
            "Multiple ERC4626 vaults (theoretical and exploited)",
        ],
        remediation=(
            "Use virtual shares/assets offset (OpenZeppelin pattern). "
            "Send initial 'dead shares' to zero address. "
            "Enforce minimum first deposit. "
            "Add decimal offset to share calculation."
        ),
        swc_id=None,
        estimated_loss_usd="$10M+",
    ),

    # =========================================================================
    # INFLATION ATTACK
    # =========================================================================
    DeFiVulnType.INFLATION_ATTACK: DeFiVulnerabilityPattern(
        vuln_type=DeFiVulnType.INFLATION_ATTACK,
        name="Token Inflation Attack",
        severity="high",
        indicators=[
            # Mint without control
            r"_mint\s*\([^)]+\)",
            r"function\s+mint\s*\(",
            # Rebasing logic
            r"rebase\s*\(",
            r"totalSupply\s*=\s*",
            # Reward minting
            r"mintRewards\s*\(",
            r"_mintInflation\s*\(",
        ],
        anti_patterns=[
            # Caps and limits
            r"maxSupply",
            r"supplyCap",
            r"require\s*\(\s*totalSupply\s*\+\s*amount\s*<=",
            # Rate limiting
            r"inflationRate",
            r"maxMintPerBlock",
            # Timelock
            r"timeLock",
            r"lastMintTime",
        ],
        description=(
            "Token minting mechanism without proper caps or rate limiting. "
            "Can lead to hyperinflation, dilution of holders, or "
            "exploitation of mint functions."
        ),
        attack_example=(
            "1. Compromise mint role or exploit mint vulnerability\n"
            "2. Mint unlimited tokens\n"
            "3. Dump on market before detection\n"
            "4. Token value approaches zero"
        ),
        real_exploits=[
            "Cover Protocol ($4M, 2020)",
            "Paid Network ($180M, 2021)",
        ],
        remediation=(
            "Implement hard supply caps. "
            "Use timelock for significant mints. "
            "Limit mint rate per block/day. "
            "Consider deflationary tokenomics. "
            "Multi-sig for mint role."
        ),
        swc_id=None,
        estimated_loss_usd="$200M+",
    ),
}


class DeFiPatternDetector:
    """
    Detector for DeFi-specific vulnerability patterns.

    Usage:
        detector = DeFiPatternDetector()
        matches = detector.analyze_code(solidity_code)
        for match in matches:
            print(f"{match.pattern.name}: {match.confidence}")
    """

    def __init__(
        self,
        enabled_patterns: Optional[Set[DeFiVulnType]] = None,
        min_confidence: float = 0.3,
    ):
        """
        Initialize the DeFi pattern detector.

        Args:
            enabled_patterns: Set of patterns to check (default: all)
            min_confidence: Minimum confidence to report (0.0-1.0)
        """
        self.enabled_patterns = enabled_patterns or set(DEFI_VULNERABILITY_PATTERNS.keys())
        self.min_confidence = min_confidence

        # Pre-compile regex patterns
        self._compiled_patterns: Dict[DeFiVulnType, Dict[str, List[re.Pattern]]] = {}
        self._compile_patterns()

        logger.info(
            f"DeFiPatternDetector initialized with {len(self.enabled_patterns)} patterns"
        )

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for vuln_type, pattern in DEFI_VULNERABILITY_PATTERNS.items():
            if vuln_type not in self.enabled_patterns:
                continue

            self._compiled_patterns[vuln_type] = {
                "indicators": [
                    re.compile(p, re.IGNORECASE | re.MULTILINE)
                    for p in pattern.indicators
                ],
                "anti_patterns": [
                    re.compile(p, re.IGNORECASE | re.MULTILINE)
                    for p in pattern.anti_patterns
                ],
            }

    def analyze_code(
        self,
        code: str,
        file_path: Optional[str] = None,
    ) -> List[DeFiPatternMatch]:
        """
        Analyze Solidity code for DeFi vulnerability patterns.

        Args:
            code: Solidity source code
            file_path: Optional path for location info

        Returns:
            List of pattern matches
        """
        matches = []

        for vuln_type, compiled in self._compiled_patterns.items():
            pattern_def = DEFI_VULNERABILITY_PATTERNS[vuln_type]

            # Find indicator matches
            indicator_matches: List[Tuple[str, str]] = []
            for regex in compiled["indicators"]:
                for match in regex.finditer(code):
                    indicator_matches.append((regex.pattern, match.group(0)))

            if not indicator_matches:
                continue

            # Find anti-pattern matches (protective measures)
            anti_matches: List[Tuple[str, str]] = []
            for regex in compiled["anti_patterns"]:
                for match in regex.finditer(code):
                    anti_matches.append((regex.pattern, match.group(0)))

            # Calculate confidence
            confidence = self._calculate_confidence(
                indicator_matches, anti_matches, pattern_def
            )

            if confidence < self.min_confidence:
                continue

            # Determine if actually vulnerable (indicators without sufficient protection)
            is_vulnerable = len(indicator_matches) > len(anti_matches)

            # Extract location (first indicator match)
            first_match_text = indicator_matches[0][1]
            line_number = self._find_line_number(code, first_match_text)

            # Extract code snippet around the match
            snippet = self._extract_snippet(code, first_match_text)

            matches.append(DeFiPatternMatch(
                pattern=pattern_def,
                matched_indicators=indicator_matches,
                matched_anti_patterns=anti_matches,
                confidence=confidence,
                location={
                    "file": file_path or "unknown",
                    "line": line_number,
                    "pattern_type": vuln_type.value,
                },
                code_snippet=snippet,
                is_vulnerable=is_vulnerable,
                recommendation=pattern_def.remediation,
            ))

        # Sort by confidence (highest first)
        matches.sort(key=lambda m: -m.confidence)

        return matches

    def _calculate_confidence(
        self,
        indicators: List[Tuple[str, str]],
        anti_patterns: List[Tuple[str, str]],
        pattern: DeFiVulnerabilityPattern,
    ) -> float:
        """
        Calculate confidence score for a pattern match.

        Higher confidence when:
        - More indicators match
        - Fewer anti-patterns found
        - Pattern is critical severity
        """
        # Base confidence from indicator count
        total_indicators = len(pattern.indicators)
        matched_indicators = len(indicators)
        indicator_ratio = matched_indicators / max(total_indicators, 1)

        # Penalty for anti-patterns (protective measures found)
        anti_penalty = min(0.4, len(anti_patterns) * 0.1)

        # Severity boost
        severity_boost = {
            "critical": 0.1,
            "high": 0.05,
            "medium": 0.0,
            "low": -0.05,
        }.get(pattern.severity, 0)

        confidence = (indicator_ratio * 0.7) - anti_penalty + severity_boost + 0.2
        return max(0.0, min(1.0, confidence))

    def _find_line_number(self, code: str, match_text: str) -> int:
        """Find line number of matched text in code."""
        try:
            pos = code.find(match_text)
            if pos >= 0:
                return code[:pos].count('\n') + 1
        except Exception:
            pass
        return 0

    def _extract_snippet(self, code: str, match_text: str, context_lines: int = 3) -> str:
        """Extract code snippet around the match."""
        try:
            lines = code.split('\n')
            pos = code.find(match_text)
            if pos >= 0:
                line_num = code[:pos].count('\n')
                start = max(0, line_num - context_lines)
                end = min(len(lines), line_num + context_lines + 1)
                return '\n'.join(lines[start:end])
        except Exception:
            pass
        return match_text

    def get_pattern_info(self, vuln_type: DeFiVulnType) -> Optional[DeFiVulnerabilityPattern]:
        """Get detailed information about a specific pattern."""
        return DEFI_VULNERABILITY_PATTERNS.get(vuln_type)

    def get_all_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Get summary of all patterns for documentation."""
        result = {}
        for vuln_type, pattern in DEFI_VULNERABILITY_PATTERNS.items():
            result[vuln_type.value] = {
                "name": pattern.name,
                "severity": pattern.severity,
                "description": pattern.description,
                "real_exploits": pattern.real_exploits,
                "estimated_loss": pattern.estimated_loss_usd,
                "indicator_count": len(pattern.indicators),
                "remediation": pattern.remediation,
            }
        return result


# Convenience function
def detect_defi_vulnerabilities(
    code: str,
    min_confidence: float = 0.3,
) -> List[DeFiPatternMatch]:
    """
    Quick function to detect DeFi vulnerabilities in code.

    Args:
        code: Solidity source code
        min_confidence: Minimum confidence to report

    Returns:
        List of pattern matches
    """
    detector = DeFiPatternDetector(min_confidence=min_confidence)
    return detector.analyze_code(code)


# Export
__all__ = [
    "DeFiVulnType",
    "DeFiVulnerabilityPattern",
    "DeFiPatternMatch",
    "DeFiPatternDetector",
    "DEFI_VULNERABILITY_PATTERNS",
    "detect_defi_vulnerabilities",
]
