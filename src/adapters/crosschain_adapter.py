"""
Cross-Chain Security Adapter - Bridge and Multi-Chain Vulnerability Detection.

Based on research:
- "SmartAxe: Detecting Cross-chain Vulnerabilities in Bridge Contracts" (NDSS 2024)
- "BridgeGuard: Security Analysis of Cross-Chain Bridges" (IEEE S&P 2024)
- "Xscope: Hunting for Cross-chain Bridge Attacks" (USENIX Security 2023)

Vulnerability categories detected:
- Bridge logic vulnerabilities
- Cross-chain message manipulation
- State inconsistency attacks
- Token bridge exploits
- Cross-chain MEV/arbitrage
- Oracle manipulation in bridges
- Replay attacks across chains
- Insufficient verification

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-15
"""

from src.core.tool_protocol import (
    ToolAdapter,
    ToolMetadata,
    ToolStatus,
    ToolCategory,
    ToolCapability
)
from typing import Dict, Any, List, Optional, Set, Tuple
import logging
import re
import time
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class BridgeType(Enum):
    """Types of cross-chain bridges."""
    LOCK_MINT = "lock_mint"  # Lock on source, mint on destination
    BURN_MINT = "burn_mint"  # Burn on source, mint on destination
    LIQUIDITY_POOL = "liquidity_pool"  # Liquidity-based swaps
    MESSAGE_PASSING = "message_passing"  # Generic message relaying
    ROLLUP = "rollup"  # L1-L2 bridges
    UNKNOWN = "unknown"


# Cross-chain vulnerability patterns
CROSSCHAIN_VULNERABILITY_PATTERNS = {
    "insufficient_verification": {
        "severity": "CRITICAL",
        "description": "Cross-chain message or transaction not properly verified",
        "cwe": "CWE-345",
        "impact": "Attackers can forge messages to drain bridge funds",
        "examples": [
            "Missing signature verification",
            "Weak merkle proof validation",
            "Insufficient multi-sig checks"
        ]
    },
    "replay_attack": {
        "severity": "CRITICAL",
        "description": "Cross-chain transaction can be replayed on different chain or multiple times",
        "cwe": "CWE-294",
        "impact": "Double-spending, fund drainage",
        "examples": [
            "Missing nonce tracking",
            "Reusable signatures",
            "No chain ID validation"
        ]
    },
    "state_inconsistency": {
        "severity": "HIGH",
        "description": "State between source and destination chains can become inconsistent",
        "cwe": "CWE-362",
        "impact": "Fund loss, protocol insolvency",
        "examples": [
            "Race conditions in deposits/withdrawals",
            "Incomplete finality checks",
            "Missing rollback handling"
        ]
    },
    "oracle_manipulation": {
        "severity": "HIGH",
        "description": "Cross-chain oracle or relayer can be manipulated",
        "cwe": "CWE-346",
        "impact": "Price manipulation, false attestations",
        "examples": [
            "Single oracle dependency",
            "Insufficient oracle consensus",
            "Stale oracle data"
        ]
    },
    "bridge_fund_drainage": {
        "severity": "CRITICAL",
        "description": "Bridge contract funds can be drained",
        "cwe": "CWE-284",
        "impact": "Complete loss of bridged assets",
        "examples": [
            "Unauthorized withdrawals",
            "Infinite minting",
            "Arbitrary token transfers"
        ]
    },
    "token_mismatch": {
        "severity": "HIGH",
        "description": "Token accounting mismatch between chains",
        "cwe": "CWE-682",
        "impact": "Token inflation, protocol insolvency",
        "examples": [
            "Decimal mismatch",
            "Fee calculation errors",
            "Supply desync"
        ]
    },
    "cross_chain_mev": {
        "severity": "MEDIUM",
        "description": "Cross-chain MEV or arbitrage vulnerability",
        "cwe": "CWE-754",
        "impact": "Value extraction, unfair advantage",
        "examples": [
            "Front-running bridge transactions",
            "Sandwich attacks across chains",
            "Delayed finality exploitation"
        ]
    },
    "relayer_trust": {
        "severity": "HIGH",
        "description": "Excessive trust in relayers or validators",
        "cwe": "CWE-306",
        "impact": "Malicious relayers can forge transactions",
        "examples": [
            "Single trusted relayer",
            "No slashing mechanism",
            "Insufficient stake requirements"
        ]
    },
    "finality_assumption": {
        "severity": "HIGH",
        "description": "Incorrect assumptions about transaction finality",
        "cwe": "CWE-682",
        "impact": "Reorganization attacks, double-spending",
        "examples": [
            "Insufficient confirmations",
            "No reorg handling",
            "Optimistic acceptance"
        ]
    },
    "emergency_withdrawal": {
        "severity": "MEDIUM",
        "description": "Missing or vulnerable emergency withdrawal mechanism",
        "cwe": "CWE-693",
        "impact": "Fund lock or unauthorized emergency access",
        "examples": [
            "No pause mechanism",
            "Weak emergency access control",
            "Missing timelock"
        ]
    }
}

# Known bridge patterns (for detection)
BRIDGE_PATTERNS = {
    "deposit": ["deposit", "lock", "bridgeTo", "sendTo", "transfer"],
    "withdraw": ["withdraw", "unlock", "claim", "redeem", "mint"],
    "verify": ["verify", "validate", "checkProof", "attestation"],
    "relay": ["relay", "execute", "fulfill", "process"],
    "oracle": ["oracle", "validator", "attestor", "relayer", "messenger"]
}


class CrossChainAdapter(ToolAdapter):
    """
    Cross-Chain Security Adapter for bridge and multi-chain analysis.

    Analyzes Solidity contracts for cross-chain vulnerabilities including:
    - Bridge logic issues
    - Message passing security
    - State synchronization problems
    - Cross-chain MEV vectors
    """

    def __init__(self):
        super().__init__()
        self._supported_chains = {
            "ethereum", "polygon", "arbitrum", "optimism", "avalanche",
            "bsc", "fantom", "base", "zksync", "linea", "scroll"
        }

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="crosschain_analyzer",
            version="1.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Fernando Boiero (Cross-chain security research)",
            license="AGPL-3.0",
            homepage="https://github.com/miesc/crosschain-analyzer",
            repository="https://github.com/miesc/crosschain-analyzer",
            documentation="docs/crosschain-security.md",
            installation_cmd="pip install miesc[crosschain]",
            capabilities=[
                ToolCapability(
                    name="bridge_analysis",
                    description="Analyze bridge contracts for common vulnerabilities",
                    supported_languages=["solidity"],
                    detection_types=[
                        "insufficient_verification",
                        "replay_attack",
                        "fund_drainage",
                        "token_mismatch"
                    ]
                ),
                ToolCapability(
                    name="message_passing_security",
                    description="Analyze cross-chain message passing security",
                    supported_languages=["solidity"],
                    detection_types=[
                        "oracle_manipulation",
                        "relayer_trust",
                        "finality_assumption"
                    ]
                ),
                ToolCapability(
                    name="crosschain_mev",
                    description="Detect cross-chain MEV and arbitrage vectors",
                    supported_languages=["solidity"],
                    detection_types=["cross_chain_mev", "state_inconsistency"]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Cross-chain analyzer is always available (pattern-based)."""
        return ToolStatus.AVAILABLE

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract for cross-chain vulnerabilities.

        Args:
            contract_path: Path to the Solidity contract
            **kwargs: Additional options (detect_bridge_type, deep_analysis)

        Returns:
            Analysis results with findings
        """
        start_time = time.time()

        try:
            # Read contract
            code = self._read_file(contract_path)
            if not code:
                return self._error_result(start_time, f"Could not read: {contract_path}")

            # Detect if this is a bridge/cross-chain contract
            is_bridge = self._detect_bridge_contract(code)
            bridge_type = self._detect_bridge_type(code) if is_bridge else BridgeType.UNKNOWN

            all_findings = []

            if is_bridge:
                logger.info(f"Detected bridge contract (type: {bridge_type.value})")

                # Run comprehensive bridge analysis
                all_findings.extend(self._analyze_verification(code, contract_path))
                all_findings.extend(self._analyze_replay_protection(code, contract_path))
                all_findings.extend(self._analyze_state_consistency(code, contract_path))
                all_findings.extend(self._analyze_oracle_security(code, contract_path))
                all_findings.extend(self._analyze_fund_security(code, contract_path))
                all_findings.extend(self._analyze_token_handling(code, contract_path))
                all_findings.extend(self._analyze_emergency_mechanisms(code, contract_path))
            else:
                logger.info("Contract may interact with bridges - checking for common issues")
                # Limited analysis for contracts that may interact with bridges
                all_findings.extend(self._analyze_bridge_interactions(code, contract_path))

            # Deduplicate
            findings = self._deduplicate_findings(all_findings)

            return {
                "tool": "crosschain_analyzer",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "is_bridge_contract": is_bridge,
                    "bridge_type": bridge_type.value,
                    "chain_references": self._find_chain_references(code),
                    "bridge_patterns_found": self._count_bridge_patterns(code)
                },
                "execution_time": time.time() - start_time
            }

        except Exception as e:
            logger.error(f"Cross-chain analysis error: {e}", exc_info=True)
            return self._error_result(start_time, str(e))

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize findings."""
        return raw_output.get("findings", []) if isinstance(raw_output, dict) else []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if this adapter can analyze the file."""
        return Path(contract_path).suffix == '.sol'

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "timeout": 120,
            "detect_bridge_type": True,
            "deep_analysis": True
        }

    # ============================================================================
    # PRIVATE METHODS
    # ============================================================================

    def _error_result(self, start_time: float, error: str) -> Dict[str, Any]:
        """Create error result."""
        return {
            "tool": "crosschain_analyzer",
            "version": "1.0.0",
            "status": "error",
            "findings": [],
            "execution_time": time.time() - start_time,
            "error": error
        }

    def _read_file(self, path: str) -> Optional[str]:
        """Read file content."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return None

    def _detect_bridge_contract(self, code: str) -> bool:
        """Detect if contract is a bridge or cross-chain contract."""
        code_lower = code.lower()

        # Bridge indicators
        indicators = [
            "bridge", "crosschain", "cross-chain", "multichain",
            "layerzero", "axelar", "wormhole", "chainlink ccip",
            "arbitrum bridge", "optimism portal", "polygon bridge",
            "deposit(", "withdraw(", "relay(", "execute(",
            "sourcechain", "destchain", "targetchain"
        ]

        matches = sum(1 for ind in indicators if ind in code_lower)
        return matches >= 2  # At least 2 indicators

    def _detect_bridge_type(self, code: str) -> BridgeType:
        """Detect the type of bridge."""
        code_lower = code.lower()

        if "lock" in code_lower and "mint" in code_lower:
            return BridgeType.LOCK_MINT
        elif "burn" in code_lower and "mint" in code_lower:
            return BridgeType.BURN_MINT
        elif "liquidity" in code_lower or "pool" in code_lower:
            return BridgeType.LIQUIDITY_POOL
        elif "rollup" in code_lower or "l2" in code_lower:
            return BridgeType.ROLLUP
        elif "message" in code_lower or "relay" in code_lower:
            return BridgeType.MESSAGE_PASSING

        return BridgeType.UNKNOWN

    def _find_chain_references(self, code: str) -> List[str]:
        """Find references to specific chains."""
        code_lower = code.lower()
        found = []

        for chain in self._supported_chains:
            if chain in code_lower:
                found.append(chain)

        return found

    def _count_bridge_patterns(self, code: str) -> Dict[str, int]:
        """Count occurrences of bridge-related patterns."""
        code_lower = code.lower()
        counts = {}

        for category, patterns in BRIDGE_PATTERNS.items():
            counts[category] = sum(
                1 for pattern in patterns
                if pattern.lower() in code_lower
            )

        return counts

    def _analyze_verification(self, code: str, contract_path: str) -> List[Dict[str, Any]]:
        """Analyze verification mechanisms."""
        findings = []
        lines = code.splitlines()

        # Check for signature verification
        has_signature_check = any(
            kw in code.lower() for kw in
            ["ecrecover", "verify", "checksignature", "eip712", "ecdsa"]
        )

        # Check for merkle proof
        has_merkle_proof = "merkle" in code.lower() or "proof" in code.lower()

        # Check for multisig
        has_multisig = any(
            kw in code.lower() for kw in
            ["multisig", "threshold", "required", "confirmations"]
        )

        # Vulnerability: No verification mechanism
        if not has_signature_check and not has_merkle_proof:
            findings.append(self._create_finding(
                "insufficient_verification",
                "No signature or proof verification detected",
                contract_path,
                "Critical functions should verify cross-chain messages with signatures or proofs"
            ))

        # Check for weak verification patterns
        for i, line in enumerate(lines, 1):
            # Direct trust of msg.sender in bridge context
            if "msg.sender" in line and any(p in line.lower() for p in ["bridge", "relay", "execute"]):
                if "require" not in line and "onlyowner" not in line.lower():
                    findings.append(self._create_finding(
                        "insufficient_verification",
                        "Bridge function may trust msg.sender without verification",
                        contract_path,
                        "Verify the origin of cross-chain messages",
                        line_number=i,
                        line_content=line.strip()
                    ))

        return findings

    def _analyze_replay_protection(self, code: str, contract_path: str) -> List[Dict[str, Any]]:
        """Analyze replay attack protection."""
        findings = []

        code_lower = code.lower()

        # Check for nonce usage
        has_nonce = "nonce" in code_lower

        # Check for chain ID validation
        has_chainid = "chainid" in code_lower or "chain_id" in code_lower or "block.chainid" in code

        # Check for message hash tracking
        has_message_tracking = any(
            kw in code_lower for kw in
            ["processed", "executed", "completed", "usedmessages", "usedhashes"]
        )

        # Vulnerability: No replay protection
        if not has_nonce and not has_message_tracking:
            findings.append(self._create_finding(
                "replay_attack",
                "No nonce or message tracking for replay protection",
                contract_path,
                "Implement nonce tracking or message hash storage to prevent replays"
            ))

        # Vulnerability: No chain ID validation
        if not has_chainid:
            findings.append(self._create_finding(
                "replay_attack",
                "No chain ID validation detected",
                contract_path,
                "Include chain ID in message hashes to prevent cross-chain replays"
            ))

        return findings

    def _analyze_state_consistency(self, code: str, contract_path: str) -> List[Dict[str, Any]]:
        """Analyze state consistency between chains."""
        findings = []
        lines = code.splitlines()

        # Check for atomic operations
        has_reentrancy_guard = any(
            kw in code.lower() for kw in
            ["nonreentrant", "reentrancyguard", "mutex", "_status"]
        )

        # Check for finality considerations
        has_finality_check = any(
            kw in code.lower() for kw in
            ["finalized", "confirmations", "finality", "blocknumber"]
        )

        # Look for state updates before external calls
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            if any(call in line_lower for call in [".call(", ".send(", ".transfer("]):
                # Check if there's a state update after
                if i < len(lines) - 1:
                    next_lines = " ".join(lines[i:min(i+5, len(lines))]).lower()
                    if any(update in next_lines for update in ["mapping[", "balance", "amount", "="]):
                        if not has_reentrancy_guard:
                            findings.append(self._create_finding(
                                "state_inconsistency",
                                "State update after external call without reentrancy guard",
                                contract_path,
                                "Use reentrancy guards or checks-effects-interactions pattern",
                                line_number=i,
                                line_content=line.strip()
                            ))

        # Vulnerability: No finality check
        if not has_finality_check and "withdraw" in code.lower():
            findings.append(self._create_finding(
                "finality_assumption",
                "No finality check before allowing withdrawals",
                contract_path,
                "Consider requiring minimum confirmations before processing withdrawals"
            ))

        return findings

    def _analyze_oracle_security(self, code: str, contract_path: str) -> List[Dict[str, Any]]:
        """Analyze oracle and relayer security."""
        findings = []

        code_lower = code.lower()

        # Check for oracle usage
        has_oracle = any(kw in code_lower for kw in ["oracle", "validator", "relayer", "attestor"])

        if has_oracle:
            # Check for multi-oracle consensus
            has_consensus = any(
                kw in code_lower for kw in
                ["threshold", "quorum", "majority", "required"]
            )

            if not has_consensus:
                findings.append(self._create_finding(
                    "oracle_manipulation",
                    "Single oracle/relayer dependency detected",
                    contract_path,
                    "Implement multi-oracle consensus with threshold voting"
                ))

            # Check for oracle staking/slashing
            has_staking = "stake" in code_lower or "slash" in code_lower

            if not has_staking:
                findings.append(self._create_finding(
                    "relayer_trust",
                    "No staking/slashing mechanism for validators",
                    contract_path,
                    "Consider requiring validator stake with slashing for misbehavior"
                ))

        return findings

    def _analyze_fund_security(self, code: str, contract_path: str) -> List[Dict[str, Any]]:
        """Analyze fund security in bridge."""
        findings = []
        lines = code.splitlines()

        # Look for dangerous patterns
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()

            # Arbitrary external calls with value
            if ".call{value:" in line or "transfer(" in line or "send(" in line:
                # Check if amount is user-controlled
                if "msg.value" in line or "amount" in line:
                    if "require" not in line and "assert" not in line:
                        findings.append(self._create_finding(
                            "bridge_fund_drainage",
                            "Value transfer without validation",
                            contract_path,
                            "Validate transfer amounts against internal accounting",
                            line_number=i,
                            line_content=line.strip()
                        ))

            # Arbitrary minting
            if "_mint(" in line.lower() and "only" not in line.lower():
                findings.append(self._create_finding(
                    "bridge_fund_drainage",
                    "Minting without apparent access control",
                    contract_path,
                    "Ensure minting is restricted to verified bridge operations",
                    line_number=i,
                    line_content=line.strip()
                ))

        return findings

    def _analyze_token_handling(self, code: str, contract_path: str) -> List[Dict[str, Any]]:
        """Analyze token handling for mismatches."""
        findings = []

        code_lower = code.lower()

        # Check for decimal handling
        has_decimal_handling = "decimals" in code_lower

        if has_decimal_handling:
            # Check for proper normalization
            if "10 **" not in code and "10**" not in code:
                findings.append(self._create_finding(
                    "token_mismatch",
                    "Decimal handling without proper normalization",
                    contract_path,
                    "Ensure proper decimal scaling between chains (e.g., 10**decimals)"
                ))

        # Check for fee calculation
        has_fee = "fee" in code_lower
        if has_fee:
            # Look for potential fee issues
            if "/ 100" in code or "/100" in code:
                if "round" not in code_lower:
                    findings.append(self._create_finding(
                        "token_mismatch",
                        "Fee calculation may have rounding issues",
                        contract_path,
                        "Consider rounding direction and dust amounts in fee calculations"
                    ))

        return findings

    def _analyze_emergency_mechanisms(self, code: str, contract_path: str) -> List[Dict[str, Any]]:
        """Analyze emergency withdrawal and pause mechanisms."""
        findings = []

        code_lower = code.lower()

        # Check for pause mechanism
        has_pause = any(kw in code_lower for kw in ["pause", "whennotpaused", "pausable"])

        # Check for emergency withdrawal
        has_emergency = any(kw in code_lower for kw in ["emergency", "rescue", "recover"])

        # Check for timelock
        has_timelock = any(kw in code_lower for kw in ["timelock", "delay", "waiting"])

        if not has_pause:
            findings.append(self._create_finding(
                "emergency_withdrawal",
                "No pause mechanism detected",
                contract_path,
                "Implement pausable functionality for emergency situations"
            ))

        if not has_emergency:
            findings.append(self._create_finding(
                "emergency_withdrawal",
                "No emergency withdrawal mechanism",
                contract_path,
                "Consider adding emergency fund recovery for stuck assets"
            ))

        if has_emergency and not has_timelock:
            findings.append(self._create_finding(
                "emergency_withdrawal",
                "Emergency mechanism without timelock",
                contract_path,
                "Add timelock to emergency functions to prevent abuse"
            ))

        return findings

    def _analyze_bridge_interactions(self, code: str, contract_path: str) -> List[Dict[str, Any]]:
        """Analyze contracts that interact with bridges (not bridges themselves)."""
        findings = []

        code_lower = code.lower()

        # Check for callback handling
        if "callback" in code_lower or "receive" in code_lower:
            if "verify" not in code_lower:
                findings.append(self._create_finding(
                    "insufficient_verification",
                    "Cross-chain callback without source verification",
                    contract_path,
                    "Verify the source of cross-chain callbacks"
                ))

        return findings

    def _create_finding(
        self,
        category: str,
        title: str,
        contract_path: str,
        recommendation: str,
        line_number: Optional[int] = None,
        line_content: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a finding dictionary."""
        vuln_info = CROSSCHAIN_VULNERABILITY_PATTERNS.get(category, {})

        location = {"file": contract_path}
        if line_number:
            location["line"] = line_number
        if line_content:
            location["details"] = line_content

        return {
            "id": f"crosschain-{category}-{hash(title) % 10000}",
            "title": title,
            "description": vuln_info.get("description", title),
            "severity": vuln_info.get("severity", "MEDIUM"),
            "confidence": 0.75,
            "category": category,
            "cwe": vuln_info.get("cwe", ""),
            "location": location,
            "impact": vuln_info.get("impact", ""),
            "recommendation": recommendation,
            "source": "crosschain_analyzer"
        }

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings."""
        seen = set()
        unique = []

        for finding in findings:
            key = (finding.get("category", ""), finding.get("title", ""))
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        unique.sort(key=lambda f: severity_order.get(f.get("severity", "LOW"), 4))

        return unique


__all__ = ["CrossChainAdapter", "BridgeType", "CROSSCHAIN_VULNERABILITY_PATTERNS"]
