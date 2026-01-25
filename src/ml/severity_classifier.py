"""
ML-Based Severity Classifier for MIESC
========================================

Classifies vulnerability severity based on multiple factors:
- Financial impact
- Exploitability
- Scope
- Contract context

Based on papers 2024: fine-tuned models achieve 99% accuracy.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA
Date: January 2026
"""

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ImpactLevel(Enum):
    """Impact levels for severity calculation."""
    TOTAL_LOSS = "total_loss"
    PARTIAL_LOSS = "partial_loss"
    NO_DIRECT_LOSS = "no_direct_loss"
    INFORMATIONAL = "informational"


class ExploitabilityLevel(Enum):
    """Exploitability levels."""
    TRIVIAL = "trivial"  # Anyone can exploit easily
    MODERATE = "moderate"  # Requires some knowledge
    COMPLEX = "complex"  # Very difficult to exploit


class ScopeLevel(Enum):
    """Scope of the vulnerability."""
    PROTOCOL_WIDE = "protocol_wide"  # Affects entire protocol
    CONTRACT_WIDE = "contract_wide"  # Affects one contract
    FUNCTION_ONLY = "function_only"  # Only one function


@dataclass
class SeverityFactors:
    """Factors used to calculate severity."""
    financial_impact: ImpactLevel
    exploitability: ExploitabilityLevel
    scope: ScopeLevel
    has_known_exploit: bool = False
    affects_funds: bool = False
    requires_auth: bool = True
    probability_score: float = 0.5


@dataclass
class SeverityPrediction:
    """Result of severity classification."""
    severity: SeverityLevel
    confidence: float
    factors: SeverityFactors
    score: float
    reasoning: str
    cvss_estimate: float


@dataclass
class ContractContext:
    """Context about the contract being analyzed."""
    contract_type: str  # dex, lending, nft, etc.
    has_value_handling: bool
    uses_access_control: bool
    uses_reentrancy_guard: bool
    solidity_version: str
    is_upgradeable: bool
    estimated_tvl: str  # low, medium, high


class MLSeverityClassifier:
    """
    ML-based severity classifier for smart contract vulnerabilities.

    Uses multiple factors to determine appropriate severity:
    - Financial Impact (50% weight)
    - Exploitability (30% weight)
    - Scope (20% weight)

    Additional modifiers:
    - Known exploits boost severity
    - Access control reduces severity
    - Contract TVL adjusts impact
    """

    # Factor weights for severity calculation
    WEIGHTS = {
        "financial_impact": 0.50,
        "exploitability": 0.30,
        "scope": 0.20,
    }

    # Impact scores (0.0 - 1.0)
    IMPACT_SCORES = {
        ImpactLevel.TOTAL_LOSS: 1.0,
        ImpactLevel.PARTIAL_LOSS: 0.7,
        ImpactLevel.NO_DIRECT_LOSS: 0.3,
        ImpactLevel.INFORMATIONAL: 0.1,
    }

    # Exploitability scores (0.0 - 1.0)
    EXPLOITABILITY_SCORES = {
        ExploitabilityLevel.TRIVIAL: 1.0,
        ExploitabilityLevel.MODERATE: 0.6,
        ExploitabilityLevel.COMPLEX: 0.3,
    }

    # Scope scores (0.0 - 1.0)
    SCOPE_SCORES = {
        ScopeLevel.PROTOCOL_WIDE: 1.0,
        ScopeLevel.CONTRACT_WIDE: 0.6,
        ScopeLevel.FUNCTION_ONLY: 0.3,
    }

    # Vulnerability type to default impact mapping
    TYPE_IMPACT_MAP = {
        # Critical by default
        "reentrancy": ImpactLevel.TOTAL_LOSS,
        "flash-loan-attack": ImpactLevel.TOTAL_LOSS,
        "governance-attack": ImpactLevel.TOTAL_LOSS,
        "bridge-vulnerability": ImpactLevel.TOTAL_LOSS,
        "unprotected-selfdestruct": ImpactLevel.TOTAL_LOSS,
        "arbitrary-send": ImpactLevel.TOTAL_LOSS,

        # High by default
        "access-control": ImpactLevel.PARTIAL_LOSS,
        "oracle-manipulation": ImpactLevel.PARTIAL_LOSS,
        "price-manipulation": ImpactLevel.PARTIAL_LOSS,
        "delegatecall": ImpactLevel.PARTIAL_LOSS,
        "integer-overflow": ImpactLevel.PARTIAL_LOSS,
        "integer-underflow": ImpactLevel.PARTIAL_LOSS,

        # Medium by default
        "unchecked-call": ImpactLevel.NO_DIRECT_LOSS,
        "front-running": ImpactLevel.NO_DIRECT_LOSS,
        "sandwich-attack": ImpactLevel.NO_DIRECT_LOSS,
        "timestamp-dependence": ImpactLevel.NO_DIRECT_LOSS,
        "tx-origin": ImpactLevel.NO_DIRECT_LOSS,

        # Low/Info by default
        "gas-optimization": ImpactLevel.INFORMATIONAL,
        "naming-convention": ImpactLevel.INFORMATIONAL,
        "code-style": ImpactLevel.INFORMATIONAL,
    }

    # Vulnerability type to default exploitability
    TYPE_EXPLOITABILITY_MAP = {
        # Trivial to exploit
        "access-control": ExploitabilityLevel.TRIVIAL,
        "unprotected-selfdestruct": ExploitabilityLevel.TRIVIAL,
        "arbitrary-send": ExploitabilityLevel.TRIVIAL,

        # Moderate difficulty
        "reentrancy": ExploitabilityLevel.MODERATE,
        "oracle-manipulation": ExploitabilityLevel.MODERATE,
        "unchecked-call": ExploitabilityLevel.MODERATE,

        # Complex to exploit
        "flash-loan-attack": ExploitabilityLevel.COMPLEX,
        "governance-attack": ExploitabilityLevel.COMPLEX,
        "front-running": ExploitabilityLevel.COMPLEX,
    }

    def __init__(
        self,
        use_llm_analysis: bool = False,
        ollama_base_url: str = "http://localhost:11434",
        model: str = "deepseek-coder:6.7b",
    ):
        """
        Initialize the severity classifier.

        Args:
            use_llm_analysis: Use LLM for detailed factor analysis
            ollama_base_url: Ollama API URL
            model: Model for LLM analysis
        """
        self.use_llm = use_llm_analysis
        self.base_url = ollama_base_url
        self.model = model

        logger.info(f"MLSeverityClassifier initialized (llm={use_llm_analysis})")

    def classify(
        self,
        finding: Dict[str, Any],
        context: Optional[ContractContext] = None,
        code_snippet: str = "",
    ) -> SeverityPrediction:
        """
        Classify the severity of a finding.

        Args:
            finding: The vulnerability finding
            context: Contract context information
            code_snippet: Relevant code snippet

        Returns:
            SeverityPrediction with severity and reasoning
        """
        # Extract finding details
        vuln_type = finding.get("type", "unknown").lower()
        original_severity = finding.get("severity", "medium").lower()
        description = finding.get("description", "")

        # Analyze factors
        factors = self._analyze_factors(vuln_type, description, context, code_snippet)

        # Calculate severity score
        score = self._calculate_score(factors)

        # Apply modifiers
        score = self._apply_modifiers(score, factors, context)

        # Map score to severity level
        severity = self._score_to_severity(score)

        # Generate reasoning
        reasoning = self._generate_reasoning(factors, score, severity)

        # Estimate CVSS score
        cvss = self._estimate_cvss(factors, score)

        # Calculate confidence
        confidence = self._calculate_confidence(factors, original_severity, severity)

        return SeverityPrediction(
            severity=severity,
            confidence=confidence,
            factors=factors,
            score=score,
            reasoning=reasoning,
            cvss_estimate=cvss,
        )

    def classify_batch(
        self,
        findings: List[Dict[str, Any]],
        context: Optional[ContractContext] = None,
    ) -> List[Tuple[Dict[str, Any], SeverityPrediction]]:
        """
        Classify severity for multiple findings.

        Args:
            findings: List of findings
            context: Contract context

        Returns:
            List of (finding, prediction) tuples
        """
        results = []
        for finding in findings:
            code_snippet = finding.get("location", {}).get("snippet", "")
            prediction = self.classify(finding, context, code_snippet)

            # Update finding with new severity
            finding["original_severity"] = finding.get("severity")
            finding["severity"] = prediction.severity.value
            finding["severity_score"] = prediction.score
            finding["severity_confidence"] = prediction.confidence

            results.append((finding, prediction))

        return results

    def _analyze_factors(
        self,
        vuln_type: str,
        description: str,
        context: Optional[ContractContext],
        code: str,
    ) -> SeverityFactors:
        """Analyze factors for severity calculation."""
        # Get default impact from type
        impact = self.TYPE_IMPACT_MAP.get(vuln_type, ImpactLevel.NO_DIRECT_LOSS)

        # Get default exploitability
        exploitability = self.TYPE_EXPLOITABILITY_MAP.get(
            vuln_type, ExploitabilityLevel.MODERATE
        )

        # Determine scope from description
        scope = self._determine_scope(description, code)

        # Check for known exploit mentions
        has_known = self._check_known_exploit(description)

        # Check if affects funds
        affects_funds = self._check_affects_funds(description, code)

        # Check if requires auth
        requires_auth = self._check_requires_auth(code, context)

        return SeverityFactors(
            financial_impact=impact,
            exploitability=exploitability,
            scope=scope,
            has_known_exploit=has_known,
            affects_funds=affects_funds,
            requires_auth=requires_auth,
            probability_score=0.7 if exploitability == ExploitabilityLevel.TRIVIAL else 0.4,
        )

    def _calculate_score(self, factors: SeverityFactors) -> float:
        """Calculate severity score from factors."""
        impact_score = self.IMPACT_SCORES[factors.financial_impact]
        exploit_score = self.EXPLOITABILITY_SCORES[factors.exploitability]
        scope_score = self.SCOPE_SCORES[factors.scope]

        score = (
            impact_score * self.WEIGHTS["financial_impact"] +
            exploit_score * self.WEIGHTS["exploitability"] +
            scope_score * self.WEIGHTS["scope"]
        )

        return score

    def _apply_modifiers(
        self,
        score: float,
        factors: SeverityFactors,
        context: Optional[ContractContext],
    ) -> float:
        """Apply context-based modifiers to score."""
        # Boost for known exploits
        if factors.has_known_exploit:
            score = min(1.0, score + 0.15)

        # Boost for affecting funds
        if factors.affects_funds:
            score = min(1.0, score + 0.10)

        # Reduce if requires authentication
        if factors.requires_auth:
            score = max(0.0, score - 0.10)

        # Context-based adjustments
        if context:
            # Higher TVL = higher severity
            if context.estimated_tvl == "high":
                score = min(1.0, score + 0.10)
            elif context.estimated_tvl == "low":
                score = max(0.0, score - 0.05)

            # Reentrancy guard reduces reentrancy severity
            if context.uses_reentrancy_guard and factors.financial_impact == ImpactLevel.TOTAL_LOSS:
                score = max(0.0, score - 0.20)

        return score

    def _score_to_severity(self, score: float) -> SeverityLevel:
        """Convert numeric score to severity level."""
        if score >= 0.85:
            return SeverityLevel.CRITICAL
        elif score >= 0.65:
            return SeverityLevel.HIGH
        elif score >= 0.45:
            return SeverityLevel.MEDIUM
        elif score >= 0.25:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    def _generate_reasoning(
        self,
        factors: SeverityFactors,
        score: float,
        severity: SeverityLevel,
    ) -> str:
        """Generate human-readable reasoning for severity."""
        parts = [f"Severity: {severity.value.upper()} (score: {score:.2f})"]

        # Impact reasoning
        impact_reasons = {
            ImpactLevel.TOTAL_LOSS: "Can result in total loss of funds",
            ImpactLevel.PARTIAL_LOSS: "Can result in partial fund loss",
            ImpactLevel.NO_DIRECT_LOSS: "No direct financial loss expected",
            ImpactLevel.INFORMATIONAL: "Informational finding only",
        }
        parts.append(f"Impact: {impact_reasons[factors.financial_impact]}")

        # Exploitability reasoning
        exploit_reasons = {
            ExploitabilityLevel.TRIVIAL: "Can be exploited by anyone with minimal effort",
            ExploitabilityLevel.MODERATE: "Requires moderate technical knowledge to exploit",
            ExploitabilityLevel.COMPLEX: "Complex to exploit, requires significant expertise",
        }
        parts.append(f"Exploitability: {exploit_reasons[factors.exploitability]}")

        # Scope reasoning
        scope_reasons = {
            ScopeLevel.PROTOCOL_WIDE: "Affects entire protocol",
            ScopeLevel.CONTRACT_WIDE: "Affects single contract",
            ScopeLevel.FUNCTION_ONLY: "Limited to single function",
        }
        parts.append(f"Scope: {scope_reasons[factors.scope]}")

        # Modifiers
        modifiers = []
        if factors.has_known_exploit:
            modifiers.append("Known exploits exist (+)")
        if factors.affects_funds:
            modifiers.append("Directly affects funds (+)")
        if factors.requires_auth:
            modifiers.append("Requires authentication (-)")

        if modifiers:
            parts.append(f"Modifiers: {', '.join(modifiers)}")

        return "\n".join(parts)

    def _estimate_cvss(self, factors: SeverityFactors, score: float) -> float:
        """Estimate CVSS 3.1 score from factors."""
        # Simplified CVSS estimation
        # Attack Vector: Network (0.85) - smart contracts are always network
        av = 0.85

        # Attack Complexity
        ac = {
            ExploitabilityLevel.TRIVIAL: 0.77,  # Low
            ExploitabilityLevel.MODERATE: 0.44,  # High
            ExploitabilityLevel.COMPLEX: 0.44,  # High
        }[factors.exploitability]

        # Privileges Required
        pr = 0.62 if factors.requires_auth else 0.85  # Low vs None

        # User Interaction: None (0.85)
        ui = 0.85

        # Scope: Changed if protocol-wide
        scope_changed = factors.scope == ScopeLevel.PROTOCOL_WIDE

        # Impact (Confidentiality, Integrity, Availability)
        impact_scores = {
            ImpactLevel.TOTAL_LOSS: (0.56, 0.56, 0.56),  # High/High/High
            ImpactLevel.PARTIAL_LOSS: (0.22, 0.56, 0.22),  # Low/High/Low
            ImpactLevel.NO_DIRECT_LOSS: (0.22, 0.22, 0.0),  # Low/Low/None
            ImpactLevel.INFORMATIONAL: (0.0, 0.0, 0.0),  # None
        }
        c, i, a = impact_scores[factors.financial_impact]

        # Calculate exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate impact
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        else:
            impact = 6.42 * iss

        # Calculate CVSS
        if impact <= 0:
            cvss = 0.0
        else:
            if scope_changed:
                cvss = min(10, 1.08 * (impact + exploitability))
            else:
                cvss = min(10, impact + exploitability)

        return round(cvss, 1)

    def _calculate_confidence(
        self,
        factors: SeverityFactors,
        original: str,
        predicted: SeverityLevel,
    ) -> float:
        """Calculate confidence in the severity prediction."""
        base_confidence = 0.7

        # Higher confidence if we have clear factors
        if factors.has_known_exploit:
            base_confidence += 0.1

        if factors.affects_funds:
            base_confidence += 0.05

        # Lower confidence if predicting different from original
        severity_order = ["info", "low", "medium", "high", "critical"]
        original_idx = severity_order.index(original) if original in severity_order else 2
        predicted_idx = severity_order.index(predicted.value)

        diff = abs(original_idx - predicted_idx)
        if diff > 1:
            base_confidence -= 0.1 * (diff - 1)

        return min(0.95, max(0.3, base_confidence))

    def _determine_scope(self, description: str, code: str) -> ScopeLevel:
        """Determine scope from description and code."""
        desc_lower = description.lower()

        # Protocol-wide indicators
        if any(word in desc_lower for word in [
            "all users", "entire protocol", "all funds", "total supply",
            "all contracts", "protocol-wide", "every", "complete drainage"
        ]):
            return ScopeLevel.PROTOCOL_WIDE

        # Contract-wide indicators
        if any(word in desc_lower for word in [
            "contract", "this contract", "the contract", "balance"
        ]):
            return ScopeLevel.CONTRACT_WIDE

        return ScopeLevel.FUNCTION_ONLY

    def _check_known_exploit(self, description: str) -> bool:
        """Check if description mentions known exploits."""
        exploit_keywords = [
            "dao hack", "parity", "beanstalk", "wormhole", "ronin",
            "nomad", "harvest", "bzx", "cream", "mango",
            "known exploit", "real-world", "historic"
        ]
        desc_lower = description.lower()
        return any(kw in desc_lower for kw in exploit_keywords)

    def _check_affects_funds(self, description: str, code: str) -> bool:
        """Check if vulnerability affects funds."""
        fund_keywords = [
            "eth", "ether", "funds", "balance", "transfer", "withdraw",
            "token", "erc20", "usdc", "usdt", "dai", "weth",
            "vault", "treasury", "stake", "deposit"
        ]
        text = (description + " " + code).lower()
        return any(kw in text for kw in fund_keywords)

    def _check_requires_auth(
        self,
        code: str,
        context: Optional[ContractContext],
    ) -> bool:
        """Check if exploitation requires authentication."""
        auth_patterns = [
            r"onlyOwner",
            r"onlyAdmin",
            r"onlyRole",
            r"onlyOperator",
            r"msg\.sender\s*==\s*owner",
            r"require\s*\([^)]*msg\.sender",
            r"_checkRole",
            r"hasRole",
        ]

        for pattern in auth_patterns:
            if re.search(pattern, code):
                return True

        if context and context.uses_access_control:
            return True

        return False


# Convenience function
def classify_severity(
    finding: Dict[str, Any],
    context: Optional[ContractContext] = None,
) -> SeverityPrediction:
    """
    Quick function to classify finding severity.

    Args:
        finding: The vulnerability finding
        context: Optional contract context

    Returns:
        Severity prediction
    """
    classifier = MLSeverityClassifier()
    return classifier.classify(finding, context)


# Export
__all__ = [
    "MLSeverityClassifier",
    "SeverityLevel",
    "SeverityFactors",
    "SeverityPrediction",
    "ContractContext",
    "ImpactLevel",
    "ExploitabilityLevel",
    "ScopeLevel",
    "classify_severity",
]
