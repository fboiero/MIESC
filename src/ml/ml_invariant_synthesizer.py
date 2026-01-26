"""
ML-Enhanced Invariant Synthesizer
=================================

Extends the base InvariantSynthesizer with machine learning capabilities
for improved invariant prediction and ranking.

Features:
- Feature extraction from contract code/AST
- ML-based invariant prediction
- Confidence scoring and ranking
- Training data collection mode
- Historical invariant learning

Based on research:
- "SmartInv: LLM-Synthesized Invariants for Formal Verification" (arXiv:2411.00848)
- "PropertyGPT: LLM-driven Formal Verification of Smart Contracts" (arXiv:2405.02580)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

import hashlib
import json
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.adapters.invariant_synthesizer import (
    InvariantCategory,
    InvariantFormat,
    InvariantSynthesizer,
    SynthesizedInvariant,
)

logger = logging.getLogger(__name__)


@dataclass
class ContractFeatures:
    """Extracted features from a smart contract."""

    # Basic metrics
    line_count: int = 0
    function_count: int = 0
    state_variable_count: int = 0
    modifier_count: int = 0
    event_count: int = 0

    # Contract type indicators
    is_erc20: bool = False
    is_erc721: bool = False
    is_erc4626: bool = False
    is_upgradeable: bool = False
    has_access_control: bool = False
    has_reentrancy_guard: bool = False

    # Security-relevant patterns
    external_call_count: int = 0
    delegatecall_count: int = 0
    selfdestruct_present: bool = False
    assembly_blocks: int = 0
    unchecked_blocks: int = 0

    # DeFi patterns
    has_flash_loan: bool = False
    has_oracle: bool = False
    has_swap: bool = False
    has_staking: bool = False
    has_governance: bool = False

    # Complexity indicators
    inheritance_depth: int = 0
    import_count: int = 0
    interface_count: int = 0

    # Function patterns
    payable_functions: int = 0
    view_functions: int = 0
    pure_functions: int = 0

    def to_vector(self) -> List[float]:
        """Convert features to numerical vector for ML."""
        return [
            self.line_count / 1000,  # Normalize
            self.function_count / 50,
            self.state_variable_count / 20,
            self.modifier_count / 10,
            self.event_count / 10,
            float(self.is_erc20),
            float(self.is_erc721),
            float(self.is_erc4626),
            float(self.is_upgradeable),
            float(self.has_access_control),
            float(self.has_reentrancy_guard),
            self.external_call_count / 10,
            self.delegatecall_count / 5,
            float(self.selfdestruct_present),
            self.assembly_blocks / 5,
            self.unchecked_blocks / 5,
            float(self.has_flash_loan),
            float(self.has_oracle),
            float(self.has_swap),
            float(self.has_staking),
            float(self.has_governance),
            self.inheritance_depth / 5,
            self.import_count / 20,
            self.payable_functions / 10,
            self.view_functions / 20,
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "line_count": self.line_count,
            "function_count": self.function_count,
            "state_variable_count": self.state_variable_count,
            "modifier_count": self.modifier_count,
            "event_count": self.event_count,
            "is_erc20": self.is_erc20,
            "is_erc721": self.is_erc721,
            "is_erc4626": self.is_erc4626,
            "is_upgradeable": self.is_upgradeable,
            "has_access_control": self.has_access_control,
            "has_reentrancy_guard": self.has_reentrancy_guard,
            "external_call_count": self.external_call_count,
            "delegatecall_count": self.delegatecall_count,
            "selfdestruct_present": self.selfdestruct_present,
            "assembly_blocks": self.assembly_blocks,
            "unchecked_blocks": self.unchecked_blocks,
            "has_flash_loan": self.has_flash_loan,
            "has_oracle": self.has_oracle,
            "has_swap": self.has_swap,
            "has_staking": self.has_staking,
            "has_governance": self.has_governance,
            "inheritance_depth": self.inheritance_depth,
            "import_count": self.import_count,
            "payable_functions": self.payable_functions,
            "view_functions": self.view_functions,
        }


@dataclass
class InvariantPrediction:
    """ML prediction for an invariant."""

    category: InvariantCategory
    template_name: str
    confidence: float
    relevance_score: float
    feature_importance: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category.value,
            "template_name": self.template_name,
            "confidence": self.confidence,
            "relevance_score": self.relevance_score,
            "feature_importance": self.feature_importance,
        }


@dataclass
class TrainingExample:
    """Training example for ML model."""

    contract_hash: str
    features: ContractFeatures
    invariants: List[SynthesizedInvariant]
    validation_results: Dict[str, bool] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "contract_hash": self.contract_hash,
            "features": self.features.to_dict(),
            "invariants": [inv.to_dict() for inv in self.invariants],
            "validation_results": self.validation_results,
            "timestamp": self.timestamp.isoformat(),
        }


class FeatureExtractor:
    """
    Extracts features from Solidity contracts for ML analysis.

    Uses regex-based pattern matching for fast feature extraction
    without requiring full AST parsing.
    """

    # Patterns for feature extraction
    PATTERNS = {
        "function": r"\bfunction\s+\w+\s*\(",
        "state_var": r"^\s*(mapping|uint|int|address|bool|bytes|string)\s+\w+",
        "modifier": r"\bmodifier\s+\w+\s*\(",
        "event": r"\bevent\s+\w+\s*\(",
        "external_call": r"\.(call|delegatecall|staticcall)\s*[\({]",
        "delegatecall": r"\.delegatecall\s*[\({]",
        "selfdestruct": r"\bselfdestruct\s*\(",
        "assembly": r"\bassembly\s*\{",
        "unchecked": r"\bunchecked\s*\{",
        "import": r"^import\s+",
        "interface": r"\binterface\s+\w+",
        "payable": r"\bpayable\b",
        "view": r"\bview\b",
        "pure": r"\bpure\b",
        "is_inheritance": r"\bis\s+\w+",
    }

    # Contract type patterns
    TYPE_PATTERNS = {
        "erc20": [r"\bIERC20\b", r"\btransfer\s*\(", r"\bbalanceOf\s*\(", r"\btotalSupply\b"],
        "erc721": [r"\bIERC721\b", r"\bownerOf\s*\(", r"\btokenURI\s*\("],
        "erc4626": [r"\bIERC4626\b", r"\btotalAssets\s*\(", r"\bconvertToShares\s*\("],
        "upgradeable": [r"\bUpgradeable\b", r"\bproxy\b", r"\bUUPS\b", r"\bTransparent\b"],
        "access_control": [r"\bonlyOwner\b", r"\bAccessControl\b", r"\bOwnable\b"],
        "reentrancy_guard": [r"\bnonReentrant\b", r"\bReentrancyGuard\b"],
    }

    # DeFi patterns
    DEFI_PATTERNS = {
        "flash_loan": [r"\bflashLoan\b", r"\bIFlash\b", r"\bexecuteOperation\b"],
        "oracle": [r"\boracle\b", r"\bgetPrice\b", r"\blatestAnswer\b", r"\bChainlink\b"],
        "swap": [r"\bswap\b", r"\bgetAmountOut\b", r"\bUniswap\b", r"\bISwap\b"],
        "staking": [r"\bstake\b", r"\bunstake\b", r"\breward\b"],
        "governance": [r"\bpropose\b", r"\bvote\b", r"\bGovernor\b", r"\bquorum\b"],
    }

    def extract(self, contract_code: str) -> ContractFeatures:
        """
        Extract features from contract code.

        Args:
            contract_code: Solidity source code

        Returns:
            ContractFeatures with extracted metrics
        """
        features = ContractFeatures()
        code_lower = contract_code.lower()

        # Basic metrics
        features.line_count = len(contract_code.split("\n"))
        features.function_count = len(re.findall(self.PATTERNS["function"], contract_code))
        features.state_variable_count = len(
            re.findall(self.PATTERNS["state_var"], contract_code, re.MULTILINE)
        )
        features.modifier_count = len(re.findall(self.PATTERNS["modifier"], contract_code))
        features.event_count = len(re.findall(self.PATTERNS["event"], contract_code))

        # Security patterns
        features.external_call_count = len(
            re.findall(self.PATTERNS["external_call"], contract_code)
        )
        features.delegatecall_count = len(
            re.findall(self.PATTERNS["delegatecall"], contract_code)
        )
        features.selfdestruct_present = bool(
            re.search(self.PATTERNS["selfdestruct"], contract_code)
        )
        features.assembly_blocks = len(re.findall(self.PATTERNS["assembly"], contract_code))
        features.unchecked_blocks = len(re.findall(self.PATTERNS["unchecked"], contract_code))

        # Import and inheritance
        features.import_count = len(
            re.findall(self.PATTERNS["import"], contract_code, re.MULTILINE)
        )
        features.interface_count = len(re.findall(self.PATTERNS["interface"], contract_code))
        inheritance_matches = re.findall(self.PATTERNS["is_inheritance"], contract_code)
        features.inheritance_depth = len(inheritance_matches)

        # Function types
        features.payable_functions = len(
            re.findall(
                r"function\s+\w+[^{]*\bpayable\b", contract_code, re.IGNORECASE
            )
        )
        features.view_functions = len(
            re.findall(
                r"function\s+\w+[^{]*\bview\b", contract_code, re.IGNORECASE
            )
        )
        features.pure_functions = len(
            re.findall(
                r"function\s+\w+[^{]*\bpure\b", contract_code, re.IGNORECASE
            )
        )

        # Contract type detection
        for type_name, patterns in self.TYPE_PATTERNS.items():
            if any(re.search(p, contract_code, re.IGNORECASE) for p in patterns):
                setattr(features, f"is_{type_name}" if type_name.startswith("erc") else f"has_{type_name}", True)

        # Special handling for boolean attributes
        features.is_erc20 = any(
            re.search(p, contract_code, re.IGNORECASE)
            for p in self.TYPE_PATTERNS["erc20"]
        )
        features.is_erc721 = any(
            re.search(p, contract_code, re.IGNORECASE)
            for p in self.TYPE_PATTERNS["erc721"]
        )
        features.is_erc4626 = any(
            re.search(p, contract_code, re.IGNORECASE)
            for p in self.TYPE_PATTERNS["erc4626"]
        )
        features.is_upgradeable = any(
            re.search(p, contract_code, re.IGNORECASE)
            for p in self.TYPE_PATTERNS["upgradeable"]
        )
        features.has_access_control = any(
            re.search(p, contract_code, re.IGNORECASE)
            for p in self.TYPE_PATTERNS["access_control"]
        )
        features.has_reentrancy_guard = any(
            re.search(p, contract_code, re.IGNORECASE)
            for p in self.TYPE_PATTERNS["reentrancy_guard"]
        )

        # DeFi patterns
        for defi_type, patterns in self.DEFI_PATTERNS.items():
            has_pattern = any(
                re.search(p, contract_code, re.IGNORECASE) for p in patterns
            )
            setattr(features, f"has_{defi_type}", has_pattern)

        return features


class InvariantPredictor:
    """
    ML-based invariant predictor using rule-based heuristics.

    Uses feature-based rules to predict relevant invariants.
    Can be extended with actual ML models (scikit-learn, PyTorch).
    """

    # Invariant templates by category
    INVARIANT_TEMPLATES = {
        InvariantCategory.ACCOUNTING: [
            "total_supply_equals_sum_balances",
            "transfer_preserves_supply",
            "mint_increases_supply",
            "burn_decreases_supply",
            "balance_non_negative",
        ],
        InvariantCategory.SOLVENCY: [
            "vault_solvency",
            "sufficient_collateral",
            "reserve_ratio_maintained",
            "withdrawal_possible",
        ],
        InvariantCategory.ACCESS_CONTROL: [
            "owner_functions_protected",
            "role_based_access",
            "admin_only_sensitive_functions",
            "no_unauthorized_mint",
        ],
        InvariantCategory.REENTRANCY: [
            "reentrancy_lock_valid",
            "state_before_external_call",
            "no_callback_reentrancy",
        ],
        InvariantCategory.STATE_TRANSITION: [
            "valid_state_transitions",
            "monotonic_increase",
            "no_invalid_state",
        ],
        InvariantCategory.OVERFLOW: [
            "no_overflow_on_add",
            "no_underflow_on_sub",
            "safe_multiplication",
        ],
        InvariantCategory.TEMPORAL: [
            "timelock_respected",
            "no_premature_withdrawal",
            "epoch_progression",
        ],
    }

    # Feature-to-category relevance weights
    RELEVANCE_WEIGHTS = {
        "is_erc20": {InvariantCategory.ACCOUNTING: 0.9, InvariantCategory.ACCESS_CONTROL: 0.5},
        "is_erc4626": {InvariantCategory.SOLVENCY: 0.95, InvariantCategory.ACCOUNTING: 0.8},
        "has_access_control": {InvariantCategory.ACCESS_CONTROL: 0.9},
        "has_reentrancy_guard": {InvariantCategory.REENTRANCY: 0.7},
        "external_call_count": {InvariantCategory.REENTRANCY: 0.8},
        "has_flash_loan": {InvariantCategory.SOLVENCY: 0.9, InvariantCategory.REENTRANCY: 0.7},
        "has_oracle": {InvariantCategory.ACCOUNTING: 0.6},
        "has_governance": {InvariantCategory.ACCESS_CONTROL: 0.8, InvariantCategory.TEMPORAL: 0.7},
        "has_staking": {InvariantCategory.TEMPORAL: 0.8, InvariantCategory.ACCOUNTING: 0.7},
    }

    def predict(self, features: ContractFeatures) -> List[InvariantPrediction]:
        """
        Predict relevant invariants based on contract features.

        Args:
            features: Extracted contract features

        Returns:
            List of invariant predictions sorted by relevance
        """
        predictions = []
        feature_dict = features.to_dict()

        # Calculate category relevance scores
        category_scores: Dict[InvariantCategory, float] = {cat: 0.0 for cat in InvariantCategory}

        for feature_name, category_weights in self.RELEVANCE_WEIGHTS.items():
            feature_value = feature_dict.get(feature_name, 0)

            # Normalize feature value
            if isinstance(feature_value, bool):
                normalized = 1.0 if feature_value else 0.0
            elif isinstance(feature_value, (int, float)):
                normalized = min(feature_value / 10, 1.0)  # Cap at 1.0
            else:
                normalized = 0.0

            # Add weighted contribution to categories
            for category, weight in category_weights.items():
                category_scores[category] += normalized * weight

        # Generate predictions for each relevant category
        for category, score in category_scores.items():
            if score > 0.1:  # Threshold for relevance
                for template in self.INVARIANT_TEMPLATES.get(category, []):
                    # Calculate confidence based on feature match
                    confidence = self._calculate_confidence(features, category, template)

                    predictions.append(
                        InvariantPrediction(
                            category=category,
                            template_name=template,
                            confidence=confidence,
                            relevance_score=score,
                            feature_importance=self._get_feature_importance(
                                features, category
                            ),
                        )
                    )

        # Sort by relevance * confidence
        predictions.sort(key=lambda p: p.relevance_score * p.confidence, reverse=True)

        return predictions[:20]  # Return top 20 predictions

    def _calculate_confidence(
        self,
        features: ContractFeatures,
        category: InvariantCategory,
        template: str,
    ) -> float:
        """Calculate confidence score for a specific invariant."""
        base_confidence = 0.5

        # Boost confidence based on specific feature-template matches
        if category == InvariantCategory.ACCOUNTING:
            if features.is_erc20 and "supply" in template:
                base_confidence += 0.3
            if features.is_erc4626 and "balance" in template:
                base_confidence += 0.25

        elif category == InvariantCategory.SOLVENCY:
            if features.is_erc4626 and "vault" in template:
                base_confidence += 0.35
            if features.has_flash_loan:
                base_confidence += 0.2

        elif category == InvariantCategory.ACCESS_CONTROL:
            if features.has_access_control:
                base_confidence += 0.3

        elif category == InvariantCategory.REENTRANCY:
            if features.external_call_count > 0:
                base_confidence += 0.2
            if not features.has_reentrancy_guard:
                base_confidence += 0.2  # More important to check

        return min(base_confidence, 0.95)

    def _get_feature_importance(
        self,
        features: ContractFeatures,
        category: InvariantCategory,
    ) -> Dict[str, float]:
        """Get feature importance for a category."""
        importance = {}
        feature_dict = features.to_dict()

        for feature_name, category_weights in self.RELEVANCE_WEIGHTS.items():
            if category in category_weights:
                feature_value = feature_dict.get(feature_name, 0)
                if feature_value:
                    importance[feature_name] = category_weights[category]

        return importance


class MLInvariantSynthesizer:
    """
    ML-enhanced invariant synthesizer.

    Combines traditional pattern-based synthesis with ML predictions
    for improved invariant generation.
    """

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        collect_training_data: bool = False,
    ):
        """
        Initialize the ML invariant synthesizer.

        Args:
            data_dir: Directory for training data storage
            collect_training_data: Whether to collect training examples
        """
        self.base_synthesizer = InvariantSynthesizer()
        self.feature_extractor = FeatureExtractor()
        self.predictor = InvariantPredictor()

        self.data_dir = data_dir or Path.home() / ".miesc" / "ml_invariants"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.collect_training_data = collect_training_data
        self.training_examples: List[TrainingExample] = []

        # Load existing training data
        if self.collect_training_data:
            self._load_training_data()

        logger.info(
            f"MLInvariantSynthesizer initialized "
            f"(training_mode={collect_training_data})"
        )

    def synthesize(
        self,
        contract_path: str,
        formats: Optional[List[InvariantFormat]] = None,
        max_invariants: int = 20,
        use_ml_ranking: bool = True,
    ) -> Dict[str, Any]:
        """
        Synthesize invariants with ML enhancement.

        Args:
            contract_path: Path to contract file
            formats: Output formats
            max_invariants: Maximum invariants to generate
            use_ml_ranking: Whether to use ML for ranking

        Returns:
            Dictionary with synthesized invariants
        """
        # Read contract
        try:
            with open(contract_path, "r") as f:
                contract_code = f.read()
        except Exception as e:
            return {"status": "error", "error": str(e), "invariants": []}

        # Extract features
        features = self.feature_extractor.extract(contract_code)
        logger.info(f"Extracted features: {features.function_count} functions, "
                   f"ERC20={features.is_erc20}, ERC4626={features.is_erc4626}")

        # Get ML predictions
        predictions = []
        if use_ml_ranking:
            predictions = self.predictor.predict(features)
            logger.info(f"ML predictions: {len(predictions)} invariant candidates")

        # Get base invariants
        base_result = self.base_synthesizer.synthesize(
            contract_path=contract_path,
            formats=formats,
            max_invariants=max_invariants,
        )

        if base_result.get("status") != "success":
            return base_result

        # Enhance with ML ranking
        invariants = []
        for inv in base_result.get("invariants", []):
            if isinstance(inv, dict):
                # Convert category string to enum if needed
                inv_copy = inv.copy()
                if isinstance(inv_copy.get("category"), str):
                    try:
                        inv_copy["category"] = InvariantCategory(inv_copy["category"])
                    except ValueError:
                        inv_copy["category"] = InvariantCategory.CUSTOM
                invariants.append(SynthesizedInvariant(**inv_copy))
            else:
                invariants.append(inv)

        if use_ml_ranking and predictions:
            invariants = self._rank_with_ml(invariants, predictions, features)

        # Collect training data if enabled
        if self.collect_training_data:
            contract_hash = hashlib.sha256(contract_code.encode()).hexdigest()[:16]
            example = TrainingExample(
                contract_hash=contract_hash,
                features=features,
                invariants=invariants[:max_invariants],
            )
            self.training_examples.append(example)
            self._save_training_data()

        # Build result
        result = {
            "status": "success",
            "contract": contract_path,
            "invariants": [
                inv.to_dict() if hasattr(inv, "to_dict") else inv
                for inv in invariants[:max_invariants]
            ],
            "ml_enhanced": use_ml_ranking,
            "features": features.to_dict(),
            "predictions": [p.to_dict() for p in predictions[:10]],
            "summary": {
                "total": min(len(invariants), max_invariants),
                "ml_predictions": len(predictions),
                "feature_vector_size": len(features.to_vector()),
            },
        }

        return result

    def _rank_with_ml(
        self,
        invariants: List[SynthesizedInvariant],
        predictions: List[InvariantPrediction],
        features: ContractFeatures,
    ) -> List[SynthesizedInvariant]:
        """Rank invariants using ML predictions."""
        # Create prediction lookup
        prediction_map: Dict[str, InvariantPrediction] = {}
        for pred in predictions:
            prediction_map[pred.template_name] = pred
            # Also map by category
            for inv in invariants:
                if inv.category == pred.category:
                    if inv.name not in prediction_map:
                        prediction_map[inv.name] = pred

        # Score each invariant
        scored_invariants: List[Tuple[SynthesizedInvariant, float]] = []

        for inv in invariants:
            # Base score from importance
            importance_scores = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}
            base_score = importance_scores.get(inv.importance, 0.5)

            # ML boost
            ml_boost = 0.0
            if inv.name in prediction_map:
                pred = prediction_map[inv.name]
                ml_boost = pred.confidence * pred.relevance_score * 0.5
            elif inv.category.value in [p.category.value for p in predictions]:
                # Category match
                ml_boost = 0.2

            # Feature relevance boost
            feature_boost = self._calculate_feature_relevance(inv, features)

            final_score = base_score + ml_boost + feature_boost
            inv.confidence = min(inv.confidence + ml_boost, 0.99)

            scored_invariants.append((inv, final_score))

        # Sort by score
        scored_invariants.sort(key=lambda x: x[1], reverse=True)

        return [inv for inv, _ in scored_invariants]

    def _calculate_feature_relevance(
        self,
        inv: SynthesizedInvariant,
        features: ContractFeatures,
    ) -> float:
        """Calculate relevance boost based on features."""
        boost = 0.0

        # Category-specific boosts
        if inv.category == InvariantCategory.ACCOUNTING:
            if features.is_erc20 or features.is_erc4626:
                boost += 0.15

        elif inv.category == InvariantCategory.SOLVENCY:
            if features.is_erc4626:
                boost += 0.2
            if features.has_flash_loan:
                boost += 0.1

        elif inv.category == InvariantCategory.ACCESS_CONTROL:
            if features.has_access_control:
                boost += 0.15

        elif inv.category == InvariantCategory.REENTRANCY:
            if features.external_call_count > 0:
                boost += 0.1
            if not features.has_reentrancy_guard:
                boost += 0.1

        return boost

    def add_validation_result(
        self,
        contract_hash: str,
        invariant_name: str,
        passed: bool,
    ) -> None:
        """
        Add validation result for training feedback.

        Args:
            contract_hash: Hash of the contract
            invariant_name: Name of the invariant
            passed: Whether the invariant passed validation
        """
        for example in self.training_examples:
            if example.contract_hash == contract_hash:
                example.validation_results[invariant_name] = passed
                break

        self._save_training_data()

    def get_training_stats(self) -> Dict[str, Any]:
        """Get statistics about collected training data."""
        if not self.training_examples:
            return {"total_examples": 0}

        total_invariants = sum(len(ex.invariants) for ex in self.training_examples)
        validated_count = sum(
            len(ex.validation_results) for ex in self.training_examples
        )
        passed_count = sum(
            sum(1 for v in ex.validation_results.values() if v)
            for ex in self.training_examples
        )

        # Category distribution
        category_counts: Counter = Counter()
        for ex in self.training_examples:
            for inv in ex.invariants:
                category_counts[inv.category.value] += 1

        return {
            "total_examples": len(self.training_examples),
            "total_invariants": total_invariants,
            "validated_invariants": validated_count,
            "passed_validations": passed_count,
            "pass_rate": passed_count / validated_count if validated_count > 0 else 0,
            "category_distribution": dict(category_counts),
        }

    def _save_training_data(self) -> None:
        """Save training data to disk."""
        data_file = self.data_dir / "training_data.json"

        data = {
            "version": "1.0",
            "examples": [ex.to_dict() for ex in self.training_examples],
            "saved_at": datetime.now().isoformat(),
        }

        try:
            with open(data_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
            logger.debug(f"Saved {len(self.training_examples)} training examples")
        except Exception as e:
            logger.error(f"Error saving training data: {e}")

    def _load_training_data(self) -> None:
        """Load training data from disk."""
        data_file = self.data_dir / "training_data.json"

        if not data_file.exists():
            return

        try:
            with open(data_file, "r") as f:
                data = json.load(f)

            # Note: Full deserialization would require more complex handling
            # For now, we just count loaded examples
            examples = data.get("examples", [])
            logger.info(f"Loaded {len(examples)} training examples from disk")

        except Exception as e:
            logger.error(f"Error loading training data: {e}")


# ============================================================================
# Convenience Functions
# ============================================================================


def extract_contract_features(contract_code: str) -> ContractFeatures:
    """
    Extract features from contract code.

    Args:
        contract_code: Solidity source code

    Returns:
        ContractFeatures object
    """
    extractor = FeatureExtractor()
    return extractor.extract(contract_code)


def predict_invariants(contract_code: str) -> List[InvariantPrediction]:
    """
    Predict relevant invariants for a contract.

    Args:
        contract_code: Solidity source code

    Returns:
        List of invariant predictions
    """
    extractor = FeatureExtractor()
    predictor = InvariantPredictor()

    features = extractor.extract(contract_code)
    return predictor.predict(features)


def synthesize_with_ml(
    contract_path: str,
    formats: Optional[List[str]] = None,
    max_invariants: int = 20,
) -> Dict[str, Any]:
    """
    Synthesize invariants with ML enhancement.

    Args:
        contract_path: Path to contract file
        formats: Output formats
        max_invariants: Maximum invariants

    Returns:
        Dictionary with results
    """
    synthesizer = MLInvariantSynthesizer()

    format_enums = None
    if formats:
        format_enums = []
        for f in formats:
            try:
                format_enums.append(InvariantFormat(f))
            except ValueError:
                pass

    return synthesizer.synthesize(
        contract_path=contract_path,
        formats=format_enums,
        max_invariants=max_invariants,
    )


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "MLInvariantSynthesizer",
    "FeatureExtractor",
    "InvariantPredictor",
    "ContractFeatures",
    "InvariantPrediction",
    "TrainingExample",
    "extract_contract_features",
    "predict_invariants",
    "synthesize_with_ml",
]
