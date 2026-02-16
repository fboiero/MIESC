"""
Tests for the ML-Based Severity Classifier module.

Tests cover:
- Enums: SeverityLevel, ImpactLevel, ExploitabilityLevel, ScopeLevel
- Dataclasses: SeverityFactors, SeverityPrediction, ContractContext
- MLSeverityClassifier class methods
- Convenience function: classify_severity
"""

import pytest

from src.ml.severity_classifier import (
    ContractContext,
    ExploitabilityLevel,
    ImpactLevel,
    MLSeverityClassifier,
    ScopeLevel,
    SeverityFactors,
    SeverityLevel,
    SeverityPrediction,
    classify_severity,
)

# =============================================================================
# Enum Tests
# =============================================================================


class TestSeverityLevel:
    """Tests for SeverityLevel enum."""

    def test_all_severity_levels_defined(self):
        """Test that all severity levels are defined."""
        assert SeverityLevel.CRITICAL.value == "critical"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.LOW.value == "low"
        assert SeverityLevel.INFO.value == "info"

    def test_severity_level_count(self):
        """Test that we have exactly 5 severity levels."""
        assert len(SeverityLevel) == 5


class TestImpactLevel:
    """Tests for ImpactLevel enum."""

    def test_all_impact_levels_defined(self):
        """Test that all impact levels are defined."""
        assert ImpactLevel.TOTAL_LOSS.value == "total_loss"
        assert ImpactLevel.PARTIAL_LOSS.value == "partial_loss"
        assert ImpactLevel.NO_DIRECT_LOSS.value == "no_direct_loss"
        assert ImpactLevel.INFORMATIONAL.value == "informational"

    def test_impact_level_count(self):
        """Test that we have exactly 4 impact levels."""
        assert len(ImpactLevel) == 4


class TestExploitabilityLevel:
    """Tests for ExploitabilityLevel enum."""

    def test_all_exploitability_levels_defined(self):
        """Test that all exploitability levels are defined."""
        assert ExploitabilityLevel.TRIVIAL.value == "trivial"
        assert ExploitabilityLevel.MODERATE.value == "moderate"
        assert ExploitabilityLevel.COMPLEX.value == "complex"

    def test_exploitability_level_count(self):
        """Test that we have exactly 3 exploitability levels."""
        assert len(ExploitabilityLevel) == 3


class TestScopeLevel:
    """Tests for ScopeLevel enum."""

    def test_all_scope_levels_defined(self):
        """Test that all scope levels are defined."""
        assert ScopeLevel.PROTOCOL_WIDE.value == "protocol_wide"
        assert ScopeLevel.CONTRACT_WIDE.value == "contract_wide"
        assert ScopeLevel.FUNCTION_ONLY.value == "function_only"

    def test_scope_level_count(self):
        """Test that we have exactly 3 scope levels."""
        assert len(ScopeLevel) == 3


# =============================================================================
# Dataclass Tests
# =============================================================================


class TestSeverityFactors:
    """Tests for SeverityFactors dataclass."""

    def test_create_with_required_fields(self):
        """Test creating SeverityFactors with required fields."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.TRIVIAL,
            scope=ScopeLevel.PROTOCOL_WIDE,
        )
        assert factors.financial_impact == ImpactLevel.TOTAL_LOSS
        assert factors.exploitability == ExploitabilityLevel.TRIVIAL
        assert factors.scope == ScopeLevel.PROTOCOL_WIDE

    def test_default_values(self):
        """Test that default values are set correctly."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.NO_DIRECT_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.FUNCTION_ONLY,
        )
        assert factors.has_known_exploit is False
        assert factors.affects_funds is False
        assert factors.requires_auth is True
        assert factors.probability_score == 0.5

    def test_custom_optional_values(self):
        """Test setting custom optional values."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.TRIVIAL,
            scope=ScopeLevel.PROTOCOL_WIDE,
            has_known_exploit=True,
            affects_funds=True,
            requires_auth=False,
            probability_score=0.9,
        )
        assert factors.has_known_exploit is True
        assert factors.affects_funds is True
        assert factors.requires_auth is False
        assert factors.probability_score == 0.9


class TestSeverityPrediction:
    """Tests for SeverityPrediction dataclass."""

    def test_create_prediction(self):
        """Test creating a SeverityPrediction."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.TRIVIAL,
            scope=ScopeLevel.PROTOCOL_WIDE,
        )
        prediction = SeverityPrediction(
            severity=SeverityLevel.CRITICAL,
            confidence=0.95,
            factors=factors,
            score=0.9,
            reasoning="Test reasoning",
            cvss_estimate=9.8,
        )
        assert prediction.severity == SeverityLevel.CRITICAL
        assert prediction.confidence == 0.95
        assert prediction.score == 0.9
        assert prediction.reasoning == "Test reasoning"
        assert prediction.cvss_estimate == 9.8


class TestContractContext:
    """Tests for ContractContext dataclass."""

    def test_create_context(self):
        """Test creating ContractContext."""
        context = ContractContext(
            contract_type="dex",
            has_value_handling=True,
            uses_access_control=True,
            uses_reentrancy_guard=True,
            solidity_version="0.8.20",
            is_upgradeable=False,
            estimated_tvl="high",
        )
        assert context.contract_type == "dex"
        assert context.has_value_handling is True
        assert context.uses_access_control is True
        assert context.uses_reentrancy_guard is True
        assert context.solidity_version == "0.8.20"
        assert context.is_upgradeable is False
        assert context.estimated_tvl == "high"


# =============================================================================
# MLSeverityClassifier Tests
# =============================================================================


class TestMLSeverityClassifierInit:
    """Tests for MLSeverityClassifier initialization."""

    def test_default_init(self):
        """Test default initialization."""
        classifier = MLSeverityClassifier()
        assert classifier.use_llm is False
        assert classifier.base_url == "http://localhost:11434"
        assert classifier.model == "deepseek-coder:6.7b"

    def test_custom_init(self):
        """Test custom initialization."""
        classifier = MLSeverityClassifier(
            use_llm_analysis=True,
            ollama_base_url="http://custom:8080",
            model="llama2:7b",
        )
        assert classifier.use_llm is True
        assert classifier.base_url == "http://custom:8080"
        assert classifier.model == "llama2:7b"


class TestMLSeverityClassifierClassify:
    """Tests for classify method."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return MLSeverityClassifier()

    def test_classify_reentrancy_critical(self, classifier):
        """Test classifying reentrancy vulnerability."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "description": "Reentrancy vulnerability affects all funds in the protocol",
        }
        result = classifier.classify(finding)

        assert isinstance(result, SeverityPrediction)
        assert result.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        assert result.factors.financial_impact == ImpactLevel.TOTAL_LOSS
        assert result.confidence > 0.0

    def test_classify_gas_optimization_info(self, classifier):
        """Test classifying gas optimization finding."""
        finding = {
            "type": "gas-optimization",
            "severity": "info",
            "description": "Unnecessary storage read in loop",
        }
        result = classifier.classify(finding)

        assert result.severity in [SeverityLevel.INFO, SeverityLevel.LOW]
        assert result.factors.financial_impact == ImpactLevel.INFORMATIONAL

    def test_classify_unknown_type(self, classifier):
        """Test classifying unknown vulnerability type."""
        finding = {
            "type": "unknown-vuln-type",
            "severity": "medium",
            "description": "Some unknown vulnerability",
        }
        result = classifier.classify(finding)

        assert isinstance(result, SeverityPrediction)
        assert result.factors.financial_impact == ImpactLevel.NO_DIRECT_LOSS
        assert result.factors.exploitability == ExploitabilityLevel.MODERATE

    def test_classify_with_context(self, classifier):
        """Test classifying with contract context."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "description": "Reentrancy in withdraw function",
        }
        context = ContractContext(
            contract_type="vault",
            has_value_handling=True,
            uses_access_control=True,
            uses_reentrancy_guard=True,
            solidity_version="0.8.20",
            is_upgradeable=False,
            estimated_tvl="high",
        )
        result = classifier.classify(finding, context)

        # With reentrancy guard, score should be reduced
        assert isinstance(result, SeverityPrediction)

    def test_classify_with_code_snippet(self, classifier):
        """Test classifying with code snippet."""
        finding = {
            "type": "access-control",
            "severity": "high",
            "description": "Missing access control",
        }
        code = """
        function withdraw() public {
            // No onlyOwner modifier
            payable(msg.sender).transfer(address(this).balance);
        }
        """
        result = classifier.classify(finding, code_snippet=code)

        assert isinstance(result, SeverityPrediction)
        assert result.factors.affects_funds is True

    def test_classify_with_auth_code(self, classifier):
        """Test classifying code with authentication."""
        finding = {
            "type": "access-control",
            "severity": "medium",
            "description": "Weak access control",
        }
        code = """
        function withdraw() public onlyOwner {
            payable(msg.sender).transfer(address(this).balance);
        }
        """
        result = classifier.classify(finding, code_snippet=code)

        assert result.factors.requires_auth is True


class TestMLSeverityClassifierClassifyBatch:
    """Tests for classify_batch method."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return MLSeverityClassifier()

    def test_classify_batch_multiple_findings(self, classifier):
        """Test batch classification of multiple findings."""
        findings = [
            {"type": "reentrancy", "severity": "high", "description": "Reentrancy found"},
            {"type": "gas-optimization", "severity": "info", "description": "Gas issue"},
            {
                "type": "access-control",
                "severity": "medium",
                "description": "Access control issue",
            },
        ]
        results = classifier.classify_batch(findings)

        assert len(results) == 3
        for finding, prediction in results:
            assert isinstance(prediction, SeverityPrediction)
            assert "original_severity" in finding
            assert "severity_score" in finding
            assert "severity_confidence" in finding

    def test_classify_batch_empty_list(self, classifier):
        """Test batch classification with empty list."""
        results = classifier.classify_batch([])
        assert results == []

    def test_classify_batch_with_context(self, classifier):
        """Test batch classification with context."""
        findings = [
            {"type": "reentrancy", "severity": "high", "description": "Reentrancy in vault"},
        ]
        context = ContractContext(
            contract_type="vault",
            has_value_handling=True,
            uses_access_control=True,
            uses_reentrancy_guard=False,
            solidity_version="0.8.20",
            is_upgradeable=False,
            estimated_tvl="high",
        )
        results = classifier.classify_batch(findings, context)

        assert len(results) == 1

    def test_classify_batch_updates_findings(self, classifier):
        """Test that batch classification updates findings in place."""
        findings = [
            {"type": "reentrancy", "severity": "high", "description": "Reentrancy"},
        ]
        classifier.classify_batch(findings)

        assert findings[0]["original_severity"] == "high"
        assert "severity" in findings[0]
        assert "severity_score" in findings[0]


class TestMLSeverityClassifierScoreCalculation:
    """Tests for score calculation methods."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return MLSeverityClassifier()

    def test_calculate_score_max(self, classifier):
        """Test maximum score calculation."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.TRIVIAL,
            scope=ScopeLevel.PROTOCOL_WIDE,
        )
        score = classifier._calculate_score(factors)

        # 1.0 * 0.5 + 1.0 * 0.3 + 1.0 * 0.2 = 1.0
        assert score == 1.0

    def test_calculate_score_min(self, classifier):
        """Test minimum score calculation."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.INFORMATIONAL,
            exploitability=ExploitabilityLevel.COMPLEX,
            scope=ScopeLevel.FUNCTION_ONLY,
        )
        score = classifier._calculate_score(factors)

        # 0.1 * 0.5 + 0.3 * 0.3 + 0.3 * 0.2 = 0.05 + 0.09 + 0.06 = 0.20
        assert abs(score - 0.20) < 0.01

    def test_calculate_score_medium(self, classifier):
        """Test medium score calculation."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.PARTIAL_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.CONTRACT_WIDE,
        )
        score = classifier._calculate_score(factors)

        # 0.7 * 0.5 + 0.6 * 0.3 + 0.6 * 0.2 = 0.35 + 0.18 + 0.12 = 0.65
        assert abs(score - 0.65) < 0.01


class TestMLSeverityClassifierModifiers:
    """Tests for score modifiers."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return MLSeverityClassifier()

    def test_apply_modifiers_known_exploit_boost(self, classifier):
        """Test known exploit boosts score."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.PARTIAL_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.CONTRACT_WIDE,
            has_known_exploit=True,
            requires_auth=False,  # Disable auth reduction for isolated test
        )
        base_score = 0.5
        modified = classifier._apply_modifiers(base_score, factors, None)

        assert modified == 0.65  # 0.5 + 0.15

    def test_apply_modifiers_affects_funds_boost(self, classifier):
        """Test affects funds boosts score."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.PARTIAL_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.CONTRACT_WIDE,
            affects_funds=True,
            requires_auth=False,  # Disable auth reduction for isolated test
        )
        base_score = 0.5
        modified = classifier._apply_modifiers(base_score, factors, None)

        assert modified == 0.60  # 0.5 + 0.10

    def test_apply_modifiers_requires_auth_reduction(self, classifier):
        """Test requires auth reduces score."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.PARTIAL_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.CONTRACT_WIDE,
            requires_auth=True,
        )
        base_score = 0.5
        modified = classifier._apply_modifiers(base_score, factors, None)

        assert modified == 0.40  # 0.5 - 0.10

    def test_apply_modifiers_high_tvl_boost(self, classifier):
        """Test high TVL boosts score."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.PARTIAL_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.CONTRACT_WIDE,
            requires_auth=False,
        )
        context = ContractContext(
            contract_type="vault",
            has_value_handling=True,
            uses_access_control=True,
            uses_reentrancy_guard=False,
            solidity_version="0.8.20",
            is_upgradeable=False,
            estimated_tvl="high",
        )
        base_score = 0.5
        modified = classifier._apply_modifiers(base_score, factors, context)

        assert modified == 0.60  # 0.5 + 0.10

    def test_apply_modifiers_low_tvl_reduction(self, classifier):
        """Test low TVL reduces score."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.PARTIAL_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.CONTRACT_WIDE,
            requires_auth=False,
        )
        context = ContractContext(
            contract_type="test",
            has_value_handling=False,
            uses_access_control=False,
            uses_reentrancy_guard=False,
            solidity_version="0.8.20",
            is_upgradeable=False,
            estimated_tvl="low",
        )
        base_score = 0.5
        modified = classifier._apply_modifiers(base_score, factors, context)

        assert modified == 0.45  # 0.5 - 0.05

    def test_apply_modifiers_reentrancy_guard_reduction(self, classifier):
        """Test reentrancy guard reduces score for total loss."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.CONTRACT_WIDE,
            requires_auth=False,
        )
        context = ContractContext(
            contract_type="vault",
            has_value_handling=True,
            uses_access_control=True,
            uses_reentrancy_guard=True,
            solidity_version="0.8.20",
            is_upgradeable=False,
            estimated_tvl="medium",
        )
        base_score = 0.8
        modified = classifier._apply_modifiers(base_score, factors, context)

        assert abs(modified - 0.60) < 0.001  # 0.8 - 0.20

    def test_apply_modifiers_score_capped_at_1(self, classifier):
        """Test score is capped at 1.0."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.TRIVIAL,
            scope=ScopeLevel.PROTOCOL_WIDE,
            has_known_exploit=True,
            affects_funds=True,
            requires_auth=False,
        )
        base_score = 0.95
        modified = classifier._apply_modifiers(base_score, factors, None)

        assert modified == 1.0

    def test_apply_modifiers_score_floor_at_0(self, classifier):
        """Test score has floor at 0.0."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.INFORMATIONAL,
            exploitability=ExploitabilityLevel.COMPLEX,
            scope=ScopeLevel.FUNCTION_ONLY,
            requires_auth=True,
        )
        base_score = 0.05
        modified = classifier._apply_modifiers(base_score, factors, None)

        assert modified == 0.0


class TestMLSeverityClassifierScoreToSeverity:
    """Tests for score to severity mapping."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return MLSeverityClassifier()

    @pytest.mark.parametrize(
        "score,expected",
        [
            (1.0, SeverityLevel.CRITICAL),
            (0.90, SeverityLevel.CRITICAL),
            (0.85, SeverityLevel.CRITICAL),
            (0.80, SeverityLevel.HIGH),
            (0.65, SeverityLevel.HIGH),
            (0.60, SeverityLevel.MEDIUM),
            (0.45, SeverityLevel.MEDIUM),
            (0.40, SeverityLevel.LOW),
            (0.25, SeverityLevel.LOW),
            (0.20, SeverityLevel.INFO),
            (0.0, SeverityLevel.INFO),
        ],
    )
    def test_score_to_severity_mapping(self, classifier, score, expected):
        """Test score to severity mapping at various thresholds."""
        result = classifier._score_to_severity(score)
        assert result == expected


class TestMLSeverityClassifierCVSS:
    """Tests for CVSS estimation."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return MLSeverityClassifier()

    def test_estimate_cvss_critical(self, classifier):
        """Test CVSS for critical vulnerability."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.TRIVIAL,
            scope=ScopeLevel.PROTOCOL_WIDE,
            requires_auth=False,
        )
        cvss = classifier._estimate_cvss(factors, 1.0)

        assert cvss >= 9.0

    def test_estimate_cvss_informational(self, classifier):
        """Test CVSS for informational finding."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.INFORMATIONAL,
            exploitability=ExploitabilityLevel.COMPLEX,
            scope=ScopeLevel.FUNCTION_ONLY,
            requires_auth=True,
        )
        cvss = classifier._estimate_cvss(factors, 0.1)

        assert cvss == 0.0

    def test_estimate_cvss_medium(self, classifier):
        """Test CVSS for medium vulnerability."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.PARTIAL_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.CONTRACT_WIDE,
            requires_auth=False,
        )
        cvss = classifier._estimate_cvss(factors, 0.5)

        assert 4.0 <= cvss <= 7.0

    def test_estimate_cvss_is_rounded(self, classifier):
        """Test CVSS score is rounded to 1 decimal place."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.PARTIAL_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.CONTRACT_WIDE,
        )
        cvss = classifier._estimate_cvss(factors, 0.5)

        # Check it's rounded to 1 decimal
        assert cvss == round(cvss, 1)


class TestMLSeverityClassifierReasoning:
    """Tests for reasoning generation."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return MLSeverityClassifier()

    def test_generate_reasoning_includes_severity(self, classifier):
        """Test reasoning includes severity level."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.TRIVIAL,
            scope=ScopeLevel.PROTOCOL_WIDE,
        )
        reasoning = classifier._generate_reasoning(factors, 0.9, SeverityLevel.CRITICAL)

        assert "CRITICAL" in reasoning
        assert "0.90" in reasoning

    def test_generate_reasoning_includes_impact(self, classifier):
        """Test reasoning includes impact reasoning."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.CONTRACT_WIDE,
        )
        reasoning = classifier._generate_reasoning(factors, 0.7, SeverityLevel.HIGH)

        assert "total loss of funds" in reasoning

    def test_generate_reasoning_includes_modifiers(self, classifier):
        """Test reasoning includes modifiers."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.TRIVIAL,
            scope=ScopeLevel.PROTOCOL_WIDE,
            has_known_exploit=True,
            affects_funds=True,
            requires_auth=True,
        )
        reasoning = classifier._generate_reasoning(factors, 0.9, SeverityLevel.CRITICAL)

        assert "Known exploits exist" in reasoning
        assert "Directly affects funds" in reasoning
        assert "Requires authentication" in reasoning


class TestMLSeverityClassifierFactorAnalysis:
    """Tests for factor analysis methods."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return MLSeverityClassifier()

    def test_determine_scope_protocol_wide(self, classifier):
        """Test scope detection for protocol-wide."""
        description = "This affects all users of the protocol"
        scope = classifier._determine_scope(description, "")

        assert scope == ScopeLevel.PROTOCOL_WIDE

    def test_determine_scope_contract_wide(self, classifier):
        """Test scope detection for contract-wide."""
        description = "This affects the contract balance"
        scope = classifier._determine_scope(description, "")

        assert scope == ScopeLevel.CONTRACT_WIDE

    def test_determine_scope_function_only(self, classifier):
        """Test scope detection for function-only."""
        description = "Minor issue in helper function"
        scope = classifier._determine_scope(description, "")

        assert scope == ScopeLevel.FUNCTION_ONLY

    def test_check_known_exploit_dao(self, classifier):
        """Test detection of known DAO exploit."""
        description = "Similar to the DAO hack"
        result = classifier._check_known_exploit(description)

        assert result is True

    def test_check_known_exploit_wormhole(self, classifier):
        """Test detection of known Wormhole exploit."""
        description = "Pattern similar to Wormhole bridge exploit"
        result = classifier._check_known_exploit(description)

        assert result is True

    def test_check_known_exploit_none(self, classifier):
        """Test no known exploit detected."""
        description = "Standard vulnerability finding"
        result = classifier._check_known_exploit(description)

        assert result is False

    def test_check_affects_funds_transfer(self, classifier):
        """Test funds detection with transfer."""
        description = "Can transfer ETH to attacker"
        result = classifier._check_affects_funds(description, "")

        assert result is True

    def test_check_affects_funds_tokens(self, classifier):
        """Test funds detection with tokens."""
        code = "IERC20(token).transfer(attacker, amount);"
        result = classifier._check_affects_funds("", code)

        assert result is True

    def test_check_affects_funds_no_funds(self, classifier):
        """Test no funds affected."""
        description = "UI issue in dApp"
        result = classifier._check_affects_funds(description, "")

        assert result is False

    def test_check_requires_auth_onlyowner(self, classifier):
        """Test auth detection with onlyOwner."""
        code = "function withdraw() public onlyOwner {"
        result = classifier._check_requires_auth(code, None)

        assert result is True

    def test_check_requires_auth_msg_sender(self, classifier):
        """Test auth detection with msg.sender check."""
        code = "require(msg.sender == owner, 'Not owner');"
        result = classifier._check_requires_auth(code, None)

        assert result is True

    def test_check_requires_auth_no_auth(self, classifier):
        """Test no auth required."""
        code = "function publicFunction() public {"
        result = classifier._check_requires_auth(code, None)

        assert result is False

    def test_check_requires_auth_from_context(self, classifier):
        """Test auth from contract context."""
        context = ContractContext(
            contract_type="vault",
            has_value_handling=True,
            uses_access_control=True,
            uses_reentrancy_guard=False,
            solidity_version="0.8.20",
            is_upgradeable=False,
            estimated_tvl="high",
        )
        result = classifier._check_requires_auth("", context)

        assert result is True


class TestMLSeverityClassifierConfidence:
    """Tests for confidence calculation."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return MLSeverityClassifier()

    def test_calculate_confidence_known_exploit_boost(self, classifier):
        """Test known exploit boosts confidence."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.TRIVIAL,
            scope=ScopeLevel.PROTOCOL_WIDE,
            has_known_exploit=True,
        )
        confidence = classifier._calculate_confidence(factors, "critical", SeverityLevel.CRITICAL)

        assert confidence >= 0.79  # 0.7 base + 0.1 for known exploit

    def test_calculate_confidence_severity_match(self, classifier):
        """Test confidence when original matches predicted."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.PARTIAL_LOSS,
            exploitability=ExploitabilityLevel.MODERATE,
            scope=ScopeLevel.CONTRACT_WIDE,
        )
        confidence = classifier._calculate_confidence(factors, "high", SeverityLevel.HIGH)

        assert confidence >= 0.7

    def test_calculate_confidence_severity_mismatch(self, classifier):
        """Test confidence when there's large severity mismatch."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.TRIVIAL,
            scope=ScopeLevel.PROTOCOL_WIDE,
        )
        # Predicting critical when original was info
        confidence = classifier._calculate_confidence(factors, "info", SeverityLevel.CRITICAL)

        # Should have reduced confidence due to mismatch
        assert confidence < 0.8

    def test_calculate_confidence_capped_at_95(self, classifier):
        """Test confidence is capped at 0.95."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.TOTAL_LOSS,
            exploitability=ExploitabilityLevel.TRIVIAL,
            scope=ScopeLevel.PROTOCOL_WIDE,
            has_known_exploit=True,
            affects_funds=True,
        )
        confidence = classifier._calculate_confidence(factors, "critical", SeverityLevel.CRITICAL)

        assert confidence <= 0.95

    def test_calculate_confidence_floor_at_30(self, classifier):
        """Test confidence has floor at 0.30."""
        factors = SeverityFactors(
            financial_impact=ImpactLevel.INFORMATIONAL,
            exploitability=ExploitabilityLevel.COMPLEX,
            scope=ScopeLevel.FUNCTION_ONLY,
        )
        # Large mismatch
        confidence = classifier._calculate_confidence(factors, "info", SeverityLevel.CRITICAL)

        assert confidence >= 0.30


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestClassifySeverityFunction:
    """Tests for classify_severity convenience function."""

    def test_classify_severity_basic(self):
        """Test basic usage of classify_severity."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "description": "Reentrancy vulnerability",
        }
        result = classify_severity(finding)

        assert isinstance(result, SeverityPrediction)

    def test_classify_severity_with_context(self):
        """Test classify_severity with context."""
        finding = {
            "type": "access-control",
            "severity": "medium",
            "description": "Missing access control",
        }
        context = ContractContext(
            contract_type="vault",
            has_value_handling=True,
            uses_access_control=False,
            uses_reentrancy_guard=False,
            solidity_version="0.8.20",
            is_upgradeable=False,
            estimated_tvl="high",
        )
        result = classify_severity(finding, context)

        assert isinstance(result, SeverityPrediction)


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestMLSeverityClassifierEdgeCases:
    """Edge case tests for MLSeverityClassifier."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return MLSeverityClassifier()

    def test_empty_finding(self, classifier):
        """Test handling of empty finding."""
        finding = {}
        result = classifier.classify(finding)

        assert isinstance(result, SeverityPrediction)
        # Should use defaults
        assert result.factors.financial_impact == ImpactLevel.NO_DIRECT_LOSS

    def test_finding_with_location_snippet(self, classifier):
        """Test finding with location containing snippet."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "description": "Reentrancy",
            "location": {"snippet": "call{value: amount}('')"},
        }
        results = classifier.classify_batch([finding])

        assert len(results) == 1

    def test_special_characters_in_description(self, classifier):
        """Test handling of special characters."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "description": "Re-entrancy with <script>alert('xss')</script>",
        }
        result = classifier.classify(finding)

        assert isinstance(result, SeverityPrediction)

    def test_very_long_description(self, classifier):
        """Test handling of very long description."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "description": "A" * 10000,
        }
        result = classifier.classify(finding)

        assert isinstance(result, SeverityPrediction)

    def test_unicode_in_description(self, classifier):
        """Test handling of unicode characters."""
        finding = {
            "type": "access-control",
            "severity": "medium",
            "description": "Vulnerabilidad de control de acceso 漏洞",
        }
        result = classifier.classify(finding)

        assert isinstance(result, SeverityPrediction)


# =============================================================================
# Type Mappings Tests
# =============================================================================


class TestTypeMappings:
    """Tests for vulnerability type mappings."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return MLSeverityClassifier()

    @pytest.mark.parametrize(
        "vuln_type,expected_impact",
        [
            ("reentrancy", ImpactLevel.TOTAL_LOSS),
            ("flash-loan-attack", ImpactLevel.TOTAL_LOSS),
            ("governance-attack", ImpactLevel.TOTAL_LOSS),
            ("bridge-vulnerability", ImpactLevel.TOTAL_LOSS),
            ("access-control", ImpactLevel.PARTIAL_LOSS),
            ("oracle-manipulation", ImpactLevel.PARTIAL_LOSS),
            ("unchecked-call", ImpactLevel.NO_DIRECT_LOSS),
            ("front-running", ImpactLevel.NO_DIRECT_LOSS),
            ("gas-optimization", ImpactLevel.INFORMATIONAL),
        ],
    )
    def test_type_to_impact_mapping(self, classifier, vuln_type, expected_impact):
        """Test vulnerability type to impact mapping."""
        assert classifier.TYPE_IMPACT_MAP.get(vuln_type) == expected_impact

    @pytest.mark.parametrize(
        "vuln_type,expected_exploitability",
        [
            ("access-control", ExploitabilityLevel.TRIVIAL),
            ("unprotected-selfdestruct", ExploitabilityLevel.TRIVIAL),
            ("reentrancy", ExploitabilityLevel.MODERATE),
            ("oracle-manipulation", ExploitabilityLevel.MODERATE),
            ("flash-loan-attack", ExploitabilityLevel.COMPLEX),
            ("governance-attack", ExploitabilityLevel.COMPLEX),
        ],
    )
    def test_type_to_exploitability_mapping(self, classifier, vuln_type, expected_exploitability):
        """Test vulnerability type to exploitability mapping."""
        assert classifier.TYPE_EXPLOITABILITY_MAP.get(vuln_type) == expected_exploitability
