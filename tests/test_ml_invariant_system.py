"""
Tests for ML Invariant Synthesis and Validation System
=======================================================

Comprehensive tests for:
- MLInvariantSynthesizer: ML-enhanced invariant generation
- FeatureExtractor: Contract feature extraction
- InvariantPredictor: ML-based invariant prediction
- InvariantValidator: Foundry-based validation
- InvariantTestGenerator: Test file generation

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.adapters.invariant_synthesizer import (
    InvariantCategory,
    InvariantFormat,
    SynthesizedInvariant,
)
from src.ml.ml_invariant_synthesizer import (
    ContractFeatures,
    FeatureExtractor,
    InvariantPrediction,
    InvariantPredictor,
    MLInvariantSynthesizer,
    TrainingExample,
    extract_contract_features,
    predict_invariants,
    synthesize_with_ml,
)
from src.ml.invariant_validator import (
    InvariantTestGenerator,
    InvariantTestResult,
    InvariantValidator,
    ValidationReport,
    validate_invariants,
    quick_validate,
)
from src.poc.validators.foundry_runner import (
    FoundryResult,
    TestResult,
    TestStatus,
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_erc20_code():
    """Sample ERC20 contract code."""
    return '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyToken is ERC20, Ownable {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    constructor() ERC20("MyToken", "MTK") Ownable(msg.sender) {}

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    function burn(uint256 amount) public {
        _burn(msg.sender, amount);
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function balanceOf(address account) public view override returns (uint256) {
        return super.balanceOf(account);
    }
}
'''


@pytest.fixture
def sample_erc4626_code():
    """Sample ERC4626 vault contract code."""
    return '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract MyVault is ERC4626, ReentrancyGuard {
    constructor(IERC20 asset) ERC4626(asset) ERC20("Vault Token", "vTKN") {}

    function deposit(uint256 assets, address receiver) public override nonReentrant returns (uint256) {
        return super.deposit(assets, receiver);
    }

    function withdraw(uint256 assets, address receiver, address owner) public override nonReentrant returns (uint256) {
        return super.withdraw(assets, receiver, owner);
    }

    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view override returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? assets : assets * supply / totalAssets();
    }

    function convertToAssets(uint256 shares) public view override returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? shares : shares * totalAssets() / supply;
    }
}
'''


@pytest.fixture
def sample_defi_code():
    """Sample DeFi contract with flash loans."""
    return '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashLoanReceiver {
    function executeOperation(uint256 amount, uint256 fee, bytes calldata data) external;
}

contract FlashLender {
    IERC20 public token;
    uint256 public flashLoanFee = 9; // 0.09%

    function flashLoan(uint256 amount, bytes calldata data) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        token.transfer(msg.sender, amount);

        IFlashLoanReceiver(msg.sender).executeOperation(amount, amount * flashLoanFee / 10000, data);

        require(token.balanceOf(address(this)) >= balanceBefore + amount * flashLoanFee / 10000, "Flash loan not repaid");
    }

    function getPrice() public view returns (uint256) {
        return oracle.latestAnswer();
    }
}
'''


@pytest.fixture
def sample_invariants():
    """Sample synthesized invariants."""
    return [
        SynthesizedInvariant(
            name="total_supply_equals_sum",
            description="Total supply equals sum of all balances",
            category=InvariantCategory.ACCOUNTING,
            importance="CRITICAL",
            natural_language="The total supply must equal the sum of all user balances",
            solidity_assertion="totalSupply() == sum_of_balances",
            foundry_test="assertTrue(target.totalSupply() >= 0);",
            confidence=0.9,
        ),
        SynthesizedInvariant(
            name="no_negative_balance",
            description="Balances cannot be negative",
            category=InvariantCategory.ACCOUNTING,
            importance="HIGH",
            natural_language="No account can have a negative balance",
            solidity_assertion="balanceOf(user) >= 0",
            foundry_test="assertTrue(target.balanceOf(address(this)) >= 0);",
            confidence=0.95,
        ),
        SynthesizedInvariant(
            name="owner_access_control",
            description="Only owner can mint",
            category=InvariantCategory.ACCESS_CONTROL,
            importance="CRITICAL",
            natural_language="Minting is restricted to the contract owner",
            foundry_test="// Test owner access",
            confidence=0.85,
        ),
    ]


@pytest.fixture
def mock_foundry_result():
    """Mock successful Foundry test result."""
    return FoundryResult(
        success=True,
        tests=[
            TestResult(
                name="invariant_total_supply_equals_sum",
                status=TestStatus.PASSED,
                gas_used=50000,
                duration_ms=100,
            ),
            TestResult(
                name="invariant_no_negative_balance",
                status=TestStatus.PASSED,
                gas_used=45000,
                duration_ms=80,
            ),
            TestResult(
                name="invariant_owner_access_control",
                status=TestStatus.FAILED,
                gas_used=60000,
                duration_ms=150,
                error_message="Assertion failed",
            ),
        ],
        total_tests=3,
        passed=2,
        failed=1,
        skipped=0,
        total_gas=155000,
        execution_time_ms=330,
        raw_output="Tests completed",
        forge_version="0.2.0",
    )


# ============================================================================
# ContractFeatures Tests
# ============================================================================


class TestContractFeatures:
    """Tests for ContractFeatures dataclass."""

    def test_default_values(self):
        """Test default feature values."""
        features = ContractFeatures()
        assert features.line_count == 0
        assert features.function_count == 0
        assert features.is_erc20 is False
        assert features.has_access_control is False

    def test_to_vector(self):
        """Test conversion to numerical vector."""
        features = ContractFeatures(
            line_count=100,
            function_count=10,
            is_erc20=True,
            has_access_control=True,
        )
        vector = features.to_vector()

        assert isinstance(vector, list)
        assert len(vector) == 25  # Expected vector length
        assert all(isinstance(v, float) for v in vector)
        assert vector[5] == 1.0  # is_erc20

    def test_to_dict(self):
        """Test conversion to dictionary."""
        features = ContractFeatures(
            line_count=50,
            is_erc4626=True,
            has_flash_loan=True,
        )
        d = features.to_dict()

        assert d["line_count"] == 50
        assert d["is_erc4626"] is True
        assert d["has_flash_loan"] is True
        assert "function_count" in d


# ============================================================================
# FeatureExtractor Tests
# ============================================================================


class TestFeatureExtractor:
    """Tests for FeatureExtractor."""

    def test_extract_basic_metrics(self, sample_erc20_code):
        """Test basic metric extraction."""
        extractor = FeatureExtractor()
        features = extractor.extract(sample_erc20_code)

        assert features.line_count > 0
        assert features.function_count >= 4  # mint, burn, transfer, balanceOf
        assert features.import_count >= 2

    def test_detect_erc20(self, sample_erc20_code):
        """Test ERC20 detection."""
        extractor = FeatureExtractor()
        features = extractor.extract(sample_erc20_code)

        assert features.is_erc20 is True
        assert features.is_erc721 is False
        assert features.is_erc4626 is False

    def test_detect_erc4626(self, sample_erc4626_code):
        """Test ERC4626 vault detection."""
        extractor = FeatureExtractor()
        features = extractor.extract(sample_erc4626_code)

        assert features.is_erc4626 is True
        assert features.has_reentrancy_guard is True

    def test_detect_access_control(self, sample_erc20_code):
        """Test access control detection."""
        extractor = FeatureExtractor()
        features = extractor.extract(sample_erc20_code)

        assert features.has_access_control is True  # Ownable + onlyOwner

    def test_detect_defi_patterns(self, sample_defi_code):
        """Test DeFi pattern detection."""
        extractor = FeatureExtractor()
        features = extractor.extract(sample_defi_code)

        assert features.has_flash_loan is True
        assert features.has_oracle is True

    def test_detect_external_calls(self):
        """Test external call detection."""
        code = '''
        function risky() external {
            (bool success,) = target.call{value: 1 ether}("");
            target.delegatecall(data);
        }
        '''
        extractor = FeatureExtractor()
        features = extractor.extract(code)

        assert features.external_call_count >= 1
        assert features.delegatecall_count >= 1

    def test_detect_security_patterns(self):
        """Test security pattern detection."""
        code = '''
        contract Unsafe {
            function destroy() external {
                selfdestruct(payable(msg.sender));
            }

            function risky() external {
                assembly {
                    sstore(0, 1)
                }
            }

            function calc() external {
                unchecked {
                    x = x + 1;
                }
            }
        }
        '''
        extractor = FeatureExtractor()
        features = extractor.extract(code)

        assert features.selfdestruct_present is True
        assert features.assembly_blocks >= 1
        assert features.unchecked_blocks >= 1

    def test_empty_code(self):
        """Test with empty code."""
        extractor = FeatureExtractor()
        features = extractor.extract("")

        assert features.line_count == 1
        assert features.function_count == 0


# ============================================================================
# InvariantPredictor Tests
# ============================================================================


class TestInvariantPredictor:
    """Tests for InvariantPredictor."""

    def test_predict_for_erc20(self, sample_erc20_code):
        """Test predictions for ERC20 contract."""
        extractor = FeatureExtractor()
        predictor = InvariantPredictor()

        features = extractor.extract(sample_erc20_code)
        predictions = predictor.predict(features)

        assert len(predictions) > 0
        # Should predict accounting invariants for ERC20
        categories = [p.category for p in predictions]
        assert InvariantCategory.ACCOUNTING in categories

    def test_predict_for_vault(self, sample_erc4626_code):
        """Test predictions for ERC4626 vault."""
        extractor = FeatureExtractor()
        predictor = InvariantPredictor()

        features = extractor.extract(sample_erc4626_code)
        predictions = predictor.predict(features)

        assert len(predictions) > 0
        categories = [p.category for p in predictions]
        # Vault should have solvency invariants
        assert InvariantCategory.SOLVENCY in categories

    def test_prediction_confidence(self, sample_erc20_code):
        """Test prediction confidence scores."""
        extractor = FeatureExtractor()
        predictor = InvariantPredictor()

        features = extractor.extract(sample_erc20_code)
        predictions = predictor.predict(features)

        for pred in predictions:
            assert 0 <= pred.confidence <= 1
            assert 0 <= pred.relevance_score

    def test_prediction_limit(self, sample_erc20_code):
        """Test that predictions are limited to top 20."""
        extractor = FeatureExtractor()
        predictor = InvariantPredictor()

        features = extractor.extract(sample_erc20_code)
        predictions = predictor.predict(features)

        assert len(predictions) <= 20

    def test_prediction_sorting(self, sample_erc20_code):
        """Test that predictions are sorted by relevance * confidence."""
        extractor = FeatureExtractor()
        predictor = InvariantPredictor()

        features = extractor.extract(sample_erc20_code)
        predictions = predictor.predict(features)

        if len(predictions) >= 2:
            for i in range(len(predictions) - 1):
                score1 = predictions[i].relevance_score * predictions[i].confidence
                score2 = predictions[i + 1].relevance_score * predictions[i + 1].confidence
                assert score1 >= score2

    def test_feature_importance(self, sample_erc20_code):
        """Test feature importance in predictions."""
        extractor = FeatureExtractor()
        predictor = InvariantPredictor()

        features = extractor.extract(sample_erc20_code)
        predictions = predictor.predict(features)

        for pred in predictions:
            assert isinstance(pred.feature_importance, dict)

    def test_empty_features(self):
        """Test predictions with minimal features."""
        predictor = InvariantPredictor()
        features = ContractFeatures()  # All defaults

        predictions = predictor.predict(features)
        # Should still return some basic predictions
        assert isinstance(predictions, list)


# ============================================================================
# InvariantPrediction Tests
# ============================================================================


class TestInvariantPrediction:
    """Tests for InvariantPrediction dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        pred = InvariantPrediction(
            category=InvariantCategory.ACCOUNTING,
            template_name="total_supply_invariant",
            confidence=0.85,
            relevance_score=0.9,
            feature_importance={"is_erc20": 0.9},
        )
        d = pred.to_dict()

        assert d["category"] == "accounting"
        assert d["template_name"] == "total_supply_invariant"
        assert d["confidence"] == 0.85
        assert d["feature_importance"] == {"is_erc20": 0.9}


# ============================================================================
# TrainingExample Tests
# ============================================================================


class TestTrainingExample:
    """Tests for TrainingExample dataclass."""

    def test_to_dict(self, sample_invariants):
        """Test conversion to dictionary."""
        example = TrainingExample(
            contract_hash="abc123",
            features=ContractFeatures(is_erc20=True),
            invariants=sample_invariants[:1],
            validation_results={"inv1": True},
        )
        d = example.to_dict()

        assert d["contract_hash"] == "abc123"
        assert "features" in d
        assert "invariants" in d
        assert len(d["invariants"]) == 1


# ============================================================================
# MLInvariantSynthesizer Tests
# ============================================================================


class TestMLInvariantSynthesizer:
    """Tests for MLInvariantSynthesizer."""

    def test_initialization(self):
        """Test synthesizer initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            synth = MLInvariantSynthesizer(data_dir=Path(tmpdir))
            assert synth.data_dir.exists()

    def test_initialization_training_mode(self):
        """Test initialization with training mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            synth = MLInvariantSynthesizer(
                data_dir=Path(tmpdir),
                collect_training_data=True,
            )
            assert synth.collect_training_data is True

    @patch("src.ml.ml_invariant_synthesizer.InvariantSynthesizer")
    def test_synthesize_success(self, mock_base_synth, sample_erc20_code):
        """Test successful synthesis."""
        # Mock base synthesizer
        mock_instance = MagicMock()
        mock_instance.synthesize.return_value = {
            "status": "success",
            "invariants": [
                {
                    "name": "test_inv",
                    "description": "Test",
                    "category": "accounting",
                    "importance": "HIGH",
                    "natural_language": "Test invariant",
                    "confidence": 0.8,
                }
            ],
        }
        mock_base_synth.return_value = mock_instance

        with tempfile.TemporaryDirectory() as tmpdir:
            # Write test contract
            contract_file = Path(tmpdir) / "Test.sol"
            contract_file.write_text(sample_erc20_code)

            synth = MLInvariantSynthesizer(data_dir=Path(tmpdir))
            result = synth.synthesize(str(contract_file))

            assert result["status"] == "success"
            assert "features" in result
            assert "ml_enhanced" in result

    def test_synthesize_file_not_found(self):
        """Test synthesis with non-existent file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            synth = MLInvariantSynthesizer(data_dir=Path(tmpdir))
            result = synth.synthesize("/nonexistent/file.sol")

            assert result["status"] == "error"

    def test_add_validation_result(self):
        """Test adding validation results."""
        with tempfile.TemporaryDirectory() as tmpdir:
            synth = MLInvariantSynthesizer(
                data_dir=Path(tmpdir),
                collect_training_data=True,
            )

            # Add a training example first
            synth.training_examples.append(
                TrainingExample(
                    contract_hash="test123",
                    features=ContractFeatures(),
                    invariants=[],
                )
            )

            synth.add_validation_result("test123", "inv1", True)

            assert synth.training_examples[0].validation_results["inv1"] is True

    def test_get_training_stats_empty(self):
        """Test training stats with no examples."""
        with tempfile.TemporaryDirectory() as tmpdir:
            synth = MLInvariantSynthesizer(data_dir=Path(tmpdir))
            stats = synth.get_training_stats()

            assert stats["total_examples"] == 0

    def test_get_training_stats(self, sample_invariants):
        """Test training stats with examples."""
        with tempfile.TemporaryDirectory() as tmpdir:
            synth = MLInvariantSynthesizer(data_dir=Path(tmpdir))
            synth.training_examples = [
                TrainingExample(
                    contract_hash="abc",
                    features=ContractFeatures(),
                    invariants=sample_invariants,
                    validation_results={"inv1": True, "inv2": False},
                )
            ]

            stats = synth.get_training_stats()

            assert stats["total_examples"] == 1
            assert stats["total_invariants"] == 3
            assert stats["validated_invariants"] == 2
            assert stats["passed_validations"] == 1


# ============================================================================
# Convenience Function Tests
# ============================================================================


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_extract_contract_features(self, sample_erc20_code):
        """Test extract_contract_features function."""
        features = extract_contract_features(sample_erc20_code)
        assert isinstance(features, ContractFeatures)
        assert features.is_erc20 is True

    def test_predict_invariants(self, sample_erc20_code):
        """Test predict_invariants function."""
        predictions = predict_invariants(sample_erc20_code)
        assert isinstance(predictions, list)
        assert all(isinstance(p, InvariantPrediction) for p in predictions)


# ============================================================================
# InvariantTestGenerator Tests
# ============================================================================


class TestInvariantTestGenerator:
    """Tests for InvariantTestGenerator."""

    def test_initialization(self):
        """Test generator initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = InvariantTestGenerator(output_dir=Path(tmpdir))
            assert generator.output_dir.exists()

    def test_generate_test_file(self, sample_invariants):
        """Test test file generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = InvariantTestGenerator(output_dir=Path(tmpdir))

            test_file = generator.generate_test_file(
                invariants=sample_invariants,
                contract_name="MyToken",
                contract_path="src/MyToken.sol",
            )

            assert test_file.exists()
            content = test_file.read_text()
            assert "contract MyTokenInvariantTest" in content
            assert "invariant_" in content

    def test_generate_test_file_no_valid_invariants(self):
        """Test error when no valid invariants."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = InvariantTestGenerator(output_dir=Path(tmpdir))

            # Invariant without foundry_test or solidity_assertion
            bad_inv = SynthesizedInvariant(
                name="bad",
                description="No test",
                category=InvariantCategory.CUSTOM,
                importance="LOW",
                natural_language="Bad invariant",
            )

            with pytest.raises(ValueError):
                generator.generate_test_file(
                    invariants=[bad_inv],
                    contract_name="Test",
                    contract_path="Test.sol",
                )

    def test_generate_individual_tests(self, sample_invariants):
        """Test individual test file generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = InvariantTestGenerator(output_dir=Path(tmpdir))

            test_files = generator.generate_individual_tests(
                invariants=sample_invariants,
                contract_name="MyToken",
                contract_path="src/MyToken.sol",
            )

            assert len(test_files) > 0
            for f in test_files:
                assert f.exists()

    def test_sanitize_name(self):
        """Test name sanitization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = InvariantTestGenerator(output_dir=Path(tmpdir))

            assert generator._sanitize_name("valid_name") == "valid_name"
            assert generator._sanitize_name("has-dash") == "has_dash"
            assert generator._sanitize_name("123start") == "inv_123start"
            assert generator._sanitize_name("") == "unnamed"

    def test_wrap_assertion(self):
        """Test assertion wrapping."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = InvariantTestGenerator(output_dir=Path(tmpdir))

            assert "assertTrue" in generator._wrap_assertion("x > 0")
            assert generator._wrap_assertion("assert(x);") == "assert(x);"

    def test_cleanup(self):
        """Test cleanup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir) / "tests_to_clean"
            generator = InvariantTestGenerator(output_dir=test_dir)
            # output_dir is already created by InvariantTestGenerator
            (generator.output_dir / "test.sol").touch()

            generator.cleanup()
            assert not generator.output_dir.exists()


# ============================================================================
# InvariantTestResult Tests
# ============================================================================


class TestInvariantTestResult:
    """Tests for InvariantTestResult dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = InvariantTestResult(
            invariant_name="test_inv",
            category=InvariantCategory.ACCOUNTING,
            passed=True,
            test_status=TestStatus.PASSED,
            gas_used=50000,
            execution_time_ms=100,
        )
        d = result.to_dict()

        assert d["invariant_name"] == "test_inv"
        assert d["passed"] is True
        assert d["gas_used"] == 50000


# ============================================================================
# ValidationReport Tests
# ============================================================================


class TestValidationReport:
    """Tests for ValidationReport dataclass."""

    def test_pass_rate_empty(self):
        """Test pass rate with no invariants."""
        report = ValidationReport(
            contract_name="Test",
            contract_hash="abc",
            total_invariants=0,
            passed=0,
            failed=0,
            skipped=0,
            results=[],
            total_execution_time_ms=0,
            total_gas_used=0,
        )
        assert report.pass_rate == 0.0

    def test_pass_rate(self):
        """Test pass rate calculation."""
        report = ValidationReport(
            contract_name="Test",
            contract_hash="abc",
            total_invariants=4,
            passed=3,
            failed=1,
            skipped=0,
            results=[],
            total_execution_time_ms=100,
            total_gas_used=50000,
        )
        assert report.pass_rate == 0.75

    def test_to_dict(self):
        """Test conversion to dictionary."""
        report = ValidationReport(
            contract_name="Test",
            contract_hash="abc123",
            total_invariants=2,
            passed=1,
            failed=1,
            skipped=0,
            results=[],
            total_execution_time_ms=200,
            total_gas_used=100000,
            foundry_version="0.2.0",
        )
        d = report.to_dict()

        assert d["contract_name"] == "Test"
        assert d["pass_rate"] == 0.5
        assert d["foundry_version"] == "0.2.0"


# ============================================================================
# InvariantValidator Tests
# ============================================================================


class TestInvariantValidator:
    """Tests for InvariantValidator."""

    def test_initialization(self):
        """Test validator initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = InvariantValidator(project_dir=tmpdir)
            assert validator.project_dir == Path(tmpdir)
            assert validator.fuzzing_runs == 256

    def test_initialization_custom_settings(self):
        """Test initialization with custom settings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = InvariantValidator(
                project_dir=tmpdir,
                fuzzing_runs=512,
                fuzzing_depth=200,
                timeout=1200,
            )
            assert validator.fuzzing_runs == 512
            assert validator.fuzzing_depth == 200
            assert validator.timeout == 1200

    def test_validate_no_testable(self, sample_invariants):
        """Test validation with no testable invariants."""
        # Remove all test code
        bad_invariants = [
            SynthesizedInvariant(
                name="no_test",
                description="No test code",
                category=InvariantCategory.CUSTOM,
                importance="LOW",
                natural_language="Test",
            )
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            validator = InvariantValidator(project_dir=tmpdir)
            report = validator.validate(
                invariants=bad_invariants,
                contract_name="Test",
                contract_path="Test.sol",
            )

            assert report.total_invariants == 0
            assert report.skipped == 1
            assert len(report.errors) > 0

    @patch.object(InvariantValidator, "_validate_batch")
    def test_validate_batch_mode(self, mock_validate, sample_invariants):
        """Test validation in batch mode."""
        mock_validate.return_value = ValidationReport(
            contract_name="Test",
            contract_hash="abc",
            total_invariants=3,
            passed=2,
            failed=1,
            skipped=0,
            results=[],
            total_execution_time_ms=100,
            total_gas_used=50000,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            validator = InvariantValidator(project_dir=tmpdir)
            report = validator.validate(
                invariants=sample_invariants,
                contract_name="Test",
                contract_path="Test.sol",
                run_individual=False,
            )

            mock_validate.assert_called_once()
            assert report.total_invariants == 3

    def test_get_feedback_for_ml(self):
        """Test ML feedback generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = InvariantValidator(project_dir=tmpdir)

            report = ValidationReport(
                contract_name="Test",
                contract_hash="abc123",
                total_invariants=2,
                passed=1,
                failed=1,
                skipped=0,
                results=[
                    InvariantTestResult(
                        invariant_name="inv1",
                        category=InvariantCategory.ACCOUNTING,
                        passed=True,
                        test_status=TestStatus.PASSED,
                    ),
                    InvariantTestResult(
                        invariant_name="inv2",
                        category=InvariantCategory.SOLVENCY,
                        passed=False,
                        test_status=TestStatus.FAILED,
                    ),
                ],
                total_execution_time_ms=100,
                total_gas_used=50000,
            )

            feedback = validator.get_feedback_for_ml(report)

            assert feedback["contract_hash"] == "abc123"
            assert feedback["pass_rate"] == 0.5
            assert len(feedback["invariants"]) == 2

    def test_get_validation_stats_empty(self):
        """Test stats with no validations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = InvariantValidator(project_dir=tmpdir)
            stats = validator.get_validation_stats()

            assert stats["total_validations"] == 0

    def test_get_validation_stats(self):
        """Test validation statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = InvariantValidator(project_dir=tmpdir)

            # Add validation history
            validator.validation_history = [
                ValidationReport(
                    contract_name="Test1",
                    contract_hash="abc",
                    total_invariants=4,
                    passed=3,
                    failed=1,
                    skipped=0,
                    results=[
                        InvariantTestResult(
                            invariant_name="inv1",
                            category=InvariantCategory.ACCOUNTING,
                            passed=True,
                            test_status=TestStatus.PASSED,
                        ),
                    ],
                    total_execution_time_ms=100,
                    total_gas_used=50000,
                ),
            ]

            stats = validator.get_validation_stats()

            assert stats["total_validations"] == 1
            assert stats["total_invariants"] == 4
            assert stats["total_passed"] == 3

    def test_save_report(self):
        """Test saving validation report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = InvariantValidator(project_dir=tmpdir)

            report = ValidationReport(
                contract_name="Test",
                contract_hash="abc",
                total_invariants=2,
                passed=1,
                failed=1,
                skipped=0,
                results=[],
                total_execution_time_ms=100,
                total_gas_used=50000,
            )

            output_path = Path(tmpdir) / "report.json"
            validator.save_report(report, output_path)

            assert output_path.exists()
            with open(output_path) as f:
                data = json.load(f)
            assert data["contract_name"] == "Test"

    def test_cleanup(self):
        """Test cleanup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = InvariantValidator(project_dir=tmpdir)
            validator.test_generator.output_dir.mkdir(parents=True, exist_ok=True)
            (validator.test_generator.output_dir / "test.sol").touch()

            validator.cleanup()
            # Cleanup should remove generated files


# ============================================================================
# Integration Tests
# ============================================================================


class TestMLInvariantIntegration:
    """Integration tests for ML invariant system."""

    def test_full_pipeline_erc20(self, sample_erc20_code):
        """Test full pipeline: extraction -> prediction -> synthesis setup."""
        # Extract features
        features = extract_contract_features(sample_erc20_code)
        assert features.is_erc20 is True
        assert features.has_access_control is True

        # Get predictions
        predictions = predict_invariants(sample_erc20_code)
        assert len(predictions) > 0

        # Check relevant categories are predicted
        categories = [p.category for p in predictions]
        assert InvariantCategory.ACCOUNTING in categories

    def test_full_pipeline_vault(self, sample_erc4626_code):
        """Test full pipeline for vault contract."""
        features = extract_contract_features(sample_erc4626_code)
        assert features.is_erc4626 is True
        assert features.has_reentrancy_guard is True

        predictions = predict_invariants(sample_erc4626_code)
        categories = [p.category for p in predictions]
        assert InvariantCategory.SOLVENCY in categories

    def test_test_generation_and_validation_setup(self, sample_invariants):
        """Test test generation pipeline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = InvariantTestGenerator(output_dir=Path(tmpdir))

            # Generate test file
            test_file = generator.generate_test_file(
                invariants=sample_invariants,
                contract_name="TestContract",
                contract_path="src/TestContract.sol",
                setup_code="target = new TestContract();",
            )

            assert test_file.exists()
            content = test_file.read_text()

            # Verify content
            assert "pragma solidity" in content
            assert "import" in content
            assert "function setUp()" in content
            assert "function invariant_" in content

    def test_validation_report_generation(self, sample_invariants):
        """Test validation report structure."""
        results = [
            InvariantTestResult(
                invariant_name=inv.name,
                category=inv.category,
                passed=i % 2 == 0,
                test_status=TestStatus.PASSED if i % 2 == 0 else TestStatus.FAILED,
                gas_used=50000 + i * 1000,
            )
            for i, inv in enumerate(sample_invariants)
        ]

        report = ValidationReport(
            contract_name="TestContract",
            contract_hash="test123",
            total_invariants=len(sample_invariants),
            passed=sum(1 for r in results if r.passed),
            failed=sum(1 for r in results if not r.passed),
            skipped=0,
            results=results,
            total_execution_time_ms=500,
            total_gas_used=sum(r.gas_used or 0 for r in results),
        )

        # Verify report
        assert report.total_invariants == 3
        assert 0 <= report.pass_rate <= 1

        # Verify serialization
        d = report.to_dict()
        assert "contract_name" in d
        assert "pass_rate" in d
        assert "results" in d


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_extractor_malformed_code(self):
        """Test extraction with malformed Solidity code."""
        extractor = FeatureExtractor()
        features = extractor.extract("this is not { valid solidity }")

        # Should not crash, just return minimal features
        assert isinstance(features, ContractFeatures)

    def test_predictor_extreme_features(self):
        """Test prediction with extreme feature values."""
        predictor = InvariantPredictor()

        features = ContractFeatures(
            line_count=100000,
            function_count=1000,
            external_call_count=500,
        )

        predictions = predictor.predict(features)
        # Should handle extreme values without crashing
        assert isinstance(predictions, list)

    def test_generator_special_characters_in_name(self, sample_invariants):
        """Test generator with special characters in invariant names."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = InvariantTestGenerator(output_dir=Path(tmpdir))

            # Invariant with special characters in name
            special_inv = SynthesizedInvariant(
                name="test-inv@#$%^&*",
                description="Special chars",
                category=InvariantCategory.CUSTOM,
                importance="LOW",
                natural_language="Test",
                solidity_assertion="true",
            )

            test_file = generator.generate_test_file(
                invariants=[special_inv],
                contract_name="Test",
                contract_path="Test.sol",
            )

            content = test_file.read_text()
            # Should have sanitized function name (function invariant_test_inv_______)
            # Note: @ in NatSpec comments (@title, @notice) is expected
            assert "function invariant_test_inv" in content
            # The function name should not have special chars
            assert "function invariant_test-inv" not in content
            assert "function invariant_test@" not in content

    def test_validator_with_fork_url(self):
        """Test validator initialization with fork URL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            validator = InvariantValidator(
                project_dir=tmpdir,
                fork_url="https://eth-mainnet.g.alchemy.com/v2/demo",
            )
            assert validator.fork_url is not None

    def test_training_data_persistence(self, sample_invariants):
        """Test training data save/load."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create and save
            synth1 = MLInvariantSynthesizer(
                data_dir=Path(tmpdir),
                collect_training_data=True,
            )
            synth1.training_examples.append(
                TrainingExample(
                    contract_hash="test",
                    features=ContractFeatures(is_erc20=True),
                    invariants=sample_invariants[:1],
                )
            )
            synth1._save_training_data()

            # Check file exists
            data_file = Path(tmpdir) / "training_data.json"
            assert data_file.exists()

            # Create new instance and load
            synth2 = MLInvariantSynthesizer(
                data_dir=Path(tmpdir),
                collect_training_data=True,
            )
            # Loading happens in __init__


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
