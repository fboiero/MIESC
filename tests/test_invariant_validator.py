"""
Tests for src/ml/invariant_validator.py

Comprehensive tests for invariant validation including:
- InvariantTestResult and ValidationReport dataclasses
- InvariantTestGenerator class
- InvariantValidator class
- Convenience functions
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.adapters.invariant_synthesizer import InvariantCategory, SynthesizedInvariant
from src.ml.invariant_validator import (
    InvariantTestGenerator,
    InvariantTestResult,
    InvariantValidator,
    ValidationReport,
)
from src.poc.validators.foundry_runner import FoundryResult, TestResult, TestStatus


class TestInvariantTestResult:
    """Tests for InvariantTestResult dataclass."""

    def test_default_values(self):
        """Test default values."""
        result = InvariantTestResult(
            invariant_name="balance_positive",
            category=InvariantCategory.ACCOUNTING,
            passed=True,
            test_status=TestStatus.PASSED,
        )
        assert result.invariant_name == "balance_positive"
        assert result.category == InvariantCategory.ACCOUNTING
        assert result.passed is True
        assert result.gas_used is None
        assert result.execution_time_ms == 0
        assert result.error_message is None
        assert result.counterexample is None
        assert result.fuzzing_runs == 0

    def test_with_all_values(self):
        """Test with all values set."""
        result = InvariantTestResult(
            invariant_name="test",
            category=InvariantCategory.ACCESS_CONTROL,
            passed=False,
            test_status=TestStatus.FAILED,
            gas_used=50000,
            execution_time_ms=150.5,
            error_message="Assertion failed",
            counterexample="x=100, y=0",
            fuzzing_runs=256,
            traces="Call trace...",
        )
        assert result.gas_used == 50000
        assert result.counterexample == "x=100, y=0"

    def test_to_dict(self):
        """Test to_dict method."""
        result = InvariantTestResult(
            invariant_name="test",
            category=InvariantCategory.STATE_TRANSITION,
            passed=True,
            test_status=TestStatus.PASSED,
            gas_used=25000,
            fuzzing_runs=128,
        )
        d = result.to_dict()
        assert d["invariant_name"] == "test"
        assert d["category"] == "state_transition"
        assert d["passed"] is True
        assert d["test_status"] == "passed"
        assert d["gas_used"] == 25000
        assert d["fuzzing_runs"] == 128


class TestValidationReport:
    """Tests for ValidationReport dataclass."""

    def test_default_values(self):
        """Test default values."""
        report = ValidationReport(
            contract_name="TestContract",
            contract_hash="abc123",
            total_invariants=10,
            passed=8,
            failed=1,
            skipped=1,
            results=[],
            total_execution_time_ms=1000.0,
            total_gas_used=500000,
        )
        assert report.contract_name == "TestContract"
        assert report.errors == []
        assert report.foundry_version is None

    def test_pass_rate_normal(self):
        """Test pass_rate calculation."""
        report = ValidationReport(
            contract_name="Test",
            contract_hash="abc",
            total_invariants=10,
            passed=7,
            failed=3,
            skipped=0,
            results=[],
            total_execution_time_ms=0,
            total_gas_used=0,
        )
        assert report.pass_rate == 0.7

    def test_pass_rate_zero_invariants(self):
        """Test pass_rate with zero invariants."""
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

    def test_to_dict(self):
        """Test to_dict method."""
        result = InvariantTestResult(
            invariant_name="test",
            category=InvariantCategory.ACCOUNTING,
            passed=True,
            test_status=TestStatus.PASSED,
        )
        report = ValidationReport(
            contract_name="TestContract",
            contract_hash="abc123",
            total_invariants=1,
            passed=1,
            failed=0,
            skipped=0,
            results=[result],
            total_execution_time_ms=500.0,
            total_gas_used=25000,
            foundry_version="0.2.0",
            errors=["Warning 1"],
        )
        d = report.to_dict()
        assert d["contract_name"] == "TestContract"
        assert d["pass_rate"] == 1.0
        assert len(d["results"]) == 1
        assert d["foundry_version"] == "0.2.0"
        assert "timestamp" in d


class TestInvariantTestGenerator:
    """Tests for InvariantTestGenerator class."""

    @pytest.fixture
    def generator(self, tmp_path):
        """Create generator with temp directory."""
        return InvariantTestGenerator(output_dir=tmp_path)

    @pytest.fixture
    def sample_invariant(self):
        """Create sample invariant."""
        return SynthesizedInvariant(
            name="balance_positive",
            category=InvariantCategory.ACCOUNTING,
            description="Balance should always be positive",
            importance="HIGH",
            natural_language="The balance must remain non-negative",
            solidity_assertion="target.balance() >= 0",
        )

    @pytest.fixture
    def invariant_with_foundry_test(self):
        """Create invariant with foundry_test."""
        return SynthesizedInvariant(
            name="owner_set",
            category=InvariantCategory.ACCESS_CONTROL,
            description="Owner should be set",
            importance="CRITICAL",
            natural_language="The contract owner must always be set",
            foundry_test='assertNotEq(target.owner(), address(0), "Owner not set");',
        )

    def test_init_default_output_dir(self):
        """Test initialization with default output directory."""
        gen = InvariantTestGenerator()
        assert gen.output_dir.exists()

    def test_init_custom_output_dir(self, tmp_path):
        """Test initialization with custom output directory."""
        output = tmp_path / "custom"
        gen = InvariantTestGenerator(output_dir=output)
        assert gen.output_dir == output
        assert gen.output_dir.exists()

    def test_generate_test_file(self, generator, sample_invariant):
        """Test generating test file."""
        test_file = generator.generate_test_file(
            invariants=[sample_invariant],
            contract_name="Token",
            contract_path="src/Token.sol",
        )
        assert test_file.exists()
        content = test_file.read_text()
        assert "Token" in content
        assert "invariant_" in content

    def test_generate_test_file_with_foundry_test(self, generator, invariant_with_foundry_test):
        """Test generating test file with foundry_test field."""
        test_file = generator.generate_test_file(
            invariants=[invariant_with_foundry_test],
            contract_name="Contract",
            contract_path="src/Contract.sol",
        )
        content = test_file.read_text()
        assert "assertNotEq" in content

    def test_generate_test_file_custom_setup(self, generator, sample_invariant):
        """Test with custom setup code."""
        test_file = generator.generate_test_file(
            invariants=[sample_invariant],
            contract_name="Token",
            contract_path="src/Token.sol",
            setup_code="target = new Token(1000);",
        )
        content = test_file.read_text()
        assert "target = new Token(1000);" in content

    def test_generate_test_file_no_valid_invariants(self, generator):
        """Test with no valid invariants raises error."""
        inv = SynthesizedInvariant(
            name="no_test",
            category=InvariantCategory.CUSTOM,
            description="No test available",
            importance="LOW",
            natural_language="No testable assertion",
            # No foundry_test or solidity_assertion
        )
        with pytest.raises(ValueError, match="No valid invariants"):
            generator.generate_test_file(
                invariants=[inv],
                contract_name="Test",
                contract_path="src/Test.sol",
            )

    def test_generate_individual_tests(self, generator, sample_invariant):
        """Test generating individual test files."""
        test_files = generator.generate_individual_tests(
            invariants=[sample_invariant],
            contract_name="Token",
            contract_path="src/Token.sol",
        )
        assert len(test_files) == 1
        assert test_files[0].exists()

    def test_wrap_assertion_already_statement(self, generator):
        """Test wrapping assertion that's already a statement."""
        result = generator._wrap_assertion("require(x > 0);")
        assert result == "require(x > 0);"

    def test_wrap_assertion_condition(self, generator):
        """Test wrapping a condition in assertTrue."""
        result = generator._wrap_assertion("balance > 0")
        assert "assertTrue" in result
        assert "balance > 0" in result

    def test_wrap_assertion_assert_keyword(self, generator):
        """Test wrapping assertion starting with assert."""
        result = generator._wrap_assertion("assert(x > 0)")
        assert result == "assert(x > 0);"

    def test_sanitize_name(self, generator):
        """Test name sanitization."""
        assert generator._sanitize_name("valid_name") == "valid_name"
        assert generator._sanitize_name("with-dash") == "with_dash"
        assert generator._sanitize_name("with space") == "with_space"
        assert generator._sanitize_name("123start") == "inv_123start"
        assert generator._sanitize_name("") == "unnamed"

    def test_cleanup(self, tmp_path):
        """Test cleanup removes output directory."""
        output_dir = tmp_path / "test_output"
        gen = InvariantTestGenerator(output_dir=output_dir)
        assert output_dir.exists()
        gen.cleanup()
        assert not output_dir.exists()


def _make_foundry_result(
    success: bool = True,
    tests: list = None,
    total_tests: int = 1,
    passed: int = 1,
    failed: int = 0,
    skipped: int = 0,
    total_gas: int = 25000,
    execution_time_ms: float = 100.0,
    raw_output: str = "",
    forge_version: str = None,
    error: str = None,
) -> FoundryResult:
    """Helper to create FoundryResult with all required fields."""
    if tests is None:
        tests = []
    return FoundryResult(
        success=success,
        tests=tests,
        total_tests=total_tests,
        passed=passed,
        failed=failed,
        skipped=skipped,
        total_gas=total_gas,
        execution_time_ms=execution_time_ms,
        raw_output=raw_output,
        forge_version=forge_version,
        error=error,
    )


class TestInvariantValidator:
    """Tests for InvariantValidator class."""

    @pytest.fixture
    def mock_runner(self):
        """Create mock FoundryRunner."""
        runner = MagicMock()
        runner.run_test.return_value = _make_foundry_result(
            success=True,
            tests=[
                TestResult(
                    name="invariant_test",
                    status=TestStatus.PASSED,
                    gas_used=25000,
                    duration_ms=100.0,
                )
            ],
            total_tests=1,
            passed=1,
            failed=0,
            skipped=0,
            total_gas=25000,
            execution_time_ms=100.0,
            raw_output="",
            forge_version="0.2.0",
        )
        return runner

    @pytest.fixture
    def validator(self, tmp_path, mock_runner):
        """Create validator with mocked runner."""
        with patch("src.ml.invariant_validator.FoundryRunner", return_value=mock_runner):
            val = InvariantValidator(project_dir=tmp_path)
            val.runner = mock_runner
            return val

    @pytest.fixture
    def sample_invariant(self):
        """Create sample invariant."""
        return SynthesizedInvariant(
            name="test",
            category=InvariantCategory.ACCOUNTING,
            description="Test invariant",
            importance="HIGH",
            natural_language="Value must be positive",
            solidity_assertion="target.value() > 0",
        )

    def test_init(self, tmp_path):
        """Test initialization."""
        with patch("src.ml.invariant_validator.FoundryRunner"):
            val = InvariantValidator(
                project_dir=tmp_path,
                fuzzing_runs=512,
                fuzzing_depth=50,
                timeout=300,
            )
            assert val.fuzzing_runs == 512
            assert val.fuzzing_depth == 50
            assert val.timeout == 300

    def test_validate_no_testable_invariants(self, validator):
        """Test validate with no testable invariants."""
        inv = SynthesizedInvariant(
            name="no_test",
            category=InvariantCategory.CUSTOM,
            description="No test",
            importance="LOW",
            natural_language="No testable assertion",
        )
        report = validator.validate(
            invariants=[inv],
            contract_name="Test",
            contract_path="src/Test.sol",
        )
        assert report.total_invariants == 0
        assert report.skipped == 1
        assert "No testable invariants" in report.errors[0]

    def test_validate_batch(self, validator, sample_invariant, mock_runner):
        """Test batch validation."""
        mock_runner.run_test.return_value = _make_foundry_result(
            success=True,
            tests=[
                TestResult(
                    name="invariant_test",
                    status=TestStatus.PASSED,
                    gas_used=25000,
                    duration_ms=100.0,
                )
            ],
            total_tests=1,
            passed=1,
            failed=0,
            skipped=0,
            total_gas=25000,
            execution_time_ms=100.0,
            raw_output="",
        )

        with patch.object(validator.test_generator, "generate_test_file") as mock_gen:
            mock_gen.return_value = Path("/tmp/test.sol")

            report = validator.validate(
                invariants=[sample_invariant],
                contract_name="Test",
                contract_path="src/Test.sol",
                run_individual=False,
            )

            assert report.contract_name == "Test"
            assert report in validator.validation_history

    def test_validate_individual(self, validator, sample_invariant, mock_runner):
        """Test individual validation."""
        mock_runner.run_test.return_value = _make_foundry_result(
            success=True,
            tests=[
                TestResult(
                    name="invariant_test",
                    status=TestStatus.PASSED,
                    gas_used=25000,
                    duration_ms=100.0,
                )
            ],
            total_tests=1,
            passed=1,
            failed=0,
            skipped=0,
            total_gas=25000,
            execution_time_ms=100.0,
            raw_output="",
        )

        with patch.object(validator.test_generator, "generate_individual_tests") as mock_gen:
            mock_gen.return_value = [Path("/tmp/test.sol")]

            report = validator.validate(
                invariants=[sample_invariant],
                contract_name="Test",
                contract_path="src/Test.sol",
                run_individual=True,
            )

            assert report.total_invariants == 1

    def test_validate_exception_handling(self, validator, sample_invariant):
        """Test validation handles exceptions."""
        with patch.object(validator.test_generator, "generate_test_file") as mock_gen:
            mock_gen.side_effect = Exception("Generation failed")

            report = validator.validate(
                invariants=[sample_invariant],
                contract_name="Test",
                contract_path="src/Test.sol",
            )

            assert len(report.errors) > 0
            assert "Generation failed" in report.errors[0]

    def test_get_feedback_for_ml(self, validator):
        """Test ML feedback generation."""
        result = InvariantTestResult(
            invariant_name="test",
            category=InvariantCategory.ACCOUNTING,
            passed=True,
            test_status=TestStatus.PASSED,
            gas_used=25000,
        )
        report = ValidationReport(
            contract_name="Test",
            contract_hash="abc123",
            total_invariants=1,
            passed=1,
            failed=0,
            skipped=0,
            results=[result],
            total_execution_time_ms=100.0,
            total_gas_used=25000,
        )

        feedback = validator.get_feedback_for_ml(report)
        assert feedback["contract_hash"] == "abc123"
        assert feedback["pass_rate"] == 1.0
        assert len(feedback["invariants"]) == 1
        assert feedback["invariants"][0]["passed"] is True

    def test_get_validation_stats_empty(self, validator):
        """Test stats with no validations."""
        stats = validator.get_validation_stats()
        assert stats["total_validations"] == 0

    def test_get_validation_stats(self, validator):
        """Test stats with validations."""
        result = InvariantTestResult(
            invariant_name="test",
            category=InvariantCategory.ACCOUNTING,
            passed=True,
            test_status=TestStatus.PASSED,
        )
        report = ValidationReport(
            contract_name="Test",
            contract_hash="abc",
            total_invariants=2,
            passed=1,
            failed=1,
            skipped=0,
            results=[result],
            total_execution_time_ms=200.0,
            total_gas_used=50000,
        )
        validator.validation_history.append(report)

        stats = validator.get_validation_stats()
        assert stats["total_validations"] == 1
        assert stats["total_invariants"] == 2
        assert stats["total_passed"] == 1
        assert stats["total_failed"] == 1
        assert "category_breakdown" in stats

    def test_save_report(self, validator, tmp_path):
        """Test saving report to file."""
        report = ValidationReport(
            contract_name="Test",
            contract_hash="abc",
            total_invariants=1,
            passed=1,
            failed=0,
            skipped=0,
            results=[],
            total_execution_time_ms=100.0,
            total_gas_used=25000,
        )

        output_path = tmp_path / "report.json"
        validator.save_report(report, output_path)

        assert output_path.exists()
        with open(output_path) as f:
            data = json.load(f)
            assert data["contract_name"] == "Test"

    def test_cleanup(self, validator):
        """Test cleanup calls test_generator cleanup."""
        with patch.object(validator.test_generator, "cleanup") as mock_cleanup:
            validator.cleanup()
            mock_cleanup.assert_called_once()


class TestMapResultsToInvariants:
    """Tests for _map_results_to_invariants method."""

    @pytest.fixture
    def validator(self, tmp_path):
        """Create validator."""
        with patch("src.ml.invariant_validator.FoundryRunner"):
            return InvariantValidator(project_dir=tmp_path)

    def test_map_matching_result(self, validator):
        """Test mapping when test result matches invariant."""
        inv = SynthesizedInvariant(
            name="balance_check",
            category=InvariantCategory.ACCOUNTING,
            description="Check balance",
            importance="HIGH",
            natural_language="Balance must be checked",
            solidity_assertion="true",
        )

        foundry_result = _make_foundry_result(
            success=True,
            tests=[
                TestResult(
                    name="invariant_balance_check",
                    status=TestStatus.PASSED,
                    gas_used=10000,
                    duration_ms=50.0,
                )
            ],
            total_tests=1,
            passed=1,
            failed=0,
            skipped=0,
            total_gas=10000,
            execution_time_ms=50.0,
            raw_output="",
        )

        results = validator._map_results_to_invariants([inv], foundry_result)
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].gas_used == 10000

    def test_map_no_matching_result(self, validator):
        """Test mapping when no test result matches."""
        inv = SynthesizedInvariant(
            name="missing_test",
            category=InvariantCategory.CUSTOM,
            description="No match",
            importance="LOW",
            natural_language="Test is missing",
            solidity_assertion="true",
        )

        foundry_result = _make_foundry_result(
            success=True,
            tests=[],
            total_tests=0,
            passed=0,
            failed=0,
            skipped=0,
            total_gas=0,
            execution_time_ms=0.0,
            raw_output="",
        )

        results = validator._map_results_to_invariants([inv], foundry_result)
        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].test_status == TestStatus.SKIPPED


class TestValidateIndividualEdgeCases:
    """Edge case tests for individual validation."""

    @pytest.fixture
    def validator(self, tmp_path):
        """Create validator with mocks."""
        with patch("src.ml.invariant_validator.FoundryRunner") as mock_runner_cls:
            mock_runner = MagicMock()
            mock_runner_cls.return_value = mock_runner
            val = InvariantValidator(project_dir=tmp_path)
            val.runner = mock_runner
            return val

    def test_individual_no_test_files_generated(self, validator):
        """Test individual validation when no test files generated."""
        inv = SynthesizedInvariant(
            name="test",
            category=InvariantCategory.SOLVENCY,
            description="Test",
            importance="MEDIUM",
            natural_language="Solvency check",
            solidity_assertion="true",
        )

        with patch.object(validator.test_generator, "generate_individual_tests") as mock_gen:
            mock_gen.return_value = []  # No files generated

            report = validator._validate_individual(
                invariants=[inv],
                contract_name="Test",
                contract_path="src/Test.sol",
                contract_hash="abc",
                setup_code="",
            )

            assert report.skipped == 1

    def test_individual_empty_tests_result(self, validator):
        """Test individual validation with empty tests in result."""
        inv = SynthesizedInvariant(
            name="test",
            category=InvariantCategory.REENTRANCY,
            description="Test",
            importance="CRITICAL",
            natural_language="Reentrancy guard check",
            solidity_assertion="true",
        )

        validator.runner.run_test.return_value = _make_foundry_result(
            success=True,
            tests=[],  # Empty tests
            total_tests=0,
            passed=0,
            failed=0,
            skipped=0,
            total_gas=0,
            execution_time_ms=100.0,
            raw_output="",
        )

        with patch.object(validator.test_generator, "generate_individual_tests") as mock_gen:
            mock_gen.return_value = [Path("/tmp/test.sol")]

            report = validator._validate_individual(
                invariants=[inv],
                contract_name="Test",
                contract_path="src/Test.sol",
                contract_hash="abc",
                setup_code="",
            )

            # Should still produce result based on success flag
            assert len(report.results) == 1

    def test_individual_exception_during_validation(self, validator):
        """Test individual validation handles exceptions."""
        inv = SynthesizedInvariant(
            name="test",
            category=InvariantCategory.OVERFLOW,
            description="Test",
            importance="HIGH",
            natural_language="Overflow protection check",
            solidity_assertion="true",
        )

        with patch.object(validator.test_generator, "generate_individual_tests") as mock_gen:
            mock_gen.side_effect = Exception("Test generation failed")

            report = validator._validate_individual(
                invariants=[inv],
                contract_name="Test",
                contract_path="src/Test.sol",
                contract_hash="abc",
                setup_code="",
            )

            assert len(report.results) == 1
            assert report.results[0].test_status == TestStatus.ERROR


class TestInvariantCategories:
    """Test all InvariantCategory enum values."""

    @pytest.fixture
    def generator(self, tmp_path):
        """Create generator."""
        return InvariantTestGenerator(output_dir=tmp_path)

    @pytest.mark.parametrize(
        "category,expected_value",
        [
            (InvariantCategory.ACCOUNTING, "accounting"),
            (InvariantCategory.SOLVENCY, "solvency"),
            (InvariantCategory.ACCESS_CONTROL, "access_control"),
            (InvariantCategory.STATE_TRANSITION, "state_transition"),
            (InvariantCategory.REENTRANCY, "reentrancy"),
            (InvariantCategory.OVERFLOW, "overflow"),
            (InvariantCategory.TEMPORAL, "temporal"),
            (InvariantCategory.CUSTOM, "custom"),
        ],
    )
    def test_category_values(self, generator, category, expected_value):
        """Test all category values work correctly."""
        inv = SynthesizedInvariant(
            name=f"test_{expected_value}",
            category=category,
            description=f"Test for {expected_value}",
            importance="HIGH",
            natural_language=f"Testing {expected_value} category",
            solidity_assertion="target.check()",
        )

        test_file = generator.generate_test_file(
            invariants=[inv],
            contract_name="TestContract",
            contract_path="src/Test.sol",
        )

        content = test_file.read_text()
        assert expected_value in content


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_validate_invariants_cleanup(self, tmp_path):
        """Test validate_invariants cleans up after completion."""
        from src.ml.invariant_validator import validate_invariants

        inv = SynthesizedInvariant(
            name="test",
            category=InvariantCategory.ACCOUNTING,
            description="Test",
            importance="HIGH",
            natural_language="Test assertion",
            solidity_assertion="true",
        )

        with patch("src.ml.invariant_validator.InvariantValidator") as mock_cls:
            mock_validator = MagicMock()
            mock_validator.validate.return_value = ValidationReport(
                contract_name="Test",
                contract_hash="abc",
                total_invariants=1,
                passed=1,
                failed=0,
                skipped=0,
                results=[],
                total_execution_time_ms=0,
                total_gas_used=0,
            )
            mock_cls.return_value = mock_validator

            result = validate_invariants(
                invariants=[inv],
                contract_name="Test",
                contract_path="src/Test.sol",
                project_dir=str(tmp_path),
            )

            assert result.contract_name == "Test"
            mock_validator.cleanup.assert_called_once()

    def test_quick_validate(self, tmp_path):
        """Test quick_validate function."""
        from src.ml.invariant_validator import quick_validate

        inv = SynthesizedInvariant(
            name="test",
            category=InvariantCategory.ACCOUNTING,
            description="Test",
            importance="HIGH",
            natural_language="Test check",
            solidity_assertion="true",
        )

        contract_code = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;
        contract TestContract {
            function check() public pure returns (bool) { return true; }
        }
        """

        with patch("src.ml.invariant_validator.InvariantValidator") as mock_cls:
            mock_validator = MagicMock()
            mock_validator.validate.return_value = ValidationReport(
                contract_name="TestContract",
                contract_hash="abc",
                total_invariants=1,
                passed=1,
                failed=0,
                skipped=0,
                results=[],
                total_execution_time_ms=0,
                total_gas_used=0,
            )
            mock_cls.return_value = mock_validator

            result = quick_validate(
                invariant=inv,
                contract_code=contract_code,
            )

            assert result is True

    def test_quick_validate_failure(self, tmp_path):
        """Test quick_validate returns False on failure."""
        from src.ml.invariant_validator import quick_validate

        inv = SynthesizedInvariant(
            name="failing",
            category=InvariantCategory.ACCOUNTING,
            description="Failing test",
            importance="HIGH",
            natural_language="This will fail",
            solidity_assertion="false",
        )

        with patch("src.ml.invariant_validator.InvariantValidator") as mock_cls:
            mock_validator = MagicMock()
            mock_validator.validate.return_value = ValidationReport(
                contract_name="TestContract",
                contract_hash="abc",
                total_invariants=1,
                passed=0,
                failed=1,
                skipped=0,
                results=[],
                total_execution_time_ms=0,
                total_gas_used=0,
            )
            mock_cls.return_value = mock_validator

            result = quick_validate(
                invariant=inv,
                contract_code="contract Test {}",
            )

            assert result is False

    def test_quick_validate_exception(self):
        """Test quick_validate handles exceptions during validation."""
        from src.ml.invariant_validator import quick_validate

        inv = SynthesizedInvariant(
            name="error",
            category=InvariantCategory.CUSTOM,
            description="Error test",
            importance="LOW",
            natural_language="Will cause error",
            solidity_assertion="error",
        )

        with patch("src.ml.invariant_validator.InvariantValidator") as mock_cls:
            mock_validator = MagicMock()
            # Exception during validate(), not during __init__()
            mock_validator.validate.side_effect = Exception("Validation failed")
            mock_cls.return_value = mock_validator

            result = quick_validate(
                invariant=inv,
                contract_code="invalid",
            )

            assert result is False
            mock_validator.cleanup.assert_called_once()
