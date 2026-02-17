"""
Tests for Benchmark Runner module.

Tests the benchmark framework for evaluating MIESC detection accuracy.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from unittest.mock import MagicMock, patch

import pytest

from src.benchmark.benchmark_runner import (
    BenchmarkResult,
    BenchmarkRunner,
    ContractResult,
    DetectionMetrics,
    run_benchmark,
)
from src.benchmark.dataset_loader import (
    GroundTruth,
    VulnerabilityCategory,
    VulnerableContract,
)


class TestDetectionMetrics:
    """Test DetectionMetrics dataclass."""

    def test_create_metrics(self):
        """Test creating metrics."""
        metrics = DetectionMetrics(
            category="reentrancy",
            true_positives=10,
            false_positives=2,
            false_negatives=3,
        )
        assert metrics.category == "reentrancy"
        assert metrics.true_positives == 10
        assert metrics.false_positives == 2
        assert metrics.false_negatives == 3

    def test_default_values(self):
        """Test default values."""
        metrics = DetectionMetrics(category="test")
        assert metrics.true_positives == 0
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0
        assert metrics.true_negatives == 0

    def test_precision_calculation(self):
        """Test precision calculation."""
        metrics = DetectionMetrics(
            category="test",
            true_positives=80,
            false_positives=20,
        )
        assert metrics.precision == 0.8

    def test_precision_zero_division(self):
        """Test precision with no detections."""
        metrics = DetectionMetrics(category="test")
        assert metrics.precision == 0.0

    def test_recall_calculation(self):
        """Test recall calculation."""
        metrics = DetectionMetrics(
            category="test",
            true_positives=70,
            false_negatives=30,
        )
        assert metrics.recall == 0.7

    def test_recall_zero_division(self):
        """Test recall with no ground truth."""
        metrics = DetectionMetrics(category="test")
        assert metrics.recall == 0.0

    def test_f1_score_calculation(self):
        """Test F1 score calculation."""
        metrics = DetectionMetrics(
            category="test",
            true_positives=80,
            false_positives=20,
            false_negatives=20,
        )
        # precision = 80/100 = 0.8, recall = 80/100 = 0.8
        # F1 = 2 * 0.8 * 0.8 / (0.8 + 0.8) = 0.8
        assert abs(metrics.f1_score - 0.8) < 0.0001

    def test_f1_score_zero_division(self):
        """Test F1 with zero precision and recall."""
        metrics = DetectionMetrics(category="test")
        assert metrics.f1_score == 0.0

    def test_accuracy_calculation(self):
        """Test accuracy calculation."""
        metrics = DetectionMetrics(
            category="test",
            true_positives=85,
            true_negatives=10,
            false_positives=3,
            false_negatives=2,
        )
        # accuracy = (85 + 10) / (85 + 10 + 3 + 2) = 95/100 = 0.95
        assert metrics.accuracy == 0.95

    def test_accuracy_zero_division(self):
        """Test accuracy with no samples."""
        metrics = DetectionMetrics(category="test")
        assert metrics.accuracy == 0.0

    def test_to_dict(self):
        """Test dictionary conversion."""
        metrics = DetectionMetrics(
            category="reentrancy",
            true_positives=10,
            false_positives=2,
            false_negatives=3,
        )
        d = metrics.to_dict()
        assert d["category"] == "reentrancy"
        assert d["true_positives"] == 10
        assert d["false_positives"] == 2
        assert d["false_negatives"] == 3
        assert "precision" in d
        assert "recall" in d
        assert "f1_score" in d


class TestContractResult:
    """Test ContractResult dataclass."""

    @pytest.fixture
    def ground_truth(self):
        """Create sample ground truth."""
        return [
            GroundTruth(
                category=VulnerabilityCategory.REENTRANCY,
                lines=[10, 15],
                description="Reentrancy vulnerability",
            )
        ]

    def test_create_result(self, ground_truth):
        """Test creating contract result."""
        result = ContractResult(
            contract_name="Token.sol",
            contract_path="/path/to/Token.sol",
            ground_truth=ground_truth,
            detected_findings=[{"type": "reentrancy", "line": 10}],
        )
        assert result.contract_name == "Token.sol"
        assert len(result.ground_truth) == 1

    def test_default_values(self, ground_truth):
        """Test default values."""
        result = ContractResult(
            contract_name="Test.sol",
            contract_path="/path",
            ground_truth=ground_truth,
            detected_findings=[],
        )
        assert result.true_positives == []
        assert result.false_positives == []
        assert result.false_negatives == []
        assert result.analysis_time_ms == 0.0
        assert result.error is None

    def test_with_error(self, ground_truth):
        """Test result with error."""
        result = ContractResult(
            contract_name="Test.sol",
            contract_path="/path",
            ground_truth=ground_truth,
            detected_findings=[],
            error="timeout",
        )
        assert result.error == "timeout"

    def test_to_dict(self, ground_truth):
        """Test dictionary conversion."""
        result = ContractResult(
            contract_name="Token.sol",
            contract_path="/path/to/Token.sol",
            ground_truth=ground_truth,
            detected_findings=[{"type": "reentrancy"}],
            true_positives=[{"type": "reentrancy"}],
            analysis_time_ms=1500.5,
        )
        d = result.to_dict()
        assert d["contract_name"] == "Token.sol"
        assert d["ground_truth_count"] == 1
        assert d["detected_count"] == 1
        assert d["true_positives"] == 1
        assert d["false_positives"] == 0
        assert d["analysis_time_ms"] == 1500.5


class TestBenchmarkResult:
    """Test BenchmarkResult dataclass."""

    @pytest.fixture
    def sample_result(self):
        """Create sample benchmark result."""
        return BenchmarkResult(
            timestamp=datetime(2026, 2, 17, 10, 0, 0),
            total_contracts=100,
            analyzed_contracts=95,
            failed_contracts=5,
            total_ground_truth=150,
            total_detected=140,
            contract_results=[],
            metrics_by_category={
                "reentrancy": DetectionMetrics(
                    category="reentrancy",
                    true_positives=30,
                    false_positives=5,
                    false_negatives=10,
                )
            },
            overall_metrics=DetectionMetrics(
                category="overall",
                true_positives=100,
                false_positives=40,
                false_negatives=50,
            ),
            total_time_seconds=120.5,
        )

    def test_create_result(self, sample_result):
        """Test creating benchmark result."""
        assert sample_result.total_contracts == 100
        assert sample_result.analyzed_contracts == 95
        assert sample_result.miesc_version == "4.3.0"

    def test_success_rate(self, sample_result):
        """Test success rate calculation."""
        assert sample_result.success_rate == 0.95

    def test_success_rate_zero_contracts(self):
        """Test success rate with zero contracts."""
        result = BenchmarkResult(
            timestamp=datetime.now(),
            total_contracts=0,
            analyzed_contracts=0,
            failed_contracts=0,
            total_ground_truth=0,
            total_detected=0,
            contract_results=[],
            metrics_by_category={},
            overall_metrics=DetectionMetrics(category="overall"),
            total_time_seconds=0,
        )
        assert result.success_rate == 0.0

    def test_summary_generation(self, sample_result):
        """Test summary generation."""
        summary = sample_result.summary()
        assert "MIESC BENCHMARK RESULTS" in summary
        assert "Total Contracts: 100" in summary
        assert "Precision:" in summary
        assert "Recall:" in summary
        assert "F1 Score:" in summary
        assert "reentrancy" in summary

    def test_to_dict(self, sample_result):
        """Test dictionary conversion."""
        d = sample_result.to_dict()
        assert "timestamp" in d
        assert "miesc_version" in d
        assert d["summary"]["total_contracts"] == 100
        assert d["summary"]["success_rate"] == 0.95
        assert "overall_metrics" in d
        assert "metrics_by_category" in d

    def test_save_to_file(self, sample_result, tmp_path):
        """Test saving results to file."""
        output_path = tmp_path / "results.json"
        sample_result.save(output_path)

        assert output_path.exists()
        with open(output_path) as f:
            data = json.load(f)
        assert data["summary"]["total_contracts"] == 100


class TestBenchmarkRunner:
    """Test BenchmarkRunner class."""

    @pytest.fixture
    def runner(self):
        """Create runner instance."""
        return BenchmarkRunner(timeout=30, line_tolerance=5)

    @pytest.fixture
    def sample_contract(self):
        """Create sample vulnerable contract."""
        return VulnerableContract(
            name="Token.sol",
            path="/path/to/Token.sol",
            source_code="contract Token {}",
            pragma_version="^0.8.0",
            vulnerabilities=[
                GroundTruth(
                    category=VulnerabilityCategory.REENTRANCY,
                    lines=[50, 55],
                    description="Reentrancy",
                )
            ],
        )

    def test_init_default(self):
        """Test default initialization."""
        runner = BenchmarkRunner()
        assert runner.miesc_path == "miesc"
        assert runner.timeout == 120
        assert runner.line_tolerance == 10

    def test_init_custom(self):
        """Test custom initialization."""
        runner = BenchmarkRunner(
            miesc_path="/custom/miesc",
            timeout=60,
            line_tolerance=15,
        )
        assert runner.miesc_path == "/custom/miesc"
        assert runner.timeout == 60
        assert runner.line_tolerance == 15

    def test_type_mapping(self, runner):
        """Test type mapping dictionary."""
        assert runner.TYPE_MAPPING["reentrancy"] == "reentrancy"
        assert runner.TYPE_MAPPING["reentrancy-eth"] == "reentrancy"
        assert runner.TYPE_MAPPING["integer-overflow"] == "arithmetic"
        assert runner.TYPE_MAPPING["unchecked-lowlevel"] == "unchecked_low_level_calls"

    def test_extract_lines_single_line(self, runner):
        """Test extracting single line number."""
        finding = {"line": 50}
        lines = runner._extract_lines(finding)
        assert lines == [50]

    def test_extract_lines_multiple_lines(self, runner):
        """Test extracting multiple lines."""
        finding = {"lines": [10, 20, 30]}
        lines = runner._extract_lines(finding)
        assert lines == [10, 20, 30]

    def test_extract_lines_location_dict(self, runner):
        """Test extracting lines from location dict."""
        finding = {"location": {"line": 42}}
        lines = runner._extract_lines(finding)
        assert 42 in lines

    def test_extract_lines_location_start_line(self, runner):
        """Test extracting start_line from location."""
        finding = {"location": {"start_line": 100}}
        lines = runner._extract_lines(finding)
        assert 100 in lines

    def test_extract_lines_location_string(self, runner):
        """Test extracting line from string location."""
        finding = {"location": "Token.sol:75"}
        lines = runner._extract_lines(finding)
        assert 75 in lines

    def test_extract_lines_default(self, runner):
        """Test default line when none found."""
        finding = {"description": "vulnerability"}
        lines = runner._extract_lines(finding)
        assert lines == [0]

    def test_categories_related(self, runner):
        """Test related categories check."""
        assert runner._categories_related("reentrancy", "unchecked_low_level_calls")
        assert runner._categories_related("bad_randomness", "time_manipulation")
        assert runner._categories_related("oracle_manipulation", "flash_loan")

    def test_categories_not_related(self, runner):
        """Test unrelated categories."""
        assert not runner._categories_related("reentrancy", "arithmetic")
        assert not runner._categories_related("access_control", "denial_of_service")

    def test_match_findings_true_positive(self, runner):
        """Test matching findings - true positive."""
        ground_truth = [
            GroundTruth(
                category=VulnerabilityCategory.REENTRANCY,
                lines=[50],
            )
        ]
        findings = [{"type": "reentrancy", "line": 52}]

        tp, fp, fn = runner._match_findings(ground_truth, findings)
        assert len(tp) == 1
        assert len(fp) == 0
        assert len(fn) == 0

    def test_match_findings_false_positive(self, runner):
        """Test matching findings - false positive."""
        ground_truth = [
            GroundTruth(
                category=VulnerabilityCategory.REENTRANCY,
                lines=[50],
            )
        ]
        findings = [{"type": "arithmetic", "line": 100}]

        tp, fp, fn = runner._match_findings(ground_truth, findings)
        assert len(tp) == 0
        assert len(fp) == 1
        assert len(fn) == 1

    def test_match_findings_false_negative(self, runner):
        """Test matching findings - false negative."""
        ground_truth = [
            GroundTruth(
                category=VulnerabilityCategory.REENTRANCY,
                lines=[50],
            )
        ]
        findings = []

        tp, fp, fn = runner._match_findings(ground_truth, findings)
        assert len(tp) == 0
        assert len(fp) == 0
        assert len(fn) == 1

    def test_match_findings_with_tolerance(self, runner):
        """Test matching with line tolerance."""
        ground_truth = [
            GroundTruth(
                category=VulnerabilityCategory.REENTRANCY,
                lines=[50],
            )
        ]
        # Line 55 is within tolerance of 5
        findings = [{"type": "reentrancy", "line": 55}]

        tp, fp, fn = runner._match_findings(ground_truth, findings)
        assert len(tp) == 1

    def test_match_findings_outside_tolerance(self, runner):
        """Test matching outside line tolerance."""
        ground_truth = [
            GroundTruth(
                category=VulnerabilityCategory.REENTRANCY,
                lines=[50],
            )
        ]
        # Line 60 is outside tolerance of 5
        findings = [{"type": "reentrancy", "line": 60}]

        tp, fp, fn = runner._match_findings(ground_truth, findings)
        assert len(tp) == 0
        assert len(fp) == 1

    @patch("subprocess.run")
    def test_analyze_contract_success(self, mock_run, runner, sample_contract, tmp_path):
        """Test successful contract analysis."""
        # Create mock output file
        output_data = {"findings": [{"type": "reentrancy", "line": 50}]}

        mock_run.return_value = MagicMock(returncode=0)

        with patch("tempfile.NamedTemporaryFile") as mock_temp:
            temp_file = tmp_path / "output.json"
            temp_file.write_text(json.dumps(output_data))
            mock_temp.return_value.__enter__.return_value.name = str(temp_file)

            result = runner._analyze_contract(sample_contract, "smart")

        assert result.contract_name == "Token.sol"
        assert result.error is None

    @patch("subprocess.run")
    def test_analyze_contract_timeout(self, mock_run, runner, sample_contract):
        """Test contract analysis timeout."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="miesc", timeout=30)

        result = runner._analyze_contract(sample_contract, "smart")

        assert result.error == "timeout"

    @patch("subprocess.run")
    def test_analyze_contract_exception(self, mock_run, runner, sample_contract):
        """Test contract analysis with exception."""
        mock_run.side_effect = Exception("Unexpected error")

        result = runner._analyze_contract(sample_contract, "smart")

        assert "Unexpected error" in result.error

    def test_calculate_results(self, runner, sample_contract):
        """Test results calculation."""
        contracts = [sample_contract]
        results = [
            ContractResult(
                contract_name=sample_contract.name,
                contract_path=sample_contract.path,
                ground_truth=sample_contract.vulnerabilities,
                detected_findings=[{"type": "reentrancy", "line": 50}],
                true_positives=[{"type": "reentrancy", "line": 50}],
                false_positives=[],
                false_negatives=[],
                analysis_time_ms=1000,
            )
        ]

        benchmark_result = runner._calculate_results(contracts, results, 1.0, "smart")

        assert benchmark_result.total_contracts == 1
        assert benchmark_result.analyzed_contracts == 1
        assert benchmark_result.overall_metrics.true_positives == 1

    @patch.object(BenchmarkRunner, "_analyze_contract")
    def test_run_sequential(self, mock_analyze, runner, sample_contract):
        """Test running benchmark sequentially."""
        mock_analyze.return_value = ContractResult(
            contract_name=sample_contract.name,
            contract_path=sample_contract.path,
            ground_truth=sample_contract.vulnerabilities,
            detected_findings=[],
        )

        result = runner.run([sample_contract], parallel=False)

        assert result.total_contracts == 1
        mock_analyze.assert_called_once()

    @patch.object(BenchmarkRunner, "_analyze_contract")
    def test_run_parallel(self, mock_analyze, runner, sample_contract):
        """Test running benchmark in parallel."""
        mock_analyze.return_value = ContractResult(
            contract_name=sample_contract.name,
            contract_path=sample_contract.path,
            ground_truth=sample_contract.vulnerabilities,
            detected_findings=[],
        )

        result = runner.run([sample_contract], parallel=True, max_workers=2)

        assert result.total_contracts == 1

    @patch.object(BenchmarkRunner, "_analyze_contract")
    def test_run_with_verbose(self, mock_analyze, runner, sample_contract, capsys):
        """Test running with verbose output."""
        mock_analyze.return_value = ContractResult(
            contract_name=sample_contract.name,
            contract_path=sample_contract.path,
            ground_truth=sample_contract.vulnerabilities,
            detected_findings=[],
        )

        runner.run([sample_contract], parallel=False, verbose=True)

        captured = capsys.readouterr()
        assert "Token.sol" in captured.out


class TestRunBenchmarkFunction:
    """Test run_benchmark convenience function."""

    @patch.object(BenchmarkRunner, "run")
    def test_run_benchmark(self, mock_run):
        """Test run_benchmark function."""
        mock_run.return_value = MagicMock(spec=BenchmarkResult)

        contract = VulnerableContract(
            name="Test.sol",
            path="/path/test.sol",
            source_code="",
            pragma_version="^0.8.0",
            vulnerabilities=[],
        )

        run_benchmark([contract], mode="quick", parallel=False)

        mock_run.assert_called_once()


class TestMetricsEdgeCases:
    """Test edge cases for metrics calculations."""

    def test_all_true_positives(self):
        """Test perfect detection."""
        metrics = DetectionMetrics(
            category="test",
            true_positives=100,
            false_positives=0,
            false_negatives=0,
        )
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.f1_score == 1.0

    def test_all_false_positives(self):
        """Test all false positives."""
        metrics = DetectionMetrics(
            category="test",
            true_positives=0,
            false_positives=100,
            false_negatives=0,
        )
        assert metrics.precision == 0.0
        assert metrics.recall == 0.0
        assert metrics.f1_score == 0.0

    def test_all_false_negatives(self):
        """Test all false negatives."""
        metrics = DetectionMetrics(
            category="test",
            true_positives=0,
            false_positives=0,
            false_negatives=100,
        )
        assert metrics.precision == 0.0
        assert metrics.recall == 0.0

    def test_unbalanced_metrics(self):
        """Test unbalanced precision/recall."""
        # High precision, low recall
        metrics = DetectionMetrics(
            category="test",
            true_positives=10,
            false_positives=0,
            false_negatives=90,
        )
        assert metrics.precision == 1.0
        assert metrics.recall == 0.1
        # F1 should be closer to the lower value
        assert metrics.f1_score < 0.3
