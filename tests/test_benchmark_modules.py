"""
Tests for slither_benchmark and pattern_benchmark modules.

Covers:
- SlitherBenchmarkRunner: dataclass results, _parse_slither_finding, _match_findings,
  _cats_related, _calculate_results, edge cases
- PatternBenchmarkRunner: PatternMatch/PatternBenchmarkResult dataclasses,
  _detect_patterns per category, _check_state_after_call, run() with synthetic data,
  summary() output, edge cases (empty results, unknown category)
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.benchmark.benchmark_runner import DetectionMetrics, ContractResult, BenchmarkResult
from src.benchmark.dataset_loader import GroundTruth, VulnerabilityCategory, VulnerableContract
from src.benchmark.slither_benchmark import SlitherBenchmarkRunner
from src.benchmark.pattern_benchmark import (
    PatternBenchmarkResult,
    PatternBenchmarkRunner,
    PatternMatch,
    run_pattern_benchmark,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def make_gt(category_str: str, lines=None) -> GroundTruth:
    return GroundTruth(
        category=VulnerabilityCategory.from_string(category_str),
        lines=lines or [10],
        severity="High",
    )


def make_contract(name="TestContract", source_code="", vuln_category="reentrancy", lines=None):
    return VulnerableContract(
        name=name,
        path=f"/tmp/{name}.sol",
        source_code=source_code,
        pragma_version="^0.8.0",
        vulnerabilities=[make_gt(vuln_category, lines or [10])],
    )


# ===========================================================================
# SlitherBenchmarkRunner tests
# ===========================================================================

class TestSlitherBenchmarkRunner:

    def test_default_init(self):
        runner = SlitherBenchmarkRunner()
        assert runner.timeout == 60
        assert runner.line_tolerance == 10

    def test_custom_init(self):
        runner = SlitherBenchmarkRunner(timeout=120, line_tolerance=5)
        assert runner.timeout == 120
        assert runner.line_tolerance == 5

    # ------------------------------------------------------------------
    # _parse_slither_finding
    # ------------------------------------------------------------------

    def test_parse_slither_finding_known_detector(self):
        runner = SlitherBenchmarkRunner()
        detector = {
            "check": "reentrancy-eth",
            "impact": "High",
            "confidence": "High",
            "description": "Reentrancy in withdraw()",
            "elements": [
                {
                    "source_mapping": {
                        "lines": [42, 43],
                        "filename_relative": "vulnerable.sol",
                    }
                }
            ],
        }
        finding = runner._parse_slither_finding(detector, "/tmp/vulnerable.sol")
        assert finding is not None
        assert finding["type"] == "reentrancy-eth"
        assert finding["severity"] == "High"
        assert 42 in finding["lines"]
        assert finding["location"]["line"] == 42

    def test_parse_slither_finding_irrelevant_contract_returns_none(self):
        runner = SlitherBenchmarkRunner()
        detector = {
            "check": "reentrancy-eth",
            "impact": "High",
            "confidence": "High",
            "description": "Reentrancy",
            "elements": [
                {
                    "source_mapping": {
                        "lines": [10],
                        "filename_relative": "other_contract.sol",  # different file
                    }
                }
            ],
        }
        result = runner._parse_slither_finding(detector, "/tmp/mycontract.sol")
        assert result is None

    def test_parse_slither_finding_no_elements(self):
        runner = SlitherBenchmarkRunner()
        detector = {
            "check": "tx-origin",
            "impact": "Medium",
            "confidence": "High",
            "description": "tx.origin used",
            "elements": [],
        }
        # No elements means no source mapping — irrelevant by default
        result = runner._parse_slither_finding(detector, "/tmp/test.sol")
        assert result is None

    def test_parse_slither_finding_no_lines_in_source_mapping(self):
        runner = SlitherBenchmarkRunner()
        detector = {
            "check": "reentrancy-eth",
            "impact": "High",
            "confidence": "High",
            "description": "Reentrancy",
            "elements": [
                {
                    "source_mapping": {
                        "lines": [],
                        "filename_relative": "test.sol",
                    }
                }
            ],
        }
        finding = runner._parse_slither_finding(detector, "/tmp/test.sol")
        assert finding is not None
        assert finding["lines"] == []
        assert finding["location"]["line"] == 0

    # ------------------------------------------------------------------
    # _match_findings
    # ------------------------------------------------------------------

    def test_match_findings_true_positive(self):
        runner = SlitherBenchmarkRunner(line_tolerance=5)
        gt = [make_gt("reentrancy", lines=[42])]
        findings = [{"type": "reentrancy-eth", "lines": [42], "location": {"line": 42}}]
        tp, fp, fn = runner._match_findings(gt, findings)
        assert len(tp) == 1
        assert len(fp) == 0
        assert len(fn) == 0

    def test_match_findings_false_positive(self):
        runner = SlitherBenchmarkRunner(line_tolerance=2)
        gt = [make_gt("reentrancy", lines=[100])]
        findings = [{"type": "reentrancy-eth", "lines": [50], "location": {"line": 50}}]
        tp, fp, fn = runner._match_findings(gt, findings)
        assert len(tp) == 0
        assert len(fp) == 1
        assert len(fn) == 1

    def test_match_findings_false_negative(self):
        runner = SlitherBenchmarkRunner()
        gt = [make_gt("reentrancy", lines=[10])]
        tp, fp, fn = runner._match_findings(gt, [])
        assert len(tp) == 0
        assert len(fp) == 0
        assert len(fn) == 1
        assert fn[0] is gt[0]

    def test_match_findings_empty_both(self):
        runner = SlitherBenchmarkRunner()
        tp, fp, fn = runner._match_findings([], [])
        assert tp == []
        assert fp == []
        assert fn == []

    def test_match_findings_unknown_detector_type(self):
        runner = SlitherBenchmarkRunner()
        gt = [make_gt("reentrancy", lines=[10])]
        findings = [{"type": "some-unknown-check", "lines": [10], "location": {"line": 10}}]
        tp, fp, fn = runner._match_findings(gt, findings)
        # "other" != "reentrancy" and not related, so it's a FP
        assert len(fp) == 1

    # ------------------------------------------------------------------
    # _cats_related
    # ------------------------------------------------------------------

    def test_cats_related_reentrancy_and_unchecked(self):
        runner = SlitherBenchmarkRunner()
        assert runner._cats_related("reentrancy", "unchecked_low_level_calls") is True

    def test_cats_related_bad_randomness_and_time(self):
        runner = SlitherBenchmarkRunner()
        assert runner._cats_related("bad_randomness", "time_manipulation") is True

    def test_cats_related_different_groups(self):
        runner = SlitherBenchmarkRunner()
        assert runner._cats_related("reentrancy", "access_control") is False

    def test_cats_related_same_category(self):
        runner = SlitherBenchmarkRunner()
        assert runner._cats_related("access_control", "access_control") is True

    # ------------------------------------------------------------------
    # _calculate_results
    # ------------------------------------------------------------------

    def test_calculate_results_basic(self):
        runner = SlitherBenchmarkRunner()
        contracts = [make_contract()]
        results = [
            ContractResult(
                contract_name="TestContract",
                contract_path="/tmp/TestContract.sol",
                ground_truth=contracts[0].vulnerabilities,
                detected_findings=[{"type": "reentrancy-eth"}],
                true_positives=[{"type": "reentrancy-eth"}],
                false_positives=[],
                false_negatives=[],
            )
        ]
        bench = runner._calculate_results(contracts, results, 1.5)
        assert bench.total_contracts == 1
        assert bench.analyzed_contracts == 1
        assert bench.failed_contracts == 0
        assert bench.overall_metrics.true_positives == 1
        assert bench.miesc_version == "slither-only"

    def test_calculate_results_with_error(self):
        runner = SlitherBenchmarkRunner()
        contracts = [make_contract()]
        results = [
            ContractResult(
                contract_name="TestContract",
                contract_path="/tmp/TestContract.sol",
                ground_truth=contracts[0].vulnerabilities,
                detected_findings=[],
                error="timeout",
            )
        ]
        bench = runner._calculate_results(contracts, results, 0.5)
        assert bench.analyzed_contracts == 0
        assert bench.failed_contracts == 1

    def test_calculate_results_empty_contracts(self):
        runner = SlitherBenchmarkRunner()
        bench = runner._calculate_results([], [], 0.0)
        assert bench.total_contracts == 0
        assert bench.total_detected == 0


# ===========================================================================
# PatternMatch dataclass
# ===========================================================================

class TestPatternMatch:

    def test_create_pattern_match(self):
        pm = PatternMatch(
            pattern_name="reentrancy-call",
            category="reentrancy",
            line=42,
            confidence=0.8,
            code_snippet="msg.sender.call{value: amount}(\"\");",
        )
        assert pm.pattern_name == "reentrancy-call"
        assert pm.category == "reentrancy"
        assert pm.line == 42
        assert pm.confidence == 0.8


# ===========================================================================
# PatternBenchmarkResult dataclass
# ===========================================================================

class TestPatternBenchmarkResult:

    def _make_result(self, tp=5, fn=2, rates=None):
        return PatternBenchmarkResult(
            total_contracts=3,
            total_ground_truth=tp + fn,
            patterns_tested=["reentrancy", "access_control"],
            true_positives=tp,
            false_negatives=fn,
            detection_rate_by_category=rates or {"reentrancy": 0.8, "access_control": 0.6},
            processing_time_ms=12.5,
            timestamp=datetime.now(),
        )

    def test_summary_contains_key_metrics(self):
        result = self._make_result()
        summary = result.summary()
        assert "PATTERN DETECTION BENCHMARK" in summary
        assert "True positives: 5" in summary
        assert "False negatives: 2" in summary

    def test_summary_shows_recall_percentage(self):
        result = self._make_result(tp=7, fn=3)
        summary = result.summary()
        # Overall recall = 7/10 = 70.0%
        assert "70.0%" in summary

    def test_summary_zero_ground_truth_no_crash(self):
        result = PatternBenchmarkResult(
            total_contracts=0,
            total_ground_truth=0,
            patterns_tested=[],
            true_positives=0,
            false_negatives=0,
            detection_rate_by_category={},
            processing_time_ms=0.0,
            timestamp=datetime.now(),
        )
        summary = result.summary()
        assert "0.0%" in summary

    def test_summary_includes_detection_rates(self):
        result = self._make_result(rates={"reentrancy": 1.0, "access_control": 0.5})
        summary = result.summary()
        assert "reentrancy" in summary
        assert "100.0%" in summary


# ===========================================================================
# PatternBenchmarkRunner — _detect_patterns
# ===========================================================================

class TestPatternBenchmarkRunnerDetect:

    def setup_method(self):
        self.runner = PatternBenchmarkRunner(line_tolerance=5)

    def test_detect_reentrancy_classic_call(self):
        # Must include a state update AFTER the call to satisfy context_check
        code = (
            "function withdraw() external {\n"
            '    msg.sender.call{value: amount}("");\n'
            "    balances[msg.sender] = 0;\n"
            "}"
        )
        matches = self.runner._detect_patterns(code, "reentrancy")
        assert len(matches) >= 1

    def test_detect_reentrancy_suppressed_by_guard(self):
        code = 'modifier nonReentrant() {}\nfunction withdraw() nonReentrant external {\n    msg.sender.call{value: amount}("");\n}'
        matches = self.runner._detect_patterns(code, "reentrancy")
        # nonReentrant is an anti-pattern — should suppress detection
        assert len(matches) == 0

    def test_detect_access_control_tx_origin(self):
        code = "require(tx.origin == owner);"
        matches = self.runner._detect_patterns(code, "access_control")
        assert len(matches) >= 1

    def test_detect_timestamp(self):
        code = "if (block.timestamp > deadline) { revert(); }"
        matches = self.runner._detect_patterns(code, "timestamp")
        assert len(matches) >= 1

    def test_detect_bad_randomness_blockhash(self):
        code = "uint rand = uint(blockhash(block.number - 1));"
        matches = self.runner._detect_patterns(code, "bad_randomness")
        assert len(matches) >= 1

    def test_detect_dos_loop(self):
        code = "for (uint i = 0; i < users.length; i++) { pay(users[i]); }"
        matches = self.runner._detect_patterns(code, "denial_of_service")
        assert len(matches) >= 1

    def test_detect_unchecked_low_level_call(self):
        code = "addr.call(data);"
        matches = self.runner._detect_patterns(code, "unchecked_low_level_calls")
        assert len(matches) >= 1

    def test_detect_arithmetic_addition(self):
        code = "pragma solidity ^0.6.0;\nuint result = a + b;"
        matches = self.runner._detect_patterns(code, "arithmetic")
        # Solidity 0.6 has no built-in overflow protection
        assert len(matches) >= 1

    def test_detect_arithmetic_suppressed_by_safemath(self):
        code = "using SafeMath for uint;\nuint result = a.add(b);"
        matches = self.runner._detect_patterns(code, "arithmetic")
        assert len(matches) == 0

    def test_unknown_category_returns_empty(self):
        code = "some code"
        matches = self.runner._detect_patterns(code, "totally_unknown_category")
        assert matches == []

    def test_empty_code_returns_empty(self):
        matches = self.runner._detect_patterns("", "reentrancy")
        assert matches == []

    # ------------------------------------------------------------------
    # _check_state_after_call (static)
    # ------------------------------------------------------------------

    def test_check_state_after_call_detects_update(self):
        code = "contract C {\n    function f() {\n        msg.sender.call('');\n        balances[msg.sender] = 0;\n    }\n}"
        # call is at line 3 (1-indexed), state update at line 4
        result = PatternBenchmarkRunner._check_state_after_call(code, 3)
        assert result is True

    def test_check_state_after_call_no_update(self):
        code = "contract C {\n    function f() {\n        msg.sender.call('');\n    }\n}"
        result = PatternBenchmarkRunner._check_state_after_call(code, 3)
        assert result is False

    def test_check_state_after_call_out_of_bounds(self):
        code = "line1\nline2"
        result = PatternBenchmarkRunner._check_state_after_call(code, 100)
        assert result is False


# ===========================================================================
# PatternBenchmarkRunner — run() integration
# ===========================================================================

class TestPatternBenchmarkRunnerRun:

    def test_run_with_matching_contract(self):
        runner = PatternBenchmarkRunner(line_tolerance=10)
        code = "function withdraw() {\n    msg.sender.call{value: amount}(\"\");\n    balances[msg.sender] = 0;\n}"
        contract = VulnerableContract(
            name="Reentrancy",
            path="/tmp/R.sol",
            source_code=code,
            pragma_version="^0.6.0",
            vulnerabilities=[make_gt("reentrancy", lines=[2])],
        )
        result = runner.run([contract], verbose=False)
        assert result.total_contracts == 1
        assert result.total_ground_truth == 1
        # Pattern should fire at line 2 → true positive
        assert result.true_positives == 1
        assert result.false_negatives == 0
        assert "reentrancy" in result.detection_rate_by_category

    def test_run_empty_contracts(self):
        runner = PatternBenchmarkRunner()
        result = runner.run([], verbose=False)
        assert result.total_contracts == 0
        assert result.true_positives == 0
        assert result.false_negatives == 0
        assert result.detection_rate_by_category == {}

    def test_run_miss_increments_false_negatives(self):
        runner = PatternBenchmarkRunner(line_tolerance=2)
        # Ground truth at line 100, but no matching pattern anywhere
        code = "// no vulnerable code here"
        contract = VulnerableContract(
            name="Clean",
            path="/tmp/Clean.sol",
            source_code=code,
            pragma_version="^0.8.0",
            vulnerabilities=[make_gt("reentrancy", lines=[100])],
        )
        result = runner.run([contract], verbose=False)
        assert result.false_negatives == 1
        assert result.true_positives == 0

    def test_run_returns_detection_rates_between_0_and_1(self):
        runner = PatternBenchmarkRunner()
        code = "block.timestamp > 0;"
        contract = VulnerableContract(
            name="Timestamp",
            path="/tmp/T.sol",
            source_code=code,
            pragma_version="^0.8.0",
            vulnerabilities=[make_gt("time_manipulation", lines=[1])],
        )
        result = runner.run([contract], verbose=False)
        for rate in result.detection_rate_by_category.values():
            assert 0.0 <= rate <= 1.0

    def test_run_processing_time_is_positive(self):
        runner = PatternBenchmarkRunner()
        result = runner.run([], verbose=False)
        assert result.processing_time_ms >= 0.0

    def test_run_via_convenience_function(self):
        result = run_pattern_benchmark([], verbose=False)
        assert result.total_contracts == 0

    def test_patterns_tested_list_populated(self):
        runner = PatternBenchmarkRunner()
        result = runner.run([], verbose=False)
        assert len(result.patterns_tested) > 0
        assert "reentrancy" in result.patterns_tested
