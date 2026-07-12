"""Tests for SlitherBenchmarkRunner pure helpers (parse/match/category relations).

No slither subprocess — only the result-parsing and ground-truth matching logic.
"""

from __future__ import annotations

from miesc.benchmark.dataset_loader import (
    GroundTruth,
    VulnerabilityCategory,
    VulnerableContract,
)
from miesc.benchmark.slither_benchmark import ContractResult, SlitherBenchmarkRunner


def _runner():
    return SlitherBenchmarkRunner()


class TestCategoryRelations:
    def test_related_groups(self):
        r = _runner()
        assert r._cats_related("reentrancy", "unchecked_low_level_calls") is True
        assert r._cats_related("bad_randomness", "time_manipulation") is True

    def test_unrelated(self):
        assert _runner()._cats_related("reentrancy", "arithmetic") is False


class TestParseSlitherFinding:
    def test_relevant_finding_parsed(self):
        det = {
            "check": "reentrancy-eth",
            "impact": "High",
            "elements": [{"source_mapping": {"lines": [5], "filename_relative": "MyC.sol"}}],
        }
        out = _runner()._parse_slither_finding(det, "MyC.sol")
        assert out is not None
        assert out["type"] == "reentrancy-eth"
        assert out["lines"] == [5]

    def test_irrelevant_finding_dropped(self):
        det = {
            "check": "x",
            "elements": [{"source_mapping": {"lines": [1], "filename_relative": "other.sol"}}],
        }
        assert _runner()._parse_slither_finding(det, "MyC.sol") is None


class TestMatchFindings:
    def test_true_positive(self):
        r = _runner()
        gt = [GroundTruth(category=VulnerabilityCategory.REENTRANCY, lines=[5])]
        findings = [{"type": "reentrancy-eth", "lines": [5], "location": {"line": 5}}]
        tp, fp, fn = r._match_findings(gt, findings)
        assert len(tp) == 1
        assert len(fn) == 0

    def test_false_positive_and_negative(self):
        r = _runner()
        gt = [GroundTruth(category=VulnerabilityCategory.REENTRANCY, lines=[5])]
        findings = [{"type": "unrelated-check", "lines": [99], "location": {"line": 99}}]
        tp, fp, fn = r._match_findings(gt, findings)
        assert len(tp) == 0
        assert len(fp) == 1
        assert len(fn) == 1


class TestCalculateResults:
    def test_aggregates_metrics(self):
        r = _runner()
        gt = GroundTruth(category=VulnerabilityCategory.REENTRANCY, lines=[5])
        vc = VulnerableContract(
            name="C", path="C.sol", source_code="x", pragma_version="0.8.0",
            vulnerabilities=[gt], source_url="", dataset="test",
        )
        cr = ContractResult(
            contract_name="C", contract_path="C.sol", ground_truth=[gt],
            detected_findings=[], true_positives=[{"type": "reentrancy-eth"}],
            false_positives=[{"type": "x"}], false_negatives=[], analysis_time_ms=10, error=None,
        )
        res = r._calculate_results([vc], [cr], 1.5)
        assert res.overall_metrics.true_positives == 1
        assert res.overall_metrics.false_positives == 1
        assert res.total_time_seconds == 1.5
