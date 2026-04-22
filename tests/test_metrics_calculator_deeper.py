"""
Deep coverage for src.benchmark.metrics_calculator — MetricsDelta,
ComparisonResult, and MetricsCalculator class.

Target: 46% → 75%+.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.benchmark.metrics_calculator import (
    ComparisonResult,
    MetricsCalculator,
    MetricsDelta,
)

# ---------------------------------------------------------------------------
# MetricsDelta
# ---------------------------------------------------------------------------


class TestMetricsDelta:
    def test_absolute_change(self):
        d = MetricsDelta(metric_name="precision", before=0.5, after=0.7)
        assert abs(d.absolute_change - 0.2) < 0.001

    def test_relative_change(self):
        d = MetricsDelta(metric_name="recall", before=0.5, after=0.75)
        assert abs(d.relative_change - 0.5) < 0.001

    def test_relative_change_from_zero(self):
        d = MetricsDelta(metric_name="recall", before=0.0, after=0.5)
        assert d.relative_change == float("inf")

    def test_relative_change_zero_to_zero(self):
        d = MetricsDelta(metric_name="recall", before=0.0, after=0.0)
        assert d.relative_change == 0.0

    def test_improved_higher_is_better(self):
        d = MetricsDelta(metric_name="recall", before=0.5, after=0.8)
        assert d.improved is True
        d2 = MetricsDelta(metric_name="recall", before=0.8, after=0.5)
        assert d2.improved is False

    def test_improved_lower_is_better_for_fp(self):
        d = MetricsDelta(metric_name="false_positive_rate", before=0.3, after=0.1)
        assert d.improved is True
        d2 = MetricsDelta(metric_name="fp_rate", before=0.1, after=0.3)
        assert d2.improved is False

    def test_to_dict(self):
        d = MetricsDelta(metric_name="f1", before=0.4, after=0.6)
        out = d.to_dict()
        assert out["metric"] == "f1"
        assert out["before"] == 0.4
        assert out["after"] == 0.6
        assert abs(out["change"] - 0.2) < 0.001
        assert abs(out["change_pct"] - 50.0) < 0.1
        assert out["improved"] is True


# ---------------------------------------------------------------------------
# ComparisonResult
# ---------------------------------------------------------------------------


class TestComparisonResult:
    @pytest.fixture
    def comparison(self):
        now = datetime.now(timezone.utc)
        return ComparisonResult(
            before_version="5.1.8",
            after_version="5.1.9",
            before_timestamp=now,
            after_timestamp=now,
            overall_delta={
                "precision": MetricsDelta("precision", 0.22, 0.35),
                "recall": MetricsDelta("recall", 0.80, 0.82),
            },
            category_deltas={
                "reentrancy": {
                    "f1_score": MetricsDelta("f1_score", 0.36, 0.45),
                },
            },
            improvements=["Precision improved by 13pp"],
            regressions=[],
        )

    def test_summary_output(self, comparison):
        s = comparison.summary()
        assert isinstance(s, str)
        assert "5.1.8" in s
        assert "5.1.9" in s
        assert "BENCHMARK COMPARISON" in s
        assert "Precision improved" in s

    def test_summary_with_regressions(self, comparison):
        comparison.regressions = ["DoS recall dropped"]
        s = comparison.summary()
        assert "REGRESSIONS" in s
        assert "DoS recall dropped" in s

    def test_to_dict(self, comparison):
        d = comparison.to_dict()
        assert d["before_version"] == "5.1.8"
        assert "precision" in d["overall_delta"]
        assert "reentrancy" in d["category_deltas"]

    def test_to_dict_roundtrip_json(self, comparison):
        import json
        d = comparison.to_dict()
        j = json.dumps(d)
        loaded = json.loads(j)
        assert loaded["before_version"] == "5.1.8"


# ---------------------------------------------------------------------------
# MetricsCalculator
# ---------------------------------------------------------------------------


class TestMetricsCalculatorCompare:
    @pytest.fixture
    def calc(self):
        return MetricsCalculator()

    def test_instantiate(self, calc):
        assert calc is not None

    def test_compare_needs_benchmark_results(self, calc):
        """MetricsCalculator.compare() takes BenchmarkResult objects."""
        from src.benchmark.benchmark_runner import BenchmarkResult, DetectionMetrics
        now = datetime.now(timezone.utc)
        metrics = DetectionMetrics(
            category="overall",
            true_positives=8, false_positives=2, false_negatives=2,
        )
        br = BenchmarkResult(
            timestamp=now, total_contracts=100, analyzed_contracts=100,
            failed_contracts=0, total_ground_truth=10, total_detected=8,
            contract_results=[], metrics_by_category={},
            overall_metrics=metrics, total_time_seconds=5.0,
        )
        result = calc.compare(before=br, after=br)
        assert isinstance(result, ComparisonResult)
