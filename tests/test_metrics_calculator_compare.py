"""Tests for MetricsCalculator.compare / confusion matrix / summary (pure math)."""

from __future__ import annotations

from datetime import datetime

from miesc.benchmark.metrics_calculator import (
    BenchmarkResult,
    DetectionMetrics,
    MetricsCalculator,
)

_TS = datetime(2026, 6, 21, 12, 0)


def _result(tp, fp, fn, version):
    om = DetectionMetrics(
        category="overall",
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=0,
    )
    cat = {
        "reentrancy": DetectionMetrics(
            category="reentrancy",
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=0,
        )
    }
    return BenchmarkResult(
        timestamp=_TS,
        total_contracts=10,
        analyzed_contracts=10,
        failed_contracts=0,
        total_ground_truth=tp + fn,
        total_detected=tp + fp,
        contract_results=[],
        metrics_by_category=cat,
        overall_metrics=om,
        total_time_seconds=1.0,
        miesc_version=version,
        config={},
    )


class TestCompare:
    def test_improvement_detected(self):
        calc = MetricsCalculator()
        comp = calc.compare(_result(5, 5, 5, "5.3"), _result(8, 2, 2, "5.4"))
        assert len(comp.improvements) > 0
        assert comp.regressions == []

    def test_regression_detected(self):
        calc = MetricsCalculator()
        comp = calc.compare(_result(8, 2, 2, "5.3"), _result(4, 6, 6, "5.4"))
        assert len(comp.regressions) > 0

    def test_summary_is_string(self):
        calc = MetricsCalculator()
        comp = calc.compare(_result(5, 5, 5, "5.3"), _result(8, 2, 2, "5.4"))
        assert isinstance(comp.summary(), str)
        assert "5.4" in comp.summary()

    def test_comparison_to_dict(self):
        calc = MetricsCalculator()
        comp = calc.compare(_result(5, 5, 5, "5.3"), _result(6, 4, 4, "5.4"))
        d = comp.to_dict()
        assert isinstance(d, dict)


class TestConfusionMatrix:
    def test_from_result(self):
        cm = MetricsCalculator().calculate_confusion_matrix(_result(8, 2, 2, "5.4"))
        assert cm.true_positives == 8
        assert abs(cm.precision - 0.8) < 1e-9
