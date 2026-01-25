"""
Metrics Calculator for Benchmark Comparison
============================================

Calculates detection metrics and compares benchmark runs.

Usage:
    from src.benchmark import MetricsCalculator, compare_runs

    calc = MetricsCalculator()
    comparison = calc.compare(before_result, after_result)
    print(comparison.summary())
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .benchmark_runner import BenchmarkResult, DetectionMetrics


@dataclass
class ConfusionMatrix:
    """Confusion matrix for binary classification."""

    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.true_positives + self.true_negatives + self.false_positives + self.false_negatives
        return (self.true_positives + self.true_negatives) / total if total > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    @property
    def specificity(self) -> float:
        return 1.0 - self.false_positive_rate

    def to_dict(self) -> Dict:
        return {
            "tp": self.true_positives,
            "fp": self.false_positives,
            "tn": self.true_negatives,
            "fn": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "accuracy": round(self.accuracy, 4),
            "fpr": round(self.false_positive_rate, 4),
        }


@dataclass
class MetricsDelta:
    """Change in metrics between two runs."""

    metric_name: str
    before: float
    after: float

    @property
    def absolute_change(self) -> float:
        return self.after - self.before

    @property
    def relative_change(self) -> float:
        if self.before == 0:
            return float('inf') if self.after > 0 else 0.0
        return (self.after - self.before) / self.before

    @property
    def improved(self) -> bool:
        # For FP rate, lower is better
        if "false_positive" in self.metric_name.lower() or "fp" in self.metric_name.lower():
            return self.after < self.before
        return self.after > self.before

    def to_dict(self) -> Dict:
        return {
            "metric": self.metric_name,
            "before": round(self.before, 4),
            "after": round(self.after, 4),
            "change": round(self.absolute_change, 4),
            "change_pct": round(self.relative_change * 100, 2),
            "improved": self.improved,
        }


@dataclass
class ComparisonResult:
    """Result of comparing two benchmark runs."""

    before_version: str
    after_version: str
    before_timestamp: datetime
    after_timestamp: datetime
    overall_delta: Dict[str, MetricsDelta]
    category_deltas: Dict[str, Dict[str, MetricsDelta]]
    improvements: List[str]
    regressions: List[str]

    def summary(self) -> str:
        """Generate human-readable comparison summary."""
        lines = [
            "=" * 70,
            "BENCHMARK COMPARISON",
            "=" * 70,
            f"Before: {self.before_version} ({self.before_timestamp.strftime('%Y-%m-%d %H:%M')})",
            f"After:  {self.after_version} ({self.after_timestamp.strftime('%Y-%m-%d %H:%M')})",
            "",
            "OVERALL METRICS CHANGE",
            "-" * 50,
        ]

        for name, delta in self.overall_delta.items():
            arrow = "↑" if delta.improved else "↓" if delta.absolute_change != 0 else "→"
            color_indicator = "+" if delta.improved else "-" if not delta.improved and delta.absolute_change != 0 else " "
            lines.append(
                f"  {name:20} {delta.before*100:6.2f}% → {delta.after*100:6.2f}% "
                f"({color_indicator}{delta.absolute_change*100:+.2f}%) {arrow}"
            )

        if self.improvements:
            lines.extend(["", "IMPROVEMENTS", "-" * 50])
            for imp in self.improvements:
                lines.append(f"  ✓ {imp}")

        if self.regressions:
            lines.extend(["", "REGRESSIONS", "-" * 50])
            for reg in self.regressions:
                lines.append(f"  ✗ {reg}")

        if self.category_deltas:
            lines.extend(["", "BY CATEGORY", "-" * 50])
            for cat, deltas in sorted(self.category_deltas.items()):
                f1_delta = deltas.get("f1_score")
                if f1_delta:
                    arrow = "↑" if f1_delta.improved else "↓"
                    lines.append(
                        f"  {cat:25} F1: {f1_delta.before*100:5.1f}% → "
                        f"{f1_delta.after*100:5.1f}% ({f1_delta.absolute_change*100:+.1f}%) {arrow}"
                    )

        lines.append("=" * 70)
        return "\n".join(lines)

    def to_dict(self) -> Dict:
        return {
            "before_version": self.before_version,
            "after_version": self.after_version,
            "before_timestamp": self.before_timestamp.isoformat(),
            "after_timestamp": self.after_timestamp.isoformat(),
            "overall_delta": {k: v.to_dict() for k, v in self.overall_delta.items()},
            "category_deltas": {
                cat: {k: v.to_dict() for k, v in deltas.items()}
                for cat, deltas in self.category_deltas.items()
            },
            "improvements": self.improvements,
            "regressions": self.regressions,
        }


class MetricsCalculator:
    """
    Calculates and compares benchmark metrics.

    Usage:
        calc = MetricsCalculator()
        comparison = calc.compare(result1, result2)
        print(comparison.summary())
    """

    def calculate_confusion_matrix(self, result: BenchmarkResult) -> ConfusionMatrix:
        """Calculate confusion matrix from benchmark result."""
        return ConfusionMatrix(
            true_positives=result.overall_metrics.true_positives,
            false_positives=result.overall_metrics.false_positives,
            false_negatives=result.overall_metrics.false_negatives,
            true_negatives=result.overall_metrics.true_negatives,
        )

    def compare(
        self,
        before: BenchmarkResult,
        after: BenchmarkResult,
    ) -> ComparisonResult:
        """
        Compare two benchmark runs.

        Args:
            before: Baseline benchmark result
            after: New benchmark result

        Returns:
            ComparisonResult with deltas and analysis
        """
        # Calculate overall deltas
        overall_delta = self._calculate_metric_deltas(
            before.overall_metrics,
            after.overall_metrics,
        )

        # Calculate category deltas
        category_deltas = {}
        all_categories = set(before.metrics_by_category.keys()) | set(after.metrics_by_category.keys())

        for cat in all_categories:
            before_metrics = before.metrics_by_category.get(cat, DetectionMetrics(category=cat))
            after_metrics = after.metrics_by_category.get(cat, DetectionMetrics(category=cat))
            category_deltas[cat] = self._calculate_metric_deltas(before_metrics, after_metrics)

        # Identify improvements and regressions
        improvements = []
        regressions = []

        # Check overall metrics
        for name, delta in overall_delta.items():
            if abs(delta.absolute_change) > 0.01:  # >1% change
                if delta.improved:
                    improvements.append(f"{name}: {delta.absolute_change*100:+.1f}%")
                else:
                    regressions.append(f"{name}: {delta.absolute_change*100:+.1f}%")

        # Check categories
        for cat, deltas in category_deltas.items():
            f1_delta = deltas.get("f1_score")
            if f1_delta and abs(f1_delta.absolute_change) > 0.05:  # >5% change
                if f1_delta.improved:
                    improvements.append(f"{cat} detection: {f1_delta.absolute_change*100:+.1f}% F1")
                else:
                    regressions.append(f"{cat} detection: {f1_delta.absolute_change*100:+.1f}% F1")

        return ComparisonResult(
            before_version=before.miesc_version,
            after_version=after.miesc_version,
            before_timestamp=before.timestamp,
            after_timestamp=after.timestamp,
            overall_delta=overall_delta,
            category_deltas=category_deltas,
            improvements=improvements,
            regressions=regressions,
        )

    def _calculate_metric_deltas(
        self,
        before: DetectionMetrics,
        after: DetectionMetrics,
    ) -> Dict[str, MetricsDelta]:
        """Calculate deltas for all metrics."""
        return {
            "precision": MetricsDelta("precision", before.precision, after.precision),
            "recall": MetricsDelta("recall", before.recall, after.recall),
            "f1_score": MetricsDelta("f1_score", before.f1_score, after.f1_score),
        }

    @staticmethod
    def load_result(path: Path) -> BenchmarkResult:
        """Load benchmark result from JSON file."""
        with open(path, "r") as f:
            data = json.load(f)

        # Reconstruct BenchmarkResult from dict
        overall = DetectionMetrics(
            category="overall",
            true_positives=data["overall_metrics"]["true_positives"],
            false_positives=data["overall_metrics"]["false_positives"],
            false_negatives=data["overall_metrics"]["false_negatives"],
        )

        metrics_by_cat = {}
        for cat, m in data.get("metrics_by_category", {}).items():
            metrics_by_cat[cat] = DetectionMetrics(
                category=cat,
                true_positives=m.get("true_positives", 0),
                false_positives=m.get("false_positives", 0),
                false_negatives=m.get("false_negatives", 0),
            )

        return BenchmarkResult(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            total_contracts=data["summary"]["total_contracts"],
            analyzed_contracts=data["summary"]["analyzed_contracts"],
            failed_contracts=data["summary"]["failed_contracts"],
            total_ground_truth=data["summary"]["total_ground_truth"],
            total_detected=data["summary"]["total_detected"],
            contract_results=[],  # Not needed for comparison
            metrics_by_category=metrics_by_cat,
            overall_metrics=overall,
            total_time_seconds=data["total_time_seconds"],
            miesc_version=data.get("miesc_version", "unknown"),
        )


def calculate_metrics(result: BenchmarkResult) -> ConfusionMatrix:
    """Convenience function to calculate confusion matrix."""
    calc = MetricsCalculator()
    return calc.calculate_confusion_matrix(result)


def compare_runs(
    before_path: Path,
    after_path: Path,
) -> ComparisonResult:
    """Compare two saved benchmark runs."""
    calc = MetricsCalculator()
    before = calc.load_result(before_path)
    after = calc.load_result(after_path)
    return calc.compare(before, after)
