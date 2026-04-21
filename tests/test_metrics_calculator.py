"""
Tests for src.benchmark.metrics_calculator — ConfusionMatrix dataclass.

Coverage target: 37% → 70%+. Focuses on the ConfusionMatrix property
calculations which are the core computation.
"""

from __future__ import annotations

import pytest

from src.benchmark.metrics_calculator import ConfusionMatrix


class TestConfusionMatrix:
    def test_from_counts(self):
        cm = ConfusionMatrix(true_positives=8, false_positives=2,
                             false_negatives=1, true_negatives=89)
        assert cm.true_positives == 8
        assert cm.false_positives == 2

    def test_precision(self):
        cm = ConfusionMatrix(true_positives=8, false_positives=2)
        assert abs(cm.precision - 0.8) < 0.01

    def test_recall(self):
        cm = ConfusionMatrix(true_positives=8, false_negatives=1)
        assert abs(cm.recall - 8 / 9) < 0.01

    def test_f1_score(self):
        cm = ConfusionMatrix(true_positives=8, false_positives=2, false_negatives=1)
        p, r = 0.8, 8 / 9
        expected = 2 * p * r / (p + r)
        assert abs(cm.f1_score - expected) < 0.01

    def test_zero_division_safe(self):
        cm = ConfusionMatrix()
        assert cm.precision == 0.0
        assert cm.recall == 0.0
        assert cm.f1_score == 0.0
        assert cm.accuracy == 0.0

    def test_perfect_detection(self):
        cm = ConfusionMatrix(true_positives=10, true_negatives=90)
        assert cm.precision == 1.0
        assert cm.recall == 1.0
        assert cm.f1_score == 1.0

    def test_all_false_positives(self):
        cm = ConfusionMatrix(false_positives=10, false_negatives=5, true_negatives=85)
        assert cm.precision == 0.0
        assert cm.recall == 0.0

    def test_accuracy(self):
        cm = ConfusionMatrix(true_positives=8, false_positives=2,
                             false_negatives=1, true_negatives=89)
        assert abs(cm.accuracy - 0.97) < 0.01

    def test_false_positive_rate(self):
        cm = ConfusionMatrix(false_positives=2, true_negatives=98)
        assert abs(cm.false_positive_rate - 0.02) < 0.01

    def test_specificity(self):
        cm = ConfusionMatrix(false_positives=2, true_negatives=98)
        assert abs(cm.specificity - 0.98) < 0.01

    def test_to_dict_has_all_keys(self):
        cm = ConfusionMatrix(true_positives=5, false_positives=1,
                             false_negatives=2, true_negatives=92)
        d = cm.to_dict()
        for key in ("tp", "fp", "tn", "fn", "precision", "recall", "f1_score", "accuracy", "fpr"):
            assert key in d, f"Missing key: {key}"
        assert d["tp"] == 5
        assert isinstance(d["precision"], float)

    def test_to_dict_values_bounded(self):
        cm = ConfusionMatrix(true_positives=50, false_positives=50,
                             false_negatives=50, true_negatives=50)
        d = cm.to_dict()
        for key in ("precision", "recall", "f1_score", "accuracy", "fpr"):
            assert 0.0 <= d[key] <= 1.0, f"{key} out of [0,1]: {d[key]}"
