"""
Tests for MIESC evaluation metrics module.

Tests the evaluation metrics used for measuring vulnerability detection effectiveness.
"""

import math
import pytest

from src.evaluation.metrics import (
    Finding,
    EvaluationMetrics,
    compute_precision,
    compute_recall,
    compute_f1,
    compute_mrr,
    compute_dcg,
    compute_ndcg,
    compute_map,
    evaluate_findings,
    compare_metrics,
)


class TestFinding:
    """Test Finding dataclass."""

    def test_finding_creation(self):
        """Test creating a finding."""
        f = Finding(id="1", swc_id="SWC-107", title="Reentrancy")
        assert f.id == "1"
        assert f.swc_id == "SWC-107"
        assert f.title == "Reentrancy"

    def test_finding_defaults(self):
        """Test finding default values."""
        f = Finding(id="1")
        assert f.severity == "MEDIUM"
        assert f.confidence == 0.5
        assert f.location is None

    def test_matches_by_swc(self):
        """Test matching by SWC ID."""
        f1 = Finding(id="1", swc_id="SWC-107")
        f2 = Finding(id="2", swc_id="SWC-107")
        f3 = Finding(id="3", swc_id="SWC-106")
        
        assert f1.matches(f2) is True
        assert f1.matches(f3) is False

    def test_matches_by_title(self):
        """Test matching by title."""
        f1 = Finding(id="1", title="Reentrancy vulnerability")
        f2 = Finding(id="2", title="Reentrancy in withdraw")
        f3 = Finding(id="3", title="Integer overflow")
        
        assert f1.matches(f2) is True  # "reentrancy" keyword
        assert f1.matches(f3) is False

    def test_matches_by_title_substring(self):
        """Test matching by title substring."""
        f1 = Finding(id="1", title="Access control issue")
        f2 = Finding(id="2", title="Missing access control check")
        
        assert f1.matches(f2) is True

    def test_matches_strict_mode(self):
        """Test strict matching with line numbers."""
        f1 = Finding(id="1", swc_id="SWC-107", location={"line": 10})
        f2 = Finding(id="2", swc_id="SWC-107", location={"line": 10})
        f3 = Finding(id="3", swc_id="SWC-107", location={"line": 20})
        
        assert f1.matches(f2, strict=True) is True
        assert f1.matches(f3, strict=True) is False

    def test_matches_no_swc_no_title(self):
        """Test no match when no identifiers."""
        f1 = Finding(id="1")
        f2 = Finding(id="2")
        
        assert f1.matches(f2) is False


class TestEvaluationMetrics:
    """Test EvaluationMetrics dataclass."""

    def test_metrics_creation(self):
        """Test creating metrics."""
        m = EvaluationMetrics()
        assert m.true_positives == 0
        assert m.precision == 0.0
        assert m.f1_score == 0.0

    def test_metrics_to_dict(self):
        """Test converting metrics to dict."""
        m = EvaluationMetrics(
            true_positives=10,
            false_positives=2,
            false_negatives=3,
            precision=0.833,
            recall=0.769,
            f1_score=0.8,
            adapter_name="slither",
            rag_enabled=True,
        )
        d = m.to_dict()
        
        assert d["classification"]["true_positives"] == 10
        assert d["retrieval"]["precision"] == 0.833
        assert d["metadata"]["adapter"] == "slither"
        assert d["metadata"]["rag_enabled"] is True


class TestBasicMetrics:
    """Test basic metric computation functions."""

    def test_precision_basic(self):
        """Test precision calculation."""
        assert compute_precision(8, 2) == 0.8  # 8 / (8 + 2) = 0.8
        assert compute_precision(10, 0) == 1.0  # Perfect precision
        assert compute_precision(0, 10) == 0.0  # All false positives

    def test_precision_zero_division(self):
        """Test precision with no predictions."""
        assert compute_precision(0, 0) == 0.0

    def test_recall_basic(self):
        """Test recall calculation."""
        assert compute_recall(8, 2) == 0.8  # 8 / (8 + 2) = 0.8
        assert compute_recall(10, 0) == 1.0  # Perfect recall
        assert compute_recall(0, 10) == 0.0  # All false negatives

    def test_recall_zero_division(self):
        """Test recall with no ground truth."""
        assert compute_recall(0, 0) == 0.0

    def test_f1_basic(self):
        """Test F1 score calculation."""
        # F1 = 2 * (0.8 * 0.8) / (0.8 + 0.8) = 0.8
        assert abs(compute_f1(0.8, 0.8) - 0.8) < 0.0001
        
        # F1 = 2 * (1.0 * 0.5) / (1.0 + 0.5) = 0.667
        assert abs(compute_f1(1.0, 0.5) - 0.667) < 0.01

    def test_f1_zero_division(self):
        """Test F1 with zero precision and recall."""
        assert compute_f1(0.0, 0.0) == 0.0


class TestRankingMetrics:
    """Test ranking metric functions."""

    def test_mrr_basic(self):
        """Test MRR calculation."""
        # [1, 3, 2] -> (1/1 + 1/3 + 1/2) / 3 ≈ 0.611
        mrr = compute_mrr([1, 3, 2])
        assert abs(mrr - 0.611) < 0.01

    def test_mrr_perfect(self):
        """Test perfect MRR (all found at position 1)."""
        assert compute_mrr([1, 1, 1]) == 1.0

    def test_mrr_empty(self):
        """Test MRR with no rankings."""
        assert compute_mrr([]) == 0.0

    def test_mrr_with_zeros(self):
        """Test MRR with some not found (rank 0)."""
        # [1, 0, 2] -> (1/1 + 0 + 1/2) / 3 = 0.5
        mrr = compute_mrr([1, 0, 2])
        assert abs(mrr - 0.5) < 0.01

    def test_dcg_basic(self):
        """Test DCG calculation."""
        # DCG = rel_1/log2(2) + rel_2/log2(3) + rel_3/log2(4)
        # DCG = 3/1 + 2/1.585 + 1/2 = 3 + 1.262 + 0.5 = 4.762
        relevances = [3, 2, 1]
        dcg = compute_dcg(relevances)
        assert abs(dcg - 4.762) < 0.01

    def test_dcg_with_k(self):
        """Test DCG with limit k."""
        relevances = [3, 2, 1, 0, 0]
        dcg_k2 = compute_dcg(relevances, k=2)
        # Only first 2: 3/1 + 2/1.585 = 3 + 1.262 = 4.262
        assert abs(dcg_k2 - 4.262) < 0.01

    def test_dcg_empty(self):
        """Test DCG with empty list."""
        assert compute_dcg([]) == 0.0

    def test_ndcg_perfect(self):
        """Test perfect NDCG (already sorted)."""
        relevances = [3, 2, 1]
        ndcg = compute_ndcg(relevances)
        assert ndcg == 1.0

    def test_ndcg_worst(self):
        """Test worst NDCG (reverse sorted)."""
        relevances = [1, 2, 3]  # Reversed
        ndcg = compute_ndcg(relevances)
        # Should be less than 1
        assert ndcg < 1.0

    def test_ndcg_zero(self):
        """Test NDCG with all zeros."""
        assert compute_ndcg([0, 0, 0]) == 0.0


class TestMAP:
    """Test Mean Average Precision."""

    def test_map_basic(self):
        """Test MAP calculation."""
        # Query 1: [True, False, True] -> AP = (1/1 + 2/3) / 2 = 0.833
        # Query 2: [True, True, False] -> AP = (1/1 + 2/2) / 2 = 1.0
        # MAP = (0.833 + 1.0) / 2 = 0.917
        predictions = [[True, False, True], [True, True, False]]
        map_score = compute_map(predictions)
        assert abs(map_score - 0.917) < 0.01

    def test_map_perfect(self):
        """Test perfect MAP."""
        predictions = [[True, True], [True, True]]
        assert compute_map(predictions) == 1.0

    def test_map_empty(self):
        """Test MAP with no queries."""
        assert compute_map([]) == 0.0

    def test_map_no_relevant(self):
        """Test MAP with no relevant results."""
        predictions = [[False, False], [False, False]]
        assert compute_map(predictions) == 0.0


class TestEvaluateFindings:
    """Test evaluate_findings function."""

    def test_evaluate_perfect(self):
        """Test perfect detection."""
        predicted = [
            Finding(id="1", swc_id="SWC-107"),
            Finding(id="2", swc_id="SWC-101"),
        ]
        ground_truth = [
            Finding(id="a", swc_id="SWC-107"),
            Finding(id="b", swc_id="SWC-101"),
        ]
        
        metrics = evaluate_findings(predicted, ground_truth)
        
        assert metrics.true_positives == 2
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.f1_score == 1.0

    def test_evaluate_with_false_positives(self):
        """Test detection with false positives."""
        predicted = [
            Finding(id="1", swc_id="SWC-107"),
            Finding(id="2", swc_id="SWC-101"),
            Finding(id="3", swc_id="SWC-999"),  # FP
        ]
        ground_truth = [
            Finding(id="a", swc_id="SWC-107"),
            Finding(id="b", swc_id="SWC-101"),
        ]
        
        metrics = evaluate_findings(predicted, ground_truth)
        
        assert metrics.true_positives == 2
        assert metrics.false_positives == 1
        assert metrics.false_negatives == 0

    def test_evaluate_with_false_negatives(self):
        """Test detection with false negatives."""
        predicted = [
            Finding(id="1", swc_id="SWC-107"),
        ]
        ground_truth = [
            Finding(id="a", swc_id="SWC-107"),
            Finding(id="b", swc_id="SWC-101"),  # FN
        ]
        
        metrics = evaluate_findings(predicted, ground_truth)
        
        assert metrics.true_positives == 1
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 1

    def test_evaluate_empty_predicted(self):
        """Test evaluation with no predictions."""
        predicted = []
        ground_truth = [Finding(id="a", swc_id="SWC-107")]
        
        metrics = evaluate_findings(predicted, ground_truth)
        
        assert metrics.true_positives == 0
        assert metrics.false_negatives == 1

    def test_evaluate_empty_ground_truth(self):
        """Test evaluation with no ground truth."""
        predicted = [Finding(id="1", swc_id="SWC-107")]
        ground_truth = []
        
        metrics = evaluate_findings(predicted, ground_truth)
        
        assert metrics.false_positives == 1
        assert metrics.false_negatives == 0

    def test_evaluate_by_severity(self):
        """Test evaluation produces severity breakdown."""
        predicted = [
            Finding(id="1", swc_id="SWC-107", severity="HIGH"),
            Finding(id="2", swc_id="SWC-101", severity="MEDIUM"),
        ]
        ground_truth = [
            Finding(id="a", swc_id="SWC-107", severity="HIGH"),
        ]
        
        metrics = evaluate_findings(predicted, ground_truth)
        
        assert "HIGH" in metrics.by_severity
        assert metrics.by_severity["HIGH"]["tp"] == 1


class TestCompareMetrics:
    """Test compare_metrics function."""

    def test_compare_improvement(self):
        """Test comparing metrics showing improvement."""
        baseline = EvaluationMetrics(
            precision=0.5,
            recall=0.5,
            f1_score=0.5,
            false_positives=10,
            false_negatives=5,
            inference_time_ms=100,
        )
        treatment = EvaluationMetrics(
            precision=0.8,
            recall=0.7,
            f1_score=0.75,
            false_positives=4,
            false_negatives=3,
            inference_time_ms=150,
        )
        
        comparison = compare_metrics(baseline, treatment)
        
        assert comparison["precision_change_pct"] == 60.0  # 0.5 -> 0.8 = 60%
        assert comparison["fp_reduction"] == 6  # 10 -> 4
        assert comparison["fn_reduction"] == 2  # 5 -> 3

    def test_compare_regression(self):
        """Test comparing metrics showing regression."""
        baseline = EvaluationMetrics(f1_score=0.8)
        treatment = EvaluationMetrics(f1_score=0.6)
        
        comparison = compare_metrics(baseline, treatment)
        
        assert comparison["f1_change_pct"] < 0  # Negative change

    def test_compare_generates_recommendation(self):
        """Test that comparison generates recommendation."""
        baseline = EvaluationMetrics(f1_score=0.5, inference_time_ms=100)
        treatment = EvaluationMetrics(f1_score=0.7, inference_time_ms=200)
        
        comparison = compare_metrics(baseline, treatment)
        
        assert "recommendation" in comparison
        assert len(comparison["recommendation"]) > 0

    def test_compare_from_zero(self):
        """Test comparing when baseline is zero."""
        baseline = EvaluationMetrics(precision=0.0)
        treatment = EvaluationMetrics(precision=0.5)
        
        comparison = compare_metrics(baseline, treatment)
        
        # Should handle division by zero gracefully
        assert comparison["precision_change_pct"] == float("inf")


class TestRecommendations:
    """Test recommendation generation."""

    def test_strong_recommendation(self):
        """Test strong recommendation with significant improvement."""
        baseline = EvaluationMetrics(f1_score=0.5, inference_time_ms=100)
        treatment = EvaluationMetrics(f1_score=0.7, inference_time_ms=200)
        
        comparison = compare_metrics(baseline, treatment)
        
        assert "Strong recommendation" in comparison["recommendation"]

    def test_conditional_recommendation(self):
        """Test conditional recommendation with high latency."""
        baseline = EvaluationMetrics(f1_score=0.5, inference_time_ms=100)
        treatment = EvaluationMetrics(f1_score=0.7, inference_time_ms=2000)
        
        comparison = compare_metrics(baseline, treatment)
        
        assert "Conditional" in comparison["recommendation"]

    def test_not_recommended(self):
        """Test not recommended when no improvement."""
        baseline = EvaluationMetrics(f1_score=0.8)
        treatment = EvaluationMetrics(f1_score=0.7)
        
        comparison = compare_metrics(baseline, treatment)
        
        assert "Not recommended" in comparison["recommendation"]
