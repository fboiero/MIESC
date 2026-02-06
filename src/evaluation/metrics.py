"""
Evaluation Metrics for MIESC LLM and RAG Analysis.

Provides standard information retrieval and classification metrics
for measuring vulnerability detection effectiveness.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: February 2026
"""

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a vulnerability finding for evaluation."""

    id: str
    swc_id: Optional[str] = None
    cwe_id: Optional[str] = None
    title: str = ""
    severity: str = "MEDIUM"
    location: Optional[Dict[str, Any]] = None
    confidence: float = 0.5

    def matches(self, other: "Finding", strict: bool = False) -> bool:
        """Check if this finding matches another finding."""
        # Match by SWC ID if both have it
        if self.swc_id and other.swc_id:
            if self.swc_id == other.swc_id:
                if strict and self.location and other.location:
                    return self.location.get("line") == other.location.get("line")
                return True

        # Match by title similarity (case-insensitive)
        if self.title and other.title:
            t1 = self.title.lower()
            t2 = other.title.lower()
            # Direct substring match
            if t1 in t2 or t2 in t1:
                return True
            # Keyword-based matching for common vulnerability types
            vuln_keywords = [
                "reentrancy", "overflow", "underflow", "access control",
                "delegatecall", "selfdestruct", "front-run", "frontrun",
                "oracle", "flash loan", "signature", "replay", "dos",
                "denial of service", "timestamp", "randomness", "phishing",
                "permit", "callback", "proxy", "storage", "uninitialized"
            ]
            for keyword in vuln_keywords:
                if keyword in t1 and keyword in t2:
                    return True

        return False


@dataclass
class EvaluationMetrics:
    """Container for all evaluation metrics."""

    # Classification metrics
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0

    # Retrieval metrics
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

    # Ranking metrics
    mrr: float = 0.0  # Mean Reciprocal Rank
    ndcg: float = 0.0  # Normalized Discounted Cumulative Gain
    map_score: float = 0.0  # Mean Average Precision

    # RAG-specific metrics
    context_relevance: float = 0.0  # How relevant retrieved context was
    retrieval_latency_ms: float = 0.0  # Time to retrieve context

    # Performance metrics
    inference_time_ms: float = 0.0
    total_tokens: int = 0

    # Additional info
    adapter_name: str = ""
    rag_enabled: bool = False
    model_name: str = ""

    # Per-severity breakdown
    by_severity: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "classification": {
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "false_negatives": self.false_negatives,
                "true_negatives": self.true_negatives,
            },
            "retrieval": {
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1_score": round(self.f1_score, 4),
            },
            "ranking": {
                "mrr": round(self.mrr, 4),
                "ndcg": round(self.ndcg, 4),
                "map": round(self.map_score, 4),
            },
            "rag": {
                "context_relevance": round(self.context_relevance, 4),
                "retrieval_latency_ms": round(self.retrieval_latency_ms, 2),
            },
            "performance": {
                "inference_time_ms": round(self.inference_time_ms, 2),
                "total_tokens": self.total_tokens,
            },
            "metadata": {
                "adapter": self.adapter_name,
                "rag_enabled": self.rag_enabled,
                "model": self.model_name,
            },
            "by_severity": self.by_severity,
        }


def compute_precision(tp: int, fp: int) -> float:
    """
    Compute precision: TP / (TP + FP)

    Precision measures how many of the detected vulnerabilities are actual vulnerabilities.
    High precision means few false positives.
    """
    if tp + fp == 0:
        return 0.0
    return tp / (tp + fp)


def compute_recall(tp: int, fn: int) -> float:
    """
    Compute recall (sensitivity): TP / (TP + FN)

    Recall measures how many of the actual vulnerabilities were detected.
    High recall means few missed vulnerabilities.
    """
    if tp + fn == 0:
        return 0.0
    return tp / (tp + fn)


def compute_f1(precision: float, recall: float) -> float:
    """
    Compute F1 score: 2 * (precision * recall) / (precision + recall)

    F1 is the harmonic mean of precision and recall.
    """
    if precision + recall == 0:
        return 0.0
    return 2 * (precision * recall) / (precision + recall)


def compute_mrr(rankings: List[int]) -> float:
    """
    Compute Mean Reciprocal Rank.

    Args:
        rankings: List of ranks where relevant items were found (1-indexed).
                  Use 0 or infinity if no relevant item was found.

    Returns:
        MRR score between 0 and 1.

    Example:
        rankings = [1, 3, 2]  # Found at position 1, 3, and 2
        mrr = (1/1 + 1/3 + 1/2) / 3 = 0.61
    """
    if not rankings:
        return 0.0

    rr_sum = 0.0
    for rank in rankings:
        if rank > 0:
            rr_sum += 1.0 / rank

    return rr_sum / len(rankings)


def compute_dcg(relevances: List[float], k: Optional[int] = None) -> float:
    """
    Compute Discounted Cumulative Gain.

    Args:
        relevances: List of relevance scores for each position (0 = not relevant, 1+ = relevant)
        k: Number of positions to consider (None = all)

    Returns:
        DCG score.
    """
    if not relevances:
        return 0.0

    if k is not None:
        relevances = relevances[:k]

    dcg = 0.0
    for i, rel in enumerate(relevances, 1):
        dcg += rel / math.log2(i + 1)

    return dcg


def compute_ndcg(relevances: List[float], k: Optional[int] = None) -> float:
    """
    Compute Normalized Discounted Cumulative Gain.

    NDCG normalizes DCG by the ideal DCG (if results were perfectly sorted).

    Args:
        relevances: List of relevance scores for each position
        k: Number of positions to consider

    Returns:
        NDCG score between 0 and 1.
    """
    dcg = compute_dcg(relevances, k)

    # Ideal DCG is when relevances are sorted descending
    ideal_relevances = sorted(relevances, reverse=True)
    idcg = compute_dcg(ideal_relevances, k)

    if idcg == 0:
        return 0.0

    return dcg / idcg


def compute_map(predictions: List[List[bool]], k: Optional[int] = None) -> float:
    """
    Compute Mean Average Precision.

    Args:
        predictions: List of queries, each containing a list of booleans
                    indicating if each result was relevant.
        k: Number of positions to consider per query.

    Returns:
        MAP score between 0 and 1.
    """
    if not predictions:
        return 0.0

    ap_sum = 0.0

    for query_results in predictions:
        if k is not None:
            query_results = query_results[:k]

        # Average Precision for this query
        relevant_count = 0
        precision_sum = 0.0

        for i, is_relevant in enumerate(query_results, 1):
            if is_relevant:
                relevant_count += 1
                precision_sum += relevant_count / i

        if relevant_count > 0:
            ap_sum += precision_sum / relevant_count

    return ap_sum / len(predictions)


def evaluate_findings(
    predicted: List[Finding],
    ground_truth: List[Finding],
    strict_matching: bool = False
) -> EvaluationMetrics:
    """
    Evaluate predicted findings against ground truth.

    Args:
        predicted: List of findings produced by the analyzer
        ground_truth: List of known vulnerabilities (labeled data)
        strict_matching: If True, also match by line number

    Returns:
        EvaluationMetrics with all computed scores.
    """
    metrics = EvaluationMetrics()

    # Track which ground truth findings were matched
    matched_gt: Set[int] = set()

    # Compute TP and FP
    for pred in predicted:
        found_match = False
        for i, gt in enumerate(ground_truth):
            if i not in matched_gt and pred.matches(gt, strict=strict_matching):
                matched_gt.add(i)
                found_match = True
                break

        if found_match:
            metrics.true_positives += 1
        else:
            metrics.false_positives += 1

    # FN = ground truth items that weren't matched
    metrics.false_negatives = len(ground_truth) - len(matched_gt)

    # Compute derived metrics
    metrics.precision = compute_precision(metrics.true_positives, metrics.false_positives)
    metrics.recall = compute_recall(metrics.true_positives, metrics.false_negatives)
    metrics.f1_score = compute_f1(metrics.precision, metrics.recall)

    # Compute by-severity breakdown
    severity_gt: Dict[str, List[Finding]] = {}
    severity_pred: Dict[str, List[Finding]] = {}

    for f in ground_truth:
        sev = f.severity.upper()
        severity_gt.setdefault(sev, []).append(f)

    for f in predicted:
        sev = f.severity.upper()
        severity_pred.setdefault(sev, []).append(f)

    for sev in set(list(severity_gt.keys()) + list(severity_pred.keys())):
        gt_list = severity_gt.get(sev, [])
        pred_list = severity_pred.get(sev, [])

        tp = sum(1 for p in pred_list if any(p.matches(g) for g in gt_list))
        fp = len(pred_list) - tp
        fn = len(gt_list) - tp

        metrics.by_severity[sev] = {
            "tp": max(tp, 0),
            "fp": fp,
            "fn": fn,
            "precision": compute_precision(tp, fp),
            "recall": compute_recall(tp, fn),
        }

    return metrics


def compare_metrics(
    baseline: EvaluationMetrics,
    treatment: EvaluationMetrics
) -> Dict[str, Any]:
    """
    Compare two sets of metrics (e.g., with vs without RAG).

    Args:
        baseline: Metrics without the treatment (e.g., RAG disabled)
        treatment: Metrics with the treatment (e.g., RAG enabled)

    Returns:
        Dictionary with improvement percentages and analysis.
    """
    def pct_change(old: float, new: float) -> float:
        if old == 0:
            return float("inf") if new > 0 else 0.0
        return ((new - old) / old) * 100

    return {
        "precision_change_pct": round(pct_change(baseline.precision, treatment.precision), 2),
        "recall_change_pct": round(pct_change(baseline.recall, treatment.recall), 2),
        "f1_change_pct": round(pct_change(baseline.f1_score, treatment.f1_score), 2),
        "fp_reduction": baseline.false_positives - treatment.false_positives,
        "fn_reduction": baseline.false_negatives - treatment.false_negatives,
        "latency_increase_pct": round(
            pct_change(baseline.inference_time_ms, treatment.inference_time_ms), 2
        ),
        "summary": {
            "baseline": baseline.to_dict(),
            "treatment": treatment.to_dict(),
        },
        "recommendation": _generate_recommendation(baseline, treatment),
    }


def _generate_recommendation(baseline: EvaluationMetrics, treatment: EvaluationMetrics) -> str:
    """Generate a recommendation based on metric comparison."""
    f1_improvement = treatment.f1_score - baseline.f1_score
    fp_reduction = baseline.false_positives - treatment.false_positives
    latency_increase = treatment.inference_time_ms - baseline.inference_time_ms

    if f1_improvement > 0.1:
        if latency_increase < 1000:  # Less than 1 second
            return "Strong recommendation: Enable RAG. Significant F1 improvement with acceptable latency."
        else:
            return "Conditional: Enable RAG for thorough audits. Consider disabling for quick scans."
    elif f1_improvement > 0.05:
        if fp_reduction > 0:
            return "Moderate recommendation: Enable RAG. Modest F1 improvement with FP reduction."
        else:
            return "Neutral: RAG provides small improvement. Consider based on use case."
    elif f1_improvement > 0:
        return "Weak recommendation: RAG provides marginal improvement. Optional."
    else:
        return "Not recommended: RAG does not improve detection in this configuration."


__all__ = [
    "Finding",
    "EvaluationMetrics",
    "compute_precision",
    "compute_recall",
    "compute_f1",
    "compute_mrr",
    "compute_dcg",
    "compute_ndcg",
    "compute_map",
    "evaluate_findings",
    "compare_metrics",
]
