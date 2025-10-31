#!/usr/bin/env python3
"""
MIESC Evaluation Statistics Script

This script computes rigorous statistical metrics for MIESC validation:
- Precision, Recall, F1 Score, Cohen's Kappa
- Bootstrap 95% Confidence Intervals
- McNemar's Test for paired comparisons
- Paired t-test for continuous metrics
- Effect size calculations (Cohen's d)

Author: Fernando Boiero
Institution: Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
License: GPL-3.0
Version: 1.0
Date: 2025-01-19
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
import numpy as np
from scipy import stats
from sklearn.metrics import cohen_kappa_score, confusion_matrix
import pandas as pd

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ConfusionMatrix:
    """Confusion matrix for binary classification"""
    tp: int  # True Positives
    fp: int  # False Positives
    tn: int  # True Negatives
    fn: int  # False Negatives

    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP)"""
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN)"""
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1_score(self) -> float:
        """F1 = 2 * (Precision * Recall) / (Precision + Recall)"""
        p, r = self.precision, self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def fpr(self) -> float:
        """False Positive Rate = FP / (FP + TN)"""
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0

    @property
    def fnr(self) -> float:
        """False Negative Rate = FN / (FN + TP)"""
        return self.fn / (self.fn + self.tp) if (self.fn + self.tp) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        """Accuracy = (TP + TN) / (TP + TN + FP + FN)"""
        total = self.tp + self.tn + self.fp + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0


@dataclass
class StatisticalResults:
    """Complete statistical results for a tool"""
    tool_name: str
    confusion_matrix: ConfusionMatrix
    precision: float
    recall: float
    f1_score: float
    fpr: float
    accuracy: float
    cohen_kappa: float = 0.0
    precision_ci95: Tuple[float, float] = (0.0, 0.0)
    recall_ci95: Tuple[float, float] = (0.0, 0.0)
    f1_ci95: Tuple[float, float] = (0.0, 0.0)
    sample_size: int = 0


# ============================================================================
# BOOTSTRAP CONFIDENCE INTERVALS
# ============================================================================

def bootstrap_ci(data: np.ndarray, metric_func, n_iterations: int = 10000, alpha: float = 0.05) -> Tuple[float, float]:
    """
    Calculate bootstrap confidence interval for a metric.

    Args:
        data: Array of ground truth and predictions [(ground_truth, prediction), ...]
        metric_func: Function to calculate metric from confusion matrix
        n_iterations: Number of bootstrap samples
        alpha: Significance level (0.05 for 95% CI)

    Returns:
        Tuple of (lower_bound, upper_bound)
    """
    n = len(data)
    bootstrap_stats = []

    for _ in range(n_iterations):
        # Resample with replacement
        indices = np.random.choice(n, size=n, replace=True)
        sample = data[indices]

        # Calculate metric on this bootstrap sample
        cm = calculate_confusion_matrix_from_samples(sample)
        stat = metric_func(cm)
        bootstrap_stats.append(stat)

    # Percentile method
    lower = np.percentile(bootstrap_stats, alpha/2 * 100)
    upper = np.percentile(bootstrap_stats, (1 - alpha/2) * 100)

    return (lower, upper)


def calculate_confusion_matrix_from_samples(samples: np.ndarray) -> ConfusionMatrix:
    """Calculate confusion matrix from (ground_truth, prediction) pairs"""
    tp = np.sum((samples[:, 0] == 1) & (samples[:, 1] == 1))
    fp = np.sum((samples[:, 0] == 0) & (samples[:, 1] == 1))
    tn = np.sum((samples[:, 0] == 0) & (samples[:, 1] == 0))
    fn = np.sum((samples[:, 0] == 1) & (samples[:, 1] == 0))

    return ConfusionMatrix(tp=int(tp), fp=int(fp), tn=int(tn), fn=int(fn))


# ============================================================================
# STATISTICAL SIGNIFICANCE TESTS
# ============================================================================

def mcnemar_test(tool1_predictions: np.ndarray, tool2_predictions: np.ndarray, ground_truth: np.ndarray) -> Dict:
    """
    McNemar's test for comparing two classifiers on the same dataset.

    Args:
        tool1_predictions: Binary predictions from tool 1
        tool2_predictions: Binary predictions from tool 2
        ground_truth: Ground truth labels

    Returns:
        Dictionary with test results
    """
    # Create contingency table
    # Rows: Tool 1 (correct/incorrect)
    # Cols: Tool 2 (correct/incorrect)
    tool1_correct = (tool1_predictions == ground_truth).astype(int)
    tool2_correct = (tool2_predictions == ground_truth).astype(int)

    # Count disagreements
    n_01 = np.sum((tool1_correct == 0) & (tool2_correct == 1))  # Tool 1 wrong, Tool 2 right
    n_10 = np.sum((tool1_correct == 1) & (tool2_correct == 0))  # Tool 1 right, Tool 2 wrong

    # McNemar's test statistic with continuity correction
    if (n_01 + n_10) == 0:
        statistic = 0.0
        p_value = 1.0
    else:
        statistic = ((abs(n_01 - n_10) - 1) ** 2) / (n_01 + n_10)
        p_value = 1 - stats.chi2.cdf(statistic, df=1)

    return {
        'statistic': float(statistic),
        'p_value': float(p_value),
        'n_01': int(n_01),  # Tool 1 wrong, Tool 2 right
        'n_10': int(n_10),  # Tool 1 right, Tool 2 wrong
        'significant': p_value < 0.05,
        'interpretation': 'Tool 2 significantly better' if p_value < 0.05 and n_01 > n_10 else
                         'Tool 1 significantly better' if p_value < 0.05 and n_10 > n_01 else
                         'No significant difference'
    }


def paired_t_test(metric1: np.ndarray, metric2: np.ndarray) -> Dict:
    """
    Paired t-test for comparing continuous metrics.

    Args:
        metric1: Metric values for tool 1 (e.g., precision per contract)
        metric2: Metric values for tool 2

    Returns:
        Dictionary with test results
    """
    # Check assumptions
    differences = metric2 - metric1

    # Shapiro-Wilk test for normality
    _, p_normality = stats.shapiro(differences) if len(differences) < 5000 else (None, 0.05)

    # Paired t-test
    t_stat, p_value = stats.ttest_rel(metric2, metric1)

    # Effect size (Cohen's d)
    mean_diff = np.mean(differences)
    std_diff = np.std(differences, ddof=1)
    cohens_d = mean_diff / std_diff if std_diff > 0 else 0.0

    # Effect size interpretation
    effect_size_interpretation = (
        'negligible' if abs(cohens_d) < 0.2 else
        'small' if abs(cohens_d) < 0.5 else
        'medium' if abs(cohens_d) < 0.8 else
        'large'
    )

    return {
        't_statistic': float(t_stat),
        'p_value': float(p_value),
        'p_normality': float(p_normality) if p_normality is not None else None,
        'mean_difference': float(mean_diff),
        'cohens_d': float(cohens_d),
        'effect_size': effect_size_interpretation,
        'significant': p_value < 0.05,
        'interpretation': f"Metric2 significantly {'higher' if mean_diff > 0 else 'lower'} than Metric1" if p_value < 0.05 else "No significant difference"
    }


def calculate_cohens_kappa(ground_truth: np.ndarray, predictions: np.ndarray) -> float:
    """
    Calculate Cohen's Kappa for inter-rater reliability.

    Args:
        ground_truth: Ground truth labels
        predictions: Predicted labels

    Returns:
        Cohen's Kappa value
    """
    return cohen_kappa_score(ground_truth, predictions)


# ============================================================================
# MAIN EVALUATION FUNCTION
# ============================================================================

def load_results_data(results_dir: Path) -> Dict:
    """
    Load experimental results from JSON files.

    Expected structure:
    {
        "contracts": [
            {
                "name": "contract1.sol",
                "ground_truth": [1, 0, 1, 0],  # Binary labels
                "slither": [1, 1, 1, 0],
                "mythril": [0, 0, 1, 0],
                "aderyn": [1, 0, 1, 1],
                "miesc": [1, 0, 1, 0],
                "miesc_ai": [1, 0, 1, 0]
            },
            ...
        ]
    }
    """
    results_file = results_dir / 'evaluation_results.json'

    if not results_file.exists():
        print(f"❌ Results file not found: {results_file}")
        print(f"   Please run the benchmark first: make bench")
        sys.exit(1)

    with open(results_file, 'r') as f:
        return json.load(f)


def calculate_metrics_for_tool(tool_name: str, predictions: List, ground_truth: List) -> StatisticalResults:
    """Calculate all metrics for a single tool"""
    # Convert to numpy arrays
    pred_array = np.array(predictions, dtype=int)
    truth_array = np.array(ground_truth, dtype=int)

    # Calculate confusion matrix
    cm = calculate_confusion_matrix_from_samples(np.column_stack([truth_array, pred_array]))

    # Calculate Cohen's Kappa
    kappa = calculate_cohens_kappa(truth_array, pred_array)

    # Prepare data for bootstrap
    data = np.column_stack([truth_array, pred_array])

    # Bootstrap confidence intervals
    precision_ci = bootstrap_ci(data, lambda cm: cm.precision, n_iterations=10000)
    recall_ci = bootstrap_ci(data, lambda cm: cm.recall, n_iterations=10000)
    f1_ci = bootstrap_ci(data, lambda cm: cm.f1_score, n_iterations=10000)

    return StatisticalResults(
        tool_name=tool_name,
        confusion_matrix=cm,
        precision=cm.precision,
        recall=cm.recall,
        f1_score=cm.f1_score,
        fpr=cm.fpr,
        accuracy=cm.accuracy,
        cohen_kappa=kappa,
        precision_ci95=precision_ci,
        recall_ci95=recall_ci,
        f1_ci95=f1_ci,
        sample_size=len(predictions)
    )


def compare_tools(tool1_name: str, tool1_preds: np.ndarray,
                 tool2_name: str, tool2_preds: np.ndarray,
                 ground_truth: np.ndarray) -> Dict:
    """Compare two tools using statistical tests"""
    # McNemar's test for binary predictions
    mcnemar_results = mcnemar_test(tool1_preds, tool2_preds, ground_truth)

    # Calculate precision per contract for paired t-test
    # (This is a simplification - in practice, calculate per-contract metrics)
    tool1_precision_per_contract = []
    tool2_precision_per_contract = []

    # For demonstration, we'll calculate overall precision
    # In a real scenario, you'd calculate per-contract or per-finding
    tool1_cm = calculate_confusion_matrix_from_samples(np.column_stack([ground_truth, tool1_preds]))
    tool2_cm = calculate_confusion_matrix_from_samples(np.column_stack([ground_truth, tool2_preds]))

    # Create arrays for t-test (simulated per-contract precision)
    # In reality, this should be calculated from actual per-contract data
    n_samples = len(ground_truth)
    tool1_precision_array = np.full(n_samples, tool1_cm.precision)
    tool2_precision_array = np.full(n_samples, tool2_cm.precision)

    paired_t_results = paired_t_test(tool1_precision_array, tool2_precision_array)

    return {
        'comparison': f"{tool1_name} vs {tool2_name}",
        'mcnemar_test': mcnemar_results,
        'paired_t_test': paired_t_results
    }


def generate_results_table(results: Dict[str, StatisticalResults]) -> pd.DataFrame:
    """Generate a formatted results table"""
    data = []
    for tool_name, stats in results.items():
        data.append({
            'Tool': tool_name,
            'Precision': f"{stats.precision:.4f}",
            'Precision CI95': f"[{stats.precision_ci95[0]:.4f}, {stats.precision_ci95[1]:.4f}]",
            'Recall': f"{stats.recall:.4f}",
            'Recall CI95': f"[{stats.recall_ci95[0]:.4f}, {stats.recall_ci95[1]:.4f}]",
            'F1 Score': f"{stats.f1_score:.4f}",
            'F1 CI95': f"[{stats.f1_ci95[0]:.4f}, {stats.f1_ci95[1]:.4f}]",
            'FPR': f"{stats.fpr:.4f}",
            'Accuracy': f"{stats.accuracy:.4f}",
            "Cohen's κ": f"{stats.cohen_kappa:.4f}",
            'Sample Size': stats.sample_size
        })

    return pd.DataFrame(data)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='MIESC Evaluation Statistics')
    parser.add_argument('--input', type=str, default='analysis/results/',
                       help='Input directory with evaluation results')
    parser.add_argument('--output', type=str, default='analysis/results/stats.json',
                       help='Output JSON file for statistics')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    input_dir = Path(args.input)
    output_file = Path(args.output)

    print("=" * 70)
    print("MIESC Evaluation Statistics")
    print("=" * 70)
    print(f"📁 Input directory: {input_dir}")
    print(f"💾 Output file: {output_file}")
    print()

    # Load results
    print("📊 Loading evaluation results...")
    data = load_results_data(input_dir)

    # Extract predictions and ground truth
    # This is a simplified structure - adapt based on actual data format
    contracts = data.get('contracts', [])

    if not contracts:
        print("❌ No contract data found in results")
        sys.exit(1)

    # Aggregate predictions across all contracts
    tools = ['slither', 'mythril', 'aderyn', 'miesc', 'miesc_ai']
    all_predictions = {tool: [] for tool in tools}
    all_ground_truth = []

    for contract in contracts:
        ground_truth = contract.get('ground_truth', [])
        all_ground_truth.extend(ground_truth)

        for tool in tools:
            predictions = contract.get(tool, [])
            all_predictions[tool].extend(predictions)

    # Calculate metrics for each tool
    print("\n📈 Calculating metrics for each tool...")
    results = {}

    for tool in tools:
        print(f"   • {tool}")
        results[tool] = calculate_metrics_for_tool(
            tool,
            all_predictions[tool],
            all_ground_truth
        )

    # Generate results table
    print("\n📋 Results Summary:")
    results_table = generate_results_table(results)
    print(results_table.to_string(index=False))

    # Perform pairwise comparisons
    print("\n🔬 Statistical Comparisons:")

    comparisons = []

    # Compare MIESC+AI vs each baseline
    baseline_tools = ['slither', 'mythril', 'aderyn', 'miesc']
    ground_truth_array = np.array(all_ground_truth, dtype=int)
    miesc_ai_preds = np.array(all_predictions['miesc_ai'], dtype=int)

    for baseline_tool in baseline_tools:
        baseline_preds = np.array(all_predictions[baseline_tool], dtype=int)
        comparison = compare_tools(
            baseline_tool, baseline_preds,
            'miesc_ai', miesc_ai_preds,
            ground_truth_array
        )
        comparisons.append(comparison)

        print(f"\n   {comparison['comparison']}:")
        print(f"      McNemar p-value: {comparison['mcnemar_test']['p_value']:.4f} "
              f"({'significant' if comparison['mcnemar_test']['significant'] else 'not significant'})")
        print(f"      Interpretation: {comparison['mcnemar_test']['interpretation']}")

    # Save results to JSON
    print(f"\n💾 Saving results to {output_file}...")
    output_file.parent.mkdir(parents=True, exist_ok=True)

    output_data = {
        'tools': {tool: asdict(stats) for tool, stats in results.items()},
        'comparisons': comparisons,
        'summary': {
            'best_precision': max(results.items(), key=lambda x: x[1].precision)[0],
            'best_recall': max(results.items(), key=lambda x: x[1].recall)[0],
            'best_f1': max(results.items(), key=lambda x: x[1].f1_score)[0],
        }
    }

    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2, default=str)

    print(f"✅ Statistics saved successfully!")
    print(f"\n📊 Summary:")
    print(f"   Best Precision: {output_data['summary']['best_precision']}")
    print(f"   Best Recall: {output_data['summary']['best_recall']}")
    print(f"   Best F1 Score: {output_data['summary']['best_f1']}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
