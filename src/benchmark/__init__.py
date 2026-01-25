"""
MIESC Benchmark Framework
=========================

Framework for evaluating MIESC detection accuracy against known vulnerability datasets.

Supported Datasets:
- SmartBugs Curated (143 contracts, 10 categories)
- Damn Vulnerable DeFi (18 challenges)
- SWC Registry Test Cases

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

from .benchmark_runner import (
    BenchmarkRunner,
    BenchmarkResult,
    ContractResult,
    DetectionMetrics,
    run_benchmark,
)

from .dataset_loader import (
    DatasetLoader,
    VulnerableContract,
    GroundTruth,
    load_smartbugs,
    load_dvd,
)

from .metrics_calculator import (
    MetricsCalculator,
    ConfusionMatrix,
    calculate_metrics,
    compare_runs,
)

__all__ = [
    # Runner
    "BenchmarkRunner",
    "BenchmarkResult",
    "ContractResult",
    "DetectionMetrics",
    "run_benchmark",
    # Loader
    "DatasetLoader",
    "VulnerableContract",
    "GroundTruth",
    "load_smartbugs",
    "load_dvd",
    # Metrics
    "MetricsCalculator",
    "ConfusionMatrix",
    "calculate_metrics",
    "compare_runs",
]
