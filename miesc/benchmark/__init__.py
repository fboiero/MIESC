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
    BenchmarkResult,
    BenchmarkRunner,
    ContractResult,
    DetectionMetrics,
    run_benchmark,
)
from .dataset_loader import (
    DatasetLoader,
    GroundTruth,
    VulnerableContract,
    load_dvd,
    load_smartbugs,
)
from .metrics_calculator import (
    ConfusionMatrix,
    MetricsCalculator,
    calculate_metrics,
    compare_runs,
)
from .pattern_benchmark import (
    PatternBenchmarkResult,
    PatternBenchmarkRunner,
    PatternMatch,
    run_pattern_benchmark,
)
from .slither_benchmark import (
    SlitherBenchmarkRunner,
    run_slither_benchmark,
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
    # Slither Direct
    "SlitherBenchmarkRunner",
    "run_slither_benchmark",
    # Pattern Direct
    "PatternBenchmarkRunner",
    "PatternBenchmarkResult",
    "PatternMatch",
    "run_pattern_benchmark",
]
