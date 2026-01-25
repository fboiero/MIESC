"""
Benchmark Runner for MIESC
==========================

Runs MIESC analysis against known vulnerable contracts and
measures detection accuracy.

Usage:
    from src.benchmark import BenchmarkRunner, load_smartbugs

    runner = BenchmarkRunner()
    contracts = load_smartbugs()
    results = runner.run(contracts)
    print(results.summary())
"""

import asyncio
import json
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from .dataset_loader import VulnerableContract, VulnerabilityCategory, GroundTruth


@dataclass
class DetectionMetrics:
    """Metrics for a single category."""

    category: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0

    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP)"""
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN)"""
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def f1_score(self) -> float:
        """F1 = 2 * (precision * recall) / (precision + recall)"""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        """Accuracy = (TP + TN) / (TP + TN + FP + FN)"""
        total = self.true_positives + self.true_negatives + self.false_positives + self.false_negatives
        return (self.true_positives + self.true_negatives) / total if total > 0 else 0.0

    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
        }


@dataclass
class ContractResult:
    """Result of analyzing a single contract."""

    contract_name: str
    contract_path: str
    ground_truth: List[GroundTruth]
    detected_findings: List[Dict]
    true_positives: List[Dict] = field(default_factory=list)
    false_positives: List[Dict] = field(default_factory=list)
    false_negatives: List[GroundTruth] = field(default_factory=list)
    analysis_time_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "contract_name": self.contract_name,
            "ground_truth_count": len(self.ground_truth),
            "detected_count": len(self.detected_findings),
            "true_positives": len(self.true_positives),
            "false_positives": len(self.false_positives),
            "false_negatives": len(self.false_negatives),
            "analysis_time_ms": round(self.analysis_time_ms, 2),
            "error": self.error,
        }


@dataclass
class BenchmarkResult:
    """Complete benchmark result."""

    timestamp: datetime
    total_contracts: int
    analyzed_contracts: int
    failed_contracts: int
    total_ground_truth: int
    total_detected: int
    contract_results: List[ContractResult]
    metrics_by_category: Dict[str, DetectionMetrics]
    overall_metrics: DetectionMetrics
    total_time_seconds: float
    miesc_version: str = "4.3.0"
    config: Dict = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        """Percentage of contracts successfully analyzed."""
        return self.analyzed_contracts / self.total_contracts if self.total_contracts > 0 else 0.0

    def summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            "=" * 60,
            "MIESC BENCHMARK RESULTS",
            "=" * 60,
            f"Timestamp: {self.timestamp.isoformat()}",
            f"MIESC Version: {self.miesc_version}",
            "",
            "DATASET SUMMARY",
            "-" * 40,
            f"Total Contracts: {self.total_contracts}",
            f"Analyzed: {self.analyzed_contracts} ({self.success_rate*100:.1f}%)",
            f"Failed: {self.failed_contracts}",
            f"Ground Truth Vulns: {self.total_ground_truth}",
            f"Detected Findings: {self.total_detected}",
            "",
            "OVERALL METRICS",
            "-" * 40,
            f"Precision: {self.overall_metrics.precision*100:.2f}%",
            f"Recall: {self.overall_metrics.recall*100:.2f}%",
            f"F1 Score: {self.overall_metrics.f1_score*100:.2f}%",
            f"True Positives: {self.overall_metrics.true_positives}",
            f"False Positives: {self.overall_metrics.false_positives}",
            f"False Negatives: {self.overall_metrics.false_negatives}",
            "",
            "METRICS BY CATEGORY",
            "-" * 40,
        ]

        for cat, metrics in sorted(self.metrics_by_category.items()):
            if metrics.true_positives + metrics.false_negatives > 0:
                lines.append(
                    f"  {cat:30} P:{metrics.precision*100:5.1f}% "
                    f"R:{metrics.recall*100:5.1f}% F1:{metrics.f1_score*100:5.1f}%"
                )

        lines.extend([
            "",
            f"Total Time: {self.total_time_seconds:.2f}s",
            f"Avg Time/Contract: {self.total_time_seconds/max(self.analyzed_contracts,1)*1000:.0f}ms",
            "=" * 60,
        ])

        return "\n".join(lines)

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "miesc_version": self.miesc_version,
            "summary": {
                "total_contracts": self.total_contracts,
                "analyzed_contracts": self.analyzed_contracts,
                "failed_contracts": self.failed_contracts,
                "success_rate": round(self.success_rate, 4),
                "total_ground_truth": self.total_ground_truth,
                "total_detected": self.total_detected,
            },
            "overall_metrics": self.overall_metrics.to_dict(),
            "metrics_by_category": {k: v.to_dict() for k, v in self.metrics_by_category.items()},
            "total_time_seconds": round(self.total_time_seconds, 2),
            "contract_results": [r.to_dict() for r in self.contract_results],
        }

    def save(self, path: Path):
        """Save results to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


class BenchmarkRunner:
    """
    Runs MIESC analysis against benchmark datasets.

    Usage:
        runner = BenchmarkRunner()
        contracts = load_smartbugs()
        results = runner.run(contracts, parallel=True)
    """

    # Map MIESC finding types to benchmark categories
    TYPE_MAPPING = {
        # Reentrancy
        "reentrancy": "reentrancy",
        "reentrancy-eth": "reentrancy",
        "reentrancy-no-eth": "reentrancy",
        "reentrancy-benign": "reentrancy",
        "reentrancy-unlimited-gas": "reentrancy",
        # Access Control
        "unprotected-upgrade": "access_control",
        "suicidal": "access_control",
        "arbitrary-send-eth": "access_control",
        "arbitrary-send-erc20": "access_control",
        "protected-vars": "access_control",
        "tx-origin": "access_control",
        "missing-access-control": "access_control",
        # Arithmetic
        "integer-overflow": "arithmetic",
        "integer-underflow": "arithmetic",
        "divide-before-multiply": "arithmetic",
        "unchecked-arithmetic": "arithmetic",
        # Unchecked calls
        "unchecked-lowlevel": "unchecked_low_level_calls",
        "unchecked-send": "unchecked_low_level_calls",
        "unchecked-transfer": "unchecked_low_level_calls",
        "low-level-calls": "unchecked_low_level_calls",
        # DoS
        "locked-ether": "denial_of_service",
        "costly-loop": "denial_of_service",
        "calls-loop": "denial_of_service",
        # Randomness
        "weak-prng": "bad_randomness",
        "block-timestamp": "bad_randomness",
        # Timestamp
        "timestamp": "time_manipulation",
        "block-timestamp": "time_manipulation",
        # DeFi specific
        "oracle-manipulation": "oracle_manipulation",
        "flash-loan": "flash_loan",
        "price-manipulation": "price_manipulation",
        "governance-attack": "governance",
    }

    def __init__(
        self,
        miesc_path: Optional[str] = None,
        timeout: int = 120,
        line_tolerance: int = 10,
    ):
        """
        Initialize benchmark runner.

        Args:
            miesc_path: Path to miesc CLI (default: uses 'miesc' from PATH)
            timeout: Analysis timeout per contract in seconds
            line_tolerance: Line number tolerance for matching detections
        """
        self.miesc_path = miesc_path or "miesc"
        self.timeout = timeout
        self.line_tolerance = line_tolerance

    def run(
        self,
        contracts: List[VulnerableContract],
        parallel: bool = True,
        max_workers: int = 4,
        mode: str = "smart",
        verbose: bool = False,
    ) -> BenchmarkResult:
        """
        Run benchmark on contracts.

        Args:
            contracts: List of vulnerable contracts to test
            parallel: Run analyses in parallel
            max_workers: Number of parallel workers
            mode: MIESC mode ('smart', 'full', 'quick')
            verbose: Print progress

        Returns:
            BenchmarkResult with all metrics
        """
        start_time = time.time()
        contract_results = []

        if parallel:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._analyze_contract, c, mode): c
                    for c in contracts
                }

                for i, future in enumerate(as_completed(futures)):
                    contract = futures[future]
                    try:
                        result = future.result()
                        contract_results.append(result)
                        if verbose:
                            status = "OK" if not result.error else f"ERR: {result.error[:30]}"
                            print(f"[{i+1}/{len(contracts)}] {contract.name}: {status}")
                    except Exception as e:
                        contract_results.append(ContractResult(
                            contract_name=contract.name,
                            contract_path=contract.path,
                            ground_truth=contract.vulnerabilities,
                            detected_findings=[],
                            error=str(e),
                        ))
        else:
            for i, contract in enumerate(contracts):
                result = self._analyze_contract(contract, mode)
                contract_results.append(result)
                if verbose:
                    status = "OK" if not result.error else f"ERR: {result.error[:30]}"
                    print(f"[{i+1}/{len(contracts)}] {contract.name}: {status}")

        total_time = time.time() - start_time

        # Calculate metrics
        return self._calculate_results(contracts, contract_results, total_time, mode)

    def _analyze_contract(self, contract: VulnerableContract, mode: str) -> ContractResult:
        """Analyze a single contract."""
        start_time = time.time()

        try:
            # Run MIESC analysis
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                output_path = tmp.name

            cmd = [
                self.miesc_path,
                "audit", mode,
                contract.path,
                "--output", output_path,
                "--format", "json",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Parse output
            findings = []
            if Path(output_path).exists():
                with open(output_path, "r") as f:
                    data = json.load(f)
                    findings = data.get("findings", data.get("vulnerabilities", []))

            analysis_time = (time.time() - start_time) * 1000

            # Match findings to ground truth
            tp, fp, fn = self._match_findings(contract.vulnerabilities, findings)

            return ContractResult(
                contract_name=contract.name,
                contract_path=contract.path,
                ground_truth=contract.vulnerabilities,
                detected_findings=findings,
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                analysis_time_ms=analysis_time,
            )

        except subprocess.TimeoutExpired:
            return ContractResult(
                contract_name=contract.name,
                contract_path=contract.path,
                ground_truth=contract.vulnerabilities,
                detected_findings=[],
                error="timeout",
                analysis_time_ms=(time.time() - start_time) * 1000,
            )
        except Exception as e:
            return ContractResult(
                contract_name=contract.name,
                contract_path=contract.path,
                ground_truth=contract.vulnerabilities,
                detected_findings=[],
                error=str(e),
                analysis_time_ms=(time.time() - start_time) * 1000,
            )

    def _match_findings(
        self,
        ground_truth: List[GroundTruth],
        findings: List[Dict],
    ) -> Tuple[List[Dict], List[Dict], List[GroundTruth]]:
        """
        Match detected findings to ground truth.

        Returns:
            (true_positives, false_positives, false_negatives)
        """
        true_positives = []
        false_positives = []
        matched_gt = set()

        for finding in findings:
            # Get finding details
            finding_type = finding.get("type", finding.get("check", "")).lower()
            finding_lines = self._extract_lines(finding)
            mapped_category = self.TYPE_MAPPING.get(finding_type, "other")

            # Try to match with ground truth
            matched = False
            for i, gt in enumerate(ground_truth):
                if i in matched_gt:
                    continue

                # Check category match (relaxed)
                gt_cat = gt.category.value
                if mapped_category == gt_cat or self._categories_related(mapped_category, gt_cat):
                    # Check line overlap
                    if gt.overlaps_with(finding_lines, tolerance=self.line_tolerance):
                        true_positives.append(finding)
                        matched_gt.add(i)
                        matched = True
                        break

            if not matched:
                false_positives.append(finding)

        # False negatives = unmatched ground truth
        false_negatives = [
            gt for i, gt in enumerate(ground_truth)
            if i not in matched_gt
        ]

        return true_positives, false_positives, false_negatives

    def _extract_lines(self, finding: Dict) -> List[int]:
        """Extract line numbers from a finding."""
        lines = []

        # Try different formats
        if "line" in finding:
            lines.append(int(finding["line"]))
        if "lines" in finding:
            lines.extend([int(l) for l in finding["lines"]])
        if "location" in finding:
            loc = finding["location"]
            if isinstance(loc, dict):
                if "line" in loc:
                    lines.append(int(loc["line"]))
                if "start_line" in loc:
                    lines.append(int(loc["start_line"]))
            elif isinstance(loc, str) and ":" in loc:
                try:
                    lines.append(int(loc.split(":")[-1]))
                except ValueError:
                    pass

        return lines or [0]

    def _categories_related(self, cat1: str, cat2: str) -> bool:
        """Check if two categories are related."""
        related_groups = [
            {"reentrancy", "unchecked_low_level_calls"},
            {"access_control", "tx-origin"},
            {"bad_randomness", "time_manipulation"},
            {"oracle_manipulation", "price_manipulation", "flash_loan"},
        ]

        for group in related_groups:
            if cat1 in group and cat2 in group:
                return True
        return False

    def _calculate_results(
        self,
        contracts: List[VulnerableContract],
        results: List[ContractResult],
        total_time: float,
        mode: str,
    ) -> BenchmarkResult:
        """Calculate aggregate metrics from results."""

        # Initialize metrics by category
        metrics_by_cat: Dict[str, DetectionMetrics] = {}
        overall = DetectionMetrics(category="overall")

        for result in results:
            # Update overall
            overall.true_positives += len(result.true_positives)
            overall.false_positives += len(result.false_positives)
            overall.false_negatives += len(result.false_negatives)

            # Update by category
            for tp in result.true_positives:
                cat = self.TYPE_MAPPING.get(
                    tp.get("type", tp.get("check", "")).lower(),
                    "other"
                )
                if cat not in metrics_by_cat:
                    metrics_by_cat[cat] = DetectionMetrics(category=cat)
                metrics_by_cat[cat].true_positives += 1

            for fp in result.false_positives:
                cat = self.TYPE_MAPPING.get(
                    fp.get("type", fp.get("check", "")).lower(),
                    "other"
                )
                if cat not in metrics_by_cat:
                    metrics_by_cat[cat] = DetectionMetrics(category=cat)
                metrics_by_cat[cat].false_positives += 1

            for fn in result.false_negatives:
                cat = fn.category.value
                if cat not in metrics_by_cat:
                    metrics_by_cat[cat] = DetectionMetrics(category=cat)
                metrics_by_cat[cat].false_negatives += 1

        analyzed = sum(1 for r in results if not r.error)
        failed = sum(1 for r in results if r.error)

        return BenchmarkResult(
            timestamp=datetime.now(),
            total_contracts=len(contracts),
            analyzed_contracts=analyzed,
            failed_contracts=failed,
            total_ground_truth=sum(len(c.vulnerabilities) for c in contracts),
            total_detected=sum(len(r.detected_findings) for r in results),
            contract_results=results,
            metrics_by_category=metrics_by_cat,
            overall_metrics=overall,
            total_time_seconds=total_time,
            config={"mode": mode, "timeout": self.timeout},
        )


def run_benchmark(
    contracts: List[VulnerableContract],
    mode: str = "smart",
    parallel: bool = True,
    verbose: bool = True,
) -> BenchmarkResult:
    """Convenience function to run benchmark."""
    runner = BenchmarkRunner()
    return runner.run(contracts, parallel=parallel, mode=mode, verbose=verbose)
