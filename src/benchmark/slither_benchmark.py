"""
Direct Slither Benchmark
========================

Lightweight benchmark using Slither directly for faster iteration.
This bypasses the full MIESC CLI for faster benchmarking.
"""

import json
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from .dataset_loader import VulnerableContract, VulnerabilityCategory, GroundTruth
from .benchmark_runner import BenchmarkResult, ContractResult, DetectionMetrics


class SlitherBenchmarkRunner:
    """
    Fast benchmark using Slither directly.

    Much faster than full MIESC CLI - useful for quick iteration.
    """

    # Slither detector -> category mapping
    DETECTOR_MAP = {
        # Reentrancy
        "reentrancy-eth": "reentrancy",
        "reentrancy-no-eth": "reentrancy",
        "reentrancy-benign": "reentrancy",
        "reentrancy-unlimited-gas": "reentrancy",
        "reentrancy-events": "reentrancy",
        # Access control
        "arbitrary-send-eth": "access_control",
        "arbitrary-send-erc20": "access_control",
        "arbitrary-send-erc20-permit": "access_control",
        "suicidal": "access_control",
        "unprotected-upgrade": "access_control",
        "protected-vars": "access_control",
        "tx-origin": "access_control",
        # Arithmetic (pre-0.8)
        "divide-before-multiply": "arithmetic",
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
        # Timestamp
        "timestamp": "time_manipulation",
        "block-timestamp": "time_manipulation",
    }

    def __init__(self, timeout: int = 60, line_tolerance: int = 10):
        self.timeout = timeout
        self.line_tolerance = line_tolerance

    def run(
        self,
        contracts: List[VulnerableContract],
        parallel: bool = True,
        max_workers: int = 8,
        verbose: bool = True,
    ) -> BenchmarkResult:
        """Run Slither-only benchmark."""
        start_time = time.time()
        results = []

        if parallel:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._analyze_with_slither, c): c
                    for c in contracts
                }
                for i, future in enumerate(as_completed(futures)):
                    contract = futures[future]
                    try:
                        result = future.result()
                        results.append(result)
                        if verbose:
                            status = "OK" if not result.error else f"ERR"
                            tp = len(result.true_positives)
                            fp = len(result.false_positives)
                            fn = len(result.false_negatives)
                            print(f"[{i+1}/{len(contracts)}] {contract.name}: {status} TP={tp} FP={fp} FN={fn}")
                    except Exception as e:
                        results.append(ContractResult(
                            contract_name=contract.name,
                            contract_path=contract.path,
                            ground_truth=contract.vulnerabilities,
                            detected_findings=[],
                            error=str(e),
                        ))
        else:
            for i, contract in enumerate(contracts):
                result = self._analyze_with_slither(contract)
                results.append(result)
                if verbose:
                    status = "OK" if not result.error else "ERR"
                    print(f"[{i+1}/{len(contracts)}] {contract.name}: {status}")

        total_time = time.time() - start_time
        return self._calculate_results(contracts, results, total_time)

    def _analyze_with_slither(self, contract: VulnerableContract) -> ContractResult:
        """Analyze single contract with Slither."""
        start_time = time.time()

        try:
            # Run Slither with JSON output
            cmd = [
                "slither",
                contract.path,
                "--json", "-",
                "--exclude-informational",
                "--exclude-optimization",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Parse JSON output (Slither outputs to stderr for JSON)
            findings = []
            try:
                output = result.stdout or result.stderr
                if output.strip():
                    # Slither might output multiple JSON objects, take the last one
                    lines = output.strip().split('\n')
                    for line in reversed(lines):
                        if line.startswith('{'):
                            data = json.loads(line)
                            if 'results' in data:
                                for detector in data.get('results', {}).get('detectors', []):
                                    finding = self._parse_slither_finding(detector, contract.path)
                                    if finding:
                                        findings.append(finding)
                            break
            except json.JSONDecodeError:
                pass

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

    def _parse_slither_finding(self, detector: Dict, contract_path: str) -> Optional[Dict]:
        """Parse a Slither detector result."""
        check = detector.get('check', '')

        # Get line numbers from elements
        lines = []
        for elem in detector.get('elements', []):
            if 'source_mapping' in elem:
                sm = elem['source_mapping']
                if sm.get('lines'):
                    lines.extend(sm['lines'])

        # Filter to only findings in the target contract
        target_name = Path(contract_path).stem.lower()
        relevant = False
        for elem in detector.get('elements', []):
            if 'source_mapping' in elem:
                filename = elem['source_mapping'].get('filename_relative', '')
                if target_name in filename.lower():
                    relevant = True
                    break

        if not relevant:
            return None

        return {
            'type': check,
            'severity': detector.get('impact', 'Medium'),
            'confidence': detector.get('confidence', 'Medium'),
            'lines': lines,
            'location': {
                'file': contract_path,
                'line': lines[0] if lines else 0,
            },
            'description': detector.get('description', ''),
        }

    def _match_findings(
        self,
        ground_truth: List[GroundTruth],
        findings: List[Dict],
    ) -> Tuple[List[Dict], List[Dict], List[GroundTruth]]:
        """Match findings to ground truth."""
        true_positives = []
        false_positives = []
        matched_gt = set()

        for finding in findings:
            finding_type = finding.get('type', '').lower()
            finding_lines = finding.get('lines', [finding.get('location', {}).get('line', 0)])
            if not isinstance(finding_lines, list):
                finding_lines = [finding_lines]

            mapped_category = self.DETECTOR_MAP.get(finding_type, 'other')

            matched = False
            for i, gt in enumerate(ground_truth):
                if i in matched_gt:
                    continue

                gt_cat = gt.category.value
                if mapped_category == gt_cat or self._cats_related(mapped_category, gt_cat):
                    if gt.overlaps_with(finding_lines, tolerance=self.line_tolerance):
                        true_positives.append(finding)
                        matched_gt.add(i)
                        matched = True
                        break

            if not matched:
                false_positives.append(finding)

        false_negatives = [gt for i, gt in enumerate(ground_truth) if i not in matched_gt]
        return true_positives, false_positives, false_negatives

    def _cats_related(self, c1: str, c2: str) -> bool:
        """Check if categories are related."""
        groups = [
            {"reentrancy", "unchecked_low_level_calls"},
            {"access_control"},
            {"bad_randomness", "time_manipulation"},
        ]
        for g in groups:
            if c1 in g and c2 in g:
                return True
        return False

    def _calculate_results(
        self,
        contracts: List[VulnerableContract],
        results: List[ContractResult],
        total_time: float,
    ) -> BenchmarkResult:
        """Calculate aggregate metrics."""
        metrics_by_cat: Dict[str, DetectionMetrics] = {}
        overall = DetectionMetrics(category="overall")

        for result in results:
            overall.true_positives += len(result.true_positives)
            overall.false_positives += len(result.false_positives)
            overall.false_negatives += len(result.false_negatives)

            for tp in result.true_positives:
                cat = self.DETECTOR_MAP.get(tp.get('type', '').lower(), 'other')
                if cat not in metrics_by_cat:
                    metrics_by_cat[cat] = DetectionMetrics(category=cat)
                metrics_by_cat[cat].true_positives += 1

            for fp in result.false_positives:
                cat = self.DETECTOR_MAP.get(fp.get('type', '').lower(), 'other')
                if cat not in metrics_by_cat:
                    metrics_by_cat[cat] = DetectionMetrics(category=cat)
                metrics_by_cat[cat].false_positives += 1

            for fn in result.false_negatives:
                cat = fn.category.value
                if cat not in metrics_by_cat:
                    metrics_by_cat[cat] = DetectionMetrics(category=cat)
                metrics_by_cat[cat].false_negatives += 1

        analyzed = sum(1 for r in results if not r.error)

        return BenchmarkResult(
            timestamp=datetime.now(),
            total_contracts=len(contracts),
            analyzed_contracts=analyzed,
            failed_contracts=len(results) - analyzed,
            total_ground_truth=sum(len(c.vulnerabilities) for c in contracts),
            total_detected=sum(len(r.detected_findings) for r in results),
            contract_results=results,
            metrics_by_category=metrics_by_cat,
            overall_metrics=overall,
            total_time_seconds=total_time,
            miesc_version="slither-only",
        )


def run_slither_benchmark(
    contracts: List[VulnerableContract],
    parallel: bool = True,
    verbose: bool = True,
) -> BenchmarkResult:
    """Convenience function."""
    runner = SlitherBenchmarkRunner()
    return runner.run(contracts, parallel=parallel, verbose=verbose)
