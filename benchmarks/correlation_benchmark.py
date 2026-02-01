#!/usr/bin/env python3
"""
MIESC Correlation Engine A/B Benchmark
Compara precisión/recall con y sin motor de correlación.

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from detectors.smartbugs_detectors import SmartBugsDetectorEngine  # noqa: E402
from ml.correlation_engine import SmartCorrelationEngine  # noqa: E402

# Configuration
DATASET_PATH = PROJECT_ROOT / "benchmarks" / "datasets" / "smartbugs-curated" / "dataset"
RESULTS_PATH = PROJECT_ROOT / "benchmarks" / "results"

# Category mappings
SMARTBUGS_CATEGORIES = {
    "access_control": ["SWC-105", "SWC-106"],
    "arithmetic": ["SWC-101"],
    "bad_randomness": ["SWC-120"],
    "denial_of_service": ["SWC-113", "SWC-128"],
    "front_running": ["SWC-114"],
    "other": [],
    "reentrancy": ["SWC-107"],
    "short_addresses": ["SWC-129"],
    "time_manipulation": ["SWC-116"],
    "unchecked_low_level_calls": ["SWC-104"],
}

TYPE_TO_CATEGORY = {
    # Reentrancy
    "reentrancy": "reentrancy",
    "reentrancy-eth": "reentrancy",
    "state-variable-written-after-external-call": "reentrancy",
    # Arithmetic
    "arithmetic": "arithmetic",
    "overflow": "arithmetic",
    "underflow": "arithmetic",
    # Access Control
    "access-control": "access_control",
    "unprotected-upgrade": "access_control",
    "arbitrary-send": "access_control",
    "arbitrary-send-eth": "access_control",
    "tx-origin": "access_control",
    "missing-authorization": "access_control",
    # Bad Randomness
    "bad-randomness": "bad_randomness",
    "bad_randomness": "bad_randomness",
    "weak-prng": "bad_randomness",
    # DoS
    "dos": "denial_of_service",
    "denial-of-service": "denial_of_service",
    "denial_of_service": "denial_of_service",
    # Front Running
    "front-running": "front_running",
    "front_running": "front_running",
    "frontrunning": "front_running",
    # Unchecked calls
    "unchecked-call": "unchecked_low_level_calls",
    "unchecked-lowlevel": "unchecked_low_level_calls",
    "unchecked-low-level-calls": "unchecked_low_level_calls",
    # Time
    "time-manipulation": "time_manipulation",
    "timestamp": "time_manipulation",
    # Short addresses
    "short-addresses": "short_addresses",
    "short_addresses": "short_addresses",
}


def load_contracts() -> List[Dict[str, Any]]:
    """Load SmartBugs contracts with ground truth."""
    contracts = []

    for category in SMARTBUGS_CATEGORIES.keys():
        category_path = DATASET_PATH / category
        if not category_path.exists():
            continue

        for sol_file in category_path.glob("*.sol"):
            contracts.append(
                {
                    "path": sol_file,
                    "name": sol_file.stem,
                    "category": category,
                    "expected_swcs": SMARTBUGS_CATEGORIES[category],
                }
            )

    return contracts


def run_smartbugs_detector(contract_path: Path) -> List[Dict[str, Any]]:
    """Run SmartBugs detector on a contract."""
    try:
        engine = SmartBugsDetectorEngine()
        findings = engine.analyze_file(contract_path)
        return [
            {
                "type": f.category,
                "severity": f.severity.value,
                "message": f.description,
                "location": {
                    "file": str(contract_path),
                    "line": f.line,
                    "snippet": f.code_snippet,
                },
                "swc_id": f.swc_id,
                "confidence": f.confidence,
                "tool": "smartbugs-detector",
            }
            for f in findings
        ]
    except Exception:
        return []


def run_aderyn(contract_path: Path) -> List[Dict[str, Any]]:
    """Run Aderyn on a contract."""
    try:
        result = subprocess.run(
            ["aderyn", str(contract_path), "--output", "stdout", "-q"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout:
            try:
                data = json.loads(result.stdout)
                findings = []
                for d in data.get("high_issues", {}).get("issues", []):
                    findings.append(
                        {
                            "type": d.get("title", ""),
                            "severity": "high",
                            "message": d.get("description", ""),
                            "location": {"file": str(contract_path), "line": 0},
                            "confidence": 0.8,
                            "tool": "aderyn",
                        }
                    )
                for d in data.get("medium_issues", {}).get("issues", []):
                    findings.append(
                        {
                            "type": d.get("title", ""),
                            "severity": "medium",
                            "message": d.get("description", ""),
                            "location": {"file": str(contract_path), "line": 0},
                            "confidence": 0.7,
                            "tool": "aderyn",
                        }
                    )
                return findings
            except json.JSONDecodeError:
                pass
    except Exception:
        pass
    return []


def map_to_category(finding: Dict[str, Any]) -> str:
    """Map a finding to SmartBugs category."""
    finding_type = finding.get("type", "").lower().replace(" ", "-").replace("_", "-")

    # Direct type mapping
    if finding_type in TYPE_TO_CATEGORY:
        return TYPE_TO_CATEGORY[finding_type]

    # Partial match
    for key, cat in TYPE_TO_CATEGORY.items():
        if key in finding_type or finding_type in key:
            return cat

    # SWC mapping
    swc = finding.get("swc_id", "")
    for cat, swcs in SMARTBUGS_CATEGORIES.items():
        if swc in swcs:
            return cat

    return "unknown"


def evaluate_findings(
    findings: List[Dict[str, Any]],
    expected_category: str,
) -> Tuple[bool, int, int]:
    """
    Evaluate if findings detect the expected vulnerability.

    Returns:
        (detected, true_positives, false_positives)
    """
    detected = False
    true_positives = 0
    false_positives = 0

    for f in findings:
        mapped_cat = map_to_category(f)
        if mapped_cat == expected_category:
            detected = True
            true_positives += 1
        else:
            false_positives += 1

    return detected, true_positives, false_positives


def run_benchmark():
    """Run A/B comparison benchmark."""
    print("\n" + "=" * 70)
    print("  MIESC Correlation Engine A/B Benchmark")
    print("=" * 70)

    contracts = load_contracts()
    print(f"\nDataset: {DATASET_PATH}")
    print(f"Contracts: {len(contracts)}")

    # Results storage
    baseline_results = defaultdict(lambda: {"detected": 0, "tp": 0, "fp": 0, "total": 0})
    correlated_results = defaultdict(lambda: {"detected": 0, "tp": 0, "fp": 0, "total": 0})

    total_baseline_findings = 0
    total_correlated_findings = 0
    total_filtered_fp = 0

    print("\nRunning evaluation...")

    for i, contract in enumerate(contracts):
        if (i + 1) % 20 == 0:
            print(f"  Progress: {i+1}/{len(contracts)}")

        contract_path = contract["path"]
        category = contract["category"]

        # Run all tools
        all_findings = []

        # SmartBugs detector
        sb_findings = run_smartbugs_detector(contract_path)
        all_findings.extend(sb_findings)

        # Aderyn (if available)
        aderyn_findings = run_aderyn(contract_path)
        all_findings.extend(aderyn_findings)

        # BASELINE: Evaluate without correlation
        baseline_detected, baseline_tp, baseline_fp = evaluate_findings(all_findings, category)

        baseline_results[category]["total"] += 1
        if baseline_detected:
            baseline_results[category]["detected"] += 1
        baseline_results[category]["tp"] += baseline_tp
        baseline_results[category]["fp"] += baseline_fp
        total_baseline_findings += len(all_findings)

        # WITH CORRELATION: Apply correlation engine
        if all_findings:
            engine = SmartCorrelationEngine(
                min_tools_for_validation=1,
                similarity_threshold=0.75,
            )

            # Add findings by tool
            for f in all_findings:
                tool = f.get("tool", "unknown")
                engine.add_findings(tool, [f])

            correlated = engine.correlate()

            # Filter by confidence and FP probability - optimized thresholds
            filtered = [
                f
                for f in correlated
                if f.final_confidence >= 0.30 and f.false_positive_probability <= 0.75
            ]

            filtered_as_fp = len(correlated) - len(filtered)
            total_filtered_fp += filtered_as_fp
            total_correlated_findings += len(filtered)

            # Evaluate correlated findings
            corr_findings = [f.to_dict() for f in filtered]
            corr_detected, corr_tp, corr_fp = evaluate_findings(corr_findings, category)

            correlated_results[category]["total"] += 1
            if corr_detected:
                correlated_results[category]["detected"] += 1
            correlated_results[category]["tp"] += corr_tp
            correlated_results[category]["fp"] += corr_fp
        else:
            correlated_results[category]["total"] += 1

    # Calculate metrics
    def calc_metrics(results, total_findings):
        total_detected = sum(r["detected"] for r in results.values())
        total_contracts = sum(r["total"] for r in results.values())
        total_tp = sum(r["tp"] for r in results.values())
        total_fp = sum(r["fp"] for r in results.values())

        # Recall = contracts detected / total contracts
        recall = total_detected / total_contracts if total_contracts > 0 else 0

        # Precision = contracts with TPs / total findings
        # This is more meaningful for correlation which deduplicates
        precision = total_detected / total_findings if total_findings > 0 else 0

        return {
            "recall": round(recall * 100, 2),
            "precision": round(precision * 100, 2),
            "detected": total_detected,
            "total": total_contracts,
            "tp": total_tp,
            "fp": total_fp,
        }

    baseline_metrics = calc_metrics(baseline_results, total_baseline_findings)
    correlated_metrics = calc_metrics(correlated_results, total_correlated_findings)

    # Print results
    print("\n" + "=" * 70)
    print("  RESULTADOS COMPARATIVOS")
    print("=" * 70)

    print("\n" + "-" * 35 + " BASELINE (Sin correlación) " + "-" * 7)
    print(f"  Recall:    {baseline_metrics['recall']:.2f}%")
    print(f"  Precision: {baseline_metrics['precision']:.2f}%")
    print(f"  Hallazgos: {total_baseline_findings}")
    print(f"  TPs: {baseline_metrics['tp']} | FPs: {baseline_metrics['fp']}")

    print("\n" + "-" * 35 + " CON CORRELACIÓN " + "-" * 18)
    print(f"  Recall:    {correlated_metrics['recall']:.2f}%")
    print(f"  Precision: {correlated_metrics['precision']:.2f}%")
    print(f"  Hallazgos: {total_correlated_findings}")
    print(f"  TPs: {correlated_metrics['tp']} | FPs: {correlated_metrics['fp']}")
    print(f"  Filtrados como FP: {total_filtered_fp}")

    print("\n" + "-" * 35 + " MEJORA " + "-" * 27)
    recall_delta = correlated_metrics["recall"] - baseline_metrics["recall"]
    precision_delta = correlated_metrics["precision"] - baseline_metrics["precision"]
    fp_reduction = 1 - (correlated_metrics["fp"] / max(baseline_metrics["fp"], 1))

    print(f"  Δ Recall:    {recall_delta:+.2f}%")
    print(f"  Δ Precision: {precision_delta:+.2f}%")
    print(f"  Reducción FP: {fp_reduction*100:.1f}%")
    print(
        f"  Deduplicación: {(1 - total_correlated_findings/max(total_baseline_findings, 1))*100:.1f}%"
    )

    print("\n" + "-" * 35 + " POR CATEGORÍA " + "-" * 20)
    for cat in sorted(SMARTBUGS_CATEGORIES.keys()):
        if baseline_results[cat]["total"] > 0:
            b_recall = baseline_results[cat]["detected"] / baseline_results[cat]["total"] * 100
            c_recall = correlated_results[cat]["detected"] / correlated_results[cat]["total"] * 100
            print(f"  {cat:30s} B:{b_recall:5.1f}%  C:{c_recall:5.1f}%")

    # Save results
    results = {
        "timestamp": datetime.now().isoformat(),
        "dataset": str(DATASET_PATH),
        "total_contracts": len(contracts),
        "baseline": {
            "metrics": baseline_metrics,
            "total_findings": total_baseline_findings,
            "by_category": dict(baseline_results),
        },
        "correlated": {
            "metrics": correlated_metrics,
            "total_findings": total_correlated_findings,
            "filtered_as_fp": total_filtered_fp,
            "by_category": dict(correlated_results),
        },
        "improvement": {
            "recall_delta": recall_delta,
            "precision_delta": precision_delta,
            "fp_reduction": fp_reduction,
            "deduplication_rate": 1 - total_correlated_findings / max(total_baseline_findings, 1),
        },
    }

    output_path = RESULTS_PATH / f"correlation_ab_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\nResultados guardados: {output_path}")

    return results


if __name__ == "__main__":
    run_benchmark()
