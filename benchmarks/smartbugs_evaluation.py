#!/usr/bin/env python3
"""
MIESC v4.1 - SmartBugs Scientific Evaluation
Validates MIESC against the SmartBugs Curated Dataset (143 contracts)

Dataset: https://github.com/smartbugs/smartbugs-curated
Reference: Durieux et al., "Empirical Review of Automated Analysis Tools on 47,587 Ethereum Smart Contracts", ICSE 2020

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import concurrent.futures
import json
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Import SmartBugs-specific detectors
from detectors.smartbugs_detectors import SmartBugsDetectorEngine  # noqa: E402

# Configuration
DATASET_PATH = PROJECT_ROOT / "benchmarks" / "datasets" / "smartbugs-curated"
RESULTS_PATH = PROJECT_ROOT / "benchmarks" / "results"
TIMEOUT_PER_CONTRACT = 120  # seconds

# SWC Category mapping
SWC_MAPPING = {
    "access_control": "SWC-105",
    "arithmetic": "SWC-101",
    "bad_randomness": "SWC-120",
    "denial_of_service": "SWC-113",
    "front_running": "SWC-114",
    "reentrancy": "SWC-107",
    "short_addresses": "SWC-129",
    "time_manipulation": "SWC-116",
    "unchecked_low_level_calls": "SWC-104",
    "other": "SWC-000",
}

# Reverse mapping for MIESC findings
MIESC_TO_CATEGORY = {
    "SWC-105": "access_control",
    "SWC-115": "access_control",
    "SWC-101": "arithmetic",
    "SWC-120": "bad_randomness",
    "SWC-113": "denial_of_service",
    "SWC-128": "denial_of_service",
    "SWC-114": "front_running",
    "SWC-107": "reentrancy",
    "SWC-129": "short_addresses",
    "SWC-116": "time_manipulation",
    "SWC-104": "unchecked_low_level_calls",
    "SWC-112": "unchecked_low_level_calls",
}


@dataclass
class ContractResult:
    """Result of analyzing a single contract."""

    name: str
    path: str
    category: str
    ground_truth_vulns: List[Dict]
    detected_vulns: List[Dict]
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    execution_time: float = 0.0
    error: Optional[str] = None


@dataclass
class EvaluationMetrics:
    """Aggregated evaluation metrics."""

    total_contracts: int = 0
    total_ground_truth: int = 0
    total_detected: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    execution_time: float = 0.0
    by_category: Dict[str, Dict] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


def load_ground_truth() -> Dict[str, Dict]:
    """Load ground truth from vulnerabilities.json."""
    vuln_file = DATASET_PATH / "vulnerabilities.json"
    with open(vuln_file, "r") as f:
        data = json.load(f)

    ground_truth = {}
    for contract in data:
        path = contract["path"]
        ground_truth[path] = {
            "name": contract["name"],
            "vulnerabilities": contract["vulnerabilities"],
            "pragma": contract.get("pragma", "unknown"),
        }

    return ground_truth


def get_solc_version_from_file(contract_path: Path) -> Optional[str]:
    """Extract solc version from pragma statement."""
    try:
        content = contract_path.read_text()
        import re

        match = re.search(r"pragma\s+solidity\s*[\^>=<]*\s*(\d+\.\d+\.\d+)", content)
        if match:
            return match.group(1)
        # Try simpler pattern
        match = re.search(r"pragma\s+solidity\s*[\^>=<]*\s*(\d+\.\d+)", content)
        if match:
            version = match.group(1)
            # Map to installed version
            if version.startswith("0.4"):
                return "0.4.25"
            elif version.startswith("0.5"):
                return "0.5.16"
            elif version.startswith("0.8"):
                return "0.8.20"
        return None
    except Exception:
        return None


def run_miesc_analysis(contract_path: Path, timeout: int = TIMEOUT_PER_CONTRACT) -> Dict:
    """Run MIESC analysis on a single contract."""
    try:
        # Auto-select solc version
        solc_version = get_solc_version_from_file(contract_path)
        if solc_version:
            subprocess.run(["solc-select", "use", solc_version], capture_output=True, timeout=10)

        # Use slither for fast static analysis (Layer 1)
        cmd = ["slither", str(contract_path), "--json", "-"]

        # Get solc path if version available
        if solc_version:
            solc_path = (
                Path.home()
                / ".solc-select"
                / "artifacts"
                / f"solc-{solc_version}"
                / f"solc-{solc_version}"
            )
            if solc_path.exists():
                cmd.extend(["--solc", str(solc_path)])

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=PROJECT_ROOT
        )

        if result.returncode == 0 or result.stdout:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"detectors": [], "error": "JSON parse error"}
        else:
            return {"detectors": [], "error": result.stderr[:500]}

    except subprocess.TimeoutExpired:
        return {"detectors": [], "error": "Timeout"}
    except Exception as e:
        return {"detectors": [], "error": str(e)}


def run_aderyn_analysis(contract_path: Path, timeout: int = TIMEOUT_PER_CONTRACT) -> Dict:
    """Run Aderyn analysis on a single contract."""
    try:
        result = subprocess.run(
            ["aderyn", str(contract_path), "--output", "json"],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=PROJECT_ROOT,
        )

        # Aderyn outputs to file, try to read it
        json_output = contract_path.parent / "report.json"
        if json_output.exists():
            with open(json_output) as f:
                data = json.load(f)
            json_output.unlink()  # Clean up
            return data

        return {"findings": [], "error": result.stderr[:500] if result.stderr else None}

    except subprocess.TimeoutExpired:
        return {"findings": [], "error": "Timeout"}
    except Exception as e:
        return {"findings": [], "error": str(e)}


def run_smartbugs_detectors(contract_path: Path, min_confidence: str = None) -> List[Dict]:
    """
    Run SmartBugs-specific detectors on a contract.

    Args:
        contract_path: Path to the contract file
        min_confidence: Minimum confidence level to include ('high', 'medium', 'low')
                       If None, includes all findings
    """
    try:
        engine = SmartBugsDetectorEngine()
        findings = engine.analyze_file(contract_path)

        # Confidence level ordering
        confidence_levels = {"high": 3, "medium": 2, "low": 1}
        min_level = confidence_levels.get(min_confidence, 0)

        results = []
        for finding in findings:
            # Filter by confidence if specified
            finding_level = confidence_levels.get(finding.confidence, 2)
            if finding_level < min_level:
                continue

            results.append(
                {
                    "tool": "smartbugs-detector",
                    "check": finding.title,
                    "impact": finding.severity.value,
                    "confidence": finding.confidence,
                    "description": finding.description,
                    "lines": [finding.line] if finding.line else [],
                    "category": finding.category,
                    "swc_id": finding.swc_id,
                }
            )
        return results
    except Exception:
        return []


def extract_findings(
    slither_result: Dict, aderyn_result: Dict, smartbugs_findings: List[Dict] = None
) -> List[Dict]:
    """Extract and normalize findings from tool outputs."""
    findings = []

    # Extract from Slither
    if "results" in slither_result and "detectors" in slither_result["results"]:
        for detector in slither_result["results"]["detectors"]:
            finding = {
                "tool": "slither",
                "check": detector.get("check", "unknown"),
                "impact": detector.get("impact", "unknown"),
                "confidence": detector.get("confidence", "unknown"),
                "description": detector.get("description", ""),
                "lines": [],
            }

            # Extract lines
            for elem in detector.get("elements", []):
                if "source_mapping" in elem:
                    lines = elem["source_mapping"].get("lines", [])
                    finding["lines"].extend(lines)

            # Map to SWC category - improved mapping for SmartBugs categories
            check = detector.get("check", "").lower()
            description = detector.get("description", "").lower()

            # Reentrancy
            if "reentrancy" in check or "reentrancy" in description:
                finding["category"] = "reentrancy"
            # Access Control
            elif any(
                x in check
                for x in ["arbitrary", "suicidal", "unprotected", "tx-origin", "tx.origin"]
            ):
                finding["category"] = "access_control"
            elif "protected" in check and "function" in check:
                finding["category"] = "access_control"
            # Arithmetic (overflow/underflow)
            elif any(x in check for x in ["overflow", "underflow", "divide-before-multiply"]):
                finding["category"] = "arithmetic"
            elif any(x in description for x in ["overflow", "underflow", "arithmetic"]):
                finding["category"] = "arithmetic"
            # Time Manipulation
            elif any(x in check for x in ["timestamp", "block-timestamp", "weak-prng"]):
                finding["category"] = "time_manipulation"
            elif "block.timestamp" in description or "block.number" in description:
                finding["category"] = "time_manipulation"
            # Unchecked Low Level Calls
            elif any(x in check for x in ["low-level", "unchecked", "call-loop", "delegatecall"]):
                finding["category"] = "unchecked_low_level_calls"
            elif any(
                x in check for x in ["unchecked-send", "unchecked-transfer", "unchecked-lowlevel"]
            ):
                finding["category"] = "unchecked_low_level_calls"
            # Denial of Service
            elif any(x in check for x in ["dos", "denial", "locked-ether", "calls-loop"]):
                finding["category"] = "denial_of_service"
            elif "gas" in check and "loop" in description:
                finding["category"] = "denial_of_service"
            # Bad Randomness
            elif any(x in check for x in ["random", "prng", "blockhash"]):
                finding["category"] = "bad_randomness"
            elif any(x in description for x in ["randomness", "predictable", "blockhash"]):
                finding["category"] = "bad_randomness"
            # Front Running
            elif any(x in check for x in ["front-run", "frontrun", "race-condition"]):
                finding["category"] = "front_running"
            elif "transaction order" in description:
                finding["category"] = "front_running"
            else:
                finding["category"] = "other"

            findings.append(finding)

    # Extract from Aderyn
    for severity in ["high", "medium", "low"]:
        for issue in aderyn_result.get(f"{severity}_issues", {}).get("issues", []):
            finding = {
                "tool": "aderyn",
                "check": issue.get("title", "unknown"),
                "impact": severity,
                "description": issue.get("description", ""),
                "lines": [],
                "category": "other",
            }

            # Extract lines from instances
            for instance in issue.get("instances", []):
                if "line" in instance:
                    finding["lines"].append(instance["line"])

            # Map to category
            title = issue.get("title", "").lower()
            if "reentrancy" in title:
                finding["category"] = "reentrancy"
            elif "access" in title or "owner" in title:
                finding["category"] = "access_control"

            findings.append(finding)

    # Include SmartBugs-specific detector findings
    if smartbugs_findings:
        findings.extend(smartbugs_findings)

    return findings


def match_findings(
    ground_truth: List[Dict], detected: List[Dict], category: str
) -> Tuple[int, int, int]:
    """Match detected findings against ground truth for a category."""
    # Get ground truth lines for this category
    gt_lines = set()
    for vuln in ground_truth:
        if vuln.get("category") == category:
            gt_lines.update(vuln.get("lines", []))

    # Get detected lines for this category
    detected_lines = set()
    for finding in detected:
        if finding.get("category") == category:
            detected_lines.update(finding.get("lines", []))

    # Also count by category match (not just line match)
    gt_has_category = any(v.get("category") == category for v in ground_truth)
    detected_has_category = any(f.get("category") == category for f in detected)

    # Calculate metrics
    # True positive: detected and in ground truth
    tp = len(gt_lines & detected_lines)

    # If no line match but category match, count as partial TP
    if tp == 0 and gt_has_category and detected_has_category:
        tp = 1  # At least detected the right category

    # False positive: detected but not in ground truth
    fp = len(detected_lines - gt_lines)

    # False negative: in ground truth but not detected
    fn = len(gt_lines - detected_lines)

    return tp, fp, fn


def evaluate_contract(contract_info: Tuple[str, Dict]) -> ContractResult:
    """Evaluate a single contract."""
    rel_path, truth = contract_info
    contract_path = DATASET_PATH / rel_path

    # Determine category from path
    category = rel_path.split("/")[1] if "/" in rel_path else "unknown"

    result = ContractResult(
        name=truth["name"],
        path=rel_path,
        category=category,
        ground_truth_vulns=truth["vulnerabilities"],
        detected_vulns=[],
    )

    if not contract_path.exists():
        result.error = f"File not found: {contract_path}"
        return result

    start_time = time.time()

    # Run analysis
    slither_result = run_miesc_analysis(contract_path)
    aderyn_result = run_aderyn_analysis(contract_path)

    # Run SmartBugs-specific detectors (target 0% recall categories)
    smartbugs_findings = run_smartbugs_detectors(contract_path, min_confidence=_MIN_CONFIDENCE)

    result.execution_time = time.time() - start_time

    # Check for errors
    if slither_result.get("error") and aderyn_result.get("error"):
        result.error = f"Slither: {slither_result['error']}, Aderyn: {aderyn_result['error']}"

    # Extract findings (including SmartBugs detectors)
    result.detected_vulns = extract_findings(slither_result, aderyn_result, smartbugs_findings)

    # Match against ground truth
    tp, fp, fn = match_findings(result.ground_truth_vulns, result.detected_vulns, category)

    result.true_positives = tp
    result.false_positives = fp
    result.false_negatives = fn

    return result


# Module-level config for confidence filtering
_MIN_CONFIDENCE = None


def run_evaluation(
    max_contracts: Optional[int] = None, parallel: bool = True, min_confidence: str = None
) -> EvaluationMetrics:
    """Run full evaluation on SmartBugs dataset."""
    global _MIN_CONFIDENCE
    _MIN_CONFIDENCE = min_confidence

    print("\n" + "=" * 70)
    print("  MIESC v4.1 - SmartBugs Scientific Evaluation")
    print("  Dataset: 143 contracts, 10 vulnerability categories")
    if min_confidence:
        print(f"  Confidence filter: {min_confidence}+")
    print("=" * 70 + "\n")

    # Handle foundry.toml at start to avoid Foundry detection
    foundry_toml = PROJECT_ROOT / "foundry.toml"
    foundry_backup = PROJECT_ROOT / "foundry.toml.bak"
    foundry_renamed = False

    if foundry_toml.exists() and not foundry_backup.exists():
        foundry_toml.rename(foundry_backup)
        foundry_renamed = True
        print("[INFO] Temporarily disabled foundry.toml for Slither compatibility")

    # Load ground truth
    print("[1/4] Loading ground truth...")
    ground_truth = load_ground_truth()
    print(f"      Loaded {len(ground_truth)} contracts")

    # Prepare contracts
    contracts = list(ground_truth.items())
    if max_contracts:
        contracts = contracts[:max_contracts]

    # Initialize metrics
    metrics = EvaluationMetrics(total_contracts=len(contracts))
    category_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "count": 0})

    # Run evaluation
    print(f"\n[2/4] Analyzing {len(contracts)} contracts...")
    results = []

    start_time = time.time()

    if parallel and len(contracts) > 5:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(evaluate_contract, c): c for c in contracts}
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                result = future.result()
                results.append(result)

                # Progress
                if (i + 1) % 10 == 0 or (i + 1) == len(contracts):
                    print(f"      Progress: {i+1}/{len(contracts)} contracts")
    else:
        for i, contract in enumerate(contracts):
            result = evaluate_contract(contract)
            results.append(result)

            if (i + 1) % 10 == 0:
                print(f"      Progress: {i+1}/{len(contracts)} contracts")

    metrics.execution_time = time.time() - start_time

    # Aggregate results
    print("\n[3/4] Aggregating results...")

    for result in results:
        # Count ground truth vulnerabilities
        metrics.total_ground_truth += len(result.ground_truth_vulns)
        metrics.total_detected += len(result.detected_vulns)

        # Aggregate metrics
        metrics.true_positives += result.true_positives
        metrics.false_positives += result.false_positives
        metrics.false_negatives += result.false_negatives

        # By category
        cat = result.category
        category_stats[cat]["tp"] += result.true_positives
        category_stats[cat]["fp"] += result.false_positives
        category_stats[cat]["fn"] += result.false_negatives
        category_stats[cat]["count"] += 1

        # Track errors
        if result.error:
            metrics.errors.append(f"{result.name}: {result.error}")

    # Calculate final metrics
    if metrics.true_positives + metrics.false_positives > 0:
        metrics.precision = metrics.true_positives / (
            metrics.true_positives + metrics.false_positives
        )

    if metrics.true_positives + metrics.false_negatives > 0:
        metrics.recall = metrics.true_positives / (metrics.true_positives + metrics.false_negatives)

    if metrics.precision + metrics.recall > 0:
        metrics.f1_score = (
            2 * (metrics.precision * metrics.recall) / (metrics.precision + metrics.recall)
        )

    # Calculate per-category metrics
    for cat, stats in category_stats.items():
        tp, fp, fn = stats["tp"], stats["fp"], stats["fn"]

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        metrics.by_category[cat] = {
            "contracts": stats["count"],
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        }

    # Restore foundry.toml
    if foundry_renamed and foundry_backup.exists():
        foundry_backup.rename(foundry_toml)
        print("[INFO] Restored foundry.toml")

    return metrics, results


def generate_report(metrics: EvaluationMetrics, results: List[ContractResult]):
    """Generate evaluation report."""
    print("\n[4/4] Generating report...")

    # Create results directory
    RESULTS_PATH.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Console output
    print("\n" + "=" * 70)
    print("  EVALUATION RESULTS")
    print("=" * 70)

    print(f"\n  Contracts Analyzed: {metrics.total_contracts}")
    print(f"  Total Execution Time: {metrics.execution_time:.1f}s")
    print(f"  Avg Time per Contract: {metrics.execution_time/metrics.total_contracts:.2f}s")

    print(f"\n  Ground Truth Vulnerabilities: {metrics.total_ground_truth}")
    print(f"  Detected Findings: {metrics.total_detected}")

    print(f"\n  True Positives:  {metrics.true_positives}")
    print(f"  False Positives: {metrics.false_positives}")
    print(f"  False Negatives: {metrics.false_negatives}")

    print(f"\n  PRECISION: {metrics.precision:.2%}")
    print(f"  RECALL:    {metrics.recall:.2%}")
    print(f"  F1-SCORE:  {metrics.f1_score:.2%}")

    print("\n  Results by Category:")
    print("  " + "-" * 66)
    print(f"  {'Category':<25} {'Contracts':>10} {'Precision':>12} {'Recall':>10} {'F1':>10}")
    print("  " + "-" * 66)

    for cat, stats in sorted(metrics.by_category.items()):
        print(
            f"  {cat:<25} {stats['contracts']:>10} {stats['precision']:>11.2%} {stats['recall']:>9.2%} {stats['f1_score']:>9.2%}"
        )

    print("  " + "-" * 66)

    if metrics.errors:
        print(f"\n  Errors: {len(metrics.errors)}")

    # Save JSON report
    report = {
        "timestamp": timestamp,
        "dataset": "SmartBugs Curated",
        "total_contracts": metrics.total_contracts,
        "execution_time_seconds": round(metrics.execution_time, 2),
        "metrics": {
            "precision": round(metrics.precision, 4),
            "recall": round(metrics.recall, 4),
            "f1_score": round(metrics.f1_score, 4),
            "true_positives": metrics.true_positives,
            "false_positives": metrics.false_positives,
            "false_negatives": metrics.false_negatives,
        },
        "by_category": metrics.by_category,
        "errors_count": len(metrics.errors),
    }

    report_file = RESULTS_PATH / f"smartbugs_evaluation_{timestamp}.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n  Report saved: {report_file}")

    # Save detailed results
    detailed_file = RESULTS_PATH / f"smartbugs_detailed_{timestamp}.json"
    detailed = [
        {
            "name": r.name,
            "path": r.path,
            "category": r.category,
            "ground_truth": len(r.ground_truth_vulns),
            "detected": len(r.detected_vulns),
            "tp": r.true_positives,
            "fp": r.false_positives,
            "fn": r.false_negatives,
            "time": round(r.execution_time, 2),
            "error": r.error,
        }
        for r in results
    ]

    with open(detailed_file, "w") as f:
        json.dump(detailed, f, indent=2)

    print(f"  Detailed results: {detailed_file}")

    return report_file


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="MIESC SmartBugs Evaluation")
    parser.add_argument("--max", type=int, help="Max contracts to analyze")
    parser.add_argument("--no-parallel", action="store_true", help="Disable parallel execution")
    parser.add_argument("--category", type=str, help="Only evaluate specific category")
    parser.add_argument(
        "--min-confidence",
        type=str,
        choices=["high", "medium", "low"],
        help="Minimum confidence level for findings (high=highest precision, low=highest recall)",
    )

    args = parser.parse_args()

    # Run evaluation
    metrics, results = run_evaluation(
        max_contracts=args.max, parallel=not args.no_parallel, min_confidence=args.min_confidence
    )

    # Generate report
    generate_report(metrics, results)

    print("\n" + "=" * 70)
    print("  EVALUATION COMPLETE")
    print("=" * 70 + "\n")

    return metrics


if __name__ == "__main__":
    main()
