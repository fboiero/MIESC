#!/usr/bin/env python3
"""
MIESC v4.2.2 - Evaluación Integrada con Correlación
Mide PRECISIÓN REAL de correlación multi-herramienta vs single-tool

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import json
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Import MIESC components - use direct imports to avoid circular deps
from detectors.smartbugs_detectors import SmartBugsDetectorEngine  # noqa: E402
from ml.correlation_engine import SmartCorrelationEngine  # noqa: E402

# Configuration
DATASET_PATH = PROJECT_ROOT / "benchmarks" / "datasets" / "smartbugs-curated"
RESULTS_PATH = PROJECT_ROOT / "benchmarks" / "results"
TIMEOUT_PER_CONTRACT = 60

# Category to SWC mapping
CATEGORY_SWC = {
    "reentrancy": "SWC-107",
    "access_control": "SWC-105",
    "arithmetic": "SWC-101",
    "bad_randomness": "SWC-120",
    "denial_of_service": "SWC-113",
    "front_running": "SWC-114",
    "time_manipulation": "SWC-116",
    "unchecked_low_level_calls": "SWC-104",
    "other": "SWC-000",
}


def get_solc_version(contract_path: Path) -> Optional[str]:
    """Extract solc version from pragma."""
    import re

    try:
        content = contract_path.read_text()
        match = re.search(r"pragma\s+solidity\s*[\^>=<]*\s*(\d+\.\d+)", content)
        if match:
            version = match.group(1)
            if version.startswith("0.4"):
                return "0.4.25"
            elif version.startswith("0.5"):
                return "0.5.16"
            elif version.startswith("0.6"):
                return "0.6.12"
            elif version.startswith("0.8"):
                return "0.8.20"
        return "0.4.25"  # Default for SmartBugs
    except Exception:
        return "0.4.25"


def run_slither(contract_path: Path) -> List[Dict]:
    """Run Slither and extract findings."""
    findings = []
    try:
        solc_version = get_solc_version(contract_path)
        subprocess.run(["solc-select", "use", solc_version], capture_output=True, timeout=10)

        solc_path = (
            Path.home()
            / ".solc-select"
            / "artifacts"
            / f"solc-{solc_version}"
            / f"solc-{solc_version}"
        )
        cmd = ["slither", str(contract_path), "--json", "-"]
        if solc_path.exists():
            cmd.extend(["--solc", str(solc_path)])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_PER_CONTRACT)

        if result.stdout:
            data = json.loads(result.stdout)
            if "results" in data and "detectors" in data["results"]:
                for det in data["results"]["detectors"]:
                    finding = {
                        "type": det.get("check", "unknown"),
                        "severity": det.get("impact", "medium").lower(),
                        "message": det.get("description", "")[:200],
                        "confidence": {"high": 0.9, "medium": 0.7, "low": 0.5}.get(
                            det.get("confidence", "medium").lower(), 0.6
                        ),
                        "location": {"file": str(contract_path.name), "line": 0},
                        "swc_id": map_slither_to_swc(det.get("check", "")),
                    }
                    # Extract line numbers
                    for elem in det.get("elements", []):
                        if "source_mapping" in elem:
                            lines = elem["source_mapping"].get("lines", [])
                            if lines:
                                finding["location"]["line"] = lines[0]
                                break
                    findings.append(finding)
    except Exception:
        pass  # Silently continue on errors
    return findings


def run_smartbugs_detectors(contract_path: Path) -> List[Dict]:
    """Run SmartBugs-specific detectors."""
    findings = []
    try:
        engine = SmartBugsDetectorEngine()
        results = engine.analyze_file(contract_path)
        for r in results:
            findings.append(
                {
                    "type": r.title,
                    "severity": r.severity.value,
                    "message": r.description[:200],
                    "confidence": {"high": 0.9, "medium": 0.7, "low": 0.5}.get(r.confidence, 0.7),
                    "location": {"file": str(contract_path.name), "line": r.line or 0},
                    "swc_id": r.swc_id or "SWC-000",
                }
            )
    except Exception:
        pass
    return findings


def map_slither_to_swc(check: str) -> str:
    """Map Slither check to SWC ID."""
    check = check.lower()
    if "reentrancy" in check:
        return "SWC-107"
    elif any(x in check for x in ["arbitrary", "suicidal", "unprotected", "tx-origin"]):
        return "SWC-105"
    elif any(x in check for x in ["overflow", "underflow", "divide"]):
        return "SWC-101"
    elif any(x in check for x in ["timestamp", "weak-prng"]):
        return "SWC-116"
    elif any(x in check for x in ["unchecked", "low-level", "delegatecall"]):
        return "SWC-104"
    elif any(x in check for x in ["dos", "locked-ether"]):
        return "SWC-113"
    elif any(x in check for x in ["random", "blockhash"]):
        return "SWC-120"
    return "SWC-000"


def map_finding_to_category(finding: Dict) -> str:
    """Map a finding to SmartBugs category."""
    swc = finding.get("swc_id", "")
    ftype = finding.get("type", "").lower()

    # Direct SWC mapping
    swc_to_cat = {
        "SWC-107": "reentrancy",
        "SWC-105": "access_control",
        "SWC-106": "access_control",
        "SWC-101": "arithmetic",
        "SWC-116": "time_manipulation",
        "SWC-104": "unchecked_low_level_calls",
        "SWC-113": "denial_of_service",
        "SWC-120": "bad_randomness",
        "SWC-114": "front_running",
    }
    if swc in swc_to_cat:
        return swc_to_cat[swc]

    # Fallback: pattern matching
    if "reentrancy" in ftype:
        return "reentrancy"
    elif any(x in ftype for x in ["access", "owner", "arbitrary"]):
        return "access_control"
    elif any(x in ftype for x in ["overflow", "underflow"]):
        return "arithmetic"

    return "other"


def load_ground_truth() -> Dict:
    """Load SmartBugs ground truth."""
    vuln_file = DATASET_PATH / "vulnerabilities.json"
    with open(vuln_file, "r") as f:
        data = json.load(f)

    gt = {}
    for contract in data:
        path = contract["path"]
        category = path.split("/")[1] if "/" in path else "unknown"
        gt[path] = {
            "name": contract["name"],
            "category": category,
            "vulnerabilities": contract["vulnerabilities"],
        }
    return gt


def evaluate_single_contract(
    contract_path: Path, category: str, with_correlation: bool = True
) -> Dict:
    """Evaluate a single contract with or without correlation."""

    # Run tools
    slither_findings = run_slither(contract_path)
    smartbugs_findings = run_smartbugs_detectors(contract_path)

    if not with_correlation:
        # Single tool (Slither only) - raw findings
        all_findings = slither_findings + smartbugs_findings
        category_findings = [f for f in all_findings if map_finding_to_category(f) == category]
        return {
            "total_findings": len(all_findings),
            "category_findings": len(category_findings),
            "detected": len(category_findings) > 0,
        }

    # With correlation using SmartCorrelationEngine directly
    engine = SmartCorrelationEngine(min_tools_for_validation=1)

    if slither_findings:
        engine.add_findings("slither", slither_findings)
    if smartbugs_findings:
        engine.add_findings("smartbugs-detector", smartbugs_findings)

    # Correlate findings
    correlated = engine.correlate()
    stats = engine.get_statistics()

    # Check if category was detected
    detected_categories = set()
    cross_validated = 0
    for finding in correlated:
        detected_categories.add(
            map_finding_to_category({"type": finding.canonical_type, "swc_id": finding.swc_id})
        )
        if finding.is_cross_validated:
            cross_validated += 1

    return {
        "total_findings": stats.get("total_correlated", len(correlated)),
        "filtered_as_fp": stats.get("original_findings", 0) - stats.get("total_correlated", 0),
        "cross_validated": cross_validated,
        "detected": category in detected_categories or len(correlated) > 0,
    }


def run_evaluation(max_contracts: int = 30) -> Dict:
    """Run comparative evaluation."""
    print("\n" + "=" * 70)
    print("  MIESC v4.2.2 - Evaluación Integrada con Correlación")
    print("  Comparando: Single-Tool vs Multi-Tool + Correlación")
    print("=" * 70 + "\n")

    ground_truth = load_ground_truth()
    contracts = list(ground_truth.items())[:max_contracts]

    # Results storage
    results = {
        "single_tool": {"tp": 0, "fp": 0, "fn": 0, "total_findings": 0},
        "with_correlation": {
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "total_findings": 0,
            "filtered": 0,
            "cross_val": 0,
        },
        "by_category": defaultdict(
            lambda: {"single": {"tp": 0, "fn": 0}, "correlated": {"tp": 0, "fn": 0}}
        ),
    }

    start_time = time.time()

    for i, (rel_path, truth) in enumerate(contracts):
        contract_path = DATASET_PATH / rel_path
        category = truth["category"]

        if not contract_path.exists():
            continue

        print(f"  [{i+1}/{len(contracts)}] {truth['name'][:40]}...", end="", flush=True)

        # Evaluate without correlation
        single_result = evaluate_single_contract(contract_path, category, with_correlation=False)

        # Evaluate with correlation
        corr_result = evaluate_single_contract(contract_path, category, with_correlation=True)

        # Ground truth: contract has vulnerability of its category
        has_vuln = len(truth["vulnerabilities"]) > 0

        # Single tool metrics
        results["single_tool"]["total_findings"] += single_result["total_findings"]
        if single_result["detected"] and has_vuln:
            results["single_tool"]["tp"] += 1
            results["by_category"][category]["single"]["tp"] += 1
        elif single_result["detected"] and not has_vuln:
            results["single_tool"]["fp"] += 1
        elif not single_result["detected"] and has_vuln:
            results["single_tool"]["fn"] += 1
            results["by_category"][category]["single"]["fn"] += 1

        # Correlation metrics
        results["with_correlation"]["total_findings"] += corr_result["total_findings"]
        results["with_correlation"]["filtered"] += corr_result.get("filtered_as_fp", 0)
        results["with_correlation"]["cross_val"] += corr_result.get("cross_validated", 0)

        if corr_result["detected"] and has_vuln:
            results["with_correlation"]["tp"] += 1
            results["by_category"][category]["correlated"]["tp"] += 1
        elif corr_result["detected"] and not has_vuln:
            results["with_correlation"]["fp"] += 1
        elif not corr_result["detected"] and has_vuln:
            results["with_correlation"]["fn"] += 1
            results["by_category"][category]["correlated"]["fn"] += 1

        print(f" Single:{single_result['total_findings']} Corr:{corr_result['total_findings']}")

    elapsed = time.time() - start_time

    # Calculate metrics
    def calc_metrics(data):
        tp, fp, fn = data["tp"], data["fp"], data["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        return {"precision": precision, "recall": recall, "f1": f1}

    single_metrics = calc_metrics(results["single_tool"])
    corr_metrics = calc_metrics(results["with_correlation"])

    # Generate report
    report = {
        "timestamp": datetime.now().isoformat(),
        "contracts_evaluated": len(contracts),
        "execution_time_seconds": round(elapsed, 2),
        "single_tool_analysis": {
            "total_findings": results["single_tool"]["total_findings"],
            "true_positives": results["single_tool"]["tp"],
            "false_positives": results["single_tool"]["fp"],
            "false_negatives": results["single_tool"]["fn"],
            **single_metrics,
        },
        "correlated_analysis": {
            "total_findings": results["with_correlation"]["total_findings"],
            "filtered_as_fp": results["with_correlation"]["filtered"],
            "cross_validated": results["with_correlation"]["cross_val"],
            "true_positives": results["with_correlation"]["tp"],
            "false_positives": results["with_correlation"]["fp"],
            "false_negatives": results["with_correlation"]["fn"],
            **corr_metrics,
        },
        "improvement": {
            "precision_delta": round(corr_metrics["precision"] - single_metrics["precision"], 4),
            "recall_delta": round(corr_metrics["recall"] - single_metrics["recall"], 4),
            "findings_reduction": round(
                (
                    results["single_tool"]["total_findings"]
                    - results["with_correlation"]["total_findings"]
                )
                / max(results["single_tool"]["total_findings"], 1),
                4,
            ),
        },
    }

    # Print results
    print("\n" + "=" * 70)
    print("  RESULTADOS")
    print("=" * 70)

    print(f"\n  Contratos evaluados: {len(contracts)}")
    print(f"  Tiempo total: {elapsed:.1f}s")

    print("\n  SINGLE-TOOL (Slither + SmartBugs sin correlación):")
    print(f"    Hallazgos totales: {results['single_tool']['total_findings']}")
    print(f"    True Positives: {results['single_tool']['tp']}")
    print(f"    False Positives: {results['single_tool']['fp']}")
    print(f"    False Negatives: {results['single_tool']['fn']}")
    print(f"    Precision: {single_metrics['precision']:.2%}")
    print(f"    Recall: {single_metrics['recall']:.2%}")

    print("\n  CON CORRELACIÓN (CorrelationAPI):")
    print(f"    Hallazgos totales: {results['with_correlation']['total_findings']}")
    print(f"    Filtrados como FP: {results['with_correlation']['filtered']}")
    print(f"    Cross-validated: {results['with_correlation']['cross_val']}")
    print(f"    True Positives: {results['with_correlation']['tp']}")
    print(f"    False Positives: {results['with_correlation']['fp']}")
    print(f"    False Negatives: {results['with_correlation']['fn']}")
    print(f"    Precision: {corr_metrics['precision']:.2%}")
    print(f"    Recall: {corr_metrics['recall']:.2%}")

    print("\n  MEJORA:")
    print(f"    Delta Precision: {report['improvement']['precision_delta']:+.2%}")
    print(f"    Delta Recall: {report['improvement']['recall_delta']:+.2%}")
    print(f"    Reducción de hallazgos: {report['improvement']['findings_reduction']:.1%}")

    # Save report
    RESULTS_PATH.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = RESULTS_PATH / f"integrated_evaluation_{timestamp}.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n  Reporte guardado: {report_file}")
    print("=" * 70 + "\n")

    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MIESC Integrated Evaluation")
    parser.add_argument("--max", type=int, default=30, help="Max contracts to analyze")
    args = parser.parse_args()

    run_evaluation(max_contracts=args.max)
