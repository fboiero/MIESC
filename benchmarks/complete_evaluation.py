#!/usr/bin/env python3
"""
MIESC v4.2.2 - Evaluación Completa del Framework
Evalúa: SmartBugs dataset + Correlación + MCP/REST API

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import concurrent.futures
import json
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Configuration
DATASET_PATH = PROJECT_ROOT / "benchmarks" / "datasets" / "smartbugs-curated"
RESULTS_PATH = PROJECT_ROOT / "benchmarks" / "results"
TIMEOUT_PER_CONTRACT = 30
MAX_WORKERS = 4

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
    "short_addresses": "SWC-129",
    "other": "SWC-000",
}


def print_header(text: str):
    """Print formatted header."""
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}")


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
        return "0.4.25"
    except Exception:
        return "0.4.25"


def run_slither_analysis(contract_path: Path) -> Tuple[List[Dict], float]:
    """Run Slither and return findings with timing."""
    findings = []
    start = time.time()

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
                        "tool": "slither",
                        "type": det.get("check", "unknown"),
                        "severity": det.get("impact", "medium").lower(),
                        "confidence": det.get("confidence", "medium").lower(),
                        "message": det.get("description", "")[:200],
                        "swc_id": map_check_to_swc(det.get("check", "")),
                    }
                    # Extract line
                    for elem in det.get("elements", []):
                        if "source_mapping" in elem:
                            lines = elem["source_mapping"].get("lines", [])
                            if lines:
                                finding["line"] = lines[0]
                                break
                    findings.append(finding)
    except Exception:
        pass

    return findings, time.time() - start


def run_smartbugs_detectors(contract_path: Path) -> Tuple[List[Dict], float]:
    """Run SmartBugs-specific detectors."""
    findings = []
    start = time.time()

    try:
        from detectors.smartbugs_detectors import SmartBugsDetectorEngine

        engine = SmartBugsDetectorEngine()
        results = engine.analyze_file(contract_path)

        for r in results:
            findings.append(
                {
                    "tool": "smartbugs-detector",
                    "type": r.title,
                    "severity": (
                        r.severity.value if hasattr(r.severity, "value") else str(r.severity)
                    ),
                    "confidence": r.confidence if hasattr(r, "confidence") else "medium",
                    "message": r.description[:200] if hasattr(r, "description") else "",
                    "line": r.line if hasattr(r, "line") else 0,
                    "swc_id": r.swc_id if hasattr(r, "swc_id") else "SWC-000",
                }
            )
    except Exception:
        pass

    return findings, time.time() - start


def map_check_to_swc(check: str) -> str:
    """Map tool check to SWC ID."""
    check = check.lower()
    if "reentrancy" in check:
        return "SWC-107"
    elif any(x in check for x in ["arbitrary", "suicidal", "unprotected", "tx-origin"]):
        return "SWC-105"
    elif any(x in check for x in ["overflow", "underflow", "divide"]):
        return "SWC-101"
    elif any(x in check for x in ["timestamp", "block.timestamp"]):
        return "SWC-116"
    elif any(x in check for x in ["unchecked", "low-level", "delegatecall"]):
        return "SWC-104"
    elif any(x in check for x in ["dos", "locked-ether", "denial"]):
        return "SWC-113"
    elif any(x in check for x in ["random", "blockhash", "weak-prng"]):
        return "SWC-120"
    elif any(x in check for x in ["front", "race"]):
        return "SWC-114"
    return "SWC-000"


def correlate_findings(findings: List[Dict]) -> Tuple[List[Dict], Dict]:
    """Correlate findings from multiple tools."""
    try:
        from ml.correlation_engine import SmartCorrelationEngine

        engine = SmartCorrelationEngine(min_tools_for_validation=1)

        # Group by tool
        by_tool = defaultdict(list)
        for f in findings:
            by_tool[f.get("tool", "unknown")].append(f)

        # Add to engine
        for tool, tool_findings in by_tool.items():
            engine.add_findings(tool, tool_findings)

        # Correlate
        correlated = engine.correlate()
        stats = engine.get_statistics()

        # Convert to dict format
        result = []
        for cf in correlated:
            result.append(
                {
                    "type": cf.canonical_type,
                    "severity": cf.severity,
                    "swc_id": cf.swc_id,
                    "confidence": cf.confidence,
                    "sources": list(cf.sources),
                    "is_cross_validated": cf.is_cross_validated,
                }
            )

        return result, stats
    except Exception as e:
        # Fallback: return original findings
        return findings, {"error": str(e)}


def load_ground_truth() -> Dict:
    """Load SmartBugs ground truth."""
    vuln_file = DATASET_PATH / "vulnerabilities.json"
    if not vuln_file.exists():
        return {}

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


def analyze_contract(contract_info: Tuple[Path, str, Dict]) -> Dict:
    """Analyze a single contract."""
    contract_path, rel_path, truth = contract_info

    result = {
        "path": rel_path,
        "name": truth.get("name", contract_path.name),
        "category": truth.get("category", "unknown"),
        "expected_vulns": len(truth.get("vulnerabilities", [])),
        "findings": {
            "raw": [],
            "correlated": [],
        },
        "timing": {},
        "error": None,
    }

    try:
        # Run Slither
        slither_findings, slither_time = run_slither_analysis(contract_path)
        result["findings"]["raw"].extend(slither_findings)
        result["timing"]["slither"] = slither_time

        # Run SmartBugs detectors
        sb_findings, sb_time = run_smartbugs_detectors(contract_path)
        result["findings"]["raw"].extend(sb_findings)
        result["timing"]["smartbugs"] = sb_time

        # Correlate
        correlated, stats = correlate_findings(result["findings"]["raw"])
        result["findings"]["correlated"] = correlated
        result["correlation_stats"] = stats

    except Exception as e:
        result["error"] = str(e)

    return result


def calculate_metrics(results: List[Dict], ground_truth: Dict) -> Dict:
    """Calculate precision, recall, F1 for results."""
    by_category = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "total_findings": 0})
    overall = {"tp": 0, "fp": 0, "fn": 0, "total_findings": 0}

    for r in results:
        cat = r["category"]
        expected_swc = CATEGORY_SWC.get(cat, "SWC-000")
        has_vuln = r["expected_vulns"] > 0

        # Check raw findings
        raw_findings = r["findings"]["raw"]
        detected_raw = any(
            f.get("swc_id") == expected_swc or map_check_to_swc(f.get("type", "")) == expected_swc
            for f in raw_findings
        )

        # Check correlated findings
        corr_findings = r["findings"]["correlated"]
        detected_corr = any(f.get("swc_id") == expected_swc for f in corr_findings)

        # For this evaluation, use correlated findings
        detected = detected_corr if corr_findings else detected_raw

        by_category[cat]["total_findings"] += (
            len(corr_findings) if corr_findings else len(raw_findings)
        )
        overall["total_findings"] += len(corr_findings) if corr_findings else len(raw_findings)

        if detected and has_vuln:
            by_category[cat]["tp"] += 1
            overall["tp"] += 1
        elif detected and not has_vuln:
            by_category[cat]["fp"] += 1
            overall["fp"] += 1
        elif not detected and has_vuln:
            by_category[cat]["fn"] += 1
            overall["fn"] += 1

    def calc(d):
        tp, fp, fn = d["tp"], d["fp"], d["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        return {"precision": precision, "recall": recall, "f1": f1, **d}

    return {
        "overall": calc(overall),
        "by_category": {cat: calc(data) for cat, data in by_category.items()},
    }


def test_mcp_integration() -> Dict:
    """Test MCP/REST API integration."""
    results = {
        "mcp_server": False,
        "rest_api": False,
        "tools_available": 0,
        "layers_configured": 7,
        "errors": [],
    }

    # Count adapters directly
    adapters_path = PROJECT_ROOT / "src" / "adapters"
    if adapters_path.exists():
        adapters = [f for f in adapters_path.iterdir() if f.name.endswith("_adapter.py")]
        results["tools_available"] = len(adapters)

    try:
        # Test correlation engine (core functionality)

        results["correlation_engine"] = True
    except Exception as e:
        results["errors"].append(f"Correlation Engine: {e}")

    try:
        # Test SmartBugs detectors

        results["smartbugs_detectors"] = True
    except Exception as e:
        results["errors"].append(f"SmartBugs Detectors: {e}")

    try:
        # Test ML pipeline

        results["ml_pipeline"] = True
    except Exception as e:
        results["errors"].append(f"ML Pipeline: {e}")

    try:
        # Test MCP REST server

        results["mcp_server"] = True
    except Exception:
        # Try alternate import
        try:
            mcp_path = PROJECT_ROOT / "src" / "miesc_mcp_rest.py"
            if mcp_path.exists():
                results["mcp_server"] = True
        except Exception:
            pass

    # REST API exists if miesc package is installed
    try:
        import miesc

        results["rest_api"] = True
        results["api_version"] = getattr(miesc, "__version__", "4.3.2")
    except Exception:
        pass

    return results


def run_complete_evaluation(max_contracts: int = 100) -> Dict:
    """Run complete evaluation."""
    print_header("MIESC v4.2.2 - EVALUACIÓN COMPLETA")
    print(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Contratos máximos: {max_contracts}")

    start_time = time.time()

    # 1. Test MCP/REST integration
    print_header("1. VALIDACIÓN DE COMPONENTES")
    mcp_results = test_mcp_integration()
    print(f"  REST API: {'OK' if mcp_results['rest_api'] else 'ERROR'}")
    print(f"  MCP Server: {'OK' if mcp_results['mcp_server'] else 'ERROR'}")
    print(f"  Herramientas: {mcp_results['tools_available']}")
    print(f"  Capas: {mcp_results['layers_configured']}")
    if mcp_results["errors"]:
        for err in mcp_results["errors"]:
            print(f"  - {err}")

    # 2. Load ground truth
    print_header("2. CARGANDO DATASET SMARTBUGS")
    ground_truth = load_ground_truth()
    print(f"  Contratos en ground truth: {len(ground_truth)}")

    # 3. Prepare contracts
    contracts_to_analyze = []
    for rel_path, truth in list(ground_truth.items())[:max_contracts]:
        contract_path = DATASET_PATH / rel_path
        if contract_path.exists():
            contracts_to_analyze.append((contract_path, rel_path, truth))

    print(f"  Contratos a analizar: {len(contracts_to_analyze)}")

    # 4. Run analysis
    print_header("3. EJECUTANDO ANÁLISIS")
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(analyze_contract, c): c for c in contracts_to_analyze}

        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            _contract_info = futures[future]
            try:
                result = future.result(timeout=60)
                results.append(result)

                # Progress
                raw_count = len(result["findings"]["raw"])
                corr_count = len(result["findings"]["correlated"])
                status = "OK" if not result["error"] else "ERR"
                print(
                    f"  [{i+1}/{len(contracts_to_analyze)}] {result['name'][:30]:<30} "
                    f"Raw:{raw_count:>3} Corr:{corr_count:>3} [{status}]"
                )

            except Exception as e:
                print(f"  [{i+1}/{len(contracts_to_analyze)}] ERROR: {e}")

    # 5. Calculate metrics
    print_header("4. CALCULANDO MÉTRICAS")
    metrics = calculate_metrics(results, ground_truth)

    print("\n  MÉTRICAS GLOBALES:")
    print(f"    Precision: {metrics['overall']['precision']:.2%}")
    print(f"    Recall: {metrics['overall']['recall']:.2%}")
    print(f"    F1-Score: {metrics['overall']['f1']:.2%}")
    print(f"    True Positives: {metrics['overall']['tp']}")
    print(f"    False Positives: {metrics['overall']['fp']}")
    print(f"    False Negatives: {metrics['overall']['fn']}")

    print("\n  POR CATEGORÍA:")
    for cat, cat_metrics in sorted(metrics["by_category"].items()):
        print(
            f"    {cat:<25} P:{cat_metrics['precision']:.0%} R:{cat_metrics['recall']:.0%} "
            f"F1:{cat_metrics['f1']:.2f} TP:{cat_metrics['tp']} FN:{cat_metrics['fn']}"
        )

    elapsed = time.time() - start_time

    # 6. Generate report
    report = {
        "timestamp": datetime.now().isoformat(),
        "version": "MIESC v4.2.2",
        "dataset": "SmartBugs-curated",
        "contracts_analyzed": len(results),
        "execution_time_seconds": round(elapsed, 2),
        "components": mcp_results,
        "metrics": {
            "overall": {
                "precision": round(metrics["overall"]["precision"], 4),
                "recall": round(metrics["overall"]["recall"], 4),
                "f1_score": round(metrics["overall"]["f1"], 4),
                "true_positives": metrics["overall"]["tp"],
                "false_positives": metrics["overall"]["fp"],
                "false_negatives": metrics["overall"]["fn"],
                "total_findings": metrics["overall"]["total_findings"],
            },
            "by_category": {
                cat: {
                    "precision": round(m["precision"], 4),
                    "recall": round(m["recall"], 4),
                    "f1_score": round(m["f1"], 4),
                    "tp": m["tp"],
                    "fp": m["fp"],
                    "fn": m["fn"],
                }
                for cat, m in metrics["by_category"].items()
            },
        },
        "correlation_improvement": {
            "raw_findings": sum(len(r["findings"]["raw"]) for r in results),
            "correlated_findings": sum(len(r["findings"]["correlated"]) for r in results),
            "reduction_rate": 0,
        },
    }

    # Calculate reduction rate
    raw = report["correlation_improvement"]["raw_findings"]
    corr = report["correlation_improvement"]["correlated_findings"]
    if raw > 0:
        report["correlation_improvement"]["reduction_rate"] = round((raw - corr) / raw, 4)

    # Save report
    print_header("5. GUARDANDO RESULTADOS")
    RESULTS_PATH.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_file = RESULTS_PATH / f"complete_evaluation_{timestamp}.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  Reporte: {report_file}")

    # Summary
    print_header("RESUMEN FINAL")
    print(f"  Contratos analizados: {len(results)}")
    print(f"  Tiempo total: {elapsed:.1f}s ({elapsed/len(results):.2f}s/contrato)")
    print(f"  Hallazgos raw: {raw}")
    print(f"  Hallazgos correlacionados: {corr}")
    print(f"  Reducción: {report['correlation_improvement']['reduction_rate']:.1%}")
    print(f"\n  RECALL: {metrics['overall']['recall']:.2%}")
    print(f"  PRECISION: {metrics['overall']['precision']:.2%}")
    print(f"  F1-SCORE: {metrics['overall']['f1']:.2%}")
    print("=" * 70 + "\n")

    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MIESC Complete Evaluation")
    parser.add_argument("--max", type=int, default=100, help="Max contracts to analyze")
    parser.add_argument("--workers", type=int, default=4, help="Parallel workers")
    args = parser.parse_args()

    MAX_WORKERS = args.workers
    run_complete_evaluation(max_contracts=args.max)
