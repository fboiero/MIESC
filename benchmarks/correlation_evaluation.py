#!/usr/bin/env python3
"""
MIESC Smart Correlation Engine Evaluation
Evalúa el motor de correlación contra el benchmark SmartBugs.

Objetivo: Mejorar precisión manteniendo recall alto.

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Direct imports to avoid __init__.py conflicts
from detectors.smartbugs_detectors import SmartBugsDetectorEngine
from ml.correlation_engine import SmartCorrelationEngine

# Inline import of correlation API to avoid circular imports
sys.path.insert(0, str(PROJECT_ROOT))


class SimplifiedCorrelationAPI:
    """Simplified API for evaluation without full dependency chain."""

    def __init__(
        self,
        min_tools_for_validation: int = 2,
        confidence_threshold: float = 0.5,
        fp_threshold: float = 0.6,
    ):
        self.engine = SmartCorrelationEngine(min_tools_for_validation=min_tools_for_validation)
        self.confidence_threshold = confidence_threshold
        self.fp_threshold = fp_threshold

    def add_tool_results(self, tool_name: str, findings: List[Dict[str, Any]]) -> int:
        return self.engine.add_findings(tool_name, findings)

    def analyze(self, output_format: str = "full") -> Dict[str, Any]:
        correlated = self.engine.correlate()

        actionable = []
        filtered_fp = []

        for f in correlated:
            if f.final_confidence >= self.confidence_threshold:
                if f.false_positive_probability <= self.fp_threshold:
                    actionable.append(f)
                else:
                    filtered_fp.append(f)

        return {
            "findings": {
                "actionable": [f.to_dict() for f in actionable],
                "likely_false_positives": [f.to_dict() for f in filtered_fp],
                "all": [f.to_dict() for f in correlated],
            },
            "summary": self.engine.get_statistics(),
        }

    def clear(self):
        self.engine.clear()


# Alias for compatibility
MIESCCorrelationAPI = SimplifiedCorrelationAPI


# SmartBugs ground truth mapping
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

CATEGORY_ALIASES = {
    "access-control": "access_control",
    "access_control": "access_control",
    "arithmetic": "arithmetic",
    "overflow": "arithmetic",
    "underflow": "arithmetic",
    "bad-randomness": "bad_randomness",
    "bad_randomness": "bad_randomness",
    "weak-prng": "bad_randomness",
    "dos": "denial_of_service",
    "denial-of-service": "denial_of_service",
    "denial_of_service": "denial_of_service",
    "front-running": "front_running",
    "front_running": "front_running",
    "frontrunning": "front_running",
    "reentrancy": "reentrancy",
    "short-addresses": "short_addresses",
    "short_addresses": "short_addresses",
    "time-manipulation": "time_manipulation",
    "time_manipulation": "time_manipulation",
    "timestamp": "time_manipulation",
    "unchecked-call": "unchecked_low_level_calls",
    "unchecked_low_level_calls": "unchecked_low_level_calls",
    "unchecked-lowlevel": "unchecked_low_level_calls",
}


def normalize_category(category: str) -> str:
    """Normaliza categoría a nombre SmartBugs."""
    category_lower = category.lower().replace(" ", "_").replace("-", "_")
    return CATEGORY_ALIASES.get(category_lower, category_lower)


def load_smartbugs_dataset(dataset_path: Path) -> List[Dict[str, Any]]:
    """Carga el dataset SmartBugs con ground truth."""
    contracts = []

    for category in SMARTBUGS_CATEGORIES.keys():
        category_path = dataset_path / category
        if not category_path.exists():
            continue

        for sol_file in category_path.glob("*.sol"):
            contracts.append(
                {
                    "path": sol_file,
                    "category": category,
                    "expected_swcs": SMARTBUGS_CATEGORIES[category],
                }
            )

    return contracts


def run_tools_on_contract(
    contract_path: Path,
    tools: List[str] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Ejecuta herramientas de análisis en un contrato.

    Returns:
        Dict de {tool_name: [findings]}
    """
    results = {}

    if not contract_path.exists():
        return results

    # SmartBugs Detector (siempre habilitado)
    try:
        engine = SmartBugsDetectorEngine()
        findings = engine.analyze_file(contract_path)
        results["smartbugs-detector"] = [
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
            }
            for f in findings
        ]
    except Exception:
        results["smartbugs-detector"] = []

    # Aderyn (si disponible)
    try:
        import subprocess

        result = subprocess.run(
            ["aderyn", str(contract_path), "--output", "stdout", "-q"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout:
            try:
                aderyn_data = json.loads(result.stdout)
                results["aderyn"] = aderyn_data.get("findings", [])
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    # Slither (si disponible)
    try:
        import subprocess

        result = subprocess.run(
            ["slither", str(contract_path), "--json", "-"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.stdout:
            try:
                slither_data = json.loads(result.stdout)
                results["slither"] = [
                    {
                        "type": d.get("check", "unknown"),
                        "severity": d.get("impact", "medium"),
                        "message": d.get("description", ""),
                        "location": {
                            "file": str(contract_path),
                            "line": 0,
                        },
                        "confidence": 0.7 if d.get("confidence") == "High" else 0.5,
                    }
                    for d in slither_data.get("results", {}).get("detectors", [])
                ]
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    return results


def evaluate_with_correlation(
    contract: Dict[str, Any],
    correlation_api: MIESCCorrelationAPI,
    confidence_threshold: float = 0.5,
) -> Dict[str, Any]:
    """
    Evalúa un contrato usando correlación.

    Returns:
        Dict con métricas de evaluación
    """
    contract_path = contract["path"]
    expected_category = contract["category"]
    expected_swcs = contract["expected_swcs"]

    # Ejecutar herramientas
    tool_results = run_tools_on_contract(contract_path)

    if not any(tool_results.values()):
        return {
            "contract": str(contract_path),
            "category": expected_category,
            "detected": False,
            "findings": 0,
            "correlated_findings": 0,
            "filtered_as_fp": 0,
        }

    # Agregar resultados al API de correlación
    correlation_api.clear()
    for tool_name, findings in tool_results.items():
        correlation_api.add_tool_results(tool_name, findings)

    # Ejecutar análisis con correlación
    report = correlation_api.analyze(output_format="full")

    # Extraer hallazgos correlacionados
    correlated_findings = report["findings"]["actionable"]
    filtered_as_fp = report["findings"]["likely_false_positives"]

    # Verificar detección
    detected = False
    detected_categories = set()

    for finding in correlated_findings:
        finding_type = finding.get("type", "")
        normalized = normalize_category(finding_type)
        detected_categories.add(normalized)

        if normalized == expected_category:
            detected = True
            break

        # Verificar por SWC ID
        swc_id = finding.get("swc_id", "")
        if swc_id in expected_swcs:
            detected = True
            break

    # También verificar hallazgos filtrados (para recall completo)
    for finding in filtered_as_fp:
        finding_type = finding.get("type", "")
        normalized = normalize_category(finding_type)

        if normalized == expected_category:
            # Detectado pero filtrado como FP
            break

    return {
        "contract": str(contract_path),
        "category": expected_category,
        "detected": detected,
        "findings": sum(len(f) for f in tool_results.values()),
        "correlated_findings": len(correlated_findings),
        "filtered_as_fp": len(filtered_as_fp),
        "detected_categories": list(detected_categories),
        "cross_validated": sum(
            1 for f in correlated_findings if f.get("is_cross_validated", False)
        ),
        "avg_confidence": sum(f["confidence"]["final"] for f in correlated_findings)
        / max(len(correlated_findings), 1),
    }


def run_evaluation(
    dataset_path: Path,
    confidence_threshold: float = 0.5,
    fp_threshold: float = 0.6,
    max_contracts: int = None,
    workers: int = 4,
) -> Dict[str, Any]:
    """
    Ejecuta evaluación completa del motor de correlación.
    """
    print(f"\n{'='*60}")
    print("  MIESC Smart Correlation Engine Evaluation")
    print(f"{'='*60}")

    # Cargar dataset
    contracts = load_smartbugs_dataset(dataset_path)
    if max_contracts:
        contracts = contracts[:max_contracts]

    print(f"\nDataset: {dataset_path}")
    print(f"Contratos: {len(contracts)}")
    print("Configuración:")
    print(f"  - Umbral de confianza: {confidence_threshold}")
    print(f"  - Umbral de FP: {fp_threshold}")

    # Crear API de correlación
    api = MIESCCorrelationAPI(
        min_tools_for_validation=2,
        confidence_threshold=confidence_threshold,
        fp_threshold=fp_threshold,
    )

    # Evaluar contratos
    results = []
    category_results = defaultdict(lambda: {"tp": 0, "fn": 0, "total": 0})

    print(f"\nEvaluando {len(contracts)} contratos...")

    for i, contract in enumerate(contracts):
        if (i + 1) % 10 == 0:
            print(f"  Progreso: {i+1}/{len(contracts)}")

        result = evaluate_with_correlation(contract, api, confidence_threshold)
        results.append(result)

        category = contract["category"]
        category_results[category]["total"] += 1

        if result["detected"]:
            category_results[category]["tp"] += 1
        else:
            category_results[category]["fn"] += 1

    # Calcular métricas
    total_detected = sum(1 for r in results if r["detected"])
    total_contracts = len(results)
    recall = total_detected / total_contracts if total_contracts > 0 else 0

    # Calcular precisión (usando hallazgos correlacionados vs total)
    total_findings = sum(r["findings"] for r in results)
    total_correlated = sum(r["correlated_findings"] for r in results)
    total_filtered_fp = sum(r["filtered_as_fp"] for r in results)

    # Precisión = TPs detectados / (TPs + FPs)
    # En este caso, TPs = hallazgos que coinciden con ground truth
    # FPs = hallazgos que no coinciden
    tps_correlated = sum(1 for r in results if r["detected"] and r["correlated_findings"] > 0)
    precision_proxy = tps_correlated / max(total_correlated, 1)

    # Métricas por categoría
    category_metrics = {}
    for cat, stats in category_results.items():
        cat_recall = stats["tp"] / stats["total"] if stats["total"] > 0 else 0
        category_metrics[cat] = {
            "recall": round(cat_recall * 100, 2),
            "detected": stats["tp"],
            "total": stats["total"],
        }

    # Resultados
    evaluation = {
        "timestamp": datetime.now().isoformat(),
        "configuration": {
            "confidence_threshold": confidence_threshold,
            "fp_threshold": fp_threshold,
            "dataset": str(dataset_path),
            "contracts_evaluated": len(contracts),
        },
        "summary": {
            "recall": round(recall * 100, 2),
            "precision_proxy": round(precision_proxy * 100, 2),
            "total_findings": total_findings,
            "correlated_findings": total_correlated,
            "filtered_as_fp": total_filtered_fp,
            "fp_filter_rate": round(total_filtered_fp / max(total_findings, 1) * 100, 2),
            "deduplication_rate": round((1 - total_correlated / max(total_findings, 1)) * 100, 2),
        },
        "by_category": category_metrics,
        "details": results,
    }

    # Imprimir resumen
    print(f"\n{'='*60}")
    print("  RESULTADOS")
    print(f"{'='*60}")
    print("\nMétricas Globales:")
    print(f"  Recall: {evaluation['summary']['recall']:.2f}%")
    print(f"  Precisión (proxy): {evaluation['summary']['precision_proxy']:.2f}%")
    print(f"  Hallazgos originales: {total_findings}")
    print(f"  Hallazgos correlacionados: {total_correlated}")
    print(f"  Filtrados como FP: {total_filtered_fp}")
    print(f"  Tasa de filtrado FP: {evaluation['summary']['fp_filter_rate']:.2f}%")
    print(f"  Tasa de deduplicación: {evaluation['summary']['deduplication_rate']:.2f}%")

    print("\nRecall por Categoría:")
    for cat, metrics in sorted(category_metrics.items()):
        print(f"  {cat}: {metrics['recall']:.1f}% ({metrics['detected']}/{metrics['total']})")

    return evaluation


def main():
    parser = argparse.ArgumentParser(
        description="Evalúa el motor de correlación MIESC contra SmartBugs"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="benchmarks/datasets/smartbugs-curated/dataset",
        help="Ruta al dataset SmartBugs",
    )
    parser.add_argument(
        "--confidence", type=float, default=0.5, help="Umbral de confianza (0.0-1.0)"
    )
    parser.add_argument(
        "--fp-threshold", type=float, default=0.6, help="Umbral de probabilidad FP (0.0-1.0)"
    )
    parser.add_argument(
        "--max-contracts", type=int, default=None, help="Máximo de contratos a evaluar"
    )
    parser.add_argument("--output", type=str, default=None, help="Archivo de salida JSON")

    args = parser.parse_args()

    dataset_path = PROJECT_ROOT / args.dataset
    if not dataset_path.exists():
        print(f"Error: Dataset no encontrado en {dataset_path}")
        sys.exit(1)

    results = run_evaluation(
        dataset_path=dataset_path,
        confidence_threshold=args.confidence,
        fp_threshold=args.fp_threshold,
        max_contracts=args.max_contracts,
    )

    # Guardar resultados
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = (
            PROJECT_ROOT
            / "benchmarks"
            / "results"
            / f"correlation_eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\nResultados guardados en: {output_path}")


if __name__ == "__main__":
    main()
