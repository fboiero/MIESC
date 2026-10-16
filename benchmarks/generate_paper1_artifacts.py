#!/usr/bin/env python3
"""Generate reproducibility artifacts for Paper 1.

The script is intentionally deterministic and only reads committed benchmark
result JSON files. It produces:

* benchmarks/results/evmbench/evmbench_ensemble_40.json
* benchmarks/results/paper1_claims_matrix.json

Run from the repository root:

    python benchmarks/generate_paper1_artifacts.py
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks" / "results"
EVMBENCH = RESULTS / "evmbench"

PROVIDERS = {
    "claude_sonnet_4_6": EVMBENCH / "evmbench_claude46_40_FINAL.json",
    "gpt_5": EVMBENCH / "evmbench_gpt5_40.json",
    "gpt_4o": EVMBENCH / "evmbench_gpt4o_40.json",
    "ollama_qwen2_5_coder_32b": EVMBENCH / "evmbench_ollama_qwen32b_40_FINAL.json",
}

CAMERA_READY_DATE = "2026-10-16"
SMARTBUGS_LATEST = RESULTS / "paper1_smartbugs_eval_layers_1_6_7.json"
SMARTBUGS_OLLAMA_FOLLOWUP = RESULTS / "paper1_smartbugs_local_ollama_followup_20260623.json"
REAL_WORLD_EXPLOITS = RESULTS / "paper1_exploits_eval_20260621.json"
EVMBENCH_STATIC = EVMBENCH / "evmbench_static_40.json"


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def reproducible_generated_at() -> str:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def metrics_from_result(data: dict) -> dict:
    recall = data.get("recall", 0)
    total_findings = data.get("total_findings", 0)
    total_detected = data.get("total_detected", 0)
    precision = total_detected / total_findings if total_findings else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    return {
        "audits_evaluated": data.get("audits_evaluated"),
        "total_vulns": data.get("total_vulns"),
        "total_detected": total_detected,
        "total_findings": total_findings,
        "recall": recall,
        "precision": precision,
        "f1": f1,
    }


def layers_from_smartbugs_artifact(data: dict, source_path: Path | None = None) -> list[int] | None:
    layers = data.get("experiment_card", {}).get("layers_evaluated") or data.get(
        "configuration", {}
    ).get("layers")
    if layers:
        return layers
    if source_path:
        match = re.search(r"layers_([0-9_]+)", source_path.stem)
        if match:
            return [int(layer) for layer in match.group(1).split("_") if layer]
    return None


def smartbugs_metrics(data: dict, source_path: Path | None = None) -> dict:
    """Normalize SmartBugs evaluator JSONs from historical and corpus runners."""
    layers_evaluated = layers_from_smartbugs_artifact(data, source_path)
    aggregate = data.get("aggregate")
    if aggregate:
        return {
            "contracts_evaluated": aggregate.get("contracts_evaluated"),
            "tp": aggregate.get("tp"),
            "fp": aggregate.get("fp"),
            "fn": aggregate.get("fn"),
            "precision": aggregate.get("precision"),
            "recall": aggregate.get("recall"),
            "f1": aggregate.get("f1"),
            "total_time_s": aggregate.get("total_time_s"),
            "avg_time_per_contract_s": aggregate.get("avg_time_per_contract_s"),
            "layers_evaluated": layers_evaluated,
        }

    metrics = data.get("metrics", {})
    return {
        "contracts_evaluated": metrics.get("total_contracts"),
        "tp": metrics.get("true_positives"),
        "fp": metrics.get("false_positives"),
        "fn": metrics.get("false_negatives"),
        "precision": metrics.get("precision"),
        "recall": metrics.get("recall"),
        "f1": metrics.get("f1_score"),
        "total_time_s": metrics.get("execution_time_seconds"),
        "avg_time_per_contract_s": metrics.get("avg_time_per_contract_s"),
        "layers_evaluated": layers_evaluated,
    }


def iter_vulns(provider: str, data: dict):
    for audit in data.get("results", []):
        audit_id = audit.get("audit")
        details = audit.get("details") or []
        for item in details:
            vuln_id = item.get("vuln")
            if not audit_id or not vuln_id:
                continue
            yield {
                "key": f"{audit_id}:{vuln_id}",
                "audit": audit_id,
                "vuln": vuln_id,
                "description": item.get("description", ""),
                "provider": provider,
                "matched": bool(item.get("matched")),
            }


def generate_ensemble() -> dict:
    provider_data = {name: load_json(path) for name, path in PROVIDERS.items()}

    all_vulns: dict[str, dict] = {}
    for provider, data in provider_data.items():
        for item in iter_vulns(provider, data):
            entry = all_vulns.setdefault(
                item["key"],
                {
                    "audit": item["audit"],
                    "vuln": item["vuln"],
                    "description": item["description"],
                    "providers_detected": [],
                    "matched": False,
                },
            )
            if item["description"] and not entry["description"]:
                entry["description"] = item["description"]
            if item["matched"]:
                entry["matched"] = True
                entry["providers_detected"].append(provider)

    vulnerabilities = [
        {
            **entry,
            "providers_detected": sorted(set(entry["providers_detected"])),
            "n_providers_detected": len(set(entry["providers_detected"])),
        }
        for _, entry in sorted(all_vulns.items())
    ]

    total_vulns = len(vulnerabilities)
    detected = sum(1 for item in vulnerabilities if item["matched"])

    provider_summary = {}
    for provider, data in provider_data.items():
        provider_summary[provider] = {
            "source": str(PROVIDERS[provider].relative_to(ROOT)),
            "date": data.get("date"),
            "version": data.get("version"),
            "audits_evaluated": data.get("audits_evaluated"),
            "total_vulns": data.get("total_vulns"),
            "total_detected": data.get("total_detected"),
            "recall": data.get("recall"),
            "total_findings": data.get("total_findings"),
        }

    return {
        "artifact": "evmbench_ensemble_40",
        "generated_at": reproducible_generated_at(),
        "method": (
            "Union over matched vulnerabilities keyed by audit_id:vulnerability_id "
            "from the four provider result files. A vulnerability is counted as "
            "detected if any provider marks it as matched=true."
        ),
        "input_files": {name: str(path.relative_to(ROOT)) for name, path in PROVIDERS.items()},
        "provider_summary": provider_summary,
        "audits_evaluated": len({item["audit"] for item in vulnerabilities}),
        "total_vulns": total_vulns,
        "total_detected": detected,
        "recall": detected / total_vulns if total_vulns else 0,
        "missed": total_vulns - detected,
        "detected_by_provider_count": {
            "1": sum(1 for item in vulnerabilities if item["n_providers_detected"] == 1),
            "2": sum(1 for item in vulnerabilities if item["n_providers_detected"] == 2),
            "3": sum(1 for item in vulnerabilities if item["n_providers_detected"] == 3),
            "4": sum(1 for item in vulnerabilities if item["n_providers_detected"] == 4),
        },
        "vulnerabilities": vulnerabilities,
    }


def generate_claims_matrix(ensemble: dict) -> dict:
    smartbugs = load_json(SMARTBUGS_LATEST)
    smartbugs_summary = smartbugs_metrics(smartbugs, SMARTBUGS_LATEST)
    smartbugs_followup = load_json(SMARTBUGS_OLLAMA_FOLLOWUP)
    real_world_exploits = load_json(REAL_WORLD_EXPLOITS)
    evmbench_static = load_json(EVMBENCH_STATIC)
    provider_data = {name: load_json(path) for name, path in PROVIDERS.items()}

    return {
        "artifact": "paper1_claims_matrix",
        "generated_at": reproducible_generated_at(),
        "purpose": "Trace Paper 1 quantitative claims to local artifacts or external sources.",
        "claims": [
            {
                "claim_id": "smartbugs_latest_reproducible",
                "paper_claim": "MIESC latest local SmartBugs run reports 95.8% recall (137/143).",
                "value": smartbugs_summary,
                "unit": "recall",
                "source_artifact": str(SMARTBUGS_LATEST.relative_to(ROOT)),
                "status": "supported",
                "notes": (
                    "v5.4.1 final local run with context-aware FP filters and multiline "
                    "access_control/front_running patterns. 7/10 categories reached 100% "
                    "recall; front_running reached 50%."
                ),
            },
            {
                "claim_id": "smartbugs_local_ollama_followup",
                "paper_claim": (
                    "Adding local Ollama analysis over the residual SmartBugs misses "
                    "raises recall to 97.9% (140/143) at zero API cost."
                ),
                "source_artifact": [
                    str(SMARTBUGS_OLLAMA_FOLLOWUP.relative_to(ROOT)),
                    str(SMARTBUGS_LATEST.relative_to(ROOT)),
                ],
                "status": "supported_secondary",
                "unit": "recall",
                "value": smartbugs_followup["aggregate"],
                "notes": (
                    "Paper 1 v2 reports a local qwen2.5-coder:32b/Ollama follow-up "
                    "over the six misses of the reproducible 1,6,7 profile. It is a "
                    "secondary claim because the primary full-corpus reproducible "
                    "profile remains the deterministic 137/143 SmartBugs run."
                ),
            },
            {
                "claim_id": "evmbench_claude_sonnet_4_6",
                "paper_claim": "Claude Sonnet 4.6 reaches 82.5% recall on EVMBench local extraction.",
                "value": ensemble["provider_summary"]["claude_sonnet_4_6"]["recall"],
                "unit": "recall",
                "source_artifact": ensemble["provider_summary"]["claude_sonnet_4_6"]["source"],
                "status": "supported",
            },
            {
                "claim_id": "evmbench_gpt_5",
                "paper_claim": "GPT-5 reaches 77.5% recall on EVMBench local extraction.",
                "value": ensemble["provider_summary"]["gpt_5"]["recall"],
                "unit": "recall",
                "source_artifact": ensemble["provider_summary"]["gpt_5"]["source"],
                "status": "supported",
            },
            {
                "claim_id": "evmbench_gpt_4o",
                "paper_claim": "GPT-4o reaches approximately 73.7% recall on EVMBench local extraction.",
                "value": ensemble["provider_summary"]["gpt_4o"]["recall"],
                "unit": "recall",
                "source_artifact": ensemble["provider_summary"]["gpt_4o"]["source"],
                "status": "supported_with_note",
                "notes": "Provider file evaluates all 40 audit entries but one clone_failed entry has 0/2 detected.",
            },
            {
                "claim_id": "evmbench_ollama_qwen32b",
                "paper_claim": "Ollama qwen2.5-coder:32b reaches 59.2% recall on EVMBench local extraction.",
                "value": ensemble["provider_summary"]["ollama_qwen2_5_coder_32b"]["recall"],
                "unit": "recall",
                "source_artifact": ensemble["provider_summary"]["ollama_qwen2_5_coder_32b"][
                    "source"
                ],
                "status": "supported",
            },
            {
                "claim_id": "evmbench_static_only",
                "paper_claim": "Static-only MIESC reaches 18.3% recall on EVMBench local extraction.",
                "value": evmbench_static["recall"],
                "unit": "recall",
                "source_artifact": str(EVMBENCH_STATIC.relative_to(ROOT)),
                "status": "supported",
                "notes": (
                    f"Static-only detected {evmbench_static['total_detected']} of "
                    f"{evmbench_static['total_vulns']} vulnerabilities with "
                    f"{evmbench_static['total_findings']} HIGH/CRITICAL findings."
                ),
            },
            {
                "claim_id": "evmbench_ensemble_union",
                "paper_claim": "The four-provider ensemble reaches union recall on EVMBench local extraction.",
                "value": ensemble["recall"],
                "unit": "recall",
                "source_artifact": "benchmarks/results/evmbench/evmbench_ensemble_40.json",
                "status": "supported",
                "notes": (
                    f"Union detected {ensemble['total_detected']} of {ensemble['total_vulns']} "
                    "audit:vulnerability keys."
                ),
            },
            {
                "claim_id": "evmbench_table_metrics",
                "paper_claim": "EVMBench table precision, recall, F1, counts, and n values are derived from local JSON artifacts.",
                "value": {
                    "static_only": metrics_from_result(evmbench_static),
                    "ollama_qwen2_5_coder_32b": metrics_from_result(
                        provider_data["ollama_qwen2_5_coder_32b"]
                    ),
                    "gpt_4o": metrics_from_result(provider_data["gpt_4o"]),
                    "gpt_5": metrics_from_result(provider_data["gpt_5"]),
                    "claude_sonnet_4_6": metrics_from_result(provider_data["claude_sonnet_4_6"]),
                    "ensemble_union": {
                        "audits_evaluated": ensemble["audits_evaluated"],
                        "total_vulns": ensemble["total_vulns"],
                        "total_detected": ensemble["total_detected"],
                        "recall": ensemble["recall"],
                    },
                },
                "unit": "mixed metrics",
                "source_artifact": [
                    str(EVMBENCH_STATIC.relative_to(ROOT)),
                    "benchmarks/results/evmbench/evmbench_ensemble_40.json",
                    *[str(path.relative_to(ROOT)) for path in PROVIDERS.values()],
                ],
                "status": "supported",
            },
            {
                "claim_id": "evmbench_ensemble_diversity",
                "paper_claim": "The ensemble has 13 one-provider, 16 two-provider, 23 three-provider, and 59 four-provider detections, with 9 misses.",
                "value": {
                    "detected_by_provider_count": ensemble["detected_by_provider_count"],
                    "missed": ensemble["missed"],
                },
                "unit": "vulnerability count",
                "source_artifact": "benchmarks/results/evmbench/evmbench_ensemble_40.json",
                "status": "supported",
            },
            {
                "claim_id": "evmbench_official_size",
                "paper_claim": "Official EVMBench describes 117 curated vulnerabilities from 40 repositories/audits.",
                "value": 117,
                "unit": "curated vulnerabilities",
                "source_artifact": "https://arxiv.org/abs/2603.04915",
                "status": "external_primary_source",
                "notes": "Paper should distinguish official EVMBench size from the local 120 high-severity finding extraction.",
            },
            {
                "claim_id": "cecuro_877",
                "paper_claim": "Cecuro reports 87.7% recall on EVMBench detect task.",
                "value": 0.877,
                "unit": "recall",
                "source_artifact": (
                    "https://chainwire.org/2026/04/16/"
                    "ai-audit-firm-cecuro-outperforms-nearest-rival-by-2x-on-openai-smart-contract-exploit-benchmark/"
                ),
                "status": "external_secondary_source",
                "notes": "Use as reported benchmark, not peer-reviewed state-of-the-art claim.",
            },
            {
                "claim_id": "real_world_exploits",
                "paper_claim": (
                    "MIESC detects 9/11 real-world DeFi exploits (81.8% recall, "
                    "95% Wilson CI [52%, 95%]) across $1.59B in evaluated losses."
                ),
                "value": real_world_exploits["aggregate"],
                "unit": "recall",
                "source_artifact": str(REAL_WORLD_EXPLOITS.relative_to(ROOT)),
                "status": "supported_with_note",
                "notes": (
                    "Small manually curated exploit sample; used as indicative external-validity "
                    "evidence rather than a definitive population estimate."
                ),
            },
            # --- RIBCi camera-ready additive artifacts (2026-10-16) ---
            {
                "claim_id": "ablation_llm_free",
                "paper_claim": (
                    "LLM-free ablation: static 82.5% (118/143), +own detectors 93.0% "
                    "(133/143), +intelligence 97.9% (140/143); each step gains contracts "
                    "without losing any."
                ),
                "value": {
                    "l1_static": load_json(RESULTS / "paper1_ablation_l1_raw_20261015.json")[
                        "aggregate"
                    ],
                    "l1_6_7": load_json(RESULTS / "paper1_ablation_l167_raw_20261015.json")[
                        "aggregate"
                    ],
                    "l1_6_7_intel": load_json(RESULTS / "paper1_ablation_l167_intel_20261015.json")[
                        "aggregate"
                    ],
                },
                "unit": "recall over 143 contracts",
                "source_artifact": [
                    "benchmarks/results/paper1_ablation_l1_raw_20261015.json",
                    "benchmarks/results/paper1_ablation_l167_raw_20261015.json",
                    "benchmarks/results/paper1_ablation_l167_intel_20261015.json",
                ],
                "command": "python benchmarks/paper1_ablation_summary.py",
                "date": CAMERA_READY_DATE,
                "status": "supported",
            },
            {
                "claim_id": "evmbench_null_control",
                "paper_claim": (
                    "A contract-agnostic null control credits 50% (60/120) under the "
                    "lenient matcher; the control-resistant subset is 60 vulnerabilities."
                ),
                "value": {
                    "credited": 60,
                    "total": 120,
                    "pct": 0.5,
                    "control_resistant_subset": 60,
                },
                "unit": "lenient-matched vulnerabilities",
                "source_artifact": [
                    "benchmarks/evmbench_matcher_null_control.py",
                    "benchmarks/results/evmbench/evmbench_claude46_40_FINAL.json",
                ],
                "command": (
                    "python benchmarks/evmbench_matcher_null_control.py "
                    "benchmarks/results/evmbench/evmbench_claude46_40_FINAL.json "
                    "--ensemble benchmarks/results/evmbench/evmbench_ensemble_40.json"
                ),
                "date": CAMERA_READY_DATE,
                "status": "supported",
                "notes": "Computed, not stored: the 4 generic findings match 60/120 vulns.",
            },
            {
                "claim_id": "evmbench_same_run_protocols",
                "paper_claim": (
                    "One Claude run scored under every protocol: lenient 88.3% (106/120), "
                    "control-resistant 78.3% (47/60); official judge GPT-4o 21.4% (25/117) "
                    "and GPT-5 27.4% (32/117); judge agreement 104/117; of 32 GPT-5-detected "
                    "vulns, 30 are also credited by the lenient matcher."
                ),
                "value": {
                    **load_json(EVMBENCH / "same_run_claude_20261016" / "summary.json"),
                    "gpt5_lenient_cross": "30/32",
                },
                "unit": "mixed protocols",
                "source_artifact": [
                    "benchmarks/results/evmbench/same_run_claude_20261016/summary.json",
                    "benchmarks/results/evmbench/same_run_claude_20261016/verdicts.json",
                ],
                "command": (
                    "python benchmarks/evmbench_same_run_protocols.py --model claude "
                    "--judges gpt-4o,gpt-5 "
                    "--out benchmarks/results/evmbench/same_run_claude_20261016"
                ),
                "date": CAMERA_READY_DATE,
                "status": "supported",
            },
            {
                "claim_id": "fp_filter_effect",
                "paper_claim": (
                    "The production FP filter removes 207 of 1,263 false positives (16%) "
                    "with no true-positive loss, raising finding-level precision from "
                    "13.3% to 15.5%."
                ),
                "value": {
                    k: load_json(RESULTS / "smartbugs_fp_filter_effect_20260710.json")[k]
                    for k in ("raw_baseline", "filtered_production", "delta")
                },
                "unit": "finding-level false positives",
                "source_artifact": "benchmarks/results/smartbugs_fp_filter_effect_20260710.json",
                "command": "python benchmarks/smartbugs_fp_filter_effect_20260710.py",
                "date": CAMERA_READY_DATE,
                "status": "supported",
            },
        ],
    }


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def main() -> None:
    ensemble = generate_ensemble()
    write_json(EVMBENCH / "evmbench_ensemble_40.json", ensemble)
    write_json(RESULTS / "paper1_claims_matrix.json", generate_claims_matrix(ensemble))

    print(
        "EVMBench ensemble: "
        f"{ensemble['total_detected']}/{ensemble['total_vulns']} "
        f"({ensemble['recall']:.1%})"
    )
    print("Wrote benchmarks/results/evmbench/evmbench_ensemble_40.json")
    print("Wrote benchmarks/results/paper1_claims_matrix.json")


if __name__ == "__main__":
    main()
