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

SMARTBUGS_LATEST = RESULTS / "paper1_smartbugs_eval_layers_1_6_7.json"
EVMBENCH_STATIC = EVMBENCH / "evmbench_static_40.json"


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


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


def smartbugs_metrics(data: dict) -> dict:
    """Normalize SmartBugs evaluator JSONs from historical and corpus runners."""
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
            "layers_evaluated": data.get("experiment_card", {}).get("layers_evaluated"),
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
        "layers_evaluated": data.get("configuration", {}).get("layers"),
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
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": (
            "Union over matched vulnerabilities keyed by audit_id:vulnerability_id "
            "from the four provider result files. A vulnerability is counted as "
            "detected if any provider marks it as matched=true."
        ),
        "input_files": {
            name: str(path.relative_to(ROOT)) for name, path in PROVIDERS.items()
        },
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
    smartbugs_summary = smartbugs_metrics(smartbugs)
    evmbench_static = load_json(EVMBENCH_STATIC)
    provider_data = {name: load_json(path) for name, path in PROVIDERS.items()}

    return {
        "artifact": "paper1_claims_matrix",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "purpose": "Trace Paper 1 quantitative claims to local artifacts or external sources.",
        "claims": [
            {
                "claim_id": "smartbugs_latest_reproducible",
                "paper_claim": "MIESC latest local SmartBugs run reports 93.7% recall.",
                "value": smartbugs_summary,
                "unit": "recall",
                "source_artifact": str(SMARTBUGS_LATEST.relative_to(ROOT)),
                "status": "supported",
                "notes": (
                    "Fresh 2026-05-06 miesc evaluate corpus run over 143 SmartBugs "
                    "contracts using layers 1,6,7 after Slither solc selection "
                    "was fixed to respect Solidity pragma ranges. Layer 6 activates "
                    "SmartBugs-specific detectors, DA-GNN, SmartBugs-ML, SmartGuard "
                    "availability, and related specialized analyzers."
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
                "source_artifact": ensemble["provider_summary"]["ollama_qwen2_5_coder_32b"]["source"],
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
                    "claude_sonnet_4_6": metrics_from_result(
                        provider_data["claude_sonnet_4_6"]
                    ),
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
                    *[
                        str(path.relative_to(ROOT))
                        for path in PROVIDERS.values()
                    ],
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
