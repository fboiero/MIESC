#!/usr/bin/env python3
"""Generate Paper 2 claim matrix from local remediation artifacts."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIX_EVAL = ROOT / "benchmarks/results/fix_eval_results.json"
OUT = ROOT / "benchmarks/results/paper2_claims_matrix.json"
PATCH_TRANSFORMS_OUT = ROOT / "benchmarks/results/paper2_patch_quality_by_transform.json"
COMPILE_FAILURES_OUT = ROOT / "benchmarks/results/paper2_compile_failure_by_category.json"
COMPILE_TAXONOMY = ROOT / "benchmarks/results/paper2_compile_failure_taxonomy.json"
EXPERIMENT_AUDIT = ROOT / "benchmarks/results/paper2_experiment_audit.json"

METRIC_DEFINITIONS = {
    "fix_applied": (
        "The patcher produced a modified Solidity source file for at least one "
        "fixable HIGH/CRITICAL finding."
    ),
    "fix_compiles": (
        "The patched source compiled as a standalone file, without restoring the "
        "original project dependency tree."
    ),
    "vuln_eliminated": (
        "A re-scan reported fewer HIGH/CRITICAL findings for the target category."
    ),
    "no_regression": (
        "The patched contract did not materially increase finding count under the "
        "same scanner; this is not semantic equivalence."
    ),
}

CATEGORY_TO_TRANSFORM = {
    "access_control": "onlyOwner_modifier_insertion",
    "arithmetic": "safemath_or_checked_arithmetic_comment",
    "bad_randomness": "generic_manual_remediation_block",
    "denial_of_service": "generic_manual_remediation_block",
    "front_running": "generic_manual_remediation_block",
    "other": "generic_manual_remediation_block",
    "reentrancy": "reentrancy_guard_injection",
    "short_addresses": "generic_manual_remediation_block",
    "time_manipulation": "generic_manual_remediation_block",
    "unchecked_low_level_calls": "require_success_wrapper",
}


def pct(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def reproducible_generated_at() -> str:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def sum_metrics(rows: list[dict[str, int]]) -> dict[str, int]:
    keys = ["contracts", "fix_applied", "fix_compiles", "vuln_eliminated", "no_regression", "fix_failed"]
    return {key: sum(row.get(key, 0) for row in rows) for key in keys}


def build_patch_quality_by_transform(fix_eval: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = {}
    for category, metrics in fix_eval["by_category"].items():
        transform = CATEGORY_TO_TRANSFORM.get(category, "unclassified")
        entry = grouped.setdefault(transform, {"categories": [], "metrics": []})
        entry["categories"].append(category)
        entry["metrics"].append(metrics)

    transforms = {}
    for transform, entry in sorted(grouped.items()):
        metrics = sum_metrics(entry["metrics"])
        applied = metrics["fix_applied"]
        transforms[transform] = {
            "status": "derived_from_category_mapping",
            "categories": sorted(entry["categories"]),
            "metrics": metrics,
            "rates": {
                "application": pct(metrics["fix_applied"], metrics["contracts"]),
                "standalone_compilation": pct(metrics["fix_compiles"], applied),
                "vulnerability_elimination": pct(metrics["vuln_eliminated"], applied),
                "no_regression": pct(metrics["no_regression"], applied),
            },
        }

    return {
        "artifact": "paper2_patch_quality_by_transform",
        "generated_at": reproducible_generated_at(),
        "source_artifact": str(FIX_EVAL.relative_to(ROOT)),
        "scope": "Paper 2 remediation only; does not modify Paper 1 detection evidence.",
        "limitations": (
            "Transform classes are derived from SmartBugs categories and current patcher "
            "behavior, not from per-finding AST diffs."
        ),
        "transforms": transforms,
    }


def build_compile_failure_by_category(fix_eval: dict[str, Any]) -> dict[str, Any]:
    categories = {}
    total_failures = 0
    for category, metrics in sorted(fix_eval["by_category"].items()):
        applied = metrics["fix_applied"]
        compile_failures = max(applied - metrics["fix_compiles"], 0)
        total_failures += compile_failures
        categories[category] = {
            "status": "derived_from_fix_eval_counts",
            "fix_applied": applied,
            "fix_compiles": metrics["fix_compiles"],
            "compile_failures": compile_failures,
            "compile_failure_rate": pct(compile_failures, applied),
        }

    return {
        "artifact": "paper2_compile_failure_by_category",
        "generated_at": reproducible_generated_at(),
        "source_artifact": str(FIX_EVAL.relative_to(ROOT)),
        "scope": "Standalone compilation failures for Paper 2 patched artifacts.",
        "limitations": (
            "This artifact identifies where compilation fails by category. It does not "
            "classify root causes such as missing imports, Solidity version mismatch, "
            "or undefined symbols because fix_eval_results.json does not preserve "
            "per-contract compiler stderr."
        ),
        "totals": {
            "fix_applied": fix_eval["totals"]["fix_applied"],
            "fix_compiles": fix_eval["totals"]["fix_compiles"],
            "compile_failures": total_failures,
            "compile_failure_rate": pct(total_failures, fix_eval["totals"]["fix_applied"]),
        },
        "by_category": categories,
    }


def main() -> None:
    fix_eval = load_json(FIX_EVAL)
    compile_taxonomy = load_json(COMPILE_TAXONOMY) if COMPILE_TAXONOMY.exists() else None
    experiment_audit = load_json(EXPERIMENT_AUDIT) if EXPERIMENT_AUDIT.exists() else None
    totals = fix_eval["totals"]

    contracts = totals["contracts"]
    applied = totals["fix_applied"]
    compiles = totals["fix_compiles"]
    eliminated = totals["vuln_eliminated"]
    no_regression = totals["no_regression"]
    fix_failed = totals["fix_failed"]

    claims = [
        {
            "claim_id": "fix_application_rate",
            "paper_claim": f"MIESC applies fixes to {applied} of {contracts} SmartBugs contracts.",
            "source_artifact": str(FIX_EVAL.relative_to(ROOT)),
            "status": "supported",
            "scope": "corpus_wide",
            "paper1_dependency": None,
            "metric_definition": METRIC_DEFINITIONS["fix_applied"],
            "unit": "contracts",
            "value": {
                "fix_applied": applied,
                "contracts": contracts,
                "rate": pct(applied, contracts),
            },
        },
        {
            "claim_id": "standalone_compilation_rate",
            "paper_claim": f"{compiles} of {applied} patched contracts compile standalone.",
            "source_artifact": str(FIX_EVAL.relative_to(ROOT)),
            "status": "supported",
            "scope": "corpus_wide",
            "paper1_dependency": None,
            "metric_definition": METRIC_DEFINITIONS["fix_compiles"],
            "unit": "patched contracts",
            "value": {
                "fix_compiles": compiles,
                "fix_applied": applied,
                "rate": pct(compiles, applied),
            },
        },
        {
            "claim_id": "vulnerability_elimination_rate",
            "paper_claim": (
                f"{eliminated} of {applied} patched contracts reduce HIGH/CRITICAL "
                "findings on re-scan."
            ),
            "source_artifact": str(FIX_EVAL.relative_to(ROOT)),
            "status": "supported",
            "scope": "corpus_wide_bounded_rescan",
            "paper1_dependency": None,
            "metric_definition": METRIC_DEFINITIONS["vuln_eliminated"],
            "unit": "patched contracts",
            "value": {
                "vuln_eliminated": eliminated,
                "fix_applied": applied,
                "rate": pct(eliminated, applied),
            },
        },
        {
            "claim_id": "no_regression_rate",
            "paper_claim": (
                f"No-regression criterion holds for {no_regression} of {applied} "
                "patched contracts."
            ),
            "source_artifact": str(FIX_EVAL.relative_to(ROOT)),
            "status": "supported_with_note",
            "scope": "corpus_wide_bounded_rescan",
            "paper1_dependency": None,
            "metric_definition": METRIC_DEFINITIONS["no_regression"],
            "notes": (
                "Regression is measured by finding-count growth on re-scan, allowing up to "
                "two extra informational findings caused by inline guard code."
            ),
            "unit": "patched contracts",
            "value": {
                "no_regression": no_regression,
                "fix_applied": applied,
                "rate": pct(no_regression, applied),
            },
        },
        {
            "claim_id": "fix_failed_count",
            "paper_claim": "The recorded fix evaluation reports zero failed fix applications after filtering.",
            "source_artifact": str(FIX_EVAL.relative_to(ROOT)),
            "status": "supported_with_note",
            "scope": "corpus_wide",
            "paper1_dependency": None,
            "notes": "Contracts without fixable HIGH/CRITICAL findings are skipped before fix application.",
            "unit": "contracts",
            "value": fix_failed,
        },
        {
            "claim_id": "per_category_patch_metrics",
            "paper_claim": "Per-category patch metrics are derived from fix_eval_results.json.",
            "source_artifact": str(FIX_EVAL.relative_to(ROOT)),
            "status": "supported",
            "scope": "corpus_wide",
            "paper1_dependency": None,
            "unit": "mixed metrics",
            "value": fix_eval["by_category"],
        },
        {
            "claim_id": "compile_failure_taxonomy",
            "paper_claim": (
                "Standalone compile failures are classified from preserved solc stderr "
                "when paper2_compile_failure_taxonomy.json is present."
            ),
            "source_artifact": str(COMPILE_TAXONOMY.relative_to(ROOT)),
            "status": "supported" if compile_taxonomy else "missing_optional_artifact",
            "scope": "failed_patched_contracts",
            "paper1_dependency": None,
            "unit": "compiler failure classes",
            "value": (
                compile_taxonomy.get("compile_failure_taxonomy")
                if compile_taxonomy
                else None
            ),
        },
        {
            "claim_id": "experiment_validity_audit",
            "paper_claim": (
                "Paper 2 reports original-vs-patched standalone compilation, joint "
                "success metrics, and no-regression threshold sensitivity."
            ),
            "source_artifact": str(EXPERIMENT_AUDIT.relative_to(ROOT)),
            "status": "supported" if experiment_audit else "missing_optional_artifact",
            "scope": "experiment_validity",
            "paper1_dependency": None,
            "unit": "validity audit metrics",
            "value": (
                {
                    "totals": experiment_audit.get("totals"),
                    "rates": experiment_audit.get("rates"),
                    "compile_transitions": experiment_audit.get("compile_transitions"),
                    "joint_success_metrics": experiment_audit.get("joint_success_metrics"),
                    "no_regression_sensitivity": experiment_audit.get("no_regression_sensitivity", {}).get("thresholds"),
                }
                if experiment_audit
                else None
            ),
        },
        {
            "claim_id": "paper1_detection_input",
            "paper_claim": (
                "Paper 2 inherits detection evidence from Paper 1: SmartBugs full-corpus "
                "reproducible recall 95.8% and EVMBench local high-severity ensemble "
                "recall 92.5%."
            ),
            "source_artifact": "paper/PAPER1_REPRODUCIBILITY.md; benchmarks/results/paper1_claims_matrix.json",
            "status": "inherited_from_paper1",
            "scope": "detection_input_only",
            "paper1_dependency": {
                "smartbugs_f1": 0.3604,
                "smartbugs_local_ollama_followup_recall": 0.979,
                "smartbugs_precision": 0.2219,
                "smartbugs_recall": 0.958,
                "evmbench_recall": 0.925,
                "rule": (
                    "Paper 2 inherits the 95.8% machine-readable SmartBugs detection "
                    "evidence; the 97.9% local Ollama follow-up is reported by Paper 1 "
                    "but is not used to recalculate remediation metrics."
                ),
            },
            "unit": "detection metrics",
            "value": None,
        },
        {
            "claim_id": "no_semantic_equivalence_claim",
            "paper_claim": "Paper 2 does not claim full semantic equivalence of patched contracts.",
            "source_artifact": str(FIX_EVAL.relative_to(ROOT)),
            "status": "limitation",
            "scope": "construct_validity",
            "paper1_dependency": None,
            "unit": "limitation",
            "value": None,
        },
        {
            "claim_id": "no_corpus_wide_formal_proof_claim",
            "paper_claim": "Paper 2 does not claim corpus-wide formal proof coverage.",
            "source_artifact": str(FIX_EVAL.relative_to(ROOT)),
            "status": "limitation",
            "scope": "artifact_granularity",
            "paper1_dependency": None,
            "unit": "limitation",
            "value": None,
        },
        {
            "claim_id": "no_dependency_aware_compilation_claim",
            "paper_claim": "Paper 2 currently reports standalone compilation, not dependency-aware compilation.",
            "source_artifact": str(FIX_EVAL.relative_to(ROOT)),
            "status": "limitation",
            "scope": "compilation_model",
            "paper1_dependency": None,
            "unit": "limitation",
            "value": None,
        },
    ]

    payload = {
        "artifact": "paper2_claims_matrix",
        "generated_at": reproducible_generated_at(),
        "purpose": "Trace Paper 2 remediation claims to local artifacts.",
        "paper1_compatibility_rule": (
            "Paper 2 may inherit Paper 1 detection claims but must not regenerate or "
            "change Paper 1 detection evidence."
        ),
        "claims": claims,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    PATCH_TRANSFORMS_OUT.write_text(
        json.dumps(build_patch_quality_by_transform(fix_eval), indent=2) + "\n",
        encoding="utf-8",
    )
    COMPILE_FAILURES_OUT.write_text(
        json.dumps(build_compile_failure_by_category(fix_eval), indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        "Paper 2 fix claims: "
        f"{applied}/{contracts} applied, "
        f"{compiles}/{applied} compiled, "
        f"{eliminated}/{applied} eliminated"
    )
    print(f"Wrote {OUT.relative_to(ROOT)}")
    print(f"Wrote {PATCH_TRANSFORMS_OUT.relative_to(ROOT)}")
    print(f"Wrote {COMPILE_FAILURES_OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
