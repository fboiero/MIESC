#!/usr/bin/env python3
"""Audit Paper 2 remediation experiment for reviewer-facing validity checks."""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks.fix_eval import compile_contract  # noqa: E402

DETAILS = ROOT / "benchmarks/results/paper2_compile_failure_taxonomy.json"
OUT = ROOT / "benchmarks/results/paper2_experiment_audit.json"


def pct(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def compile_originals(contracts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    results = {}
    for row in contracts:
        contract = row["contract"]
        results[contract] = compile_contract(ROOT / contract)
    return results


def threshold_counts(contracts: list[dict[str, Any]], thresholds: list[int]) -> dict[str, Any]:
    counts = {str(threshold): 0 for threshold in thresholds}
    eligible = 0
    missing = 0
    deltas = []

    for row in contracts:
        before = row.get("total_findings_before")
        after = row.get("total_findings_after")
        if before is None or after is None:
            missing += 1
            continue
        eligible += 1
        delta = after - before
        deltas.append(delta)
        for threshold in thresholds:
            if delta <= threshold:
                counts[str(threshold)] += 1

    return {
        "eligible_contracts": eligible,
        "missing_rescan_counts": missing,
        "thresholds": {
            str(threshold): {
                "passing_contracts": counts[str(threshold)],
                "rate": pct(counts[str(threshold)], eligible),
            }
            for threshold in thresholds
        },
        "finding_delta_distribution": dict(sorted(Counter(deltas).items())),
    }


def main() -> None:
    details = load_json(DETAILS)
    contracts = details["contracts"]
    original_compile = compile_originals(contracts)

    transitions: Counter[str] = Counter()
    joint: Counter[str] = Counter()
    by_category: dict[str, Counter[str]] = defaultdict(Counter)
    original_failure_taxonomy: Counter[str] = Counter()

    for row in contracts:
        contract = row["contract"]
        category = row["category"]
        original = original_compile[contract]
        patched = row["compile"]
        orig_ok = original["compiles"]
        patched_ok = patched["compiles"]
        eliminated = bool(row.get("vuln_eliminated"))
        no_regression = bool(row.get("no_regression"))

        transition = f"original_{'compiles' if orig_ok else 'fails'}__patched_{'compiles' if patched_ok else 'fails'}"
        transitions[transition] += 1
        by_category[category][transition] += 1

        if not orig_ok:
            original_failure_taxonomy[original["failure_class"]] += 1

        if patched_ok and eliminated:
            joint["compile_and_eliminate"] += 1
        if patched_ok and no_regression:
            joint["compile_and_no_regression"] += 1
        if eliminated and no_regression:
            joint["eliminate_and_no_regression"] += 1
        if patched_ok and eliminated and no_regression:
            joint["compile_eliminate_and_no_regression"] += 1

    applied = len(contracts)
    original_compiles = sum(1 for result in original_compile.values() if result["compiles"])
    patched_compiles = sum(1 for row in contracts if row["compile"]["compiles"])
    orig_compile_rows = [row for row in contracts if original_compile[row["contract"]]["compiles"]]
    patched_compiles_given_original = sum(1 for row in orig_compile_rows if row["compile"]["compiles"])

    payload = {
        "artifact": "paper2_experiment_audit",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_artifact": str(DETAILS.relative_to(ROOT)),
        "scope": "Paper 2 remediation experiment validity audit; does not modify Paper 1 detection evidence.",
        "totals": {
            "patched_contracts": applied,
            "original_standalone_compiles": original_compiles,
            "patched_standalone_compiles": patched_compiles,
            "patched_compiles_given_original_compiles": patched_compiles_given_original,
        },
        "rates": {
            "original_standalone_compilation": pct(original_compiles, applied),
            "patched_standalone_compilation": pct(patched_compiles, applied),
            "patched_compilation_conditional_on_original_compilation": pct(
                patched_compiles_given_original, original_compiles
            ),
        },
        "compile_transitions": dict(sorted(transitions.items())),
        "original_compile_failure_taxonomy": dict(sorted(original_failure_taxonomy.items())),
        "joint_success_metrics": {
            key: {
                "count": joint[key],
                "rate": pct(joint[key], applied),
            }
            for key in [
                "compile_and_eliminate",
                "compile_and_no_regression",
                "eliminate_and_no_regression",
                "compile_eliminate_and_no_regression",
            ]
        },
        "no_regression_sensitivity": threshold_counts(contracts, [0, 1, 2, 5, 10]),
        "by_category_compile_transitions": {
            category: dict(sorted(counts.items()))
            for category, counts in sorted(by_category.items())
        },
        "limitations": [
            "Original and patched compilation are both standalone checks; neither restores project dependencies.",
            "No-regression sensitivity is based on scanner finding-count deltas, not semantic equivalence.",
            "Compiler failure classes are heuristic labels derived from solc stdout/stderr.",
        ],
    }

    OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUT.relative_to(ROOT)}")
    print(
        "Original standalone compilation: "
        f"{original_compiles}/{applied}; patched: {patched_compiles}/{applied}; "
        "patched given original compiled: "
        f"{patched_compiles_given_original}/{original_compiles}"
    )


if __name__ == "__main__":
    main()
