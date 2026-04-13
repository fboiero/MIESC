#!/usr/bin/env python3
"""
DeepAuditAgent benchmark on the Rekt exploit corpus.

Measures the v5.1.6 Bloque-3 features that are invisible to the
static-detector path: multi-LLM consensus outcomes, properties auto-generated
for access-control findings, DeFi-confirmed oracle findings, and the
manual-review flag distribution.

Only runs against exploits whose contract fixture exists locally under
data/datasets/rekt_exploits/contracts/.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig  # noqa: E402


GT_PATH = PROJECT_ROOT / "data" / "datasets" / "rekt_exploits" / "exploits_ground_truth.json"
CONTRACTS_DIR = PROJECT_ROOT / "data" / "datasets" / "rekt_exploits" / "contracts"
RESULTS_DIR = PROJECT_ROOT / "benchmarks" / "results"


def load_targets() -> List[Dict[str, Any]]:
    """Return exploits that have a real fixture on disk."""
    data = json.loads(GT_PATH.read_text())
    targets = []
    for e in data["exploits"]:
        contract = e.get("contract_file") or e.get("contract")
        if not contract:
            continue
        path = PROJECT_ROOT / "data" / "datasets" / "rekt_exploits" / contract
        if not path.exists():
            # Sometimes the contract path is relative to `contracts/`
            alt = CONTRACTS_DIR / Path(contract).name
            if alt.exists():
                path = alt
            else:
                continue
        targets.append({**e, "path": str(path)})
    return targets


def vuln_class_match(findings: List[Dict[str, Any]], expected: str) -> bool:
    """Return True if ANY finding plausibly matches the expected vulnerability class."""
    norm = (expected or "").lower().replace("_", " ").replace("-", " ")
    keywords = {
        "reentrancy": ["reentran", "external call", "cei"],
        "access control": ["access", "auth", "owner", "privileg", "tx.origin", "suicid"],
        "flash loan": ["flash", "loan"],
        "flash loan governance": ["flash", "governance"],
        "oracle manipulation": ["oracle", "price", "manipul", "twap"],
        "input validation": ["input", "valid", "unchecked"],
        "arithmetic": ["arithmetic", "overflow", "underflow", "integer"],
        "initialization": ["init", "initializ"],
        "signature verification": ["signature", "ecdsa", "ecrecover", "merkle"],
    }
    needles = keywords.get(norm, [norm])
    for f in findings:
        hay = " ".join(
            str(f.get(k, "")) for k in ("type", "title", "check", "description", "category")
        ).lower()
        if any(n in hay for n in needles):
            return True
    return False


def run_benchmark(timeout: int = 120, max_targets: int = 0, enable_llm: bool = False) -> Dict[str, Any]:
    targets = load_targets()
    if max_targets:
        targets = targets[:max_targets]

    config = DeepAuditConfig(
        timeout_seconds=timeout,
        max_iterations=3,
        enable_llm=enable_llm,            # local LLM is slow; default OFF
        enable_rag=True,
        enable_taint=True,
        enable_call_graph=False,          # skip heavy call-graph building for throughput
        enable_exploit_chains=True,
        max_workers=2,
    )

    agent = DeepAuditAgent(config=config)

    totals = {
        "targets": len(targets),
        "detected_by_class": 0,
        "findings_total": 0,
        "needs_manual_review_total": 0,
        "properties_generated_total": 0,
        "defi_confirmed_total": 0,
        "mitigated_total": 0,
        "time_total_s": 0.0,
    }
    rows = []

    for i, t in enumerate(targets, 1):
        name = t.get("name", Path(t["path"]).stem)
        expected = t.get("vulnerability_class", t.get("vulnerability", ""))
        print(f"\n[{i}/{len(targets)}] {name}  ({expected})")
        print(f"  -> {t['path']}")
        start = time.time()
        try:
            result = agent.analyze(t["path"])
        except Exception as e:
            print(f"  ERROR: {e}")
            rows.append({"name": name, "error": str(e)})
            continue
        elapsed = time.time() - start

        findings = result.get("findings", [])
        detected = vuln_class_match(findings, expected)

        phase3 = result.get("phases", {}).get("deep_investigation", {})
        needs_review = phase3.get("needs_manual_review", 0)
        properties = phase3.get("properties_generated", 0)
        defi = phase3.get("defi_confirmed", 0)
        mitigated = phase3.get("mitigated", 0)

        row = {
            "name": name,
            "expected": expected,
            "path": t["path"],
            "detected_by_class": bool(detected),
            "findings_count": len(findings),
            "needs_manual_review": needs_review,
            "properties_generated": properties,
            "defi_confirmed": defi,
            "mitigated": mitigated,
            "elapsed_s": round(elapsed, 2),
        }
        rows.append(row)

        totals["findings_total"] += len(findings)
        totals["needs_manual_review_total"] += needs_review
        totals["properties_generated_total"] += properties
        totals["defi_confirmed_total"] += defi
        totals["mitigated_total"] += mitigated
        totals["time_total_s"] += elapsed
        if detected:
            totals["detected_by_class"] += 1

        mark = "✓" if detected else "✗"
        print(
            f"  {mark} {len(findings)} findings, "
            f"{needs_review} review / {properties} properties / {defi} DeFi / {mitigated} mitigated "
            f"— {elapsed:.1f}s"
        )

    totals["recall_by_class"] = (
        round(totals["detected_by_class"] / totals["targets"] * 100, 1) if totals["targets"] else 0.0
    )
    totals["time_total_s"] = round(totals["time_total_s"], 1)

    return {"totals": totals, "rows": rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=120, help="Per-contract timeout (s)")
    parser.add_argument("--max", type=int, default=0, help="Max contracts (0=all available)")
    parser.add_argument("--enable-llm", action="store_true", help="Enable multi-LLM consensus (slow)")
    parser.add_argument("--output", default=None, help="Write JSON to this path")
    args = parser.parse_args()

    report = run_benchmark(timeout=args.timeout, max_targets=args.max, enable_llm=args.enable_llm)

    # Summary
    t = report["totals"]
    print("\n" + "=" * 60)
    print("  DeepAuditAgent — Rekt benchmark summary")
    print("=" * 60)
    print(f"  Contracts analyzed      : {t['targets']}")
    print(f"  Detection by class      : {t['detected_by_class']}/{t['targets']} ({t['recall_by_class']}%)")
    print(f"  Findings (sum)          : {t['findings_total']}")
    print(f"  Needs manual review     : {t['needs_manual_review_total']}")
    print(f"  Properties generated    : {t['properties_generated_total']}")
    print(f"  DeFi confirmed          : {t['defi_confirmed_total']}")
    print(f"  Mitigated (RAG)         : {t['mitigated_total']}")
    print(f"  Total time              : {t['time_total_s']}s")
    print()

    out_path = Path(args.output) if args.output else (
        RESULTS_DIR / f"deep_audit_rekt_{time.strftime('%Y%m%d_%H%M%S')}.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    print(f"  Detailed results: {out_path}")


if __name__ == "__main__":
    main()
