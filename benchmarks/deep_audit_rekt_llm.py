#!/usr/bin/env python3
"""
DeepAuditAgent benchmark on the Rekt corpus — WITH multi-LLM consensus.

Forces two distinct Ollama models for the code_analysis and verification
use cases so the v5.1.6 Bloque-3 consensus mechanism actually fires
(otherwise primary == verifier and we get consensus='single_opinion').

Measures, for each CRITICAL finding:
  - consensus verdict  (agree_confirmed / agree_rejected / disagreement / single_opinion)
  - confidence delta applied (+0.20 / -0.30 / -0.10 / 0)
  - needs_manual_review flag

This is the SLOW benchmark — expect ~30 seconds per CRITICAL finding.

Usage:
    python3 benchmarks/deep_audit_rekt_llm.py --primary qwen2.5-coder:14b \\
                                              --verifier deepseek-coder:33b \\
                                              --max 3
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig  # noqa: E402
from benchmarks.deep_audit_rekt import load_targets, vuln_class_match  # noqa: E402


def run(
    primary_model: str,
    verifier_model: str,
    timeout: int,
    max_targets: int,
) -> Dict[str, Any]:
    targets = load_targets()
    if max_targets:
        targets = targets[:max_targets]

    config = DeepAuditConfig(
        timeout_seconds=timeout,
        max_iterations=3,
        enable_llm=True,               # THE key flag
        enable_rag=True,
        enable_taint=True,
        enable_call_graph=False,
        enable_exploit_chains=False,   # speed — don't need chains for this benchmark
    )
    agent = DeepAuditAgent(config=config)

    # Force two distinct models so consensus actually happens
    def _mock_get_model(use_case: str) -> str:
        if use_case == "verification":
            return verifier_model
        return primary_model

    rows: List[Dict[str, Any]] = []
    totals = {
        "targets": len(targets),
        "critical_findings": 0,
        "consensus_calls": 0,
        "agree_confirmed": 0,
        "agree_rejected": 0,
        "disagreement": 0,
        "single_opinion": 0,
        "needs_manual_review": 0,
        "detected_by_class": 0,
        "time_total_s": 0.0,
    }

    # Apply the model mock for the whole benchmark run
    with patch("src.core.llm_config.get_model", side_effect=_mock_get_model):
        for i, t in enumerate(targets, 1):
            name = t.get("name", Path(t["path"]).stem)
            expected = t.get("vulnerability_class", t.get("vulnerability", ""))
            print(f"\n[{i}/{len(targets)}] {name}  ({expected})")
            start = time.time()
            try:
                result = agent.analyze(t["path"])
            except Exception as e:
                print(f"  ERROR: {e}")
                rows.append({"name": name, "error": str(e)})
                continue
            elapsed = time.time() - start

            findings = result.get("findings", [])
            # HIGH + CRITICAL match the same gate the agent applies in Phase 3
            criticals = [
                f for f in findings
                if f.get("severity", "").lower() in ("critical", "high")
            ]
            by_consensus: Counter = Counter()
            review_count = 0

            for f in criticals:
                inv = f.get("investigation") or {}
                cons = inv.get("llm_consensus")
                if cons:
                    by_consensus[cons.get("consensus", "?")] += 1
                    if cons.get("needs_manual_review"):
                        review_count += 1

            detected = vuln_class_match(findings, expected)
            row = {
                "name": name,
                "expected": expected,
                "path": t["path"],
                "detected_by_class": bool(detected),
                "critical_count": len(criticals),
                "consensus_breakdown": dict(by_consensus),
                "needs_manual_review_in_criticals": review_count,
                "elapsed_s": round(elapsed, 1),
            }
            rows.append(row)

            totals["critical_findings"] += len(criticals)
            totals["consensus_calls"] += sum(by_consensus.values())
            totals["agree_confirmed"] += by_consensus.get("agree_confirmed", 0)
            totals["agree_rejected"] += by_consensus.get("agree_rejected", 0)
            totals["disagreement"] += by_consensus.get("disagreement", 0)
            totals["single_opinion"] += by_consensus.get("single_opinion", 0)
            totals["needs_manual_review"] += review_count
            totals["time_total_s"] += elapsed
            if detected:
                totals["detected_by_class"] += 1

            mark = "✓" if detected else "✗"
            print(
                f"  {mark} criticals={len(criticals)}  consensus={dict(by_consensus)}  "
                f"review={review_count}  {elapsed:.1f}s"
            )

    totals["time_total_s"] = round(totals["time_total_s"], 1)
    totals["recall_by_class"] = (
        round(totals["detected_by_class"] / totals["targets"] * 100, 1)
        if totals["targets"] else 0.0
    )
    return {
        "primary_model": primary_model,
        "verifier_model": verifier_model,
        "totals": totals,
        "rows": rows,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--primary", default="qwen2.5-coder:14b")
    parser.add_argument("--verifier", default="deepseek-coder:33b")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--max", type=int, default=0)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    print(f"Primary  (code_analysis): {args.primary}")
    print(f"Verifier (verification):  {args.verifier}")
    print(f"Timeout per contract:     {args.timeout}s")
    print(f"Max targets:              {args.max or 'all'}")
    print()

    report = run(args.primary, args.verifier, args.timeout, args.max)
    t = report["totals"]

    print("\n" + "=" * 60)
    print("  DeepAuditAgent LLM consensus — Rekt benchmark")
    print("=" * 60)
    print(f"  Primary model     : {report['primary_model']}")
    print(f"  Verifier model    : {report['verifier_model']}")
    print(f"  Contracts         : {t['targets']}")
    print(f"  Detection by class: {t['detected_by_class']}/{t['targets']} ({t['recall_by_class']}%)")
    print(f"  Criticals total   : {t['critical_findings']}")
    print(f"  Consensus calls   : {t['consensus_calls']}")
    print(f"    agree_confirmed : {t['agree_confirmed']}")
    print(f"    agree_rejected  : {t['agree_rejected']}")
    print(f"    disagreement    : {t['disagreement']}")
    print(f"    single_opinion  : {t['single_opinion']}")
    print(f"  Needs manual rev. : {t['needs_manual_review']}")
    print(f"  Total time        : {t['time_total_s']}s")

    out_path = Path(args.output) if args.output else (
        PROJECT_ROOT / "benchmarks" / "results"
        / f"deep_audit_rekt_llm_{time.strftime('%Y%m%d_%H%M%S')}.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    print(f"\n  Detailed results: {out_path}")


if __name__ == "__main__":
    main()
