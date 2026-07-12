#!/usr/bin/env python3
"""
Real per-finding measurement on the FULL SmartBugs-curated corpus, using MIESC's own
pure-Python intelligence/pattern detector (src/core/intelligence.detect_zero_recall_
categories) — no solc/compilation needed (Slither and Aderyn are blocked in this env:
solc-select is broken and only solc 0.8.x is present, which cannot compile the legacy
0.4.x corpus; Aderyn panics on the legacy AST).

Each finding is labeled TP/FP by SmartBugs-curated ground truth (folder == intended
vuln category), then run through the recall-safe agentic quality loop.

Caveats (recorded in the artifact):
- The detector is MIESC's RECALL-oriented pattern layer, not a full scanner, so its FP
  profile (cross-category pattern firings) differs from Slither/Aderyn (which add lots
  of informational-lint FPs). This measures the lever's reach on REAL pattern-detector
  output — a different, complementary field signal from the fp_seed test.
- SmartBugs-curated labels at the contract-category level (folder == one intended vuln);
  a cross-category finding is counted FP even if arguably real. Standard convention.
- Findings carry function='unknown' (the pattern layer does not resolve function names),
  so function-scoped benign matching degrades to contract scope -> watch the recall cost.

Usage: python3 scripts/measure_real_scanner.py
Author: Fernando Boiero · License: AGPL-3.0
"""
from __future__ import annotations

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import argparse  # noqa: E402

from scripts.agentic_quality_loop import (  # noqa: E402
    load_benign_patterns,
    make_llm_verifier,
    verify,
)
from miesc.core.intelligence import detect_zero_recall_categories  # noqa: E402

CORPUS = os.path.join(ROOT, "benchmarks", "datasets", "smartbugs-curated", "dataset")


def to_category(ftype: str) -> str:
    t = (ftype or "").lower()
    if "reentr" in t:
        return "reentrancy"
    if "unchecked" in t or "low_level" in t or "low-level" in t:
        return "unchecked_low_level_calls"
    if "bad_randomness" in t or "prng" in t or "randomness" in t:
        return "bad_randomness"
    if "time_manip" in t or "timestamp" in t:
        return "time_manipulation"
    if "rounding" in t or "overflow" in t or "underflow" in t or "arithmetic" in t or "division" in t:
        return "arithmetic"
    if "access" in t or "tx_origin" in t or "tx-origin" in t or "delegatecall" in t or "suicidal" in t or "owner" in t:
        return "access_control"
    if "dos" in t or "denial" in t or "unbounded" in t or "loop" in t:
        return "denial_of_service"
    if "front" in t:
        return "front_running"
    if "short" in t:
        return "short_addresses"
    return "other"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verifier", choices=["rule", "llm"], default="rule")
    ap.add_argument("--model", default="qwen2.5-coder:14b")
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--limit", type=int, default=0, help="cap total findings (0 = all); use for LLM speed")
    ap.add_argument("--per-cat", type=int, default=0, help="contracts per category (0 = all)")
    args = ap.parse_args()

    patterns = load_benign_patterns()
    llm_fn = make_llm_verifier(args.model, args.host) if args.verifier == "llm" else None
    cats = sorted(d for d in os.listdir(CORPUS) if os.path.isdir(os.path.join(CORPUS, d)))
    tp = fp = tp_kept = tp_lost = fp_dropped = fp_leaked = 0
    contracts = 0
    n_findings = 0
    stop = False

    for cat in cats:
        if stop:
            break
        paths = sorted(glob.glob(os.path.join(CORPUS, cat, "*.sol")))
        if args.per_cat:
            paths = paths[: args.per_cat]
        for path in paths:
            code = open(path, errors="ignore").read()
            try:
                findings = detect_zero_recall_categories(code)
            except Exception:
                continue
            contracts += 1
            for f in findings:
                if args.limit and n_findings >= args.limit:
                    stop = True
                    break
                n_findings += 1
                fcat = to_category(f.get("type", ""))
                is_tp = fcat == cat
                finding = {
                    "type": fcat,
                    "title": f.get("type"),
                    "function": (f.get("location") or {}).get("function", "") or "",
                    "severity": f.get("severity", ""),
                }
                dropped = verify(finding, code, patterns, llm_fn=llm_fn)["verdict"] == "false_positive"
                if is_tp:
                    tp += 1
                    tp_lost += dropped
                    tp_kept += not dropped
                else:
                    fp += 1
                    fp_dropped += dropped
                    fp_leaked += not dropped
            if stop:
                break

    kept = tp_kept + fp_leaked
    result = {
        "artifact": "agentic_loop_real_detector_measurement",
        "generated_at_note": "stamp at commit time",
        "detector": "MIESC intelligence pattern layer (detect_zero_recall_categories), no solc",
        "verifier": (f"LLM via Ollama ({args.model}), recall-safe" if llm_fn
                     else "recall-safe rule-based agentic quality loop (no LLM)"),
        "findings_measured": n_findings,
        "limit": args.limit,
        "blocked_alternatives": "Slither/Aderyn unavailable: solc-select broken, only solc 0.8.x present (cannot compile legacy 0.4.x); Aderyn panics on legacy AST.",
        "contracts": contracts,
        "tp_findings": tp,
        "fp_findings": fp,
        "tp_kept": tp_kept,
        "tp_lost": tp_lost,
        "fp_dropped": fp_dropped,
        "fp_leaked": fp_leaked,
        "fp_drop_rate": round(fp_dropped / fp, 4) if fp else 0.0,
        "recall_retained": round(tp_kept / tp, 4) if tp else 0.0,
        "precision_before": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
        "precision_after": round(tp_kept / kept, 4) if kept else 0.0,
        "caveats": [
            "MIESC recall-oriented pattern layer, not a full scanner -> FP profile differs from Slither/Aderyn (no informational-lint FPs here).",
            "SmartBugs-curated category labels (folder == intended vuln); cross-category findings counted FP.",
            "function='unknown' -> function-scoped benign matching degrades to contract scope (recall risk shown in tp_lost).",
            "rule-based verifier only; LLM/semantic loop (Loops A/B) is the production path.",
        ],
    }
    print("=== REAL DETECTOR MEASUREMENT (MIESC pattern layer, recall-safe loop) ===")
    for k, v in result.items():
        if k != "caveats":
            print(f"  {k}: {v}")
    tag = "llm" if llm_fn else "rule"
    out = os.path.join(ROOT, "benchmarks", "results", f"agentic_loop_real_detector_{tag}_20260621.json")
    json.dump(result, open(out, "w"), indent=2)
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
