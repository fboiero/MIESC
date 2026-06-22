#!/usr/bin/env python3
"""
Wild benign-context evaluation of the recall-safe verifier — field-number harness.

Runs in an environment with a WORKING solc-select (the paper's reproduction env; NOT
this dev box, where solc-select is broken). Produces the honest field measurement the
research doc calls for: real scanner output, benign-context labels, verifier lift.

Three phases:

  1) collect  — run Slither (solc-select per pragma) over a corpus; emit one record per
                finding with the contract code, plus a CSV for human labeling.
  2) label    — fill the `label` for each finding: True = real (unmitigated) vulnerability,
                False = benign-context false positive (the contract mitigates THIS finding).
                Do it by hand (authoritative) in the CSV, or auto-label with an INDEPENDENT
                judge model (--judge-model) — note the semi-circularity in the doc.
  3) measure  — run BenignContextVerifier on the labeled findings and report FP-drop,
                recall, and precision before/after (the field lift).

Usage:
  python3 scripts/wild_benign_context_eval.py collect <corpus_dir> -o wild_findings.jsonl [--max 200]
  python3 scripts/wild_benign_context_eval.py label  wild_findings.jsonl -o wild_labeled.jsonl --judge-model qwen2.5-coder:32b
  python3 scripts/wild_benign_context_eval.py measure wild_labeled.jsonl --verify-model qwen2.5-coder:32b

See docs/research/WILD_BENIGN_CONTEXT_EVAL_INSTRUCTIONS.md.
Author: Fernando Boiero · License: AGPL-3.0
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from src.ml.benign_context_verifier import BenignContextVerifier  # noqa: E402

# Slither detector -> a coarse vuln category the verifier understands.
DETECTOR_CATEGORY = {
    "reentrancy-eth": "reentrancy", "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy", "reentrancy-events": "reentrancy",
    "arbitrary-send-eth": "access_control", "suicidal": "access_control",
    "controlled-delegatecall": "access_control", "tx-origin": "access_control",
    "unchecked-lowlevel": "unchecked_low_level_calls",
    "unchecked-send": "unchecked_low_level_calls",
    "unchecked-transfer": "unchecked_low_level_calls",
    "timestamp": "time_manipulation", "weak-prng": "bad_randomness",
    "calls-loop": "denial_of_service", "divide-before-multiply": "arithmetic",
}


def pick_solc(code: str) -> str | None:
    """Highest installed solc satisfying the pragma minor (e.g. ^0.4.x -> 0.4.26)."""
    m = re.search(r"pragma solidity\s*[\^>=]*\s*0\.(\d+)\.(\d+)", code)
    if not m:
        return None
    minor = m.group(1)
    try:
        installed = subprocess.run(["solc-select", "versions"], capture_output=True, text=True).stdout
    except Exception:
        return None
    cands = sorted(
        (v for v in re.findall(r"0\.\d+\.\d+", installed) if v.split(".")[1] == minor),
        key=lambda v: int(v.split(".")[2]), reverse=True,
    )
    if cands:
        return cands[0]
    # Not installed -> try to install the latest patch of that minor (best effort)
    guess = {"4": "0.4.26", "5": "0.5.17", "6": "0.6.12", "7": "0.7.6", "8": "0.8.26"}.get(minor)
    if guess:
        subprocess.run(["solc-select", "install", guess], capture_output=True, text=True)
        return guess
    return None


def run_slither(path: str, code: str, timeout: int) -> list[dict] | None:
    ver = pick_solc(code)
    if not ver:
        return None
    subprocess.run(["solc-select", "use", ver], capture_output=True, text=True)
    out = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
    try:
        subprocess.run(["slither", path, "--json", out], capture_output=True, text=True, timeout=timeout)
        if not os.path.exists(out) or os.path.getsize(out) == 0:
            return None
        data = json.load(open(out))
    except Exception:
        return None
    finally:
        if os.path.exists(out):
            os.unlink(out)
    findings = []
    for r in data.get("results", {}).get("detectors", []):
        fn = ""
        line = 0
        for e in r.get("elements", []):
            if e.get("type") == "function" and not fn:
                fn = e.get("name", "")
            lines = (e.get("source_mapping") or {}).get("lines") or []
            if lines and not line:
                line = lines[0]
        findings.append({
            "check": r.get("check", ""),
            "type": DETECTOR_CATEGORY.get(r.get("check", ""), r.get("check", "other")),
            "function": fn or "unknown", "line": line, "severity": r.get("impact", ""),
        })
    return findings


# --------------------------------------------------------------------------- #
def cmd_collect(args) -> int:
    files = sorted(glob.glob(os.path.join(args.corpus, "**", "*.sol"), recursive=True))
    if args.max:
        files = files[: args.max]
    records, scanned, skipped = [], 0, 0
    for path in files:
        code = open(path, errors="ignore").read()
        fs = run_slither(path, code, args.timeout)
        if fs is None:
            skipped += 1
            print(f"  skip {os.path.basename(path)} (no solc / scan failed)")
            continue
        scanned += 1
        for f in fs:
            records.append({
                "contract": path, "check": f["check"], "type": f["type"],
                "function": f["function"], "line": f["line"], "severity": f["severity"],
                "code": code, "label": None,
            })
        print(f"  scan {os.path.basename(path)}: {len(fs)} findings")
    with open(args.out, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    # human-labeling CSV (code omitted; label column blank for the auditor to fill)
    csv_path = args.out.rsplit(".", 1)[0] + "_TO_LABEL.csv"
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["idx", "contract", "check", "type", "function", "line", "label(True=real/False=benignFP)"])
        for i, r in enumerate(records):
            w.writerow([i, os.path.basename(r["contract"]), r["check"], r["type"], r["function"], r["line"], ""])
    print(f"\ncollected {len(records)} findings from {scanned} contracts ({skipped} skipped)")
    print(f"  findings: {args.out}\n  label here (or via --judge-model): {csv_path}")
    return 0


def cmd_label(args) -> int:
    records = [json.loads(l) for l in open(args.infile) if l.strip()]
    v = BenignContextVerifier(model=args.judge_model)  # used only for its _query (judge)
    labeled = 0
    for r in records:
        if r.get("label") is not None:
            continue
        prompt = (
            "You are an INDEPENDENT senior auditor establishing ground truth (do not be "
            "lenient). Is this reported finding a REAL, exploitable vulnerability, or a "
            "FALSE POSITIVE because the contract mitigates it in context?\n"
            f"Finding: {r['check']} ({r['type']}) in '{r['function']}'.\n"
            f"Contract:\n```solidity\n{r['code'][:6000]}\n```\n"
            'Answer ONLY JSON: {"real": true|false}. real=true means a genuine unmitigated '
            "vulnerability; real=false means mitigated/benign in context."
        )
        raw = v._query(prompt)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                r["label"] = bool(json.loads(m.group(0)).get("real") is True)
                labeled += 1
            except Exception:
                pass
    with open(args.out, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    print(f"labeled {labeled}/{len(records)} via judge {args.judge_model} -> {args.out}")
    print("NOTE: LLM judge labels are semi-circular; hand-verify a sample for a definitive number.")
    return 0


def cmd_measure(args) -> int:
    records = [json.loads(l) for l in open(args.infile) if l.strip()]
    records = [r for r in records if isinstance(r.get("label"), bool)]
    if not records:
        print("No labeled records (fill 'label' first).")
        return 1
    v = BenignContextVerifier(model=args.verify_model)
    tp = fp = tp_kept = tp_lost = fp_drop = fp_leak = 0
    for r in records:
        finding = {"type": r["type"], "title": r["check"],
                   "location": {"function": r["function"], "line": r["line"]}, "severity": r["severity"]}
        dropped = v.verify(finding, r["code"]) == "false_positive"
        if r["label"]:  # real vuln
            tp += 1
            tp_lost += dropped
            tp_kept += not dropped
        else:  # benign-context FP
            fp += 1
            fp_drop += dropped
            fp_leak += not dropped
    kept = tp_kept + fp_leak
    res = {
        "labeled_findings": len(records), "real": tp, "benign_fp": fp,
        "fp_dropped": fp_drop, "fp_drop_rate": round(fp_drop / fp, 4) if fp else 0.0,
        "real_kept": tp_kept, "real_lost": tp_lost,
        "recall_retained": round(tp_kept / tp, 4) if tp else 0.0,
        "precision_before": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
        "precision_after": round(tp_kept / kept, 4) if kept else 0.0,
        "verify_model": args.verify_model or "rule-only",
    }
    print("=== WILD BENIGN-CONTEXT MEASUREMENT ===")
    for k, val in res.items():
        print(f"  {k}: {val}")
    if res["real_lost"]:
        print("  WARNING: recall-safety violated (real vulns lost) — investigate before trusting precision.")
    out = os.path.join(ROOT, "benchmarks", "results", "wild_benign_context_measurement.json")
    json.dump(res, open(out, "w"), indent=2)
    print(f"\nwrote {out}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Wild benign-context evaluation harness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect"); c.add_argument("corpus"); c.add_argument("-o", "--out", default="wild_findings.jsonl")
    c.add_argument("--max", type=int, default=0); c.add_argument("--timeout", type=int, default=60)
    lb = sub.add_parser("label"); lb.add_argument("infile"); lb.add_argument("-o", "--out", default="wild_labeled.jsonl")
    lb.add_argument("--judge-model", default="qwen2.5-coder:32b")
    m = sub.add_parser("measure"); m.add_argument("infile"); m.add_argument("--verify-model", default=None)
    args = ap.parse_args()
    return {"collect": cmd_collect, "label": cmd_label, "measure": cmd_measure}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
