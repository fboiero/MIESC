#!/usr/bin/env python3
"""
Safe-precision feasibility: can a LEARNED FP filter beat the deterministic +4pp ceiling
WITHOUT losing recall?

We proved this session that the LLM and guard-presence patterns are NOT recall-safe (they
drop real vulns). The only proven-safe lever so far is type-deterministic patterns (~+4pp).
This experiment tests whether MIESC's trainable GradientBoosting FP classifier
(src/ml/fp_ml_classifier.py), trained on the 6 wild ground-truth sources, has an operating
threshold where it drops MORE benign FPs than the deterministic rules while keeping recall
~1.0 on held-out data.

Label convention (MATCHES the wild harness): label=True = real/TP, False = FP.
The classifier predicts P(TP); P(FP) = 1 - P(TP). A finding is DROPPED if P(FP) >= threshold.
Recall-safe threshold = the highest threshold at which 0 real (label=True) findings are dropped
on the held-out set (i.e., every real finding has P(FP) < threshold).

Usage:
  python3 scripts/fp_classifier_feasibility.py build   # consolidate wild jsonl -> dataset
  python3 scripts/fp_classifier_feasibility.py run     # train + threshold sweep

Author: Fernando Boiero · License: AGPL-3.0
"""
from __future__ import annotations

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

DATASET = "/tmp/fp_dataset_multisource.jsonl"
# the wild-harness outputs with anchored labels (exact-anchored '_x' / full where available)
WILD_GLOBS = [
    "/tmp/wild_fsalzano_full.jsonl",
    "/tmp/wild_dappscan_x.jsonl",
    "/tmp/wild_c4_numoen_x.jsonl",
    "/tmp/wild_sherlock_gmx_x.jsonl",
    "/tmp/wild_solidifi.jsonl",
]


def build() -> int:
    """Reshape wild jsonl ({type,check,severity,code,label}) -> classifier format
    ({finding, context, label}), keep only bool-labeled, dedup."""
    seen, out, tp, fp = set(), [], 0, 0
    for g in WILD_GLOBS:
        for path in glob.glob(g):
            for line in open(path, errors="ignore"):
                if not line.strip():
                    continue
                r = json.loads(line)
                if not isinstance(r.get("label"), bool):
                    continue
                code = r.get("code", "")
                key = (r.get("check"), r.get("line"), r.get("contract"), r["label"])
                if key in seen:
                    continue
                seen.add(key)
                finding = {
                    "type": r.get("type", ""),
                    "check": r.get("check", ""),
                    "severity": r.get("severity", "medium") or "medium",
                    "function": r.get("function", ""),
                    "line": r.get("line", 0),
                }
                out.append({"finding": finding, "context": code, "label": bool(r["label"]),
                            "_source": os.path.basename(path)})
                tp += r["label"]
                fp += not r["label"]
    with open(DATASET, "w") as fh:
        for o in out:
            fh.write(json.dumps(o) + "\n")
    print(f"dataset: {len(out)} samples ({tp} real/TP, {fp} FP) -> {DATASET}")
    return 0


def run() -> int:
    try:
        import numpy as np
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.model_selection import train_test_split
    except ImportError:
        print("scikit-learn required: pip install scikit-learn numpy")
        return 1
    from src.ml.fp_ml_classifier import extract_features

    rows = [json.loads(l) for l in open(DATASET) if l.strip()]
    X, y = [], []
    for r in rows:
        feats = extract_features(r["finding"], r.get("context", ""))
        X.append(feats.to_vector())
        y.append(1 if r["label"] else 0)  # 1 = real/TP, 0 = FP
    X, y = np.array(X), np.array(y)
    print(f"loaded {len(y)} samples | TP={int(y.sum())} FP={int((y == 0).sum())} | features={X.shape[1]}")

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    clf = GradientBoostingClassifier(n_estimators=200, max_depth=3, random_state=42)
    clf.fit(X_tr, y_tr)
    p_fp = 1.0 - clf.predict_proba(X_te)[:, 1]  # P(FP) on held-out

    n_real = int((y_te == 1).sum())
    n_fp = int((y_te == 0).sum())
    base_prec = n_real / (n_real + n_fp)
    print(f"\nheld-out: {n_real} real + {n_fp} FP | baseline precision (no filter) = {base_prec:.4f}\n")
    print(f"{'P(FP)>=thr drop':>16} | {'real_lost':>9} | {'recall':>7} | {'fp_dropped':>10} | {'precision_after':>15}")
    print("-" * 72)
    recall_safe = None
    for thr in [0.99, 0.97, 0.95, 0.9, 0.85, 0.8, 0.75, 0.7, 0.6, 0.5]:
        drop = p_fp >= thr
        real_lost = int((drop & (y_te == 1)).sum())
        fp_dropped = int((drop & (y_te == 0)).sum())
        kept_real = n_real - real_lost
        kept_fp = n_fp - fp_dropped
        recall = kept_real / n_real
        prec_after = kept_real / (kept_real + kept_fp) if (kept_real + kept_fp) else 0.0
        flag = ""
        if real_lost == 0 and recall_safe is None and fp_dropped > 0:
            recall_safe = (thr, fp_dropped, prec_after)
            flag = "  <- recall-safe"
        print(f"{thr:>16.2f} | {real_lost:>9} | {recall:>7.4f} | {fp_dropped:>10} | {prec_after:>15.4f}{flag}")

    print("\n=== VERDICT ===")
    det_ceiling = base_prec + 0.041  # the deterministic +4pp result from fsalzano
    if recall_safe:
        thr, fpd, prec = recall_safe
        lift = prec - base_prec
        print(f"recall-safe operating point: P(FP)>={thr:.2f} | precision {base_prec:.4f} -> {prec:.4f} "
              f"(+{lift*100:.1f}pp) at recall 1.0, dropping {fpd} FPs")
        print(f"deterministic +4pp ceiling ~ {det_ceiling:.4f}; learned filter "
              f"{'BEATS it safely' if prec > det_ceiling else 'does NOT beat it'}.")
    else:
        print("NO recall-safe operating point drops any FP without losing a real vuln on held-out.")
        print("=> the learned filter (with these features) cannot beat the deterministic floor safely.")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    raise SystemExit(build() if cmd == "build" else run())
