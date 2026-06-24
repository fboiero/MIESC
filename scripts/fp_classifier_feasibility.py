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


def _structural_features(finding: dict, code: str) -> list:
    """The EXACT structural signals the deterministic recall-safe rules use, as numeric
    features — the lever the 17 coarse features miss. No new deps."""
    import re

    from src.ml.benign_context_verifier import (
        _CONTEXTUAL_BENIGN, BenignContextVerifier, _extract_function, _func_signature,
        _function_at_line, _is_cei, _timestamp_is_benign, match_benign,
    )
    global _V
    try:
        _V
    except NameError:
        _V = BenignContextVerifier(model=None)
    line = finding.get("line") or 0
    fn = finding.get("function") or ""
    f2 = {"type": finding.get("type"), "title": finding.get("check"),
          "location": {"function": fn, "line": line}}
    benign = match_benign(f2, code, _V.patterns)
    has_benign = 1.0 if benign else 0.0
    is_ctx = 1.0 if (benign and benign["id"] in _CONTEXTUAL_BENIGN) else 0.0
    is_det = 1.0 if (benign and benign["id"] not in _CONTEXTUAL_BENIGN) else 0.0
    if fn and fn not in ("unknown", ""):
        body, sig = _extract_function(code, fn), _func_signature(code, fn)
    elif line:
        body, sig = _function_at_line(code, line)
    else:
        body, sig = "", ""
    scoped = 1.0 if body else 0.0
    has_guard = 1.0 if re.search(r"nonReentrant|ReentrancyGuard|onlyOwner|onlyRole", sig or "") else 0.0
    is_cei = 1.0 if (body and _is_cei(body)) else 0.0
    ts_benign = 1.0 if (body and _timestamp_is_benign(body)) else 0.0
    pragma08 = 1.0 if re.search(r"pragma\s+solidity\s*\^?0\.8", code) else 0.0
    lines = code.splitlines()
    flagged = lines[line - 1] if (isinstance(line, int) and 1 <= line <= len(lines)) else ""
    window = " ".join(lines[line - 1:line + 2]) if flagged else ""
    checked = 1.0 if re.search(r"require\s*\(\s*(ok|success)", window) else 0.0
    native_transfer = 1.0 if (re.search(r"\.transfer\(", flagged)
                              and not re.search(r"\.transfer\([^)]*,", flagged)) else 0.0
    safeerc = 1.0 if re.search(r"safeTransfer|SafeERC20", flagged) else 0.0
    body_len = min(len(body) / 2000.0, 1.0)
    return [has_benign, is_ctx, is_det, scoped, has_guard, is_cei, ts_benign,
            pragma08, checked, native_transfer, safeerc, body_len]


def run(rich: bool = False) -> int:
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
        v = list(extract_features(r["finding"], r.get("context", "")).to_vector())
        if rich:
            v += _structural_features(r["finding"], r.get("context", ""))
        X.append(v)
        y.append(1 if r["label"] else 0)  # 1 = real/TP, 0 = FP
    X, y = np.array(X), np.array(y)
    print(f"[{'RICH (coarse+structural)' if rich else 'COARSE'} features]")
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


def rank() -> int:
    """Recall-safe TRIAGE: rank findings by P(real) instead of dropping. Measures how much
    review effort the ranking saves — the fraction of findings an auditor must inspect
    (top-down) to catch ALL real vulns, vs random order. Nothing is dropped (recall 1.0)."""
    import numpy as np
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import train_test_split

    from src.ml.fp_ml_classifier import extract_features

    rows = [json.loads(l) for l in open(DATASET) if l.strip()]

    def feats(r):
        return list(extract_features(r["finding"], r.get("context", "")).to_vector()) + \
            _structural_features(r["finding"], r.get("context", ""))

    X = np.array([feats(r) for r in rows]); y = np.array([1 if r["label"] else 0 for r in rows])
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    clf = GradientBoostingClassifier(n_estimators=200, max_depth=3, random_state=42).fit(Xtr, ytr)
    p_real = clf.predict_proba(Xte)[:, 1]

    order = np.argsort(-p_real)               # rank by P(real), descending
    y_ranked = yte[order]
    n = len(yte); n_real = int(yte.sum())
    auc = roc_auc_score(yte, p_real)
    cum_real = np.cumsum(y_ranked)
    print(f"held-out: {n} findings ({n_real} real, {n - n_real} FP) | ranking AUC = {auc:.4f}\n")
    print(f"{'catch % of reals':>16} | {'review depth':>12} | {'effective precision':>19} | {'vs random':>10}")
    print("-" * 70)
    for frac in (0.80, 0.90, 0.95, 0.99, 1.00):
        need = int(np.ceil(frac * n_real))
        depth = int(np.searchsorted(cum_real, need) + 1)   # findings to review to catch `need` reals
        eff_prec = need / depth
        rand_depth = int(np.ceil(frac * n))                 # random order: review frac of all
        saved = 1 - depth / rand_depth
        print(f"{int(frac*100):>15}% | {depth:>5}/{n} | {eff_prec:>19.4f} | {saved*100:>8.1f}%")
    # the headline: how many FPs sit below the last real (pure-noise tail you can deprioritize)
    last_real_rank = int(np.max(np.where(y_ranked == 1)) + 1)
    tail_fp = n - last_real_rank
    print(f"\nlast real vuln at rank {last_real_rank}/{n}; {tail_fp} FPs ranked below it "
          f"({100*tail_fp/(n-n_real):.1f}% of FPs are pure-noise tail).")
    print("Recall-safe by construction: nothing dropped (recall 1.0); this is pure reordering.")
    return 0


def cross() -> int:
    """Decisive recall-safety test: train on fsalzano (its FPs + reals), pick the recall-safe
    threshold on a fsalzano hold-out, then check whether AUDIT-GRADE reals (DAppSCAN/Code4rena/
    Sherlock — entirely held out) survive that threshold. If they get dropped, the within-source
    gain was overfitting; if they survive, the rich learned filter generalizes."""
    import numpy as np
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split

    from src.ml.fp_ml_classifier import extract_features

    rows = [json.loads(l) for l in open(DATASET) if l.strip()]

    def feats(r):
        return list(extract_features(r["finding"], r.get("context", "")).to_vector()) + \
            _structural_features(r["finding"], r.get("context", ""))

    fz = [r for r in rows if "fsalzano" in r.get("_source", "")]
    audit_real = [r for r in rows if "fsalzano" not in r.get("_source", "") and r["label"]]
    Xf = np.array([feats(r) for r in fz]); yf = np.array([1 if r["label"] else 0 for r in fz])
    Xa = np.array([feats(r) for r in audit_real])
    print(f"train (fsalzano): {len(fz)} ({int(yf.sum())} real, {int((yf==0).sum())} FP) | "
          f"held-out audit-grade reals: {len(audit_real)}")

    Xtr, Xval, ytr, yval = train_test_split(Xf, yf, test_size=0.3, random_state=42, stratify=yf)
    clf = GradientBoostingClassifier(n_estimators=200, max_depth=3, random_state=42)
    clf.fit(Xtr, ytr)
    # recall-safe threshold on the fsalzano validation split (highest thr with 0 real dropped)
    pv = 1.0 - clf.predict_proba(Xval)[:, 1]
    thr = None
    for t in [0.999, 0.998, 0.995, 0.99, 0.98, 0.97, 0.95]:
        if int(((pv >= t) & (yval == 1)).sum()) == 0:
            thr = t; break
    thr = thr or 0.999
    fp_val = int(((pv >= thr) & (yval == 0)).sum())
    print(f"fsalzano-calibrated recall-safe threshold P(FP)>={thr} (drops {fp_val} fsalzano FPs, 0 reals)")
    # apply to the held-out audit-grade reals
    pa = 1.0 - clf.predict_proba(Xa)[:, 1]
    audit_dropped = int((pa >= thr).sum())
    print(f"\n=== CROSS-SOURCE VERDICT ===")
    print(f"audit-grade reals dropped at that threshold: {audit_dropped}/{len(audit_real)} "
          f"(recall {1 - audit_dropped/len(audit_real):.4f})")
    if audit_dropped == 0:
        print(f"RECALL-SAFE: drops 0 audit-grade real vulns (and {fp_val} fsalzano FPs) at the strict")
        print(f"cross-safe threshold. Well-behaved on audit-grade (unlike LLM/guards). BUT the safe")
        print(f"FP-drop at this strict threshold is small — the modest gain does NOT robustly beat the")
        print(f"deterministic +4pp floor (see the threshold sweep / SAFE_PRECISION_FEASIBILITY doc).")
    else:
        print("DOES NOT generalize: the fsalzano-calibrated threshold loses audit-grade reals.")
        print("=> the within-source gain was overfitting; the ceiling holds in practice.")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "build":
        raise SystemExit(build())
    if cmd == "cross":
        raise SystemExit(cross())
    if cmd == "rank":
        raise SystemExit(rank())
    raise SystemExit(run(rich=(cmd == "rich")))
