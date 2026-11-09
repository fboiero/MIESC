#!/usr/bin/env python3
"""Additive experiment (2026-08-11): measure the SHIPPED SOLUTION's precision/recall
on SmartBugs-curated through the production false-positive filter path, versus the
raw unfiltered detector baseline that benchmarks/smartbugs_evaluation.py reports
(P 13.26 / R 83.19 / F1 22.87; TP 193 / FP 1263 / FN 39, run 20260811_110804).

Rationale: `miesc scan` applies miesc/ml/fp_filter.py FalsePositiveFilter by default
(strictness=medium), but the raw benchmark calls the detectors directly and never
runs that filter. This script isolates the filter's effect: SAME detectors
(Slither + Aderyn + SmartBugs), SAME ground truth, SAME match_findings scoring as
smartbugs_evaluation.py -- the only added step is the production filter, kept/dropped
by the identical `not fr.is_likely_fp` rule scan.py uses.

Writes a NEW dated result file. Does NOT touch any frozen paper artifact.
Adapted from smartbugs_fp_filter_effect_20260710.py (import fixed src.ml -> miesc.ml
after the src/->miesc/ package unification).
"""
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "benchmarks"))

import smartbugs_evaluation as sbe  # noqa: E402
from miesc.ml.fp_filter import FalsePositiveFilter  # noqa: E402


_CONFIDENCE_LEVELS = {"high": 0.9, "medium": 0.7, "low": 0.4, "informational": 0.2}


def _confidence_to_float(value) -> float:
    """The filter expects numeric confidence (as production findings carry); the
    benchmark findings carry string levels ('High'/'Medium'/'Low'). Normalize."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return _CONFIDENCE_LEVELS.get(value.strip().lower(), 0.7)
    return 0.7


def metrics(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(f1, 4),
    }


def main() -> None:
    truth = sbe.load_ground_truth()
    # Mirror `miesc scan` default construction exactly.
    fpf = FalsePositiveFilter(strictness="medium", use_rag=False)

    raw = defaultdict(lambda: [0, 0, 0])  # category -> [tp, fp, fn]
    flt = defaultdict(lambda: [0, 0, 0])
    per_contract = []
    t0 = time.time()
    items = sorted(truth.items())

    for i, (rel_path, info) in enumerate(items, 1):
        contract_path = sbe.DATASET_PATH / rel_path
        category = rel_path.split("/")[1] if "/" in rel_path else "unknown"
        if not contract_path.exists():
            continue

        slither = sbe.run_miesc_analysis(contract_path)
        aderyn = sbe.run_aderyn_analysis(contract_path)
        sb = sbe.run_smartbugs_detectors(contract_path, min_confidence=sbe._MIN_CONFIDENCE)
        detected = sbe.extract_findings(slither, aderyn, sb)

        try:
            source = contract_path.read_text(errors="replace")
        except Exception:
            source = ""

        # Apply the production filter. Populate the fields fp_filter reads
        # (type/severity) from the benchmark's category/impact so the class-based
        # suppression (e.g. SafeMath/0.8 arithmetic) can fire as it does in production.
        kept = []
        for f in detected:
            ff = dict(f)
            ff.setdefault("type", f.get("category", ""))
            ff.setdefault("severity", f.get("impact", f.get("severity", "")))
            ff["confidence"] = _confidence_to_float(f.get("confidence"))
            fr = fpf.filter_finding(ff, code_context=source, file_path=str(contract_path))
            if not fr.is_likely_fp:
                kept.append(f)

        gt = info["vulnerabilities"]
        rtp, rfp, rfn = sbe.match_findings(gt, detected, category)
        ktp, kfp, kfn = sbe.match_findings(gt, kept, category)
        raw[category][0] += rtp
        raw[category][1] += rfp
        raw[category][2] += rfn
        flt[category][0] += ktp
        flt[category][1] += kfp
        flt[category][2] += kfn
        per_contract.append(
            {
                "path": rel_path,
                "category": category,
                "raw": [rtp, rfp, rfn],
                "filtered": [ktp, kfp, kfn],
                "fps_removed": rfp - kfp,
                "tps_lost": rtp - ktp,
                "detected": len(detected),
                "kept": len(kept),
            }
        )
        print(
            f"  [{i}/{len(items)}] {rel_path:<55} fp {rfp}->{kfp}  tp {rtp}->{ktp}",
            flush=True,
        )

    def agg(d):
        tp = sum(v[0] for v in d.values())
        fp = sum(v[1] for v in d.values())
        fn = sum(v[2] for v in d.values())
        return metrics(tp, fp, fn)

    raw_agg = agg(raw)
    flt_agg = agg(flt)
    out = {
        "experiment": "smartbugs_fp_filter_effect",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "note": (
            "ADDITIVE experiment, not part of frozen paper evidence. Same detectors "
            "(Slither+Aderyn+SmartBugs), same ground truth, same match_findings scoring "
            "as smartbugs_evaluation.py. Only added step: production FalsePositiveFilter "
            "(strictness=medium, use_rag=False), dropping findings where fr.is_likely_fp, "
            "exactly as `miesc scan` does. Measures what the shipped product actually returns."
        ),
        "raw_baseline": raw_agg,
        "filtered_production": flt_agg,
        "delta": {
            "fps_removed": raw_agg["fp"] - flt_agg["fp"],
            "tps_lost": raw_agg["tp"] - flt_agg["tp"],
            "precision_gain": round(flt_agg["precision"] - raw_agg["precision"], 4),
            "recall_change": round(flt_agg["recall"] - raw_agg["recall"], 4),
        },
        "per_category": {
            c: {"raw": metrics(*raw[c]), "filtered": metrics(*flt[c])}
            for c in sorted(set(raw) | set(flt))
        },
        "per_contract": per_contract,
        "total_time_s": round(time.time() - t0, 1),
        "contracts_evaluated": len(per_contract),
    }
    outpath = PROJECT_ROOT / "benchmarks" / "results" / "smartbugs_fp_filter_effect_20260811.json"
    outpath.write_text(json.dumps(out, indent=2))

    print("\n" + "=" * 64)
    print(f"  RAW      : {raw_agg}")
    print(f"  FILTERED : {flt_agg}")
    print(
        f"  FPs removed: {raw_agg['fp'] - flt_agg['fp']}  |  TPs lost: "
        f"{raw_agg['tp'] - flt_agg['tp']}  |  recall {raw_agg['recall']} -> {flt_agg['recall']}"
    )
    print(f"  wrote {outpath}")


if __name__ == "__main__":
    main()
