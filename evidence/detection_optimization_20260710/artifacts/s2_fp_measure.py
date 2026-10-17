"""Stage-2 measurement: does the orchestrator FP filter (issue #69) raise
precision WITHOUT dropping recall? Runs the ml_orchestrator on a SmartBugs
subset with fp_strictness off vs high and compares category-level recall and
finding-level precision. Additive, dated artifact — reads only, writes JSON.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, ".")
from miesc.cli.commands.evaluate import _normalize_category  # noqa: E402
from src.core.ml_orchestrator import get_ml_orchestrator  # noqa: E402

DATASET = Path("benchmarks/datasets/smartbugs-curated/dataset")
# Focus: high-FP categories + reentrancy (to prove TPs survive). N per category.
CATS = ["reentrancy", "arithmetic", "unchecked_low_level_calls",
        "time_manipulation", "access_control"]
PER_CAT = 6


def categories_of(findings):
    cats = set()
    for f in findings:
        c = _normalize_category(
            str(f.get("type", f.get("check", ""))),
            str(f.get("title", "")),
            str(f.get("description", "")),
        )
        if c:
            cats.add(c)
    return cats


def main():
    orch = get_ml_orchestrator()
    rows = []
    for cat in CATS:
        files = sorted((DATASET / cat).glob("*.sol"))[:PER_CAT]
        for sol in files:
            row = {"contract": sol.name, "gt": cat}
            for mode in ("off", "medium", "high"):
                r = orch.analyze(str(sol), tools=["slither"], timeout=60, fp_strictness=mode)
                fs = r.ml_filtered_findings
                cats = categories_of(fs)
                tp = sum(1 for f in fs if _normalize_category(
                    str(f.get("type", f.get("check", ""))),
                    str(f.get("title", "")), str(f.get("description", ""))) == cat)
                row[mode] = {"detected": cat in cats, "total": len(fs), "tp": tp,
                             "fp": len(fs) - tp, "fp_removed": r.false_positives_removed}
            rows.append(row)
            print(f"  {cat:24} {sol.name[:24]:24} "
                  f"off det={row['off']['detected']!s:5} tot={row['off']['total']:3} | "
                  f"med det={row['medium']['detected']!s:5} tot={row['medium']['total']:3} | "
                  f"high det={row['high']['detected']!s:5} tot={row['high']['total']:3}")

    def agg(mode):
        n = len(rows)
        det = sum(1 for r in rows if r[mode]["detected"])
        tp = sum(r[mode]["tp"] for r in rows)
        tot = sum(r[mode]["total"] for r in rows)
        return {"n": n, "recall": round(det / n, 4), "detected": det,
                "precision": round(tp / tot, 4) if tot else 0.0,
                "total_findings": tot, "tp": tp, "fp": tot - tp}

    summary = {m: agg(m) for m in ("off", "medium", "high")}
    summary["rows"] = rows
    out = Path("benchmarks/results/detection_optimization_20260710/s2_fp_measure_curve.json")
    out.write_text(json.dumps(summary, indent=2))
    base = summary["off"]
    print("\n=== RESUMEN curva off/medium/high (n={}) ===".format(base["n"]))
    for m in ("off", "medium", "high"):
        s = summary[m]
        safe = "recall-safe" if s["detected"] == base["detected"] else "!! RECALL LOSS"
        print(f"  {m:7}: recall={s['recall']:.1%}  precision={s['precision']:.1%}  "
              f"FP={s['fp']:4}  det={s['detected']}  [{safe}]")


if __name__ == "__main__":
    main()
