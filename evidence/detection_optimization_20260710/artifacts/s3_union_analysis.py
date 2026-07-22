"""Union analysis: what do we recover by NOT running DeepSeek in isolation?

Recomputes, from stored raw findings, the SET of ground-truth vulns each run
detected, then shows the union across runs (self-ensemble) — no API calls. This
answers: can we stop losing to non-determinism and gain by combining runs?
"""
import json
from pathlib import Path

import sys
sys.path.insert(0, "benchmarks/results/detection_optimization_20260710")
from s3_deepseek_measure import GT, matched  # reuse ground truth + matcher

DIR = Path("benchmarks/results/detection_optimization_20260710")


def detected_set(run_json):
    """Set of (contract, gt_line) this run detected, from its stored raw findings."""
    d = json.loads((DIR / run_json).read_text())
    found = set()
    for name, vulns in GT.items():
        findings = d["raw"][name]["findings"]
        for (ln, kws) in vulns:
            if matched(ln, kws, findings):
                found.add((name, ln))
    return found


TOTAL = sum(len(v) for v in GT.values())


def show(label, s):
    print(f"  {label:38} {len(s):2}/{TOTAL} = {len(s)/TOTAL:.1%}")


def main():
    runs = {}
    for f in ["s3_ds_baseline.json", "s3_ds_lever.json",
              "s3_ds_baseline_run2.json", "s3_ds_lever_run2.json"]:
        if (DIR / f).exists():
            runs[f.replace("s3_ds_", "").replace(".json", "")] = detected_set(f)

    print("=== corridas individuales ===")
    for k, s in runs.items():
        show(k, s)

    print("\n=== UNIONS (self-ensemble, sin API extra) ===")
    if "baseline" in runs and "lever" in runs:
        u = runs["baseline"] | runs["lever"]
        show("baseline UNION lever (run1)", u)
        print(f"      lever solo perdia: {sorted(runs['baseline'] - runs['lever'])}")
    all_ds = set().union(*runs.values()) if runs else set()
    show(f"UNION de las {len(runs)} corridas DeepSeek", all_ds)

    # Static+pattern floor (the prior stage) — from s3_static_set.json
    sf = DIR / "s3_static_set.json"
    if sf.exists():
        static_set = {tuple(x) for x in json.loads(sf.read_text())["static_set"]}
        print("\n=== EL PISO PREVIO (static) + UNION COMPLETO ===")
        show("static (slither) solo", static_set)
        full = static_set | all_ds
        show("static UNION DeepSeek(todas)", full)
        best_single = max([len(s) for s in runs.values()] + [len(static_set)])
        print(f"      mejor single = {best_single}/{TOTAL} = {best_single/TOTAL:.1%}"
              f"  ->  union = {len(full)}/{TOTAL} = {len(full)/TOTAL:.1%}  (+{len(full)-best_single})")
        print(f"      DeepSeek le suma a static: {sorted(all_ds - static_set)}")
        print(f"      static le suma a DeepSeek: {sorted(static_set - all_ds)}")
        never_caught = {(n, ln) for n, vs in GT.items() for (ln, _) in vs} - full
        print(f"      NADIE detecta ({len(never_caught)}): {sorted(never_caught)}")

    Path(DIR / "s3_union_result.json").write_text(json.dumps(
        {"total": TOTAL, "runs": {k: sorted(map(list, v)) for k, v in runs.items()},
         "union_all": sorted(map(list, all_ds)), "union_recall": len(all_ds) / TOTAL}, indent=2))


if __name__ == "__main__":
    main()
