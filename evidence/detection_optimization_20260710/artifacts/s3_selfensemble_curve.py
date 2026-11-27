"""Self-ensemble curve: does unioning N independent DeepSeek runs keep gaining?

Loads the independent lever runs (s3_ds_lever_i*.json), reports single-run
variance, and the union recall as N grows (averaged over all k-subsets, so the
curve is order-independent), plus static UNION full-ensemble. No API calls.
"""
import json
import itertools
from pathlib import Path
import sys

sys.path.insert(0, "benchmarks/results/detection_optimization_20260710")
from s3_deepseek_measure import GT, matched

DIR = Path("benchmarks/results/detection_optimization_20260710")
TOTAL = sum(len(v) for v in GT.values())


def detected_set(path):
    d = json.loads(path.read_text())
    found = set()
    for name, vulns in GT.items():
        fs = d["raw"][name]["findings"]
        for (ln, kws) in vulns:
            if matched(ln, kws, fs):
                found.add((name, ln))
    return found


def main():
    run_paths = sorted(DIR.glob("s3_ds_lever_i*.json"))
    sets = [detected_set(p) for p in run_paths]
    n = len(sets)
    if n == 0:
        print("no independent runs yet")
        return

    singles = [len(s) for s in sets]
    print(f"=== {n} corridas lever independientes ===")
    print(f"  single-run recall: min={min(singles)/TOTAL:.1%} "
          f"mean={sum(singles)/n/TOTAL:.1%} max={max(singles)/TOTAL:.1%}  "
          f"(vulns: {sorted(singles)})")

    print("\n=== curva de union (promedio sobre todos los k-subsets) ===")
    curve = []
    for k in range(1, n + 1):
        sizes = [len(set().union(*combo)) for combo in itertools.combinations(sets, k)]
        avg = sum(sizes) / len(sizes)
        curve.append(avg)
        marg = f"  (+{avg - curve[k - 2]:.2f})" if k > 1 else ""
        print(f"  union de {k}: {avg/TOTAL:6.1%}  ({avg:.2f}/{TOTAL}){marg}")

    full = set().union(*sets)
    print(f"\n  UNION de las {n} (techo self-ensemble): {len(full)}/{TOTAL} = {len(full)/TOTAL:.1%}")

    sf = DIR / "s3_static_set.json"
    if sf.exists():
        static_set = {tuple(x) for x in json.loads(sf.read_text())["static_set"]}
        combined = static_set | full
        print(f"  static ({len(static_set)}) UNION self-ensemble ({len(full)}) = "
              f"{len(combined)}/{TOTAL} = {len(combined)/TOTAL:.1%}")
        never = {(nm, ln) for nm, vs in GT.items() for (ln, _) in vs} - combined
        print(f"  NADIE detecta ({len(never)}): {sorted(never)}")

    Path(DIR / "s3_selfensemble_result.json").write_text(json.dumps({
        "n_runs": n, "singles": singles, "union_curve": curve,
        "full_union": len(full), "total": TOTAL}, indent=2))


if __name__ == "__main__":
    main()
