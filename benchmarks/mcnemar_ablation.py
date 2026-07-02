#!/usr/bin/env python3
"""P1-A.2 — Paired McNemar test on the ablation's per-contract outcomes.

The ablation compares detection configs over the SAME contracts, so "with vs
without the intelligence layer" is a PAIRED comparison. Comparing two aggregate
recall numbers cannot tell you whether the difference is significant; McNemar
can, because it looks at the discordant pairs (contracts one config detects and
the other misses).

Reads an ``ablation_study_*.json`` produced by ``ablation_study.py`` (which now
records ``per_contract`` detection outcomes per config) and reports the 2x2
contingency table, the McNemar statistic and a p-value.

Usage:
    python benchmarks/mcnemar_ablation.py                       # latest file, all_layers vs L1_L3_symbolic
    python benchmarks/mcnemar_ablation.py --input <file.json>
    python benchmarks/mcnemar_ablation.py --on all_layers --off L1_static

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

import argparse
import json
import sys
from pathlib import Path

from scipy import stats

PROJECT_ROOT = Path(__file__).parent.parent
RESULTS_DIR = PROJECT_ROOT / "benchmarks" / "results"


def latest_ablation_file():
    files = sorted(RESULTS_DIR.glob("ablation_study_*.json"))
    if not files:
        sys.exit(f"ERROR: no ablation_study_*.json in {RESULTS_DIR}")
    return files[-1]


def get_per_contract(data, config_name):
    """Return {contract_path: bool} for a config, or exit if missing."""
    for cfg in data.get("configurations", []):
        if cfg.get("config") == config_name:
            pc = cfg.get("per_contract")
            if not pc:
                sys.exit(
                    f"ERROR: config '{config_name}' has no per_contract data. "
                    "Re-run ablation_study.py with the per-contract patch."
                )
            return pc
    have = [c.get("config") for c in data.get("configurations", [])]
    sys.exit(f"ERROR: config '{config_name}' not found. Available: {have}")


def mcnemar(on, off):
    """Compute the 2x2 table and McNemar test over the shared contracts.

    Convention: 'on' = intelligence layer enabled, 'off' = without it.
    b = on detects & off misses (intelligence helped)
    c = on misses & off detects (intelligence hurt)
    """
    shared = sorted(set(on) & set(off))
    a = b = c = d = 0
    for k in shared:
        o, f = bool(on[k]), bool(off[k])
        if o and f:
            a += 1
        elif o and not f:
            b += 1
        elif not o and f:
            c += 1
        else:
            d += 1
    n_disc = b + c

    # Exact binomial for few discordant pairs; chi-square (continuity-corrected)
    # for larger samples — the standard McNemar guidance (threshold ~25).
    if n_disc == 0:
        method, stat, p = "no discordant pairs", 0.0, 1.0
    elif n_disc < 25:
        method = "exact binomial"
        res = stats.binomtest(b, n_disc, 0.5, alternative="two-sided")
        stat, p = float(b), float(res.pvalue)
    else:
        method = "chi-square (continuity-corrected)"
        stat = (abs(b - c) - 1) ** 2 / n_disc
        p = float(stats.chi2.sf(stat, df=1))

    return {"a": a, "b": b, "c": c, "d": d, "n": len(shared),
            "method": method, "statistic": stat, "p_value": p}


def main():
    ap = argparse.ArgumentParser(description="Paired McNemar test on ablation outcomes")
    ap.add_argument("--input", type=Path, help="ablation_study_*.json (default: latest)")
    ap.add_argument("--on", default="all_layers", help="intelligence-ON config (default: all_layers)")
    ap.add_argument("--off", default="L1_L3_symbolic",
                    help="intelligence-OFF baseline config (default: L1_L3_symbolic)")
    ap.add_argument("--save", action="store_true", help="write a dated JSON next to the input")
    args = ap.parse_args()

    path = args.input or latest_ablation_file()
    data = json.loads(Path(path).read_text())
    on = get_per_contract(data, args.on)
    off = get_per_contract(data, args.off)
    r = mcnemar(on, off)

    print(f"\n{'='*60}")
    print("  McNemar paired test — intelligence layer contribution")
    print(f"  input: {Path(path).name}")
    print(f"  ON = {args.on}   OFF = {args.off}   (n={r['n']} shared contracts)")
    print(f"{'='*60}")
    print(f"  {'':<22}{'OFF detects':>14}{'OFF misses':>14}")
    print(f"  {'ON detects':<22}{r['a']:>14}{r['b']:>14}")
    print(f"  {'ON misses':<22}{r['c']:>14}{r['d']:>14}")
    print(f"{'-'*60}")
    print(f"  discordant: b (ON only)={r['b']}  c (OFF only)={r['c']}")
    print(f"  method: {r['method']}")
    print(f"  statistic = {r['statistic']:.4f}   p-value = {r['p_value']:.4g}")
    sig = "SIGNIFICANT (p<0.05)" if r["p_value"] < 0.05 else "NOT significant (p>=0.05)"
    direction = "intelligence HELPS" if r["b"] > r["c"] else (
        "intelligence HURTS" if r["c"] > r["b"] else "no net direction")
    print(f"  => {sig}; net direction: {direction}")
    print(f"{'='*60}\n")

    if args.save:
        out = RESULTS_DIR / f"mcnemar_{args.on}_vs_{args.off}.json"
        out.write_text(json.dumps({"input": Path(path).name, "on": args.on,
                                   "off": args.off, **r}, indent=2) + "\n")
        print(f"  Saved to: {out}")


if __name__ == "__main__":
    main()
