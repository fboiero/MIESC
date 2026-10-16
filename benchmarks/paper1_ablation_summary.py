"""Paper 1 controlled ablation on SmartBugs-curated (deterministic, no LLM).

Recomputes contract-level recall, precision, Wilson 95% intervals and paired
exact McNemar tests from three `miesc evaluate corpus` outputs produced with
MIESC v5.4.1 in one environment:

  1. layer 1 static analyzers only, intelligence engine off
       miesc evaluate corpus <smartbugs>/dataset --layers 1 --no-intelligence
  2. layers 1, 6, 7, intelligence engine off
       miesc evaluate corpus <smartbugs>/dataset --layers 1,6,7 --no-intelligence
  3. layers 1, 6, 7, intelligence engine on (the paper's profile)
       miesc evaluate corpus <smartbugs>/dataset --layers 1,6,7

Usage:
    python3 benchmarks/paper1_ablation_summary.py \
        benchmarks/results/paper1_ablation_l1_raw_20261015.json \
        benchmarks/results/paper1_ablation_l167_raw_20261015.json \
        benchmarks/results/paper1_ablation_l167_intel_20261015.json
"""
import json
import sys
from math import comb, sqrt


def hits(path):
    data = json.load(open(path))
    out = {}
    for rec in data["per_contract"]:
        key = rec["contract"].split("dataset/")[-1]
        out[key] = bool(set(rec["ground_truth"]) & set(rec["aggregate"]["detected_categories"]))
    return out, data["aggregate"]


def wilson(k, n, z=1.959964):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return 100 * (c - h), 100 * (c + h)


def mcnemar(x, y):
    b = sum(1 for k in x if x[k] and not y[k])
    c = sum(1 for k in x if y[k] and not x[k])
    n = b + c
    p = min(1.0, 2 * sum(comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n) if n else 1.0
    return b, c, p


names = ["Layer 1 static, no intelligence", "Layers 1+6+7, no intelligence", "Layers 1+6+7 + intelligence"]
runs = [hits(p) for p in sys.argv[1:4]]
for name, (h, agg) in zip(names, runs):
    k, n = sum(h.values()), len(h)
    lo, hi = wilson(k, n)
    print(f"{name:34s} recall {k}/{n} = {100 * k / n:.1f}% [{lo:.1f}, {hi:.1f}]  "
          f"precision {100 * agg['precision']:.1f}%  (TP {agg['tp']}, FP {agg['fp']})")
for (i, j) in ((0, 1), (1, 2), (0, 2)):
    lost, gained, p = mcnemar(runs[i][0], runs[j][0])
    print(f"{names[i]} -> {names[j]}: gained {gained}, lost {lost}, exact McNemar p = {p:.2g}")
