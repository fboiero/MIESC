"""Compare the isolated EmbeddingRAG A/B across backends: Delta_7B vs Delta_32B.

Loads both raw datasets, runs the identical honest analysis on each (paired
majority-vote over both-success runs, Wilson 95% CIs, paired McNemar exact,
spray metrics, within-arm flip rate, per category), and prints side by side.
The headline comparison is whether a weaker backend moves RAG off the null the
32B showed.
"""

import json
import math
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent
DATASETS = {
    "32B": HERE / "rag_ab_raw_20261121.json",
    "7B": HERE / "rag_ab_raw_7b_20261121.json",
}


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d
    return (round(p, 4), round(max(0, centre - half), 4), round(min(1, centre + half), 4))


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    cdf = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return round(min(1.0, 2 * cdf), 4)


def analyse(raw_path):
    d = json.loads(raw_path.read_text())
    meta, rows = d["meta"], d["results"]
    by_cr = defaultdict(dict)
    true_cat = {}
    for r in rows:
        by_cr[(r["contract"], r["run"])][r["arm"]] = r
        true_cat[r["contract"]] = r["true_category"]
    contracts = sorted(true_cat)

    per = {}  # contract -> {"on":[hits], "off":[hits]}
    dropped = []
    # spray accumulators (paired both-success run-pairs)
    sp = {"n": 0, "nf_on": 0, "nf_off": 0, "ot_on": 0, "ot_off": 0, "t_on": 0, "t_off": 0}
    for c in contracts:
        on_hits, off_hits = [], []
        for run in (1, 2, 3):
            cell = by_cr.get((c, run), {})
            on, off = cell.get("on"), cell.get("off")
            if not on or not off:
                continue
            if on.get("status") != "success" or off.get("status") != "success":
                continue
            on_hits.append(1 if on.get("hit") else 0)
            off_hits.append(1 if off.get("hit") else 0)
            sp["n"] += 1
            sp["nf_on"] += on.get("n_findings", 0)
            sp["nf_off"] += off.get("n_findings", 0)
            tc = on["true_category"]
            sp["ot_on"] += sum(1 for x in (on.get("detected_categories") or []) if x != tc)
            sp["ot_off"] += sum(1 for x in (off.get("detected_categories") or []) if x != tc)
            sp["t_on"] += on.get("time_s", 0)
            sp["t_off"] += off.get("time_s", 0)
        if len(on_hits) < 2:
            dropped.append(c)
            continue
        per[c] = {"on": on_hits, "off": off_hits}

    def maj(lst):
        return sum(lst) * 2 >= len(lst)

    def summarize(cat=None):
        cs = [c for c in per if (cat is None or true_cat[c] == cat)]
        n = len(cs)
        on_det = {c: maj(per[c]["on"]) for c in cs}
        off_det = {c: maj(per[c]["off"]) for c in cs}
        on_k = sum(on_det.values())
        off_k = sum(off_det.values())
        b = sum(1 for c in cs if on_det[c] and not off_det[c])
        cc = sum(1 for c in cs if off_det[c] and not on_det[c])
        return {
            "n": n, "recall_on": wilson(on_k, n), "recall_off": wilson(off_k, n),
            "delta_pp": round((on_k - off_k) / n * 100, 1) if n else 0.0,
            "disc_on_only": b, "disc_off_only": cc, "mcnemar_p": mcnemar_exact(b, cc),
        }

    # within-arm ON flip rate
    flips = valid = 0
    for c in per:
        v = per[c]["on"]
        if len(v) >= 2:
            valid += 1
            if len(set(v)) > 1:
                flips += 1

    n = max(sp["n"], 1)
    return {
        "model": meta.get("model"), "digest": meta.get("model_digest"),
        "elapsed_min": meta.get("elapsed_min"), "n_dropped": len(dropped),
        "dropped": [Path(c).name for c in dropped],
        "flip_rate_on": f"{flips}/{valid}",
        "spray": {
            "nf_on": round(sp["nf_on"] / n, 2), "nf_off": round(sp["nf_off"] / n, 2),
            "offtarget_on": round(sp["ot_on"] / n, 2), "offtarget_off": round(sp["ot_off"] / n, 2),
            "time_on": round(sp["t_on"] / n, 1), "time_off": round(sp["t_off"] / n, 1),
        },
        "overall": summarize(),
        "by_category": {cat: summarize(cat) for cat in meta["categories"]},
    }


def fmt_ci(ci):
    return f"{ci[0]*100:.1f}% [{ci[1]*100:.1f},{ci[2]*100:.1f}]"


def main():
    res = {k: analyse(p) for k, p in DATASETS.items()}
    (HERE / "rag_ab_compare_20261122.json").write_text(json.dumps(res, indent=2))

    print("=" * 72)
    print("ISOLATED EmbeddingRAG A/B — 7B vs 32B (same corpus, same harness)")
    print("=" * 72)
    for k in ("32B", "7B"):
        r = res[k]
        o = r["overall"]
        print(f"\n### {k}  ({r['model']} {r['digest']}, {r['elapsed_min']}min, dropped={r['n_dropped']})")
        print(f"  OVERALL n={o['n']}  recall_ON={fmt_ci(o['recall_on'])}  "
              f"recall_OFF={fmt_ci(o['recall_off'])}")
        print(f"          DELTA={o['delta_pp']:+}pp  discordant(ON-only={o['disc_on_only']}, "
              f"OFF-only={o['disc_off_only']})  McNemar p={o['mcnemar_p']}")
        print(f"  SPRAY   findings ON={r['spray']['nf_on']} OFF={r['spray']['nf_off']}  |  "
              f"off-target ON={r['spray']['offtarget_on']} OFF={r['spray']['offtarget_off']}  |  "
              f"time ON={r['spray']['time_on']}s OFF={r['spray']['time_off']}s")
        print(f"  NOISE   within-arm(ON) flip rate = {r['flip_rate_on']}")
        for cat, s in r["by_category"].items():
            print(f"    {cat:14s} n={s['n']:2d}  ON={s['recall_on'][0]*100:5.1f}%  "
                  f"OFF={s['recall_off'][0]*100:5.1f}%  Δ={s['delta_pp']:+5.1f}pp  "
                  f"disc({s['disc_on_only']},{s['disc_off_only']})  p={s['mcnemar_p']}")
    print("\n" + "=" * 72)
    d32 = res["32B"]["overall"]["delta_pp"]
    d7 = res["7B"]["overall"]["delta_pp"]
    print(f"HEADLINE  ΔRecall_32B={d32:+}pp (p={res['32B']['overall']['mcnemar_p']})   "
          f"ΔRecall_7B={d7:+}pp (p={res['7B']['overall']['mcnemar_p']})")
    print("=" * 72)


if __name__ == "__main__":
    main()
