#!/usr/bin/env python3
"""P1-C — Render the EVMBench per-provider comparison as a paper-ready table.

Reads the ``evmbench_<provider>_40.json`` files (from evmbench_eval.py, run WITH
--judge) and emits a booktabs comparison table plus a text summary, ranked by
recall. Only files present are shown, so it works while some providers are still
running. Corrupt files (``*.CORRUPT_*``) are ignored by construction — pass only
the clean paths.

Usage:
    python benchmarks/evmbench_compare_table.py                 # all providers found
    python benchmarks/evmbench_compare_table.py -o p1c_table.tex

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

import argparse
import json
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results" / "evmbench"

# Paper-facing provider labels (order is the canonical display order).
PROVIDERS = [
    ("gpt-4o", "GPT-4o"),
    ("gpt-5", "GPT-5"),
    ("claude", "Claude Sonnet 4.6"),
]


def load(provider):
    f = RESULTS_DIR / f"evmbench_{provider}_40.json"
    if not f.exists():
        return None
    d = json.loads(f.read_text())
    return {
        "recall": d.get("recall"),
        "detected": d.get("total_detected"),
        "vulns": d.get("total_vulns"),
        "audits": d.get("audits_evaluated"),
    }


def main():
    ap = argparse.ArgumentParser(description="EVMBench provider comparison table")
    ap.add_argument("-o", "--output", type=Path, help="write .tex here (default: stdout)")
    args = ap.parse_args()

    rows = []
    for key, label in PROVIDERS:
        r = load(key)
        if r and r["recall"] is not None:
            rows.append((label, r))
    if not rows:
        raise SystemExit("No provider result files found in " + str(RESULTS_DIR))
    rows.sort(key=lambda x: -x[1]["recall"])

    print("=== P1-C EVMBench provider comparison (with LLM judge) ===")
    for label, r in rows:
        print(f"  {label:<20} recall {r['recall']:.1%}  "
              f"({r['detected']}/{r['vulns']} vulns, {r['audits']}/40 audits)")
    missing = [lab for k, lab in PROVIDERS if not load(k)]
    if missing:
        print(f"  (still pending: {', '.join(missing)})")

    lines = [
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{EVMBench per-provider detection recall (40 Code4rena audits, "
        "MIESC static+frontier pipeline, LLM-judge matching).}",
        "\\label{tab:evmbench-providers}",
        "\\begin{tabular}{lccc}",
        "\\toprule",
        "Provider & Recall & Vulns & Audits \\\\",
        "\\midrule",
    ]
    for label, r in rows:
        lines.append(f"{label} & {r['recall'] * 100:.1f}\\% & "
                     f"{r['detected']}/{r['vulns']} & {r['audits']}/40 \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    tex = "\n".join(lines)

    print()
    if args.output:
        args.output.write_text(tex + "\n")
        print(f"LaTeX table -> {args.output}")
    else:
        print(tex)


if __name__ == "__main__":
    main()
