#!/usr/bin/env python3
"""Render the P1-A ablation results as a paper-ready LaTeX table.

Reads an ``ablation_study_*.json`` (from ablation_study.py) and, optionally, a
McNemar result (from mcnemar_ablation.py), and emits a booktabs table plus a
plain-text summary. Honest by construction: the caption records the LLM model
actually used and whether the run is partial, and per-config SD is shown when a
variance config was measured.

Usage:
    python benchmarks/ablation_to_latex.py                     # latest ablation, no McNemar
    python benchmarks/ablation_to_latex.py --mcnemar benchmarks/results/mcnemar_all_layers_vs_L1_L3_symbolic.json
    python benchmarks/ablation_to_latex.py --input <file.json> -o table.tex

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
RESULTS_DIR = PROJECT_ROOT / "benchmarks" / "results"

# Human-readable, paper-facing names for the ablation configs.
LABELS = {
    "L1_static": "Static (Slither+Aderyn)",
    "L1_L3_symbolic": "\\; + Symbolic (Mythril)",
    "L1_L5_llm": "\\; + Intelligence (LLM)",
    "L1_L3_L5": "\\; + Symbolic + Intelligence",
    "all_layers": "All layers",
}


def latest_ablation_file():
    files = sorted(RESULTS_DIR.glob("ablation_study_*.json"))
    if not files:
        sys.exit(f"ERROR: no ablation_study_*.json in {RESULTS_DIR}")
    return files[-1]


def pct(x):
    return f"{x * 100:.1f}\\%"


def fmt_metric(cfg, key):
    """Mean, with ±SD when the config carries a metrics_std (variance run)."""
    m = cfg["metrics"][key]
    sd = cfg.get("metrics_std")
    if sd and key in sd:
        return f"{m * 100:.1f} $\\pm$ {sd[key] * 100:.1f}\\%"
    return pct(m)


def build_table(data, mcnemar):
    model = data.get("llm_model", "config-default")
    partial = data.get("partial", False)
    n = data.get("total_contracts", "?")
    partial_note = " \\textbf{[PARTIAL RUN]}" if partial else ""

    lines = [
        "\\begin{table}[t]",
        "\\centering",
        f"\\caption{{Layer-contribution ablation on SmartBugs-curated "
        f"({n} contracts, model \\texttt{{{model}}}). Raw detector output "
        f"\\emph{{before}} the false-positive filter.{partial_note}}}",
        "\\label{tab:ablation}",
        "\\begin{tabular}{lccc}",
        "\\toprule",
        "Configuration & Recall & Precision & F1 \\\\",
        "\\midrule",
    ]
    for cfg in data.get("configurations", []):
        label = LABELS.get(cfg["config"], cfg["config"])
        nruns = cfg.get("num_runs", 1)
        runtag = f" ($n{{=}}{nruns}$)" if nruns > 1 else ""
        lines.append(
            f"{label}{runtag} & {fmt_metric(cfg, 'recall')} & "
            f"{fmt_metric(cfg, 'precision')} & {fmt_metric(cfg, 'f1')} \\\\"
        )
    lines += ["\\bottomrule", "\\end{tabular}"]

    if mcnemar:
        on, off = mcnemar.get("on", "?"), mcnemar.get("off", "?")
        stat, p = mcnemar.get("statistic"), mcnemar.get("p_value")
        method = mcnemar.get("method", "McNemar")
        sig = "significant" if (p is not None and p < 0.05) else "not significant"
        lines.append(
            f"\\vspace{{2pt}}\\footnotesize McNemar ({LABELS.get(on, on)} vs "
            f"{LABELS.get(off, off)}, {method}): statistic $={stat:.3f}$, "
            f"$p = {p:.3g}$ ({sig})."
        )
    lines.append("\\end{table}")
    return "\n".join(lines)


def build_summary(data, mcnemar):
    out = ["=== P1-A ablation summary ===",
           f"model: {data.get('llm_model')}  partial: {data.get('partial')}  "
           f"configs: {data.get('configs_completed', len(data.get('configurations', [])))}"]
    for cfg in data.get("configurations", []):
        m = cfg["metrics"]
        sd = cfg.get("metrics_std")
        rec = f"{m['recall']:.1%}" + (f" ±{sd['recall']:.1%}" if sd else "")
        out.append(f"  {cfg['config']:<16} recall {rec:<14} prec {m['precision']:.1%}  f1 {m['f1']:.1%}")
    if mcnemar:
        out.append(f"  McNemar {mcnemar.get('on')} vs {mcnemar.get('off')}: "
                   f"p={mcnemar.get('p_value'):.3g} ({mcnemar.get('method')})")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Render ablation results as LaTeX")
    ap.add_argument("--input", type=Path, help="ablation_study_*.json (default: latest)")
    ap.add_argument("--mcnemar", type=Path, help="mcnemar_*.json (optional)")
    ap.add_argument("-o", "--output", type=Path, help="write .tex here (default: stdout)")
    args = ap.parse_args()

    path = args.input or latest_ablation_file()
    data = json.loads(Path(path).read_text())
    mcnemar = json.loads(args.mcnemar.read_text()) if args.mcnemar else None

    table = build_table(data, mcnemar)
    print(build_summary(data, mcnemar))
    print()
    if args.output:
        args.output.write_text(table + "\n")
        print(f"LaTeX table → {args.output}")
    else:
        print(table)


if __name__ == "__main__":
    main()
