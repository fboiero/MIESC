# MIESC benchmarks — script index

Index of the scripts under `benchmarks/`, grouped by role. "Canonical" scripts
produce a figure cited in the RIBCi–CYTED 2026 camera-ready papers (verified by
`verify_paper_claims.py`); "supporting" scripts build datasets or render paper
tables; "exploratory" scripts were used to investigate ideas and back no paper
figure; "legacy" scripts predate the camera-ready evaluation and are kept for
history.

Results land in `benchmarks/results/`. Naming convention for new result files:
`<paper>_<experiment>_<YYYYMMDD>.json` (e.g. `paper1_ablation_l167_raw_20261015.json`,
`evmbench/same_run_claude_20261016/`). Exploratory and superseded runs are not
cited by the papers; see each paper's `PAPER*_REPRODUCIBILITY.md` for the
authoritative artifact→claim→command mapping.

## Canonical — back a camera-ready figure

| Script | Purpose | Backs |
|---|---|---|
| `verify_paper_claims.py` | Recompute every paper figure from JSON and check the `.tex` + Data Availability. | both papers |
| `generate_paper1_artifacts.py` | EVMBench ensemble + Paper 1 claims matrix (deterministic, `SOURCE_DATE_EPOCH`). | Paper 1 |
| `generate_paper2_artifacts.py` | Paper 2 claims matrix + derived taxonomies from `fix_eval_results.json`. | Paper 2 |
| `audit_paper2_experiment.py` | Original-vs-patched compilation validity + joint metrics. | Paper 2 |
| `smartbugs_evaluation.py` | SmartBugs-curated detection evaluation engine (137/143, precision, F1). | Paper 1 |
| `paper1_ablation_summary.py` | Deterministic LLM-free ablation 82.5 → 93.0 → 97.9 % (118/133/140). | Paper 1 §ablation |
| `mcnemar_ablation.py` | Paired McNemar test over the ablation's per-contract outcomes. | Paper 1 §ablation |
| `evaluate_exploits.py` | Real-world exploit recall (9/11, Wilson CI) on the Rekt corpus. | Paper 1 |
| `evmbench_eval.py` | EVMBench recall for MIESC (static baseline 22/120, provider runs). | Paper 1 §EVMBench |
| `evmbench_matcher_null_control.py` | Null control: contract-agnostic findings credit 60/120 (50 %). | Paper 1 §EVMBench |
| `evmbench_same_run_protocols.py` | One run scored under every protocol (lenient + official GPT-4o/GPT-5). | Paper 1 §EVMBench |
| `evmbench_official_detect.py` | Official EVMBench detect-mode JUDGE_PROMPT grading (used by the same-run script). | Paper 1 §EVMBench |
| `smartbugs_fp_filter_effect_20260710.py` | FP filter effect: removes 207/1,263, precision 13.3 → 15.5 %. | Paper 1 §FP filter |
| `fix_eval.py` | `miesc scan` + `miesc fix` over SmartBugs with external Slither validation. | Paper 2 |
| `paper2_prepatch_slither_baseline.py` | Pre-patch Slither HIGH-finding baseline (before/after). | Paper 2 |

## Supporting — datasets and paper tables

| Script | Purpose |
|---|---|
| `build_datasets.py` | Build/refresh the benchmark datasets (SmartBugs, Rekt, …). |
| `ablation_to_latex.py` | Render the ablation results as a paper-ready LaTeX table. |
| `evmbench_compare_table.py` | Render the EVMBench per-provider comparison table. |
| `generate_charts.py` | Generate charts for SmartBugs evaluation results. |
| `check_regression.py` | CI benchmark-regression gate. |

## Exploratory — investigations, no paper figure

| Script | Purpose |
|---|---|
| `exploits_victim_rerun.py` | **DISCARDED** victim-code exploit re-run (see `data/datasets/rekt_exploits/victims/README.md`). |
| `deep_audit_rekt.py`, `deep_audit_rekt_llm.py` | DeepAuditAgent experiments on the Rekt corpus. |
| `p2b_scale_eval.py` | At-scale evaluation of the Paper 2 generation contributions. |
| `evaluate_extended_exploits.py` | Extended exploit evaluation (496 contracts). |
| `correlation_benchmark.py`, `correlation_evaluation.py` | Correlation-engine A/B experiments. |
| `etherscan_distribution.py` | Etherscan contract-distribution analysis. |

## Legacy — predate the camera-ready evaluation

`ablation_study.py` (superseded by `paper1_ablation_summary.py`),
`comparative_benchmark.py`, `competitor_comparison.py`, `complete_evaluation.py`,
`integrated_evaluation.py`, `scalability_benchmark.py`, `solidifi_benchmark.py`,
`run_benchmark.py`, `run_benchmarks.py`, `reproduce_benchmark.py`. Kept for
history; not part of the camera-ready evidence.
