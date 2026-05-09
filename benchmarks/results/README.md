# Benchmark Results

This directory keeps curated benchmark outputs that support reproducible claims,
papers, or release gates.

## Canonical Evidence

Paper evidence:

- `paper1_claims_matrix.json`
- `paper1_smartbugs_eval*.json`
- `paper1_smartbugs_eval*.jsonl`
- `paper1_smartbugs_full_all_layers_smoke_20260506.json`
- `paper1_smartbugs_full_all_layers_smoke_20260506.jsonl`
- `paper2_claims_matrix.json`
- `paper2_compile_failure_by_category.json`
- `paper2_compile_failure_taxonomy.json`
- `paper2_experiment_audit.json`
- `paper2_patch_quality_by_transform.json`

Release or regression evidence:

- `v5.1.6_benchmark_report.md`
- `v5.1.6_deep_audit_rekt_report.md`
- `v5.1.6_fp_dataset_pilot.md`
- `v5.1.7_gates_report.md`
- `tooling_smoke_layers_1_6.json`
- `tooling_smoke_layers_1_6.jsonl`

## Policy

Timestamped exploratory outputs should not be committed by default. Keep them
local under `evaluation_results/`, `analysis/`, or `reports/` unless a paper,
release note, or reproducibility guide references them directly.

When a new result becomes canonical, add it to this README and link it from the
corresponding paper or release documentation.
