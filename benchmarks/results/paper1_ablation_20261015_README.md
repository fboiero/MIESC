# Paper 1 controlled ablation (2026-10-15)

Deterministic, no LLM. MIESC v5.4.1 (git tag `v5.4.1`), Slither 0.11.6, Linux,
static solc builds 0.4.24/0.4.25/0.4.26/0.5.17 in `~/.solc-select/artifacts`.
Aderyn, Solhint, Wake and Semgrep were not installed; the 4naly3er CLI was not
installed, so MIESC's built-in pattern fallback ran in its place.

| File | Command (run from the v5.4.1 checkout) |
|---|---|
| `paper1_ablation_l1_raw_20261015.json` | `miesc evaluate corpus benchmarks/datasets/smartbugs-curated/dataset --layers 1 --timeout 120 --no-intelligence` |
| `paper1_ablation_l167_raw_20261015.json` | `miesc evaluate corpus benchmarks/datasets/smartbugs-curated/dataset --layers 1,6,7 --timeout 120 --no-intelligence` |
| `paper1_ablation_l167_intel_20261015.json` | `miesc evaluate corpus benchmarks/datasets/smartbugs-curated/dataset --layers 1,6,7 --timeout 120` |

Note: the `reproducibility.command` field inside the JSON files does not record
`--no-intelligence`; this table is the authoritative record of the flags.

Summary, Wilson intervals and exact McNemar tests:
`python3 benchmarks/paper1_ablation_summary.py <l1_raw> <l167_raw> <l167_intel>`

Result: 118/143 (82.5%) -> 133/143 (93.0%) -> 140/143 (97.9%); gains 15 (p=6.1e-5)
and 7 (p=0.016), no contract lost. The full profile matches the Linux Docker
revalidation `paper1_smartbugs_revalidation_docker_20260709.json` (140/143).
