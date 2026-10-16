# Paper 1 — Reproducibility (RIBCi–CYTED 2026 camera-ready)

Version: camera-ready, 2026-10-16.

This document maps every quantitative claim in Paper 1
(`paper/ribci-cyted-2026/paper1-camera-ready.tex`) to the repository artifact and
command that produces it. A single script re-checks all of them:

```bash
python benchmarks/verify_paper_claims.py
```

It recomputes each figure from its backing JSON, confirms the value appears in the
camera-ready `.tex`, verifies that every artifact named in the "Data Availability"
section exists, and exits non-zero on any mismatch. Documented discrepancies are
listed in `paper/ribci-cyted-2026/ERRATA.md`.

## Environment

| Component | Version / setting |
|---|---|
| OS | macOS ARM64 (Apple Silicon, 48 GB) for the canonical runs; Linux/Docker for the revalidation and the ablation |
| MIESC | v5.4.1, tag `09ef10f` |
| Python | 3.14.4 for the original SmartBugs runs (2026-05-06…09); 3.12.6 for the 2026-10 regeneration and verification |
| Slither | 0.11.5 (pinned in `requirements-lock.txt`; the regenerated camera-ready artifacts do not re-run Slither, so the exact patch version does not affect them) |
| solc | selected per-contract `pragma` via `solc-select` (e.g. `^0.4.x → solc-0.4.26`) |
| Foundry | 1.3.5 |
| Determinism | all generators honour `SOURCE_DATE_EPOCH`; the camera-ready artifacts were regenerated with `SOURCE_DATE_EPOCH` = 2026-10-16 |

## Artifact → claim → command

| Claim (paper value) | Artifact | Command |
|---|---|---|
| SmartBugs recall 95.8 % (137/143), precision 22.2 %, F1 36.0 % | `benchmarks/results/paper1_smartbugs_eval_layers_1_6_7.json` | `python -m miesc.cli.main evaluate corpus benchmarks/datasets/smartbugs-curated/dataset --layers 1,6,7 --timeout 120 --output <json> --jsonl <jsonl>` |
| SmartBugs FP count (see ERRATA E-1: paper 481, consistent 480) | `..._corrected_20261016.json` | same run; corrected copy via the aggregate/per-category reconciliation |
| LLM-free ablation 82.5 % → 93.0 % → 97.9 % (118/133/140) | `paper1_ablation_l1_raw_20261015.json`, `..._l167_raw_...`, `..._l167_intel_...` | `python benchmarks/paper1_ablation_summary.py` |
| Local-Ollama follow-up 97.9 % (140/143) | `paper1_smartbugs_local_ollama_followup_20260623.json` | follow-up scan over the 6 residual misses |
| Real-world exploits 9/11, Wilson CI [52 %, 95 %], $1.59 B | `paper1_exploits_eval_20260621.json` | `python benchmarks/evaluate_exploits.py` (needs DeFiHackLabs sources) |
| EVMBench providers (claude 82.5 %, GPT-5 77.5 %, GPT-4o 73.7 %, Ollama 59.2 %) | `evmbench/evmbench_*_40*.json` | stored MIESC provider runs |
| EVMBench static-only 18.3 % (22/120) | `evmbench/evmbench_static_40.json` | `EVMBENCH_AUDITS_DIR=... python benchmarks/evmbench_eval.py --max-audits 40 --output <json>` |
| EVMBench ensemble union 92.5 % (111/120) | `evmbench/evmbench_ensemble_40.json` + `paper1_claims_matrix.json` | `SOURCE_DATE_EPOCH=2026-10-16 python benchmarks/generate_paper1_artifacts.py` |
| EVMBench null control 50 % (60/120); control-resistant subset 60 | computed | `python benchmarks/evmbench_matcher_null_control.py evmbench/evmbench_claude46_40_FINAL.json --ensemble evmbench/evmbench_ensemble_40.json` |
| Same run, every protocol: lenient 88.3 % (106/120), control-resistant 78.3 % (47/60), GPT-4o 21.4 % (25/117), GPT-5 27.4 % (32/117), judge agreement 104/117, GPT-5∩lenient 30/32 | `evmbench/same_run_claude_20261016/{summary,verdicts}.json` | `python benchmarks/evmbench_same_run_protocols.py --model claude --judges gpt-4o,gpt-5 --out evmbench/same_run_claude_20261016` |
| FP filter removes 207/1,263 (16 %), precision 13.3 % → 15.5 % | `smartbugs_fp_filter_effect_20260710.json` | `python benchmarks/smartbugs_fp_filter_effect_20260710.py` |

The per-claim matrix with `source_file`/`command`/`date` for each entry is
`benchmarks/results/paper1_claims_matrix.json`.

## EVMBench: official vs local

The official EVMBench source (OpenAI, 2026-02-18; arXiv:2603.04915;
`github.com/paradigmxyz/evmbench`) describes **117** curated vulnerabilities. The
local MIESC extraction evaluates **120** high-severity findings across 40 audit
entries. The paper labels the local figure "EVMBench local extraction" and never
conflates it with the official 117. The same-run official-judge protocol scores
against the official 117.

## Known limitations of the artifacts

- **Platform-dependent SmartBugs recall.** The canonical macOS run detects
  137/143 (95.8 %); a Linux/Docker revalidation of the same release detects
  140/143 (97.9 %), recovering the two front-running and one short-address
  contracts. The difference is not traced to a specific cause, so 95.8 % is kept
  as the conservative primary figure and configurations are compared only within
  one environment.
- **Unparsed judge responses in the same-run EVMBench experiment.** Of the 197
  contract files scanned across the 40 audits, 8 LLM responses could not be
  parsed ("Could not parse response" in
  `evmbench/same_run_claude_20261016.log`); those findings are simply absent, not
  credited.
- **Exploit case study runs on attack reproductions, not victims.** The 9/11
  result analyzes DeFiHackLabs proof-of-concept harnesses, not the exploited
  victim contracts. A victim-code re-run was attempted and **discarded** for
  methodological reasons (see `data/datasets/rekt_exploits/victims/README.md`).
- **Parser crashes in the pre-patch baseline.** In the Paper 2 pre-patch Slither
  baseline, a small number of contracts fail to parse/compile and are recorded as
  such rather than silently dropped; counts reflect only successfully analyzed
  contracts.
- **Small exploit sample.** n = 11 gives a wide Wilson interval ([52 %, 95 %]);
  the exploit recall is reported as indicative, not a population estimate.

## Editorial rule

A Paper 1 numeric claim is publishable only if it appears in
`benchmarks/results/paper1_claims_matrix.json` with a `supported*` or
`external_*` status and is reproduced by `benchmarks/verify_paper_claims.py`.
RAG sources (policy in `docs/guides/RAG_SOURCE_POLICY.md`) support
interpretation and classification only; they never substitute for the direct
experimental evidence above.
