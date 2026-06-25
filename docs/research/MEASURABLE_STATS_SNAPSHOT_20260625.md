# Measurable Stats Snapshot (2026-06-25)

> Single source of truth for the tool's measurable state, captured during the stat-improvement
> loop. Additive R&D; no frozen paper evidence touched. Paper numbers are quoted for reference
> only (their canonical sources are the claims matrices).

## Improved this session (loop)

| Stat | Before | After | How |
|------|--------|-------|-----|
| `triage_ranker.py` coverage | 61% | **90%** | tests for `rank_results` + `train` |
| `benign_context_verifier.py` coverage | 76% | **83%** | tests for `filter()` + LLM JSON parsing |
| Triage model AUC (held-out) | 0.922 | **0.942** | 5-fold CV tuned hyperparameters (400/4) |
| Ranking effective precision @80% recall | 0.72 | **0.80** | tuned model |
| `dataset_adapters.py` tests | 0 | **8** | SWC/lineNumber parsers + SolidiFI adapter |
| Code4rena/Sherlock scraper tests | 0 | **11** | permalink/severity/category/folder parsers |
| `wild_benign_context_eval.py` tests | 0 | **9** | anchoring logic (anchored_real/_norm/load_gt) |
| `train_triage_model.py` tests | 0 | **1** | dataset builder reshape + dedup |

**+40 tests** on the session's new code; all green.

## Current ceilings (already near-optimal in-env)

| Module | Coverage |
|--------|----------|
| intelligence.py | 98% |
| fp_filter.py | 97% |
| result_aggregator.py | 96% |
| fp_ml_classifier.py | 92% |
| triage_ranker.py | 90% |
| vulnerability_clusterer.py | 99% |
| slither_validator.py | 97% |
| taint_analysis.py | 99% |

The core is consistently 90–99% covered; coverage is at practical ceiling. (A naive subset
test-run showed a misleading 39% src/ml total — a measurement artifact, not a gap: each module
is covered by its own test file. Always run a module's own tests before declaring a gap.)

## Recall-safe verifier / triage (this session's R&D)

| Stat | Value |
|------|-------|
| Verifier recall across 6 ground-truth sources | **1.0** (cardinal invariant) |
| Deterministic recall-safe precision lift | ~+4pp (method-independent ceiling) |
| Triage ranking AUC | 0.942 |
| Triage at 90% recall | review ~40% of findings at ~2× precision (0.66 vs 0.30) |
| `--verify-fp` + `--rank` | recall-safe; redundant for effective precision |

## Env-blocked levers (need a working solc-select)

The big detection/remediation benchmarks cannot move in this dev box (solc-select broken;
Slither cannot compile the legacy corpora). They are quoted from the frozen claims matrices:

| Benchmark | Current |
|-----------|---------|
| SmartBugs recall | 95.8% (Paper 1) |
| SmartBugs precision | 22.2% |
| EVMBench ensemble recall | 92.5% |
| DeFi exploit recall | 81.8% |
| Paper 2 remediation: applied / compile / eliminate / no-regression | 123/143 · 100% · 86/123 · 121/123 |

To improve these (e.g. Paper 1 v-next 95.8%→99.3%, or precision via the validated triage
ranking integrated into the corpus eval), run in the paper reproduction environment.
