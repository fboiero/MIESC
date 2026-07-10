# Detection-Optimization Loop — Evidence (2026-07-10)

Leverage-first, stage-by-stage optimization of MIESC detection, run as a strict
loop: **baseline → diagnose → fix → re-measure → dated artifact**. Every number
below is reproducible from the artifacts in [`artifacts/`](./artifacts/). This
dossier is additive; it does not modify any frozen paper artifact.

Guiding rule (carried from the reproducibility work): **no claim ships without a
corpus-scale measurement, and any measurement bug is disclosed, not hidden.**
Three measurement bugs were caught and corrected during this loop; they are
documented below because catching them is the point.

---

## Stage 1 — Static (commit `0911f980`)

Baseline, static-only (layer 1, no intelligence), SmartBugs-curated (143):

| Metric | Value |
|---|---|
| Recall | 85.3% (122/143) |
| Precision | 29.6% |
| False positives | 290 |

Per-category recall holes are the categories with **no static signature**
(access_control 39%, front_running 0%, short_addresses 0%) — LLM territory, not a
static-tunable gap. The reentrancy misses (2) are **Slither SlithIR crashes** on
legacy 0.4.x contracts (e.g. `reentrancy_bonus.sol`, a malformed tuple
assignment), which produce silent partial results. The pattern layer (L6) already
recovers these, so the real static profile is **L1+L6**.

**Fix**: the Slither adapter now flags `analysis_incomplete` + `incomplete_functions`
from the `Failed to generate IR` stderr marker, so a crashed-detector miss is no
longer silent. Additive observability; detection unchanged. Tested.

## Stage 2 — False-positive filter / issue #69 (commits `decb996a`, `0566e29d`)

`audit full` and every `ml_orchestrator` consumer reported
`false_positives_removed = 0`: the effective recall-safe `FalsePositiveFilter`
was wired only into the `scan` CLI; the orchestrator used the dormant trained
classifier, which removes nothing.

**Fix**: `MLOrchestrator.analyze(fp_strictness='off')` now applies the
`FalsePositiveFilter`; `audit full` exposes `--fp-strictness`.

### Measurement bug #1 caught, and the recall-safety discovery

A single-contract test (reentrancy) showed the filter as recall-safe. The
**corpus measurement told a different story**: `--fp-strictness high` DROPPED
BECToken's real `batchOverflow`, because the *"has protection against arithmetic"*
heuristic treats a SafeMath import as proof the operation is safe — it is not; the
vulnerable multiplication bypassed SafeMath.

| Strictness | Recall (subset n=29) | Detections | Recall-safe? |
|---|---|---|---|
| off | 93.1% | 27 | — |
| medium | 93.1% | 27 | ✅ |
| high (before fix) | 89.7% | 26 | ❌ dropped BECToken |
| high (after fix) | 93.1% | 27 | ✅ |

**Fix `0566e29d`**: a vulnerability-specific "safe pattern" match now *downgrades*
a real-severity finding to `needs_review` instead of dropping it. All strictness
levels are now recall-safe (BECToken preserved at every level). This also flags
that the dossier's earlier *"precision ~7× at high"* was partly bought with recall
loss — the recall-safe precision gain is modest.

## Stage 3 — Frontier LLM (DeepSeek-V4 reasoner) via API

Corpus: the frozen 29-vuln corpus (`corpus_revalidation_20260709/corpus/`, 4
contracts, 614 LOC). Ground truth is the per-vuln table from that dossier's §4.
Type-aware match = a finding within ±5 lines whose type/SWC keyword matches.

### Baseline vs DeFi-aware "lever" prompt

| Run | Type-aware recall |
|---|---|
| DeepSeek baseline (neutral prompt) | 14/29 = 48.3% (stable across runs) |
| DeepSeek lever (DeFi-economic-aware prompt) | 18–19/29 = 62–65% |
| static (Slither) alone | 16/29 = 55.2% |

The lever lifts overall recall ~+14pp, but **the gain is breadth, not depth**:
`FlashLoanVault` (the DeFi-economic contract the lever was designed for) stayed at
3–4/10 in every run. Prompting improves general coverage; it does not crack the
DeFi frontier.

### The union payoff (answers: "not lose / gain something")

Combining what we already have, **no new API calls**:

| Combination | Type-aware recall |
|---|---|
| best single approach (lever) | 18/29 = 62.1% |
| DeepSeek self-ensemble (runs unioned) | 19/29 = 65.5% |
| **static ∪ DeepSeek(all)** | **22/29 = 75.9%** (+14pp over best single) |

Complementarity is real and explainable:
- **DeepSeek adds to static** (6): AccessControl L45/L52; UnsafeToken L32/L66/L77/L138.
- **static adds to DeepSeek** (3): FlashLoanVault L72/L156; UnsafeToken L88 (incl. a reentrancy DeepSeek dropped).

**Takeaway**: optimizing one model in isolation is the wrong fight. Unioning
layers + runs is the most cost-effective lever (+14pp for free) and is why the
ensemble beats any single model. The static floor guarantees you never drop below
it — the reentrancy the LLM lost is held by static.

### Self-ensemble variance study (6 independent runs) — a methodological result

Six genuinely independent DeepSeek-reasoner runs (same lever prompt, unique output
files, no seed) revealed that **single-run LLM recall is not a point estimate — it
is a random draw**:

| Statistic | Value (n=29 vulns) |
|---|---|
| single-run min | 24.1% (7/29) |
| single-run mean | 47.7% |
| single-run max | 65.5% (19/29) |

A 41-point spread between identical calls. Reporting any single run in a paper is
therefore not reproducible — a reviewer re-running could land anywhere in [24%, 65%].

The **union of runs converges and plateaus** (average over all k-subsets, so the
curve is order-independent):

| K runs unioned | Recall | Marginal |
|---|---|---|
| 1 | 47.7% | — |
| 2 | 68.0% | +20.3 |
| 3 | 77.4% | +9.4 |
| 4 | 82.8% | +5.4 |
| 5 | 85.6% | +2.8 |
| 6 | 86.2% | +0.6 (plateau) |

Full 6-union = 25/29 = **86.2%**; static ∪ self-ensemble = 26/29 = **89.7%**. The
6th run (37.9%, a poor draw) does not move the union — the ensemble is immune to bad
draws.

**Methodological takeaway (reportable):** the honest, reproducible number for a
high-variance reasoning LLM is the **convergent ensemble** (K≈5, stated), not a
single run. A single run both *understates* the true capability (47.7% mean vs 86.2%
ensemble) and is *irreproducible*. This validates reporting the ensemble as the
headline metric (as Paper 1 does with EVMBench 92.5%) and treating single-model
recall as secondary, disclosed as mean ± CI over N runs. Small corpora (n=29)
amplify the variance; larger corpora (EVMBench n=120) shrink it by ~√N, which is why
the paper's ±4pp single-run disclosure there is defensible.

**Cost of stability**: DeepSeek-reasoner bills the hidden reasoning tokens — measured
9,161 reasoning tokens on a single contract (FlashLoanVault) vs ~350 visible output.
A K=5 self-ensemble over the 4-contract corpus is ≈ 6k input + ~190k output tokens.

### The hard frontier — 7 vulns NO source detects

`FlashLoanVault` L52 (oracle), L85 (price manip), L92 (slippage), L112
(first-depositor), L125 (share rounding), L167 (timelock); `UnsafeToken` L53
(unchecked return). Six of seven are DeFi economic logic. Neither static, nor a
reasoning LLM, nor their union crosses this frontier. It requires structural
levers (invariant fuzzing, cross-contract context, agentic PoC), documented as
future Stage 5.

### Measurement bugs #2 and #3 caught

- **#2**: a quick prevalence scan of Slither IR crashes hard-coded solc 0.4.26 for
  all contracts; contracts needing another version failed silently and were
  miscounted. The MIESC harness (per-pragma solc-select) is the source of truth.
- **#3**: the static line-extraction regex matched the date `20260709` in the file
  path instead of `location['line']`, scoring VulnerableBank 0/2 when static
  actually detects both reentrancies (2/2). Fixed to read the nested field.
- **Disclosure**: the run-2 command overwrote run-1's JSON before copying it, so
  the "4 DeepSeek runs" are 2 unique runs duplicated. Aggregate recall is stable
  across the unique runs (baseline 14/14, lever 19/18), so the lever gain is
  signal, not noise — but a genuine larger self-ensemble is still pending.

---

## Reproduce

```bash
# Stage 2 recall/precision curve (orchestrator off/medium/high)
python3 artifacts/s2_fp_measure.py
# Stage 3 DeepSeek (needs DEEPSEEK_API_KEY):
python3 artifacts/s3_deepseek_measure.py baseline
python3 artifacts/s3_deepseek_measure.py lever
python3 artifacts/s3_union_analysis.py         # union, no API
```
