# Safe-Precision Feasibility — the ~+4pp ceiling is method-independent (2026-06-24)

> Additive tool R&D. Tests whether a LEARNED FP filter can beat the deterministic
> recall-safe precision ceiling (~+4pp) established earlier this session. Reproduce with
> `scripts/fp_classifier_feasibility.py {build,run}`.

## Setup

- **Data:** 2,595 findings consolidated from the wild-harness anchored labels across the
  ground-truth sources (772 real/TP, 1,823 FP). Label convention matches the classifier
  (`label=True` = real, `False` = FP).
- **Model:** MIESC's `src/ml/fp_ml_classifier.py` GradientBoosting classifier (17 engineered
  features: severity, type-hash, code-length bucket, Solidity≥0.8, has-library, tool one-hot).
- **Method:** 70/30 stratified split; on held-out, sweep the drop threshold on `P(FP)`; the
  **recall-safe** threshold is the highest at which 0 real findings are dropped.

## Result

| Threshold `P(FP)≥` | real_lost | recall | FP dropped | precision |
|---|---|---|---|---|
| **0.99** (recall-safe) | **0** | **1.000** | 88/547 (16%) | 0.298 → **0.336 (+3.8pp)** |
| 0.97 | 7 | 0.970 | 206 | 0.398 |
| 0.90 | 10 | 0.957 | 280 | 0.454 |
| 0.70 | 46 | 0.802 | 396 | 0.552 |

At its recall-safe operating point the learned filter delivers **+3.8pp** — statistically
tied with the deterministic **+4.1pp** ceiling. It does **not** break it. There is a sharp
recall cliff: dropping the threshold from 0.99 to 0.97 immediately loses 7 real vulns.

## Interpretation

**The ~+4pp safe-precision ceiling is method-independent.** Deterministic rules, the LLM
(advisory, this session), and now a trained classifier all top out at the same place. About
3% of real vulnerabilities are scored as likely-FP by the classifier, so any recall-safe
threshold must be extreme and only removes the FPs it is most certain about. The residual
FPs are **semantically entangled** with real findings of the same type and cannot be
separated by aggregate features without losing real vulns. This is a publishable negative
result: recall-safe FP filtering has a hard, low ceiling on these corpora.

## The one untested lever

The classifier used **coarse aggregate features**. The deterministic rules win their +4pp by
using **structural** signals (a guard in the finding's function, a checked return on the
flagged line) that the 17 features do not encode. The open question: does feeding the
classifier (a) the deterministic benign-pattern match signals and (b) code embeddings
(MIESC's RAG `all-MiniLM-L6-v2`) let it find a recall-safe point that beats +4pp? If richer
features still tie +4pp, the ceiling is confirmed fundamental; if they beat it, that is the
safe-precision evolution Paper 1 v-next needs.

Artifact: `scripts/fp_classifier_feasibility.py`. Wild harness + sources:
[WILD_FIELD_MEASUREMENT_20260622.md](WILD_FIELD_MEASUREMENT_20260622.md),
[DATASET_SOURCE_CLASSIFICATION.md](DATASET_SOURCE_CLASSIFICATION.md).
