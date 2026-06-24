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

## Rich features (coarse + structural) — tested

Adding the **12 structural signals the deterministic rules use** (benign-pattern match,
function-scoped guard, CEI ordering, checked return on the flagged line, native vs ERC20
transfer, pragma≥0.8, etc.) raised the feature set to 29. Within-source (mixed 30% held-out):

| Features | recall-safe precision (recall 1.0) |
|---|---|
| Coarse (17) | +3.8pp |
| **Rich (29)** | **+4.6pp** (apparently beats the deterministic +4.1pp) |

But that +4.6pp sits at threshold `P(FP)≥0.99`, and a **cross-source recall-safety sweep**
(train on fsalzano, hold out the audit-grade reals) shows 0.99 is **not reliably
recall-safe**:

| threshold | fsalzano FP-drop | fsalzano real lost | audit-grade real lost |
|---|---|---|---|
| 0.99 | 23% | **1** | 0/88 |
| **0.995** | 6.6% | **0** | 0/88 |
| 0.999 | 1.1% | 0 | 0/88 |

The robustly recall-safe operating point (0 reals lost across fsalzano **and** audit-grade)
is **0.995**, which drops 6.6% of FPs for a **~+1.4pp** precision gain — **below the
deterministic +4.1pp**. The within-source +4.6pp was a threshold/split artifact that strict
cross-source calibration dissolves.

## Conclusion

1. **The ~+4pp deterministic ceiling STANDS.** A trained filter — coarse or rich — does not
   robustly beat it once calibrated for cross-source recall-safety. The residual FPs are
   semantically entangled with real findings; this is method-independent.
2. **But the rich ML filter is genuinely well-behaved on audit-grade findings**: 0 of 88
   held-out audit-grade real vulns are ever dropped, at any threshold. That is strictly
   better than the LLM and guard patterns, which *did* reason audit-grade reals away. So a
   rich-feature ML filter is a safe *advisory/triage* component, even though it is not a
   safe *dropper* beyond the deterministic floor.
3. **Lesson, lived again:** the in-sample gain (+4.6pp) did not survive strict out-of-sample
   recall-safety (+1.4pp). Validate cross-source before claiming a precision win.

Untested remaining levers: (a) an ENSEMBLE of the deterministic drops + the ML's *different*
safe drops (do they overlap or add?); (b) code embeddings (`all-MiniLM-L6-v2`, not installed
here). Either could move the floor; neither is shown to yet.

Artifact: `scripts/fp_classifier_feasibility.py` ({build,run,rich,cross}). Wild harness + sources:
[WILD_FIELD_MEASUREMENT_20260622.md](WILD_FIELD_MEASUREMENT_20260622.md),
[DATASET_SOURCE_CLASSIFICATION.md](DATASET_SOURCE_CLASSIFICATION.md).
