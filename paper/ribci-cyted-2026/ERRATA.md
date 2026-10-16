# Errata — RIBCi-CYTED 2026 camera-ready (repo ↔ paper discrepancies)

This file records discrepancies found between the camera-ready papers and the
repository artifacts during the pre-congress verification (Phase 2 of
`PLAN_PRE_CONGRESO.md`). The camera-ready `.tex`/`.docx` were already sent to the
editors and are **not** modified here; each item is left for Fernando Boiero to
decide (accept as-is, publish an erratum, or correct in a future version).

Date opened: 2026-10-16

---

## E-1 — Paper 1: SmartBugs false-positive count 481 vs 480

**Where in the paper (Paper 1, `paper1-camera-ready.tex`):**
- Abstract and §V: "137 TP, **481** FP, 6 misses" (line ~251).
- §V: "arithmetic (128 of the **481** false-positive pairs), reentrancy (109) and
  unchecked low-level calls (64)" (line ~253).
- §VII: "reports **481** false-positive contract–category pairs" (line ~401).

**Discrepancy:** the repository artifact
`benchmarks/results/paper1_smartbugs_eval_layers_1_6_7.json` stores
`aggregate.fp = 481`, but:
- the sum of `per_category[*].fp` is **480**
  (access_control 47, arithmetic 128, unchecked_low_level_calls 64, reentrancy
  109, denial_of_service 46, bad_randomness 46, time_manipulation 35,
  front_running/other/short_addresses 0 for fp → 480 total);
- the stored `aggregate.precision = 0.2219` is consistent with **fp = 480**
  (137 / (137 + 480) = 0.2220), not with 481 (137 / 618 = 0.2217).

So the internally consistent value is **480**; the scalar `aggregate.fp = 481`
is an off-by-one outlier.

**Root cause:** in `benchmarks/smartbugs_evaluation.py` the global aggregate
(`metrics.false_positives += result.false_positives`, line 526) and the
per-category tally (`category_stats[cat]["fp"] += result.false_positives`,
line 532) are accumulated from the **same `result` in the same loop iteration**
(lines 519–534), so the code *forces* `aggregate.fp == sum(per_category.fp)`.
A run of this code cannot produce 481 global with 480 by category. The stored
481 is therefore an out-of-band scalar edit to the JSON that did not propagate to
`precision` or to the category breakdown; it is not reproducible from the script.

**Impact:** negligible, and it does not change the paper's main claim. Precision
rounds to **22.2 %** for both 480 (0.2220) and 481 (0.2217); recall is **95.8 %**
(137/143) either way. The only rounded figure that moves is F1: it is **36.0 %**
at fp = 481 (the value printed in the paper) and **36.1 %** at fp = 480. So the
artifact is internally mixed — the category breakdown and `precision` point to
480, while `aggregate.fp` and the reported F1 point to 481 — but the
disagreement is a single false-positive pair and leaves precision and recall
unchanged. The paper's own category breakdown sums to 480.

**Resolution in the repo (this cleanup):**
- The frozen artifact `paper1_smartbugs_eval_layers_1_6_7.json` is left
  **unchanged** as the record of the paper's run.
- A corrected, dated, internally consistent copy is published as
  `benchmarks/results/paper1_smartbugs_eval_layers_1_6_7_corrected_20261016.json`
  with `aggregate.fp = 480` and `precision` recomputed, plus a `correction`
  block pointing here.
- `benchmarks/verify_paper_claims.py` recomputes from the corrected artifact and
  flags the paper's 481 against the recomputed 480, referencing this entry.

**Decision pending (Fernando):** accept 481↔480 as a one-unit rounding-neutral
discrepancy (recommended; 22.2 % unchanged), or issue an erratum changing "481"
to "480" in a post-camera-ready version.
