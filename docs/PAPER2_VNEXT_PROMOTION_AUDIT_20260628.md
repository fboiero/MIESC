# Paper 2 v-next Promotion Dry Audit - 2026-06-28

This is a dry audit for promoting the retry-v8 remediation evidence into a
future Paper 2 baseline. It does not edit frozen paper files, PDFs, canonical
benchmark artifacts, or claims matrices.

## Decision State

Ready for authorization, not ready for silent promotion.

The retry-v8 evidence is scientifically stronger than the current Paper 2 v2
baseline, but promoting it changes frozen paper and benchmark surfaces. The
promotion should therefore happen as an explicit v-next baseline operation with
regenerated PDFs, reproducibility notes, claim matrices, and freeze validation.

## Evidence Inputs

Current frozen v2 baseline:

- `benchmarks/results/fix_eval_results.json`
- `paper/paper2-remediation.tex`
- `paper/PAPER2_REPRODUCIBILITY.md`
- `benchmarks/results/paper2_claims_matrix.json`

Candidate v-next evidence:

- `benchmarks/results/fix_eval_full_external_slither_retry_20260628_codex_v8.json`
- `benchmarks/results/fix_eval_full_external_slither_retry_details_20260628_codex_v8.json`
- `docs/PAPER2_VNEXT_BASELINE_DECISION_20260628.md`

## Derived Claim Table

| Claim | Current v2 | Candidate v8 | Promotion note |
| --- | ---: | ---: | --- |
| Corpus contracts | 143 | 143 | unchanged |
| Current-scan patches emitted | 123/143 = 86.0% | 123/143 = 86.0% | unchanged denominator |
| Standalone compilation | 123/123 = 100.0% | 123/123 = 100.0% | unchanged |
| Target finding eliminated by MIESC re-scan | 86/123 = 69.9% | 88/123 = 71.5% | headline improvement, but same-family re-scan |
| Bounded no-regression | 121/123 = 98.4% | 121/123 = 98.4% | unchanged, still not semantic equivalence |
| Scan-empty contracts | 2 | 2 | unchanged |
| Scan retries | not recorded | 2 | methodology/auditability improvement |
| External Slither checked | 123 | 123 | unchanged |
| External Slither clean-HIGH | 58/123 = 47.2% | 67/123 = 54.5% | strongest independent-validation improvement |
| External residual HIGH findings | 65 | 56 | improves residual profile |
| External Slither errors | 0 | 0 | unchanged |

Recommended headline wording:

> In the retry-stabilized v-next run, MIESC emits 123 patches over the
> 143-contract SmartBugs-curated corpus, compiles all emitted patches
> standalone, eliminates the target finding in 88/123 cases by MIESC re-scan,
> satisfies the bounded no-regression criterion in 121/123 cases, and leaves
> 67/123 patched contracts clean of HIGH findings under external Slither
> validation.

## Category Delta

Only four category aggregates change versus the current v2 canonical baseline:

| Category | Delta |
| --- | --- |
| `access_control` | target eliminated `9 -> 10`, external clean-HIGH `13 -> 14`, external findings `4 -> 3` |
| `other` | target eliminated `1 -> 2`, external clean-HIGH `0 -> 1`, external findings `3 -> 2` |
| `reentrancy` | external clean-HIGH `2 -> 7`, external findings `29 -> 24` |
| `unchecked_low_level_calls` | external clean-HIGH `27 -> 29`, external findings `20 -> 18` |

All other category aggregates stay unchanged for the promoted metrics.

## Frozen File Targets

If Fernando authorizes promotion, these frozen files need edits. Line numbers
refer to the current working tree after rebasing on `main` commit
`4a2d427`.

### `paper/paper2-remediation.tex`

| Lines | Required update |
| ---: | --- |
| 61 | Abstract metrics: `86/123 -> 88/123`, `58/123 -> 67/123`; add retry-stabilized wording only if space allows. |
| 96 | Contribution metrics: keep `86%` application, `100%` compilation, update elimination `70% -> 72%` and clean-HIGH `47% -> 55%`. |
| 243 | Experimental setup: mention retry-stabilized external Slither validation and `scan_empty` retry accounting. |
| 261-266 | Aggregate table: update eliminated row to `88/123` and `72%`; clean-HIGH row to `67/123` and `55%`; keep other rows unchanged. |
| 271 | Aggregate narrative: update eliminated, no-regression unchanged, clean-HIGH changed; mention 2 scan retries if promoted. |
| 281-287 | Per-category table: update access control eliminated `9 -> 10`, others eliminated `10 -> 11`, total eliminated `86 -> 88`; validate whether category clean-HIGH is discussed outside table. |
| 295-299 | Category and transformation narrative: update residual discussion from 58 clean/65 residual to 67 clean/56 residual and describe reentrancy/unchecked-call external improvement. |
| 413 | End-to-end narrative: update corpus-level percentages `70% -> 72%`, `47% -> 55%`. |
| 433 | Comparison table: update MIESC Fix% `70 -> 72` if the v8 baseline is promoted. |
| 441 | Comparison narrative: update `86/123, 70% -> 88/123, 72%`. |
| 445-447 | Failure analysis: update semantic gap `37/123 -> 35/123`, clean-HIGH `58/123 -> 67/123`, residual `65 -> 56`; external-validation gap wording should be softened. |
| 467 | Compilation denominator remains accurate; optionally add that retry-v8 preserves the same denominator and compile result. |
| 495 | Threats to validity: add retry accounting as mitigation, while preserving the warning about same-family re-scan. |
| 507 | Conclusion metrics: update `86/123 -> 88/123`, `70% -> 72%`, `58/123 -> 67/123`, `47% -> 55%`. |
| 511 | Limitations remain valid; no metric change required unless v-next text adds retry-stabilized scope. |

### `paper/PAPER2_REPRODUCIBILITY.md`

| Lines | Required update |
| ---: | --- |
| 3 | Date should move to the approved v-next freeze date. |
| 5-14 | Add a v-next note above or after the v3 editorial note explaining retry-v8 and that the baseline was explicitly promoted. |
| 18-30 | Baseline section: preserve denominator explanation, add retry accounting, update eliminated and clean-HIGH metrics. |
| 37-39 | Artifact table: replace or supplement canonical source with retry-v8 artifact paths after `fix_eval_results.json` is regenerated. |
| 52-58 | Reproduction command: add `--scan-empty-retries 1`. |
| 77 | Expected claim summary: `86/123 eliminated -> 88/123 eliminated`. |
| 100-114 | JSON expected totals: update `vuln_eliminated`, add `scan_retries: 2`, update `external_clean_high` and `external_findings`. |
| 121-126 | Derived metrics table: update eliminated to `88/123 = 71.5%`, clean-HIGH to `67/123 = 54.5%`. |
| 141-144 | Interpretation: update clean-HIGH and residual HIGH counts; keep separated-metric warning. |

### Benchmark/claims surfaces

These are frozen or canonical and must be regenerated only inside an authorized
baseline-promotion pass:

- `benchmarks/results/fix_eval_results.json`: replace with approved v8 totals
  only after explicit authorization.
- `benchmarks/results/paper2_claims_matrix.json`: regenerate from the approved
  canonical artifact.
- `benchmarks/results/paper2_patch_quality_by_transform.json`: check whether
  unchanged; regenerate to avoid stale derived evidence.
- `benchmarks/results/paper2_compile_failure_by_category.json`: likely
  unchanged but regenerate with the same toolchain.
- `benchmarks/results/paper2_compile_failure_taxonomy.json`: regenerate details
  from the canonical run.
- `benchmarks/results/paper2_experiment_audit.json`: regenerate and verify
  original-vs-patched joint success values.
- `paper/paper2-remediation.pdf`: regenerate from TeX after textual edits.
- arXiv/submission bundles and freeze manifest: regenerate after PDF validation.

## Promotion Gates

Before promotion:

1. Confirm Fernando authorizes a frozen Paper 2 v-next baseline update.
2. Re-run or re-validate retry-v8 JSON sanity from the candidate artifact.
3. Regenerate canonical benchmark and derived claims artifacts from the same
   source.
4. Apply paper/reproducibility text edits with the line targets above.
5. Rebuild PDF and inspect the first page, aggregate table, comparison table,
   failure analysis, and conclusion.
6. Run the paper freeze validation script.
7. Commit and tag the baseline as a new explicit paper version.

## Non-Promotion Path

If authorization is not granted, keep the current v2 paper unchanged and treat
v8 as supplemental v-next evidence. The next technical loop should target one
remaining residual class, preferably `reentrancy-eth` because it improved under
v8 but still has 10 residual HIGH findings.
