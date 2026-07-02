# Paper 2 Post-Spank Promotion Audit - 2026-06-30

This is a dry audit for promoting the post-spank remediation evidence into a
future Paper 2 baseline. It does not edit frozen paper files, PDFs, canonical
benchmark artifacts, or claims matrices.

## Decision State

Ready for Fernando authorization, not ready for silent promotion.

The post-spank evidence is stronger than both the frozen Paper 2 v2 baseline
and the retry-v8 candidate. It preserves the v8 reliability gates and improves
the independent external Slither surface. Promotion still changes frozen paper,
benchmark, and claims surfaces, so it must happen as an explicit v-next
baseline operation with regenerated artifacts and freeze validation.

## Evidence Inputs

Current frozen v2 baseline:

- `benchmarks/results/fix_eval_results.json`
- `paper/paper2-remediation.tex`
- `paper/PAPER2_REPRODUCIBILITY.md`
- `benchmarks/results/paper2_claims_matrix.json`

Prior noncanonical retry-v8 candidate:

- `benchmarks/results/fix_eval_full_external_slither_retry_20260628_codex_v8.json`
- `benchmarks/results/fix_eval_full_external_slither_retry_details_20260628_codex_v8.json`
- `docs/PAPER2_VNEXT_PROMOTION_AUDIT_20260628.md`

Current post-spank candidate:

- `benchmarks/results/fix_eval_full_external_slither_post_spank_20260630_codex.json`
- `benchmarks/results/fix_eval_full_external_slither_post_spank_details_20260630_codex.json`
- `benchmarks/results/fix_eval_reentrancy_spank_dual_20260630_codex.json`
- `docs/PAPER2_RESIDUAL_MATRIX_20260629.md`

## Derived Claim Table

| Claim | Current v2 | Retry-v8 | Post-spank candidate | Promotion note |
| --- | ---: | ---: | ---: | --- |
| Corpus contracts | 143 | 143 | 143 | unchanged |
| Current-scan patches emitted | 123/143 = 86.0% | 123/143 = 86.0% | 123/143 = 86.0% | unchanged denominator |
| Standalone compilation | 123/123 = 100.0% | 123/123 = 100.0% | 123/123 = 100.0% | unchanged |
| Target finding eliminated by MIESC re-scan | 86/123 = 69.9% | 88/123 = 71.5% | 88/123 = 71.5% | same-family re-scan improvement vs v2 |
| Bounded no-regression | 121/123 = 98.4% | 121/123 = 98.4% | 121/123 = 98.4% | unchanged, not semantic equivalence |
| Scan-empty contracts | 2 | 2 | 2 | unchanged |
| Scan retries | not recorded | 2 | 2 | methodology/auditability improvement |
| External Slither checked | 123 | 123 | 123 | unchanged |
| External Slither clean-HIGH | 58/123 = 47.2% | 67/123 = 54.5% | 70/123 = 56.9% | strongest independent-validation improvement |
| External residual HIGH findings | 65 | 56 | 53 | improves residual profile |
| External `reentrancy-eth` HIGH findings | not separately claimed in v2 paper | 10 | 3 | post-spank closes most remaining reentrancy residuals |
| External Slither errors | 0 | 0 | 0 | unchanged |

Recommended headline wording:

> In the post-spank v-next candidate, MIESC emits 123 patches over the
> 143-contract SmartBugs-curated corpus, compiles all emitted patches
> standalone, eliminates the target finding in 88/123 cases by MIESC re-scan,
> satisfies the bounded no-regression criterion in 121/123 cases, and leaves
> 70/123 patched contracts clean of HIGH findings under external Slither
> validation. External `reentrancy-eth` residuals fall from 10 in retry-v8 to 3.

## Category And Residual Delta

Post-spank keeps retry-v8 category totals for application, compilation,
elimination, no-regression, scan-empty, and scan-retry counts. The measurable
new uplift is in independent external validation:

| External check | Retry-v8 | Post-spank | Delta |
| --- | ---: | ---: | ---: |
| `controlled-array-length` | 28 | 28 | 0 |
| `weak-prng` | 13 | 13 | 0 |
| `reentrancy-eth` | 10 | 3 | -7 |
| `shadowing-state` | 9 | 9 | 0 |
| `arbitrary-send-eth` | 3 | 3 | 0 |
| `uninitialized-state` | 3 | 3 | 0 |
| `controlled-delegatecall` | 1 | 1 | 0 |
| `encode-packed-collision` | 1 | 1 | 0 |

The full-run clean-HIGH improvement is smaller than the raw `reentrancy-eth`
drop because several contracts still contain other HIGH classes. This should be
reported honestly: the post-spank work improves the reentrancy residual profile
and the clean-HIGH aggregate, but it does not make the residual set trivial.

## Frozen File Targets

If Fernando authorizes promotion, these frozen files need edits. Line numbers
refer to the current `lane/codex` tree after rebasing on `main` commit
`0c6e083`.

### `paper/paper2-remediation.tex`

| Lines | Required update |
| ---: | --- |
| 61 | Abstract metrics: `86/123 -> 88/123`, `58/123 -> 70/123`; mention 123/123 compile and 121/123 no-regression remain unchanged. |
| 96 | Contribution metrics: keep `86%` application and `100%` compilation; update elimination `70% -> 72%` and clean-HIGH `47% -> 57%`. |
| 243 | Experimental setup: mention retry-stabilized external Slither validation with `--scan-empty-retries 1` and post-spank noncanonical evidence source before promotion. |
| 261-266 | Aggregate table: update eliminated row to `88/123` and `72%`; clean-HIGH row to `70/123` and `57%`; keep application, compile, no-regression, and fix-failed rows unchanged. |
| 271 | Aggregate narrative: update eliminated, clean-HIGH, and residual counts; mention 2 scan retries only if the promoted reproducibility note includes them. |
| 281-287 | Per-category table: update access-control eliminated `9 -> 10`, others eliminated `10 -> 11`, total eliminated `86 -> 88`; compile/no-regression rows remain unchanged. |
| 295-299 | Category and transformation narrative: update external clean-HIGH `58/123 -> 70/123`, residual HIGH `65 -> 53`, and describe `reentrancy-eth` `10 -> 3` versus retry-v8. |
| 413 | End-to-end narrative: update corpus-level percentages `70% -> 72%`, `47% -> 57%`. |
| 433 | Comparison table: update MIESC Fix% `70 -> 72` if the v-next baseline is promoted. |
| 441 | Comparison narrative: update `86/123, 70% -> 88/123, 72%`. |
| 445-447 | Failure analysis: update semantic gap `37/123 -> 35/123`, clean-HIGH `58/123 -> 70/123`, residual `65 -> 53`; note remaining residuals are dominated by semantic classes. |
| 467 | Compilation denominator remains accurate; optionally add that post-spank preserves the same denominator and compile result. |
| 495 | Threats to validity: add retry accounting and external residual-class ranking as mitigation, while preserving the warning about same-family re-scan. |
| 507 | Conclusion metrics: update `86/123 -> 88/123`, `70% -> 72%`, `58/123 -> 70/123`, `47% -> 57%`. |
| 511 | Limitations remain valid; no metric change required unless v-next text adds residual-class detail. |

### `paper/PAPER2_REPRODUCIBILITY.md`

| Lines | Required update |
| ---: | --- |
| 3 | Date should move to the approved v-next freeze date. |
| 5-14 | Add a v-next note above or after the v3 editorial note explaining post-spank evidence and that the baseline was explicitly promoted. |
| 18-30 | Baseline section: preserve denominator explanation, add retry accounting, update eliminated and clean-HIGH metrics. |
| 37-39 | Artifact table: replace or supplement canonical source with post-spank artifact paths after `fix_eval_results.json` is regenerated. |
| 52-58 | Reproduction command: add `--scan-empty-retries 1`; keep explicit canonical output paths only during authorized baseline regeneration. |
| 77 | Expected claim summary: `86/123 eliminated -> 88/123 eliminated`; add `70/123 clean-HIGH` if the generated script output is extended. |
| 100-114 | JSON expected totals: update `vuln_eliminated: 88`, add `scan_retries: 2`, update `external_clean_high: 70`, `external_findings: 53`; keep `external_errors: 0`. |
| 121-126 | Derived metrics table: update eliminated to `88/123 = 71.5%`, clean-HIGH to `70/123 = 56.9%`. |
| 141-144 | Interpretation: update clean-HIGH and residual HIGH counts; keep separated-metric warning. |

### Benchmark/Claims Surfaces

These are frozen or canonical and must be regenerated only inside an authorized
baseline-promotion pass:

- `benchmarks/results/fix_eval_results.json`: replace with approved post-spank
  totals only after explicit authorization.
- `benchmarks/results/paper2_claims_matrix.json`: regenerate from the approved
  canonical artifact.
- `benchmarks/results/paper2_patch_quality_by_transform.json`: regenerate to
  avoid stale derived evidence.
- `benchmarks/results/paper2_compile_failure_by_category.json`: likely
  unchanged but regenerate with the same toolchain.
- `benchmarks/results/paper2_compile_failure_taxonomy.json`: regenerate details
  from the canonical run.
- `benchmarks/results/paper2_experiment_audit.json`: regenerate and verify
  original-vs-patched joint success values.
- `paper/paper2-remediation.pdf`: regenerate from TeX after textual edits.
- arXiv/submission bundles and freeze manifest: regenerate after PDF
  validation.

## Promotion Gates

Before promotion:

1. Confirm Fernando authorizes a frozen Paper 2 v-next baseline update.
2. Re-validate post-spank aggregate and details JSON sanity from the candidate
   artifacts.
3. Regenerate canonical benchmark and derived claims artifacts from the same
   source.
4. Apply paper/reproducibility text edits with the line targets above.
5. Rebuild PDF and inspect the abstract, aggregate table, comparison table,
   failure analysis, conclusion, and reproducibility note.
6. Run the paper freeze validation script.
7. Commit and tag the baseline as a new explicit paper version.

## Non-Promotion Path

If authorization is not granted, keep the current v2 paper unchanged and treat
post-spank as supplemental v-next evidence. The next technical loop should
triage the 3 remaining full-run `reentrancy-eth` residuals individually, but
only promote new transforms when they preserve compile, no-regression, and
external-error gates.
