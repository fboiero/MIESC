# Paper 2 v-next Baseline Decision - 2026-06-28

This is a non-frozen decision report for Paper 2 remediation. It does not
change `paper/`, generated PDFs, reproducibility manifests, canonical claim
matrices, or `benchmarks/results/fix_eval_results.json`.

## Executive Decision

Recommendation: prepare a formal Paper 2 v-next baseline from the retry-v8
evidence, but do not silently replace the current paper numbers.

The v8 run is strong enough to become the next candidate baseline because it
keeps the same SmartBugs-curated corpus and patched-contract denominator as the
current v2 paper baseline while improving the two most important quality
signals:

- target finding eliminated by MIESC re-scan: `86/123` -> `88/123`;
- external Slither clean-HIGH: `58/123` -> `67/123`;
- external residual HIGH findings: `65` -> `56`;
- external Slither errors: `0` -> `0`.

The v8 change is not just a better aggregate number. It also records
`scan_empty` retry metadata, which explains earlier applied-set instability and
makes the evaluation more auditable.

## Evidence Sources

Current Paper 2 v2 canonical source:

- `benchmarks/results/fix_eval_results.json`
- `paper/PAPER2_REPRODUCIBILITY.md`
- `paper/paper2-remediation.tex`

v-next candidate source:

- `benchmarks/results/fix_eval_full_external_slither_retry_20260628_codex_v8.json`
- `benchmarks/results/fix_eval_full_external_slither_retry_details_20260628_codex_v8.json`
- `benchmarks/results/fix_eval_scan_empty_retry_access_control_external_slither_20260628_codex.json`
- `benchmarks/results/fix_eval_full_external_slither_v7_delta_triage_20260627_codex.json`

## Aggregate Comparison

| Metric | Current v2 baseline | v8 candidate | Decision |
| --- | ---: | ---: | --- |
| Corpus contracts | 143 | 143 | same denominator |
| Fixes applied | 123 | 123 | same patched set size |
| Fixed contracts compiling | 123/123 | 123/123 | stable |
| Target finding eliminated | 86/123 = 69.9% | 88/123 = 71.5% | improves |
| Bounded no-regression | 121/123 = 98.4% | 121/123 = 98.4% | stable |
| Scan-empty contracts | 2 | 2 | stable, now retry-accounted |
| Scan retries | not recorded | 2 | improves auditability |
| External Slither checked | 123 | 123 | stable |
| External Slither clean-HIGH | 58/123 = 47.2% | 67/123 = 54.5% | improves |
| External HIGH findings | 65 | 56 | improves |
| External Slither errors | 0 | 0 | stable |

The candidate baseline should be described as an incremental v-next
stabilization of the v2 external-validation method, not as a different
experiment.

## Claim Matrix

| Candidate claim | Source | Promotion status | Notes |
| --- | --- | --- | --- |
| MIESC emits patches for 123/143 current-scan contracts. | v8 aggregate totals | promotable | Same denominator as v2. Keep `18 no-HIGH` and `2 scan_empty` explicit. |
| 123/123 emitted patches compile standalone. | v8 aggregate totals | promotable | Strong, stable claim. |
| 88/123 patches eliminate the target finding by MIESC re-scan. | v8 aggregate totals | promotable with caveat | Re-scan remains same-family validation; keep separate from Slither clean-HIGH. |
| 121/123 satisfy bounded no-regression. | v8 aggregate totals | promotable with caveat | Bounded scanner criterion, not semantic equivalence. |
| 67/123 patched contracts are clean of HIGH findings under external Slither. | v8 aggregate totals | promotable | Best headline upgrade; external validation remains independent but not proof of correctness. |
| Remaining external HIGH findings fall to 56. | v8 external ranking | promotable as residual analysis | Useful in limitations/future work. |
| The retry harness stabilizes scan-empty variability. | v8 metadata + v7 triage | promotable as methodology note | Do not overstate: two contracts still scan-empty after retry. |

## Residual HIGH Findings

v8 external Slither HIGH ranking:

| Check | Count | Interpretation |
| --- | ---: | --- |
| `controlled-array-length` | 28 | Requires contract-specific storage/accounting redesign; generic bounded-push was rejected because it did not remove the detector and adds policy. |
| `weak-prng` | 13 | Requires oracle/commit-reveal/VRF redesign; generic replacements would be detector-silencing. |
| `reentrancy-eth` | 10 | Some residuals are still patcher candidates only when CEI state update patterns are stable; remaining cases need case review. |
| `shadowing-state` | 9 | Mostly code-structure quality issue; generic rename is risky without whole-contract semantic context. |
| `arbitrary-send-eth` | 3 | Game/reward payout semantics; owner-only or recipient rewrites can break intended behavior. |
| `uninitialized-state` | 3 | Owner-state case improved; non-owner state initialization needs contract-specific defaults. |
| `controlled-delegatecall` | 1 | Fallback/unknown delegatecall remains semantic risk; generic guard can break proxy-like behavior. |
| `encode-packed-collision` | 1 | Hash-domain redesign; must preserve signature/hash compatibility. |

Residual interpretation: the remaining gap is mostly semantic, not syntactic.
The paper should say compilation is solved for emitted patches, while semantic
closure under independent analyzers remains the research frontier.

## Scientific Framing

Use separate metrics. Do not collapse v8 into one success rate.

Recommended wording:

> In the v-next retry-stabilized run, MIESC emits 123 patches over the
> 143-contract SmartBugs-curated corpus, compiles all emitted patches
> standalone, eliminates the target finding in 88/123 cases by MIESC re-scan,
> and leaves 67/123 patched contracts clean of HIGH findings under external
> Slither validation.

Avoid:

- claiming "88 contracts fixed" without saying "by MIESC re-scan";
- claiming "67 contracts verified" without saying "clean of HIGH findings under
  external Slither";
- treating `121/123 no-regression` as functional equivalence;
- implying residual `weak-prng`, `controlled-array-length`, or payout semantics
  can be safely solved by a generic patch.

## Paper Update Impact

If Fernando authorizes a frozen paper baseline update, update these surfaces:

- Paper 2 abstract: `86/123` -> `88/123`, `58/123` -> `67/123`.
- Contributions: external clean-HIGH percentage `47%` -> `55%`.
- Methodology: add `--scan-empty-retries 1` and `scan_retries` accounting.
- Aggregate table: replace v2 aggregate values with v8 values.
- Category/residual discussion: residual HIGH findings `65` -> `56`, ranking as
  listed above.
- Reproducibility doc: record v8 artifact paths and command.
- Claims matrix: regenerate from the approved canonical artifact.
- Freeze manifest and PDFs: regenerate only after all text/artifact edits are
  approved.

Do not change `benchmarks/results/fix_eval_results.json` until the paper
baseline update is explicitly authorized.

## Recommended Next Loop

Run a final paper-baseline dry audit before touching frozen files:

1. Generate a small derived claims table from v8 and current v2 JSON.
2. Verify all paper text occurrences that would change.
3. Produce an edit checklist with exact line targets in `paper/paper2-remediation.tex`
   and `paper/PAPER2_REPRODUCIBILITY.md`.
4. Ask Fernando for explicit authorization to promote v8 to canonical Paper 2
   baseline.

If authorization is not granted, keep v8 as supplemental v-next evidence and
continue technical work on one residual class at a time.
