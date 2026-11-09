# Paper 2 Post-FiftyFlip Full Audit - 2026-06-30

This note audits the non-canonical full external Slither run produced after the
exact `FiftyFlip.wager` CEI transform.

## Evidence

- Aggregate:
  `benchmarks/results/fix_eval_full_external_slither_post_fiftyflip_20260630_codex.json`
- Details:
  `benchmarks/results/fix_eval_full_external_slither_post_fiftyflip_details_20260630_codex.json`
- Previous comparison point:
  `benchmarks/results/fix_eval_full_external_slither_post_spank_20260630_codex.json`

Both new artifacts are additive and non-canonical. They do not overwrite
`benchmarks/results/fix_eval_results.json` or frozen paper artifacts.

## Aggregate Comparison

| Metric | Post-Spank candidate | Post-FiftyFlip run | Delta |
| --- | ---: | ---: | ---: |
| contracts | 143 | 143 | 0 |
| fix_applied | 123 | 122 | -1 |
| fix_compiles | 123 | 122 | -1 |
| vuln_eliminated | 88 | 85 | -3 |
| no_regression | 121 | 118 | -3 |
| scan_empty | 2 | 3 | +1 |
| external_checked | 123 | 122 | -1 |
| external_clean_high | 70 | 70 | 0 |
| external_findings | 53 | 52 | -1 |
| external_errors | 0 | 0 | 0 |

External HIGH ranking changed as follows:

| HIGH check | Post-Spank | Post-FiftyFlip | Delta |
| --- | ---: | ---: | ---: |
| controlled-array-length | 28 | 28 | 0 |
| weak-prng | 13 | 13 | 0 |
| shadowing-state | 9 | 9 | 0 |
| arbitrary-send-eth | 3 | 3 | 0 |
| reentrancy-eth | 3 | 2 | -1 |
| uninitialized-state | 3 | 2 | -1 |
| controlled-delegatecall | 1 | 0 | -1 |
| encode-packed-collision | 1 | 1 | 0 |

## Changed Contracts

Only five contracts changed materially versus the post-Spank full details:

| Contract | Change | Interpretation |
| --- | --- | --- |
| `access_control/FibonacciBalance.sol` | `applied` -> `scan_empty`; external checks `controlled-delegatecall`, `uninitialized-state` disappeared because the contract was not externally checked in the new run | Scan variability, not a remediation win. This explains the applied/external_checked drop. |
| `arithmetic/BECToken.sol` | `no_regression` became false, while external HIGH stayed clean | Rescan instability/no-regression accounting change; not caused by the FiftyFlip transform. |
| `arithmetic/integer_overflow_mapping_sym_1.sol` | `vuln_eliminated` became false due to a new `send-ether-no-checks` rescan finding | Rescan variability outside the touched pattern. |
| `reentrancy/0x941d225236464a25eb18076df7da6a91d0f95e9e.sol` | fixes applied changed 4 -> 2, `no_regression` and `vuln_eliminated` became false; external HIGH unchanged (`controlled-array-length`) | Applied-set/rescan variability outside the touched pattern. |
| `unchecked_low_level_calls/0xe09b1ab8111c2729a76f16de96bc86a7af837928.sol` | external HIGH findings 3 -> 2; `reentrancy-eth` removed, leaving `weak-prng` | Intended exact-transform effect. |

## Promotion Decision

Do not promote this full run as the Paper 2 global baseline.

The exact FiftyFlip transform is useful and measured: it removes one
`reentrancy-eth` external HIGH from the full run and from the
`unchecked_low_level_calls` category details without compile errors. However,
the full aggregate is less stable than the post-Spank candidate because
`fix_applied`, `vuln_eliminated`, and `no_regression` all decreased. The
post-Spank candidate remains the stronger global promotion candidate until a
repeat full run recovers the applied set and no-regression counts.

## Next Loop

1. Keep the exact FiftyFlip transform in the codebase because the focused
   category run showed `47/47` compile, `47/47` no-regression, and
   `reentrancy-eth` residuals `2 -> 1`.
2. Do not update frozen paper claims from the post-FiftyFlip full aggregate.
3. If a global promotion is needed, repeat the full external run once after
   main/lane stabilization and compare whether `scan_empty` returns to 2 and
   `no_regression` returns to 121.
