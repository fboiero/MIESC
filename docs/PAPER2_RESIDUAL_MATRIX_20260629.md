# Paper 2 v8 Residual Matrix - 2026-06-29

This note is a non-frozen planning artifact for Paper 2 v-next. It does not
edit the paper text, generated PDFs, canonical claims matrices, or canonical
benchmark artifacts.

## Executive State

The retry-v8 external Slither run is the strongest current noncanonical Paper 2
candidate:

| Metric | Value |
| --- | ---: |
| Contracts | 143 |
| Fixes applied | 123 |
| Fixes that compile | 123/123 |
| Vulnerabilities eliminated by internal rescan | 88/123 |
| No regression by internal rescan | 121/123 |
| External Slither checked | 123 |
| External Slither clean-HIGH | 67/123 |
| External Slither residual HIGH findings | 56 |
| External Slither errors | 0 |

The remaining HIGH findings are not mostly compile or harness defects anymore.
They are concentrated in detector classes where safe generic remediation is
limited by contract semantics. The next scientific improvement should therefore
separate stable patch candidates from residuals that must be described as
limitations or manually remediated examples.

## Post-v8 Reentrancy Update - 2026-06-30

A later reentrancy-category external Slither run closed the last current
`reentrancy-eth` residual in that category without changing compile or
regression gates:

| Evidence | Value |
| --- | ---: |
| Artifact | `benchmarks/results/fix_eval_reentrancy_spank_dual_20260630_codex.json` |
| Contracts | 31 |
| Fixes that compile | 31/31 |
| Vulnerabilities eliminated by internal rescan | 30/31 |
| No regression by internal rescan | 29/31 |
| External Slither checked | 31 |
| External Slither errors | 0 |
| `reentrancy-eth` residuals | 0 |

This is category-level evidence, not yet a promoted full-corpus baseline. The
retry-v8 full-run table above should remain unchanged until a new full
noncanonical external Slither run repeats the improvement with explicit
noncanonical output paths.

## Residual Matrix

| External Slither check | Count | Example contracts | Classification | Safe next action | Claim guidance |
| --- | ---: | --- | --- | --- | --- |
| `controlled-array-length` | 28 | `access_control/mapping_write.sol`; `bad_randomness/blackjack.sol`; `bad_randomness/lottery.sol` | Documentation-only / semantic redesign. Generic bounded-push rewriting was already rejected by evidence because it does not reliably clear the finding and risks behavior changes. | Do not add a generic transform. Only document the residual or add a manual case study when the array invariant is explicit. | Treat as residual semantic risk, not a patcher failure. Do not claim elimination without a contract-specific proof. |
| `weak-prng` | 13 | `bad_randomness/blackjack.sol`; `bad_randomness/lucky_doubler.sol`; `bad_randomness/random_number_generator.sol` | Documentation-only / semantic redesign. Replacing entropy sources honestly requires an oracle, commit-reveal protocol, VRF, or application-level redesign. | Keep the generic autopatch rejected. If needed, build one manual redesign appendix, separate from automated remediation metrics. | Avoid detector-silencing claims. Present as an intentionally out-of-scope semantic remediation class. |
| `reentrancy-eth` | 10 in retry-v8 full run; 0 in the 2026-06-30 current reentrancy-category run | `access_control/parity_wallet_bug_2.sol`; `reentrancy/0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol`; `reentrancy/reentrancy_bonus.sol`; later `reentrancy/spank_chain_payment.sol` | Mixed, now substantially improved in category evidence. Stable CEI patterns remain safe candidates, but fallback/proxy and payout variants need care. | Do not add broad generic rewrites. The next evidence step is a full noncanonical external run to see whether category gains repeat at corpus level. | Claim current category elimination of `reentrancy-eth` only with the 2026-06-30 artifact. Do not update full-corpus Paper 2 baseline numbers until a full rerun confirms it. |
| `shadowing-state` | 9 | `reentrancy/0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol`; several unchecked low-level call contracts | Mostly documentation-only. Safe remediation often requires whole-contract renaming, inheritance review, and ABI/storage-layout awareness. | Do not add a broad rename transform. Consider a manual example only if the inheritance and storage layout are trivial. | Report as a residual code-quality/security smell outside the automated patcher target. |
| `arbitrary-send-eth` | 3 | `other/crypto_roulette.sol`; `reentrancy/reentrancy_bonus.sol`; `time_manipulation/roulette.sol` | Documentation-only / payout semantics. Earlier probing showed generic onlyOwner or recipient rewrites would silence Slither by changing the game/reward behavior. | Keep generic transform rejected. Preserve as limitation unless a contract-specific payout invariant is known. | Do not count detector silencing as remediation when value-transfer semantics change. |
| `uninitialized-state` | 3 | `access_control/FibonacciBalance.sol`; `denial_of_service/send_loop.sol`; `unchecked_low_level_calls/lotto.sol` | Mixed. Owner-state initialization is already improved; remaining defaults are per-contract invariants. | Add targeted initialization only when the intended value is obvious from constructor or ownership logic. Otherwise document the residual. | Claim only narrowly, with before/after external evidence for each class. |
| `controlled-delegatecall` | 1 | `access_control/FibonacciBalance.sol` | Semantic proxy/fallback residual. Named delegatecall functions improved previously, but fallback/unknown delegatecall cannot be safely gated generically. | Do not patch fallback delegatecall broadly. Consider manual review notes. | Keep as residual semantic risk after the measured guard improvement. |
| `encode-packed-collision` | 1 | `reentrancy/spank_chain_payment.sol` | Documentation-only / signature-domain redesign. Fixing it may alter signed-message compatibility. | Do not rewrite hashes automatically. A safe fix needs explicit domain separation and migration plan. | Describe as protocol-level redesign, not automated source remediation. |

## Evidence-Backed Rejections

The following dated artifacts support not overclaiming generic fixes:

| Residual family | Evidence artifact | Decision |
| --- | --- | --- |
| `controlled-array-length` | `benchmarks/results/fix_eval_controlled_array_probe_20260624_codex.json` | Generic bounded-push remediation rejected. |
| `weak-prng` | `benchmarks/results/fix_eval_weak_prng_probe_20260624_codex.json` | Generic entropy replacement rejected. |
| `arbitrary-send-eth` | `benchmarks/results/fix_eval_arbitrary_send_probe_20260625_codex.json` | Generic payout rewrite rejected. |
| `reentrancy-eth` | `benchmarks/results/fix_eval_reentrancy_zeroing_single_20260628_codex.json` | Narrow zero-before-call CEI transform has direct external HIGH-removal evidence. |
| `reentrancy-eth` | `benchmarks/results/fix_eval_reentrancy_bonus_indirect_20260629_codex.json` | Boolean-claim ordering is semantic hardening; current external evidence does not improve Paper 2 aggregate metrics. |
| `reentrancy-eth` | `benchmarks/results/fix_eval_reentrancy_spank_dual_20260630_codex.json` | Exact SpankChain LCOpenTimeout and byzantineCloseChannel CEI transforms remove the last current reentrancy-category `reentrancy-eth` residual while preserving compile, no-regression, and external-error gates. |

## Next Probe Queue

1. Run a full noncanonical external Slither verification after the 2026-06-30
   reentrancy-category closure, using explicit `--results-output` and
   `--details-output` paths, before promoting any new Paper 2 baseline number.
2. Avoid generic transforms for `controlled-array-length`, `weak-prng`,
   `arbitrary-send-eth`, broad state shadowing, fallback delegatecall, and
   `abi.encodePacked` collisions unless a contract-specific invariant is
   available.
3. Continue any further `reentrancy-eth` probes only if a future full run exposes
   new residuals; prefer stable CEI signatures with direct external evidence.
4. Promote no new baseline metric until a full noncanonical external Slither run
   repeats the improvement with explicit `--results-output` and
   `--details-output` paths.

## Paper Wording Guidance

Paper 2 should frame retry-v8 as evidence that the remediation pipeline now
solves the engineering reliability layer: every applied fix compiles, external
validation completes without Slither errors, and the clean-HIGH metric improves
over the frozen v2 baseline. The remaining residuals should be described as the
semantic frontier of automated remediation, not as simple missed edits.

The strongest claim is:

> Automated remediation reached 123/123 compiling applied fixes and 67/123
> external clean-HIGH outcomes under independent Slither validation; remaining
> HIGH findings concentrate in classes that require semantic redesign,
> contract-specific invariants, or protocol migration.

Do not claim that retry-v8 fully fixes weak randomness, arbitrary payouts,
array-length control, fallback delegatecall, hash-domain collisions, or state
shadowing. Those are stronger as limitations and future-work targets because the
current evidence shows that honest remediation is more than detector silencing.
