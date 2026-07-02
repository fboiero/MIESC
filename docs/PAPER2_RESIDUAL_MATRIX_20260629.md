# Paper 2 v8 Residual Matrix - 2026-06-29

This note is a non-frozen planning artifact for Paper 2 v-next. It does not
edit the paper text, generated PDFs, canonical claims matrices, or canonical
benchmark artifacts.

## Executive State

The post-spank external Slither run is the strongest current noncanonical Paper
2 candidate. It preserves the retry-v8 compile, elimination, and regression
gates while improving the independent external HIGH outcome:

| Metric | Value |
| --- | ---: |
| Contracts | 143 |
| Fixes applied | 123 |
| Fixes that compile | 123/123 |
| Vulnerabilities eliminated by internal rescan | 88/123 |
| No regression by internal rescan | 121/123 |
| External Slither checked | 123 |
| External Slither clean-HIGH | 70/123 |
| External Slither residual HIGH findings | 53 |
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

A follow-up full noncanonical external Slither run repeated the improvement at
corpus level:

| Evidence | Value |
| --- | ---: |
| Artifact | `benchmarks/results/fix_eval_full_external_slither_post_spank_20260630_codex.json` |
| Contracts | 143 |
| Fixes that compile | 123/123 |
| Vulnerabilities eliminated by internal rescan | 88/123 |
| No regression by internal rescan | 121/123 |
| External Slither clean-HIGH | 70/123 |
| External Slither residual HIGH findings | 53 |
| External Slither errors | 0 |
| `reentrancy-eth` residuals | 3 |

Compared with retry-v8, this improves clean-HIGH from 67/123 to 70/123, reduces
external HIGH findings from 56 to 53, and reduces `reentrancy-eth` from 10 to 3.
This is still noncanonical evidence: it is ready for Paper 2 v-next promotion
planning, but it does not update frozen PDFs, canonical benchmark artifacts, or
claims matrices by itself.

## Residual Matrix

| External Slither check | Count | Example contracts | Classification | Safe next action | Claim guidance |
| --- | ---: | --- | --- | --- | --- |
| `controlled-array-length` | 28 | `access_control/mapping_write.sol`; `bad_randomness/blackjack.sol`; `bad_randomness/lottery.sol` | Documentation-only / semantic redesign. Generic bounded-push rewriting was already rejected by evidence because it does not reliably clear the finding and risks behavior changes. | Do not add a generic transform. Only document the residual or add a manual case study when the array invariant is explicit. | Treat as residual semantic risk, not a patcher failure. Do not claim elimination without a contract-specific proof. |
| `weak-prng` | 13 | `bad_randomness/blackjack.sol`; `bad_randomness/lucky_doubler.sol`; `bad_randomness/random_number_generator.sol` | Documentation-only / semantic redesign. Replacing entropy sources honestly requires an oracle, commit-reveal protocol, VRF, or application-level redesign. | Keep the generic autopatch rejected. If needed, build one manual redesign appendix, separate from automated remediation metrics. | Avoid detector-silencing claims. Present as an intentionally out-of-scope semantic remediation class. |
| `reentrancy-eth` | 3 in post-spank full run; 0 in the 2026-06-30 current reentrancy-category run | remaining full-run residuals include non-reentrancy-category contracts such as fallback/proxy or cross-category payout patterns; `reentrancy/spank_chain_payment.sol` is now removed from `reentrancy-eth` | Mixed, substantially improved. Stable CEI patterns are largely exhausted in the reentrancy category; remaining full-corpus residuals likely need contract-specific fallback/proxy or payout reasoning. | Do not add broad generic rewrites. Triage the 3 remaining full-run residuals individually before any further transform. | Claim full-corpus `reentrancy-eth` reduction 10->3 with the post-spank artifact, and category-level reentrancy elimination with the category artifact. |
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
| `reentrancy-eth` | `benchmarks/results/fix_eval_full_external_slither_post_spank_20260630_codex.json` | Full noncanonical external Slither verification preserves 123/123 compile and 121/123 no-regression while improving clean-HIGH 67->70, external findings 56->53, and `reentrancy-eth` 10->3 versus retry-v8. |

## Next Probe Queue

1. Prepare a promotion audit for the post-spank full run: list exact frozen-file
   line targets, claims-matrix deltas, reproducibility notes, and rollback gates
   before any Fernando-authorized Paper 2 baseline update.
2. Avoid generic transforms for `controlled-array-length`, `weak-prng`,
   `arbitrary-send-eth`, broad state shadowing, fallback delegatecall, and
   `abi.encodePacked` collisions unless a contract-specific invariant is
   available.
3. Triage the 3 remaining full-run `reentrancy-eth` residuals individually. Do
   not add a new transform unless the target has a stable CEI signature and the
   external HIGH removal can be shown without compile or no-regression loss.
4. Promote no new canonical baseline metric until the promotion audit is
   reviewed and the frozen paper/benchmark update is explicitly authorized.

## Paper Wording Guidance

Paper 2 should frame the post-spank full run as evidence that the remediation
pipeline now solves the engineering reliability layer: every applied fix
compiles, external validation completes without Slither errors, and the
clean-HIGH metric improves over both the frozen v2 baseline and retry-v8. The
remaining residuals should be described as the semantic frontier of automated
remediation, not as simple missed edits.

The strongest claim is:

> Automated remediation reached 123/123 compiling applied fixes and 70/123
> external clean-HIGH outcomes under independent Slither validation, with
> `reentrancy-eth` residuals reduced from 10 to 3 versus the prior retry-v8
> candidate; remaining HIGH findings concentrate in classes that require
> semantic redesign, contract-specific invariants, or protocol migration.

Do not claim that the post-spank candidate fully fixes weak randomness, arbitrary payouts,
array-length control, fallback delegatecall, hash-domain collisions, or state
shadowing. Those are stronger as limitations and future-work targets because the
current evidence shows that honest remediation is more than detector silencing.
