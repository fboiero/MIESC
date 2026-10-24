# Revert-invariant gap execution — advisory eval (2026-10-24)

**Non-canonical. No benchmark claim.** This exercises the `enable_gap_execution` path end-to-end
(`mine → execute_access_control_gaps → counterexample_findings`) on two controls. It is additive
evidence for the capability, not a precision/recall measurement, and touches no frozen artifact.

Reproduce with `benchmarks/revert_invariant_gap_eval.py` (raw result:
`revert_invariant_gap_execution_eval_20261024.json`). `forge` 1.3.5 was on PATH for this run.

## FP control — real audited libraries (expect 0)

Full source trees of OpenZeppelin `contracts`, Solady, and Uniswap v2-periphery (clone and pass
with `--fp-corpus`), globbed as `**/*.sol` (so test and example contracts are included too).

| Files scanned | Counterexamples | Findings emitted | Result |
|---------------|-----------------|------------------|--------|
| 805 | 0 | 0 | ✅ pass |

Silent for the right reason: these libraries have no inconsistent access-control family, and
guards behind modifiers/inheritance resolve to guarded/opaque rather than being flagged.

## Positive control — synthetic contracts with a known missing guard (expect a counterexample)

Small, execution-eligible contracts (no-arg constructor, elementary args).

| Fixture | Expected | Got | Findings | Result |
|---------|----------|-----|----------|--------|
| `unguarded_setter` (`setFee` guarded, `setTreasury` not) | `setTreasury` | `setTreasury` | 1 | ✅ |
| `unguarded_upgrade` (`upgradeTo` guarded, `upgradeImpl` not) | `upgradeImpl` | `upgradeImpl` | 1 | ✅ |
| `vacuous_revert` (unguarded setter reverts on a zero arg) | — | — | 0 | ✅ |
| `consistent_family` (both siblings guarded) | — | — | 0 | ✅ |

The last two are the precision checks: a call that reverts for an unrelated reason is **not**
promoted to a counterexample (no vacuous pass), and a consistent family produces no gap at all.

## Reading

- The path confirms a real missing access-control guard by *execution* (an unauthorized
  `address(0xBEEF)` call succeeds), not by inference, and only then emits a finding.
- It stays silent on a large body of audited code and on the two "looks-like-a-gap-but-isn't"
  shapes — consistent with the precision discipline of the whole revert-invariant chain.
- This says nothing about recall on real-world vulnerable contracts (most have constructor
  arguments and so fall outside the current executable subset); it is a soundness/FP probe only.
