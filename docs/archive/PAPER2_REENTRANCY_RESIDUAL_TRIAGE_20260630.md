# Paper 2 Reentrancy Residual Triage - 2026-06-30

This is a non-frozen triage note for the 3 remaining `reentrancy-eth` HIGH
checks in the post-spank full external Slither run. It does not edit paper
files, canonical benchmark artifacts, or claims matrices.

## Evidence Source

- Aggregate artifact:
  `benchmarks/results/fix_eval_full_external_slither_post_spank_20260630_codex.json`
- Details artifact:
  `benchmarks/results/fix_eval_full_external_slither_post_spank_details_20260630_codex.json`

Post-spank totals:

| Metric | Value |
| --- | ---: |
| Contracts | 143 |
| Fixes applied | 123 |
| Fixes that compile | 123/123 |
| Vulnerabilities eliminated by MIESC re-scan | 88/123 |
| No regression by MIESC re-scan | 121/123 |
| External Slither clean-HIGH | 70/123 |
| External Slither residual HIGH findings | 53 |
| External `reentrancy-eth` residuals | 3 |
| External Slither errors | 0 |

## Residuals

| Contract | Dataset category | External HIGH checks after patch | Internal re-scan state | Classification | Next action |
| --- | --- | --- | --- | --- | --- |
| `access_control/parity_wallet_bug_2.sol` | `access_control` | `reentrancy-eth` | compile OK, target eliminated, no-regression OK; MIESC re-scan still reports `reentrancy-eth` plus access-control findings | Fallback/proxy/multisig semantic residual. The source stores pending multisig transactions and performs arbitrary `call.value(...)(data)` in `execute`/`confirm`; safe remediation requires wallet semantics, pending operation lifecycle, and delegate/proxy context. | Do not add a generic transform. Treat as manual protocol redesign unless a very narrow wallet-specific patch is designed and externally validated. |
| `unchecked_low_level_calls/0x663e4229142a27f00bafb5d087e1e730648314c3.sol` | `unchecked_low_level_calls` | `controlled-array-length`, `reentrancy-eth`, `weak-prng` | compile OK, target eliminated, no-regression OK; MIESC re-scan residuals include access-control, constructor, array-length, and weak-prng classes, not `reentrancy-eth` | Large production-like auction/NFT contract with multiple residual classes. The source already documents CEI-like auction removal before transfer in `_bid`; remaining Slither high check is mixed with array-length and randomness findings. | Do not add a broad transform. Triage only if the exact external Slither path can be extracted; otherwise document as semantic residual in a large multi-class contract. |
| `unchecked_low_level_calls/0xe09b1ab8111c2729a76f16de96bc86a7af837928.sol` | `unchecked_low_level_calls` | `reentrancy-eth`, `weak-prng` | compile OK, target eliminated, no-regression OK; MIESC re-scan residuals are randomness/signature classes, not `reentrancy-eth` | Stable CEI candidate. Slither reports `FiftyFlip.wager(...)`: unchecked external `whale.call.value(donate_amount)(...)` occurs before writes to `bet.amount`, `bet.blockNumber`, `bet.betMask`, and `bet.player`. | Best next code probe: exact single-contract transform that records the `bet` fields before the whale donation call, preserving compile/no-regression and checking external Slither. |

## Probe Recommendation

The only immediate automated-remediation candidate is the `FiftyFlip.wager`
ordering pattern:

```solidity
whale.call.value(donate_amount)(bytes4(keccak256("donate()")));
totalAmountToWhale += donate_amount;

bet.amount = amount;
bet.blockNumber = block.number;
bet.betMask = bMask;
bet.player = player;
```

A conservative transform would move the `bet.*` writes before the whale call,
leaving `totalAmountToWhale += donate_amount` adjacent to the donation accounting
unless an external run shows Slither still flags it. Because the call return is
unchecked already, moving the ticket reservation before the call should not add a
new revert path; however, it changes reentrant visibility of an in-flight wager
and must be validated externally before any claim.

Do not promote a broad "move arbitrary state writes before any low-level call"
rule. The safe shape here is narrow: one `Bet storage bet = bets[ticketID]`,
ticket-newness precondition, fixed set of four `bet` assignments, one
`whale.call.value(donate_amount)(...)`, and no intervening control flow.

## Claim Guidance

- Already promotable: post-spank full run reduces full-corpus `reentrancy-eth`
  from 10 to 3 versus retry-v8 and improves clean-HIGH 67/123 to 70/123.
- Not yet promotable: "MIESC eliminates all reentrancy residuals in the full
  corpus." Three full-run residuals remain.
- Next measured claim, if the `FiftyFlip` probe succeeds: one additional
  full-run `reentrancy-eth` residual class has a stable exact CEI transform,
  with before/after external Slither evidence.
