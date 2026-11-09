# SDD: Adversarial Transaction Ordering

Date: 2026-07-11
Owner: Codex lane
Status: proposed, first provider-neutral plan contract implemented

## 1. Signal

MIESC already covers sequence oracles, economic attack simulation, oracle feed
hardening, and detector-level MEV/front-running patterns. The remaining gap is a
provider-neutral planning artifact for adversarial ordering: given victim,
attacker, keeper, liquidator, or settler transactions, generate bounded
permutation checks that prove whether front-running, back-running, sandwiching,
liquidation races, weak commit-reveal, or transaction-order dependence can
change the victim outcome.

This SDD adds an agentic contract for adversarial transaction ordering. It does
not add another regex detector and does not recalculate profitability. It emits
relative ordering assumptions, actor roles, state dependencies, slippage/deadline
limits, ordering-specific oracles, mitigations, and validation tests that can be
fed to Foundry fork tests, Anvil block ordering, stateful fuzzing, deterministic
replay, or downstream economic simulation.

Relevant external signals:

- OWASP SCWE-052 covers transaction order dependence and explicitly includes
  front-running and back-running.
- OWASP SCWE-037 covers insufficient front-running protection and recommends
  mitigation patterns such as commit-reveal.
- Recent TOD work statically checks order-sensitive smart-contract behavior.
- Recent sandwich/MEV work continues to model transaction insertion/reordering
  around victims as a dominant DeFi risk.

## 2. Spec

Add a provider-neutral capability:

`adversarial_transaction_ordering`

The capability emits `adversarial_transaction_ordering_plans`, each containing:

- `ordering_pattern`: front-run, back-run, sandwich, liquidation race,
  permit nonce denial, commit-reveal gap, auction reorder, or unknown.
- `transactions`: victim/attacker/keeper/liquidator/settler roles, relative
  positions, function names, state dependencies, and slippage/deadline/limit
  evidence.
- `risks`: transaction-order dependence, slippage gap, deadline gap,
  commit-reveal gap, liquidation race, permit nonce DoS, or similar hypotheses.
- `oracle`: validation condition for the permutation.
- `mitigations`: minOut, deadline, commit-reveal, batch auction, private routing,
  anti-sandwich guard, or protocol-specific controls.
- `validation_tests`: bounded replay/fork/fuzz tests for the ordering hypothesis.

Parser aliases:

- `adversarial_ordering_plans`
- `adversarial_transaction_ordering_plans`
- `transaction_ordering_plans`
- `mev_oracle_plans`

Non-goals:

- Replacing sequence-oracle plans for generic transaction sequences.
- Replacing economic attack simulation, capital, fees, or profit formulas.
- Replacing existing MEV/front-running regex detectors.
- Claiming exploitability without replay, fork simulation, or counterexample
  evidence.
- Editing frozen paper artifacts or canonical benchmark outputs.

## 3. Design

Implemented first checkpoint:

1. Add `AgentCapability.ADVERSARIAL_TRANSACTION_ORDERING`.
2. Add `OrderingTransaction`.
3. Add `OrderingRisk`.
4. Add `AdversarialOrderingPlan`.
5. Add `AdversarialTransactionOrderingAgent`.
6. Add `parse_adversarial_transaction_ordering_plans()`.
7. Export the contract through `src.llm` and `miesc.llm`.

The plan is ordering-validation guidance. It references market, mempool,
sequence, or economic summaries by input, but does not duplicate full sequence
steps, asset flows, capital requirements, or profit equations.

False-positive controls:

- Require explicit relative ordering or ordering-dependent state evidence.
- Keep slippage, deadline, commit-reveal, oracle freshness, and liquidity
  assumptions explicit.
- Treat private orderflow as an assumption, not a guarantee.
- Treat mitigations as checks to validate, not proof of safety.
- Keep this artifact separate from detector-owned files and adapter heuristics.

## 4. Validation

Focused tests:

- Provider-neutral agent capability and prompt tests.
- Parser alias and confidence-bound tests.
- Incomplete item rejection.
- Direct dataclass `to_dict()` sanitization.
- Public `miesc.llm` facade export and parser usability.

No frozen papers, canonical benchmark outputs, adapter-owned files, or claims
matrices are part of this checkpoint.

## 5. Integration Plan: 50 Activities

Discovery:

1. Inventory public swap functions.
2. Inventory slippage/minOut parameters.
3. Inventory deadline parameters.
4. Inventory liquidation functions.
5. Inventory keeper-triggered settlement functions.
6. Inventory auction bid/fill/settle functions.
7. Inventory commit-reveal flows.
8. Inventory permit composition flows.
9. Inventory oracle-update-dependent functions.
10. Classify actor roles per function.

Ordering semantics:

11. Identify victim transactions.
12. Identify attacker front-run candidates.
13. Identify attacker back-run candidates.
14. Identify same-block sandwich candidates.
15. Identify liquidation priority races.
16. Identify auction reordering races.
17. Identify permit nonce DoS ordering.
18. Identify weak commit-open ordering.
19. Identify private-orderflow assumptions.
20. Identify builder/mempool assumptions.

Contract and parser:

21. Add adversarial ordering capability.
22. Add ordering transaction schema.
23. Add ordering risk schema.
24. Add ordering plan schema.
25. Add provider-neutral agent.
26. Add parser aliases.
27. Add direct sanitization tests.
28. Add public exports.
29. Add public facade tests.
30. Keep no-signal output empty.

Validation generation:

31. Generate front-run before victim test.
32. Generate back-run after victim test.
33. Generate sandwich around victim test.
34. Generate minOut protection test.
35. Generate deadline protection test.
36. Generate liquidation race test.
37. Generate auction reorder test.
38. Generate commit-reveal early-open test.
39. Generate permit nonce DoS test.
40. Generate private-orderflow assumption test.

Evaluation:

41. Add safe minOut fixture.
42. Add missing minOut fixture.
43. Add missing deadline fixture.
44. Add liquidation race fixture.
45. Add commit-reveal weakness fixture.
46. Add permit nonce DoS fixture.
47. Run non-canonical fixture suite.
48. Compare ordering-plan TPR/FPR only on ground-truth fixtures.
49. Prepare promotion memo for Fernando.
50. Update paper/benchmark claims only after explicit approval.

## 6. References

- OWASP SCWE-052 Transaction Order Dependence:
  https://scs.owasp.org/SCWE/SCSVS-ARCH/SCWE-052/
- OWASP SCWE-037 Insufficient Protection Against Front-Running:
  https://scs.owasp.org/SCWE/SCSVS-GOV/SCWE-037/
- Statically Checking Transaction Ordering Dependency in Ethereum Smart
  Contracts:
  https://dl.acm.org/doi/10.1145/3659463.3660013
- FIRST: FrontrunnIng Resistant Smart ConTracts:
  https://arxiv.org/abs/2204.00955
- An anti-sandwich mechanism for EVM's smart contracts:
  https://www.sciencedirect.com/science/article/abs/pii/S0167739X25003711
