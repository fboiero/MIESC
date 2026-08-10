# SDD: Metamorphic and Differential Testing Guidance

Date: 2026-07-10
Owner lane: Codex
Status: proposed, first provider-neutral plan contract implemented

## 1. Signal

MIESC can already extract invariants, synthesize transaction-sequence oracles,
focus semantic graph gates, guide snapshot fuzzing, and reason about economic
exploitability. The remaining gap is the oracle problem: for many Solidity
bugs, especially accounting drift and DeFi state machines, the exact expected
output for one execution is hard to know upfront.

Metamorphic testing addresses that gap by checking relations between a baseline
execution and a derived variant execution. Differential testing adds the same
comparison discipline across implementations, compiler settings, protocol
versions, or reference models.

This SDD adds a provider-neutral artifact that answers:

> Which baseline/variant executions should remain equivalent, inverse,
> monotonic, idempotent, commutative, round-trip, or conservative, and what
> state observables should be compared?

Relevant external signals:

- Metamorphic testing has been applied to smart-contract vulnerability
  detection by defining relations that expose abnormal gas and account
  interaction behavior.
- 2025 smart-contract validation work applies metamorphic relations to
  Ethereum crowdfunding contracts and evaluates the relations against mutation
  testing.
- Ethereum testing guidance highlights property-based testing as a core smart
  contract validation workflow; metamorphic relations give the agent a way to
  synthesize stronger properties when a single-run oracle is unavailable.
- Differential fuzzing practice for Solidity compares behavior across variants
  or implementations to find unexpected divergence.

## 2. Spec

Add `metamorphic_diff_testing` as a provider-neutral plan type.

Inputs:

- Solidity source.
- Existing findings.
- Optional invariant candidates.
- Optional `SequenceOraclePlan` objects.
- Optional `SnapshotFuzzingPlan` objects.
- Local-first policy constraints.

Output:

```json
{
  "differential_test_plans": [
    {
      "id": "split_merge_deposit_plan",
      "objective": "Compare split and merged deposits for share drift",
      "target_vulnerability_types": ["share_price_inflation"],
      "relations": [
        {
          "id": "split_merge_deposit",
          "relation_type": "split_merge",
          "baseline_sequence": [
            {
              "function": "deposit",
              "actor": "user",
              "arguments": ["100 ether"],
              "expected_effect": "mint baseline shares"
            }
          ],
          "variant_sequence": [
            {
              "function": "deposit",
              "actor": "user",
              "arguments": ["50 ether"]
            },
            {
              "function": "deposit",
              "actor": "user",
              "arguments": ["50 ether"]
            }
          ],
          "expected_relation": "final shares and assets match within rounding",
          "tolerance_hint": "at most one wei",
          "evidence": ["deposit uses asset/share conversion"]
        }
      ],
      "state_observables": ["balanceOf(user)", "totalSupply()", "totalAssets()"],
      "oracle": "split and merged executions diverge beyond tolerance",
      "recommended_tools": ["foundry", "echidna", "halmos"],
      "confidence": 0.84,
      "evidence": ["deposit is nonlinear around totalSupply"]
    }
  ]
}
```

Parser aliases:

- `differential_test_plans`
- `metamorphic_test_plans`
- `metamorphic_diff_plans`

Non-goals:

- Confirming a vulnerability without replay or counterexample evidence.
- Duplicating transaction sequence synthesis.
- Duplicating snapshot seed or waypoint planning.
- Deciding economic exploitability.
- Binding to a specific model, API, hosted provider, or local backend.
- Editing frozen paper artifacts or canonical benchmark outputs.

## 3. Design

Implemented first checkpoint:

1. Add `AgentCapability.METAMORPHIC_DIFF_TESTING`.
2. Add `MetamorphicRelation`.
3. Add `DifferentialTestPlan`.
4. Add `MetamorphicDiffTestingAgent`.
5. Add `parse_differential_test_plans()`.
6. Export the contract through `src.llm` and `miesc.llm`.

The plan is deliberately a test-guidance artifact. It should feed Foundry,
Echidna, Halmos, Medusa, symbolic executors, or future local adapters, but it
does not by itself become a vulnerability finding.

False-positive controls:

- Plans require an objective, oracle, and at least one valid relation.
- Relations require both baseline and variant sequences.
- Relations require an explicit expected relation.
- Confidence, text, observables, tools, evidence, and metadata are bounded.
- Prompt text prohibits provider/model/API binding.
- Sequence, snapshot, graph, and economic artifacts remain separate concerns.

## 4. Validation

Focused validation:

```bash
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
ruff check src/llm/agentic_contracts.py src/llm/__init__.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
```

Required assertions:

- capability is provider-neutral;
- prompts avoid vendor/model binding;
- parser aliases are accepted;
- incomplete differential plans are rejected;
- hostile fields are sanitized;
- public `miesc.llm` facade exports remain stable.

## 5. Integration Plan

The next 50 activities should remain additive and non-canonical until Fernando
approves a benchmark or paper baseline update.

Discovery and schema:

1. Inventory ERC20/ERC4626/accounting functions suitable for split/merge MRs.
2. Inventory mint/redeem/deposit/withdraw round-trip candidates.
3. Inventory pause/config/admin idempotence candidates.
4. Inventory commutative operation pairs.
5. Inventory monotonic counters and rate accumulators.
6. Inventory conservation observables for balances, shares, debt, reserves.
7. Inventory reference implementations in fixtures.
8. Inventory compiler/config axes already available in harnesses.
9. Define relation taxonomy.
10. Define observable taxonomy.

Contract and local heuristics:

11. Add metamorphic/differential plan contracts.
12. Add parser and sanitization tests.
13. Add public exports.
14. Add local heuristic for split/merge ERC4626 deposits.
15. Add local heuristic for mint/redeem round trips.
16. Add local heuristic for borrow/repay round trips.
17. Add local heuristic for transfer commutativity.
18. Add local heuristic for pause/config idempotence.
19. Add local heuristic for monotonic indexes.
20. Keep no-signal output empty.

Harness bridge:

21. Convert relations into Foundry test skeletons.
22. Convert relations into Echidna property skeletons.
23. Convert relations into Halmos assertion hints.
24. Reuse snapshot seeds as starting states.
25. Reuse sequence plans as baseline candidates.
26. Add tolerance helpers for rounding.
27. Add observable extraction helpers.
28. Add event comparison helpers.
29. Add revert-behavior comparison helpers.
30. Add gas-delta reporting without treating gas alone as a confirmed bug.

Differential axes:

31. Compare optimized vs unoptimized compiler settings where available.
32. Compare implementation vs reference model where available.
33. Compare patched vs unpatched artifacts only in non-canonical evidence.
34. Compare proxy implementation versions when fixtures expose them.
35. Compare fork-state replay against local mock state where safe.
36. Preserve deterministic plan ordering.
37. Add resource/time budget policy.
38. Add local-first provider route tests.
39. Add MCP/schema exposure.
40. Add CLI JSON output behind opt-in profile.

Evaluation:

41. Add fixture for split/merge share inflation.
42. Add fixture for mint/redeem rounding leakage.
43. Add fixture for borrow/repay debt drift.
44. Add fixture for pause idempotence regression.
45. Add fixture for transfer commutativity violation.
46. Run non-canonical unit fixture suite.
47. Run non-canonical EVMBench subset if relevant.
48. Compare relation-violation TPR/FPR only on ground-truth fixtures.
49. Prepare promotion memo for Fernando.
50. Update paper/benchmark claims only after explicit approval.

## 6. References

- Metamorphic Testing for Smart Contract Vulnerabilities Detection:
  https://arxiv.org/abs/2303.03179
- Metamorphic Testing for Smart Contract Validation: A Case Study of
  Ethereum-Based Crowdfunding Contracts: https://arxiv.org/abs/2501.09955
- Ethereum smart contract testing guide:
  https://ethereum.org/developers/docs/smart-contracts/testing/
- Solidity differential fuzzing practice note:
  https://medium.com/coinmonks/solidity-security-practices-part-ix-differential-fuzzing-f4bea56eeb54
