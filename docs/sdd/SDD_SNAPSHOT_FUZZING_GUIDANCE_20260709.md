# SDD: Snapshot/Dataflow-Guided Fuzzing for Solidity

Date: 2026-07-09
Owner lane: Codex
Status: proposed, first provider-neutral campaign contract implemented

## 1. Signal

MIESC has adapters for Echidna, Foundry, Medusa-style fuzzing, DogeFuzz, PoC
validation, sequence-oracle planning, and semantic graph gating. The missing
piece is a stable artifact that describes how to guide fuzzing campaigns with
reusable state snapshots, dataflow waypoints, branch/frontier targets, and
priority transactions.

Relevant research trends:

- ItyFuzz uses snapshot-based fuzzing and dataflow/comparison waypoints to
  reach exploitable smart-contract states without replaying long prefixes.
- SMARTIAN uses static and dynamic data-flow information to guide transaction
  sequence fuzzing.
- ConFuzzius combines evolutionary fuzzing with constraint solving and data
  dependency analysis for smart contracts.
- sFuzz and other AFL-style approaches show the value of lightweight adaptive
  feedback, but they do not by themselves solve state reuse.

MIESC already captures parts of this world: Echidna can keep a corpus, DogeFuzz
has seeds, and sequence-oracle plans preserve invocation order. It does not yet
have a provider-neutral campaign plan that says which state to snapshot, which
frontier to target, and which transaction should receive priority.

## 2. Spec

Add a provider-neutral `snapshot_fuzzing_guidance` artifact.

Inputs:

- Solidity source.
- Existing findings.
- Optional `SequenceOraclePlan` objects.
- Optional `SemanticGraphGate` objects.
- Policy constraints: local-first, max source chars, max snapshots.

Output:

```json
{
  "snapshot_fuzzing_plans": [
    {
      "id": "vault_snapshot_campaign",
      "objective": "Reuse post-liquidity state to fuzz share inflation",
      "target_vulnerability_types": ["share_price_inflation"],
      "seeds": [
        {
          "id": "seed_after_liquidity",
          "setup_sequence": [
            {
              "function": "deposit",
              "actor": "victim",
              "arguments": ["100 ether"],
              "value_hint": "",
              "precondition": "",
              "expected_effect": "vault has initial liquidity"
            }
          ],
          "target_state": "vault initialized with nonzero assets and shares",
          "priority": 0.9,
          "evidence": ["deposit initializes assets and shares"]
        }
      ],
      "waypoints": [
        {
          "id": "waypoint_share_price_delta",
          "kind": "dataflow",
          "target": "totalAssets / totalSupply",
          "objective": "maximize share price drift",
          "distance_hint": "ratio changes without matching mint",
          "evidence": ["donate affects assets but not shares"]
        }
      ],
      "priority_transactions": [
        {"function": "donate", "actor": "attacker", "arguments": ["amount"]}
      ],
      "oracle": "share price remains proportional after donation and deposit",
      "recommended_tools": ["foundry", "echidna", "ityfuzz"],
      "budget_hint": "bounded snapshot replay before full campaign",
      "confidence": 0.88
    }
  ]
}
```

Non-goals:

- Shipping a new EVM fuzzer in this checkpoint.
- Editing `src/adapters/**` without Claude-lane coordination.
- Claiming benchmark improvement before non-canonical evaluation.
- Depending on a specific model, API, or remote provider.
- Replacing sequence-oracle plans or semantic graph gates.

## 3. Design

Implemented first checkpoint:

1. Add `AgentCapability.SNAPSHOT_FUZZING_GUIDANCE`.
2. Add `SnapshotSeed`, `FuzzingWaypoint`, and `SnapshotFuzzingPlan`.
3. Add `SnapshotFuzzingAgent`.
4. Add `parse_snapshot_fuzzing_plans()` with strict sanitization.
5. Export the contract through `src.llm` and `miesc.llm`.

The contract is intentionally backend-neutral. Foundry snapshots, Echidna
corpus reuse, Medusa campaigns, ItyFuzz-style snapshots, or a local heuristic
planner can all consume or produce the same campaign guidance.

False-positive controls:

- A plan requires an objective, an oracle, and at least one seed, waypoint, or
  priority transaction.
- Campaign plans are fuzzing guidance, not confirmed vulnerabilities.
- Snapshot priorities and confidences are bounded to `[0, 1]`.
- Text, list, metadata, source, and step fields are bounded and sanitized.
- Provider/model names stay outside the contract.

## 4. Validation

Focused validation:

```bash
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
ruff check src/llm/agentic_contracts.py src/llm/__init__.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
```

Required assertions:

- capability is provider-neutral;
- prompt avoids vendor/model binding;
- aliases such as `snapshot_campaigns` parse correctly;
- incomplete plans are rejected;
- hostile fields are sanitized;
- public facade exports remain stable.

## 5. Integration Plan

The next 50 activities are split by file ownership and can be parallelized when
write scopes are disjoint.

Discovery and schema:

1. Compare ItyFuzz snapshot fields with MIESC sequence plans.
2. Compare SMARTIAN dataflow targets with Slither IR summaries.
3. Compare ConFuzzius data dependencies with MIESC call graph output.
4. Inventory Echidna corpus features.
5. Inventory Foundry `vm.snapshot` and replay options.
6. Inventory Medusa corpus/state features.
7. Define snapshot seed priority semantics.
8. Define branch-distance waypoint conventions.
9. Define dataflow waypoint conventions.
10. Define non-canonical evidence paths.

Contract and local heuristic:

11. Add snapshot fuzzing contracts.
12. Add parser and sanitization tests.
13. Add public exports.
14. Add local heuristic provider support for snapshot plans.
15. Infer seeds from sequence-oracle setup prefixes.
16. Infer waypoints from semantic graph dataflow edges.
17. Infer priority transactions from external calls and state writes.
18. Infer budget hints from profile timeout.
19. Keep deterministic plan ordering.
20. Add no-signal empty-plan tests.

Foundry/Echidna bridge:

21. Convert seeds to Foundry setup blocks.
22. Convert priority transactions to Foundry fuzz actions.
23. Convert waypoints to Foundry assertions or assumptions.
24. Convert seeds to Echidna initialization corpus hints.
25. Convert oracles to Echidna property stubs.
26. Preserve actor/value hints.
27. Bound generated harness size.
28. Capture replay metadata.
29. Feed failing replay into `CounterexampleEvidence`.
30. Feed evidence into PoC generation.

Agentic and profile integration:

31. Add `enable_snapshot_fuzzing_guidance` profile knob.
32. Route paper agentic profile to build snapshot plans metadata-only.
33. Feed snapshot plans into sequence-oracle validation.
34. Feed semantic graph gates into snapshot plan generation.
35. Expose MCP schema for snapshot plans.
36. Add CLI JSON output.
37. Add report section for campaign guidance.
38. Add traceability from finding to seed/waypoint/oracle.
39. Add resource policy for snapshot count.
40. Add local-first policy test.

Evaluation and promotion:

41. Build tiny fixture for share inflation.
42. Build tiny fixture for oracle manipulation.
43. Build tiny fixture for liquidation branch frontier.
44. Build tiny fixture for reentrancy state frontier.
45. Run non-canonical unit fixture campaigns.
46. Run non-canonical SmartBugs subset.
47. Run non-canonical EVMBench subset.
48. Compare campaign hit rate and time-to-oracle only.
49. Prepare promotion criteria for Fernando review.
50. Update paper claims only after explicit baseline approval.

## 6. References

- ItyFuzz: https://arxiv.org/abs/2306.17135
- ItyFuzz project: https://github.com/fuzzland/ityfuzz
- SMARTIAN: https://speakerdeck.com/line_devday2021/smartian-enhancing-smart-contract-fuzzing-with-static-and-dynamic-data-flow-analyses
- ConFuzzius: https://discovery.ucl.ac.uk/id/eprint/10182330/
- sFuzz: https://doi.org/10.1145/3395363.3397376
