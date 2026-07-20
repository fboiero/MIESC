# SDD: Sequence-Oracle Detection for Stateful Solidity Bugs

Date: 2026-07-09
Owner lane: Codex
Status: proposed, first provider-neutral agent contract implemented

## 1. Signal

MIESC already combines static analysis, fuzzing, symbolic execution, formal
verification, invariant synthesis, PoC generation, and agentic audit. The
remaining gap is not another single-call detector. Many Solidity failures only
become visible after a stateful sequence:

- donation before deposit in vault share math;
- manipulate reserves, then read an oracle, then borrow or liquidate;
- initialize, delegate, upgrade, then bypass access control;
- vote, queue, replay, and execute under stale governance assumptions;
- partial withdraw, callback, and final accounting drift.

Recent and relevant work points in the same direction:

- SmarTest combines symbolic execution with sequence prioritization to find
  vulnerable transaction sequences.
- FinanceFuzz uses financial properties to guide fuzzing toward vulnerable
  state transitions.
- SmartOracle proposes fine-grained dynamic invariants as application-specific
  oracles.
- Synapse-style agentic analysis uses focal context, semantic tools, and
  reusable vulnerability reasoning patterns, but MIESC must keep the contract
  provider-neutral and local-first.
- Echidna already falsifies user-defined properties with random call sequences,
  so MIESC can generate better oracles before invoking existing tools.

## 2. Spec

Add a provider-neutral "sequence oracle plan" artifact.

Inputs:

- Solidity source.
- Existing findings from static, symbolic, fuzzing, formal, or agentic layers.
- Candidate invariants from `InvariantExtractionAgent` or
  `InvariantSynthesizer`.
- Optional profile constraints such as max sequence length, target tool, and
  local-first policy.

Output:

```json
{
  "sequence_oracle_plans": [
    {
      "id": "share_inflation_sequence",
      "objective": "Validate whether donation before deposit inflates shares",
      "invariant_id": "asset_conservation",
      "vulnerability_types": ["share_price_inflation"],
      "sequence": [
        {
          "function": "deposit",
          "actor": "victim",
          "arguments": ["1 ether"],
          "value_hint": "",
          "precondition": "pool is initialized",
          "expected_effect": "victim receives baseline shares"
        }
      ],
      "oracle": "shares remain proportional to assets",
      "recommended_tools": ["foundry", "echidna", "halmos"],
      "confidence": 0.8,
      "evidence": ["deposit and donate write shared accounting state"]
    }
  ]
}
```

Non-goals for the first checkpoint:

- Claiming benchmark uplift before a controlled non-canonical run.
- Replacing Echidna, Foundry, Halmos, Mythril, or Manticore.
- Requiring a specific model, API, or remote provider.
- Generating full harnesses before the plan schema is stable.

## 3. Design

Implemented first checkpoint:

1. Add `AgentCapability.SEQUENCE_ORACLE_SYNTHESIS`.
2. Add `SequenceStep` and `SequenceOraclePlan` data contracts.
3. Add `SequenceOracleAgent`, which builds a bounded `ReasoningTask`.
4. Add `parse_sequence_oracle_plans()` to normalize provider JSON into safe
   Python objects.
5. Export the types through both `src.llm` and `miesc.llm`.

The design keeps DPG compliance by depending on capabilities and providers, not
model names. A local heuristic provider, local model, remote approved provider,
or future symbolic planner can all return the same JSON shape.

False-positive controls:

- Require an explicit oracle; plans without an oracle are discarded.
- Require at least one valid sequence step.
- Bound prompt size, list sizes, text fields, metadata, and confidence values.
- Treat plans as validation hypotheses, not confirmed vulnerabilities.

## 4. Validation

Focused tests for this checkpoint:

```bash
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
ruff check src/llm/agentic_contracts.py src/llm/__init__.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
```

Expected checks:

- provider-neutral capability is used;
- prompts avoid vendor/model binding;
- JSON alias `plans` is accepted for future tool compatibility;
- malformed or incomplete plans are rejected;
- public `miesc.llm` facade exports the new contract;
- sanitization handles hostile scalar fields.

## 5. Integration Plan

The 50-activity rollout is intentionally split into parallel lanes.

Discovery and schema:

1. Inventory state-transition signals from Slither IR.
2. Inventory Echidna call-sequence output shapes.
3. Inventory Foundry invariant failure traces.
4. Inventory Halmos counterexample traces.
5. Inventory Mythril/Manticore transaction outputs.
6. Normalize vulnerability labels for sequence-dependent violations.
7. Define benchmark-safe non-canonical evidence filenames.
8. Add profile knob for max sequence length.
9. Add agent task examples for DeFi accounting.
10. Add agent task examples for governance replay.

Planner and contracts:

11. Add `SequenceOraclePlan` contract.
12. Add parser and sanitizer tests.
13. Add local heuristic sequence planner.
14. Add provider adapter route for the new capability.
15. Add profile plumbing for sequence oracle synthesis.
16. Add MCP schema exposure for sequence plans.
17. Add CLI JSON export for plans.
18. Add correlation metadata from plans to findings.
19. Add confidence calibration rules.
20. Add no-vendor regression tests.

Harness generation:

21. Generate Foundry handler skeletons from plans.
22. Generate Echidna property wrappers from plans.
23. Generate Halmos assertion hints from plans.
24. Convert plan sequence steps into PoC setup sections.
25. Preserve actors and value hints safely.
26. Bound generated Solidity size.
27. Add import path hardening.
28. Add fixture contracts for share inflation.
29. Add fixture contracts for oracle manipulation.
30. Add fixture contracts for governance replay.

Tool execution:

31. Run Foundry plan validation behind opt-in profile.
32. Run Echidna plan validation behind opt-in profile.
33. Run Halmos plan validation behind opt-in profile.
34. Capture call sequences as `CounterexampleEvidence`.
35. Feed failed oracles into PoC generation.
36. Feed validated failures into finding judgment.
37. Feed clean results into false-positive reduction.
38. Add timeout and resource policy per tool.
39. Add local-only default execution mode.
40. Add evidence bundle output.

Bench and reporting:

41. Run small non-canonical SmartBugs slice.
42. Run small non-canonical EVMBench slice.
43. Compare recall on sequence-dependent categories only.
44. Compare false positives on benign context slice.
45. Record failures without changing frozen matrices.
46. Add report section for sequence-oracle hypotheses.
47. Add report section for validated counterexamples.
48. Add dashboard metric for plan validation rate.
49. Prepare promotion criteria for paper profiles.
50. Only after approval, run full benchmark and update claims.

Parallelization:

- Activities 1-10 can run in parallel as read-only explorers.
- Activities 11-20 are mostly `src/llm` and profile plumbing; keep one writer
  per file group.
- Activities 21-30 can split by target harness if write scopes are disjoint.
- Activities 31-40 should run after harness schema stabilizes.
- Activities 41-50 must use non-canonical outputs until baseline approval.

## 6. References

- SmarTest: https://www.usenix.org/conference/usenixsecurity21/presentation/so
- FinanceFuzz: https://doi.org/10.1016/j.bcra.2025.100301
- SmartOracle: https://www.computer.org/csdl/journal/ts/2025/04/10855805/23QQVZAQare
- Synapse: https://yajin.org/papers/fse2026_synapse.pdf
- Echidna: https://github.com/crytic/echidna
