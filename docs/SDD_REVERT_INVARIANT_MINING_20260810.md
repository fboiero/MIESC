# SDD: Revert-Invariant Mining for Defensive Oracle Synthesis

Date: 2026-08-10
Owner/Lane: Codex
Status: Proposed SDD, not implemented, no benchmark claim

## Signal

MIESC already has invariant synthesis, invariant validation, fuzzing adapters, snapshot fuzzing guidance, sequence-oracle plans, semantic graph gates, RAG-backed vulnerability knowledge, and proof-of-concept generation. The missing layer is different: it treats successful defenses as signal.

Modern Solidity contracts encode many security properties as `require`, `assert`, and `if (...) revert` guards. Existing MIESC logic can notice some guard patterns and can generate candidate invariants, but it does not yet mine revert-causing guards as a first-class defensive corpus, cluster them by semantic intent, and translate missing or inconsistent defensive categories into fuzzing or validation oracles.

Recent work on revert-invariant mining frames reverted Ethereum transactions as evidence of active on-chain defenses. The useful MIESC technique is **Revert-Invariant Mining for Defensive Oracle Synthesis**: extract guard predicates, normalize them, classify their defensive intent, compare them against expected defenses for a contract role, and generate provider-neutral oracle plans when important defensive categories are absent, weakened, or inconsistently applied.

This should remain provider-neutral. A hosted reasoning provider, a local model, or deterministic local heuristics can all implement the same contract. The SDD must describe agents and interfaces, not a required model or API.

## Spec/Goal

Add a future capability named:

```text
revert_invariant_mining
```

Expected output key:

```text
revert_invariant_oracle_plans
```

Suggested aliases:

```text
defensive_oracle_synthesis
revert_guard_mining
failure_invariant_mining
```

The capability must produce advisory oracle plans. It should not emit confirmed vulnerabilities unless a downstream test, fuzzer, symbolic executor, replay, or human review confirms the missing or bypassed guard.

Primary objectives:

1. Extract guard predicates from Solidity source: `require`, `assert`, custom-error `revert`, and `if (...) revert` forms.
2. Normalize predicates into stable defensive categories such as access control, slippage threshold, replay prevention, proof/signature verification, bounds checks, pause/feature toggles, allow/ban lists, freshness checks, and accounting caps.
3. Compare guards against contract semantics and peer functions to identify missing, weaker, unreachable, or inconsistent defenses.
4. Generate fuzzing, symbolic, or replay obligations that try to violate the expected guard.
5. Feed confirmed counterexamples into existing finding, evidence, and false-positive controls.

## Design/Contract

Introduce a provider-neutral data contract before implementation:

```python
RevertInvariantOraclePlan = {
    "id": "string",
    "objective": "string",
    "contract_role": "string",
    "guard_inventory": [
        {
            "source_anchor": "file:line",
            "function": "string",
            "guard_kind": "require|assert|if_revert|custom_error",
            "predicate": "string",
            "error_signal": "string",
            "normalized_terms": ["string"],
            "defensive_category": "string",
            "confidence": "low|medium|high",
        }
    ],
    "gap_hypothesis": {
        "category": "string",
        "expected_guard": "string",
        "observed_gap": "missing|weaker|inconsistent|unreachable|dead_guard",
        "affected_functions": ["string"],
        "semantic_preconditions": ["string"],
        "negative_checks": ["string"],
    },
    "oracle": {
        "property": "string",
        "expected_revert": "string",
        "counterexample_success_condition": "string",
    },
    "execution_plan": {
        "recommended_tools": ["foundry", "echidna", "halmos", "local_fixture"],
        "sequence": ["call"],
        "actors": ["string"],
        "inputs_to_mutate": ["string"],
        "budget_hint": "string",
    },
    "promotion": {
        "state": "hypothesis|test_generated|counterexample|replayed|rejected",
        "evidence": ["string"],
        "blockers": ["string"],
    },
    "metadata": {
        "capability": "revert_invariant_mining",
        "schema_version": "1",
    },
}
```

The capability composes existing MIESC pieces:

- `InvariantSynthesizer` remains responsible for proposing candidate invariants.
- `InvariantValidator` remains responsible for executing generated checks.
- `SnapshotFuzzingPlan` and `SequenceOraclePlan` can consume generated oracle obligations.
- `SemanticGraphGate` can supply function/state anchors for guard comparison.
- `EmbeddingRAG` and local knowledge-base records can supply known defensive categories.
- False-positive filtering must downgrade plans that only identify missing guard style without exploitability evidence.

## Prompt Requirements

Prompt and parser design must refer to an **interchangeable security reasoning agent**. The implementation must not require a vendor, hosted endpoint, product family, or specific model.

The reasoning agent must:

- Extract only guards anchored to source lines.
- Separate observed guards from inferred missing defenses.
- Return normalized categories in bounded structured output.
- Include negative checks showing why a missing guard may be benign.
- Avoid confirmed-finding language unless execution evidence exists.
- Support local deterministic fallback based on guard extraction and keyword/category rules.

## False-Positive Controls

The capability must avoid creating noisy "missing require" findings:

- A missing guard is only a hypothesis until a counterexample violates the expected property.
- A function without an explicit guard may be safe when a modifier, upstream caller, inherited hook, checked library, or protocol-level invariant enforces the same property.
- A revert guard can be unreachable or dead; dead guards should not be treated as active defense.
- Error messages are useful labels, not proof of the predicate's semantics.
- Provider output must be bounded and parser-validated before integration.
- All generated oracle plans must retain source anchors and category provenance.

Promotion rules:

- `hypothesis`: extracted guard inventory or category gap only.
- `test_generated`: a property or fuzz harness exists but has no failing execution.
- `counterexample`: fuzzing or symbolic execution reaches a guard bypass or unexpected success.
- `replayed`: deterministic local or fork replay demonstrates exploit-relevant impact.
- `rejected`: modifier/inherited/upstream checks or execution evidence disprove the gap.

## Non-Goals

- No remote chain dependency in the first implementation.
- No canonical benchmark update from the SDD alone.
- No requirement to fine-tune an embedding model.
- No generic style lint for guard messages.
- No confirmed vulnerability when only a category gap is observed.
- No replacement for current invariant synthesis or fuzzing adapters.

## Integration Plan

Phase 0 is this SDD. Future work should land in small, testable steps:

1. Add schema contracts and parser tests under the provider-neutral agentic contract layer.
2. Add a deterministic Solidity guard extractor for `require`, `assert`, and `if (...) revert`.
3. Add category normalization with local fallback rules.
4. Add guard-gap comparison across sibling public/external functions.
5. Add oracle plan generation for missing replay prevention, slippage threshold, proof/signature verification, pause/feature toggles, allow/ban lists, freshness checks, and accounting caps.
6. Bridge oracle plans into existing invariant validation and fuzzing guidance.
7. Keep all initial evaluation non-canonical until a controlled benchmark run is explicitly approved.

## 50-Activity Parallelization Map

These activities can run across five lanes with disjoint file ownership.

1. Inventory existing invariant dataclasses.
2. Inventory existing parser sanitization helpers.
3. Inventory guard extraction logic in current adapters.
4. Inventory existing fuzzing oracle fields.
5. Inventory false-positive filter guard heuristics.
6. Define `RevertInvariantGuard` schema.
7. Define `GuardGapHypothesis` schema.
8. Define `RevertInvariantOracle` schema.
9. Define `RevertInvariantExecutionPlan` schema.
10. Define `RevertInvariantOraclePlan` schema.
11. Add strict parser for canonical output key.
12. Add parser aliases for defensive oracle synthesis.
13. Add bounded text/list sanitization tests.
14. Add no-provider-binding regression tests.
15. Add public facade exports.
16. Implement deterministic `require(...)` extraction.
17. Implement deterministic `assert(...)` extraction.
18. Implement deterministic custom-error `revert` extraction.
19. Implement deterministic `if (...) revert` extraction.
20. Add multiline predicate extraction tests.
21. Add category rules for access control.
22. Add category rules for slippage thresholds.
23. Add category rules for replay prevention.
24. Add category rules for proof/signature verification.
25. Add category rules for pause and feature toggles.
26. Add category rules for allow/ban lists.
27. Add category rules for freshness/deadline checks.
28. Add category rules for accounting caps.
29. Add sibling-function guard comparison.
30. Add inherited modifier awareness.
31. Add upstream caller guard awareness.
32. Add dead/unreachable guard hints.
33. Add oracle plan generation for missing replay checks.
34. Add oracle plan generation for missing slippage checks.
35. Add oracle plan generation for missing proof verification.
36. Add oracle plan generation for missing pause enforcement.
37. Add oracle plan generation for inconsistent allow/ban checks.
38. Add Foundry property metadata bridge.
39. Add Echidna property metadata bridge.
40. Add Halmos assertion metadata bridge.
41. Add vulnerable fixture for replayable signature.
42. Add safe fixture for nonce-bound signature.
43. Add vulnerable fixture for caller-provided slippage omission.
44. Add safe fixture for minimum output enforcement.
45. Add vulnerable fixture for missing proof verification.
46. Add safe fixture for proof root validation.
47. Add tests that unconfirmed gaps remain advisory.
48. Add tests that confirmed counterexamples promote state.
49. Add non-canonical evidence script for a small fixture slice.
50. Add runbook notes for comparing mined defensive categories with reported findings.

Parallel lanes:

- Lane A: schema, parser, exports, and provider-neutral tests.
- Lane B: deterministic guard extraction and source anchors.
- Lane C: category normalization and sibling/inherited guard comparison.
- Lane D: oracle generation and execution handoff metadata.
- Lane E: fixtures, non-canonical evidence, and reporting/runbook notes.

## Validation

For this SDD:

```bash
test -s docs/SDD_REVERT_INVARIANT_MINING_20260810.md
rg -n "interchangeable security reasoning agent|provider-neutral|50-Activity" docs/SDD_REVERT_INVARIANT_MINING_20260810.md
git diff --check -- docs/SDD_REVERT_INVARIANT_MINING_20260810.md
```

Provider/model-name checks should run against the document content during review and should return no requirement binding the capability to one provider.

For future implementation:

- Unit tests for extraction across one-line, multiline, and custom-error guard forms.
- Schema/parser tests proving bounded provider-neutral output.
- Fixture tests with vulnerable and safe examples per defensive category.
- Integration tests proving guard gaps stay advisory until execution confirms them.
- Non-canonical benchmark probes before any claimed uplift.

## References

- Raven: Mining Defensive Patterns in Ethereum via Semantic Transaction Revert Invariants Categories, arXiv:2512.22616v1, 2025-12-27. https://arxiv.org/html/2512.22616v1
- Demystifying Invariant Effectiveness for Securing Smart Contracts, arXiv:2404.14580. https://arxiv.org/abs/2404.14580
- Solidity documentation: error handling with `assert`, `require`, `revert`, and exceptions. https://docs.soliditylang.org/en/latest/control-structures.html#error-handling-assert-require-revert-and-exceptions
- Local reference: `docs/SDD_SEQUENCE_ORACLE_DETECTION_20260709.md`
- Local reference: `docs/SDD_SNAPSHOT_FUZZING_GUIDANCE_20260709.md`
- Local reference: `docs/SDD_SEMANTIC_GRAPH_GATING_20260709.md`
