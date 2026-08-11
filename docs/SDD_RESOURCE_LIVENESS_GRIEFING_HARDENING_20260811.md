# SDD: Resource/Liveness Griefing Hardening

Date: 2026-08-11
Owner/Lane: Codex
Status: Proposed SDD, not implemented, no benchmark claim

## Signal

MIESC already has classic DoS detectors, cross-function DoS heuristics, RAG records for gas-limit and failed-call griefing, external-call returndata hardening, sequence-oracle plans, snapshot fuzzing guidance, semantic graph gates, and invariant validation. The remaining gap is not another local regex for `for (...)` or `.transfer(...)`. The gap is a provider-neutral artifact that reasons about **progress**: whether an honest actor can eventually withdraw, settle, claim, process, liquidate, execute, or recover even when an attacker bloats state, reverts callbacks, withholds keeper actions, manipulates gas, or forces partial failure.

The current v6.0.0 SmartBugs report also gives local signal: `denial_of_service` remains a real recall gap at 37.50% recall in the static-only slice. Existing detectors find obvious loops and push-payment patterns, but MIESC does not yet expose a structured capability that connects growth provenance, bounded batch progress, fallback actors, failed external calls, and liveness oracles.

The technique to add is **Resource/Liveness Griefing Hardening**: synthesize resource-growth and progress invariants, generate validation obligations for fuzzing/symbolic/local fixtures, and keep hypotheses advisory until a counterexample demonstrates stuck funds, blocked settlement, unbounded gas growth, or unavailable protocol progress.

## Spec/Goal

Add a future capability named:

```text
resource_liveness_griefing_hardening
```

Expected output key:

```text
resource_liveness_griefing_plans
```

Suggested aliases:

```text
dos_liveness_hardening
resource_griefing_hardening
liveness_oracle_synthesis
progress_invariant_hardening
```

The capability must produce advisory liveness/progress plans, not confirmed findings. A plan becomes a finding only after deterministic replay, fuzzing, symbolic execution, local fixture validation, or human review confirms that legitimate progress can be blocked or made economically impractical.

Primary objectives:

1. Identify externally growable resources: arrays, queues, mappings with enumerable indexes, pending payments, claim sets, proposal lists, keeper work queues, withdrawal queues, batch settlement sets, and per-user state that affects global loops.
2. Identify progress-critical functions: withdraw, claim, refund, settle, execute, liquidate, process, finalize, burn, redeem, bridge relay, keeper upkeep, and emergency recovery.
3. Infer liveness properties such as bounded batch progress, per-user withdrawal availability, retryability after failed callbacks, keeper substitution, and no single-recipient blocking.
4. Generate validation obligations for fuzzing, symbolic execution, and local fixtures that try to grow resources, force callback reverts, under-provision gas, or skip privileged keepers.
5. Downgrade unconfirmed plans and preserve false-positive controls for intentionally bounded, paginated, pull-based, or admin-recoverable designs.

## Design/Contract

Introduce a provider-neutral data contract before implementation:

```python
ResourceLivenessGriefingPlan = {
    "id": "string",
    "objective": "string",
    "surface": {
        "resource": "string",
        "resource_kind": "array|queue|mapping_index|pending_payment|keeper_task|withdrawal_queue|proposal_queue|external_callback|unknown",
        "growth_sources": ["function"],
        "progress_functions": ["function"],
        "source_anchors": ["file:line"],
    },
    "liveness_hypothesis": {
        "category": "unbounded_loop|state_bloat|push_payment_blocking|withdrawal_queue_blocking|keeper_blocking|revert_griefing|insufficient_gas_griefing|batch_progress_failure|rate_limit_gap|fallback_absence",
        "attacker_action": "string",
        "honest_user_goal": "string",
        "blocked_progress": "string",
        "preconditions": ["string"],
        "negative_checks": ["string"],
    },
    "progress_oracle": {
        "property": "string",
        "bounded_work_claim": "string",
        "expected_revert_or_failure": "string",
        "success_condition": "string",
    },
    "execution_plan": {
        "recommended_tools": ["foundry", "echidna", "halmos", "local_fixture", "human_review"],
        "sequence": ["call"],
        "actors": ["attacker", "honest_user", "keeper", "admin"],
        "inputs_to_mutate": ["string"],
        "resource_growth_budget": "string",
        "gas_budget_hint": "string",
    },
    "promotion": {
        "state": "hypothesis|test_generated|counterexample|replayed|rejected",
        "evidence": ["string"],
        "blockers": ["string"],
    },
    "metadata": {
        "capability": "resource_liveness_griefing_hardening",
        "schema_version": "1",
    },
}
```

The capability should compose existing MIESC pieces:

- Classic DoS detectors remain first-pass local signals for loops, push payments, and failed calls.
- `SequenceOraclePlan` supplies call ordering for growth then progress attempts.
- `SnapshotFuzzingPlan` supplies reusable bloated-state seeds and waypoints.
- `SemanticGraphGate` supplies state/resource/function anchors.
- `SlithIR SSA + Interprocedural State/Taint Summary` can identify growth provenance and attacker-controlled sizes.
- `External Call Returndata Hardening` remains the sub-surface for unbounded returndata and revert-data griefing.
- `InvariantValidator`, Echidna, Foundry, and Halmos can validate progress properties and counterexamples.
- False-positive filtering must downgrade plans when pagination, pull payments, retry paths, keeper substitution, or emergency recovery are actually present.

## Prompt Requirements

Prompt and parser design must refer to an **interchangeable security reasoning agent**. No schema, parser, prompt, or test may bind the capability to a specific vendor, hosted endpoint, product family, or model.

The reasoning agent must:

- Separate observed resource growth from inferred liveness risk.
- Anchor each resource and progress function to source lines.
- Return at least one negative check for every hypothesis.
- Prefer executable progress oracles over narrative severity.
- Avoid confirmed-finding language until validation confirms blocked progress.
- Support deterministic local fallback based on loops, storage growth, external calls, and function naming.

## False-Positive Controls

The capability must avoid noisy DoS findings:

- Dynamic loops are not findings when bounded by a small constant, pagination, or caller-owned slices.
- Push-style external calls are not findings when each recipient failure is isolated and retryable.
- Keeper-only progress is not a finding when any keeper can act, users can self-service, or emergency fallback exists.
- Withdrawal queues are not findings when queue growth is bounded and progress is amortized across calls.
- Gas-heavy operations are not findings without attacker-controlled growth or a progress-critical path.
- A failed external call is not a liveness finding if state remains consistent and retryable.
- Provider output must be bounded and parser-validated before integration.

Promotion rules:

- `hypothesis`: resource/progress surface and liveness risk only.
- `test_generated`: a progress oracle or harness exists but has not failed.
- `counterexample`: fuzzing or symbolic execution demonstrates blocked progress.
- `replayed`: deterministic local or fork replay demonstrates stuck funds, blocked settlement, or unavailable progress.
- `rejected`: pagination, pull pattern, retry path, fallback actor, or bounded work disproves the risk.

## Non-Goals

- No replacement for existing DoS detectors.
- No canonical benchmark update from this SDD alone.
- No profitability requirement; griefing can be impact-driven without direct profit.
- No remote-chain dependency in the first implementation.
- No confirmed vulnerability when only a large loop exists.
- No provider-specific dependency.

## Integration Plan

Phase 0 is this SDD. Future work should land in small, testable steps:

1. Add provider-neutral schema contracts and parser tests.
2. Add local resource-growth extraction for arrays, queues, mappings, and pending payment structures.
3. Add progress-function classifier for withdraw/claim/refund/settle/execute/liquidate/process/finalize/upkeep paths.
4. Add local liveness hypothesis generator for unbounded loops, push-payment blocking, keeper blocking, insufficient gas griefing, state bloat, and batch progress failure.
5. Generate progress oracles for Foundry/Echidna/Halmos/local fixtures.
6. Add fixtures with safe and unsafe variants for each liveness family.
7. Run only non-canonical probes until benchmark promotion is explicitly approved.

## 50-Activity Parallelization Map

These activities can run across five lanes with disjoint file ownership.

1. Inventory current DoS detector outputs.
2. Inventory cross-function DoS heuristic fields.
3. Inventory SmartBugs DoS fixtures and labels.
4. Inventory benchmark false negatives in `denial_of_service`.
5. Inventory existing sequence/snapshot plan inputs.
6. Define `ResourceSurface` schema.
7. Define `GrowthSource` schema.
8. Define `ProgressFunction` schema.
9. Define `LivenessHypothesis` schema.
10. Define `ResourceLivenessGriefingPlan` schema.
11. Add parser for canonical output key.
12. Add parser aliases for DoS/liveness plans.
13. Add bounded text/list sanitization.
14. Add no-provider-binding regression tests.
15. Export public facade symbols.
16. Detect arrays that grow through public/external calls.
17. Detect queues with head/tail progress.
18. Detect mappings with enumerable indexes.
19. Detect pending payment structures.
20. Detect proposal/settlement/keeper task queues.
21. Detect progress-critical function names.
22. Detect external calls inside batch loops.
23. Detect push-payment blocking patterns.
24. Detect withdrawal queue blocking patterns.
25. Detect keeper-only progress assumptions.
26. Detect insufficient-gas griefing candidates.
27. Detect state-bloat surfaces.
28. Detect missing pagination or batch size caps.
29. Detect missing retry paths after failed callbacks.
30. Detect missing emergency recovery paths.
31. Add negative checks for bounded loops.
32. Add negative checks for pull-payment design.
33. Add negative checks for retryable failures.
34. Add negative checks for keeper substitution.
35. Add negative checks for user self-service progress.
36. Generate Foundry progress property metadata.
37. Generate Echidna liveness-like property metadata.
38. Generate Halmos assertion metadata.
39. Generate local fixture obligations.
40. Bridge plans to sequence-oracle synthesis.
41. Bridge bloated-state seeds to snapshot fuzzing.
42. Bridge growth provenance to semantic graph gates.
43. Bridge attacker-controlled sizes to SSA/taint summaries.
44. Add fixture: unbounded recipient loop blocks withdrawal.
45. Add fixture: safe paginated recipient processing.
46. Add fixture: reverting recipient blocks push payment.
47. Add fixture: safe pull payment retry path.
48. Add fixture: keeper-only blocked settlement.
49. Add fixture: safe self-service fallback settlement.
50. Add runbook notes for comparing progress-oracle plans with benchmark findings.

Parallel lanes:

- Lane A: schemas, parser, exports, and provider-neutral tests.
- Lane B: resource/growth/progress extraction.
- Lane C: liveness hypothesis generation and negative checks.
- Lane D: progress-oracle generation and tool metadata bridges.
- Lane E: fixtures, non-canonical evidence, benchmark comparison, and runbook notes.

## Validation

For this SDD:

```bash
test -s docs/SDD_RESOURCE_LIVENESS_GRIEFING_HARDENING_20260811.md
rg -n "interchangeable security reasoning agent|provider-neutral|50-Activity" docs/SDD_RESOURCE_LIVENESS_GRIEFING_HARDENING_20260811.md
git diff --check -- docs/SDD_RESOURCE_LIVENESS_GRIEFING_HARDENING_20260811.md
```

Provider/model-name checks should run against the document content during review and should return no requirement binding the capability to one provider.

For future implementation:

- Unit tests for resource and progress-function extraction.
- Parser tests for bounded provider-neutral output.
- Fixture tests for unsafe and safe variants of each liveness family.
- Integration tests proving local DoS warnings stay advisory without a blocked-progress oracle.
- Non-canonical benchmark probes before any claimed uplift.

## References

- OWASP SCWE-059: Insufficient Gas Griefing. https://scs.owasp.org/SCWE/SCSVS-DEFI/SCWE-059/
- OWASP Smart Contract Security Testing Guide: Denial of Service overview. https://scs.owasp.org/SCSTG/tests/SCSVS-BLOCK/overview/
- SMARTIAN: Enhancing Smart Contract Fuzzing with Static and Dynamic Data-Flow Analyses, ASE 2021. https://conf.researchr.org/details/ase-2021/ase-2021-papers/66/SMARTIAN-Enhancing-Smart-Contract-Fuzzing-with-Static-and-Dynamic-Data-Flow-Analyse
- Echidna smart contract fuzzer. https://github.com/crytic/echidna
- Local reference: `docs/SDD_SEQUENCE_ORACLE_DETECTION_20260709.md`
- Local reference: `docs/SDD_SNAPSHOT_FUZZING_GUIDANCE_20260709.md`
- Local reference: `docs/SDD_EXTERNAL_CALL_RETURNDATA_HARDENING_20260712.md`
- Local evidence: `benchmarks/results/v6.0.0_benchmark_report_20260811.md`
