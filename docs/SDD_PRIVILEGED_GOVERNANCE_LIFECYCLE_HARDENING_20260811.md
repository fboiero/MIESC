# SDD: Privileged Governance Lifecycle Hardening

Date: 2026-08-11
Owner/Lane: Codex
Status: Proposed SDD, not implemented, no benchmark claim

## Signal

MIESC already covers access-control detectors, upgrade-evolution analysis,
delegatecall storage aliasing, signature-domain hardening, transaction ordering,
semantic graph gating, SlithIR SSA summaries, and resource/liveness griefing.
The remaining gap is not another `onlyOwner` matcher. The gap is a
provider-neutral artifact that reasons about the **lifecycle of privileged
authority**: how roles are created, delegated, queued, delayed, revoked,
renounced, rotated, upgraded, paused, and used under emergency or compromised-key
conditions.

Smart-contract incidents often happen outside the single guarded function that a
classic access-control detector sees. A function may be guarded, but the guard
can be bypassed through an unsafe initializer, instant timelock execution,
unbounded guardian powers, stale multisig assumptions, pause-only-without-unpause
design, role admin self-grant paths, upgrade hooks, cross-chain governance
messages, or governance actions that are valid individually but unsafe as a
sequence.

The technique to add is **Privileged Governance Lifecycle Hardening**: synthesize
an authority graph and lifecycle plan, then generate validation obligations for
role-transition sequences, delay invariants, emergency powers, upgrade powers,
pause/recover flows, and cross-domain governance messages. Plans remain advisory
until replay, symbolic execution, fuzzing, or human review confirms a reachable
privilege escalation, governance bypass, or unavailable recovery path.

## Spec/Goal

Add a future capability named:

```text
privileged_governance_lifecycle_hardening
```

Expected output key:

```text
privileged_governance_lifecycle_plans
```

Suggested aliases:

```text
governance_lifecycle_hardening
privileged_role_lifecycle_plans
authority_graph_hardening
admin_timelock_hardening
emergency_power_hardening
```

The capability must produce advisory governance lifecycle plans, not confirmed
findings. A plan becomes a finding only after deterministic replay, symbolic
execution, fuzzing, local fixture validation, fork validation, or human review
confirms the unsafe state transition or missing recovery path.

Primary objectives:

1. Identify privileged actors: owner, admin, guardian, governor, proposer,
   executor, pauser, upgrader, bridge messenger, timelock, multisig, keeper, and
   role-admin relationships.
2. Identify privileged surfaces: upgrade, pause/unpause, mint/burn, treasury
   movement, oracle setter, fee setter, parameter setter, role grant/revoke,
   emergency withdrawal, bridge relay, proposal queue/execute/cancel, and
   initializer/reinitializer functions.
3. Build lifecycle transitions: bootstrap, initialization, delegation, role
   rotation, timelock queue, timelock execute, cancellation, pause, unpause,
   emergency recovery, upgrade, migration, decommission, and renounce.
4. Infer governance invariants: no unprotected initializer, admin cannot
   self-grant without delay, critical changes require timelock, emergency powers
   are bounded, pause has a recovery path, upgrades preserve authority, and
   cross-domain governance messages bind sender/domain/replay state.
5. Generate validation obligations that exercise role-transition sequences and
   reject false positives when controls are explicit, delayed, bounded, and
   recoverable.

## Design/Contract

Introduce a provider-neutral data contract before implementation:

```python
PrivilegedGovernanceLifecyclePlan = {
    "id": "string",
    "objective": "string",
    "authority_graph": {
        "actors": [
            {
                "id": "string",
                "kind": "owner|admin|guardian|governor|proposer|executor|pauser|upgrader|timelock|multisig|bridge_messenger|keeper|unknown",
                "source": "storage|constant|constructor|initializer|role|external_contract|unknown",
                "source_anchors": ["file:line"],
            }
        ],
        "roles": [
            {
                "name": "string",
                "admin_role": "string",
                "holders": ["actor_id"],
                "grant_functions": ["function"],
                "revoke_functions": ["function"],
            }
        ],
        "edges": [
            {
                "source": "actor_or_role",
                "target": "function_or_role",
                "relation": "guards|grants|revokes|queues|executes|cancels|upgrades|pauses|recovers|delegates",
                "evidence": ["string"],
            }
        ],
    },
    "lifecycle_hypothesis": {
        "category": "unprotected_initializer|role_admin_self_grant|missing_timelock|timelock_bypass|unbounded_emergency_power|pause_recovery_gap|unsafe_upgrade_authority|cross_domain_governance_replay|guardian_takeover|renounce_brick|parameter_rug|treasury_drain_path",
        "attacker_or_fault_model": "string",
        "unsafe_transition": "string",
        "critical_surface": "string",
        "preconditions": ["string"],
        "negative_checks": ["string"],
    },
    "governance_oracle": {
        "property": "string",
        "expected_safe_transition": "string",
        "forbidden_transition": "string",
        "recovery_condition": "string",
    },
    "execution_plan": {
        "recommended_tools": ["foundry", "halmos", "echidna", "slither", "openzeppelin-upgrades", "local_fixture", "human_review"],
        "sequence": ["call"],
        "actors": ["deployer", "admin", "attacker", "guardian", "governor", "executor", "user"],
        "inputs_to_mutate": ["string"],
        "delay_budget_hint": "string",
        "fork_or_timewarp_hint": "string",
    },
    "promotion": {
        "state": "hypothesis|test_generated|counterexample|replayed|rejected",
        "evidence": ["string"],
        "blockers": ["string"],
    },
    "metadata": {
        "capability": "privileged_governance_lifecycle_hardening",
        "schema_version": "1",
    },
}
```

The capability should compose existing MIESC pieces:

- Access-control findings provide guard and missing-guard seeds.
- `UpgradeEvolutionPlan` supplies storage-layout and upgrade-authority changes.
- `DelegatecallStorageAliasingPlan` supplies privileged-slot corruption paths.
- `SignatureDomainHardeningPlan` supplies off-chain authorization and replay
  surfaces.
- `CrossChainMessageHardeningPlan` supplies cross-domain sender/domain/replay
  checks.
- `SequenceOraclePlan` supplies role-transition ordering.
- `SnapshotFuzzingPlan` supplies reusable governance states and delay/queue
  waypoints.
- `SemanticGraphGate` supplies authority graph anchors.
- `SlithIR SSA + Interprocedural State/Taint Summary` supplies precise
  role-variable writes and privileged call propagation.
- `ResourceLivenessGriefingPlan` supplies pause/recover and keeper-liveness
  recovery checks.

## Prompt Requirements

Prompt and parser design must refer to an **interchangeable security reasoning agent**.
No schema, parser, prompt, or test may bind the capability to a
specific vendor, hosted endpoint, product family, or model.

The reasoning agent must:

- Separate observed authority relationships from inferred governance risk.
- Anchor each actor, role, privileged function, and lifecycle transition to
  source lines when available.
- Return at least one negative check for every hypothesis.
- Prefer executable governance oracles over narrative severity.
- Keep emergency controls and governance delays explicit.
- Avoid confirmed-finding language until validation confirms reachability.
- Support deterministic local fallback based on owner/admin/role/timelock/
  upgrade/pause naming and Slither-derived state writes.

## False-Positive Controls

The capability must avoid noisy governance findings:

- A privileged function is not a finding when its authority is explicit,
  expected, delayed, and documented.
- Admin self-grant is not a finding when it is timelocked, quorum-controlled, or
  bounded by a multisig/governor path with cancellation.
- Emergency pause is not a finding when pause duration, unpause authority, and
  recovery flow are bounded.
- Upgrade authority is not a governance finding when upgrade authorization,
  storage compatibility, initializer safety, and migration checks are enforced.
- Renounce ownership is not a finding when a replacement owner/governor/recovery
  path exists before renounce.
- Cross-domain governance is not a finding when sender, chain/domain, nonce,
  replay protection, and finality delay are verified.
- Parameter changes are not findings without a critical economic, accounting,
  oracle, fee, liquidation, mint/burn, treasury, or access-control consequence.
- Provider output must be bounded and parser-validated before integration.

Promotion rules:

- `hypothesis`: authority graph and lifecycle risk only.
- `test_generated`: a governance oracle or role-transition harness exists but
  has not failed.
- `counterexample`: fuzzing or symbolic execution demonstrates an unsafe
  transition.
- `replayed`: deterministic local or fork replay demonstrates privilege
  escalation, bypass, stuck recovery, or unauthorized critical action.
- `rejected`: timelock, quorum, cancellation, bounded emergency power, safe
  upgrade guard, or recovery path disproves the risk.

## Non-Goals

- No replacement for classic access-control detectors.
- No claim that every centralized admin surface is a vulnerability.
- No canonical benchmark update from this SDD alone.
- No remote governance service dependency in the first implementation.
- No provider-specific dependency.
- No confirmed vulnerability without a reachable unsafe transition.

## Integration Plan

Phase 0 is this SDD. Future work should land in small, testable steps:

1. Add provider-neutral schema contracts and parser tests.
2. Add local authority-graph extraction for owners, roles, timelocks, governors,
   guardians, pausers, upgraders, and bridge messengers.
3. Add privileged-surface classifier for upgrade/pause/treasury/oracle/fee/
   role/initializer/emergency paths.
4. Add lifecycle hypothesis generator for unsafe initialization, role-admin
   self-grant, missing timelock, timelock bypass, unbounded emergency power,
   pause recovery gaps, unsafe upgrade authority, cross-domain replay, and
   parameter rug paths.
5. Generate governance oracles for Foundry/Halmos/Echidna/local fixtures.
6. Add fixtures with safe and unsafe variants for role transition, timelock,
   pause/unpause, upgrade, and cross-domain governance families.
7. Run only non-canonical probes until benchmark promotion is explicitly
   approved.

## 50-Activity Parallelization Map

These activities can run across five lanes with disjoint file ownership.

1. Inventory current access-control detector outputs.
2. Inventory upgrade-evolution authority fields.
3. Inventory delegatecall privileged-slot findings.
4. Inventory signature-domain authority surfaces.
5. Inventory cross-chain governance message checks.
6. Define `GovernanceActor` schema.
7. Define `GovernanceRole` schema.
8. Define `AuthorityGraphEdge` schema.
9. Define `LifecycleHypothesis` schema.
10. Define `PrivilegedGovernanceLifecyclePlan` schema.
11. Add parser for canonical output key.
12. Add parser aliases for governance lifecycle plans.
13. Add bounded text/list sanitization.
14. Add no-provider-binding regression tests.
15. Export public facade symbols.
16. Detect owner/admin storage variables.
17. Detect OpenZeppelin-style roles and role admins.
18. Detect timelock controllers and queue/execute/cancel paths.
19. Detect governor proposer/executor paths.
20. Detect pauser/guardian/emergency roles.
21. Detect upgrader and proxy admin paths.
22. Detect initializer/reinitializer authority setup.
23. Detect bridge messenger governance sources.
24. Detect treasury and fee setter surfaces.
25. Detect oracle and risk-parameter setter surfaces.
26. Detect role grant/revoke functions.
27. Detect renounce/transfer ownership transitions.
28. Detect missing delay on critical transitions.
29. Detect missing cancellation on queued actions.
30. Detect missing unpause/recovery path.
31. Add negative checks for explicit timelocks.
32. Add negative checks for quorum and multisig paths.
33. Add negative checks for bounded emergency powers.
34. Add negative checks for safe initializer guards.
35. Add negative checks for cross-domain replay protection.
36. Generate Foundry role-transition property metadata.
37. Generate Halmos authorization assertion metadata.
38. Generate Echidna governance sequence metadata.
39. Generate local fixture obligations.
40. Bridge authority graph edges to semantic graph gates.
41. Bridge role-transition sequences to sequence-oracle synthesis.
42. Bridge delayed-state seeds to snapshot fuzzing.
43. Bridge authority writes to SSA/taint summaries.
44. Add fixture: unprotected initializer grants owner.
45. Add fixture: safe initializer guard rejects second call.
46. Add fixture: admin self-grant bypasses timelock.
47. Add fixture: safe timelock queue/execute/cancel path.
48. Add fixture: pause without recovery bricks withdrawal.
49. Add fixture: safe guardian pause with governor unpause.
50. Add runbook notes for comparing governance lifecycle plans with benchmark
    findings.

Parallel lanes:

- Lane A: schemas, parser, exports, and provider-neutral tests.
- Lane B: authority graph and privileged surface extraction.
- Lane C: lifecycle hypothesis generation and negative checks.
- Lane D: governance-oracle generation and tool metadata bridges.
- Lane E: fixtures, non-canonical evidence, benchmark comparison, and runbook
  notes.

## Validation

For this SDD:

```bash
test -s docs/SDD_PRIVILEGED_GOVERNANCE_LIFECYCLE_HARDENING_20260811.md
rg -n "interchangeable security reasoning agent|provider-neutral|50-Activity" docs/SDD_PRIVILEGED_GOVERNANCE_LIFECYCLE_HARDENING_20260811.md
git diff --check -- docs/SDD_PRIVILEGED_GOVERNANCE_LIFECYCLE_HARDENING_20260811.md
```

Provider/model-name checks should run against the document content during review
and should return no requirement binding the capability to one provider.

For future implementation:

- Unit tests for authority graph extraction.
- Parser tests for bounded provider-neutral output.
- Fixtures for unsafe and safe role-transition paths.
- Local/fork replay tests only when the victim or governance source is present.
