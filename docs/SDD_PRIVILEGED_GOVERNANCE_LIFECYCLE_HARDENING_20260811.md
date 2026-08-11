# SDD: Privileged Governance Lifecycle Hardening

Date: 2026-08-11
Owner/Lane: Codex
Status: Proposed SDD, not implemented, no benchmark claim

## Signal

MIESC already detects classic access-control symptoms: missing guards on privileged functions, excessive owner power, governance flash-loan patterns, missing timelocks in some admin paths, upgrade/admin drift, and semantic graph gates over role nodes. That coverage is useful, but it is still mostly local: it asks whether a function is guarded or whether a timelock string appears nearby.

Modern Solidity systems rely on a lifecycle of authority rather than a single `onlyOwner` modifier. Ownership can transfer in one or two steps, roles can be administered by other roles, timelocks can own controlled contracts, proposers and executors can become unavailable, guardians can pause but not unpause, multisigs can hold high-blast-radius roles, and emergency paths can bypass normal governance. OWASP SC01:2026 explicitly frames access control as more than a single modifier, including governance contracts, multisigs, guardians, proxy admins, and cross-chain routers. OpenZeppelin's TimelockController documentation also highlights the lifecycle risk that role availability and self-administered timelocks can lock controlled contracts indefinitely.

The technique to add is **Privileged Governance Lifecycle Hardening**: synthesize an authority graph, model role/admin/timelock transitions over time, classify lifecycle hazards, and generate provider-neutral validation obligations for unauthorized action, unavailable recovery, timelock bypass, overpowered emergency controls, and irreversible privilege loss.

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
authority_lifecycle_hardening
governance_privilege_hardening
role_timelock_lifecycle
admin_blast_radius_hardening
```

The capability must produce advisory lifecycle plans, not confirmed findings. It should promote a finding only after deterministic evidence, generated tests, symbolic counterexamples, or human review confirms that a privileged action can be abused, bypassed, locked forever, or recovered only through unsafe assumptions.

Primary objectives:

1. Extract privileged entrypoints: pause/unpause, mint/burn, set parameters, withdraw reserves, upgrade, grant/revoke roles, queue/execute/cancel proposals, emergency actions, and cross-chain admin relay.
2. Build an authority graph of owners, roles, role admins, timelocks, governors, guardians, proxy admins, multisigs, and controlled contracts.
3. Model lifecycle transitions: ownership transfer, role grant/revoke, timelock queue/execute/cancel, delay changes, pauser/unpauser separation, emergency bypass, upgrade admin handoff, and renounce/recovery paths.
4. Generate validation obligations for unauthorized execution, timelock bypass, role escalation, dead-admin lockout, guardian overreach, impossible unpause, unsafe delay reduction, and high-blast-radius single key.
5. Keep false-positive controls for intentionally centralized deployments, documented launch phases, bounded guardian powers, multisig/timelock controls, and explicit break-glass procedures.

## Design/Contract

Introduce a provider-neutral data contract before implementation:

```python
PrivilegedGovernanceLifecyclePlan = {
    "id": "string",
    "objective": "string",
    "authority_graph": {
        "privileged_entrypoints": ["function"],
        "authority_nodes": ["owner|role|role_admin|timelock|governor|guardian|proxy_admin|multisig|cross_chain_router|unknown"],
        "controlled_contracts": ["string"],
        "edges": [
            {
                "source": "string",
                "target": "string",
                "relation": "owns|administers|queues|executes|cancels|pauses|unpauses|upgrades|grants|revokes|relays",
                "source_anchor": "file:line",
            }
        ],
    },
    "lifecycle_hypothesis": {
        "category": "unguarded_privilege|role_escalation|timelock_bypass|unsafe_delay_change|dead_admin_lockout|guardian_overreach|impossible_recovery|pause_deadlock|upgrade_admin_drift|single_key_high_blast_radius|cross_chain_admin_spoof",
        "privileged_action": "string",
        "actor_model": "string",
        "preconditions": ["string"],
        "negative_checks": ["string"],
        "blast_radius": ["string"],
    },
    "validation_obligations": [
        {
            "tool": "foundry|echidna|halmos|local_fixture|human_review",
            "property": "string",
            "sequence": ["call"],
            "actors": ["attacker", "owner", "guardian", "governor", "proposer", "executor", "admin"],
            "expected_failure_or_revert": "string",
            "recovery_check": "string",
        }
    ],
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

- Classic access-control detectors remain first-pass signals for missing guards.
- Governance and centralization detectors supply suspicious privileged surfaces.
- `SemanticGraphGate` supplies role, modifier, event, external-call, and state anchors.
- `SequenceOraclePlan` can validate multi-step queue/execute/cancel/grant/revoke lifecycles.
- `Metamorphic Diff Testing` can validate pause/config/idempotence behavior.
- `Upgrade Evolution Analysis` can supply admin handoff and proxy-admin drift context.
- `Resource/Liveness Griefing Hardening` can consume pause deadlocks and dead-admin lockouts.
- False-positive filtering must downgrade local `onlyOwner` findings when documented timelock, multisig, role segmentation, and recovery paths are present.

## Prompt Requirements

Prompt and parser design must refer to an **interchangeable security reasoning agent**. No schema, parser, prompt, test, or SDD requirement may bind the capability to a specific vendor, hosted endpoint, product family, or model.

The reasoning agent must:

- Separate observed authority edges from inferred lifecycle hazards.
- Anchor every privileged entrypoint and authority edge to source lines.
- Include negative checks for each lifecycle hypothesis.
- Identify blast radius, not only access-control category.
- Avoid confirmed-finding language until validation confirms abuse, bypass, lockout, or unrecoverable privilege loss.
- Support deterministic local fallback based on modifiers, role constants, events, timelock functions, and ownership-transfer patterns.

## False-Positive Controls

The capability must avoid noisy governance findings:

- A single owner during launch is not a finding unless the deployment phase is indistinguishable from production or the blast radius is unmanaged.
- A guardian is not overpowered when it can pause only, cannot drain/upgrade, and unpause/recovery is governed.
- A timelock is not protection unless privileged actions are actually routed through it and delay changes cannot be immediate.
- Self-administered timelocks are not automatically unsafe, but role availability and recovery must be modeled.
- Multisig references are advisory until signer threshold, owner path, and controlled action surface are known.
- Role grants are not escalation findings when role admins are properly separated and recoverable.
- Provider output must be bounded and parser-validated before integration.

Promotion rules:

- `hypothesis`: authority graph and lifecycle risk only.
- `test_generated`: a validation sequence exists but has no failing execution.
- `counterexample`: symbolic/fuzz/local execution demonstrates bypass, escalation, lockout, or unsafe recovery.
- `replayed`: deterministic local or fork replay demonstrates impact.
- `rejected`: timelock routing, multisig controls, role separation, bounded emergency powers, and recovery paths disprove the risk.

## Non-Goals

- No replacement for classic access-control detectors.
- No generic centralization score.
- No canonical benchmark update from this SDD alone.
- No assumption that every admin key is a vulnerability.
- No provider-specific dependency.
- No confirmed finding from a local modifier pattern alone.

## Integration Plan

Phase 0 is this SDD. Future work should land in small, testable steps:

1. Add provider-neutral schema contracts and parser tests.
2. Add local authority graph extraction for owners, roles, role admins, timelocks, governors, guardians, proxy admins, and cross-chain routers.
3. Add lifecycle transition extraction for transfer, accept, grant, revoke, queue, execute, cancel, pause, unpause, delay change, upgrade, and emergency functions.
4. Add local lifecycle hazard classifier with negative checks.
5. Generate validation obligations for Foundry, Echidna, Halmos, local fixtures, and human review.
6. Add fixtures with safe and unsafe variants for each lifecycle family.
7. Run only non-canonical probes until benchmark promotion is explicitly approved.

## 50-Activity Parallelization Map

These activities can run across five lanes with disjoint file ownership.

1. Inventory current access-control detector outputs.
2. Inventory governance detector outputs.
3. Inventory centralization detector outputs.
4. Inventory upgrade/admin handoff outputs.
5. Inventory semantic graph role/modifier nodes.
6. Define `AuthorityNode` schema.
7. Define `AuthorityEdge` schema.
8. Define `PrivilegedEntrypoint` schema.
9. Define `LifecycleTransition` schema.
10. Define `PrivilegedGovernanceLifecyclePlan` schema.
11. Add parser for canonical output key.
12. Add aliases for authority lifecycle plans.
13. Add bounded text/list sanitization.
14. Add no-provider-binding regression tests.
15. Export public facade symbols.
16. Detect Ownable ownership surfaces.
17. Detect Ownable2Step transfer/accept paths.
18. Detect AccessControl role constants.
19. Detect role admin relationships.
20. Detect TimelockController queue/execute/cancel paths.
21. Detect Governor proposal execution paths.
22. Detect guardian pause/unpause surfaces.
23. Detect proxy admin/upgrade surfaces.
24. Detect multisig references and threshold hints.
25. Detect cross-chain admin relay surfaces.
26. Detect unguarded privileged entrypoints.
27. Detect role escalation via grant/revoke admin loops.
28. Detect timelock bypass on privileged calls.
29. Detect unsafe delay reduction.
30. Detect dead-admin lockout risk.
31. Detect guardian overreach.
32. Detect impossible unpause/recovery paths.
33. Detect pause deadlocks.
34. Detect upgrade admin drift.
35. Detect high-blast-radius single key.
36. Add negative checks for timelock routing.
37. Add negative checks for multisig/threshold controls.
38. Add negative checks for role separation.
39. Add negative checks for bounded guardian powers.
40. Add negative checks for documented recovery paths.
41. Generate Foundry authorization/lifecycle sequences.
42. Generate Echidna privilege invariants.
43. Generate Halmos assertion metadata.
44. Bridge authority graph to semantic graph gates.
45. Bridge pause deadlocks to liveness hardening.
46. Bridge admin handoff to upgrade evolution.
47. Add unsafe fixture for immediate delay reduction.
48. Add safe fixture for timelocked delay update.
49. Add unsafe fixture for guardian drain/upgrade.
50. Add safe fixture for pause-only guardian and governed recovery.

Parallel lanes:

- Lane A: schemas, parser, exports, and provider-neutral tests.
- Lane B: authority graph and lifecycle transition extraction.
- Lane C: hazard classifiers and negative checks.
- Lane D: validation obligations and bridges to existing plans.
- Lane E: fixtures, non-canonical evidence, benchmark comparison, and runbook notes.

## Validation

For this SDD:

```bash
test -s docs/SDD_PRIVILEGED_GOVERNANCE_LIFECYCLE_HARDENING_20260811.md
rg -n "interchangeable security reasoning agent|provider-neutral|50-Activity" docs/SDD_PRIVILEGED_GOVERNANCE_LIFECYCLE_HARDENING_20260811.md
git diff --check -- docs/SDD_PRIVILEGED_GOVERNANCE_LIFECYCLE_HARDENING_20260811.md
```

Provider/model-name checks should run against the document content during review and should return no requirement binding the capability to one provider.

For future implementation:

- Unit tests for authority graph and lifecycle transition extraction.
- Parser tests for bounded provider-neutral output.
- Fixture tests for unsafe and safe variants of each lifecycle family.
- Integration tests proving local access-control findings stay advisory without lifecycle evidence.
- Non-canonical benchmark probes before any claimed uplift.

## References

- OWASP SC01:2026 Access Control Vulnerabilities. https://scs.owasp.org/sctop10/SC01-AccessControlVulnerabilities/
- OWASP SCWE-020: Absence of Time-Locked Functions. https://scs.owasp.org/SCWE/SCSVS-AUTH/SCWE-020/
- OpenZeppelin Contracts Access Control. https://docs.openzeppelin.com/contracts/5.x/api/access
- OpenZeppelin Contracts Governance and TimelockController. https://docs.openzeppelin.com/contracts/4.x/api/governance
- OpenZeppelin Timelock role management guide. https://docs.openzeppelin.com/defender/guide/timelock-roles
- Local reference: `docs/SDD_SEMANTIC_GRAPH_GATING_20260709.md`
- Local reference: `docs/SDD_UPGRADE_EVOLUTION_ANALYSIS_20260711.md`
- Local reference: `docs/SDD_RESOURCE_LIVENESS_GRIEFING_HARDENING_20260811.md`
