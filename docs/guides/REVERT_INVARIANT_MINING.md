# Revert-Invariant Mining

Revert-invariant mining treats a contract's **own defenses as signal**. Modern Solidity encodes
many security properties as `require`, `assert`, custom-error `revert`, and `if (...) revert`
guards. MIESC mines those guards, clusters sibling functions, and flags where a defensive category
is applied **inconsistently** — some functions in a family are guarded and a peer is not.

Everything in this capability is **advisory by default and precision-first**: a gap is a
*hypothesis*, never a finding, until execution proves it. The only output that ever becomes a
finding is one MIESC has reproduced by running it.

!!! note "Design reference"
    This guide is the user-facing view. The full design rationale is in
    `docs/SDD_REVERT_INVARIANT_MINING_20260810.md`.

## The promotion ladder

A gap travels up a ladder; each rung needs more evidence than the last, and MIESC never skips one.

| State | Meaning | Becomes a finding? |
|-------|---------|--------------------|
| `hypothesis` | A gap was observed (a guarded sibling, an unguarded peer). | No |
| `test_generated` | A Foundry probe harness exists, but nothing has run it. | No |
| `counterexample` | A probe **ran** and an unauthorized call **succeeded**. | **Yes** |

The discipline across the whole chain is **"never an *unverified* finding."** A `counterexample`
is the opposite of unverified — Foundry executed the attack and it worked — so it has earned the
finding. A `hypothesis` or a `test_generated` harness never does.

## Gap categories

Each category compares a *population* of external/public state-changing functions and resolves
guards **through applied modifiers** (so a function guarded by `onlyOwner` counts as guarded):

- **`access_control`** — per privileged verb family (`set*`, `upgrade*`, `grant*`, …): if a
  sibling is access-controlled and a peer is not, that is a gap.
- **`pause_toggle`** — over user-facing mutators (`deposit`, `withdraw`, `swap`, …): if some are
  pause-gated (`whenNotPaused`) and a peer is not.
- **`freshness_check`** — over functions that accept a `deadline`/`expiry` **parameter**: if a peer
  never enforces it. A deadline enforced by a modifier, checked locally, forwarded into an inner
  call, or stored resolves out; only a parameter accepted and never referenced reads as a gap.

A guard whose mechanism MIESC cannot see — an inherited/delegating modifier (OpenZeppelin
`Pausable`'s `whenNotPaused`), a forwarded parameter — marks the function **opaque** and *excludes*
it from the comparison, rather than assuming the guard is absent. This is why the miner stays
silent on OpenZeppelin, Solady and Uniswap v2-periphery (500+ files) instead of flooding them with
false gaps.

## What the deep-audit report surfaces

With the advisory phase enabled, `report["phases"]["advisory_plans"]["capabilities"]["revert_invariants"]`
carries, additively:

| Key | Rung | Content |
|-----|------|---------|
| `plans` | — | The raw `RevertInvariantOraclePlan` (guard inventory + `gap_hypotheses`). |
| `oracle_plans` | `hypothesis` | Advisory `SequenceOraclePlan` fuzzing/oracle guidance per gap. |
| `harnesses` | `test_generated` | Foundry `vm.expectRevert` probe harnesses (incomplete by design; TODOs recorded in `blockers`). |
| `executions` | `hypothesis`/`counterexample` | Results of actually running access-control probes (opt-in). |

A confirmed `counterexample` is additionally promoted into `report["findings"]` as a normal
finding (`type="access_control"`, `severity="High"`, `confidence=0.85`), passing through the
**same** false-positive filter and dedup as every other finding.

## Enabling it

Both flags are **off by default** on `DeepAuditConfig`:

```python
from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig

# Advisory metadata only (no execution): plans, oracle_plans, harnesses.
agent = DeepAuditAgent(DeepAuditConfig(enable_advisory_plans=True))

# Also run access-control probes with Foundry and promote confirmed
# counterexamples to findings. Requires `forge` on PATH; adds wall-clock.
agent = DeepAuditAgent(DeepAuditConfig(enable_gap_execution=True))

report = agent.analyze("Contract.sol")
```

`enable_gap_execution` is the single switch for both running the probes and emitting the resulting
findings — turning it on means "I accept the Foundry wall-clock to get execution-verified
evidence."

## Precision guarantees & safety

- **Never an unverified finding.** Only a reproduced `counterexample` reaches the finding set.
- **Execution is gated and degrades gracefully.** No `forge` on PATH, an ineligible contract
  (constructor arguments, non-elementary parameters), or a probe that does not compile → the gap
  is returned unchanged, never an error.
- **Self-contained probes.** The probe inlines the contract under test plus a minimal `Vm`
  interface — no `forge-std`, no network.
- **Cheatcode-injection refusal.** Source that itself references Foundry cheatcodes is refused for
  execution, so a contract cannot smuggle test behavior into the probe.
- **No bypass of controls.** Counterexample findings go through the normal FP filter and dedup.

## Limitations (current)

- **Execution is access-control only.** `freshness_check` needs the deadline parameter's position
  and `pause_toggle` needs the pauser — neither can be reached deterministically, so those
  categories stop at `test_generated`. Completing and executing them is proposed future work
  (a provider-neutral reasoning agent).
- **Executable subset.** Only contracts that deploy with a no-arg constructor and functions whose
  parameters are elementary (uint/int/address/bool/bytesN) are probed; everything else stays at
  `test_generated`.
- **A counterexample proves reachability, not impact.** An unguarded setter whose value is never
  read is a real missing guard but may be low-impact — hence `confidence=0.85`, not `1.0`.
- **No benchmark claim.** These results are advisory; no canonical precision/recall uplift is
  claimed from this capability.
