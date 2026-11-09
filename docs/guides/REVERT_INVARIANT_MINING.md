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

A gap travels up a ladder; each rung needs more evidence than the last. The rungs are artifacts,
not prerequisites: the executor can take an access-control gap from `hypothesis` straight to
`counterexample`, while the `test_generated` harness for the same gap is produced alongside.

| State | Meaning | Becomes a finding? |
|-------|---------|--------------------|
| `hypothesis` | A gap was observed (a guarded sibling, an unguarded peer). | No |
| `test_generated` | A Foundry probe harness exists, but nothing has run it. | No |
| `counterexample` | A probe **ran**, and an unauthorized call **did not revert and wrote the contract's storage**. | **Yes** |

The discipline across the whole chain is **"never an *unverified* finding."** A `counterexample`
is the opposite of unverified — Foundry executed the unauthorized call, it did not revert, and it
wrote the target's storage — so it has earned the finding. A `hypothesis` or a `test_generated`
harness never does. A call that merely *does not revert* is not enough: a guard that returns
early, or a setter that no-ops on the zero argument, leaves the gap at `hypothesis`.

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
| `executions` | `hypothesis`/`counterexample` | Results of actually running access-control probes (opt-in). Each entry carries a `reason` when the gap was not executed or not promoted, and an `isolation` record (`ffi`, `fs_permissions`, `env`, `network`) describing what the sandbox enforced for that run. |

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

`enable_gap_execution` is the switch for running the probes and emitting the resulting findings —
turning it on means "I accept running the contract under Foundry to get execution-verified
evidence." On its own it produces **findings only**: the `executions` metadata (and the rest of
`capabilities.revert_invariants`) appears only when `enable_advisory_plans=True` as well. With both
flags on, the access-control probes currently run twice per contract (once for the metadata, once
for the findings).

## Precision guarantees & safety

- **Never an unverified finding.** Only a reproduced `counterexample` reaches the finding set.
- **Execution is gated and degrades gracefully.** No `forge` on PATH, an ineligible contract
  (constructor arguments, non-elementary parameters), or a probe that does not compile → the gap
  is returned unchanged, never an error.
- **No bypass of controls.** Counterexample findings go through the normal FP filter and dedup.

!!! warning "The contract under audit executes"
    `enable_gap_execution` runs the **audited contract** inside Foundry, and Foundry grants
    cheatcode access to every contract a test deploys — so the audited bytecode can call `vm.*`
    exactly like the probe. Treat the flag as "run this code", and enable it only on code you are
    willing to run, ideally inside a network-less container. The executor keeps the surface as
    small as it can enforce:

    - the generated `foundry.toml` pins `ffi = false` and `fs_permissions = []`, so a permissive
      global `~/.foundry/foundry.toml` cannot re-enable shell or file access;
    - `forge` runs with an allow-listed environment (`PATH`, `HOME`, temp/locale/SSL variables)
      and `FOUNDRY_PROFILE=default`, so `vm.env*` cannot read API keys or RPC URLs;
    - outbound network is **denied only where the host has an unprivileged sandbox**
      (`sandbox-exec` on macOS, `unshare -rn` on Linux). `vm.rpc`/`createFork` have no
      configuration switch, so on a host without a sandbox the audited contract can reach the
      network. Every executed result says which case applied in `isolation.network`
      (`"denied"` or `"unrestricted"`), and a warning is logged when unrestricted — check it;
    - a source that names the cheatcode address or the `"hevm cheat code"` seed is refused
      outright. This is defense in depth against a contract aiming at the host, not isolation: the
      address can be computed at runtime, which is exactly why the layers above exist.

## Limitations (current)

- **Execution is access-control only.** `freshness_check` needs the deadline parameter's position
  and `pause_toggle` needs the pauser — neither can be reached deterministically, so those
  categories stop at `test_generated`. Completing and executing them is proposed future work
  (a provider-neutral reasoning agent).
- **Executable subset.** Only contracts that deploy with a no-arg constructor and functions whose
  parameters are elementary (uint/int/address/bool/bytesN) are probed; everything else stays at
  `test_generated`.
- **A counterexample proves an unauthorized storage write, not impact.** An unguarded setter
  whose value is never read is a real missing guard but may be low-impact — hence
  `confidence=0.85`, not `1.0`. Writes to *other* contracts' storage are not observed, so a
  function that only mutates external state stays `hypothesis`.
- **`solc` must be cached on a sandboxed host.** With outbound network denied, `forge` cannot
  download the compiler the contract's pragma asks for; the probe then fails to compile and the
  gap stays `hypothesis` with `reason = "probe did not compile or run standalone"` — silently
  inconclusive, never a false positive. Pre-install the versions you need (`forge build --use <version>` on any file, outside the
  sandbox) before relying on execution.
- **No benchmark claim.** These results are advisory; no canonical precision/recall uplift is
  claimed from this capability.
