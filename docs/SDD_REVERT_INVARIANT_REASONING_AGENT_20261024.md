# SDD: Revert-Invariant Reasoning Agent (freshness / pause execution)

Date: 2026-10-24
Owner/Lane: Claude
Status: **Implemented (local + remote reasoning-provider path; access-control-style subset).** The
control-probe precision invariant, the pause/freshness executor (`miesc/llm/revert_invariant_reasoning.py`),
the `enable_gap_reasoning` wiring and tests have shipped. Fact resolution is local-first
(deterministic literal cases, no tokens); when the local extractor cannot name the one identity it
needs — a non-literally-named pauser, or a deadline parameter index — and a reasoning provider is
supplied, the provider is asked for that single identity via `auto_reasoning_provider` /
`ReasoningTask` (capability `counterexample_validation`, gated by `agentic_invariants_allow_remote`),
and the answer is validated against the parsed contract. A wrong provider answer fails CLOSED: the
control+baseline probe does not confirm the state, so nothing promotes. Still open: widening the
executable subset beyond no-arg-constructor + elementary args. A post-merge review found the first control probe failing *open*: baseline and state check ran in one test, so a guarded sibling that reverts on its second call for an unrelated reason (one-shot, cooldown, a pauser with a side effect) or a bare `require(deadline > 0)` against the zero literal confirmed a fake state. The control now runs `test_control_baseline` and `test_control_state` from fresh state, passes a nonzero past deadline, and requires the sibling to revert with the guard's own revert data (degrading to a plain revert only when that payload is not readable); those four cases are regression fixtures.

## Context

The deterministic revert-invariant chain is complete on `main`:

- miner + three gap categories — `access_control`, `pause_toggle`, `freshness_check`;
- advisory oracle-plan bridge (`SequenceOraclePlan`);
- `test_generated` probe harnesses (incomplete by design);
- **access-control execution** (`enable_gap_execution`): runs a Foundry probe and promotes a real
  counterexample to a finding;
- the finding bridge (counterexample → finding, through the normal FP filter).

Only `access_control` reaches the `counterexample` rung, because its *rejectable state* needs no
contract knowledge — an unauthorized caller is just `vm.prank(address(0xBEEF))`. `freshness_check`
and `pause_toggle` stop at `test_generated`: reaching their rejectable state needs facts a
deterministic probe cannot synthesize (which argument is the deadline; which function is the
pauser and who may call it).

This SDD proposes a **reasoning agent** that supplies exactly those missing facts — and nothing
more — so those two categories can also reach `counterexample` **without** opening a false-positive
hole.

## Goal / Non-goal

**Goal.** Raise the *executable* fraction of `freshness_check` / `pause_toggle` gaps from 0% to
whatever can be **independently verified**, and emit a counterexample only when execution confirms
it, exactly as the access-control executor does today.

**Non-goal — stated first because it is the most likely misread.** The LLM is **not a detector**
and **not allowed to decide that a gap is real.** It fills in bounded, structured facts; the
verdict stays with Foundry. If a reader expects "the model finds bugs," this design has failed.

## The one hard constraint: the LLM may not construct the rejectable state

This is the entire reason the step was deferred, stated precisely.

For access control the rejectable state is generated deterministically (`vm.prank(0xBEEF)`), so a
probe that succeeds unambiguously means "no guard." For pause/freshness the rejectable state is
*"paused"* / *"past the deadline"*, and reaching it requires contract-specific facts. If we let the
LLM assert those facts and build the probe from them, a **wrong** fact can still compile and run,
the target call can succeed **for a reason unrelated to the guard**, and we would emit a
counterexample that is a lie. Compilation success does not protect us — the promotion rule's
*input* would be LLM-shaped.

Therefore the design **separates what the LLM proposes from what Foundry verifies**, and verifies
the rejectable state **independently** before trusting any probe result.

### 1. The LLM emits structured facts, never Solidity

Through the existing provider-neutral `parse_*` contract layer in `agentic_contracts.py` (the same
layer `InvariantExtractionAgent` uses), a new bounded contract — call it `GapProbeFacts` — carries
only:

```text
GapProbeFacts = {
  "category": "freshness_check | pause_toggle",
  "constructor_args": ["elementary zero-literals or simple values"],
  "target_call_args": ["args for the unguarded function"],
  # freshness:
  "deadline_param_index": int,          # which parameter is the deadline/expiry
  # pause:
  "pauser_function": "string",          # the function that sets the paused state
  "pauser_authorized_by": "owner|role|open|unknown",
  "pauser_call_args": ["..."],
}
```

Every field is parser-validated and bounded (reusing `_safe_label`, `_safe_text_list`,
`_bounded_nonnegative_int`). The **deterministic** harness generator then builds the probe Solidity
from these facts — the LLM never writes a line of the probe. (There is prior art to extend rather
than invent: `agentic_contracts.py` already carries `{function, deadline_source}`-shaped contracts
around line 653.)

### 2. The control probe — the load-bearing beam

Before trusting the *target* probe, generate a **control probe** that proves the proposed
rejectable state is actually reached, using the **guarded sibling** (known from the gap) as the
oracle:

- **pause:** reach the proposed paused state (`pauser_function`), then call the sibling that *is*
  `whenNotPaused`; assert it **reverts**. If the guarded sibling does **not** revert, the proposed
  "paused state" is not paused → discard, inconclusive, never a counterexample.
- **freshness:** `vm.warp` past the proposed deadline arg, then call the *guarded* sibling; it must
  revert. If it does not, the proposed deadline position is wrong → inconclusive.

A **counterexample requires both**: the control probe **reverts** (the state is real) **and** the
target probe **succeeds** (the guard is absent on the sibling). Either alone is inconclusive. This
is what makes a wrong LLM fact fail *closed* (into `test_generated`/inconclusive) instead of into a
false finding.

### 3. Degradation ladder (longer than the executor's)

| Condition | Outcome |
|-----------|---------|
| `forge` absent | `test_generated` |
| provider absent (no key / offline) | `test_generated` (+ a deterministic local fallback that only handles the *literal* cases: a param literally named `deadline`; a function literally named `pause()` — never a guess) |
| LLM output fails the parser | `test_generated` |
| probe does not compile | inconclusive |
| **control probe does not revert** | inconclusive, with a reason naming the LLM's proposal as unverified |
| control reverts **and** target succeeds | `counterexample` → finding (through the normal FP filter, as today) |

## Provider neutrality

Mirror `_extract_agentic_invariants` exactly — do not invent a parallel provider path:

- `provider = auto_reasoning_provider(prefer_local_fallback=True)` (`reasoning_provider_adapter.py`);
- a policy carrying `allow_remote`, enforced at `reasoning_provider_adapter.py:280`;
- a bounded, parser-validated response; a timeout; swallow-and-degrade on any failure.

The implementation must not name a vendor, model, or endpoint.

## Configuration (open decisions for review)

- **New flag `enable_gap_reasoning`, default off, and it should *require* `enable_gap_execution`.**
  Reasoning without execution is just a harness-completer and there is no honest promotion without
  the forge run. This is the first opt-in that *spends provider tokens* in the audit path, so it
  earns its own switch.
- **Remote gate.** `DeepAuditConfig.agentic_invariants_allow_remote` already gates remote providers
  for the agentic-invariants path. **Decision for Fernando:** reuse that flag for gap reasoning
  (one "may this audit call a remote model" switch), or add a parallel
  `gap_reasoning_allow_remote`? Recommendation: reuse — a second remote gate is a footgun. Default
  stays local-only.

## What this does NOT change

- `access_control` execution is unchanged (it never needed the LLM).
- The "never an *unverified* finding" rule is unchanged and, if anything, strengthened: a
  freshness/pause counterexample now carries **two** forge-verified facts (state reached, guard
  absent), not one.
- Counterexamples remain promoted-plan/finding metadata through the existing controls; this SDD
  does not add a new finding path, only new *inputs* to the one from the finding bridge.

## Validation (for the future implementation)

- Fixture: an LLM that proposes the **wrong** pauser → control probe fails to revert → **zero**
  findings (the central FP test).
- Fixture: correct facts, genuinely unguarded sibling → one counterexample, line anchored at the
  sibling declaration.
- Fixture: provider absent → `test_generated`, no error; forge absent → `test_generated`.
- Non-vacuous negative control: 0 freshness/pause counterexamples across OpenZeppelin, Solady,
  Uniswap v2-periphery.
- No benchmark claim.

## Open questions for review

1. Remote gate: reuse `agentic_invariants_allow_remote` or add a gap-specific one?
2. Executable subset for pause/freshness — same elementary-args + no-arg-constructor limit as the
   access-control executor, or widen once the LLM can propose constructor args? (Recommendation:
   keep the same limit for the first slice; widening is a later, separately-measured step.)
3. Is the control-probe-as-oracle acceptable as the sole gate, or do we also want a second
   independent signal (e.g. a differential run) before promotion? (Recommendation: control probe is
   sufficient for the first slice; it already requires two forge-verified facts.)
