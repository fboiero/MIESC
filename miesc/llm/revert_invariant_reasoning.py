"""Execute ``freshness_check`` / ``pause_toggle`` gap hypotheses, failing CLOSED on a wrong fact.

This is the reasoning-agent slice of the revert-invariant SDD
(``docs/SDD_REVERT_INVARIANT_REASONING_AGENT_20261024.md``). It lets the two gap categories whose
*rejectable state* needs contract-specific facts -- "paused" and "past the deadline" -- reach the
``counterexample`` rung that :mod:`miesc.llm.revert_invariant_executor` already reaches for
``access_control``.

The one hard constraint (the entire point)
------------------------------------------
The facts layer must **not** construct the rejectable state as ground truth. A wrong fact (the
"pauser" that does not pause; the parameter that is not the deadline) can still compile and run, the
target call can succeed for a reason unrelated to the guard, and we would emit a counterexample that
is a lie. So a counterexample requires **both** Foundry probes to agree, and a wrong fact fails into
``hypothesis`` (inconclusive), never into a finding:

- **control probe** -- two Foundry tests, each from a **fresh** ``setUp`` state so no call-count
  effect leaks between them: ``test_control_baseline`` calls the *guarded sibling*
  (``gap.guarded_example``) and asserts it *succeeds* before the state is reached;
  ``test_control_state`` reaches the proposed state and asserts the sibling **reverts with the
  guard's own revert data** (the ``require`` message or custom error extracted from the locally
  defined modifier / local check; when that payload is not extractable the check degrades to a
  plain revert). Both must be ``Success`` for the state to count as real. Running them in one test
  would let a sibling that reverts on its *second* call for any reason (a one-shot ``claim``, a
  cooldown, a pauser with an unrelated side effect) impersonate the guard -- that is exactly the
  false counterexample this layer exists to prevent. The freshness control passes a **nonzero**
  past deadline so a mere ``require(deadline > 0)`` cannot pass for a deadline check.
- **target probe** -- in the same state, call the unguarded affected function and reuse the
  executor's storage-write assertion: it ``Failure``s only when the call both *succeeded* and
  *wrote* the target's storage.

Promotion to ``counterexample`` happens only when both control tests are ``Success`` **and** the
target test is ``Failure``. Anything less is inconclusive.

First slice -- local deterministic fallback only
------------------------------------------------
This slice implements the CI-testable local path and no remote path. Facts are extracted only for
the **literal** cases, never a guess:

- **pause:** a pauser literally named ``pause`` (no-arg) or ``setPaused``/``setPause`` (single
  ``bool``), callable by the deployer, that reaches the paused state; the guarded sibling applies a
  locally-defined ``whenNotPaused``-style guard (verified by execution, not by name). ``unpause`` is
  recognized as a toggle but never selected as the state-reaching call -- it un-pauses, so the
  control probe would never confirm the paused state.
- **freshness:** a guarded sibling with an integer parameter literally named for a deadline/expiry
  (``_DEADLINE_HINTS``) that it checks; the control probe ``vm.warp``s forward and passes a past
  deadline.

The provider hook is accepted so a reasoning provider can be wired later, but this slice ignores it
and lets the local literal-case extractor decide. When facts cannot be extracted locally the gap is
returned unchanged (``promotion_state="hypothesis"`` + a reason), never an error.

Eligibility mirrors the access-control executor: a no-arg constructor, elementary arguments on both
the target and the guarded sibling, ``forge`` present, a source that does not reference the
cheatcode contract, and a standalone-compilable contract. The sandbox (``ffi=false``, scrubbed
environment, network denial, cheatcode-source refusal) is reused verbatim and never weakened.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from miesc.llm._solidity_text import _match_brace
from miesc.llm.agentic_contracts import MAX_AGENT_SOURCE_CHARS
from miesc.llm.revert_invariant_executor import (
    _HEVM_ADDRESS,
    _PROBE_TOML,
    _arg_type,
    _has_blocking_constructor,
    _network_sandbox,
    _pragma_prefix,
    _probe_env,
    _references_cheatcodes,
    _split_top_level,
    _target_contract,
    _zero_args,
)
from miesc.llm.revert_invariant_mining import (
    _DEADLINE_HINTS,
    GuardGapHypothesis,
    RevertInvariantOraclePlan,
    _collect_functions,
    _FuncSig,
    _strip_comments,
)

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime import weight
    from miesc.llm.agentic_contracts import ReasoningProvider

logger = logging.getLogger(__name__)

_PAUSE_PROBE = "RevertInvariantPauseProbe"
_FRESHNESS_PROBE = "RevertInvariantFreshnessProbe"
_REASONING_CATEGORIES = ("pause_toggle", "freshness_check")

# A past timestamp baseline: warp block.timestamp well above zero so a past deadline (the zero
# literal) is unambiguously behind it regardless of the comparison operator's direction.
_WARP_TARGET = "1000000"
# The past deadline handed to the guarded sibling in the control: strictly between zero and the
# warped ``block.timestamp`` so a plain non-zero validation cannot pass for a freshness check.
_PAST_DEADLINE = "1"

# Revert payload of a guard, read from its locally-defined body (comments already stripped, string
# literals intact): ``require(cond, "msg")`` -> ``Error(string)``; ``revert Custom();`` (no args) ->
# the custom error selector; a bare ``require(cond)`` / ``revert()`` -> empty revert data.
_REQUIRE_MSG_RE = re.compile(
    r'\brequire\s*\((?P<cond>[^;]*?),\s*"(?P<msg>(?:[^"\\]|\\.)*)"\s*\)\s*;'
)
_REQUIRE_BARE_RE = re.compile(r"\brequire\s*\((?P<cond>[^;\"]*)\)\s*;")
_CUSTOM_ERROR_RE = re.compile(r"\brevert\s+(?P<err>[A-Za-z_]\w*)\s*\(\s*\)\s*;")

# Elementary integer type (the only type for which ``type(T).max`` and a zero past-deadline both
# make sense). ``uint256[]`` / ``bytes32`` / ``address`` deliberately do not match.
_INT_TYPE_RE = re.compile(r"u?int(?:\d+)?$")


@dataclass
class _ReasoningFacts:
    """Bounded, deterministically-extracted facts the probe generator turns into Solidity.

    The LLM (or the local extractor) never writes probe Solidity; it only fills these fields, and
    the control probe verifies the proposed state before any target result is trusted.
    """

    category: str
    guarded_sibling: str
    guarded_zero_args: List[str]
    targets: Dict[str, List[str]]  # affected function -> its zero-argument literals
    # pause_toggle
    pauser: str = ""
    pauser_args: List[str] = field(default_factory=list)  # [] (no-arg) or ["true"] (single bool)
    # freshness_check
    guarded_deadline_index: int = -1
    guarded_deadline_type: str = ""
    # Solidity expression of the guard's revert data (``abi.encodeWithSignature("Error(string)",
    # "msg")``, ``abi.encodeWithSelector(Err.selector)`` or ``bytes("")``), or ``""`` when it could
    # not be read -- the control then degrades to a plain-revert check.
    guard_revert_expr: str = ""


# --------------------------------------------------------------------------------------
# Deterministic local fact extraction (literal cases only -- never a guess).
# --------------------------------------------------------------------------------------
def _find_pauser(functions: List["_FuncSig"]) -> Optional[Tuple[str, List[str]]]:
    """A deployer-callable function that reaches the *paused* state, by literal name.

    Preference order (deterministic): a no-arg ``pause()`` first, then a single-``bool``
    ``setPaused``/``setPause`` called with ``true``. ``unpause`` is intentionally not selectable --
    it un-pauses, so it can never reach the rejectable state the control probe must confirm.
    """
    no_arg: Dict[str, str] = {}
    bool_arg: Dict[str, str] = {}
    for sig in functions:
        if sig.visibility not in ("external", "public") or not sig.mutates:
            continue
        low = sig.name.lower()
        params = sig.params.strip()
        if low == "pause" and params == "":
            no_arg.setdefault(low, sig.name)
        elif low in ("setpaused", "setpause"):
            parts = _split_top_level(params)
            if len(parts) == 1 and _arg_type(parts[0]) == "bool":
                bool_arg.setdefault(low, sig.name)
    if "pause" in no_arg:
        return no_arg["pause"], []
    for key in ("setpaused", "setpause"):
        if key in bool_arg:
            return bool_arg[key], ["true"]
    return None


def _deadline_slot(sig: "_FuncSig") -> Tuple[Optional[int], str]:
    """``(index, type)`` of the first integer parameter literally named for a deadline/expiry.

    ``(None, "")`` when the function has no such parameter or it is not an elementary integer (the
    only type for which ``type(T).max`` and a zero past-deadline are both well defined).
    """
    for i, raw in enumerate(_split_top_level(sig.params)):
        toks = raw.split()
        if len(toks) < 2:
            continue
        ident = toks[-1]
        if any(hint in ident.lower() for hint in _DEADLINE_HINTS):
            t = (_arg_type(raw) or "").strip()
            if t and _INT_TYPE_RE.match(t):
                return i, t
    return None, ""


def _modifier_body(masked: str, name: str) -> Optional[str]:
    """Body text of a locally-defined modifier, or ``None`` (inherited / not found)."""
    m = re.search(r"\bmodifier\s+" + re.escape(name) + r"\b[^{;]*\{", masked)
    if not m:
        return None
    end = _match_brace(masked, m.end() - 1)
    return masked[m.end() : end]


def _qualified_error(masked: str, err: str) -> str:
    """``Contract.Err`` when the custom error is declared inside a contract (the probe lives
    outside it), ``Err`` when it is declared at file level."""
    decl = re.search(r"\berror\s+" + re.escape(err) + r"\s*\(", masked)
    first_type = re.search(
        r"\b(?:abstract\s+contract|contract|interface|library)\s+[A-Za-z_]\w*", masked
    )
    if decl and first_type and decl.start() > first_type.start():
        owner = _target_contract(masked)
        if owner:
            return f"{owner}.{err}"
    return err


def _revert_expr_in(body: str, must_mention: str = "", masked: str = "") -> Optional[str]:
    """Expected revert data (as a Solidity expression) of the first guard statement in ``body``
    whose condition mentions ``must_mention`` (any statement when empty)."""
    for m in _REQUIRE_MSG_RE.finditer(body):
        if must_mention and must_mention not in m.group("cond"):
            continue
        msg = m.group("msg")
        return f'abi.encodeWithSignature("Error(string)", "{msg}")'
    for m in _CUSTOM_ERROR_RE.finditer(body):
        prefix = body[: m.start()]
        if must_mention and must_mention not in prefix[-200:]:
            continue
        return f"abi.encodeWithSelector({_qualified_error(masked, m.group('err'))}.selector)"
    for m in _REQUIRE_BARE_RE.finditer(body):
        if must_mention and must_mention not in m.group("cond"):
            continue
        return 'bytes("")'
    return None


def _pause_guard_revert_expr(masked: str, guarded: "_FuncSig") -> str:
    """Revert data of the pause guard applied to ``guarded``: the locally-defined modifier whose
    body mentions the paused state, else the first modifier with a readable guard statement."""
    candidates = []
    for mod in guarded.modifiers:
        body = _modifier_body(masked, mod)
        if body is None:
            continue
        expr = _revert_expr_in(body, masked=masked)
        if expr is not None:
            candidates.append((("paus" in body.lower()), expr))
    for prefer_paused in (True, False):
        for flag, expr in candidates:
            if flag == prefer_paused:
                return expr
    return ""


def _freshness_guard_revert_expr(guarded: "_FuncSig", deadline_index: int, masked: str = "") -> str:
    """Revert data of the local deadline check in ``guarded`` (the statement naming the deadline
    parameter), or ``""`` when it is not a readable local statement."""
    parts = _split_top_level(guarded.params)
    toks = parts[deadline_index].split() if deadline_index < len(parts) else []
    param = toks[-1] if len(toks) >= 2 else ""
    if not param:
        return ""
    return _revert_expr_in(guarded.body, must_mention=param, masked=masked) or ""


def _extract_local_facts(
    gap: GuardGapHypothesis, by_name: Dict[str, "_FuncSig"], masked: str = ""
) -> Optional[_ReasoningFacts]:
    """Deterministic literal-case facts, or ``None`` (fail CLOSED -> gap unchanged)."""
    guarded = by_name.get(gap.guarded_example)
    if guarded is None:
        return None
    guarded_zero = _zero_args(guarded.params)
    if guarded_zero is None:
        return None  # the control probe calls the sibling: non-elementary args are ineligible

    targets: Dict[str, List[str]] = {}
    for fn in gap.affected_functions:
        sig = by_name.get(fn)
        if sig is None:
            continue
        zeros = _zero_args(sig.params)
        if zeros is None:
            continue  # non-elementary target args -> not executable here
        targets[fn] = zeros
    if not targets:
        return None

    if gap.category == "pause_toggle":
        pauser = _find_pauser(list(by_name.values()))
        if pauser is None:
            return None
        name, args = pauser
        return _ReasoningFacts(
            category=gap.category,
            guarded_sibling=gap.guarded_example,
            guarded_zero_args=guarded_zero,
            targets=targets,
            pauser=name,
            pauser_args=args,
            guard_revert_expr=_pause_guard_revert_expr(masked, guarded),
        )

    if gap.category == "freshness_check":
        idx, dtype = _deadline_slot(guarded)
        if idx is None:
            return None
        return _ReasoningFacts(
            category=gap.category,
            guarded_sibling=gap.guarded_example,
            guarded_zero_args=guarded_zero,
            targets=targets,
            guarded_deadline_index=idx,
            guarded_deadline_type=dtype,
            guard_revert_expr=_freshness_guard_revert_expr(guarded, idx, masked),
        )
    return None


def _extract_facts(
    gap: GuardGapHypothesis,
    by_name: Dict[str, "_FuncSig"],
    source_code: str,
    *,
    masked: str = "",
    provider: "Optional[ReasoningProvider]" = None,
    allow_remote: bool = False,
) -> Optional[_ReasoningFacts]:
    """Resolve probe facts for ``gap``.

    First slice: deterministic local extraction only. The ``provider`` / ``allow_remote`` hook is
    accepted so a bounded, parser-validated reasoning provider can be wired later; the remote path
    is intentionally not implemented yet, so any provider is ignored and the local literal-case
    extractor decides. Facts always fail CLOSED: when the literal case does not hold this returns
    ``None`` and the gap is left unchanged.

    Resolution order: the deterministic literal-case extractor first (cheapest, no tokens). Only
    when it cannot name the identity it needs (a non-literally-named pauser, a deadline parameter
    not named ``deadline``/``expir``) and a reasoning ``provider`` is supplied is the provider
    asked -- for that ONE identity, which is then validated against the parsed contract. The
    control+baseline probe downstream is the final gate, so a wrong provider answer fails CLOSED
    (the guarded sibling will not revert, or will revert without the state) and never promotes.
    """
    local = _extract_local_facts(gap, by_name, masked)
    if local is not None:
        return local
    if provider is None:
        return None
    remote = _extract_remote_facts(
        gap, by_name, source_code, provider=provider, allow_remote=allow_remote
    )
    if remote is None:
        return None
    # The provider only names an identity; the guard's revert payload is still read locally so the
    # control probe holds the remote path to the same standard as the local one.
    guarded = by_name.get(gap.guarded_example)
    if guarded is not None and not remote.guard_revert_expr:
        if remote.category == "pause_toggle":
            remote.guard_revert_expr = _pause_guard_revert_expr(masked, guarded)
        else:
            remote.guard_revert_expr = _freshness_guard_revert_expr(
                guarded, remote.guarded_deadline_index, masked
            )
    return remote


def _common_prefix(
    gap: GuardGapHypothesis, by_name: Dict[str, "_FuncSig"]
) -> Optional[Tuple["_FuncSig", List[str], Dict[str, List[str]]]]:
    """``(guarded_sibling_sig, its_zero_args, {target: zero_args})`` or ``None`` when the gap is
    structurally ineligible (missing/non-elementary guarded sibling, no elementary target)."""
    guarded = by_name.get(gap.guarded_example)
    if guarded is None:
        return None
    guarded_zero = _zero_args(guarded.params)
    if guarded_zero is None:
        return None
    targets: Dict[str, List[str]] = {}
    for fn in gap.affected_functions:
        sig = by_name.get(fn)
        if sig is None:
            continue
        zeros = _zero_args(sig.params)
        if zeros is None:
            continue
        targets[fn] = zeros
    if not targets:
        return None
    return guarded, guarded_zero, targets


def _remote_identity(
    objective: str,
    prompt: str,
    inputs: Dict[str, object],
    output_schema: Dict[str, object],
    provider: "ReasoningProvider",
    allow_remote: bool,
) -> Optional[Dict[str, object]]:
    """Ask the provider for one bounded identity fact; ``None`` on any failure (fail CLOSED)."""
    try:
        from miesc.llm.agentic_contracts import (
            AgentCapability,
            DPGAgentConfig,
            ReasoningTask,
        )

        task = ReasoningTask(
            capability=AgentCapability.COUNTEREXAMPLE_VALIDATION,
            objective=objective,
            prompt=prompt,
            inputs=inputs,
            output_schema=output_schema,
            policy=DPGAgentConfig(allow_remote=allow_remote),
        )
        result = provider.complete_json(task)
        data = getattr(result, "data", None)
        return data if isinstance(data, dict) else None
    except Exception as e:  # provider error, policy refusal, malformed output -> fail closed
        logger.debug("revert-invariant reasoning: provider identity call failed: %s", e)
        return None


def _extract_remote_facts(
    gap: GuardGapHypothesis,
    by_name: Dict[str, "_FuncSig"],
    source_code: str,
    *,
    provider: "ReasoningProvider",
    allow_remote: bool,
) -> Optional[_ReasoningFacts]:
    """Fill the one identity the local extractor could not, from the provider, then VALIDATE it
    against the parsed contract. Returns ``None`` (fail closed) on any invalid/missing answer."""
    prefix = _common_prefix(gap, by_name)
    if prefix is None:
        return None
    guarded, guarded_zero, targets = prefix

    if gap.category == "pause_toggle":
        data = _remote_identity(
            objective="Name the function that reaches the paused state.",
            prompt=(
                "A contract has a pause-gated sibling and an un-gated peer. Name the single "
                "external/public, state-changing function that SETS the paused state and is "
                "callable by the deployer (no arguments, or a single bool set to true). Reply as "
                'JSON {"pauser": "<functionName>"} and nothing else. If none exists, reply '
                '{"pauser": ""}.'
            ),
            inputs={
                "source": source_code[:MAX_AGENT_SOURCE_CHARS],
                "guarded_sibling": guarded.name,
            },
            output_schema={"pauser": "string (an external/public state-changing function name)"},
            provider=provider,
            allow_remote=allow_remote,
        )
        if not data:
            return None
        name = data.get("pauser")
        if not isinstance(name, str) or not name:
            return None
        sig = by_name.get(name)
        if sig is None or sig.visibility not in ("external", "public") or not sig.mutates:
            return None
        params = sig.params.strip()
        if params == "":
            pauser_args: List[str] = []
        else:
            parts = _split_top_level(params)
            if len(parts) != 1 or _arg_type(parts[0]) != "bool":
                return None
            pauser_args = ["true"]
        return _ReasoningFacts(
            category=gap.category,
            guarded_sibling=gap.guarded_example,
            guarded_zero_args=guarded_zero,
            targets=targets,
            pauser=name,
            pauser_args=pauser_args,
        )

    if gap.category == "freshness_check":
        plist = _split_top_level(guarded.params)
        data = _remote_identity(
            objective="Identify the deadline/expiry parameter of the guarded function.",
            prompt=(
                f"Function `{guarded.name}` has parameters (0-indexed): "
                f"{[p.strip() for p in plist]}. Which one is the transaction deadline/expiry "
                "checked against block.timestamp? Reply as JSON "
                '{"deadline_index": <int>} and nothing else. If none, reply {"deadline_index": -1}.'
            ),
            inputs={
                "source": source_code[:MAX_AGENT_SOURCE_CHARS],
                "guarded_sibling": guarded.name,
            },
            output_schema={"deadline_index": "integer, 0-based parameter position or -1"},
            provider=provider,
            allow_remote=allow_remote,
        )
        if not data:
            return None
        idx = data.get("deadline_index")
        if not isinstance(idx, int) or isinstance(idx, bool) or not (0 <= idx < len(params)):
            return None
        dtype = (_arg_type(params[idx]) or "").strip()
        if not dtype or not _INT_TYPE_RE.match(dtype):
            return None
        return _ReasoningFacts(
            category=gap.category,
            guarded_sibling=gap.guarded_example,
            guarded_zero_args=guarded_zero,
            targets=targets,
            guarded_deadline_index=idx,
            guarded_deadline_type=dtype,
        )
    return None


# --------------------------------------------------------------------------------------
# Deterministic probe generation (the facts layer never writes Solidity by hand).
# --------------------------------------------------------------------------------------
def _selector(contract: str, fn: str, args: List[str]) -> str:
    return ", ".join([f"{contract}.{fn}.selector", *args])


def _wrap_probe(source: str, contract: str, probe_name: str, body: str) -> str:
    """Inline the audited contract + a minimal ``Vm`` + the generated probe contract."""
    return (
        f"{_pragma_prefix(source)}{source}\n\n"
        f"interface Vm {{\n"
        f"    function record() external;\n"
        f"    function accesses(address) external returns (bytes32[] memory, bytes32[] memory);\n"
        f"    function warp(uint256) external;\n"
        f"}}\n\n"
        f"contract {probe_name} {{\n"
        f"    Vm constant vm = Vm({_HEVM_ADDRESS});\n"
        f"    {contract} target;\n"
        f"    function setUp() public {{ target = new {contract}(); }}\n\n"
        f"{body}}}\n"
    )


def _target_test(contract: str, fn: str, args: List[str], reach: str, label: str) -> str:
    """A target probe mirroring the executor: ``Failure`` iff the call succeeded AND wrote storage.

    Every pre-gate that merely fails to *reach* the state must ``return`` (inconclusive), never
    ``require`` -- a ``require`` tripping here would be read as a counterexample. The storage-write
    assertion is the only ``require`` that may fail.
    """
    sel = _selector(contract, fn, args)
    return (
        f"    function test_target_{fn}() public {{\n"
        f"{reach}"
        f"        vm.record();\n"
        f"        (bool ok, ) = address(target).call(abi.encodeWithSelector({sel}));\n"
        f"        (, bytes32[] memory writes) = vm.accesses(address(target));\n"
        f'        require(!(ok && writes.length > 0), "{label}");\n'
        f"    }}\n"
    )


def _state_assertions(facts: _ReasoningFacts, label: str) -> str:
    """The sibling must revert -- and, when the guard's payload is known, revert *with it*."""
    out = f'        require(!okS, "{label}");\n'
    if facts.guard_revert_expr:
        out += (
            f"        require(keccak256(ret) == keccak256({facts.guard_revert_expr}), "
            f'"control: guarded sibling reverted for a reason other than its guard");\n'
        )
    return out


def _build_pause_probe(source: str, contract: str, facts: _ReasoningFacts) -> str:
    pauser_sel = _selector(contract, facts.pauser, facts.pauser_args)
    guarded_sel = _selector(contract, facts.guarded_sibling, facts.guarded_zero_args)
    control = (
        f"    function test_control_baseline() public {{\n"
        f"        (bool okB, ) = address(target).call(abi.encodeWithSelector({guarded_sel}));\n"
        f'        require(okB, "control baseline: guarded sibling reverted in a fresh state");\n'
        f"    }}\n"
        f"    function test_control_state() public {{\n"
        f"        (bool reached, ) = address(target).call(abi.encodeWithSelector({pauser_sel}));\n"
        f'        require(reached, "control: the proposed pauser reverted");\n'
        f"        (bool okS, bytes memory ret) = address(target).call("
        f"abi.encodeWithSelector({guarded_sel}));\n"
        f"{_state_assertions(facts, 'control: guarded sibling did not revert when paused')}"
        f"    }}\n"
    )
    reach = (
        f"        (bool reached, ) = address(target).call("
        f"abi.encodeWithSelector({pauser_sel}));\n"
        f"        if (!reached) return;\n"
    )
    targets = "".join(
        _target_test(
            contract,
            fn,
            args,
            reach,
            "target succeeded and wrote storage while paused",
        )
        for fn, args in facts.targets.items()
    )
    return _wrap_probe(source, contract, _PAUSE_PROBE, control + "\n" + targets)


def _build_freshness_probe(source: str, contract: str, facts: _ReasoningFacts) -> str:
    future = list(facts.guarded_zero_args)
    future[facts.guarded_deadline_index] = f"type({facts.guarded_deadline_type}).max"
    guarded_future = _selector(contract, facts.guarded_sibling, future)
    # A nonzero deadline strictly before the warped timestamp: a mere ``require(deadline > 0)``
    # must not be able to pass for a freshness check.
    past = list(facts.guarded_zero_args)
    past[facts.guarded_deadline_index] = f"{facts.guarded_deadline_type}({_PAST_DEADLINE})"
    guarded_past = _selector(contract, facts.guarded_sibling, past)
    control = (
        f"    function test_control_baseline() public {{\n"
        f"        vm.warp({_WARP_TARGET});\n"
        f"        (bool okB, ) = address(target).call("
        f"abi.encodeWithSelector({guarded_future}));\n"
        f'        require(okB, "control baseline: guarded sibling reverted with a future deadline");\n'
        f"    }}\n"
        f"    function test_control_state() public {{\n"
        f"        vm.warp({_WARP_TARGET});\n"
        f"        (bool okS, bytes memory ret) = address(target).call("
        f"abi.encodeWithSelector({guarded_past}));\n"
        f"{_state_assertions(facts, 'control: guarded sibling did not revert with a past deadline')}"
        f"    }}\n"
    )
    reach = f"        vm.warp({_WARP_TARGET});\n"
    targets = "".join(
        _target_test(
            contract,
            fn,
            args,
            reach,
            "target succeeded and wrote storage past the deadline",
        )
        for fn, args in facts.targets.items()
    )
    return _wrap_probe(source, contract, _FRESHNESS_PROBE, control + "\n" + targets)


def _evidence(facts: _ReasoningFacts, fn: str) -> str:
    if facts.category == "pause_toggle":
        return (
            f"a Foundry probe called `{facts.pauser}` and the guarded sibling "
            f"`{facts.guarded_sibling}`, which succeeds in a fresh state, then reverted"
            f"{_with_guard(facts)}; in that state `{fn}` did not revert and wrote the contract's "
            f"storage -- no pause gate protects `{fn}`"
        )
    return (
        f"a Foundry probe advanced time: the guarded sibling `{facts.guarded_sibling}` accepted a "
        f"future deadline and reverted on a past one{_with_guard(facts)}; `{fn}` then did not "
        f"revert and wrote the contract's storage with a past deadline -- no freshness/deadline "
        f"check protects `{fn}`"
    )


def _with_guard(facts: _ReasoningFacts) -> str:
    return " with its guard's own revert data" if facts.guard_revert_expr else ""


# --------------------------------------------------------------------------------------
# Execution (mirrors revert_invariant_executor._run_probe; same sandbox, same JSON parse).
# --------------------------------------------------------------------------------------
def _run_reasoning_probe(
    forge: str,
    source_code: str,
    contract: str,
    facts: _ReasoningFacts,
    timeout: int,
) -> Dict[str, object]:
    """Compile+run the control/target probes under the hardened project/env/sandbox and decide.

    A counterexample is promoted only when both ``test_control_baseline`` and ``test_control_state``
    are ``Success`` (the proposed rejectable state is real, from fresh state each) AND a
    ``test_target_<fn>`` is ``Failure`` (the unguarded call succeeded and wrote storage in that
    state). A wrong fact makes a control test fail -> no promotion.
    """
    if facts.category == "pause_toggle":
        probe = _build_pause_probe(source_code, contract, facts)
        probe_name = _PAUSE_PROBE
    else:
        probe = _build_freshness_probe(source_code, contract, facts)
        probe_name = _FRESHNESS_PROBE

    sandbox = _network_sandbox()
    isolation: Dict[str, object] = {
        "ffi": False,
        "fs_permissions": [],
        "env": "scrubbed",
        "network": "denied" if sandbox else "unrestricted",
    }
    if not sandbox:
        logger.warning(
            "revert-invariant reasoning: no network sandbox available on this host; the audited "
            "contract runs with Foundry cheatcodes and unrestricted outbound network"
        )
    with tempfile.TemporaryDirectory(prefix="miesc_revinv_reason_") as tmp:
        root = Path(tmp)
        (root / "foundry.toml").write_text(_PROBE_TOML)
        test_dir = root / "test"
        test_dir.mkdir()
        (test_dir / f"{probe_name}.t.sol").write_text(probe)
        cmd = [
            *(sandbox or ()),
            forge,
            "test",
            "--json",
            "--match-contract",
            probe_name,
        ]
        try:
            proc = subprocess.run(
                cmd,
                cwd=root,
                env=_probe_env(),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return {
                "promotion_state": "hypothesis",
                "reason": "probe execution timed out",
                "isolation": isolation,
            }
        except Exception as e:  # never let execution break the audit
            return {
                "promotion_state": "hypothesis",
                "reason": f"probe execution error: {e}",
                "isolation": isolation,
            }

    try:
        report = json.loads(proc.stdout)
    except (ValueError, TypeError):
        return {
            "promotion_state": "hypothesis",
            "reason": "probe did not compile or run standalone",
            "isolation": isolation,
        }

    statuses: Dict[str, str] = {}
    if isinstance(report, dict):
        for suite in report.values():
            if isinstance(suite, dict):
                for name, res in suite.get("test_results", {}).items():
                    if isinstance(res, dict):
                        statuses[name.split("(")[0]] = res.get("status", "")
    if not statuses:
        return {
            "promotion_state": "hypothesis",
            "reason": "probe produced no test results",
            "isolation": isolation,
        }

    control = {
        "baseline": statuses.get("test_control_baseline", ""),
        "state": statuses.get("test_control_state", ""),
        "guard_revert_data": "matched" if facts.guard_revert_expr else "not_extractable",
    }
    if control["baseline"] != "Success" or control["state"] != "Success":
        return {
            "promotion_state": "hypothesis",
            "reason": (
                "control probe did not confirm the proposed rejectable state; the proposed facts "
                "are unverified and the gap is not promoted"
            ),
            "control": control,
            "isolation": isolation,
        }

    counterexamples = sorted(
        fn for fn in facts.targets if statuses.get(f"test_target_{fn}") == "Failure"
    )
    if counterexamples:
        return {
            "promotion_state": "counterexample",
            "counterexamples": counterexamples,
            "evidence": [_evidence(facts, fn) for fn in counterexamples],
            "control": control,
            "isolation": isolation,
        }
    return {
        "promotion_state": "hypothesis",
        "reason": (
            "control confirmed the state but no unguarded target both succeeded and wrote storage; "
            "not promoted"
        ),
        "control": control,
        "isolation": isolation,
    }


def execute_reasoning_gaps(
    plans: List[RevertInvariantOraclePlan],
    source_code: str,
    *,
    timeout: int = 120,
    provider: "Optional[ReasoningProvider]" = None,
    allow_remote: bool = False,
) -> List[Dict[str, object]]:
    """Execute the ``pause_toggle`` / ``freshness_check`` gaps in ``plans`` against ``source_code``.

    Returns one result per eligible gap (``id`` = ``<plan id>-<category>-<first affected
    function>``), mirroring :func:`execute_access_control_gaps`:
      - ``promotion_state="counterexample"`` + ``counterexamples=[fn, ...]`` + ``evidence`` +
        ``control`` (both control statuses and whether the guard's revert data was matched) +
        ``isolation`` when both probes agree (see module docstring);
      - ``promotion_state="hypothesis"`` (unchanged) with a ``reason`` otherwise -- ``forge``
        absent, cheatcode-referencing source, constructor arguments, facts not extractable locally,
        a probe that did not compile, or a control probe that did not confirm the state.

    The ``provider`` / ``allow_remote`` hook is accepted for a future remote path; this slice uses
    the deterministic local extractor only. Other categories (``access_control``) are ignored --
    they belong to the executor. Never raises.
    """
    results: List[Dict[str, object]] = []
    gaps = [
        (plan, gap)
        for plan in plans
        for gap in plan.gap_hypotheses
        if gap.category in _REASONING_CATEGORIES and gap.affected_functions
    ]
    if not gaps:
        return results

    forge = shutil.which("forge")
    masked = _strip_comments(source_code)
    contract = _target_contract(masked)
    functions = _collect_functions(masked)
    by_name = {f.name: f for f in functions}
    touches_cheatcodes = _references_cheatcodes(source_code)

    for plan, gap in gaps:
        pid = plan.id or "revert_invariant"
        base = {
            "id": f"{pid}-{gap.category}-{gap.affected_functions[0]}",
            "category": gap.category,
            "affected_functions": list(gap.affected_functions),
            "promotion_state": "hypothesis",
        }
        if forge is None:
            results.append({**base, "reason": "forge not available; not executed"})
            continue
        if touches_cheatcodes:
            results.append(
                {**base, "reason": "source references Foundry cheatcodes; refused to execute"}
            )
            continue
        if contract is None or _has_blocking_constructor(masked):
            results.append(
                {**base, "reason": "contract has constructor arguments or is not deployable here"}
            )
            continue
        facts = _extract_facts(
            gap, by_name, source_code, masked=masked, provider=provider, allow_remote=allow_remote
        )
        if facts is None:
            results.append(
                {
                    **base,
                    "reason": (
                        "could not extract probe facts for this gap (no literal match and no "
                        "reasoning provider supplied a validatable identity); gap left unchanged"
                    ),
                }
            )
            continue

        verdict = _run_reasoning_probe(forge, source_code, contract, facts, timeout)
        results.append({**base, **verdict})
    return results


__all__ = ["execute_reasoning_gaps"]
