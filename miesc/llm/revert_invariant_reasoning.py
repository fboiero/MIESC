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

- **control probe** -- reach the proposed rejectable state, then call the *guarded sibling*
  (``gap.guarded_example``) and assert it reverts; a leading baseline call first asserts the sibling
  *succeeds* before the state is reached, so "it reverts" means "it reverts *because of the state*"
  rather than for an unrelated reason (the vacuous-pass the executor's own docstring warns about).
  The control test is ``Success`` only when the proposed state is real.
- **target probe** -- in the same state, call the unguarded affected function and reuse the
  executor's storage-write assertion: it ``Failure``s only when the call both *succeeded* and
  *wrote* the target's storage.

Promotion to ``counterexample`` happens only when the control test is ``Success`` **and** the
target test is ``Failure``. Either alone is inconclusive.

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


def _extract_local_facts(
    gap: GuardGapHypothesis, by_name: Dict[str, "_FuncSig"]
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
        )
    return None


def _extract_facts(
    gap: GuardGapHypothesis,
    by_name: Dict[str, "_FuncSig"],
    *,
    provider: "Optional[ReasoningProvider]" = None,
    allow_remote: bool = False,
) -> Optional[_ReasoningFacts]:
    """Resolve probe facts for ``gap``.

    First slice: deterministic local extraction only. The ``provider`` / ``allow_remote`` hook is
    accepted so a bounded, parser-validated reasoning provider can be wired later; the remote path
    is intentionally not implemented yet, so any provider is ignored and the local literal-case
    extractor decides. Facts always fail CLOSED: when the literal case does not hold this returns
    ``None`` and the gap is left unchanged.
    """
    del provider, allow_remote
    return _extract_local_facts(gap, by_name)


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


def _build_pause_probe(source: str, contract: str, facts: _ReasoningFacts) -> str:
    pauser_sel = _selector(contract, facts.pauser, facts.pauser_args)
    guarded_sel = _selector(contract, facts.guarded_sibling, facts.guarded_zero_args)
    control = (
        f"    function test_control() public {{\n"
        f"        (bool okBefore, ) = address(target).call(abi.encodeWithSelector({guarded_sel}));\n"
        f'        require(okBefore, "control baseline: guarded sibling reverted before pausing");\n'
        f"        (bool reached, ) = address(target).call(abi.encodeWithSelector({pauser_sel}));\n"
        f'        require(reached, "control: the proposed pauser reverted");\n'
        f"        (bool okAfter, ) = address(target).call(abi.encodeWithSelector({guarded_sel}));\n"
        f'        require(!okAfter, "control: guarded sibling did not revert when paused");\n'
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
    # The zero literal at the deadline slot is already a past deadline once time is warped forward.
    guarded_past = _selector(contract, facts.guarded_sibling, facts.guarded_zero_args)
    control = (
        f"    function test_control() public {{\n"
        f"        vm.warp({_WARP_TARGET});\n"
        f"        (bool okFuture, ) = address(target).call("
        f"abi.encodeWithSelector({guarded_future}));\n"
        f'        require(okFuture, "control baseline: guarded sibling reverted with a future deadline");\n'
        f"        (bool okPast, ) = address(target).call("
        f"abi.encodeWithSelector({guarded_past}));\n"
        f'        require(!okPast, "control: guarded sibling did not revert with a past deadline");\n'
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
            f"a Foundry probe reached the paused state via `{facts.pauser}` (the guarded sibling "
            f"`{facts.guarded_sibling}` reverted in that state), then called `{fn}`: the call did "
            f"not revert and wrote the contract's storage -- no pause gate protects `{fn}`"
        )
    return (
        f"a Foundry probe advanced time and passed a deadline already in the past (the guarded "
        f"sibling `{facts.guarded_sibling}` reverted on that past deadline), then called `{fn}`: "
        f"the call did not revert and wrote the contract's storage -- no freshness/deadline check "
        f"protects `{fn}`"
    )


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

    A counterexample is promoted only when ``test_control`` is ``Success`` (the proposed rejectable
    state is real) AND a ``test_target_<fn>`` is ``Failure`` (the unguarded call succeeded and wrote
    storage in that state). A wrong fact makes the control test fail -> no promotion.
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

    if statuses.get("test_control") != "Success":
        return {
            "promotion_state": "hypothesis",
            "reason": (
                "control probe did not confirm the proposed rejectable state; the proposed facts "
                "are unverified and the gap is not promoted"
            ),
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
            "isolation": isolation,
        }
    return {
        "promotion_state": "hypothesis",
        "reason": (
            "control confirmed the state but no unguarded target both succeeded and wrote storage; "
            "not promoted"
        ),
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
        facts = _extract_facts(gap, by_name, provider=provider, allow_remote=allow_remote)
        if facts is None:
            results.append(
                {
                    **base,
                    "reason": (
                        "could not extract probe facts for this gap locally; gap left unchanged "
                        "(no reasoning provider in this slice)"
                    ),
                }
            )
            continue

        verdict = _run_reasoning_probe(forge, source_code, contract, facts, timeout)
        results.append({**base, **verdict})
    return results


__all__ = ["execute_reasoning_gaps"]
