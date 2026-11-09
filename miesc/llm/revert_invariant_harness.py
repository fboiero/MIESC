"""Revert-guard probe harnesses: the ``test_generated`` rung for gap hypotheses.

This is the honest next step toward :class:`~miesc.ml.invariant_validator.InvariantValidator`.
A :class:`GuardGapHypothesis` is a *negative* property ("calling ``f`` in a state the guard
should reject must revert"). The validator, however, runs *positive* ``invariant_… view``
assertions and deploys the target with a no-argument constructor -- neither fits a revert probe,
and the contract-specific setup (constructor args, call args, who may pause) cannot be
synthesized deterministically. Generating and *running* such a test would manufacture
non-compiling tests or false counterexamples -- exactly what the advisory discipline forbids.

So this module stops one rung short of execution: it emits a Foundry ``vm.expectRevert`` probe
**harness** per gap and advances that artifact to ``promotion.state = "test_generated"`` (SDD:
"a property or fuzz harness exists but has no failing execution"). The harness is incomplete *by
design* -- every contract-specific step is an explicit ``TODO`` recorded in ``blockers`` -- and it
is returned as an artifact, never as a runnable ``foundry_test`` fed back into the validator, so
nothing is executed and no counterexample is ever claimed here. Only the category-generic,
un-fakeable fragments are generated (an unauthorized ``vm.prank`` for access control, a
``vm.warp`` past the deadline for freshness); the hard parts (reaching the paused state, the call
arguments) are left as TODOs rather than guessed.

Actually executing these harnesses and promoting to ``counterexample`` belongs to the
reasoning-agent / fork-replay step of the SDD.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from miesc.llm.revert_invariant_mining import GuardGapHypothesis, RevertInvariantOraclePlan

# category -> (generatable setup line for the rejectable state, extra blocker if that setup
# cannot be generated here). ``None`` blocker means the setup line is complete on its own.
_SETUP_BY_CATEGORY: Dict[str, Tuple[str, str]] = {
    "access_control": (
        "vm.prank(address(0xBEEF)); // an account without the expected authorization",
        "",
    ),
    "freshness_check": (
        "vm.warp(block.timestamp + 36500 days); // move past any deadline/expiry",
        "",
    ),
    "pause_toggle": (
        "// TODO: reach the paused state by calling the authorized pauser"
        " (its function name and caller are contract-specific)",
        "reach the paused state via the authorized pauser",
    ),
}
_DEFAULT_SETUP: Tuple[str, str] = (
    "// TODO: establish the state the guard should reject",
    "establish the state the guard should reject",
)

_HARNESS_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
// TODO: import the contract under test
// import "<path/to/Contract.sol>";

/// @notice Revert-guard probe harness (MIESC revert-invariant, promotion: test_generated).
/// @dev Category: {category}. Property: {oracle}
/// INCOMPLETE BY DESIGN -- complete every TODO before running. This file is advisory and is
/// never auto-executed; a passing run means nothing until the TODOs are filled in.
contract {name} is Test {{
    // TODO: declare the contract under test, e.g. `Contract target;`

    function setUp() public {{
        // TODO: deploy the target with its contract-specific constructor arguments
        // target = new Contract(/* ... */);
    }}
{probes}}}
"""

_PROBE_TEMPLATE = """
    /// @notice `{fn}` must revert when the {category} guard would reject the call.
    function test_revertGuard_{fn}() public {{
        {setup}
        vm.expectRevert();
        // TODO: call `{fn}` with arguments the guard should reject
        // target.{fn}(/* ... */);
    }}
"""


def _sanitize(name: str) -> str:
    return "".join(c if c.isalnum() or c == "_" else "_" for c in name) or "fn"


def harness_for_gap(gap: GuardGapHypothesis, parent_id: str, oracle: str = "") -> Dict[str, object]:
    """Build one ``test_generated`` harness artifact for a single gap hypothesis.

    Deterministic and execution-free: the returned dict carries the Foundry source, the
    ``blockers`` (every contract-specific TODO), and ``promotion_state="test_generated"``. It is
    never a runnable ``foundry_test`` -- the validator gate must not pick it up.
    """
    functions = list(gap.affected_functions)
    setup_line, setup_blocker = _SETUP_BY_CATEGORY.get(gap.category, _DEFAULT_SETUP)

    probes = "".join(
        _PROBE_TEMPLATE.format(fn=_sanitize(fn), category=gap.category, setup=setup_line)
        for fn in functions
    )
    first = _sanitize(functions[0]) if functions else gap.category
    contract_name = f"{_sanitize(parent_id)}_{gap.category}_{first}_RevertGuardProbe"
    source = _HARNESS_TEMPLATE.format(
        category=gap.category,
        oracle=oracle or f"inconsistent {gap.category} guard across sibling functions",
        name=contract_name,
        probes=probes,
    )

    blockers: List[str] = [
        "deploy the contract under test with its contract-specific constructor arguments",
        *([setup_blocker] if setup_blocker else []),
        *[f"construct arguments for `{fn}` that the guard should reject" for fn in functions],
    ]
    return {
        "id": f"{parent_id}-{gap.category}-{first}-harness",
        "category": gap.category,
        "affected_functions": functions,
        "promotion_state": "test_generated",
        "foundry_harness": source,
        "blockers": blockers,
        "note": (
            "advisory: incomplete by design and never auto-executed; complete the TODO blockers "
            "before running. Promotion to counterexample requires an actual failing execution."
        ),
    }


def generate_revert_guard_harnesses(
    plans: List[RevertInvariantOraclePlan],
) -> List[Dict[str, object]]:
    """Generate a ``test_generated`` harness artifact for every gap hypothesis in ``plans``.

    Deterministic and advisory: silent exactly where the miner is silent (no gap hypotheses ->
    no harnesses), and nothing is executed, so it adds no precision risk and emits no
    ``Finding`` or counterexample.
    """
    out: List[Dict[str, object]] = []
    for plan in plans:
        parent_id = plan.id or "revert_invariant"
        for gap in plan.gap_hypotheses:
            if not gap.affected_functions:
                continue
            out.append(harness_for_gap(gap, parent_id))
    return out


__all__ = ["generate_revert_guard_harnesses", "harness_for_gap"]
