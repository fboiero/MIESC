"""Advisory bridge: revert-invariant gap hypotheses -> sequence-aware oracle plans.

The deterministic revert-invariant miner (:mod:`miesc.llm.revert_invariant_mining`) produces
advisory :class:`GuardGapHypothesis` records -- "these sibling functions enforce a guard
inconsistently". This bridge turns each hypothesis into a provider-neutral
:class:`~miesc.llm.agentic_contracts.SequenceOraclePlan`: a fuzzing/oracle obligation the rest
of MIESC already understands and that round-trips through ``parse_sequence_oracle_plans``.

It is advisory -> advisory. It never synthesizes executable Solidity and never emits a
``Finding``; the bridged plan carries low, fixed confidence and keeps the hypothesis'
``negative_checks`` in its evidence so the benign explanations travel with the obligation.

Bridging into :class:`~miesc.ml.invariant_validator.InvariantValidator` (executable Foundry /
Solidity assertions, promotion to ``counterexample``) is deliberately *not* done here: the
validator only runs invariants that already carry a ``solidity_assertion`` or ``foundry_test``,
and turning a prose guard into runnable code belongs to the reasoning-agent step of the SDD.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from miesc.llm.agentic_contracts import SequenceOraclePlan, SequenceStep
from miesc.llm.revert_invariant_mining import GuardGapHypothesis, RevertInvariantOraclePlan

# Low and fixed: a bridged plan is a hypothesis with no execution evidence, so its confidence
# is never a function of anything the miner observed.
_BRIDGE_CONFIDENCE = 0.2
_RECOMMENDED_TOOLS = ["foundry", "echidna"]

# gap category -> (vulnerability_types, the property a fuzzer should try to violate).
_ORACLE_BY_CATEGORY: Dict[str, Tuple[List[str], str]] = {
    "access_control": (
        ["access-control", "missing-authorization"],
        "A call from an account without the expected authorization must revert.",
    ),
    "pause_toggle": (
        ["pause-bypass", "denial-of-service"],
        "A call made while the contract is paused must revert.",
    ),
    "freshness_check": (
        ["stale-transaction", "missing-deadline-check"],
        "A call made after the deadline/expiry parameter has passed must revert.",
    ),
}
_DEFAULT_ORACLE: Tuple[List[str], str] = (
    ["inconsistent-guard"],
    "A call that violates the guard observed on this function's guarded siblings must revert.",
)


def _probe_step(function: str, expected_guard: str) -> SequenceStep:
    """One independent probe: call ``function`` in a state the expected guard should reject."""
    return SequenceStep(
        function=function,
        precondition=f"reach a state that `{expected_guard}` should reject, then call `{function}`",
        expected_effect="the call must revert",
    )


def bridge_gap_to_oracle_plan(gap: GuardGapHypothesis, parent_id: str) -> SequenceOraclePlan:
    """Convert a single :class:`GuardGapHypothesis` into an advisory
    :class:`SequenceOraclePlan`. One probe step per affected function (bounded downstream by
    ``MAX_AGENT_ITEMS``)."""
    vuln_types, oracle = _ORACLE_BY_CATEGORY.get(gap.category, _DEFAULT_ORACLE)
    functions = list(gap.affected_functions)
    steps = [_probe_step(fn, gap.expected_guard) for fn in functions]
    named = ", ".join(f"`{f}`" for f in functions) or "the affected function(s)"
    first = functions[0] if functions else gap.category
    return SequenceOraclePlan(
        id=f"{parent_id}-{gap.category}-{first}",
        objective=(
            f"Probe whether {named} enforce `{gap.category}` consistently with their guarded "
            f"siblings (observed gap: {gap.observed_gap})."
        ),
        invariant_id=f"{parent_id}-{gap.category}",
        vulnerability_types=list(vuln_types),
        sequence=steps,
        oracle=oracle,
        recommended_tools=list(_RECOMMENDED_TOOLS),
        confidence=_BRIDGE_CONFIDENCE,
        # The expected guard, the preconditions, and -- crucially -- the hypothesis' own
        # negative checks, so a reviewer reading only the fuzz plan still sees why the gap may
        # be benign (inherited guard, intentional exemption, enforced upstream, ...).
        evidence=[
            f"expected guard: {gap.expected_guard}",
            *gap.semantic_preconditions,
            *gap.negative_checks,
        ],
        metadata={
            "capability": "revert_invariant_mining",
            "bridge": "gap_hypothesis_to_sequence_oracle",
            "source_gap_category": gap.category,
            "advisory": "true",
        },
    )


def bridge_revert_invariant_plans(
    plans: List[RevertInvariantOraclePlan],
) -> List[SequenceOraclePlan]:
    """Bridge every gap hypothesis in ``plans`` into advisory sequence-oracle plans.

    Deterministic and advisory-only: silent exactly where the miner is silent (no gap
    hypotheses -> no oracle plans), so it adds no precision risk and emits no ``Finding``.
    """
    out: List[SequenceOraclePlan] = []
    for plan in plans:
        parent_id = plan.id or "revert_invariant"
        for gap in plan.gap_hypotheses:
            if not gap.affected_functions:
                continue  # no probe target -> parser would drop it anyway
            out.append(bridge_gap_to_oracle_plan(gap, parent_id))
    return out


__all__ = ["bridge_gap_to_oracle_plan", "bridge_revert_invariant_plans"]
