"""Promote revert-invariant *counterexamples* into findings.

This is the last rung of the revert-invariant SDD and the only one that crosses into the finding
set. The discipline across the chain was never "never a Finding" -- it was "never an *unverified*
Finding". A ``counterexample`` from :mod:`miesc.llm.revert_invariant_executor` (access control) or
:mod:`miesc.llm.revert_invariant_reasoning` (pause / freshness) is the opposite of unverified:
Foundry executed the call and it behaved as the gap predicted. That earned evidence is a legitimate
finding.

Emission is gated on ``promotion_state == "counterexample"`` exactly -- never ``hypothesis`` or
``test_generated``. The caller is expected to pass the resulting dicts through the same
false-positive / dedup controls as every other finding (this module does not bypass them).

Each finding's ``type`` is a canonical taxonomy key (see :mod:`miesc.core.finding_taxonomy`) chosen
so the finding *aggregates* with the right family and never mislabels pause as access control:
``access_control`` -> ACCESS_CONTROL, ``dos`` -> DENIAL_OF_SERVICE (pause gating is an availability
property), ``timestamp`` -> TIME_MANIPULATION (freshness/deadline). The direct taxonomy keys are
used on purpose -- the enum *values* ``denial_of_service`` / ``time_manipulation`` would fall
through the substring fallbacks and mis-normalize.

The finding dict matches the de-facto contract consumed by ``DeepAuditAgent`` -- ``title``,
``description``, ``severity``, ``confidence``, ``type``, ``location={file,line}``, ``source``,
``evidence`` -- not any single ``Finding`` dataclass (the codebase has several).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from miesc.llm.revert_invariant_mining import _collect_functions, _line_of, _strip_comments

# Verified by execution, but a reachable unguarded setter is not automatically high-impact
# (the mutated value may never be read), so confidence is high without being certain.
_CONFIDENCE = 0.85
_UNAUTHORIZED = "address(0xBEEF)"


def _access_control_finding(
    fn: str, file_name: str, line: int, evidence: List[str]
) -> Dict[str, Any]:
    return {
        "title": f"Missing access control on `{fn}`",
        "description": (
            f"A Foundry probe called `{fn}` from an unauthorized account "
            f"({_UNAUTHORIZED}) and the call succeeded, while sibling functions in the "
            f"same family are access-controlled. An unauthorized caller can invoke "
            f"`{fn}` and mutate contract state. Reproduced by execution, not inferred."
        ),
        "severity": "High",
        "confidence": _CONFIDENCE,
        "type": "access_control",
        "location": {"file": file_name, "line": line},
        "source": "revert_invariant_executor",
        "evidence": evidence,
    }


def _pause_toggle_finding(
    fn: str, file_name: str, line: int, evidence: List[str]
) -> Dict[str, Any]:
    return {
        "title": f"Missing pause gating on `{fn}`",
        "description": (
            f"A Foundry probe paused the contract and confirmed that a sibling function reverts "
            f"while paused, then called `{fn}` in the same paused state and the call succeeded and "
            f"mutated storage. `{fn}` is not pause-gated: it keeps executing when the protocol is "
            f"paused, so the pause switch cannot stop it. Reproduced by execution, not inferred."
        ),
        # Execution-reproduced: an unguarded state-mutating call that keeps running while the
        # protocol is paused defeats the emergency stop during an incident -- High, not Medium.
        "severity": "High",
        "confidence": _CONFIDENCE,
        "type": "dos",
        "location": {"file": file_name, "line": line},
        "source": "revert_invariant_reasoning",
        "evidence": evidence,
    }


def _freshness_finding(fn: str, file_name: str, line: int, evidence: List[str]) -> Dict[str, Any]:
    return {
        "title": f"Missing deadline/freshness check on `{fn}`",
        "description": (
            f"A Foundry probe confirmed that a sibling function reverts once its deadline is in the "
            f"past, then called `{fn}` with a deadline already in the past and the call succeeded "
            f"and mutated storage. `{fn}` accepts a deadline/expiry argument but never enforces it, "
            f"so a stale request still executes. Reproduced by execution, not inferred."
        ),
        # Execution-reproduced: a stale/expired request that still executes because the deadline
        # is accepted but never enforced enables replay of expired authorizations -- High.
        "severity": "High",
        "confidence": _CONFIDENCE,
        "type": "timestamp",
        "location": {"file": file_name, "line": line},
        "source": "revert_invariant_reasoning",
        "evidence": evidence,
    }


# category -> finding builder. ``access_control`` stays byte-identical to the original emission.
_BUILDERS = {
    "access_control": _access_control_finding,
    "pause_toggle": _pause_toggle_finding,
    "freshness_check": _freshness_finding,
}


def counterexample_findings(
    executions: List[Dict[str, Any]],
    source_code: str,
    contract_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Build finding dicts for revert-invariant counterexamples.

    ``executions`` is the output of ``execute_access_control_gaps`` and/or
    ``execute_reasoning_gaps``. Only entries whose ``promotion_state`` is exactly
    ``"counterexample"`` produce findings; everything else (an unpromoted hypothesis, a
    forge-absent result) yields nothing. Each entry is dispatched on its ``category`` (defaulting
    to ``access_control`` for back-compatibility) to the matching finding shape.
    """
    masked = _strip_comments(source_code)
    line_of: Dict[str, int] = {
        f.name: _line_of(source_code, f.decl_offset) for f in _collect_functions(masked)
    }
    file_name = contract_path or "<memory>"

    findings: List[Dict[str, Any]] = []
    for ex in executions:
        if ex.get("promotion_state") != "counterexample":
            continue
        builder = _BUILDERS.get(str(ex.get("category", "access_control")))
        if builder is None:
            continue
        evidence = list(ex.get("evidence", []))
        for fn in ex.get("counterexamples", []):
            findings.append(builder(fn, file_name, line_of.get(fn, 0), evidence))
    return findings


# Static/heuristic, not execution-reproduced: confidence is well below the verified _CONFIDENCE,
# and the severity is Medium (a lead to confirm), never High.
_STATIC_CONFIDENCE = 0.5


def _trust_boundary_finding(fn: str, file_name: str, line: int, gap: Any) -> Dict[str, Any]:
    """Build a Medium, advisory finding from a ``trust_boundary`` gap hypothesis.

    Unlike the counterexample builders this is **inferred, not reproduced by execution**: the
    description says so and the ``negative_checks`` ride along as evidence so a reader confirms the
    lead rather than trusting it.
    """
    negative_checks = list(getattr(gap, "negative_checks", []))
    return {
        "title": f"Unvalidated recipient forwarded across trust boundary in `{fn}`",
        "description": (
            f"{getattr(gap, 'expected_guard', '')}. A recipient/destination value is forwarded "
            f"into an external call while its sibling fields are validated, so an unchecked "
            f"recipient can redirect value or control to an attacker-chosen address. "
            f"Static/heuristic -- inferred from the guard pattern, NOT reproduced by execution; "
            f"confirm against the callee and any base-contract or modifier guards."
        ),
        "severity": "Medium",
        "confidence": _STATIC_CONFIDENCE,
        "type": "access_control",
        "location": {"file": file_name, "line": line},
        "source": "revert_invariant_mining",
        "evidence": [getattr(gap, "expected_guard", ""), *negative_checks],
    }


def trust_boundary_findings(
    plans: List[Any],
    source_code: str,
    contract_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Promote ``trust_boundary`` gap hypotheses to Medium, advisory findings.

    ``plans`` are the :class:`RevertInvariantOraclePlan` objects from ``mine_revert_invariants``.
    Only ``category == "trust_boundary"`` hypotheses are emitted; the rest stay advisory metadata.
    Deterministic, LLM-free, and forge-free -- unlike :func:`counterexample_findings` this makes no
    execution claim, so each finding is Medium and clearly marked inferred.
    """
    masked = _strip_comments(source_code)
    line_of: Dict[str, int] = {
        f.name: _line_of(source_code, f.decl_offset) for f in _collect_functions(masked)
    }
    file_name = contract_path or "<memory>"

    findings: List[Dict[str, Any]] = []
    for plan in plans:
        for gap in getattr(plan, "gap_hypotheses", []):
            if getattr(gap, "category", "") != "trust_boundary":
                continue
            affected = getattr(gap, "affected_functions", [])
            fn = affected[0] if affected else "?"
            findings.append(_trust_boundary_finding(fn, file_name, line_of.get(fn, 0), gap))
    return findings


__all__ = ["counterexample_findings", "trust_boundary_findings"]
