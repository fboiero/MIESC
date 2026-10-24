"""Promote revert-invariant *counterexamples* into findings.

This is the last rung of the revert-invariant SDD and the only one that crosses into the finding
set. The discipline across the chain was never "never a Finding" -- it was "never an *unverified*
Finding". A ``counterexample`` from :mod:`miesc.llm.revert_invariant_executor` is the opposite of
unverified: Foundry executed an unauthorized call and it *succeeded*. That earned evidence is a
legitimate finding.

Emission is gated on ``promotion_state == "counterexample"`` exactly -- never ``hypothesis`` or
``test_generated``. The caller is expected to pass the resulting dicts through the same
false-positive / dedup controls as every other finding (this module does not bypass them).

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


def counterexample_findings(
    executions: List[Dict[str, Any]],
    source_code: str,
    contract_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Build finding dicts for access-control counterexamples only.

    ``executions`` is the output of ``execute_access_control_gaps``. Only entries whose
    ``promotion_state`` is exactly ``"counterexample"`` produce findings; everything else (an
    unpromoted hypothesis, a forge-absent result) yields nothing.
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
        evidence = list(ex.get("evidence", []))
        for fn in ex.get("counterexamples", []):
            findings.append(
                {
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
                    "location": {"file": file_name, "line": line_of.get(fn, 0)},
                    "source": "revert_invariant_executor",
                    "evidence": evidence,
                }
            )
    return findings


__all__ = ["counterexample_findings"]
