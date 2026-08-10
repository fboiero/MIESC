"""Turn a structured formal counterexample into a Foundry test scaffold.

Phase 2 of counterexample→PoC. Phase 1 parsed a prover's counterexample into
``name = value`` assignments on :class:`~miesc.formal.unified_report.Counterexample`;
this lays those concrete values into a Foundry test that reproduces the property
violation, inferring each input's Solidity type from the prover's variable naming.

The output is a **scaffold**, not a guaranteed-compiling exploit: it plugs in the
exact counterexample inputs and marks the deploy/call/assert for the developer to
finish. That is still a large step up from an opaque counterexample string — the
concrete inputs are already typed and in place.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Dict, List, Tuple

if TYPE_CHECKING:
    from miesc.formal.unified_report import Counterexample

# Solidity value types Halmos/Kontrol encode as a suffix on the variable name
# (e.g. ``p_amount_uint256``, ``halmos_to_address_01``).
_SOL_TYPE = re.compile(r"^(uint\d*|int\d*|address|bool|bytes\d+|bytes|string)$")
_DEFAULT_TYPE = "uint256"


def _infer_type_and_name(raw_name: str) -> Tuple[str, str]:
    """Infer ``(solidity_type, clean_name)`` from a prover variable name.

    Handles the Halmos/Kontrol conventions ``p_<name>_<type>`` and
    ``halmos_<name>_<type>_<id>``; falls back to ``uint256`` and the raw name.
    """
    name = raw_name
    for prefix in ("halmos_", "p_", "kontrol_"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break

    parts = [p for p in name.split("_") if p]
    sol_type = _DEFAULT_TYPE
    type_idx = None
    for i, part in enumerate(parts):
        if _SOL_TYPE.match(part):
            sol_type = "uint256" if part == "uint" else "int256" if part == "int" else part
            type_idx = i

    if type_idx is not None:
        clean_parts = parts[:type_idx]
    else:
        # drop a trailing pure-digit id segment (halmos) if present
        clean_parts = parts[:-1] if len(parts) > 1 and parts[-1].isdigit() else parts

    clean = "_".join(clean_parts).strip("_")
    return sol_type, clean or "input"


def _format_value(value: str, sol_type: str) -> str:
    """Render a counterexample value as a Solidity literal for ``sol_type``."""
    v = value.strip()
    if sol_type == "bool":
        return "false" if v in ("0", "false", "False", "") else "true"
    if sol_type == "address":
        if v.startswith("0x"):
            return f"address({v})"
        return f"address(uint160({v}))"
    if sol_type.startswith("bytes") and not v.startswith("0x"):
        # a decimal for a bytes slot is unusual; keep it visible for the dev
        return v
    return v


def _identifier(cx: "Counterexample", contract_name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9]", "", contract_name) or "Target"
    return base[:1].upper() + base[1:]


def counterexample_to_foundry_test(
    cx: "Counterexample",
    contract_name: str = "Target",
    test_name: str = "test_reproduce_counterexample",
) -> str:
    """Generate a Foundry test scaffold that reproduces ``cx``.

    Each parsed assignment becomes a typed local with the counterexample's exact
    value; the deploy/call/assert are left as clearly-marked TODOs. Falls back to a
    commented raw-witness block when the counterexample has no parsed assignments.
    """
    name = _identifier(cx, contract_name)
    prop = cx.property or "the verified property"

    lines: List[str] = []
    if cx.assignments:
        seen: Dict[str, int] = {}
        for a in cx.assignments:
            raw = str(a.get("name", "")) or "input"
            sol_type, clean = _infer_type_and_name(raw)
            # avoid duplicate identifiers
            ident = clean
            if ident in seen:
                seen[ident] += 1
                ident = f"{clean}_{seen[ident]}"
            else:
                seen[ident] = 0
            value = _format_value(str(a.get("value", "0")), sol_type)
            lines.append(f"        {sol_type} {ident} = {value}; // {raw}")
    else:
        for raw_line in (cx.text or "").splitlines() or [cx.text or ""]:
            if raw_line.strip():
                lines.append(f"        // witness: {raw_line.strip()}")

    inputs_block = "\n".join(lines) if lines else "        // (no parsed inputs)"

    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// Auto-generated PoC scaffold from a {cx.prover} counterexample.
// Property under test: {prop}
// This is a starting point: deploy the target, call the function under test with
// the counterexample inputs below, and assert the violated property.
contract {name}CounterexamplePoC is Test {{
    function {test_name}() public {{
        // Counterexample inputs (prover witness):
{inputs_block}

        // TODO: deploy the contract under test and reproduce the violation, e.g.
        //   {name} target = new {name}();
        //   target.functionUnderTest(/* inputs above */);
        //   assertTrue(/* {prop} holds */, "{prop} violated by the counterexample");
    }}
}}
"""
