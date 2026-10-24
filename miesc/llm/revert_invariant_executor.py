"""Execute access-control gap hypotheses and promote only on a real counterexample.

This is the one deterministic execution slice of the revert-invariant SDD. A
:class:`GuardGapHypothesis` of category ``access_control`` says a sibling external/public
state-changing function is not access-controlled. That is the only category whose *rejectable
state* can be reached with **zero contract knowledge**: an unauthorized caller is just
``vm.prank(address(0xBEEF))``. (``freshness_check`` would need the deadline parameter's position,
which the hypothesis does not carry; ``pause_toggle`` would need the pauser, which is never
knowable here -- both stay at the ``test_generated`` rung produced by
:mod:`miesc.llm.revert_invariant_harness`.)

The probe inverts the naive test on purpose. ``vm.expectRevert()`` would pass whenever the call
reverts *for any reason* (a zero-argument ``require``, an overflow), which is a vacuous pass. So
the probe instead performs the unauthorized call low-level and asserts it did **not** succeed:

- the unauthorized call **succeeds** -> the Foundry test fails -> ``counterexample`` (unambiguous:
  an unauthorized account mutated state);
- the unauthorized call **reverts** -> the test passes -> ``inconclusive``: the hypothesis stays
  ``hypothesis`` (it reverted, but the reason is unverified -- we never claim the guard exists,
  and we never downgrade to ``rejected`` here).

Only ``counterexample`` is ever produced; nothing is ever promoted to ``rejected``. When ``forge``
is absent, a gap is ineligible (constructor args, non-elementary parameters, non-standalone
source), or the probe fails to compile, the gap is returned unchanged -- never an error.
Promoting a counterexample into the finding set is a separate, later bridge with its own review;
this module only annotates the plan/hypothesis.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from miesc.llm.revert_invariant_mining import (
    GuardGapHypothesis,
    RevertInvariantOraclePlan,
    _collect_functions,
    _strip_comments,
)

_HEVM_ADDRESS = "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D"
_UNAUTHORIZED = "address(0xBEEF)"

_INT_WIDTHS = "8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256"


def _zero_for(sol_type: str) -> Optional[str]:
    """Return a zero literal for an elementary type, or ``None`` if not safely constructible.

    Dynamic/compound types (``string``, ``bytes``, arrays, structs, mappings) and user types
    return ``None`` -- the gap is left for the ``test_generated`` harness rather than guessing.
    """
    t = sol_type.strip()
    if t in ("uint", "int"):
        return f"{t}(0)"
    if re.fullmatch(rf"u?int({_INT_WIDTHS})", t):
        return f"{t}(0)"
    if t == "address":
        return "address(0)"
    if t == "bool":
        return "false"
    if re.fullmatch(r"bytes(1|2|3|4|8|16|32)", t):
        return f"{t}(0)"
    return None


def _arg_type(param: str) -> Optional[str]:
    """Extract the leading type token from one parameter declaration (``uint256 x`` -> uint256)."""
    param = param.strip()
    if not param:
        return None
    return param.split()[0]


def _zero_args(params_text: str) -> Optional[List[str]]:
    """Zero literals for every parameter, or ``None`` if any is not elementary."""
    params_text = params_text.strip()
    if not params_text:
        return []
    zeros: List[str] = []
    for raw in _split_top_level(params_text):
        t = _arg_type(raw)
        if t is None:
            return None
        zero = _zero_for(t)
        if zero is None:
            return None
        zeros.append(zero)
    return zeros


def _split_top_level(text: str) -> List[str]:
    """Split a parameter list on top-level commas (respecting parens/brackets)."""
    out: List[str] = []
    depth = 0
    cur = ""
    for ch in text:
        if ch in "([<":
            depth += 1
        elif ch in ")]>":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def _target_contract(masked: str) -> Optional[str]:
    """The last concrete (non-abstract/interface/library) contract declared in the source."""
    name = None
    for m in re.finditer(
        r"\b(abstract\s+contract|contract|interface|library)\s+([A-Za-z_]\w*)", masked
    ):
        if m.group(1) == "contract":
            name = m.group(2)
    return name


def _has_blocking_constructor(masked: str) -> bool:
    """True when a constructor takes at least one argument (cannot ``new Contract()``)."""
    m = re.search(r"\bconstructor\s*\(([^)]*)\)", masked)
    return bool(m and m.group(1).strip())


def _pragma_prefix(source: str) -> str:
    return "" if "pragma solidity" in source else "pragma solidity >=0.7.0;\n"


def _build_probe(source: str, contract: str, fn_args: Dict[str, List[str]]) -> str:
    """A self-contained Foundry test: the inlined contract + a minimal Vm + one probe per fn."""
    probes = []
    for fn, zeros in fn_args.items():
        sel_args = ", ".join([f"{contract}.{fn}.selector", *zeros])
        probes.append(
            f"    function test_unauthorized_{fn}() public {{\n"
            f"        vm.prank({_UNAUTHORIZED});\n"
            f"        (bool ok, ) = address(target).call(abi.encodeWithSelector({sel_args}));\n"
            f'        require(!ok, "unauthorized call succeeded");\n'
            f"    }}\n"
        )
    return (
        f"{_pragma_prefix(source)}{source}\n\n"
        f"interface Vm {{ function prank(address) external; }}\n\n"
        f"contract RevertInvariantACProbe {{\n"
        f"    Vm constant vm = Vm({_HEVM_ADDRESS});\n"
        f"    {contract} target;\n"
        f"    function setUp() public {{ target = new {contract}(); }}\n\n"
        f"{''.join(probes)}}}\n"
    )


def _eligible_functions(gap: GuardGapHypothesis, functions: list) -> Dict[str, List[str]]:
    """Map each affected function that is executable (elementary args) to its zero-arg literals."""
    by_name = {f.name: f for f in functions}
    out: Dict[str, List[str]] = {}
    for fn in gap.affected_functions:
        sig = by_name.get(fn)
        if sig is None:
            continue
        zeros = _zero_args(sig.params)
        if zeros is None:
            continue  # non-elementary parameter -> not executable here
        out[fn] = zeros
    return out


def execute_access_control_gaps(
    plans: List[RevertInvariantOraclePlan],
    source_code: str,
    *,
    timeout: int = 120,
) -> List[Dict[str, object]]:
    """Execute the access-control gaps in ``plans`` against ``source_code`` with Foundry.

    Returns one result per access-control gap:
      - ``promotion_state="counterexample"`` + ``counterexamples=[fn, ...]`` when an unauthorized
        call to an affected function succeeded;
      - ``promotion_state="hypothesis"`` (unchanged) otherwise, with a ``reason``.
    Other categories are ignored (left to the ``test_generated`` harness). Never raises.
    """
    results: List[Dict[str, object]] = []
    ac_gaps = [
        (plan, gap)
        for plan in plans
        for gap in plan.gap_hypotheses
        if gap.category == "access_control" and gap.affected_functions
    ]
    if not ac_gaps:
        return results

    forge = shutil.which("forge")
    masked = _strip_comments(source_code)
    contract = _target_contract(masked)
    functions = _collect_functions(masked)

    for plan, gap in ac_gaps:
        pid = plan.id or "revert_invariant"
        base = {
            "id": f"{pid}-access_control",
            "category": "access_control",
            "affected_functions": list(gap.affected_functions),
            "promotion_state": "hypothesis",
        }
        if forge is None:
            results.append({**base, "reason": "forge not available; not executed"})
            continue
        if contract is None or _has_blocking_constructor(masked):
            results.append(
                {**base, "reason": "contract has constructor arguments or is not deployable here"}
            )
            continue
        fn_args = _eligible_functions(gap, functions)
        if not fn_args:
            results.append({**base, "reason": "no affected function with elementary arguments"})
            continue

        verdict = _run_probe(forge, source_code, contract, fn_args, timeout)
        results.append({**base, **verdict})
    return results


def _run_probe(
    forge: str,
    source_code: str,
    contract: str,
    fn_args: Dict[str, List[str]],
    timeout: int,
) -> Dict[str, object]:
    """Compile and run the probe with ``forge test --json``; map the result to a promotion
    decision. We parse forge's own JSON (``status`` per test) directly: the counterexample signal
    must be read from the authoritative field, not re-derived."""
    import json
    import subprocess

    probe = _build_probe(source_code, contract, fn_args)
    with tempfile.TemporaryDirectory(prefix="miesc_revinv_exec_") as tmp:
        root = Path(tmp)
        (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\ntest = "test"\n')
        test_dir = root / "test"
        test_dir.mkdir()
        (test_dir / "RevertInvariantACProbe.t.sol").write_text(probe)
        try:
            proc = subprocess.run(
                [forge, "test", "--json", "--match-contract", "RevertInvariantACProbe"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return {"promotion_state": "hypothesis", "reason": "probe execution timed out"}
        except Exception as e:  # never let execution break the audit
            return {"promotion_state": "hypothesis", "reason": f"probe execution error: {e}"}

    try:
        report = json.loads(proc.stdout)
    except (ValueError, TypeError):
        # non-JSON stdout -> did not compile / did not run -> inconclusive, never a counterexample
        return {
            "promotion_state": "hypothesis",
            "reason": "probe did not compile or run standalone",
        }

    # forge --json: {"<suite id>": {"test_results": {"<name>()": {"status": "Success|Failure"}}}}
    statuses: Dict[str, str] = {}
    for suite in report.values():
        if isinstance(suite, dict):
            for name, res in suite.get("test_results", {}).items():
                if isinstance(res, dict):
                    statuses[name.split("(")[0]] = res.get("status", "")
    if not statuses:
        return {"promotion_state": "hypothesis", "reason": "probe produced no test results"}

    # A FAILED probe test means `require(!ok)` tripped: the unauthorized call succeeded.
    counterexamples = [
        name.replace("test_unauthorized_", "")
        for name, status in statuses.items()
        if status == "Failure" and name.startswith("test_unauthorized_")
    ]
    if counterexamples:
        return {
            "promotion_state": "counterexample",
            "counterexamples": sorted(set(counterexamples)),
            "evidence": [
                f"an unauthorized caller ({_UNAUTHORIZED}) successfully called "
                f"`{fn}` -- the access-control guard is absent"
                for fn in sorted(set(counterexamples))
            ],
        }
    return {
        "promotion_state": "hypothesis",
        "reason": "every unauthorized probe reverted (reason unverified); not promoted",
    }


__all__ = ["execute_access_control_gaps"]
