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
the probe performs the unauthorized call low-level, records storage accesses around it, and asserts
that the call did **not** both succeed *and* write the contract's storage:

- the unauthorized call **succeeds and writes storage** -> the Foundry test fails ->
  ``counterexample`` (unambiguous: an unauthorized account mutated state);
- the unauthorized call **reverts**, or succeeds without touching storage (an early-return guard,
  a no-op on the zero argument) -> the test passes -> ``inconclusive``: the hypothesis stays
  ``hypothesis`` (nothing was proven either way -- we never claim the guard exists, and we never
  downgrade to ``rejected`` here).

Only ``counterexample`` is ever produced; nothing is ever promoted to ``rejected``. When ``forge``
is absent, a gap is ineligible (constructor args, non-elementary parameters, non-standalone
source), or the probe fails to compile, the gap is returned unchanged -- never an error.

Security model
--------------
The contract under audit is **untrusted input, and it runs**. Foundry grants cheatcode access to
every contract a test deploys, so the audited bytecode can call ``vm.*`` just like the probe can.
The executor therefore runs ``forge`` with the smallest surface it can enforce:

- the generated ``foundry.toml`` pins ``ffi = false`` and ``fs_permissions = []`` explicitly, so a
  permissive *global* ``~/.foundry/foundry.toml`` cannot re-enable shell or file access;
- the subprocess environment is scrubbed to an allow-list (``PATH``, ``HOME``, temp and locale
  variables) with ``FOUNDRY_PROFILE=default`` pinned, so ``vm.env*`` cannot read API keys;
- outbound network is denied where the host offers an unprivileged sandbox (``sandbox-exec`` on
  macOS, ``unshare -rn`` on Linux); where it does not, the result records
  ``isolation.network = "unrestricted"`` and a warning is logged, because ``vm.rpc``/``createFork``
  have no configuration switch;
- a source that references the cheatcode address or the ``"hevm cheat code"`` seed is refused
  outright (defense in depth, not isolation -- a determined author can obfuscate the constant).

Run this opt-in path only on code you are willing to execute, preferably inside a network-less
container. Promoting a counterexample into the finding set lives in
:mod:`miesc.llm.revert_invariant_findings`; this module only annotates the plan/hypothesis.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from miesc.llm.revert_invariant_mining import (
    GuardGapHypothesis,
    RevertInvariantOraclePlan,
    _collect_functions,
    _strip_comments,
)

logger = logging.getLogger(__name__)

_HEVM_ADDRESS = "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D"
_UNAUTHORIZED = "address(0xBEEF)"

# Anything that lets the audited source reach the cheatcode contract on purpose: the well-known
# address (any casing) or the keccak seed it is derived from.
_CHEATCODE_MARKERS = re.compile(
    r"7109709ECfa91a80626fF3989D68f67F5b1DD12D|hevm\s+cheat\s+code", re.I
)

# Written verbatim into the probe project. ``ffi``/``fs_permissions`` are pinned so the auditor's
# global Foundry config can never widen what the audited contract may do.
_PROBE_TOML = '[profile.default]\nsrc = "src"\ntest = "test"\nffi = false\nfs_permissions = []\n'

# Environment allow-list for the ``forge`` subprocess. Everything else (API keys, RPC URLs, cloud
# credentials) is dropped so ``vm.envString`` & co. have nothing to read.
_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SYSTEMROOT",
)

_MACOS_NO_NETWORK_PROFILE = "(version 1)(allow default)(deny network*)"

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


def _references_cheatcodes(source: str) -> bool:
    """True when the source names the Foundry cheatcode contract (address literal or keccak seed)."""
    return bool(_CHEATCODE_MARKERS.search(source))


def _pragma_prefix(source: str) -> str:
    return "" if "pragma solidity" in source else "pragma solidity >=0.7.0;\n"


def _build_probe(source: str, contract: str, fn_args: Dict[str, List[str]]) -> str:
    """A self-contained Foundry test: the inlined contract + a minimal Vm + one probe per fn.

    Each probe records storage accesses around the unauthorized call and fails only when the call
    both succeeded **and** wrote the target's storage. A call that succeeds without writing (an
    early-return guard, a no-op on the zero argument) proves nothing and must stay inconclusive.
    """
    probes = []
    for fn, zeros in fn_args.items():
        sel_args = ", ".join([f"{contract}.{fn}.selector", *zeros])
        probes.append(
            f"    function test_unauthorized_{fn}() public {{\n"
            f"        vm.record();\n"
            f"        vm.prank({_UNAUTHORIZED});\n"
            f"        (bool ok, ) = address(target).call(abi.encodeWithSelector({sel_args}));\n"
            f"        (, bytes32[] memory writes) = vm.accesses(address(target));\n"
            f'        require(!(ok && writes.length > 0), "unauthorized call succeeded and wrote storage");\n'
            f"    }}\n"
        )
    return (
        f"{_pragma_prefix(source)}{source}\n\n"
        f"interface Vm {{\n"
        f"    function prank(address) external;\n"
        f"    function record() external;\n"
        f"    function accesses(address) external returns (bytes32[] memory, bytes32[] memory);\n"
        f"}}\n\n"
        f"contract RevertInvariantACProbe {{\n"
        f"    Vm constant vm = Vm({_HEVM_ADDRESS});\n"
        f"    {contract} target;\n"
        f"    function setUp() public {{ target = new {contract}(); }}\n\n"
        f"{''.join(probes)}}}\n"
    )


def _probe_env() -> Dict[str, str]:
    """Allow-listed environment for ``forge``: no API keys, no RPC URLs, profile pinned."""
    env = {k: os.environ[k] for k in _ENV_ALLOWLIST if k in os.environ}
    env["FOUNDRY_PROFILE"] = "default"
    return env


@functools.lru_cache(maxsize=1)
def _network_sandbox() -> Optional[tuple]:
    """Command prefix that denies outbound network to ``forge``, or ``None`` if the host has none.

    macOS: ``sandbox-exec`` with a deny-network profile. Linux: ``unshare -rn`` (user + net
    namespace), only when an unprivileged probe run succeeds. Cached per process.
    """
    if sys.platform == "darwin":
        exe = shutil.which("sandbox-exec")
        if exe:
            return (exe, "-p", _MACOS_NO_NETWORK_PROFILE)
        return None
    if sys.platform.startswith("linux"):
        exe = shutil.which("unshare")
        if not exe:
            return None
        try:
            probe = subprocess.run(
                [exe, "-rn", "true"], capture_output=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return (exe, "-rn") if probe.returncode == 0 else None
    return None


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

    Returns one result per access-control gap (``id`` = ``<plan id>-access_control-<first
    affected function>``, unique per family):
      - ``promotion_state="counterexample"`` + ``counterexamples=[fn, ...]`` when an unauthorized
        call to an affected function succeeded and wrote the contract's storage;
      - ``promotion_state="hypothesis"`` (unchanged) otherwise, with a ``reason``.
    Executed results also carry ``isolation`` (what the sandbox enforced). Other categories are
    ignored (left to the ``test_generated`` harness). Never raises.
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
    touches_cheatcodes = _references_cheatcodes(source_code)

    for plan, gap in ac_gaps:
        pid = plan.id or "revert_invariant"
        base = {
            "id": f"{pid}-access_control-{gap.affected_functions[0]}",
            "category": "access_control",
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
    """Compile and run the probe with ``forge test --json`` under the hardened project/env/sandbox;
    map the result to a promotion decision. We parse forge's own JSON (``status`` per test)
    directly: the counterexample signal must be read from the authoritative field, not re-derived.
    """
    probe = _build_probe(source_code, contract, fn_args)
    sandbox = _network_sandbox()
    isolation: Dict[str, object] = {
        "ffi": False,
        "fs_permissions": [],
        "env": "scrubbed",
        "network": "denied" if sandbox else "unrestricted",
    }
    if not sandbox:
        logger.warning(
            "revert-invariant executor: no network sandbox available on this host; the audited "
            "contract runs with Foundry cheatcodes and unrestricted outbound network"
        )
    with tempfile.TemporaryDirectory(prefix="miesc_revinv_exec_") as tmp:
        root = Path(tmp)
        (root / "foundry.toml").write_text(_PROBE_TOML)
        test_dir = root / "test"
        test_dir.mkdir()
        (test_dir / "RevertInvariantACProbe.t.sol").write_text(probe)
        cmd = [
            *(sandbox or ()),
            forge,
            "test",
            "--json",
            "--match-contract",
            "RevertInvariantACProbe",
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
        # non-JSON stdout -> did not compile / did not run -> inconclusive, never a counterexample
        return {
            "promotion_state": "hypothesis",
            "reason": "probe did not compile or run standalone",
            "isolation": isolation,
        }

    # forge --json: {"<suite id>": {"test_results": {"<name>()": {"status": "Success|Failure"}}}}
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

    # A FAILED probe test means `require(!(ok && writes.length > 0))` tripped: the unauthorized
    # call succeeded AND wrote the target's storage.
    counterexamples = sorted(
        {
            name.replace("test_unauthorized_", "")
            for name, status in statuses.items()
            if status == "Failure" and name.startswith("test_unauthorized_")
        }
    )
    if counterexamples:
        return {
            "promotion_state": "counterexample",
            "counterexamples": counterexamples,
            "evidence": [
                f"an unauthorized caller ({_UNAUTHORIZED}) called `{fn}`: the call did not revert "
                f"and wrote the contract's storage -- no access-control guard rejected it"
                for fn in counterexamples
            ],
            "isolation": isolation,
        }
    return {
        "promotion_state": "hypothesis",
        "reason": "no unauthorized probe both succeeded and wrote storage; not promoted",
        "isolation": isolation,
    }


__all__ = ["execute_access_control_gaps"]
