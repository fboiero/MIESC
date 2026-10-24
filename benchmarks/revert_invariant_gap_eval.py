#!/usr/bin/env python3
"""Non-canonical evaluation of the revert-invariant access-control gap execution path.

This is an **advisory, non-canonical** probe of `enable_gap_execution` end-to-end
(mine -> execute_access_control_gaps -> counterexample_findings). It makes **no benchmark claim**
and does not touch any frozen artifact; it only exercises the pipeline on two controls:

- **FP control** (optional `--fp-corpus DIR`): real audited libraries where no inconsistent
  access-control gap exists. Expectation: 0 counterexample findings. Clone, e.g.:
    OpenZeppelin  https://github.com/OpenZeppelin/openzeppelin-contracts  (contracts/)
    Solady        https://github.com/Vectorized/solady                   (src/)
    Uniswap v2    https://github.com/Uniswap/v2-periphery                 (contracts/)
  and pass a directory containing them (the script globs **/*.sol).

- **Positive control**: small synthetic contracts with a *known* missing access-control guard,
  eligible for execution (no-arg constructor, elementary args). Expectation: a counterexample
  exactly where the guard is genuinely absent, and silence where a sibling reverts for an
  unrelated reason (the vacuous-pass guard) or where the family is consistent.

Requires `forge` on PATH for the execution rung; without it, the positive control degrades to
0 counterexamples (reported as such), which is the correct graceful-degradation behavior.

Usage:
    python benchmarks/revert_invariant_gap_eval.py [--fp-corpus /path/to/libs] [--out result.json]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
from typing import Any, Dict, List

from miesc.llm.revert_invariant_executor import execute_access_control_gaps
from miesc.llm.revert_invariant_findings import counterexample_findings
from miesc.llm.revert_invariant_mining import mine_revert_invariants

# Positive-control fixtures: (name, source, expected_counterexample_functions).
_POSITIVE: List[tuple] = [
    (
        "unguarded_setter",  # setFee guarded, setTreasury not -> counterexample on setTreasury
        """pragma solidity ^0.8.20;
contract Vault {
  address owner; address treasury; uint256 fee;
  constructor() { owner = msg.sender; }
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  function setFee(uint256 x) external onlyOwner { fee = x; }
  function setTreasury(address a) external { treasury = a; }
}""",
        ["setTreasury"],
    ),
    (
        "unguarded_upgrade",  # upgradeTo guarded, upgradeImpl not
        """pragma solidity ^0.8.20;
contract Proxy {
  address owner; address impl;
  constructor() { owner = msg.sender; }
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  function upgradeTo(address a) external onlyOwner { impl = a; }
  function upgradeImpl(address a) external { impl = a; }
}""",
        ["upgradeImpl"],
    ),
    (
        "vacuous_revert",  # unguarded-by-access, but reverts on zero arg -> NO counterexample
        """pragma solidity ^0.8.20;
contract Vault {
  address owner; address treasury;
  constructor() { owner = msg.sender; }
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  function setFee(uint256 x) external onlyOwner { treasury = address(0); }
  function setTreasury(address a) external { require(a != address(0), "zero"); treasury = a; }
}""",
        [],
    ),
    (
        "consistent_family",  # both guarded -> no gap at all
        """pragma solidity ^0.8.20;
contract Vault {
  address owner; uint256 fee; address treasury;
  constructor() { owner = msg.sender; }
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  function setFee(uint256 x) external onlyOwner { fee = x; }
  function setTreasury(address a) external onlyOwner { treasury = a; }
}""",
        [],
    ),
]


def _eval_source(src: str, path: str | None = None) -> Dict[str, Any]:
    plans = mine_revert_invariants(src, pathlib.Path(path) if path else None)
    execs = execute_access_control_gaps(plans, src)
    findings = counterexample_findings(execs, src, path)
    confirmed = sorted(
        {
            fn
            for ex in execs
            if ex.get("promotion_state") == "counterexample"
            for fn in ex.get("counterexamples", [])
        }
    )
    return {"counterexamples": confirmed, "findings": len(findings)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fp-corpus", default=None, help="directory of audited .sol libraries")
    ap.add_argument("--out", default=None, help="write JSON result here")
    args = ap.parse_args()

    forge = shutil.which("forge")
    result: Dict[str, Any] = {
        "capability": "revert_invariant_mining / enable_gap_execution",
        "canonical": False,
        "benchmark_claim": False,
        "forge_available": bool(forge),
        "positive_control": [],
        "fp_control": None,
    }

    pos_ok = True
    for name, src, expected in _POSITIVE:
        got = _eval_source(src)
        # When forge is absent the execution rung can't confirm; only assert when we could run.
        ok = (
            (got["counterexamples"] == sorted(expected))
            if forge
            else (got["counterexamples"] == [])
        )
        pos_ok = pos_ok and ok
        result["positive_control"].append(
            {
                "name": name,
                "expected": sorted(expected),
                "got": got["counterexamples"],
                "findings": got["findings"],
                "ok": ok,
            }
        )
    result["positive_control_pass"] = pos_ok

    if args.fp_corpus:
        root = pathlib.Path(args.fp_corpus)
        files = 0
        total_cx = 0
        total_findings = 0
        offenders: List[str] = []
        for sol in root.rglob("*.sol"):
            files += 1
            r = _eval_source(sol.read_text(errors="ignore"), str(sol))
            total_cx += len(r["counterexamples"])
            total_findings += r["findings"]
            if r["findings"]:
                offenders.append(str(sol.relative_to(root)))
        result["fp_control"] = {
            "corpus": str(root),
            "files": files,
            "counterexamples": total_cx,
            "findings": total_findings,
            "offenders": offenders,
            "pass": total_findings == 0,
        }

    text = json.dumps(result, indent=2)
    if args.out:
        pathlib.Path(args.out).write_text(text + "\n")
    print(text)
    return 0 if pos_ok and (result["fp_control"] is None or result["fp_control"]["pass"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
