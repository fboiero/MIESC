"""
Functional smoke probe for ``miesc doctor --smoke`` (P1-5).
===========================================================

``doctor`` reports whether a tool is *installed* (``is_available``). That is
not the same as whether it *runs*: a tool can be present yet fail on a real
target (wrong input type, a dead CLI flag, a missing backend). This module
adds a bounded functional probe — it runs each available adapter against a
tiny self-contained contract and reports one of four honest verdicts.

Design notes:

* **Subprocess isolation.** Each probe runs the real ``run_tool`` path in a
  separate interpreter with a hard wall-clock timeout. Adapters do not reliably
  honour their own ``timeout`` kwarg, and some mutate module state or call
  ``sys.exit``; a subprocess gives a real kill switch and keeps ``doctor``
  itself crash-proof.
* **It probes a trivial contract, not a real project.** A ``functional`` verdict
  means "this adapter runs and returns a result on a 15-line contract", not
  "this adapter works on your multi-file codebase". It catches exactly the
  crash / wrong-input / dead-flag class of wiring bug.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, Tuple

# Layers whose tools are local, fast and deterministic enough to probe by
# default. The rest (fuzzing campaigns, symbolic engines, formal provers, LLM
# ensembles) only run under ``--smoke-all`` with a longer per-probe budget.
FAST_LAYERS: Tuple[int, ...] = (1, 6, 7, 8)
SLOW_LAYERS: Tuple[int, ...] = (2, 3, 4, 5, 9)

# Verdicts.
FUNCTIONAL = "functional"  # ran and returned success/inconclusive
DEGRADED = "degraded"  # available but errored / produced nothing on the fixture
SLOW = "slow"  # did not finish within the probe budget (NOT "broken")
NEEDS_BACKEND = "needs-backend"  # LLM-backed tool with no reachable backend
NOT_APPLICABLE = "not-applicable"  # correctly declined this input (e.g. a .vy / circom analyzer)

VERDICTS = (FUNCTIONAL, DEGRADED, SLOW, NEEDS_BACKEND, NOT_APPLICABLE)

# Default per-probe wall-clock budgets (seconds); the subprocess gets a small
# buffer on top so its own timeout can fire first.
FAST_TIMEOUT = 20
SLOW_TIMEOUT = 45
_SUBPROCESS_BUFFER = 10

# A minimal but non-trivial contract: a state var, a payable, an external call
# and a require — enough that static tools have something to say and AI/ML tools
# have something to read, with no imports so it compiles standalone via solc.
FIXTURE_SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SmokeProbe {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""

# Repo/package root to force onto the child's sys.path so the probe imports the
# same `miesc` as the running process (an editable-install `.pth` can otherwise
# shadow it under some interpreters).
_MIESC_ROOT = str(Path(__file__).resolve().parents[2])


def write_fixture(directory: Path) -> Path:
    """Write the probe contract into ``directory`` and return its path."""
    path = Path(directory) / "SmokeProbe.sol"
    path.write_text(FIXTURE_SOURCE, encoding="utf-8")
    return path


def layers_for(smoke_all: bool) -> Tuple[int, ...]:
    """Layer numbers to probe: fast layers by default, plus the slow ones for --smoke-all."""
    return tuple(FAST_LAYERS) + (tuple(SLOW_LAYERS) if smoke_all else ())


def _probe_env() -> Dict[str, str]:
    """Child environment with cloud LLM keys stripped: a smoke probe must never
    reach a paid API — LLM adapters default to local Ollama anyway."""
    env = dict(os.environ)
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        env.pop(key, None)
    return env


def _child_code(tool: str, fixture: str, timeout: int) -> str:
    return (
        f"import sys; sys.path.insert(0, {_MIESC_ROOT!r});\n"
        "import json\n"
        "from miesc.cli.utils import run_tool\n"
        f"r = run_tool({tool!r}, {fixture!r}, {int(timeout)})\n"
        "print(json.dumps({'status': r.get('status'), "
        "'error': (str(r.get('error') or ''))[:200], "
        "'reason': (str(r.get('reason') or ''))[:80], "
        "'findings': len(r.get('findings') or [])}))\n"
    )


def probe_tool(
    tool: str,
    fixture: str,
    *,
    timeout: int,
    llm_tools: Iterable[str],
    ollama_online: bool,
) -> Tuple[str, str]:
    """Probe one tool against the fixture. Returns ``(verdict, detail)``.

    An LLM-backed tool with no reachable backend is reported ``needs-backend``
    without spawning a probe, so an offline laptop does not mislabel the code.
    """
    if tool in set(llm_tools) and not ollama_online:
        return NEEDS_BACKEND, "no LLM backend reachable (Ollama offline)"

    try:
        proc = subprocess.run(
            [sys.executable, "-c", _child_code(tool, fixture, timeout)],
            capture_output=True,
            text=True,
            timeout=timeout + _SUBPROCESS_BUFFER,
            env=_probe_env(),
        )
    except subprocess.TimeoutExpired:
        return SLOW, f"no result within {timeout + _SUBPROCESS_BUFFER}s"

    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "non-zero exit").strip()
        return DEGRADED, tail[-200:]

    line = (proc.stdout or "").strip().splitlines()[-1] if proc.stdout.strip() else ""
    try:
        data = json.loads(line)
    except (ValueError, IndexError):
        return DEGRADED, (proc.stdout or proc.stderr or "no parseable output").strip()[-200:]

    status = str(data.get("status") or "")
    if status in ("success", "inconclusive"):
        detail = status if status == "success" else "inconclusive (ran, no signal)"
        return FUNCTIONAL, detail
    if status == "skipped":
        # The tool ran and correctly declined this input (e.g. a .vy / circom
        # analyzer handed a .sol). That is designed behaviour, not a defect.
        return NOT_APPLICABLE, data.get("reason") or "declined this input"
    return DEGRADED, data.get("error") or f"status={status or 'none'}"


def timeout_for(smoke_all: bool) -> int:
    """Per-probe budget: longer when the slow layers are in play."""
    return SLOW_TIMEOUT if smoke_all else FAST_TIMEOUT


def summarize(verdicts: Iterable[str]) -> Dict[str, int]:
    """Count verdicts into a fixed {verdict: n} shape (missing verdicts = 0)."""
    counts: Dict[str, int] = dict.fromkeys(VERDICTS, 0)
    for v in verdicts:
        if v in counts:
            counts[v] += 1
    return counts


def headline(functional: int, applicable: int, available: int, total: int) -> str:
    """The P1-5 one-liner: how many tools actually run vs are merely installed.

    ``applicable`` excludes tools that correctly declined the fixture's file type
    (``not-applicable``), so ``functional / applicable`` is the honest gap.
    """
    return (
        f"functional {functional} / applicable {applicable} "
        f"/ available {available} / total {total}"
    )


__all__ = [
    "FAST_LAYERS",
    "SLOW_LAYERS",
    "FUNCTIONAL",
    "DEGRADED",
    "SLOW",
    "NEEDS_BACKEND",
    "VERDICTS",
    "FIXTURE_SOURCE",
    "write_fixture",
    "layers_for",
    "timeout_for",
    "probe_tool",
    "summarize",
    "headline",
]
