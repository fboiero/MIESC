"""Optional ``forge build`` compile-check for generated PoC scaffolds (phase 5).

Phase 4 makes the scaffolds *statically* compile-valid; this optionally runs the
real ``forge build`` on each, so a project with Foundry installed can confirm the
generated Solidity actually compiles. Strictly best-effort and opt-in: when forge
is not on PATH (e.g. CI) or the project cannot be scaffolded, every scaffold is
reported ``skipped`` and nothing runs — it never affects the default
``verify --poc`` path.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

# A minimal forge-std test used to detect whether the environment can compile
# forge-std at all (solc availability), separate from any generated scaffold.
_BASELINE_PROBE = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract _MiescBaselineProbe is Test {
    function test_baseline() public pure {}
}
"""


def forge_available() -> bool:
    """True if the ``forge`` binary is on PATH."""
    return shutil.which("forge") is not None


def _all_skipped(scaffolds: Sequence[Tuple[str, str]]) -> List[Dict[str, str]]:
    return [{"filename": name, "status": "skipped"} for name, _ in scaffolds]


def check_scaffolds_compile(
    scaffolds: Sequence[Tuple[str, str]],
    repo_dir: str,
    contract_file: str,
) -> List[Dict[str, str]]:
    """Compile each ``(filename, solidity)`` scaffold via a temp Foundry project.

    Returns one ``{"filename", "status"}`` per scaffold with status in
    ``compiled | failed | skipped``. Each scaffold is built in isolation. This is
    best-effort: it returns all ``skipped`` when forge is unavailable or the
    project cannot be scaffolded, and never raises.
    """
    if not scaffolds:
        return []
    if not forge_available():
        return _all_skipped(scaffolds)

    try:
        from miesc.poc.foundry_scaffold import scaffold_foundry_project
        from miesc.poc.validators.foundry_runner import FoundryRunner
    except Exception:
        return _all_skipped(scaffolds)

    try:
        project = scaffold_foundry_project(Path(repo_dir), Path(contract_file))
    except Exception:
        project = None
    if project is None:
        return _all_skipped(scaffolds)

    test_dir = Path(project) / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    runner = FoundryRunner(project)

    # Baseline probe: a trivial forge-std test. If even THIS cannot build (e.g. no
    # installed solc matches forge-std's version requirement), the environment can't
    # compile any scaffold that imports forge-std — that is an environment problem,
    # not a scaffold problem, so report "skipped" rather than a misleading "failed".
    probe = test_dir / "_MiescBaselineProbe.t.sol"
    try:
        probe.write_text(_BASELINE_PROBE, encoding="utf-8")
        if not runner.compile():
            return _all_skipped(scaffolds)
    except Exception:
        return _all_skipped(scaffolds)
    finally:
        if probe.exists():
            probe.unlink()

    results: List[Dict[str, str]] = []
    for filename, solidity in scaffolds:
        test_file = test_dir / filename
        try:
            test_file.write_text(solidity, encoding="utf-8")
            compiled = bool(runner.compile())
            results.append({"filename": filename, "status": "compiled" if compiled else "failed"})
        except Exception:
            results.append({"filename": filename, "status": "skipped"})
        finally:
            if test_file.exists():
                test_file.unlink()
    return results
