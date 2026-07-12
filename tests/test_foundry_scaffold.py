"""
Tests for the Shared Foundry Scaffold Helper
============================================

Covers ``src.poc.foundry_scaffold.scaffold_foundry_project``:
- forge-absent -> returns ``None`` cleanly (no raise) via monkeypatched
  ``shutil.which``.
- live forge -> scaffolds a trivial self-contained vulnerable contract into a
  temp Foundry project and proves a real ``forge build`` succeeds against it
  through the ``@repo/`` remapping. No API, no network for the compile path.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: July 2026
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from miesc.poc.foundry_scaffold import (
    REPO_REMAP_PREFIX,
    scaffold_foundry_project,
)

TRIVIAL_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract Vuln {
    uint256 public x;

    function set(uint256 v) external {
        x = v;
    }
}
"""


@pytest.fixture
def trivial_repo():
    """A minimal repo dir containing one self-contained vulnerable contract."""
    repo = Path(tempfile.mkdtemp(prefix="miesc_scaffold_repo_"))
    contract = repo / "Vuln.sol"
    contract.write_text(TRIVIAL_CONTRACT, encoding="utf-8")
    try:
        yield repo, contract
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_returns_none_when_forge_absent(trivial_repo, monkeypatch):
    """forge missing -> return None, never raise, no workspace created."""
    repo, contract = trivial_repo
    monkeypatch.setattr("miesc.poc.foundry_scaffold.shutil.which", lambda _: None)

    result = scaffold_foundry_project(repo, contract)

    assert result is None


@pytest.mark.skipif(
    not shutil.which("forge"), reason="forge not installed"
)
def test_scaffold_compiles_real_contract(trivial_repo):
    """Live forge: scaffolded project builds against the REAL contract."""
    repo, contract = trivial_repo

    project = scaffold_foundry_project(repo, contract)
    assert project is not None
    project = Path(project)
    try:
        # Sanity: expected Foundry layout + remapping wired to the real repo.
        assert (project / "foundry.toml").is_file()
        assert (project / "test").is_dir()
        toml_text = (project / "foundry.toml").read_text(encoding="utf-8")
        assert REPO_REMAP_PREFIX in toml_text
        assert str(repo) in toml_text

        # Drop a probe test that imports the REAL contract via @repo/ and
        # deploys it - exactly what an LLM-drafted exploit will do.
        probe = project / "test" / "Probe.t.sol"
        probe.write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.13;\n"
            'import {Vuln} from "@repo/Vuln.sol";\n'
            "contract Probe {\n"
            "    function drive() external {\n"
            "        Vuln v = new Vuln();\n"
            "        v.set(42);\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        build = subprocess.run(
            ["forge", "build"],
            cwd=project,
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert build.returncode == 0, (
            f"forge build failed:\nSTDOUT:\n{build.stdout}\nSTDERR:\n{build.stderr}"
        )
    finally:
        shutil.rmtree(project, ignore_errors=True)
