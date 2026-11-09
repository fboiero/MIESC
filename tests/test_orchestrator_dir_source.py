"""
`audit full` must work on a project directory, not just a single file. The ML
orchestrator's source read used a bare `open()` that failed with "[Errno 21] Is a
directory", so the whole ML/LLM pipeline got no code on a directory target. It now
uses the shared loader, which resolves a directory to its in-scope `.sol` files.

(The earlier stop-gap — rejecting a directory in `audit full` with a pointer to
`audit batch` — is removed: the loader makes the directory case actually work.)
"""

from __future__ import annotations

import pytest

from miesc.core.ml_orchestrator import MLOrchestrator


@pytest.fixture
def orchestrator():
    return MLOrchestrator(cache_enabled=False, ml_enabled=False)


def test_read_contract_source_resolves_a_project_directory(orchestrator, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.20;\ncontract A {}\n",
        encoding="utf-8",
    )

    source = orchestrator._read_contract_source(str(tmp_path))

    # The directory is resolved to its in-scope source, not silently dropped to "".
    assert "contract A" in source


def test_read_contract_source_reads_a_single_file(orchestrator, tmp_path):
    f = tmp_path / "A.sol"
    f.write_text("contract A {}", encoding="utf-8")

    assert "contract A" in orchestrator._read_contract_source(str(f))


def test_read_contract_source_empty_for_nonexistent_path(orchestrator, tmp_path):
    assert orchestrator._read_contract_source(str(tmp_path / "nope.sol")) == ""
