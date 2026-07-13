"""Regression tests for the documentation analyzer system-temp guard.

Previously ``analyze_all`` defaulted ``project_root`` to the contract's parent
directory and ran ``rglob("I*.sol")`` (and diagram globs) against it. Given a
path under a system temp root (e.g. ``/tmp/C.sol``), ``project_root`` became
``/tmp`` and the recursive glob traversed the entire shared temp area, hanging
the process. The guard now falls back to a non-recursive scan bounded to the
immediate directory when the root is a system temp directory.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from miesc.agents.audit_readiness import documentation_analyzer as da
from miesc.agents.audit_readiness.documentation_analyzer import (
    DocumentationAnalyzer,
    _is_system_temp_root,
    _safe_rglob,
)

CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Minimal contract.
contract C {}
"""


def test_is_system_temp_root_detects_tmp():
    assert _is_system_temp_root(Path("/tmp")) is True
    assert _is_system_temp_root(Path(tempfile.gettempdir())) is True


def test_is_system_temp_root_false_for_project_dir(tmp_path):
    # mkdtemp / tmp_path style project dirs are *children* of the temp root and
    # must still be scanned recursively (real project layouts live there in CI).
    assert _is_system_temp_root(tmp_path) is False


def test_safe_rglob_recurses_for_normal_dir(tmp_path):
    (tmp_path / "IRoot.sol").write_text("interface IRoot {}")
    deep = tmp_path / "deep"
    deep.mkdir()
    (deep / "INested.sol").write_text("interface INested {}")

    found = {p.name for p in _safe_rglob(tmp_path, "I*.sol")}
    assert found == {"IRoot.sol", "INested.sol"}  # recursive


def test_safe_rglob_does_not_recurse_for_temp_root(tmp_path, monkeypatch):
    (tmp_path / "IRoot.sol").write_text("interface IRoot {}")
    deep = tmp_path / "deep"
    deep.mkdir()
    (deep / "INested.sol").write_text("interface INested {}")

    # Treat tmp_path as if it were the system temp root.
    monkeypatch.setattr(da, "_is_system_temp_root", lambda p: p == tmp_path)

    found = {p.name for p in _safe_rglob(tmp_path, "I*.sol")}
    # Only the immediate directory is scanned; the nested interface is skipped,
    # proving unrelated subtrees are never traversed.
    assert found == {"IRoot.sol"}


def test_analyze_all_on_temp_root_does_not_traverse_subdirs(tmp_path, monkeypatch):
    contract = tmp_path / "C.sol"
    contract.write_text(CONTRACT)
    (tmp_path / "IToken.sol").write_text("interface IToken {}")
    # An unrelated subtree that must NOT be scanned when root is a temp dir.
    junk = tmp_path / "unrelated"
    junk.mkdir()
    (junk / "IHidden.sol").write_text("interface IHidden {}")

    monkeypatch.setattr(da, "_is_system_temp_root", lambda p: p == tmp_path)

    analyzer = DocumentationAnalyzer()
    start = time.monotonic()
    result = analyzer.analyze_all(str(contract))
    elapsed = time.monotonic() - start

    assert elapsed < 5.0  # returns fast, no runaway recursion
    # Only the immediate-directory interface is counted; the nested one is not.
    assert result["api"]["interface_count"] == 1
