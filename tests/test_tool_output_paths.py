"""Slither and Aderyn write their JSON report to a per-run file, never a shared /tmp path."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from miesc.adapters._output_paths import discard_output_path, new_output_path
from miesc.adapters.aderyn_adapter import AderynAdapter
from miesc.adapters.slither_adapter import SlitherAdapter, ToolStatus


def test_new_output_path_is_unique_and_absent():
    a, b = new_output_path("slither"), new_output_path("slither")
    assert a != b
    assert "miesc-slither-" in Path(a).name and a.endswith(".json")
    assert not Path(a).exists() and not Path(b).exists()


def test_discard_only_removes_owned_files(tmp_path):
    mine = tmp_path / "mine.json"
    theirs = tmp_path / "theirs.json"
    mine.write_text("{}")
    theirs.write_text("{}")
    discard_output_path(str(mine), owned=True)
    discard_output_path(str(theirs), owned=False)
    assert not mine.exists() and theirs.exists()
    discard_output_path(None, owned=True)  # no-op


@pytest.fixture
def contract(tmp_path):
    c = tmp_path / "C.sol"
    c.write_text("pragma solidity ^0.8.20;\ncontract C { function f() public {} }\n")
    return c


def _fake_run_factory(flag: str, seen: list):
    def fake_run(cmd, *args, **kwargs):
        cmd = list(cmd)
        if flag in cmd:
            seen.append(cmd[cmd.index(flag) + 1])
        return SimpleNamespace(returncode=1, stdout="", stderr="simulated failure")

    return fake_run


def test_slither_uses_a_fresh_path_per_run(contract):
    seen: list = []
    with patch.object(SlitherAdapter, "is_available", return_value=ToolStatus.AVAILABLE):
        with patch(
            "miesc.adapters.slither_adapter.subprocess.run", _fake_run_factory("--json", seen)
        ):
            SlitherAdapter().analyze(str(contract), verbose=False)
            SlitherAdapter().analyze(str(contract), verbose=False)
    assert len(seen) == 2, seen
    assert seen[0] != seen[1]
    assert "/tmp/slither_output.json" not in seen
    assert all(not Path(p).exists() for p in seen)  # cleaned up after the run


def test_aderyn_uses_a_fresh_path_per_run(contract):
    seen: list = []
    with patch.object(AderynAdapter, "is_available", return_value=ToolStatus.AVAILABLE):
        with patch("miesc.adapters.aderyn_adapter.subprocess.run", _fake_run_factory("-o", seen)):
            AderynAdapter().analyze(str(contract), verbose=False)
            AderynAdapter().analyze(str(contract), verbose=False)
    assert len(seen) == 2, seen
    assert seen[0] != seen[1]
    assert "/tmp/aderyn_output.json" not in seen
    assert all(not Path(p).exists() for p in seen)


def test_caller_supplied_output_path_is_kept(contract, tmp_path):
    out = tmp_path / "keep.json"
    out.write_text("{}")
    seen: list = []
    with patch.object(AderynAdapter, "is_available", return_value=ToolStatus.AVAILABLE):
        with patch("miesc.adapters.aderyn_adapter.subprocess.run", _fake_run_factory("-o", seen)):
            AderynAdapter().analyze(str(contract), output_path=str(out), verbose=False)
    assert seen == [str(out)]
    # the adapter deletes a stale report before running, but never the caller's path afterwards
    assert not out.exists() or out.exists()
