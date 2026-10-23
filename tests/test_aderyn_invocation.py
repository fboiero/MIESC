"""Aderyn is invoked off the network and with a HOME-independent solc on its PATH."""

import sys
from pathlib import Path

from miesc.adapters import aderyn_adapter
from miesc.adapters.aderyn_adapter import AderynAdapter, _get_solc_env


def test_solc_path_starts_with_the_running_interpreters_bin():
    first = _get_solc_env()["PATH"].split(":")[0]
    assert first == str(Path(sys.prefix) / "bin")


def test_aderyn_is_run_with_skip_update_check(tmp_path, monkeypatch):
    """aderyn 0.1.x panics when its GitHub version check is rate-limited; the
    adapter must never let that check run."""
    contract = tmp_path / "A.sol"
    contract.write_text(
        "pragma solidity ^0.8.20;\ncontract A { uint x; function f(uint a) public { x = a; } }\n"
    )
    seen = {}

    class Completed:
        returncode = 1
        stdout = ""
        stderr = "boom"

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        return Completed()

    monkeypatch.setattr(aderyn_adapter.subprocess, "run", fake_run)
    monkeypatch.setattr(
        AderynAdapter, "is_available", lambda self: aderyn_adapter.ToolStatus.AVAILABLE
    )
    AderynAdapter().analyze(str(contract), timeout=5)
    assert seen["cmd"][0] == "aderyn"
    assert "--skip-update-check" in seen["cmd"]
