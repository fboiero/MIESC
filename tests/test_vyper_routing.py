"""run_layer()/run_tool() route .vy files to VyperAdapter, and skip
Solidity-only tools for them (MEJORAS3.md item 7 — before this, .vy files
had no route through the evaluate/scan tool-execution path)."""

from miesc.adapters.vyper_adapter import VyperAdapter
from miesc.cli import utils
from miesc.core.tool_protocol import ToolStatus

VY_SOURCE = """\
# @version 0.3.7

@external
def check(user: address) -> bool:
    return tx.origin == user
"""

SOL_SOURCE = "pragma solidity ^0.8.0;\ncontract C {}\n"


def test_vyper_adapter_can_analyze_only_vy_files():
    adapter = VyperAdapter()
    assert adapter.can_analyze("Vault.vy") is True
    assert adapter.can_analyze("Token.sol") is False


def test_vyper_adapter_is_available_without_external_tool():
    assert VyperAdapter().is_available() == ToolStatus.AVAILABLE


def test_run_tool_vyper_analyzes_vy_file(tmp_path):
    vy_file = tmp_path / "Vault.vy"
    vy_file.write_text(VY_SOURCE)

    result = utils.run_tool("vyper", str(vy_file))

    assert result["status"] == "success"
    assert any(f["type"] == "tx_origin_auth" for f in result["findings"])


def test_run_tool_vyper_skips_sol_file(tmp_path):
    sol_file = tmp_path / "Token.sol"
    sol_file.write_text(SOL_SOURCE)

    result = utils.run_tool("vyper", str(sol_file))

    assert result["status"] == "skipped"
    assert result["findings"] == []


def test_run_tool_solidity_only_tool_skips_vy_file(tmp_path):
    vy_file = tmp_path / "Vault.vy"
    vy_file.write_text(VY_SOURCE)

    result = utils.run_tool("slither", str(vy_file))

    assert result["status"] == "skipped"


def test_run_layer_routes_vy_file_to_vyper_only(tmp_path, monkeypatch):
    vy_file = tmp_path / "Vault.vy"
    vy_file.write_text(VY_SOURCE)

    monkeypatch.setattr(utils, "info", lambda *_a, **_k: None)
    monkeypatch.setattr(utils, "success", lambda *_a, **_k: None)
    monkeypatch.setattr(utils, "warning", lambda *_a, **_k: None)

    results = utils.run_layer(1, str(vy_file), timeout=30)
    by_tool = {r["tool"]: r for r in results}

    assert by_tool["vyper"]["status"] == "success"
    for tool in ("slither", "aderyn", "solhint", "wake", "semgrep", "fouranalyzer"):
        assert by_tool[tool]["status"] == "skipped"
