"""run_layer()/run_tool() route .vy files to VyperAdapter, and skip
Solidity-only tools for them (before this, .vy files
had no route through the evaluate/scan tool-execution path)."""

from miesc.adapters.vyper_adapter import VyperAdapter
from miesc.cli import utils
from miesc.core.ml_orchestrator import MLOrchestrator
from miesc.core.tool_protocol import ToolStatus, applies_to

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


def _quiet(monkeypatch):
    for name in ("info", "success", "warning"):
        monkeypatch.setattr(utils, name, lambda *_a, **_k: None)


def test_run_layer_routes_vy_file_to_vyper_only(tmp_path, monkeypatch):
    vy_file = tmp_path / "Vault.vy"
    vy_file.write_text(VY_SOURCE)
    _quiet(monkeypatch)

    results = utils.run_layer(1, str(vy_file), timeout=30)

    assert [r["tool"] for r in results] == ["vyper"]
    assert results[0]["status"] == "success"


def test_run_layer_on_sol_file_has_no_vyper_row(tmp_path, monkeypatch):
    sol_file = tmp_path / "Token.sol"
    sol_file.write_text(SOL_SOURCE)
    _quiet(monkeypatch)

    tools = [r["tool"] for r in utils.run_layer(1, str(sol_file), timeout=30)]

    assert "vyper" not in tools
    assert "fouranalyzer" in tools


def test_applies_to_keeps_directories_for_every_tool(tmp_path):
    assert applies_to(VyperAdapter(), str(tmp_path)) is True
    assert applies_to(VyperAdapter(), str(tmp_path / "Token.sol")) is True  # not a file yet


def test_vyper_adapter_analyze_skips_sol_file(tmp_path):
    sol_file = tmp_path / "Token.sol"
    sol_file.write_text(SOL_SOURCE)

    result = VyperAdapter().analyze(str(sol_file))

    assert result["status"] == "skipped"
    assert result["reason"] == "unsupported_source"
    assert result["findings"] == []


def test_ml_orchestrator_skips_vyper_on_sol_file(tmp_path):
    sol_file = tmp_path / "Token.sol"
    sol_file.write_text(SOL_SOURCE)

    orchestrator = MLOrchestrator(ml_enabled=False, cache_enabled=False)
    result = orchestrator._run_tool("vyper", str(sol_file))

    assert result["status"] == "skipped"
    assert result["findings"] == []


def test_ml_orchestrator_leaves_vyper_out_of_the_run_list_on_sol(tmp_path):
    """Like the --no-ml path: a tool that cannot read the file is not run and not reported."""
    sol_file = tmp_path / "Token.sol"
    sol_file.write_text(SOL_SOURCE)
    vy_file = tmp_path / "Token.vy"
    vy_file.write_text("# @version 0.3.10\n@external\ndef f():\n    pass\n")

    orchestrator = MLOrchestrator(ml_enabled=False, cache_enabled=False)
    assert "vyper" not in orchestrator._applicable_tools(["vyper", "slither"], str(sol_file))
    assert "slither" in orchestrator._applicable_tools(["vyper", "slither"], str(sol_file))
    assert "vyper" in orchestrator._applicable_tools(["vyper", "slither"], str(vy_file))
    assert "slither" not in orchestrator._applicable_tools(["vyper", "slither"], str(vy_file))
    # A directory keeps every tool (applies_to is per file).
    assert orchestrator._applicable_tools(["vyper", "slither"], str(tmp_path)) == [
        "vyper",
        "slither",
    ]
