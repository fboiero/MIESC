"""Tests for `miesc scan --profile` routing."""

import importlib
import json

from click.testing import CliRunner

from miesc.cli.commands.scan import _profile_tools, _profile_uses_agentic_path, scan


def test_scan_profile_helpers_detect_agentic_and_tool_profiles():
    assert _profile_uses_agentic_path({"agentic_ensemble": {"provider_contract": "x"}}) is True
    assert _profile_uses_agentic_path({"enable_agentic_invariants": True}) is True
    assert _profile_uses_agentic_path({"tools": ["slither"]}) is False
    assert _profile_tools({"tools": ["slither", "solhint"]}) == ["slither", "solhint"]


def test_scan_agentic_profile_routes_to_deep_agent(monkeypatch, tmp_path):
    contract = tmp_path / "Vault.sol"
    output = tmp_path / "scan.json"
    contract.write_text("pragma solidity ^0.8.20; contract Vault {}")
    seen = {}

    class FakeAgent:
        def __init__(self, config):
            seen["config"] = config

        def analyze(self, contract_path):
            seen["contract"] = contract_path
            return {
                "findings": [{"id": "agentic-1", "severity": "HIGH", "title": "Invariant"}],
                "metadata": {"agentic_invariants_count": 1},
            }

    scan_module = importlib.import_module("miesc.cli.commands.scan")
    monkeypatch.setattr("miesc.agents.deep_audit_agent.DeepAuditAgent", FakeAgent)
    monkeypatch.setattr(
        scan_module,
        "run_tool",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("run_tool called")),
    )

    result = CliRunner().invoke(
        scan,
        [str(contract), "--profile", "paper1-evmbench-ensemble", "-o", str(output), "--quiet"],
    )

    assert result.exit_code == 0, result.output
    assert seen["contract"] == str(contract)
    assert seen["config"].enable_agentic_invariants is True
    assert seen["config"].agentic_invariants_allow_remote is False

    data = json.loads(output.read_text())
    assert data["tools"] == ["miesc-agentic-scan-profile"]
    assert data["summary"]["HIGH"] == 1
    assert data["findings"][0]["tool"] == "miesc-agentic-scan-profile"


def test_scan_non_agentic_profile_uses_profile_tools(monkeypatch, tmp_path):
    contract = tmp_path / "Vault.sol"
    output = tmp_path / "scan.json"
    contract.write_text("pragma solidity ^0.8.20; contract Vault {}")
    tools_seen = []

    def fake_run_tool(tool, contract_path, timeout, **kwargs):
        tools_seen.append(tool)
        return {
            "tool": tool,
            "contract": contract_path,
            "status": "success",
            "findings": [],
            "execution_time": 0.0,
        }

    scan_module = importlib.import_module("miesc.cli.commands.scan")
    monkeypatch.setattr(scan_module, "run_tool", fake_run_tool)

    result = CliRunner().invoke(
        scan,
        [str(contract), "--profile", "fast", "-o", str(output), "--quiet"],
    )

    assert result.exit_code == 0, result.output
    assert sorted(tools_seen) == ["slither", "solhint"]
    data = json.loads(output.read_text())
    assert data["tools"] == ["slither", "solhint"]
