"""Tests for agentic audit profile routing."""

import importlib
import json

from click.testing import CliRunner

from miesc.cli.commands.audit import _profile_uses_agentic_path, audit_profile


def test_profile_uses_agentic_path_only_for_agentic_profiles():
    assert _profile_uses_agentic_path({"agentic_ensemble": {"provider_contract": "x"}}) is True
    assert _profile_uses_agentic_path({"enable_agentic_invariants": True}) is True
    assert _profile_uses_agentic_path({"tools": ["slither"]}) is False


def test_audit_profile_paper_ensemble_routes_to_deep_agent(monkeypatch, tmp_path):
    contract = tmp_path / "Vault.sol"
    output = tmp_path / "report.json"
    contract.write_text("pragma solidity ^0.8.20; contract Vault {}")
    seen = {}

    class FakeAgent:
        def __init__(self, config):
            seen["config"] = config

        def analyze(self, contract_path):
            seen["contract"] = contract_path
            return {
                "findings": [
                    {
                        "id": "agentic-1",
                        "severity": "HIGH",
                        "title": "Invariant violation",
                    }
                ],
                "summary": {"HIGH": 1, "total": 1},
                "metadata": {"agentic_invariants_count": 1},
            }

    audit_module = importlib.import_module("miesc.cli.commands.audit")
    monkeypatch.setattr("src.agents.deep_audit_agent.DeepAuditAgent", FakeAgent)
    monkeypatch.setattr(
        audit_module,
        "run_tool",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("run_tool called")),
    )

    result = CliRunner().invoke(
        audit_profile,
        ["paper1-evmbench-ensemble", str(contract), "-o", str(output)],
    )

    assert result.exit_code == 0, result.output
    assert seen["contract"] == str(contract)
    assert seen["config"].enable_agentic_invariants is True
    assert seen["config"].agentic_invariants_allow_remote is False

    data = json.loads(output.read_text())
    assert data["agentic"] is True
    assert data["summary"]["HIGH"] == 1
    assert data["results"][0]["tool"] == "miesc-agentic-profile"


def test_audit_profile_non_agentic_still_uses_tool_loop(monkeypatch, tmp_path):
    contract = tmp_path / "Vault.sol"
    output = tmp_path / "report.json"
    contract.write_text("pragma solidity ^0.8.20; contract Vault {}")
    tools_seen = []

    def fake_run_tool(tool, contract_path, timeout):
        tools_seen.append(tool)
        return {
            "tool": tool,
            "contract": contract_path,
            "status": "success",
            "findings": [],
            "execution_time": 0.0,
        }

    audit_module = importlib.import_module("miesc.cli.commands.audit")
    monkeypatch.setattr(audit_module, "run_tool", fake_run_tool)

    result = CliRunner().invoke(audit_profile, ["fast", str(contract), "-o", str(output)])

    assert result.exit_code == 0, result.output
    assert tools_seen == ["slither", "solhint"]
    data = json.loads(output.read_text())
    assert "agentic" not in data
