"""Tests for deep audit profile wiring."""

import pytest
from click.testing import CliRunner

from miesc.agents.deep_audit_agent import DeepAuditConfig
from miesc.cli.commands.audit import _apply_deep_profile_config, _smart_audit_tools, audit_deep


def test_deep_audit_profile_enables_agentic_invariants_without_remote():
    config = DeepAuditConfig(
        timeout_seconds=30,
        max_iterations=1,
        enable_agentic_invariants=False,
        agentic_invariants_allow_remote=True,
        llm_provider="ollama",
    )

    updated, profile = _apply_deep_profile_config(config, "paper1-evmbench-ensemble")

    assert updated is config
    assert profile["target_metric"]["corpus"] == "evmbench"
    assert updated.timeout_seconds == 1200
    assert updated.enable_agentic_invariants is True
    assert updated.agentic_invariants_allow_remote is False
    assert updated.llm_provider == "auto"


def test_deep_audit_profile_rejects_unknown_profile():
    with pytest.raises(Exception, match="Profile 'missing-profile' not found"):
        _apply_deep_profile_config(DeepAuditConfig(), "missing-profile")


def test_smart_audit_adds_foundry_for_foundry_projects(tmp_path):
    contract = tmp_path / "src" / "Vault.sol"
    contract.parent.mkdir()
    contract.write_text("pragma solidity ^0.8.20; contract Vault {}")
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n')

    tools = _smart_audit_tools(str(contract))
    assert "foundry" in tools
    assert "propertygpt" in tools


def test_deep_audit_selects_property_generation_by_default():
    from miesc.agents.deep_audit_agent import DeepAuditAgent, ReconResult

    assert "propertygpt" in DeepAuditAgent()._select_tools(ReconResult())


def test_deep_audit_cli_applies_profile_to_agent_config(monkeypatch, tmp_path):
    contract = tmp_path / "Vault.sol"
    contract.write_text("pragma solidity ^0.8.20; contract Vault {}")
    seen = {}

    class FakeAgent:
        def __init__(self, config):
            seen["config"] = config

        def analyze(self, contract_path):
            seen["contract"] = contract_path
            return {
                "summary": {"total": 0},
                "phases": {"reconnaissance": {"risk_profile": {"primary": "general"}}},
                "findings": [],
                "exploit_chains": [],
                "narrative": "",
            }

    monkeypatch.setattr("miesc.agents.deep_audit_agent.DeepAuditAgent", FakeAgent)

    result = CliRunner().invoke(
        audit_deep,
        [str(contract), "--profile", "paper1-evmbench-ensemble", "--no-llm", "--no-rag"],
    )

    assert result.exit_code == 0, result.output
    assert seen["contract"] == str(contract)
    assert seen["config"].timeout_seconds == 1200
    assert seen["config"].enable_agentic_invariants is True
    assert seen["config"].agentic_invariants_allow_remote is False
    assert seen["config"].enable_llm is False
    assert seen["config"].enable_rag is False


def test_deep_reasoning_timeout_flag_reaches_config(monkeypatch, tmp_path):
    # Before this flag existed, deep_reasoning_timeout was hardcoded at 1200s
    # regardless of protocol size (1 file vs. dozens) - see MEJORAS4.md #3.
    contract = tmp_path / "Vault.sol"
    contract.write_text("pragma solidity ^0.8.20; contract Vault {}")
    seen = {}

    class FakeAgent:
        def __init__(self, config):
            seen["config"] = config

        def analyze(self, contract_path):
            return {
                "summary": {"total": 0},
                "phases": {"reconnaissance": {"risk_profile": {"primary": "general"}}},
                "findings": [],
                "exploit_chains": [],
                "narrative": "",
            }

    monkeypatch.setattr("miesc.agents.deep_audit_agent.DeepAuditAgent", FakeAgent)

    result = CliRunner().invoke(
        audit_deep,
        [str(contract), "--no-llm", "--no-rag", "--deep-reasoning-timeout", "3000"],
    )

    assert result.exit_code == 0, result.output
    assert seen["config"].deep_reasoning_timeout == 3000


def test_deep_reasoning_timeout_defaults_to_1200(monkeypatch, tmp_path):
    contract = tmp_path / "Vault.sol"
    contract.write_text("pragma solidity ^0.8.20; contract Vault {}")
    seen = {}

    class FakeAgent:
        def __init__(self, config):
            seen["config"] = config

        def analyze(self, contract_path):
            return {
                "summary": {"total": 0},
                "phases": {"reconnaissance": {"risk_profile": {"primary": "general"}}},
                "findings": [],
                "exploit_chains": [],
                "narrative": "",
            }

    monkeypatch.setattr("miesc.agents.deep_audit_agent.DeepAuditAgent", FakeAgent)

    result = CliRunner().invoke(audit_deep, [str(contract), "--no-llm", "--no-rag"])

    assert result.exit_code == 0, result.output
    assert seen["config"].deep_reasoning_timeout == 1200
