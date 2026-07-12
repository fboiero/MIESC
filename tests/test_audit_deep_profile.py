"""Tests for deep audit profile wiring."""

import pytest
from click.testing import CliRunner

from miesc.cli.commands.audit import _apply_deep_profile_config, audit_deep
from miesc.agents.deep_audit_agent import DeepAuditConfig


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
