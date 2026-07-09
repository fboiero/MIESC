"""Tests for MCP profile resolution."""

from miesc.mcp_server import _resolve_profile_layers


def test_mcp_resolves_paper_profile_from_shared_config():
    profile, available = _resolve_profile_layers("paper1-evmbench-ensemble")

    assert profile is not None
    assert profile["target_metric"]["corpus"] == "evmbench"
    assert profile["agentic_ensemble"]["provider_contract"] == "reasoning_provider"
    assert "paper1-evmbench-ensemble" in available


def test_mcp_keeps_legacy_profile_aliases():
    profile, available = _resolve_profile_layers("formal")

    assert profile is not None
    assert profile["description"] == "Security-focused with formal verification emphasis"
    assert "formal" in available
