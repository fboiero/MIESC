"""Tests for paper performance profiles."""

from miesc.cli.utils import get_profile


def test_paper_profiles_are_loadable_by_name_and_alias():
    smartbugs = get_profile("paper1-smartbugs")
    evmbench = get_profile("evmbench-paper")
    remediation = get_profile("paper2")

    assert smartbugs["target_metric"]["corpus"] == "smartbugs"
    assert evmbench["target_metric"]["corpus"] == "evmbench"
    assert remediation["remediation_evidence"]["require_compile"] is True


def test_evmbench_profile_uses_provider_neutral_agent_contract():
    profile = get_profile("paper1-evmbench-ensemble")
    ensemble = profile["agentic_ensemble"]
    serialized = repr(ensemble).lower()

    assert ensemble["provider_contract"] == "reasoning_provider"
    assert ensemble["local_first"] is True
    assert ensemble["allow_remote"] is False
    assert "invariant_extraction" in ensemble["capabilities"]
    assert "deepseek" not in serialized
    assert "openai" not in serialized
    assert "anthropic" not in serialized
    assert "claude" not in serialized
