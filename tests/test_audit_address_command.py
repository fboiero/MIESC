"""End-to-end wiring test for `miesc audit address` - fetch is mocked (no
network), DeepAuditAgent is faked (no real tools), verifying only that the
command chains fetch -> write -> audit_deep correctly."""

from unittest.mock import patch

from click.testing import CliRunner

from miesc.cli.commands.audit import audit
from miesc.core.block_explorer import BlockExplorerError, FetchedContract, NotVerifiedError
from miesc.core.chain_abstraction import ChainType


def _fake_contract(**overrides):
    defaults = {
        "address": "0xabc",
        "chain": ChainType.ETHEREUM,
        "contract_name": "Vault",
        "compiler_version": "v0.8.20",
        "files": {"Vault.sol": "contract Vault {}"},
    }
    defaults.update(overrides)
    return FetchedContract(**defaults)


class TestAuditAddressCommand:
    def test_not_verified_fails_clearly(self):
        with patch(
            "miesc.core.block_explorer.fetch_verified_source",
            side_effect=NotVerifiedError(
                "0xabc on ethereum has no verified source on this explorer."
            ),
        ):
            result = CliRunner().invoke(audit, ["address", "0xabc"])
        assert result.exit_code != 0
        assert "no verified source" in result.output

    def test_explorer_error_fails_clearly(self):
        with patch(
            "miesc.core.block_explorer.fetch_verified_source",
            side_effect=BlockExplorerError("Invalid API Key"),
        ):
            result = CliRunner().invoke(audit, ["address", "0xabc", "--api-key", "bad"])
        assert result.exit_code != 0
        assert "Invalid API Key" in result.output

    def test_verified_contract_reaches_deep_audit(self, tmp_path):
        seen = {}

        class FakeAgent:
            def __init__(self, config):
                seen["config"] = config

            def analyze(self, contract_path):
                # Read the fetched file here, inside the CLI command's own
                # `with tempfile.TemporaryDirectory()` block - it's cleaned
                # up by the time CliRunner().invoke() below returns.
                from pathlib import Path

                seen["vault_sol"] = (Path(contract_path) / "Vault.sol").read_text()
                return {
                    "summary": {"total": 0},
                    "phases": {"reconnaissance": {"risk_profile": {"primary": "general"}}},
                    "findings": [],
                    "exploit_chains": [],
                    "narrative": "",
                }

        with (
            patch("miesc.core.block_explorer.fetch_verified_source", return_value=_fake_contract()),
            patch("miesc.agents.deep_audit_agent.DeepAuditAgent", FakeAgent),
        ):
            result = CliRunner().invoke(audit, ["address", "0xabc", "--api-key", "k"])

        assert result.exit_code == 0, result.output
        assert seen["config"].enable_deep_reasoning is False
        assert seen["vault_sol"] == "contract Vault {}"

    def test_deep_reasoning_flag_passed_through(self):
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

        with (
            patch("miesc.core.block_explorer.fetch_verified_source", return_value=_fake_contract()),
            patch("miesc.agents.deep_audit_agent.DeepAuditAgent", FakeAgent),
        ):
            result = CliRunner().invoke(audit, ["address", "0xabc", "--deep-reasoning"])

        assert result.exit_code == 0, result.output
        assert seen["config"].enable_deep_reasoning is True
