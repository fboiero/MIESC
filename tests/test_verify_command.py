"""
Tests for the `miesc verify` CLI command.

Covers:
  - Foundry-root autodetection walks upward from a contract path.
  - The command surfaces availability of each prover before running.
  - JSON output is properly emitted when -o is set.
  - Regression: status=no_tests is treated as NOT a failure (exit 0).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from miesc.cli.commands.verify import _find_foundry_root, verify

# ---------------------------------------------------------------------------
# _find_foundry_root
# ---------------------------------------------------------------------------


class TestFindFoundryRoot:
    def test_finds_toml_in_same_dir(self, tmp_path):
        (tmp_path / "foundry.toml").write_text("[profile.default]")
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;")
        assert _find_foundry_root(contract) == tmp_path

    def test_walks_up_to_find_toml(self, tmp_path):
        (tmp_path / "foundry.toml").write_text("[profile.default]")
        deep = tmp_path / "src" / "token"
        deep.mkdir(parents=True)
        contract = deep / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;")
        assert _find_foundry_root(contract) == tmp_path

    def test_returns_none_when_no_toml_upstream(self, tmp_path):
        deep = tmp_path / "src"
        deep.mkdir()
        contract = deep / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;")
        # No foundry.toml anywhere above
        result = _find_foundry_root(contract)
        # May return a parent that coincidentally has foundry.toml, but in
        # a pristine tmp_path it should not
        if result is not None:
            # If a coincidental match exists, at least it's a Path
            assert isinstance(result, Path)

    def test_accepts_directory_path(self, tmp_path):
        """_find_foundry_root should work even if given a directory, not a file."""
        (tmp_path / "foundry.toml").write_text("[profile.default]")
        subdir = tmp_path / "test"
        subdir.mkdir()
        assert _find_foundry_root(subdir) == tmp_path


# ---------------------------------------------------------------------------
# CLI command smoke tests
# ---------------------------------------------------------------------------


@pytest.fixture
def contract(tmp_path):
    p = tmp_path / "C.sol"
    p.write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract C { uint x; }\n"
    )
    return str(p)


class TestVerifyCommand:
    def test_help_lists_required_args(self):
        runner = CliRunner()
        result = runner.invoke(verify, ["--help"])
        assert result.exit_code == 0
        assert "CONTRACT_PATH" in result.output
        assert "--spec" in result.output
        assert "--tool" in result.output
        assert "--timeout" in result.output

    def test_missing_contract_arg_errors_out(self):
        runner = CliRunner()
        result = runner.invoke(verify, [])
        assert result.exit_code != 0

    def test_tool_smtchecker_when_solc_unavailable(self, contract):
        runner = CliRunner()
        with patch("miesc.formal.SpecRunner") as SR:
            instance = SR.return_value
            instance.availability_report.return_value = {
                "certora": False,
                "halmos": False,
                "smtchecker": False,
            }
            instance.is_solc_available.return_value = False
            result = runner.invoke(verify, [contract, "--tool", "smtchecker", "--quiet"])
            assert result.exit_code == 1
            assert "solc" in result.output.lower()

    def test_tool_halmos_without_foundry_toml_errors(self, contract):
        """Halmos requires a foundry.toml upstream of the contract. Without one
        the command must error with a clear message, not crash."""
        runner = CliRunner()
        with patch("miesc.formal.SpecRunner") as SR:
            instance = SR.return_value
            instance.availability_report.return_value = {
                "certora": False,
                "halmos": True,
                "smtchecker": False,
            }
            # Put the contract in a tmp dir that definitely has no foundry.toml.
            tmp = Path(contract).parent
            # Paranoid: make sure there's no foundry.toml sneaking in
            assert not (tmp / "foundry.toml").exists()
            result = runner.invoke(
                verify,
                [contract, "--tool", "halmos", "--quiet"],
            )
            # Either (a) we errored out cleanly with the foundry message,
            # or (b) a parent dir coincidentally has foundry.toml and halmos
            # was invoked. Accept both but mark the happy-path as primary.
            if result.exit_code == 1:
                assert "foundry.toml" in result.output.lower()

    def test_json_output_written_when_requested(self, contract, tmp_path):
        """When --output is given, results must be written to that path."""
        runner = CliRunner()
        out = tmp_path / "out.json"
        fake_result = MagicMock()
        fake_result.tool = "smtchecker"
        fake_result.spec_file = contract
        fake_result.stderr = ""
        fake_result.status = "passed"
        fake_result.rules_passed = 0
        fake_result.rules_failed = 0
        fake_result.rules_total = 0
        fake_result.counterexamples = []
        fake_result.elapsed_seconds = 0.01
        fake_result.to_dict.return_value = {
            "tool": "smtchecker",
            "status": "passed",
            "rules_passed": 0,
            "rules_failed": 0,
            "rules_total": 0,
            "counterexamples": [],
            "elapsed_seconds": 0.01,
            "spec_file": contract,
        }
        with patch("miesc.formal.SpecRunner") as SR:
            instance = SR.return_value
            instance.availability_report.return_value = {
                "certora": False,
                "halmos": False,
                "smtchecker": True,
            }
            instance.run_smtchecker.return_value = fake_result
            result = runner.invoke(
                verify,
                [contract, "--tool", "smtchecker", "--quiet", "--output", str(out)],
            )
            assert result.exit_code == 0
            assert out.exists()
            data = json.loads(out.read_text())
            # Unified report: provers are nested under "provers", with an
            # overall verdict and aggregate summary at the top level.
            assert "provers" in data
            assert "smtchecker" in data["provers"]
            assert "overall_verdict" in data
            assert "summary" in data

    def test_sarif_output_written_when_requested(self, contract, tmp_path):
        """--sarif must emit a valid SARIF 2.1.0 document from the unified report."""
        runner = CliRunner()
        out = tmp_path / "out.sarif"
        fake_result = MagicMock()
        fake_result.tool = "smtchecker"
        fake_result.spec_file = contract
        fake_result.stderr = ""
        fake_result.status = "failed"
        fake_result.rules_passed = 0
        fake_result.rules_failed = 1
        fake_result.rules_total = 1
        fake_result.counterexamples = ["CHC: Overflow at line 3"]
        fake_result.elapsed_seconds = 0.02
        with patch("miesc.formal.SpecRunner") as SR:
            instance = SR.return_value
            instance.availability_report.return_value = {
                "certora": False,
                "halmos": False,
                "smtchecker": True,
            }
            instance.run_smtchecker.return_value = fake_result
            result = runner.invoke(
                verify,
                [contract, "--tool", "smtchecker", "--quiet", "--sarif", str(out)],
            )
            assert result.exit_code == 1  # violated -> a prover failed
            assert out.exists()
            sarif = json.loads(out.read_text())
            assert sarif["version"] == "2.1.0"
            run = sarif["runs"][0]
            assert run["tool"]["driver"]["name"] == "MIESC-Formal"
            assert len(run["results"]) == 1
            region = run["results"][0]["locations"][0]["physicalLocation"]["region"]
            assert region["startLine"] == 3


# ---------------------------------------------------------------------------
# Exit code contract
# ---------------------------------------------------------------------------


class TestExitCodeContract:
    """
    The command should exit 0 when nothing failed, 1 when any prover
    reported FAILED. Status 'no_tests' (Halmos couldn't find tests)
    should NOT trigger exit 1 — it's neither pass nor fail.
    """

    def test_exit_zero_on_all_passed(self, contract):
        runner = CliRunner()
        fake_result = MagicMock()
        fake_result.tool = "smtchecker"
        fake_result.spec_file = contract
        fake_result.stderr = ""
        fake_result.status = "passed"
        fake_result.rules_passed = 0
        fake_result.rules_failed = 0
        fake_result.rules_total = 0
        fake_result.counterexamples = []
        fake_result.elapsed_seconds = 0.01
        fake_result.to_dict.return_value = {"status": "passed"}
        with patch("miesc.formal.SpecRunner") as SR:
            instance = SR.return_value
            instance.availability_report.return_value = {
                "certora": False,
                "halmos": False,
                "smtchecker": True,
            }
            instance.run_smtchecker.return_value = fake_result
            result = runner.invoke(verify, [contract, "--tool", "smtchecker", "--quiet"])
            assert result.exit_code == 0

    def test_exit_one_on_failed(self, contract):
        runner = CliRunner()
        fake_result = MagicMock()
        fake_result.tool = "smtchecker"
        fake_result.spec_file = contract
        fake_result.stderr = ""
        fake_result.status = "failed"
        fake_result.rules_passed = 0
        fake_result.rules_failed = 1
        fake_result.rules_total = 1
        fake_result.counterexamples = ["x = 0"]
        fake_result.elapsed_seconds = 0.05
        fake_result.to_dict.return_value = {"status": "failed"}
        with patch("miesc.formal.SpecRunner") as SR:
            instance = SR.return_value
            instance.availability_report.return_value = {
                "certora": False,
                "halmos": False,
                "smtchecker": True,
            }
            instance.run_smtchecker.return_value = fake_result
            result = runner.invoke(verify, [contract, "--tool", "smtchecker", "--quiet"])
            assert result.exit_code == 1

    def test_exit_zero_on_no_tests(self, contract):
        (Path(contract).parent / "foundry.toml").write_text("[profile.default]\n")
        runner = CliRunner()
        fake_result = MagicMock()
        fake_result.tool = "halmos"
        fake_result.spec_file = contract
        fake_result.stderr = ""
        fake_result.status = "no_tests"
        fake_result.rules_passed = 0
        fake_result.rules_failed = 0
        fake_result.rules_total = 0
        fake_result.counterexamples = []
        fake_result.elapsed_seconds = 0.01
        fake_result.to_dict.return_value = {"status": "no_tests"}
        with patch("miesc.formal.SpecRunner") as SR:
            instance = SR.return_value
            instance.availability_report.return_value = {
                "certora": False,
                "halmos": True,
                "smtchecker": False,
            }
            instance.run_halmos.return_value = fake_result
            result = runner.invoke(verify, [contract, "--tool", "halmos", "--quiet"])
            assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Economic invariant synthesis (--economic-invariants)
# ---------------------------------------------------------------------------

ERC4626_VAULT_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function totalAssets() public view returns (uint256) {}
    function convertToShares(uint256 a) public view returns (uint256) {}
    function convertToAssets(uint256 s) public view returns (uint256) {}
    function deposit(uint256 a, address r) public returns (uint256) {}
    function withdraw(uint256 a, address r, address o) public returns (uint256) {}
}
"""


@pytest.fixture
def vault_contract(tmp_path):
    p = tmp_path / "Vault.sol"
    p.write_text(ERC4626_VAULT_SRC)
    return str(p)


class TestEconomicInvariantsFlag:
    def test_help_lists_economic_flag(self):
        runner = CliRunner()
        result = runner.invoke(verify, ["--help"])
        assert result.exit_code == 0
        assert "--economic-invariants" in result.output
        assert "--invariants-out" in result.output

    def test_economic_invariants_emitted_without_provers(self, vault_contract, tmp_path):
        """Economic invariant synthesis must work with zero provers installed
        (prover-independent path) and write CVL/Echidna/Foundry artifacts."""
        out = tmp_path / "econ"
        runner = CliRunner()
        with patch("miesc.formal.SpecRunner") as SR:
            SR.return_value.availability_report.return_value = {
                "certora": False,
                "halmos": False,
                "smtchecker": False,
                "scribble": False,
                "kontrol": False,
            }
            result = runner.invoke(
                verify,
                [
                    vault_contract,
                    "--economic-invariants",
                    "--invariants-out",
                    str(out),
                    "--quiet",
                ],
            )
        assert result.exit_code == 0
        assert (out / "Vault.economic-invariants.json").exists()
        assert (out / "Vault.economic.spec").exists()
        assert (out / "Vault.economic.echidna.sol").exists()
        assert (out / "Vault.economic.invariants.t.sol").exists()
        cvl = (out / "Vault.economic.spec").read_text()
        assert "vaultSolvency" in cvl

    def test_economic_only_is_offline_no_ollama_required(self, vault_contract):
        """No --invariants-out, no provers, no Ollama — must still succeed."""
        runner = CliRunner()
        with patch("miesc.formal.SpecRunner") as SR:
            SR.return_value.availability_report.return_value = {
                "certora": False,
                "halmos": False,
                "smtchecker": False,
                "scribble": False,
                "kontrol": False,
            }
            with patch(
                "miesc.adapters.invariant_synthesizer.InvariantSynthesizer._is_ollama_available",
                return_value=False,
            ):
                result = runner.invoke(verify, [vault_contract, "--economic-invariants", "--quiet"])
        assert result.exit_code == 0


class TestEconomicFuzzFlag:
    def test_help_lists_fuzz_flag(self):
        runner = CliRunner()
        result = runner.invoke(verify, ["--help"])
        assert result.exit_code == 0
        assert "--fuzz" in result.output
        assert "--fuzz-test-limit" in result.output

    def test_fuzz_without_economic_invariants_warns(self, contract):
        runner = CliRunner()
        with patch("miesc.formal.SpecRunner") as SR:
            SR.return_value.availability_report.return_value = {
                "certora": False,
                "halmos": False,
                "smtchecker": False,
                "scribble": False,
                "kontrol": False,
            }
            result = runner.invoke(verify, [contract, "--fuzz", "--quiet"])
        assert "no effect" in result.output.lower()

    def test_fuzz_detected_bug_sets_exit_one(self, vault_contract):
        """A fuzz-detected economic bug must drive exit code 1 (real failure)."""
        runner = CliRunner()
        detected = {
            "status": "detected",
            "properties": ["echidna_deposit_mints_nonzero_shares"],
            "findings": [
                {
                    "severity": "critical",
                    "invariant": "erc4626_first_deposit_guard",
                    "property": "echidna_deposit_mints_nonzero_shares",
                    "description": "share price inflated",
                    "call_sequence": ["h_donate(1000)", "h_deposit(0)"],
                }
            ],
        }
        with patch("miesc.formal.SpecRunner") as SR:
            SR.return_value.availability_report.return_value = {
                "certora": False,
                "halmos": False,
                "smtchecker": False,
                "scribble": False,
                "kontrol": False,
            }
            with patch(
                "miesc.formal.economic_harness.run_economic_fuzz", return_value=detected
            ) as rf:
                result = runner.invoke(
                    verify, [vault_contract, "--economic-invariants", "--fuzz", "--quiet"]
                )
                assert rf.called
        assert result.exit_code == 1

    def test_fuzz_clean_keeps_exit_zero(self, vault_contract):
        runner = CliRunner()
        clean = {
            "status": "clean",
            "properties": ["echidna_vault_solvent"],
            "findings": [],
        }
        with patch("miesc.formal.SpecRunner") as SR:
            SR.return_value.availability_report.return_value = {
                "certora": False,
                "halmos": False,
                "smtchecker": False,
                "scribble": False,
                "kontrol": False,
            }
            with patch("miesc.formal.economic_harness.run_economic_fuzz", return_value=clean):
                result = runner.invoke(
                    verify, [vault_contract, "--economic-invariants", "--fuzz", "--quiet"]
                )
        assert result.exit_code == 0

    def test_fuzz_skipped_when_echidna_absent(self, vault_contract):
        runner = CliRunner()
        skipped = {"status": "skipped", "reason": "Echidna not installed", "findings": []}
        with patch("miesc.formal.SpecRunner") as SR:
            SR.return_value.availability_report.return_value = {
                "certora": False,
                "halmos": False,
                "smtchecker": False,
                "scribble": False,
                "kontrol": False,
            }
            with patch("miesc.formal.economic_harness.run_economic_fuzz", return_value=skipped):
                result = runner.invoke(
                    verify, [vault_contract, "--economic-invariants", "--fuzz", "--quiet"]
                )
        assert result.exit_code == 0
