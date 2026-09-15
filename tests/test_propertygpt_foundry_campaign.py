from subprocess import CompletedProcess
from unittest.mock import patch

from miesc.adapters.propertygpt_adapter import PropertyGPTAdapter

HARNESS = """pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Vault} from "@repo/src/Vault.sol";
contract VaultHandler { function deposit(uint256) public {} function withdraw(uint256) public {} }
contract VaultInvariant is StdInvariant, Test {
    VaultHandler handler;
    function setUp() public { handler = new VaultHandler(); targetContract(address(handler)); }
    function invariant_assetsRemainSafe() public pure { assertTrue(true); }
}
"""


def test_generated_campaign_repairs_once_and_keeps_counterexample(tmp_path):
    root = tmp_path / "repo"
    contract = root / "src" / "Vault.sol"
    contract.parent.mkdir(parents=True)
    contract.write_text("pragma solidity ^0.8.20; contract Vault {}", encoding="utf-8")
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    project = tmp_path / "campaign"
    (project / "test").mkdir(parents=True)
    adapter = PropertyGPTAdapter({"enable_validation": False})
    run = {
        "status": "success",
        "tests_run": 1,
        "tests_passed": 0,
        "tests_failed": 1,
        "calls_executed": 2,
        "findings": [
            {
                "description": "invariant failed",
                "counterexample": {"Sequence": [{"calldata": "deposit(1)"}]},
            }
        ],
    }

    with (
        patch("shutil.which", return_value="/usr/bin/forge"),
        patch("miesc.poc.foundry_scaffold.scaffold_foundry_project", return_value=project),
        patch.object(adapter, "_generate_foundry_harness", return_value=HARNESS),
        patch.object(adapter, "_repair_foundry_harness", return_value=HARNESS),
        patch.object(adapter, "_compile_foundry", side_effect=[(False, "bad import"), (True, "")]),
        patch.object(
            adapter,
            "_run_foundry_coverage",
            return_value={"status": "success", "summary": "Total | 80%"},
        ),
        patch("miesc.adapters.foundry_adapter.FoundryAdapter.analyze", return_value=run),
    ):
        result = adapter._run_foundry_campaign(
            contract,
            contract.read_text(),
            {"name": "Vault"},
            [{"name": "assetsRemainSafe"}],
            timeout=30,
        )

    assert result["status"] == "counterexample"
    assert result["repairs_used"] == 1
    assert result["calls_executed"] == 2
    assert result["findings"][0]["type"] == "generated_invariant_violation"
    assert result["findings"][0]["counterexample"]["Sequence"]
    assert result["harness"] == HARNESS
    assert not project.exists()


def test_generated_harness_rejects_external_io():
    assert (
        "forbidden"
        in PropertyGPTAdapter._validate_foundry_harness(
            HARNESS.replace("assertTrue(true);", "vm.ffi(new string[](0));")
        ).lower()
    )


def test_vault_delay_property_uses_compilable_stateful_template():
    source = """contract Vault {
        mapping(address => uint256) public deposits;
        function deposit() public payable {}
        function withdraw(uint256 amount) public {}
        function isWithdrawAllowed(address user) public view returns (bool) {}
    }"""
    harness = PropertyGPTAdapter._known_foundry_harness(
        source,
        "Vault",
        "@repo/src/Vault.sol",
        [{"name": "withdrawDelay", "description": "enforce withdrawal delay"}],
    )

    assert "contract VaultHandler" in harness
    assert "target.deposit{value: amount}()" in harness
    assert "target.withdraw(amount)" in harness
    assert "invariant_withdrawDelayIsEnforced" in harness
    assert PropertyGPTAdapter._validate_foundry_harness(harness) is None


def test_failed_campaign_without_counterexample_stays_inconclusive(tmp_path):
    root = tmp_path / "repo"
    contract = root / "src" / "Vault.sol"
    contract.parent.mkdir(parents=True)
    contract.write_text("pragma solidity ^0.8.20; contract Vault {}", encoding="utf-8")
    (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    project = tmp_path / "campaign"
    (project / "test").mkdir(parents=True)
    adapter = PropertyGPTAdapter()
    run = {
        "tests_run": 1,
        "tests_passed": 0,
        "tests_failed": 1,
        "calls_executed": 2,
        "findings": [{"description": "failed without a replayable sequence"}],
    }

    with (
        patch("shutil.which", return_value="/usr/bin/forge"),
        patch("miesc.poc.foundry_scaffold.scaffold_foundry_project", return_value=project),
        patch.object(adapter, "_generate_foundry_harness", return_value=HARNESS),
        patch.object(adapter, "_repair_foundry_harness", return_value=HARNESS),
        patch.object(adapter, "_compile_foundry", return_value=(True, "")),
        patch.object(
            adapter,
            "_run_foundry_coverage",
            return_value={"status": "success", "summary": "Total | 80%"},
        ),
        patch("miesc.adapters.foundry_adapter.FoundryAdapter.analyze", return_value=run),
    ):
        result = adapter._run_foundry_campaign(
            contract,
            contract.read_text(),
            {"name": "Vault"},
            [{"name": "assetsRemainSafe"}],
            timeout=30,
        )

    assert result["status"] == "inconclusive"
    assert result["findings"] == []


def test_coverage_is_kept_when_an_invariant_fails(tmp_path):
    output = "| Total | 80.00% (8/10) | 75.00% (6/8) | 50.00% (1/2) | 100.00% (3/3) |"
    adapter = PropertyGPTAdapter({"foundry_fuzz_runs": 8})

    with patch("subprocess.run", return_value=CompletedProcess([], 1, output, "")):
        coverage = adapter._run_foundry_coverage(
            tmp_path, tmp_path / "test" / "Invariant.t.sol", "0x01", 30
        )

    assert coverage["status"] == "success"
    assert coverage["percent"] == {
        "lines": 80.0,
        "statements": 75.0,
        "branches": 50.0,
        "functions": 100.0,
    }
