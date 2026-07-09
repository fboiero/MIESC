from __future__ import annotations

import json
from types import SimpleNamespace

from click.testing import CliRunner

import miesc.cli.commands.remediate as remediate_module
from miesc.cli.commands.remediate import remediate
from miesc.cli.main import cli

SIMPLE_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Victim {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""


def test_remediate_command_writes_patch_and_evidence(tmp_path):
    contract = tmp_path / "Victim.sol"
    contract.write_text(SIMPLE_CONTRACT)
    results = tmp_path / "results.json"
    results.write_text(
        json.dumps(
            {
                "contract": str(contract),
                "findings": [
                    {
                        "type": "reentrancy",
                        "function": "withdraw",
                        "severity": "High",
                        "fix_code": "add nonReentrant",
                    }
                ],
            }
        )
    )
    out_dir = tmp_path / "out"

    runner = CliRunner()
    result = runner.invoke(
        remediate,
        [str(results), "-c", str(contract), "-o", str(out_dir), "--quiet"],
    )

    assert result.exit_code == 0
    patched = out_dir / "Victim.fixed.sol"
    evidence_path = out_dir / "Victim.fixed.evidence.json"
    assert patched.exists()
    assert evidence_path.exists()
    assert "nonReentrant" in patched.read_text()

    evidence = json.loads(evidence_path.read_text())
    assert evidence["status"] == "patch_applied"
    assert evidence["fixes_applied"] == 1
    assert evidence["compile"]["checked"] is False
    assert evidence["rescan"]["checked"] is False


def test_remediate_command_handles_no_fixable_findings(tmp_path):
    contract = tmp_path / "Victim.sol"
    contract.write_text(SIMPLE_CONTRACT)
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"findings": [{"type": "reentrancy"}]}))

    runner = CliRunner()
    result = runner.invoke(
        remediate,
        [str(results), "-c", str(contract), "-o", str(tmp_path / "out"), "--quiet"],
    )

    assert result.exit_code == 0
    assert not (tmp_path / "out" / "Victim.fixed.sol").exists()
    assert (tmp_path / "out" / "Victim.fixed.evidence.json").exists()


def test_remediate_paper2_profile_requires_compile_and_rescan(tmp_path, monkeypatch):
    contract = tmp_path / "Victim.sol"
    contract.write_text(SIMPLE_CONTRACT)
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"findings": []}))
    captured = {}

    class FakeEvidence:
        status = "rescan_checked"
        fixes_applied = 1
        compile = SimpleNamespace(checked=True, compiles=True)
        rescan = SimpleNamespace(checked=True, eliminated=True, no_regression=True)

        def to_dict(self):
            return {
                "status": self.status,
                "fixes_applied": self.fixes_applied,
                "compile": {"checked": True},
                "rescan": {"checked": True},
            }

    def fake_remediate_contract(**kwargs):
        captured.update(kwargs)
        return FakeEvidence()

    monkeypatch.setattr(remediate_module, "remediate_contract", fake_remediate_contract)

    runner = CliRunner()
    result = runner.invoke(
        remediate,
        [str(results), "-c", str(contract), "--profile", "paper2", "--quiet"],
    )

    assert result.exit_code == 0
    assert captured["compile_check"] is True
    assert captured["rescan_check"] is True


def test_remediate_unknown_profile_exits_nonzero(tmp_path):
    contract = tmp_path / "Victim.sol"
    contract.write_text(SIMPLE_CONTRACT)
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"findings": []}))

    runner = CliRunner()
    result = runner.invoke(
        remediate,
        [str(results), "-c", str(contract), "--profile", "missing-profile"],
    )

    assert result.exit_code != 0
    assert "Unknown profile: missing-profile" in result.output


def test_remediate_is_registered_in_main_cli():
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "--help"])
    assert result.exit_code == 0
    assert "remediate" in result.output
