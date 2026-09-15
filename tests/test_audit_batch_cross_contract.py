"""
CLI smoke test for cross-contract exploit chain detection in `miesc audit batch`
(MEJORAS.md item #5b).

Mocks `run_tool` (the tool-execution boundary) rather than depending on a real
static analyzer flagging something in a hand-crafted fixture — same pattern as
tests/test_scan_diff.py.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from miesc.cli.commands.audit import audit

BASE_SOL = "pragma solidity ^0.8.0;\ncontract Base is Initializable {}\n"
DERIVED_SOL = (
    'pragma solidity ^0.8.0;\nimport "./Base.sol";\ncontract Derived is Base {\n'
    "    function foo() external {}\n}\n"
)
ROUTER_SOL = (
    'pragma solidity ^0.8.0;\nimport "./Derived.sol";\n'
    "interface IDerived { function foo() external; }\n"
    "contract Router {\n"
    "    function callDerived(address x) external { IDerived(x).foo(); }\n"
    "}\n"
)


def _write_fixture(tmp_path: Path) -> None:
    (tmp_path / "Base.sol").write_text(BASE_SOL)
    (tmp_path / "Derived.sol").write_text(DERIVED_SOL)
    (tmp_path / "Router.sol").write_text(ROUTER_SOL)


def _fake_run_tool(tool: str, contract: str, timeout: int = 0) -> dict:
    findings = []
    if tool == "slither" and contract.endswith("Derived.sol"):
        findings = [
            {
                "id": "f1",
                "tool": tool,
                "type": "access_control",
                "severity": "high",
                "message": "missing access control on foo",
                "location": {"file": contract, "line": 3},
            }
        ]
    return {"tool": tool, "contract": contract, "status": "success", "findings": findings}


class TestAuditBatchCrossContractChains:
    def test_chain_detected_and_included_in_json_output(self, tmp_path):
        _write_fixture(tmp_path)
        out_file = tmp_path / "batch.json"
        runner = CliRunner()

        with patch("miesc.cli.commands.audit.run_tool", side_effect=_fake_run_tool):
            result = runner.invoke(audit, ["batch", str(tmp_path), "-o", str(out_file)])

        assert result.exit_code == 0, result.output
        report = json.loads(out_file.read_text())
        assert "cross_contract_chains" in report
        chains = report["cross_contract_chains"]
        assert len(chains) == 1
        assert chains[0]["contracts"] == ["Router", "Derived"]

    def test_single_file_has_empty_chains_no_crash(self, tmp_path):
        (tmp_path / "Solo.sol").write_text(DERIVED_SOL)
        out_file = tmp_path / "batch.json"
        runner = CliRunner()

        with patch("miesc.cli.commands.audit.run_tool", side_effect=_fake_run_tool):
            result = runner.invoke(audit, ["batch", str(tmp_path), "-o", str(out_file)])

        assert result.exit_code == 0, result.output
        report = json.loads(out_file.read_text())
        assert report["cross_contract_chains"] == []
