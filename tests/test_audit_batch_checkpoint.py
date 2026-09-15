"""
CLI test for checkpoint/resume in `miesc audit batch` (MEJORAS.md item #8).

Mocks `run_tool` (the tool-execution boundary) — same pattern as
tests/test_audit_batch_cross_contract.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from miesc.cli.commands.audit import audit

SOL = "pragma solidity ^0.8.0;\ncontract {name} {{}}\n"


def _write_fixtures(tmp_path: Path, names: list[str]) -> None:
    for name in names:
        (tmp_path / f"{name}.sol").write_text(SOL.format(name=name))


def _fake_run_tool(tool: str, contract: str, timeout: int = 0) -> dict:
    return {"tool": tool, "contract": contract, "status": "success", "findings": []}


class TestAuditBatchCheckpoint:
    def test_checkpoint_written_with_all_contracts(self, tmp_path):
        _write_fixtures(tmp_path, ["A", "B", "C"])
        ckpt = tmp_path / "state.json"
        runner = CliRunner()

        with patch("miesc.cli.commands.audit.run_tool", side_effect=_fake_run_tool):
            result = runner.invoke(audit, ["batch", str(tmp_path), "--checkpoint", str(ckpt)])

        assert result.exit_code == 0, result.output
        data = json.loads(ckpt.read_text())
        assert {Path(c["contract"]).stem for c in data["contracts"]} == {"A", "B", "C"}

    def test_resume_skips_contracts_already_in_checkpoint(self, tmp_path):
        _write_fixtures(tmp_path, ["A", "B", "C"])
        ckpt = tmp_path / "state.json"
        a_path = str(tmp_path / "A.sol")

        # Pre-seed the checkpoint as if a prior run already finished A.sol.
        ckpt.write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "contract": a_path,
                            "results": [],
                            "summary": {
                                "CRITICAL": 0,
                                "HIGH": 0,
                                "MEDIUM": 0,
                                "LOW": 0,
                                "INFO": 0,
                            },
                            "total_findings": 0,
                        }
                    ],
                    "failed": [],
                }
            )
        )

        called_for: list[str] = []

        def tracking_run_tool(tool: str, contract: str, timeout: int = 0) -> dict:
            called_for.append(contract)
            return _fake_run_tool(tool, contract, timeout)

        runner = CliRunner()
        out_file = tmp_path / "batch.json"
        with patch("miesc.cli.commands.audit.run_tool", side_effect=tracking_run_tool):
            result = runner.invoke(
                audit,
                [
                    "batch",
                    str(tmp_path),
                    "--checkpoint",
                    str(ckpt),
                    "--resume",
                    "-o",
                    str(out_file),
                ],
            )

        assert result.exit_code == 0, result.output
        assert a_path not in called_for
        assert any(c.endswith("B.sol") for c in called_for)
        assert any(c.endswith("C.sol") for c in called_for)

        # Final report still includes all 3, merging the pre-seeded A.sol.
        report = json.loads(out_file.read_text())
        assert {Path(c["contract"]).stem for c in report["contracts"]} == {"A", "B", "C"}

    def test_resume_without_existing_checkpoint_runs_normally(self, tmp_path):
        _write_fixtures(tmp_path, ["A"])
        ckpt = tmp_path / "missing.json"
        runner = CliRunner()

        with patch("miesc.cli.commands.audit.run_tool", side_effect=_fake_run_tool):
            result = runner.invoke(
                audit, ["batch", str(tmp_path), "--checkpoint", str(ckpt), "--resume"]
            )

        assert result.exit_code == 0, result.output
        assert json.loads(ckpt.read_text())["contracts"]
