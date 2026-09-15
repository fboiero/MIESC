"""
Smoke tests for the `miesc xray` CLI command (MEJORAS.md item #4).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from miesc.cli.commands.xray import xray


class TestXrayCommand:
    def test_single_file_runs_and_exits_zero(self):
        runner = CliRunner()
        result = runner.invoke(xray, ["examples/contracts/DeFiVault.sol"])
        assert result.exit_code == 0
        assert "DeFiVault.sol" in result.output

    def test_json_output_has_expected_keys(self, tmp_path):
        runner = CliRunner()
        out_file = tmp_path / "xray_report.json"
        result = runner.invoke(xray, ["examples/contracts/DeFiVault.sol", "-o", str(out_file)])
        assert result.exit_code == 0
        report = json.loads(out_file.read_text())
        assert "files" in report and "hotspots" in report
        file_report = report["files"][0]
        for key in (
            "protocol_type",
            "attack_surface_score",
            "entry_points",
            "git_commits",
        ):
            assert key in file_report

    def test_directory_without_sol_files_errors(self, tmp_path):
        runner = CliRunner()
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = runner.invoke(xray, [str(empty_dir)])
        assert result.exit_code != 0

    def test_directory_recursive_scans_multiple_files(self):
        runner = CliRunner()
        result = runner.invoke(xray, ["examples/contracts/", "--recursive"])
        assert result.exit_code == 0
