"""
Tests for the --diff flag on the `miesc scan` command.

Covers:
- No changed .sol files → prints message, exits 0
- Changed .sol files are scanned (mocked tool execution)
- Non-.sol changed files are ignored
- git diff subprocess failure is reported and exits 1
- Only existing files are included (deleted files skipped)
- --diff is passed through even when combined with other flags

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from miesc.cli.commands.scan import scan

# =============================================================================
# Helpers
# =============================================================================


def _make_subprocess_result(stdout: str, returncode: int = 0) -> MagicMock:
    """Return a mock subprocess.CompletedProcess."""
    result = MagicMock()
    result.stdout = stdout
    result.returncode = returncode
    result.stderr = ""
    return result


def _git_diff_result(filenames: list[str]) -> MagicMock:
    """git diff --name-only result with given filenames."""
    return _make_subprocess_result("\n".join(filenames) + "\n" if filenames else "")


def _repo_root_result(path: str) -> MagicMock:
    return _make_subprocess_result(path + "\n")


# =============================================================================
# Tests: No changed .sol files
# =============================================================================


class TestDiffNoSolFiles:
    def test_empty_diff_exits_0(self, tmp_path):
        """When git diff returns no files, scan exits 0 with an informational message."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            contracts_dir = Path("contracts")
            contracts_dir.mkdir()
            # Nothing changed

            def fake_run(cmd, **kwargs):
                if "diff" in cmd:
                    return _git_diff_result([])
                return _repo_root_result(str(contracts_dir.resolve()))

            with patch("subprocess.run", side_effect=fake_run):
                result = runner.invoke(scan, [str(contracts_dir), "--diff", "origin/main"])

        assert result.exit_code == 0
        assert "No Solidity files changed" in result.output

    def test_only_non_sol_changed_exits_0(self, tmp_path):
        """When only .js / .ts files changed, scan exits 0."""
        runner = CliRunner()

        def fake_run(cmd, **kwargs):
            if "diff" in cmd:
                return _git_diff_result(["scripts/deploy.js", "hardhat.config.ts"])
            return _repo_root_result(str(tmp_path))

        with patch("subprocess.run", side_effect=fake_run):
            result = runner.invoke(scan, [str(tmp_path), "--diff", "HEAD~1"])

        assert result.exit_code == 0
        assert "No Solidity files changed" in result.output


# =============================================================================
# Tests: Changed .sol files are scanned
# =============================================================================


class TestDiffWithSolFiles:
    def test_single_changed_sol_file_is_scanned(self, tmp_path):
        """A single changed .sol file triggers a scan and produces output."""
        runner = CliRunner()
        sol_file = tmp_path / "Token.sol"
        sol_file.write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract T {}"
        )

        def fake_run(cmd, **kwargs):
            if "diff" in cmd:
                return _git_diff_result(["Token.sol"])
            return _repo_root_result(str(tmp_path))

        # Mock _scan_single_file to avoid real tool execution
        with (
            patch("subprocess.run", side_effect=fake_run),
            patch("miesc.cli.commands.scan._scan_single_file") as mock_scan,
            patch("miesc.cli.commands.scan._display_and_save") as mock_display,
        ):
            mock_scan.return_value = None
            mock_display.return_value = None
            runner.invoke(scan, [str(tmp_path), "--diff", "HEAD~1", "--quiet"])

        # _scan_single_file should have been called for Token.sol
        assert mock_scan.call_count == 1
        call_args = mock_scan.call_args[0]
        assert "Token.sol" in call_args[0]

    def test_multiple_changed_sol_files_all_scanned(self, tmp_path):
        """Multiple changed .sol files are all passed to _scan_single_file."""
        runner = CliRunner()
        for name in ("A.sol", "B.sol", "C.sol"):
            (tmp_path / name).write_text("// SPDX-License-Identifier: MIT\ncontract X {}")

        def fake_run(cmd, **kwargs):
            if "diff" in cmd:
                return _git_diff_result(["A.sol", "B.sol", "C.sol"])
            return _repo_root_result(str(tmp_path))

        with (
            patch("subprocess.run", side_effect=fake_run),
            patch("miesc.cli.commands.scan._scan_single_file") as mock_scan,
            patch("miesc.cli.commands.scan._display_and_save"),
        ):
            mock_scan.return_value = None
            runner.invoke(scan, [str(tmp_path), "--diff", "main", "--quiet"])

        assert mock_scan.call_count == 3

    def test_mixed_file_types_only_sol_scanned(self, tmp_path):
        """When diff contains .sol and other extensions, only .sol are scanned."""
        runner = CliRunner()
        sol_file = tmp_path / "Vault.sol"
        sol_file.write_text("// SPDX-License-Identifier: MIT\ncontract Vault {}")

        def fake_run(cmd, **kwargs):
            if "diff" in cmd:
                return _git_diff_result(["Vault.sol", "README.md", "test/Vault.t.sol"])
            return _repo_root_result(str(tmp_path))

        with (
            patch("subprocess.run", side_effect=fake_run),
            patch("miesc.cli.commands.scan._scan_single_file") as mock_scan,
            patch("miesc.cli.commands.scan._display_and_save"),
        ):
            mock_scan.return_value = None
            runner.invoke(scan, [str(tmp_path), "--diff", "HEAD~3", "--quiet"])

        # Only Vault.sol exists in tmp_path (test/Vault.t.sol path doesn't exist there)
        assert mock_scan.call_count == 1

    def test_deleted_files_not_scanned(self, tmp_path):
        """Files listed in git diff but not present on disk are silently skipped."""
        runner = CliRunner()

        def fake_run(cmd, **kwargs):
            if "diff" in cmd:
                # deleted.sol does not exist on disk
                return _git_diff_result(["deleted.sol"])
            return _repo_root_result(str(tmp_path))

        with (
            patch("subprocess.run", side_effect=fake_run),
            patch("miesc.cli.commands.scan._scan_single_file") as mock_scan,
            patch("miesc.cli.commands.scan._display_and_save"),
        ):
            mock_scan.return_value = None
            result = runner.invoke(scan, [str(tmp_path), "--diff", "HEAD~1"])

        # No existing .sol file → exits 0 with "No Solidity files changed"
        assert result.exit_code == 0
        assert "No Solidity files changed" in result.output
        assert mock_scan.call_count == 0


# =============================================================================
# Tests: git failure handling
# =============================================================================


class TestDiffGitFailure:
    def test_git_exception_exits_1(self, tmp_path):
        """If subprocess.run raises an exception, scan exits 1."""
        runner = CliRunner()

        def fake_run(cmd, **kwargs):
            raise FileNotFoundError("git not found")

        with patch("subprocess.run", side_effect=fake_run):
            result = runner.invoke(scan, [str(tmp_path), "--diff", "HEAD~1"])

        assert result.exit_code == 1
