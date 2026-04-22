"""
Tests for multi-file (directory) scan support in `miesc scan`.

Covers:
- Scanning a directory with two .sol files
- Scanning an empty directory (no .sol files)
- --recursive flag descends into subdirectories
- Single-file path is unchanged (regression guard)

Author: Fernando Boiero
"""

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from miesc.cli.commands.scan import scan

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

MINIMAL_SOL = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract C {}\n"

FAKE_TOOL_RESULT = {
    "tool": "slither",
    "status": "success",
    "findings": [{"severity": "HIGH", "type": "reentrancy", "message": "test"}],
}


def _make_runner():
    return CliRunner()


# ---------------------------------------------------------------------------
# Helper: patch run_tool to return a canned result (no real tools needed)
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_run_tool():
    """Patch run_tool to return a fake result instantly."""
    with patch(
        "miesc.cli.commands.scan.run_tool",
        return_value={
            "tool": "slither",
            "status": "success",
            "findings": [{"severity": "HIGH", "type": "reentrancy", "message": "test"}],
        },
    ) as m:
        yield m


# ---------------------------------------------------------------------------
# Test 1: directory with two .sol files — both are scanned, findings merged
# ---------------------------------------------------------------------------


def test_scan_directory_two_files(tmp_path, mock_run_tool):
    """Scanning a directory with two .sol files aggregates results from both."""
    (tmp_path / "Token.sol").write_text(MINIMAL_SOL)
    (tmp_path / "Vault.sol").write_text(MINIMAL_SOL)

    runner = _make_runner()
    result = runner.invoke(scan, [str(tmp_path), "--quiet", "--fp-strictness", "off"])

    assert result.exit_code == 0, result.output

    # run_tool should have been called once per tool per file (2 files × N tools)
    # At minimum it was called for both files
    call_contracts = {call.args[1] for call in mock_run_tool.call_args_list}
    assert any("Token.sol" in c for c in call_contracts)
    assert any("Vault.sol" in c for c in call_contracts)


# ---------------------------------------------------------------------------
# Test 2: empty directory — exits with code 1 and informative error
# ---------------------------------------------------------------------------


def test_scan_directory_no_sol_files(tmp_path):
    """Scanning a directory with no .sol files exits with error code 1."""
    # Write a non-.sol file so the directory is not empty
    (tmp_path / "README.md").write_text("nothing here")

    runner = _make_runner()
    result = runner.invoke(scan, [str(tmp_path), "--quiet", "--fp-strictness", "off"])

    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Test 3: --recursive flag picks up files in subdirectories
# ---------------------------------------------------------------------------


def test_scan_directory_recursive(tmp_path, mock_run_tool):
    """--recursive descends into subdirectories and finds nested .sol files."""
    sub = tmp_path / "sub"
    sub.mkdir()
    (tmp_path / "Root.sol").write_text(MINIMAL_SOL)
    (sub / "Nested.sol").write_text(MINIMAL_SOL)

    runner = _make_runner()
    result = runner.invoke(
        scan, [str(tmp_path), "--quiet", "--fp-strictness", "off", "--recursive"]
    )

    assert result.exit_code == 0, result.output

    call_contracts = {call.args[1] for call in mock_run_tool.call_args_list}
    assert any("Root.sol" in c for c in call_contracts)
    assert any("Nested.sol" in c for c in call_contracts)


# ---------------------------------------------------------------------------
# Test 4: --recursive without subdirectory .sol files — same as flat scan
# ---------------------------------------------------------------------------


def test_scan_directory_recursive_no_subdirs(tmp_path, mock_run_tool):
    """--recursive on a flat directory (no subdirs) works the same as flat scan."""
    (tmp_path / "Only.sol").write_text(MINIMAL_SOL)

    runner = _make_runner()
    result = runner.invoke(
        scan, [str(tmp_path), "--quiet", "--fp-strictness", "off", "--recursive"]
    )

    assert result.exit_code == 0, result.output
    call_contracts = {call.args[1] for call in mock_run_tool.call_args_list}
    assert any("Only.sol" in c for c in call_contracts)


# ---------------------------------------------------------------------------
# Test 5: single-file mode is unaffected (regression guard)
# ---------------------------------------------------------------------------


def test_scan_single_file_unchanged(tmp_path, mock_run_tool):
    """Passing a single .sol file still works exactly as before."""
    sol = tmp_path / "MyContract.sol"
    sol.write_text(MINIMAL_SOL)

    runner = _make_runner()
    result = runner.invoke(scan, [str(sol), "--quiet", "--fp-strictness", "off"])

    assert result.exit_code == 0, result.output
    # run_tool is called with the exact file path, not a directory
    call_contracts = {call.args[1] for call in mock_run_tool.call_args_list}
    assert any("MyContract.sol" in c for c in call_contracts)
