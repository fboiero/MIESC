"""
Comprehensive tests for MIESC Rich CLI Module.

Tests severity styles, CLI components, and output formatting.
Covers all methods in src/core/rich_cli.py.

Author: Fernando Boiero
"""

import os
import tempfile
from unittest.mock import patch

import pytest

from src.core.rich_cli import (
    RICH_AVAILABLE,
    SeverityStyle,
)

# =============================================================================
# Test SeverityStyle Enum
# =============================================================================


class TestSeverityStyle:
    """Tests for SeverityStyle enum."""

    def test_critical_style(self):
        """Test critical severity style."""
        assert SeverityStyle.CRITICAL.value == "bold red"

    def test_high_style(self):
        """Test high severity style."""
        assert SeverityStyle.HIGH.value == "red"

    def test_medium_style(self):
        """Test medium severity style."""
        assert SeverityStyle.MEDIUM.value == "yellow"

    def test_low_style(self):
        """Test low severity style."""
        assert SeverityStyle.LOW.value == "cyan"

    def test_info_style(self):
        """Test info severity style."""
        assert SeverityStyle.INFO.value == "dim"

    def test_all_severities_have_values(self):
        """Test all severity levels are defined."""
        expected = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        actual = [s.name for s in SeverityStyle]
        assert actual == expected

    def test_severity_is_string_enum(self):
        """Test SeverityStyle inherits from str."""
        assert isinstance(SeverityStyle.CRITICAL, str)
        assert SeverityStyle.CRITICAL == "bold red"


# =============================================================================
# Test Rich Availability
# =============================================================================


class TestRichAvailability:
    """Tests for Rich library availability."""

    def test_availability_flag_exists(self):
        """Test that availability flag is defined."""
        assert isinstance(RICH_AVAILABLE, bool)

    def test_module_imports(self):
        """Test module imports without error."""
        from src.core.rich_cli import SeverityStyle

        assert SeverityStyle is not None

    def test_rich_availability_is_boolean(self):
        """Test RICH_AVAILABLE is a boolean indicating Rich status."""
        # RICH_AVAILABLE should be True if Rich is installed, False otherwise
        assert isinstance(RICH_AVAILABLE, bool)


# =============================================================================
# Test MIESCRichCLI Class
# =============================================================================


@pytest.mark.skipif(not RICH_AVAILABLE, reason="Rich library not installed")
class TestMIESCRichCLI:
    """Tests for MIESCRichCLI class (requires Rich)."""

    @pytest.fixture
    def cli(self):
        """Create CLI instance."""
        from src.core.rich_cli import MIESCRichCLI

        return MIESCRichCLI()

    @pytest.fixture
    def verbose_cli(self):
        """Create verbose CLI instance."""
        from src.core.rich_cli import MIESCRichCLI

        return MIESCRichCLI(verbose=True)

    @pytest.fixture
    def sample_findings(self):
        """Sample findings for testing."""
        return [
            {
                "title": "Reentrancy Vulnerability",
                "severity": "critical",
                "tool": "slither",
                "layer": 1,
                "description": "External call before state update allows reentrancy attack.",
                "location": "VulnerableBank.sol:25",
                "cwe": "CWE-841",
                "swc": "SWC-107",
                "remediation": "Use checks-effects-interactions pattern or ReentrancyGuard.",
            },
            {
                "title": "Unchecked Return Value",
                "severity": "high",
                "tool": "mythril",
                "layer": 3,
                "description": "Return value of external call not checked.",
                "location": "Token.sol:42",
            },
            {
                "title": "Missing Access Control",
                "severity": "medium",
                "tool": "aderyn",
                "layer": 1,
                "description": "Function lacks access control modifier.",
                "location": "Vault.sol:15",
            },
            {
                "title": "Gas Optimization",
                "severity": "low",
                "tool": "solhint",
                "layer": 1,
                "description": "Use uint256 instead of uint.",
                "location": "Utils.sol:5",
            },
            {
                "title": "Unused Variable",
                "severity": "info",
                "tool": "slither",
                "layer": 1,
                "description": "Variable declared but never used.",
                "location": "Contract.sol:100",
            },
        ]

    @pytest.fixture
    def sample_tools(self):
        """Sample tools status."""
        return {
            "slither": {"available": True, "version": "0.10.0", "layer": 1},
            "mythril": {"available": True, "version": "0.24.0", "layer": 3},
            "echidna": {"available": False, "version": "N/A", "layer": 4},
            "halmos": {"available": True, "version": "0.1.0", "layer": 5},
        }

    # --- Initialization Tests ---

    def test_cli_initialization(self, cli):
        """Test CLI initialization."""
        assert cli.console is not None
        assert cli.verbose is False
        assert cli._progress is None
        assert cli._live is None

    def test_cli_verbose_mode(self, verbose_cli):
        """Test CLI verbose mode."""
        assert verbose_cli.verbose is True

    def test_banner_content(self, cli):
        """Test banner contains ASCII art box characters."""
        # Banner is ASCII art using box drawing chars, not literal MIESC
        assert "███" in cli.BANNER or len(cli.BANNER) > 100

    def test_banner_is_ascii_art(self, cli):
        """Test banner is multi-line ASCII art."""
        lines = cli.BANNER.strip().split("\n")
        assert len(lines) >= 5

    # --- Display Methods Tests ---

    def test_show_banner(self, cli):
        """Test show_banner executes without error."""
        # Should not raise
        cli.show_banner()

    def test_show_welcome(self, cli):
        """Test show_welcome displays system info."""
        # Should not raise
        cli.show_welcome()

    def test_show_tools_status(self, cli, sample_tools):
        """Test show_tools_status displays tool table."""
        # Should not raise
        cli.show_tools_status(sample_tools)

    def test_show_tools_status_empty(self, cli):
        """Test show_tools_status with empty dict."""
        cli.show_tools_status({})

    def test_show_contract_info_existing_file(self, cli, tmp_path):
        """Test show_contract_info with existing file."""
        contract = tmp_path / "Test.sol"
        contract.write_text(
            """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Test {
    function hello() public pure returns (string memory) {
        return "Hello";
    }
}
"""
        )
        cli.show_contract_info(str(contract))

    def test_show_contract_info_nonexistent_file(self, cli):
        """Test show_contract_info with nonexistent file."""
        cli.show_contract_info("/nonexistent/path/Contract.sol")

    def test_show_contract_info_with_code(self, cli, tmp_path):
        """Test show_contract_info with code parameter."""
        contract = tmp_path / "Test.sol"
        contract.write_text("// empty")

        code = "pragma solidity ^0.8.0;\ncontract Test {}"
        cli.show_contract_info(str(contract), code=code)

    def test_show_contract_info_verbose(self, verbose_cli, tmp_path):
        """Test show_contract_info in verbose mode shows code preview."""
        contract = tmp_path / "Test.sol"
        contract.write_text(
            """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Test {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }
}
"""
        )
        verbose_cli.show_contract_info(str(contract))

    # --- Findings Display Tests ---

    def test_show_findings_summary(self, cli, sample_findings):
        """Test show_findings_summary displays severity counts."""
        cli.show_findings_summary(sample_findings)

    def test_show_findings_summary_empty(self, cli):
        """Test show_findings_summary with empty list."""
        cli.show_findings_summary([])

    def test_show_findings_detail(self, cli, sample_findings):
        """Test show_findings_detail displays each finding."""
        cli.show_findings_detail(sample_findings)

    def test_show_findings_detail_empty(self, cli):
        """Test show_findings_detail with empty list shows success."""
        cli.show_findings_detail([])

    def test_show_findings_tree(self, cli, sample_findings):
        """Test show_findings_tree displays tree structure."""
        cli.show_findings_tree(sample_findings)

    def test_show_findings_tree_empty(self, cli):
        """Test show_findings_tree with empty list."""
        cli.show_findings_tree([])

    def test_show_finding_private(self, cli):
        """Test _show_finding private method."""
        finding = {
            "title": "Test Issue",
            "description": "Test description",
            "tool": "slither",
            "location": "test.sol:10",
            "cwe": "CWE-123",
            "swc": "SWC-101",
            "remediation": "Fix this",
        }
        cli._show_finding(finding, "red")

    def test_show_finding_minimal(self, cli):
        """Test _show_finding with minimal data."""
        finding = {"type": "TestType"}
        cli._show_finding(finding, "dim")

    # --- Progress Tests ---

    def test_create_progress(self, cli):
        """Test create_progress returns Progress instance."""
        progress = cli.create_progress()
        assert progress is not None

    def test_run_with_progress(self, cli):
        """Test run_with_progress executes tasks."""
        tasks = [
            {"name": "task1", "description": "Task 1", "total": 100},
            {"name": "task2", "description": "Task 2", "total": 100},
        ]

        results = []

        def executor(task_name, progress_callback):
            progress_callback(50)
            progress_callback(100, f"Done {task_name}")
            return {"task": task_name, "result": "success"}

        results = cli.run_with_progress(tasks, executor)

        assert len(results) == 2
        assert results[0]["result"] == "success"

    def test_run_with_progress_error(self, cli):
        """Test run_with_progress handles errors."""
        tasks = [
            {"name": "error_task", "description": "Error Task", "total": 100},
        ]

        def executor(task_name, progress_callback):
            raise ValueError("Test error")

        results = cli.run_with_progress(tasks, executor)

        assert len(results) == 1
        assert "error" in results[0]

    def test_run_audit_with_progress(self, cli, tmp_path):
        """Test run_audit_with_progress executes audit."""
        contract = tmp_path / "Test.sol"
        contract.write_text("pragma solidity ^0.8.0;\ncontract Test {}")

        layers = [
            {"number": 1, "name": "Static Analysis", "tools": ["slither", "aderyn"]},
            {"number": 2, "name": "Symbolic", "tools": ["mythril"]},
        ]

        def audit_func(layer_num, tool, progress_callback):
            progress_callback(50)
            progress_callback(100)
            return [{"tool": tool, "severity": "medium", "title": f"Finding from {tool}"}]

        result = cli.run_audit_with_progress(str(contract), layers, audit_func)

        assert "findings" in result
        assert "by_layer" in result
        assert "total" in result
        assert result["total"] > 0

    def test_run_audit_with_progress_tool_error(self, cli, tmp_path):
        """Test run_audit_with_progress handles tool errors."""
        contract = tmp_path / "Test.sol"
        contract.write_text("pragma solidity ^0.8.0;")

        layers = [
            {"number": 1, "name": "Test", "tools": ["failing_tool"]},
        ]

        def audit_func(layer_num, tool, progress_callback):
            raise RuntimeError("Tool crashed")

        result = cli.run_audit_with_progress(str(contract), layers, audit_func)

        # Should complete without raising
        assert "findings" in result

    # --- Prompt Tests ---

    def test_prompt_contract_with_mock(self, cli):
        """Test prompt_contract with mocked input."""
        with patch("src.core.rich_cli.Prompt.ask", return_value="/path/to/contract.sol"):
            result = cli.prompt_contract(default="default.sol")
            assert result == "/path/to/contract.sol"

    def test_prompt_tools_all(self, cli):
        """Test prompt_tools with 'all' selection."""
        available = ["slither", "mythril", "echidna"]

        with patch("src.core.rich_cli.Prompt.ask", return_value="all"):
            result = cli.prompt_tools(available)
            assert result == available

    def test_prompt_tools_specific(self, cli):
        """Test prompt_tools with specific selection."""
        available = ["slither", "mythril", "echidna"]

        with patch("src.core.rich_cli.Prompt.ask", return_value="1,3"):
            result = cli.prompt_tools(available)
            assert result == ["slither", "echidna"]

    def test_prompt_tools_invalid(self, cli):
        """Test prompt_tools with invalid input returns all."""
        available = ["slither", "mythril"]

        with patch("src.core.rich_cli.Prompt.ask", return_value="invalid"):
            result = cli.prompt_tools(available)
            assert result == available

    def test_prompt_confirm_yes(self, cli):
        """Test prompt_confirm returns True."""
        with patch("src.core.rich_cli.Confirm.ask", return_value=True):
            result = cli.prompt_confirm("Continue?")
            assert result is True

    def test_prompt_confirm_no(self, cli):
        """Test prompt_confirm returns False."""
        with patch("src.core.rich_cli.Confirm.ask", return_value=False):
            result = cli.prompt_confirm("Continue?")
            assert result is False

    def test_show_export_options_sarif(self, cli):
        """Test show_export_options returns sarif."""
        with patch("src.core.rich_cli.Prompt.ask", return_value="1"):
            result = cli.show_export_options()
            assert result == "sarif"

    def test_show_export_options_markdown(self, cli):
        """Test show_export_options returns markdown."""
        with patch("src.core.rich_cli.Prompt.ask", return_value="4"):
            result = cli.show_export_options()
            assert result == "markdown"

    def test_show_export_options_invalid(self, cli):
        """Test show_export_options returns default on invalid."""
        with patch("src.core.rich_cli.Prompt.ask", return_value="invalid"):
            result = cli.show_export_options()
            assert result == "sarif"

    def test_show_export_options_out_of_range(self, cli):
        """Test show_export_options returns default on out of range."""
        with patch("src.core.rich_cli.Prompt.ask", return_value="99"):
            result = cli.show_export_options()
            assert result == "sarif"

    # --- Completion and Message Tests ---

    def test_show_completion(self, cli):
        """Test show_completion displays completion message."""
        cli.show_completion(duration=45.5, findings_count=10)

    def test_show_completion_with_output(self, cli):
        """Test show_completion with output path."""
        cli.show_completion(duration=30.0, findings_count=5, output_path="/path/to/report.json")

    def test_error_method(self, cli):
        """Test error message display."""
        cli.error("Something went wrong")

    def test_warning_method(self, cli):
        """Test warning message display."""
        cli.warning("Potential issue detected")

    def test_success_method(self, cli):
        """Test success message display."""
        cli.success("Operation completed successfully")

    def test_info_method(self, cli):
        """Test info message display."""
        cli.info("Processing contract...")


# =============================================================================
# Test create_cli Factory Function
# =============================================================================


@pytest.mark.skipif(not RICH_AVAILABLE, reason="Rich library not installed")
class TestCreateCLI:
    """Tests for create_cli factory function."""

    def test_create_cli_default(self):
        """Test create_cli returns CLI instance."""
        from src.core.rich_cli import create_cli

        cli = create_cli()
        assert cli is not None
        assert cli.verbose is False

    def test_create_cli_verbose(self):
        """Test create_cli with verbose mode."""
        from src.core.rich_cli import create_cli

        cli = create_cli(verbose=True)
        assert cli is not None
        assert cli.verbose is True


# =============================================================================
# Test Edge Cases
# =============================================================================


@pytest.mark.skipif(not RICH_AVAILABLE, reason="Rich library not installed")
class TestEdgeCases:
    """Edge case tests for CLI."""

    @pytest.fixture
    def cli(self):
        from src.core.rich_cli import MIESCRichCLI

        return MIESCRichCLI()

    def test_findings_with_unknown_severity(self, cli):
        """Test handling findings with unknown severity."""
        findings = [{"title": "Unknown", "severity": "unknown", "tool": "test", "layer": 1}]
        cli.show_findings_summary(findings)
        cli.show_findings_detail(findings)

    def test_findings_without_severity(self, cli):
        """Test handling findings without severity field."""
        findings = [{"title": "No Severity", "tool": "test", "layer": 1}]
        cli.show_findings_summary(findings)

    def test_findings_tree_grouped_by_layer(self, cli):
        """Test findings tree groups by layer correctly."""
        findings = [
            {"title": "F1", "severity": "high", "tool": "slither", "layer": 1},
            {"title": "F2", "severity": "medium", "tool": "slither", "layer": 1},
            {"title": "F3", "severity": "high", "tool": "mythril", "layer": 3},
        ]
        cli.show_findings_tree(findings)

    def test_long_code_preview(self):
        """Test code preview truncates long files."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI(verbose=True)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
            # Write many lines
            for i in range(100):
                f.write(f"// Line {i}\n")
            f.flush()

            try:
                cli.show_contract_info(f.name)
            finally:
                os.unlink(f.name)

    def test_tools_without_version(self, cli):
        """Test tools status without version field."""
        tools = {
            "tool1": {"available": True, "layer": 1},
            "tool2": {"available": False, "layer": 2},
        }
        cli.show_tools_status(tools)

    def test_special_characters_in_finding(self, cli):
        """Test findings with special characters."""
        findings = [
            {
                "title": "Test <script>alert('xss')</script>",
                "severity": "high",
                "tool": "test",
                "layer": 1,
                "description": "Description with 'quotes' and \"double quotes\"",
                "location": "file.sol:1",
            }
        ]
        cli.show_findings_detail(findings)


# =============================================================================
# Test Without Rich (Graceful Degradation)
# =============================================================================


class TestWithoutRich:
    """Tests for behavior when Rich is not available."""

    def test_import_without_rich(self, monkeypatch):
        """Test module handles missing Rich gracefully."""
        from src.core import rich_cli

        assert hasattr(rich_cli, "RICH_AVAILABLE")

    def test_severity_style_without_rich(self):
        """Test SeverityStyle works regardless of Rich."""
        from src.core.rich_cli import SeverityStyle

        assert SeverityStyle.CRITICAL.value == "bold red"
        assert isinstance(SeverityStyle.CRITICAL, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
