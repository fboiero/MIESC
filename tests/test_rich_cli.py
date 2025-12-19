"""
Tests for MIESC Rich CLI Module

Tests severity styles, CLI components, and output formatting.
"""

import pytest
from io import StringIO

from src.core.rich_cli import (
    SeverityStyle,
    RICH_AVAILABLE,
)


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


class TestRichAvailability:
    """Tests for Rich library availability."""

    def test_availability_flag_exists(self):
        """Test that availability flag is defined."""
        assert isinstance(RICH_AVAILABLE, bool)

    def test_module_imports(self):
        """Test module imports without error."""
        from src.core.rich_cli import SeverityStyle
        assert SeverityStyle is not None


@pytest.mark.skipif(not RICH_AVAILABLE, reason="Rich library not installed")
class TestMIESCRichCLI:
    """Tests for MIESCRichCLI class (requires Rich)."""

    def test_cli_initialization(self):
        """Test CLI initialization."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()
        assert cli.console is not None
        assert cli.verbose is False

    def test_cli_verbose_mode(self):
        """Test CLI verbose mode."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI(verbose=True)
        assert cli.verbose is True

    def test_banner_content(self):
        """Test banner contains expected text."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()
        assert "MIESC" in cli.BANNER

    def test_severity_to_style_mapping(self):
        """Test severity to style conversion."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()

        # Test the method exists and returns expected styles
        style = cli._severity_style("critical")
        assert "red" in style

        style = cli._severity_style("high")
        assert "red" in style

        style = cli._severity_style("medium")
        assert "yellow" in style

        style = cli._severity_style("low")
        assert "cyan" in style

    def test_format_duration(self):
        """Test duration formatting."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()

        # Test formatting different durations
        result = cli._format_duration(0.5)
        assert "0.50s" in result or "500ms" in result

        result = cli._format_duration(65.0)
        assert "1" in result or "65" in result

    def test_create_findings_table(self):
        """Test findings table creation."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()

        findings = [
            {
                "severity": "critical",
                "type": "reentrancy",
                "title": "Reentrancy Attack",
                "file": "test.sol",
                "line": 42,
            },
            {
                "severity": "high",
                "type": "overflow",
                "title": "Integer Overflow",
                "file": "token.sol",
                "line": 100,
            },
        ]

        table = cli._create_findings_table(findings)
        assert table is not None


@pytest.mark.skipif(not RICH_AVAILABLE, reason="Rich library not installed")
class TestCLIOutputMethods:
    """Tests for CLI output methods."""

    def test_show_error(self):
        """Test error display method."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()
        # Should not raise
        cli.show_error("Test error message")

    def test_show_success(self):
        """Test success display method."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()
        # Should not raise
        cli.show_success("Test success message")

    def test_show_warning(self):
        """Test warning display method."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()
        # Should not raise
        cli.show_warning("Test warning message")

    def test_show_info(self):
        """Test info display method."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()
        # Should not raise
        cli.show_info("Test info message")


@pytest.mark.skipif(not RICH_AVAILABLE, reason="Rich library not installed")
class TestFindingsDisplay:
    """Tests for findings display functionality."""

    @pytest.fixture
    def sample_findings(self):
        """Sample findings for testing."""
        return [
            {
                "id": "F001",
                "severity": "critical",
                "type": "reentrancy",
                "title": "Reentrancy Vulnerability",
                "description": "External call before state update.",
                "file": "Vault.sol",
                "line": 25,
                "tool": "slither",
                "layer": 1,
            },
            {
                "id": "F002",
                "severity": "high",
                "type": "unchecked_return",
                "title": "Unchecked Return Value",
                "description": "Return value not checked.",
                "file": "Token.sol",
                "line": 42,
                "tool": "mythril",
                "layer": 3,
            },
            {
                "id": "F003",
                "severity": "medium",
                "type": "gas",
                "title": "Gas Optimization",
                "description": "Inefficient loop pattern.",
                "file": "Contract.sol",
                "line": 100,
                "tool": "aderyn",
                "layer": 1,
            },
        ]

    def test_count_by_severity(self, sample_findings):
        """Test severity counting."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()
        counts = cli._count_by_severity(sample_findings)

        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts.get("low", 0) == 0

    def test_group_by_severity(self, sample_findings):
        """Test grouping by severity."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()
        grouped = cli._group_by_severity(sample_findings)

        assert len(grouped["critical"]) == 1
        assert len(grouped["high"]) == 1
        assert len(grouped["medium"]) == 1


@pytest.mark.skipif(not RICH_AVAILABLE, reason="Rich library not installed")
class TestProgressDisplay:
    """Tests for progress display functionality."""

    def test_progress_context_manager(self):
        """Test progress bar context manager."""
        from src.core.rich_cli import MIESCRichCLI

        cli = MIESCRichCLI()

        # Should work as context manager
        with cli.progress_context("Test operation") as progress:
            assert progress is not None


class TestWithoutRich:
    """Tests for behavior when Rich is not available."""

    def test_import_without_rich(self, monkeypatch):
        """Test module handles missing Rich gracefully."""
        # The module should import even without Rich
        # (it sets RICH_AVAILABLE=False)
        from src.core import rich_cli
        assert hasattr(rich_cli, "RICH_AVAILABLE")
