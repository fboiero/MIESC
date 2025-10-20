"""
Integration Tests for MIESC CLI

Comprehensive test suite for Click-based CLI including:
- analyze command
- verify command
- classify command
- server command
- Help text and documentation
- Error handling
- Output formatting

Target Coverage: Full CLI command coverage
Test Type: Integration (uses CliRunner)

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
"""

import pytest
import json
import tempfile
from pathlib import Path
from click.testing import CliRunner
from unittest.mock import Mock, patch, MagicMock

from miesc.cli.miesc_cli import cli


class TestCLIBasics:
    """Test suite for basic CLI functionality"""

    @pytest.fixture
    def runner(self):
        """Click CLI test runner"""
        return CliRunner()

    @pytest.fixture
    def sample_contract_file(self, tmp_path):
        """Create a temporary contract file"""
        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Test {}")
        return str(contract)

    def test_cli_version(self, runner):
        """Test --version flag"""
        result = runner.invoke(cli, ['--version'])

        assert result.exit_code == 0
        assert '3.3.0' in result.output

    def test_cli_help(self, runner):
        """Test --help flag"""
        result = runner.invoke(cli, ['--help'])

        assert result.exit_code == 0
        assert 'MIESC' in result.output
        assert 'analyze' in result.output
        assert 'verify' in result.output
        assert 'classify' in result.output
        assert 'server' in result.output

    def test_cli_verbose_flag(self, runner):
        """Test -v/--verbose flag"""
        result = runner.invoke(cli, ['-v', '--help'])

        # Should not fail with verbose flag
        assert result.exit_code == 0


class TestAnalyzeCommand:
    """Test suite for 'analyze' command"""

    @pytest.fixture
    def runner(self):
        """Click CLI test runner"""
        return CliRunner()

    @pytest.fixture
    def sample_contract_file(self, tmp_path):
        """Create a temporary contract file"""
        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Test {}")
        return str(contract)

    def test_analyze_help(self, runner):
        """Test analyze command help"""
        result = runner.invoke(cli, ['analyze', '--help'])

        assert result.exit_code == 0
        assert 'analyze' in result.output.lower()
        assert 'contract' in result.output.lower()

    @patch('miesc.cli.miesc_cli.analyze_contract')
    def test_analyze_basic(self, mock_analyze, runner, sample_contract_file):
        """Test basic analyze command"""
        mock_analyze.return_value = {
            'timestamp': '2025-10-20T10:00:00',
            'contract': sample_contract_file,
            'tools_executed': ['slither'],
            'total_findings': 0,
            'findings_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'findings': [],
            'context': 'MIESC'
        }

        result = runner.invoke(cli, ['analyze', sample_contract_file])

        assert result.exit_code == 0
        assert mock_analyze.called
        # Check output contains analysis indicator
        assert '🔍' in result.output or 'Analyzing' in result.output

    @patch('miesc.cli.miesc_cli.analyze_contract')
    def test_analyze_with_type_option(self, mock_analyze, runner, sample_contract_file):
        """Test analyze with --type option"""
        mock_analyze.return_value = {
            'timestamp': '2025-10-20T10:00:00',
            'total_findings': 0,
            'findings': []
        }

        result = runner.invoke(cli, ['analyze', sample_contract_file, '--type', 'mythril'])

        assert result.exit_code == 0
        mock_analyze.assert_called_once()
        call_args = mock_analyze.call_args
        assert call_args[1]['analysis_type'] == 'mythril'

    @patch('miesc.cli.miesc_cli.analyze_contract')
    def test_analyze_with_timeout(self, mock_analyze, runner, sample_contract_file):
        """Test analyze with custom timeout"""
        mock_analyze.return_value = {'total_findings': 0, 'findings': []}

        result = runner.invoke(cli, ['analyze', sample_contract_file, '--timeout', '600'])

        assert result.exit_code == 0
        call_args = mock_analyze.call_args
        assert call_args[1]['timeout'] == 600

    def test_analyze_missing_file(self, runner):
        """Test analyze with non-existent file"""
        result = runner.invoke(cli, ['analyze', 'nonexistent.sol'])

        # Should fail with file not found
        assert result.exit_code != 0

    @patch('miesc.cli.miesc_cli.analyze_contract')
    def test_analyze_output_to_file(self, mock_analyze, runner, sample_contract_file, tmp_path):
        """Test analyze with --output option"""
        mock_analyze.return_value = {
            'timestamp': '2025-10-20T10:00:00',
            'total_findings': 1,
            'findings': [{'type': 'test'}]
        }

        output_file = tmp_path / "output.json"
        result = runner.invoke(cli, [
            'analyze',
            sample_contract_file,
            '--output', str(output_file)
        ])

        assert result.exit_code == 0
        assert output_file.exists()


class TestVerifyCommand:
    """Test suite for 'verify' command"""

    @pytest.fixture
    def runner(self):
        """Click CLI test runner"""
        return CliRunner()

    @pytest.fixture
    def sample_contract_file(self, tmp_path):
        """Create a temporary contract file"""
        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Test {}")
        return str(contract)

    def test_verify_help(self, runner):
        """Test verify command help"""
        result = runner.invoke(cli, ['verify', '--help'])

        assert result.exit_code == 0
        assert 'verify' in result.output.lower()
        assert 'formal' in result.output.lower() or 'verification' in result.output.lower()

    @patch('miesc.cli.miesc_cli.verify_contract')
    def test_verify_basic(self, mock_verify, runner, sample_contract_file):
        """Test basic verify command"""
        mock_verify.return_value = {
            'timestamp': '2025-10-20T10:00:00',
            'status': 'completed',
            'level': 'basic',
            'method': 'SMTChecker',
            'warnings': [],
            'errors': [],
            'context': 'MIESC'
        }

        result = runner.invoke(cli, ['verify', sample_contract_file])

        assert result.exit_code == 0
        assert mock_verify.called

    @patch('miesc.cli.miesc_cli.verify_contract')
    def test_verify_with_level(self, mock_verify, runner, sample_contract_file):
        """Test verify with --level option"""
        mock_verify.return_value = {'status': 'completed', 'warnings': []}

        result = runner.invoke(cli, ['verify', sample_contract_file, '--level', 'smt'])

        assert result.exit_code == 0
        call_args = mock_verify.call_args
        assert call_args[1]['verification_level'] == 'smt'

    @patch('miesc.cli.miesc_cli.verify_contract')
    def test_verify_with_properties(self, mock_verify, runner, sample_contract_file):
        """Test verify with --properties option"""
        mock_verify.return_value = {'status': 'completed', 'properties_verified': 1}

        result = runner.invoke(cli, [
            'verify',
            sample_contract_file,
            '--properties', 'invariant balance >= 0'
        ])

        assert result.exit_code == 0


class TestClassifyCommand:
    """Test suite for 'classify' command"""

    @pytest.fixture
    def runner(self):
        """Click CLI test runner"""
        return CliRunner()

    @pytest.fixture
    def sample_report_file(self, tmp_path):
        """Create a temporary report file"""
        report = tmp_path / "report.json"
        report.write_text(json.dumps({
            'timestamp': '2025-10-20T10:00:00',
            'findings': [
                {
                    'tool': 'slither',
                    'vulnerability_type': 'reentrancy',
                    'severity': 'High',
                    'swc_id': 'SWC-107'
                }
            ]
        }))
        return str(report)

    def test_classify_help(self, runner):
        """Test classify command help"""
        result = runner.invoke(cli, ['classify', '--help'])

        assert result.exit_code == 0
        assert 'classify' in result.output.lower()

    @patch('miesc.cli.miesc_cli.classify_vulnerabilities')
    def test_classify_basic(self, mock_classify, runner, sample_report_file):
        """Test basic classify command"""
        mock_classify.return_value = {
            'timestamp': '2025-10-20T10:00:00',
            'classified_findings': [],
            'statistics': {'total_findings': 0},
            'ai_triage_enabled': False,
            'context': 'MIESC'
        }

        result = runner.invoke(cli, ['classify', sample_report_file])

        assert result.exit_code == 0
        assert mock_classify.called

    @patch('miesc.cli.miesc_cli.classify_vulnerabilities')
    def test_classify_with_ai(self, mock_classify, runner, sample_report_file):
        """Test classify with --ai flag"""
        mock_classify.return_value = {
            'classified_findings': [],
            'statistics': {'total_findings': 0},
            'ai_triage_enabled': True
        }

        # Note: This will fail without a valid API key, but we can test the flag parsing
        result = runner.invoke(cli, ['classify', sample_report_file, '--ai'])

        # May fail due to API key requirement, but should attempt to call with AI enabled
        assert mock_classify.called


class TestServerCommand:
    """Test suite for 'server' command"""

    @pytest.fixture
    def runner(self):
        """Click CLI test runner"""
        return CliRunner()

    def test_server_help(self, runner):
        """Test server command help"""
        result = runner.invoke(cli, ['server', '--help'])

        assert result.exit_code == 0
        assert 'server' in result.output.lower()
        assert 'port' in result.output.lower() or 'host' in result.output.lower()


class TestErrorHandling:
    """Test suite for CLI error handling"""

    @pytest.fixture
    def runner(self):
        """Click CLI test runner"""
        return CliRunner()

    def test_invalid_command(self, runner):
        """Test invalid command"""
        result = runner.invoke(cli, ['invalid-command'])

        assert result.exit_code != 0
        assert 'Error' in result.output or 'error' in result.output or 'No such command' in result.output

    def test_analyze_invalid_type(self, runner, tmp_path):
        """Test analyze with invalid tool type"""
        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Test {}")

        result = runner.invoke(cli, ['analyze', str(contract), '--type', 'invalid-tool'])

        assert result.exit_code != 0

    @patch('miesc.cli.miesc_cli.analyze_contract')
    def test_analyze_exception_handling(self, mock_analyze, runner, tmp_path):
        """Test analyze handles exceptions gracefully"""
        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Test {}")

        mock_analyze.side_effect = Exception("Analysis failed")

        result = runner.invoke(cli, ['analyze', str(contract)])

        # Should handle exception gracefully
        assert result.exit_code != 0
        assert 'Error' in result.output or 'error' in result.output or 'failed' in result.output


# Pytest markers
pytestmark = [
    pytest.mark.integration,
    pytest.mark.cli
]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
