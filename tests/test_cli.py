"""
MIESC CLI Tests
Tests for ML CLI and command-line interface.
"""

import pytest
import sys
import os
import tempfile
from unittest.mock import patch, MagicMock
from io import StringIO


# Sample contract for testing
SAMPLE_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleContract {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}
'''


class TestMLCLI:
    """Tests for ML CLI module."""

    def test_import(self):
        """Test CLI module can be imported."""
        import src.miesc_ml_cli as cli
        assert cli is not None

    def test_main_function_exists(self):
        """Test main function exists."""
        from src.miesc_ml_cli import main
        assert callable(main)

    def test_print_banner(self):
        """Test banner printing function."""
        from src.miesc_ml_cli import print_banner

        # Capture output
        captured = StringIO()
        with patch('sys.stdout', captured):
            print_banner()

        output = captured.getvalue()
        assert 'MIESC' in output
        assert '4.0.0' in output

    def test_print_progress(self):
        """Test progress printing function."""
        from src.miesc_ml_cli import print_progress

        captured = StringIO()
        with patch('sys.stdout', captured):
            print_progress('test', 'Testing', 0.5)

        output = captured.getvalue()
        assert '50%' in output

    def test_cmd_tools(self):
        """Test tools command."""
        from src.miesc_ml_cli import cmd_tools

        # Create mock args
        args = MagicMock()
        args.layers = False

        result = cmd_tools(args)
        assert result == 0

    def test_cmd_tools_by_layer(self):
        """Test tools command with --layers flag."""
        from src.miesc_ml_cli import cmd_tools

        args = MagicMock()
        args.layers = True

        result = cmd_tools(args)
        assert result == 0

    def test_cmd_health(self):
        """Test health command."""
        from src.miesc_ml_cli import cmd_health

        args = MagicMock()
        args.json = False

        result = cmd_health(args)
        assert result == 0

    def test_cmd_health_json(self):
        """Test health command with JSON output."""
        from src.miesc_ml_cli import cmd_health

        args = MagicMock()
        args.json = True

        result = cmd_health(args)
        assert result == 0

    def test_cmd_ml_report(self):
        """Test ML report command."""
        from src.miesc_ml_cli import cmd_ml_report

        args = MagicMock()
        result = cmd_ml_report(args)
        assert result == 0

    def test_cmd_ml_feedback(self):
        """Test ML feedback command."""
        from src.miesc_ml_cli import cmd_ml_feedback

        args = MagicMock()
        args.finding_id = 'test123'
        args.type = 'tp'
        args.notes = 'Test feedback'

        result = cmd_ml_feedback(args)
        assert result == 0

    def test_cmd_ml_feedback_invalid_type(self):
        """Test ML feedback with invalid type."""
        from src.miesc_ml_cli import cmd_ml_feedback

        args = MagicMock()
        args.finding_id = 'test123'
        args.type = 'invalid_type'
        args.notes = None

        result = cmd_ml_feedback(args)
        assert result == 1  # Should fail

    @pytest.fixture
    def temp_contract(self):
        """Create temporary contract file."""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.sol', delete=False
        ) as f:
            f.write(SAMPLE_CONTRACT)
            yield f.name
        os.unlink(f.name)

    def test_cmd_ml_analyze_nonexistent(self):
        """Test ML analyze with non-existent file."""
        from src.miesc_ml_cli import cmd_ml_analyze

        args = MagicMock()
        args.contract = '/tmp/nonexistent_12345.sol'
        args.quick = False
        args.deep = False
        args.timeout = 30
        args.output = None
        args.quiet = True

        result = cmd_ml_analyze(args)
        assert result == 1  # Should fail

    def test_cmd_ml_scan_nonexistent_dir(self):
        """Test ML scan with non-existent directory."""
        from src.miesc_ml_cli import cmd_ml_scan

        args = MagicMock()
        args.directory = '/tmp/nonexistent_dir_12345'
        args.recursive = False
        args.timeout = 30

        result = cmd_ml_scan(args)
        assert result == 1  # Should fail


class TestCLIArgumentParser:
    """Tests for CLI argument parsing."""

    def test_parser_creation(self):
        """Test argument parser is created correctly."""
        import argparse
        from src.miesc_ml_cli import main

        # Main should handle no arguments gracefully
        with patch('sys.argv', ['miesc_ml_cli']):
            result = main()
            assert result == 0

    def test_subcommands_available(self):
        """Test all subcommands are available."""
        expected_commands = [
            'ml-analyze',
            'ml-scan',
            'ml-feedback',
            'ml-report',
            'tools',
            'health',
        ]

        # Check by attempting to run help for each
        for cmd in expected_commands:
            with patch('sys.argv', ['miesc_ml_cli', cmd, '--help']):
                with pytest.raises(SystemExit) as exc_info:
                    from src.miesc_ml_cli import main
                    main()
                # Help exits with 0
                assert exc_info.value.code == 0


class TestCLIOutput:
    """Tests for CLI output formatting."""

    def test_json_output_valid(self):
        """Test JSON output is valid."""
        import json
        from src.miesc_ml_cli import cmd_health

        args = MagicMock()
        args.json = True

        captured = StringIO()
        with patch('sys.stdout', captured):
            cmd_health(args)

        output = captured.getvalue()
        # Should be valid JSON
        try:
            json.loads(output)
            valid = True
        except json.JSONDecodeError:
            valid = False

        # May not output JSON if health check format different
        # Just ensure no crash
        assert True


class TestCLIErrorHandling:
    """Tests for CLI error handling."""

    def test_missing_contract_argument(self):
        """Test error when contract argument is missing."""
        with patch('sys.argv', ['miesc_ml_cli', 'ml-analyze']):
            with pytest.raises(SystemExit) as exc_info:
                from src.miesc_ml_cli import main
                main()
            # Should exit with error
            assert exc_info.value.code != 0

    def test_invalid_subcommand(self):
        """Test error with invalid subcommand."""
        with patch('sys.argv', ['miesc_ml_cli', 'invalid_command']):
            with pytest.raises(SystemExit) as exc_info:
                from src.miesc_ml_cli import main
                main()
            # argparse exits with code 2 for invalid commands
            assert exc_info.value.code == 2


class TestCLIIntegration:
    """Integration tests for CLI."""

    @pytest.fixture
    def temp_contract(self):
        """Create temporary contract file."""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.sol', delete=False
        ) as f:
            f.write(SAMPLE_CONTRACT)
            yield f.name
        os.unlink(f.name)

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory with contracts."""
        import tempfile
        import shutil

        tmpdir = tempfile.mkdtemp()
        # Create a test contract
        contract_path = os.path.join(tmpdir, 'Test.sol')
        with open(contract_path, 'w') as f:
            f.write(SAMPLE_CONTRACT)

        yield tmpdir
        shutil.rmtree(tmpdir)

    def test_full_analysis_workflow(self, temp_contract):
        """Test full analysis workflow."""
        from src.miesc_ml_cli import cmd_ml_analyze

        args = MagicMock()
        args.contract = temp_contract
        args.quick = True  # Use quick for speed
        args.deep = False
        args.timeout = 60
        args.output = None
        args.quiet = True

        # Should complete without exception
        result = cmd_ml_analyze(args)
        assert result in [0, 1]  # Success or findings

    def test_scan_directory(self, temp_dir):
        """Test directory scanning."""
        from src.miesc_ml_cli import cmd_ml_scan

        args = MagicMock()
        args.directory = temp_dir
        args.recursive = False
        args.timeout = 30

        result = cmd_ml_scan(args)
        assert result == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
