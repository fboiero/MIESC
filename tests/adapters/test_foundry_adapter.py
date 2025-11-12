"""
Comprehensive Test Suite for FoundryAdapter
============================================

Tests for Foundry testing framework adapter (Layer 2 - Dynamic Testing).

Autor: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Fecha: November 11, 2025
"""

import pytest
import tempfile
import os
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import subprocess

from src.core.tool_protocol import (
    ToolStatus, ToolCategory
)
from src.adapters.foundry_adapter import FoundryAdapter


# Sample Solidity contract for testing
SAMPLE_TEST_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract Counter {
    uint256 public count;

    function increment() public {
        count++;
    }
}

contract CounterTest is Test {
    Counter counter;

    function setUp() public {
        counter = new Counter();
    }

    function test_Increment() public {
        counter.increment();
        assertEq(counter.count(), 1);
    }

    function testFail_Overflow() public {
        counter.count = type(uint256).max;
        counter.increment();  // This should fail
    }
}
"""

# Sample Foundry text output for testing
SAMPLE_FOUNDRY_OUTPUT = """
[PASS] test_Increment() (gas: 12345)
[FAIL. Reason: Assertion failed] test_FailedAssertion() (gas: 54321)
[PASS] test_FuzzInput(uint256) (runs: 256, μ: 23456, ~: 23456)

Test result: ok. 2 passed; 1 failed; finished in 1.23s
"""

# Sample Foundry gas report
SAMPLE_GAS_REPORT = """
| Function     | Min | Avg   | Max   | Calls |
|--------------|-----|-------|-------|-------|
| increment    | 123 | 12345 | 23456 | 10    |
| decrement    | 100 | 11111 | 22222 | 5     |
| transfer     | 500 | 50000 | 99999 | 20    |
"""


class TestFoundryAdapterProtocol:
    """Test that FoundryAdapter implements Tool Adapter Protocol correctly"""

    def test_foundry_has_metadata(self):
        """Verify FoundryAdapter provides complete metadata"""
        adapter = FoundryAdapter()
        metadata = adapter.get_metadata()

        assert metadata.name == "foundry"
        assert metadata.version == "1.0.0"
        assert metadata.category == ToolCategory.DYNAMIC_TESTING
        assert metadata.author == "Paradigm (Adapter by Fernando Boiero)"
        assert metadata.license == "MIT"
        assert metadata.homepage == "https://github.com/foundry-rs/foundry"
        assert "foundryup" in metadata.installation_cmd
        assert metadata.cost == 0.0
        assert metadata.requires_api_key is False

    def test_foundry_is_optional(self):
        """DPGA compliance: Foundry must be optional"""
        adapter = FoundryAdapter()
        metadata = adapter.get_metadata()
        assert metadata.is_optional is True

    def test_foundry_has_capabilities(self):
        """Verify Foundry declares its capabilities"""
        adapter = FoundryAdapter()
        metadata = adapter.get_metadata()

        assert len(metadata.capabilities) >= 3

        # Check for unit testing capability
        unit_cap = [c for c in metadata.capabilities if c.name == "unit_testing"][0]
        assert "solidity" in unit_cap.supported_languages
        assert "test_failures" in unit_cap.detection_types

        # Check for fuzz testing capability
        fuzz_cap = [c for c in metadata.capabilities if c.name == "fuzz_testing"][0]
        assert "fuzz_failures" in fuzz_cap.detection_types

        # Check for gas profiling capability
        gas_cap = [c for c in metadata.capabilities if c.name == "gas_profiling"][0]
        assert "gas_inefficiencies" in gas_cap.detection_types


class TestFoundryAvailability:
    """Test Foundry availability checking"""

    @patch('subprocess.run')
    def test_foundry_available_when_installed(self, mock_run):
        """Test status when Foundry is installed and working"""
        # Mock successful forge --version call
        mock_run.return_value = Mock(
            returncode=0,
            stdout="forge 0.2.0"
        )

        adapter = FoundryAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.AVAILABLE
        mock_run.assert_called_once()
        assert "forge" in mock_run.call_args[0][0]
        assert "--version" in mock_run.call_args[0][0]

    @patch('subprocess.run')
    def test_foundry_not_installed(self, mock_run):
        """Test status when Foundry is not installed"""
        # Mock FileNotFoundError (forge command not found)
        mock_run.side_effect = FileNotFoundError("forge not found")

        adapter = FoundryAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.NOT_INSTALLED

    @patch('subprocess.run')
    def test_foundry_configuration_error(self, mock_run):
        """Test status when Foundry returns non-zero exit code"""
        # Mock failed forge call
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Error: configuration issue"
        )

        adapter = FoundryAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.CONFIGURATION_ERROR

    @patch('subprocess.run')
    def test_foundry_timeout(self, mock_run):
        """Test status when version check times out"""
        # Mock timeout
        mock_run.side_effect = subprocess.TimeoutExpired("forge", 5)

        adapter = FoundryAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.CONFIGURATION_ERROR


class TestFoundryAnalysis:
    """Test Foundry analysis functionality"""

    @patch('subprocess.run')
    def test_foundry_successful_analysis(self, mock_run):
        """Test successful Foundry analysis"""
        # Mock successful forge test execution
        mock_run.side_effect = [
            # First call: is_available() check
            Mock(returncode=0, stdout="forge 0.2.0"),
            # Second call: actual test run
            Mock(
                returncode=0,
                stdout=SAMPLE_FOUNDRY_OUTPUT,
                stderr=""
            )
        ]

        adapter = FoundryAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create foundry.toml to simulate Foundry project
            foundry_toml = Path(tmpdir) / "foundry.toml"
            foundry_toml.write_text("[profile.default]\nsrc = 'src'\ntest = 'test'")

            contract_path = str(Path(tmpdir) / "test" / "Counter.t.sol")
            os.makedirs(os.path.dirname(contract_path), exist_ok=True)
            Path(contract_path).write_text(SAMPLE_TEST_CONTRACT)

            result = adapter.analyze(contract_path)

            assert result['tool'] == 'foundry'
            assert result['version'] == '1.0.0'
            assert result['status'] == 'success'
            assert 'findings' in result
            assert 'execution_time' in result
            assert isinstance(result['execution_time'], float)
            assert 'tests_run' in result
            assert result['dpga_compliant'] is True

    @patch('subprocess.run')
    def test_foundry_not_available_during_analysis(self, mock_run):
        """Test analysis when Foundry is not available"""
        # Mock Foundry not installed
        mock_run.side_effect = FileNotFoundError("forge not found")

        adapter = FoundryAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert result['status'] == 'error'
        assert 'error' in result
        assert 'not available' in result['error'].lower()
        assert result['findings'] == []

    @patch('subprocess.run')
    def test_foundry_analysis_timeout(self, mock_run):
        """Test analysis timeout handling"""
        # Mock timeout during analysis
        mock_run.side_effect = [
            Mock(returncode=0, stdout="forge 0.2.0"),  # is_available
            subprocess.TimeoutExpired("forge", 300)     # analyze
        ]

        adapter = FoundryAdapter()
        result = adapter.analyze("/tmp/test.sol", timeout=300)

        assert result['status'] == 'error'
        assert 'timeout' in result['error'].lower()
        assert result['findings'] == []
        assert result['execution_time'] == 300

    @patch('subprocess.run')
    def test_foundry_project_root_detection(self, mock_run):
        """Test automatic detection of Foundry project root"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="forge 0.2.0"),
            Mock(returncode=0, stdout=SAMPLE_FOUNDRY_OUTPUT, stderr="")
        ]

        adapter = FoundryAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create foundry.toml at root
            foundry_toml = Path(tmpdir) / "foundry.toml"
            foundry_toml.write_text("[profile.default]")

            # Create nested test file
            test_dir = Path(tmpdir) / "src" / "test"
            test_dir.mkdir(parents=True)
            test_file = test_dir / "Test.sol"
            test_file.write_text(SAMPLE_TEST_CONTRACT)

            # Should find project root even from nested file
            root = adapter._find_project_root(str(test_file))
            assert root == tmpdir


class TestFoundryFindingsNormalization:
    """Test Foundry findings normalization to MIESC standard format"""

    def test_parse_test_failures(self):
        """Test parsing of test failures from Foundry output"""
        adapter = FoundryAdapter()
        findings, stats = adapter._parse_output(SAMPLE_FOUNDRY_OUTPUT, "")

        assert isinstance(findings, list)

        # Should have at least one failure
        failures = [f for f in findings if f['type'] == 'test_failure']
        assert len(failures) >= 1

        # Check failure properties
        if failures:
            failure = failures[0]
            assert failure['severity'] == 'high'
            assert 'test' in failure
            assert 'description' in failure

    def test_parse_test_statistics(self):
        """Test extraction of test statistics"""
        adapter = FoundryAdapter()
        findings, stats = adapter._parse_output(SAMPLE_FOUNDRY_OUTPUT, "")

        assert isinstance(stats, dict)
        assert 'total' in stats
        assert 'passed' in stats
        assert 'failed' in stats
        assert stats['passed'] == 2
        assert stats['failed'] == 1
        assert stats['total'] == 3

    def test_parse_gas_report(self):
        """Test gas report extraction"""
        adapter = FoundryAdapter()
        gas_report = adapter._extract_gas_report(SAMPLE_GAS_REPORT, "")

        assert isinstance(gas_report, dict)
        assert gas_report['available'] is True

        if 'functions' in gas_report:
            assert len(gas_report['functions']) >= 1
            func = gas_report['functions'][0]
            assert 'function' in func
            assert 'avg_gas' in func

    def test_normalize_empty_findings(self):
        """Test normalization with empty findings"""
        adapter = FoundryAdapter()

        empty_output = {"findings": []}
        normalized = adapter.normalize_findings(empty_output)

        assert isinstance(normalized, list)
        assert len(normalized) == 0


class TestFoundryCanAnalyze:
    """Test can_analyze() method"""

    def test_can_analyze_solidity_file(self):
        """Test that Foundry can analyze .sol files"""
        adapter = FoundryAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_TEST_CONTRACT)
            contract_path = f.name

        try:
            assert adapter.can_analyze(contract_path) is True
        finally:
            os.unlink(contract_path)

    def test_can_analyze_foundry_project(self):
        """Test that Foundry can analyze directories with foundry.toml"""
        adapter = FoundryAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create foundry.toml
            foundry_toml = Path(tmpdir) / "foundry.toml"
            foundry_toml.write_text("[profile.default]")

            assert adapter.can_analyze(tmpdir) is True

    def test_cannot_analyze_non_foundry_directory(self):
        """Test that Foundry cannot analyze directories without foundry.toml"""
        adapter = FoundryAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            assert adapter.can_analyze(tmpdir) is False

    def test_cannot_analyze_nonexistent_path(self):
        """Test that Foundry cannot analyze nonexistent paths"""
        adapter = FoundryAdapter()
        assert adapter.can_analyze("/nonexistent/path") is False


class TestFoundryConfiguration:
    """Test Foundry configuration and default settings"""

    def test_get_default_config(self):
        """Test default configuration"""
        adapter = FoundryAdapter()
        config = adapter.get_default_config()

        assert isinstance(config, dict)
        assert 'test_pattern' in config
        assert 'fuzz_runs' in config
        assert 'gas_report' in config
        assert 'timeout' in config
        assert config['fuzz_runs'] == 256
        assert config['gas_report'] is True
        assert config['timeout'] == 300

    @patch('subprocess.run')
    def test_custom_fuzz_runs(self, mock_run):
        """Test analysis with custom fuzz runs"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="forge 0.2.0"),
            Mock(returncode=0, stdout="", stderr="")
        ]

        adapter = FoundryAdapter(config={"fuzz_runs": 1000})
        result = adapter.analyze("/tmp/test.sol")

        # Verify fuzz runs was passed to subprocess
        call_args = mock_run.call_args_list[1][0][0]
        assert '--fuzz-runs' in call_args
        assert '1000' in call_args

    @patch('subprocess.run')
    def test_gas_report_flag(self, mock_run):
        """Test analysis with gas report enabled"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="forge 0.2.0"),
            Mock(returncode=0, stdout="", stderr="")
        ]

        adapter = FoundryAdapter(config={"gas_report": True})
        result = adapter.analyze("/tmp/test.sol")

        # Verify gas report flag was added
        call_args = mock_run.call_args_list[1][0][0]
        assert '--gas-report' in call_args


class TestFoundryDPGACompliance:
    """Test DPGA compliance requirements"""

    def test_foundry_is_optional(self):
        """DPGA: Foundry must be marked as optional"""
        adapter = FoundryAdapter()
        metadata = adapter.get_metadata()
        assert metadata.is_optional is True

    def test_foundry_has_open_source_license(self):
        """DPGA: Foundry must have open source compatible license"""
        adapter = FoundryAdapter()
        metadata = adapter.get_metadata()

        open_source_licenses = ["MIT", "GPL", "Apache", "BSD"]
        assert any(lic in metadata.license for lic in open_source_licenses)

    @patch('subprocess.run')
    def test_graceful_degradation_when_not_installed(self, mock_run):
        """DPGA: System must handle Foundry not being installed gracefully"""
        mock_run.side_effect = FileNotFoundError("forge not found")

        adapter = FoundryAdapter()

        # Should not raise exception
        status = adapter.is_available()
        assert status == ToolStatus.NOT_INSTALLED

        # Analysis should return error result, not raise exception
        result = adapter.analyze("/tmp/test.sol")
        assert result['status'] == 'error'
        assert isinstance(result, dict)
        assert 'error' in result

    def test_zero_cost(self):
        """DPGA: Foundry must be free (zero cost)"""
        adapter = FoundryAdapter()
        metadata = adapter.get_metadata()
        assert metadata.cost == 0.0

    def test_no_api_key_required(self):
        """DPGA: Foundry must not require API keys"""
        adapter = FoundryAdapter()
        metadata = adapter.get_metadata()
        assert metadata.requires_api_key is False


class TestFoundryFuzzTesting:
    """Test Foundry fuzz testing features"""

    def test_fuzz_runs_configurable(self):
        """Test that fuzz runs can be configured"""
        adapter = FoundryAdapter(config={"fuzz_runs": 512})
        config = adapter.get_default_config()

        # Config should allow customization
        assert 'fuzz_runs' in config

    @patch('subprocess.run')
    def test_fuzz_test_detection(self, mock_run):
        """Test detection of fuzz test results"""
        fuzz_output = "[PASS] testFuzz_Transfer(uint256,address) (runs: 256, μ: 50000, ~: 50000)"

        mock_run.side_effect = [
            Mock(returncode=0, stdout="forge 0.2.0"),
            Mock(returncode=0, stdout=fuzz_output, stderr="")
        ]

        adapter = FoundryAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert result['status'] == 'success'
        assert 'fuzz_runs' in result


class TestFoundryPerformance:
    """Test Foundry performance characteristics"""

    @patch('subprocess.run')
    def test_execution_time_reported(self, mock_run):
        """Test that execution time is always reported"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="forge 0.2.0"),
            Mock(returncode=0, stdout="", stderr="")
        ]

        adapter = FoundryAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert 'execution_time' in result
        assert isinstance(result['execution_time'], float)
        assert result['execution_time'] >= 0

    @patch('subprocess.run')
    def test_test_statistics_reported(self, mock_run):
        """Test that test statistics are reported"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="forge 0.2.0"),
            Mock(returncode=0, stdout=SAMPLE_FOUNDRY_OUTPUT, stderr="")
        ]

        adapter = FoundryAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert 'tests_run' in result
        assert 'tests_passed' in result
        assert 'tests_failed' in result


class TestFoundryGasProfiling:
    """Test Foundry gas profiling features"""

    @patch('subprocess.run')
    def test_gas_report_extraction(self, mock_run):
        """Test gas report extraction from output"""
        output_with_gas = SAMPLE_FOUNDRY_OUTPUT + "\n" + SAMPLE_GAS_REPORT

        mock_run.side_effect = [
            Mock(returncode=0, stdout="forge 0.2.0"),
            Mock(returncode=0, stdout=output_with_gas, stderr="")
        ]

        adapter = FoundryAdapter(config={"gas_report": True})
        result = adapter.analyze("/tmp/test.sol")

        assert 'gas_report' in result
        assert result['gas_report']['available'] is True

    def test_gas_report_parsing(self):
        """Test parsing of gas report table"""
        adapter = FoundryAdapter()
        gas_report = adapter._extract_gas_report(SAMPLE_GAS_REPORT, "")

        assert gas_report['available'] is True
        if 'functions' in gas_report:
            # Should extract function gas metrics
            assert len(gas_report['functions']) <= 10  # Top 10 limit


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
