"""
Comprehensive Test Suite for EchidnaAdapter
============================================

Tests for Echidna property-based fuzzer adapter (Layer 2 - Dynamic Testing).

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
from src.adapters.echidna_adapter import EchidnaAdapter


# Sample Solidity contract for testing
SAMPLE_VULNERABLE_CONTRACT = """
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;  // State change after external call
    }

    // Echidna property: balance should never exceed total supply
    function echidna_balance_check() public view returns (bool) {
        return balances[msg.sender] <= address(this).balance;
    }
}
"""

# Sample Echidna text output for testing
SAMPLE_ECHIDNA_OUTPUT = """
echidna_balance_check: failed!💥
  Call sequence:
    1. deposit()
    2. withdraw(100)
    3. withdraw(50)

echidna_no_overflow: failed!💥
  Call sequence:
    1. transfer(0x123, 1000)
    2. transfer(0x456, 2000)

Unique instructions: 1523
Unique codehashes: 2
Corpus size: 45
Seed: 1234567890
"""


class TestEchidnaAdapterProtocol:
    """Test that EchidnaAdapter implements Tool Adapter Protocol correctly"""

    def test_echidna_has_metadata(self):
        """Verify EchidnaAdapter provides complete metadata"""
        adapter = EchidnaAdapter()
        metadata = adapter.get_metadata()

        assert metadata.name == "echidna"
        assert metadata.version == "1.0.0"
        assert metadata.category == ToolCategory.DYNAMIC_TESTING
        assert metadata.author == "Trail of Bits (Adapter by Fernando Boiero)"
        assert metadata.license == "AGPL-3.0"
        assert metadata.homepage == "https://github.com/crytic/echidna"
        assert metadata.installation_cmd == "brew install echidna"
        assert metadata.cost == 0.0
        assert metadata.requires_api_key is False

    def test_echidna_is_optional(self):
        """DPGA compliance: Echidna must be optional"""
        adapter = EchidnaAdapter()
        metadata = adapter.get_metadata()
        assert metadata.is_optional is True

    def test_echidna_has_capabilities(self):
        """Verify Echidna declares its capabilities"""
        adapter = EchidnaAdapter()
        metadata = adapter.get_metadata()

        assert len(metadata.capabilities) > 0
        cap = metadata.capabilities[0]
        assert cap.name == "property_based_fuzzing"
        assert "solidity" in cap.supported_languages
        assert len(cap.detection_types) >= 3  # invariant_violations, assertion_failures, property_violations

    def test_echidna_detects_key_vulnerabilities(self):
        """Verify Echidna declares detection of key vulnerability types"""
        adapter = EchidnaAdapter()
        metadata = adapter.get_metadata()

        detection_types = metadata.capabilities[0].detection_types

        # Check for key vulnerability types
        assert "invariant_violations" in detection_types
        assert "assertion_failures" in detection_types
        assert "property_violations" in detection_types


class TestEchidnaAvailability:
    """Test Echidna availability checking"""

    @patch('subprocess.run')
    def test_echidna_available_when_installed(self, mock_run):
        """Test status when Echidna is installed and working"""
        # Mock successful echidna --version call
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Echidna 2.2.0"
        )

        adapter = EchidnaAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.AVAILABLE
        mock_run.assert_called_once()
        assert "echidna" in mock_run.call_args[0][0]
        assert "--version" in mock_run.call_args[0][0]

    @patch('subprocess.run')
    def test_echidna_not_installed(self, mock_run):
        """Test status when Echidna is not installed"""
        # Mock FileNotFoundError (echidna command not found)
        mock_run.side_effect = FileNotFoundError("echidna not found")

        adapter = EchidnaAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.NOT_INSTALLED

    @patch('subprocess.run')
    def test_echidna_configuration_error(self, mock_run):
        """Test status when Echidna returns non-zero exit code"""
        # Mock failed echidna call
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Error: configuration issue"
        )

        adapter = EchidnaAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.CONFIGURATION_ERROR

    @patch('subprocess.run')
    def test_echidna_timeout(self, mock_run):
        """Test status when version check times out"""
        # Mock timeout
        mock_run.side_effect = subprocess.TimeoutExpired("echidna", 5)

        adapter = EchidnaAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.CONFIGURATION_ERROR


class TestEchidnaAnalysis:
    """Test Echidna analysis functionality"""

    @patch('subprocess.run')
    def test_echidna_successful_analysis(self, mock_run):
        """Test successful Echidna analysis"""
        # Mock successful echidna execution
        mock_run.side_effect = [
            # First call: is_available() check
            Mock(returncode=0, stdout="Echidna 2.2.0"),
            # Second call: actual analysis
            Mock(
                returncode=0,
                stdout=SAMPLE_ECHIDNA_OUTPUT,
                stderr=""
            )
        ]

        adapter = EchidnaAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            assert result['tool'] == 'echidna'
            assert result['version'] == '1.0.0'
            assert result['status'] == 'success'
            assert 'findings' in result
            assert 'execution_time' in result
            assert isinstance(result['execution_time'], float)
            assert 'tests_run' in result
            assert result['dpga_compliant'] is True

        finally:
            os.unlink(contract_path)

    @patch('subprocess.run')
    def test_echidna_not_available_during_analysis(self, mock_run):
        """Test analysis when Echidna is not available"""
        # Mock Echidna not installed
        mock_run.side_effect = FileNotFoundError("echidna not found")

        adapter = EchidnaAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert result['status'] == 'error'
        assert 'error' in result
        assert 'not available' in result['error'].lower()
        assert result['findings'] == []

    @patch('subprocess.run')
    def test_echidna_analysis_timeout(self, mock_run):
        """Test analysis timeout handling"""
        # Mock timeout during analysis
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Echidna 2.2.0"),  # is_available
            subprocess.TimeoutExpired("echidna", 600)     # analyze
        ]

        adapter = EchidnaAdapter()
        result = adapter.analyze("/tmp/test.sol", timeout=600)

        assert result['status'] == 'error'
        assert 'timeout' in result['error'].lower()
        assert result['findings'] == []
        assert result['execution_time'] == 600

    @patch('subprocess.run')
    def test_echidna_analysis_execution_error(self, mock_run):
        """Test handling of Echidna execution errors"""
        # Mock failed execution
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Echidna 2.2.0"),  # is_available
            Mock(
                returncode=1,
                stdout="",
                stderr="Error: failed to analyze contract"
            )
        ]

        adapter = EchidnaAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert result['status'] == 'success'  # Echidna returns results even on failure
        assert 'findings' in result


class TestEchidnaFindingsNormalization:
    """Test Echidna findings normalization to MIESC standard format"""

    def test_parse_property_violations(self):
        """Test parsing of property violations from Echidna output"""
        adapter = EchidnaAdapter()
        findings = adapter._parse_output(SAMPLE_ECHIDNA_OUTPUT, "")

        assert isinstance(findings, list)
        assert len(findings) >= 2  # At least 2 property violations

        # Check first finding
        finding = findings[0]
        assert finding['type'] == 'property_violation'
        assert finding['severity'] == 'high'
        assert 'property' in finding
        assert 'description' in finding
        assert 'recommendation' in finding

    def test_call_sequence_extraction(self):
        """Test extraction of call sequences from Echidna output"""
        adapter = EchidnaAdapter()
        findings = adapter._parse_output(SAMPLE_ECHIDNA_OUTPUT, "")

        # First finding should have call sequence
        finding = findings[0]
        if 'call_sequence' in finding:
            assert isinstance(finding['call_sequence'], list)
            assert len(finding['call_sequence']) >= 1

    def test_extract_tests_run(self):
        """Test extraction of test count from output"""
        adapter = EchidnaAdapter()

        output_with_tests = "Ran 50000 tests for property echidna_test"
        tests_run = adapter._extract_tests_run(output_with_tests)

        assert tests_run == 50000

    def test_extract_coverage(self):
        """Test coverage extraction (returns basic info)"""
        adapter = EchidnaAdapter()
        coverage = adapter._extract_coverage(SAMPLE_ECHIDNA_OUTPUT)

        assert isinstance(coverage, dict)
        assert 'available' in coverage

    def test_normalize_empty_findings(self):
        """Test normalization with empty findings"""
        adapter = EchidnaAdapter()

        empty_output = {"findings": []}
        normalized = adapter.normalize_findings(empty_output)

        assert isinstance(normalized, list)
        assert len(normalized) == 0


class TestEchidnaCanAnalyze:
    """Test can_analyze() method"""

    def test_can_analyze_solidity_file(self):
        """Test that Echidna can analyze .sol files"""
        adapter = EchidnaAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            assert adapter.can_analyze(contract_path) is True
        finally:
            os.unlink(contract_path)

    def test_cannot_analyze_non_solidity_file(self):
        """Test that Echidna cannot analyze non-.sol files"""
        adapter = EchidnaAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Not a Solidity contract")
            file_path = f.name

        try:
            assert adapter.can_analyze(file_path) is False
        finally:
            os.unlink(file_path)

    def test_cannot_analyze_nonexistent_path(self):
        """Test that Echidna cannot analyze nonexistent paths"""
        adapter = EchidnaAdapter()
        assert adapter.can_analyze("/nonexistent/path") is False


class TestEchidnaConfiguration:
    """Test Echidna configuration and default settings"""

    def test_get_default_config(self):
        """Test default configuration"""
        adapter = EchidnaAdapter()
        config = adapter.get_default_config()

        assert isinstance(config, dict)
        assert 'test_limit' in config
        assert 'timeout' in config
        assert 'test_mode' in config
        assert config['test_limit'] == 50000
        assert config['timeout'] == 600
        assert config['test_mode'] == 'property'

    @patch('subprocess.run')
    def test_custom_test_limit(self, mock_run):
        """Test analysis with custom test limit"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Echidna 2.2.0"),
            Mock(returncode=0, stdout="", stderr="")
        ]

        adapter = EchidnaAdapter(config={"test_limit": 100000})
        result = adapter.analyze("/tmp/test.sol")

        # Verify test limit was passed to subprocess
        call_args = mock_run.call_args_list[1][0][0]
        assert '--test-limit' in call_args
        assert '100000' in call_args

    @patch('subprocess.run')
    def test_custom_timeout(self, mock_run):
        """Test analysis with custom timeout"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Echidna 2.2.0"),
            Mock(returncode=0, stdout="", stderr="")
        ]

        adapter = EchidnaAdapter(config={"timeout": 1200})
        result = adapter.analyze("/tmp/test.sol")

        # Verify timeout was passed to subprocess
        call_kwargs = mock_run.call_args_list[1][1]
        assert call_kwargs['timeout'] == 1200


class TestEchidnaDPGACompliance:
    """Test DPGA compliance requirements"""

    def test_echidna_is_optional(self):
        """DPGA: Echidna must be marked as optional"""
        adapter = EchidnaAdapter()
        metadata = adapter.get_metadata()
        assert metadata.is_optional is True

    def test_echidna_has_open_source_license(self):
        """DPGA: Echidna must have open source compatible license"""
        adapter = EchidnaAdapter()
        metadata = adapter.get_metadata()

        open_source_licenses = ["MIT", "GPL", "AGPL", "Apache", "BSD"]
        assert any(lic in metadata.license for lic in open_source_licenses)

    @patch('subprocess.run')
    def test_graceful_degradation_when_not_installed(self, mock_run):
        """DPGA: System must handle Echidna not being installed gracefully"""
        mock_run.side_effect = FileNotFoundError("echidna not found")

        adapter = EchidnaAdapter()

        # Should not raise exception
        status = adapter.is_available()
        assert status == ToolStatus.NOT_INSTALLED

        # Analysis should return error result, not raise exception
        result = adapter.analyze("/tmp/test.sol")
        assert result['status'] == 'error'
        assert isinstance(result, dict)
        assert 'error' in result

    def test_zero_cost(self):
        """DPGA: Echidna must be free (zero cost)"""
        adapter = EchidnaAdapter()
        metadata = adapter.get_metadata()
        assert metadata.cost == 0.0

    def test_no_api_key_required(self):
        """DPGA: Echidna must not require API keys"""
        adapter = EchidnaAdapter()
        metadata = adapter.get_metadata()
        assert metadata.requires_api_key is False


class TestEchidnaPropertyTesting:
    """Test Echidna property-based testing features"""

    def test_property_mode_default(self):
        """Test that property mode is the default test mode"""
        adapter = EchidnaAdapter()
        config = adapter.get_default_config()

        assert config['test_mode'] == 'property'

    @patch('subprocess.run')
    def test_assertion_mode(self, mock_run):
        """Test Echidna with assertion test mode"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Echidna 2.2.0"),
            Mock(returncode=0, stdout="", stderr="")
        ]

        adapter = EchidnaAdapter()
        result = adapter.analyze("/tmp/test.sol", test_mode="assertion")

        # Verify assertion mode flag was added
        call_args = mock_run.call_args_list[1][0][0]
        assert '--test-mode=assertion' in call_args

    def test_high_severity_for_violations(self):
        """Test that property violations are classified as high severity"""
        adapter = EchidnaAdapter()
        findings = adapter._parse_output(SAMPLE_ECHIDNA_OUTPUT, "")

        # All property violations should be high severity
        for finding in findings:
            if finding['type'] == 'property_violation':
                assert finding['severity'] == 'high'


class TestEchidnaPerformance:
    """Test Echidna performance characteristics"""

    @patch('subprocess.run')
    def test_execution_time_reported(self, mock_run):
        """Test that execution time is always reported"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Echidna 2.2.0"),
            Mock(returncode=0, stdout="", stderr="")
        ]

        adapter = EchidnaAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert 'execution_time' in result
        assert isinstance(result['execution_time'], float)
        assert result['execution_time'] >= 0

    @patch('subprocess.run')
    def test_test_limit_reporting(self, mock_run):
        """Test that test limit is reported in results"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Echidna 2.2.0"),
            Mock(returncode=0, stdout="Ran 50000 tests", stderr="")
        ]

        adapter = EchidnaAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert 'test_limit' in result
        assert result['test_limit'] == 50000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
