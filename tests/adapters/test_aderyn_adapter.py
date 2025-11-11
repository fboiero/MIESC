"""
Comprehensive Test Suite for AderynAdapter
============================================

Tests for Aderyn static analyzer adapter (2025 Security Enhancement).

Autor: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Fecha: November 10, 2025
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
from src.adapters.aderyn_adapter import AderynAdapter


# Sample Solidity contract for testing
SAMPLE_VULNERABLE_CONTRACT = """
pragma solidity ^0.8.0;

contract VulnerableContract {
    address public owner;
    uint256 public balance;

    // Missing access control - Aderyn should detect
    function withdraw(uint256 amount) public {
        payable(msg.sender).transfer(amount);
    }

    // tx.origin usage - Aderyn should detect
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }

    // Uninitialized state variable
    address uninitializedAddress;

    // Dangerous strict equality
    function checkBalance() public view returns (bool) {
        return address(this).balance == 100 ether;
    }
}
"""

# Sample Aderyn JSON output for testing
SAMPLE_ADERYN_OUTPUT = {
    "version": "1.0.0",
    "timestamp": "2025-01-09T12:00:00Z",
    "findings": [
        {
            "detector": "tx-origin",
            "severity": "High",
            "title": "Use of tx.origin for authorization",
            "description": "tx.origin should not be used for authorization as it can be manipulated by attackers",
            "remediation": "Use msg.sender instead of tx.origin for access control",
            "locations": [
                {
                    "source_file": "VulnerableContract.sol",
                    "source_line": 14,
                    "function_name": "transferOwnership"
                }
            ]
        },
        {
            "detector": "missing-access-control",
            "severity": "Critical",
            "title": "Missing access control",
            "description": "Function allows anyone to withdraw funds",
            "remediation": "Add proper access control modifiers",
            "locations": [
                {
                    "source_file": "VulnerableContract.sol",
                    "source_line": 8,
                    "function_name": "withdraw"
                }
            ]
        },
        {
            "detector": "uninitialized-state-variable",
            "severity": "Medium",
            "title": "Uninitialized state variable",
            "description": "State variable is declared but not initialized",
            "remediation": "Initialize the state variable in constructor or declaration",
            "locations": [
                {
                    "source_file": "VulnerableContract.sol",
                    "source_line": 18,
                    "function_name": "unknown"
                }
            ]
        },
        {
            "detector": "dangerous-strict-equality",
            "severity": "Low",
            "title": "Dangerous strict equality",
            "description": "Strict equality check on balance can be manipulated",
            "remediation": "Use >= or <= instead of == for balance checks",
            "locations": [
                {
                    "source_file": "VulnerableContract.sol",
                    "source_line": 22,
                    "function_name": "checkBalance"
                }
            ]
        }
    ]
}


class TestAderynAdapterProtocol:
    """Test that AderynAdapter implements Tool Adapter Protocol correctly"""

    def test_aderyn_has_metadata(self):
        """Verify AderynAdapter provides complete metadata"""
        adapter = AderynAdapter()
        metadata = adapter.get_metadata()

        assert metadata.name == "aderyn"
        assert metadata.version == "1.0.0"
        assert metadata.category == ToolCategory.STATIC_ANALYSIS
        assert metadata.author == "Cyfrin (Adapter by Fernando Boiero)"
        assert metadata.license == "MIT"
        assert metadata.homepage == "https://github.com/Cyfrin/aderyn"
        assert metadata.installation_cmd == "cargo install aderyn"
        assert metadata.cost == 0.0
        assert metadata.requires_api_key is False

    def test_aderyn_is_optional(self):
        """DPGA compliance: Aderyn must be optional"""
        adapter = AderynAdapter()
        metadata = adapter.get_metadata()
        assert metadata.is_optional is True

    def test_aderyn_has_capabilities(self):
        """Verify Aderyn declares its capabilities"""
        adapter = AderynAdapter()
        metadata = adapter.get_metadata()

        assert len(metadata.capabilities) > 0
        cap = metadata.capabilities[0]
        assert cap.name == "static_analysis"
        assert "solidity" in cap.supported_languages
        assert len(cap.detection_types) >= 10  # Aderyn has many detectors

    def test_aderyn_detects_key_vulnerabilities(self):
        """Verify Aderyn declares detection of key vulnerability types"""
        adapter = AderynAdapter()
        metadata = adapter.get_metadata()

        detection_types = metadata.capabilities[0].detection_types

        # Check for key vulnerability types
        assert "reentrancy" in detection_types
        assert "access_control" in detection_types
        assert "tx_origin_usage" in detection_types
        assert "uninitialized_state_variables" in detection_types


class TestAderynAvailability:
    """Test Aderyn availability checking"""

    @patch('subprocess.run')
    def test_aderyn_available_when_installed(self, mock_run):
        """Test status when Aderyn is installed and working"""
        # Mock successful aderyn --version call
        mock_run.return_value = Mock(
            returncode=0,
            stdout="aderyn 1.0.0"
        )

        adapter = AderynAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.AVAILABLE
        mock_run.assert_called_once()
        assert "aderyn" in mock_run.call_args[0][0]
        assert "--version" in mock_run.call_args[0][0]

    @patch('subprocess.run')
    def test_aderyn_not_installed(self, mock_run):
        """Test status when Aderyn is not installed"""
        # Mock FileNotFoundError (aderyn command not found)
        mock_run.side_effect = FileNotFoundError("aderyn not found")

        adapter = AderynAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.NOT_INSTALLED

    @patch('subprocess.run')
    def test_aderyn_configuration_error(self, mock_run):
        """Test status when Aderyn returns non-zero exit code"""
        # Mock failed aderyn call
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Error: configuration issue"
        )

        adapter = AderynAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.CONFIGURATION_ERROR

    @patch('subprocess.run')
    def test_aderyn_timeout(self, mock_run):
        """Test status when version check times out"""
        # Mock timeout
        mock_run.side_effect = subprocess.TimeoutExpired("aderyn", 5)

        adapter = AderynAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.CONFIGURATION_ERROR


class TestAderynAnalysis:
    """Test Aderyn analysis functionality"""

    @patch('subprocess.run')
    @patch('builtins.open', create=True)
    def test_aderyn_successful_analysis(self, mock_open, mock_run):
        """Test successful Aderyn analysis"""
        # Mock successful aderyn execution
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Analysis complete",
            stderr=""
        )

        # Mock JSON output file reading
        mock_file = MagicMock()
        mock_file.__enter__.return_value = MagicMock()
        mock_file.__enter__.return_value.read.return_value = json.dumps(SAMPLE_ADERYN_OUTPUT)
        mock_open.return_value = mock_file

        adapter = AderynAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            assert result['tool'] == 'aderyn'
            assert result['version'] == '1.0.0'
            assert result['status'] == 'success'
            assert 'findings' in result
            assert 'metadata' in result
            assert 'execution_time' in result
            assert isinstance(result['execution_time'], float)

        finally:
            os.unlink(contract_path)

    @patch('subprocess.run')
    def test_aderyn_not_available_during_analysis(self, mock_run):
        """Test analysis when Aderyn is not available"""
        # Mock Aderyn not installed
        mock_run.side_effect = FileNotFoundError("aderyn not found")

        adapter = AderynAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert result['status'] == 'error'
        assert 'error' in result
        assert 'not available' in result['error'].lower()
        assert result['findings'] == []

    @patch('subprocess.run')
    def test_aderyn_analysis_timeout(self, mock_run):
        """Test analysis timeout handling"""
        # Mock timeout during analysis
        mock_run.side_effect = subprocess.TimeoutExpired("aderyn", 300)

        adapter = AderynAdapter()
        result = adapter.analyze("/tmp/test.sol", timeout=300)

        assert result['status'] == 'error'
        assert 'timeout' in result['error'].lower()
        assert result['findings'] == []
        assert 'timeout' in result['metadata']

    @patch('subprocess.run')
    def test_aderyn_analysis_execution_error(self, mock_run):
        """Test handling of Aderyn execution errors"""
        # Mock failed execution
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Error: failed to analyze contract"
        )

        adapter = AderynAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert result['status'] == 'error'
        assert 'error' in result
        assert result['findings'] == []
        assert 'exit_code' in result['metadata']
        assert result['metadata']['exit_code'] == 1


class TestAderynFindingsNormalization:
    """Test Aderyn findings normalization to MIESC standard format"""

    def test_normalize_aderyn_findings(self):
        """Test normalization of Aderyn JSON output"""
        adapter = AderynAdapter()
        normalized = adapter.normalize_findings(SAMPLE_ADERYN_OUTPUT)

        assert isinstance(normalized, list)
        assert len(normalized) == 4  # All 4 findings from sample

        # Check first finding (tx-origin)
        finding = normalized[0]
        assert finding['type'] == 'tx-origin'
        assert finding['severity'] == 'High'
        assert finding['location']['file'] == 'VulnerableContract.sol'
        assert finding['location']['line'] == 14
        assert finding['location']['function'] == 'transferOwnership'
        assert 'id' in finding
        assert 'confidence' in finding
        assert 'message' in finding
        assert 'description' in finding
        assert 'recommendation' in finding

    def test_severity_mapping(self):
        """Test Aderyn severity mapping to MIESC standard"""
        adapter = AderynAdapter()
        normalized = adapter.normalize_findings(SAMPLE_ADERYN_OUTPUT)

        # Critical -> Critical
        critical_finding = [f for f in normalized if f['type'] == 'missing-access-control'][0]
        assert critical_finding['severity'] == 'Critical'

        # High -> High
        high_finding = [f for f in normalized if f['type'] == 'tx-origin'][0]
        assert high_finding['severity'] == 'High'

        # Medium -> Medium
        medium_finding = [f for f in normalized if f['type'] == 'uninitialized-state-variable'][0]
        assert medium_finding['severity'] == 'Medium'

        # Low -> Low
        low_finding = [f for f in normalized if f['type'] == 'dangerous-strict-equality'][0]
        assert low_finding['severity'] == 'Low'

    def test_confidence_estimation(self):
        """Test confidence estimation based on severity"""
        adapter = AderynAdapter()

        # Critical severity -> high confidence
        assert adapter._estimate_confidence('Critical', 'test') == 0.95

        # High severity -> high confidence
        assert adapter._estimate_confidence('High', 'test') == 0.90

        # Medium severity -> medium confidence
        assert adapter._estimate_confidence('Medium', 'test') == 0.85

        # Low severity -> lower confidence
        assert adapter._estimate_confidence('Low', 'test') == 0.75

    def test_owasp_mapping(self):
        """Test mapping to OWASP Smart Contract Top 10 (2025)"""
        adapter = AderynAdapter()

        # Test various detector mappings
        assert "Reentrancy" in adapter._map_to_owasp("reentrancy-detector")
        assert "Access Control" in adapter._map_to_owasp("access_control_issue")
        assert "Arithmetic" in adapter._map_to_owasp("arithmetic-overflow")
        assert "Delegatecall" in adapter._map_to_owasp("unsafe-delegatecall")

        # Unknown detector should return None
        assert adapter._map_to_owasp("unknown-detector") is None

    def test_normalize_empty_findings(self):
        """Test normalization with empty findings"""
        adapter = AderynAdapter()

        empty_output = {"findings": []}
        normalized = adapter.normalize_findings(empty_output)

        assert isinstance(normalized, list)
        assert len(normalized) == 0

    def test_normalize_missing_location(self):
        """Test normalization when location info is missing"""
        adapter = AderynAdapter()

        output_no_location = {
            "findings": [
                {
                    "detector": "test-detector",
                    "severity": "Medium",
                    "title": "Test issue",
                    "description": "Test description",
                    "locations": []  # No locations
                }
            ]
        }

        normalized = adapter.normalize_findings(output_no_location)

        assert len(normalized) == 1
        assert normalized[0]['location']['file'] == 'unknown'
        assert normalized[0]['location']['line'] == 0
        assert normalized[0]['location']['function'] == 'unknown'


class TestAderynCanAnalyze:
    """Test can_analyze() method"""

    def test_can_analyze_solidity_file(self):
        """Test that Aderyn can analyze .sol files"""
        adapter = AderynAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            assert adapter.can_analyze(contract_path) is True
        finally:
            os.unlink(contract_path)

    def test_can_analyze_directory_with_sol_files(self):
        """Test that Aderyn can analyze directories with .sol files"""
        adapter = AderynAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a .sol file in temp directory
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text(SAMPLE_VULNERABLE_CONTRACT)

            assert adapter.can_analyze(tmpdir) is True

    def test_cannot_analyze_non_solidity_file(self):
        """Test that Aderyn cannot analyze non-.sol files"""
        adapter = AderynAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Not a Solidity contract")
            file_path = f.name

        try:
            assert adapter.can_analyze(file_path) is False
        finally:
            os.unlink(file_path)

    def test_cannot_analyze_empty_directory(self):
        """Test that Aderyn cannot analyze directory without .sol files"""
        adapter = AderynAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            assert adapter.can_analyze(tmpdir) is False

    def test_cannot_analyze_nonexistent_path(self):
        """Test that Aderyn cannot analyze nonexistent paths"""
        adapter = AderynAdapter()
        assert adapter.can_analyze("/nonexistent/path") is False


class TestAderynConfiguration:
    """Test Aderyn configuration and default settings"""

    def test_get_default_config(self):
        """Test default configuration"""
        adapter = AderynAdapter()
        config = adapter.get_default_config()

        assert isinstance(config, dict)
        assert 'timeout' in config
        assert 'no_snippets' in config
        assert 'output_format' in config
        assert config['timeout'] == 300
        assert config['no_snippets'] is False
        assert config['output_format'] == 'json'

    @patch('subprocess.run')
    @patch('builtins.open', create=True)
    def test_custom_timeout(self, mock_open, mock_run):
        """Test analysis with custom timeout"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_file = MagicMock()
        mock_file.__enter__.return_value = MagicMock()
        mock_file.__enter__.return_value.read.return_value = json.dumps({"findings": []})
        mock_open.return_value = mock_file

        adapter = AderynAdapter()
        result = adapter.analyze("/tmp/test.sol", timeout=600)

        # Verify timeout was passed to subprocess
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs['timeout'] == 600

    @patch('subprocess.run')
    @patch('builtins.open', create=True)
    def test_no_snippets_flag(self, mock_open, mock_run):
        """Test analysis with no_snippets flag"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_file = MagicMock()
        mock_file.__enter__.return_value = MagicMock()
        mock_file.__enter__.return_value.read.return_value = json.dumps({"findings": []})
        mock_open.return_value = mock_file

        adapter = AderynAdapter()
        result = adapter.analyze("/tmp/test.sol", no_snippets=True)

        # Verify --no-snippets flag was added
        call_args = mock_run.call_args[0][0]
        assert '--no-snippets' in call_args


class TestAderynDPGACompliance:
    """Test DPGA compliance requirements"""

    def test_aderyn_is_optional(self):
        """DPGA: Aderyn must be marked as optional"""
        adapter = AderynAdapter()
        metadata = adapter.get_metadata()
        assert metadata.is_optional is True

    def test_aderyn_has_open_source_license(self):
        """DPGA: Aderyn must have open source compatible license"""
        adapter = AderynAdapter()
        metadata = adapter.get_metadata()

        open_source_licenses = ["MIT", "GPL", "Apache", "BSD"]
        assert any(lic in metadata.license for lic in open_source_licenses)

    @patch('subprocess.run')
    def test_graceful_degradation_when_not_installed(self, mock_run):
        """DPGA: System must handle Aderyn not being installed gracefully"""
        mock_run.side_effect = FileNotFoundError("aderyn not found")

        adapter = AderynAdapter()

        # Should not raise exception
        status = adapter.is_available()
        assert status == ToolStatus.NOT_INSTALLED

        # Analysis should return error result, not raise exception
        result = adapter.analyze("/tmp/test.sol")
        assert result['status'] == 'error'
        assert isinstance(result, dict)
        assert 'error' in result

    def test_zero_cost(self):
        """DPGA: Aderyn must be free (zero cost)"""
        adapter = AderynAdapter()
        metadata = adapter.get_metadata()
        assert metadata.cost == 0.0

    def test_no_api_key_required(self):
        """DPGA: Aderyn must not require API keys"""
        adapter = AderynAdapter()
        metadata = adapter.get_metadata()
        assert metadata.requires_api_key is False


class TestAderynCrossValidation:
    """Test Aderyn as cross-validation for Slither"""

    def test_complementary_detection(self):
        """Test that Aderyn provides complementary detection to Slither"""
        adapter = AderynAdapter()
        metadata = adapter.get_metadata()

        detection_types = metadata.capabilities[0].detection_types

        # Aderyn should detect issues that complement Slither
        assert "state_variable_shadowing" in detection_types
        assert "push_0_opcode_not_supported" in detection_types
        assert "function_selector_collision" in detection_types
        assert "multiple_constructor_schemes" in detection_types

    def test_low_false_positive_rate(self):
        """Test that Aderyn maintains high confidence (low FP rate)"""
        adapter = AderynAdapter()

        # High severity findings should have high confidence (low FP)
        confidence_critical = adapter._estimate_confidence('Critical', 'test')
        confidence_high = adapter._estimate_confidence('High', 'test')

        assert confidence_critical >= 0.90  # 90%+ confidence
        assert confidence_high >= 0.85      # 85%+ confidence


class TestAderynPerformance:
    """Test Aderyn performance characteristics"""

    @patch('subprocess.run')
    @patch('builtins.open', create=True)
    def test_fast_execution_time(self, mock_open, mock_run):
        """Test that Aderyn execution completes quickly"""
        import time

        # Mock quick execution
        def mock_subprocess_run(*args, **kwargs):
            time.sleep(0.1)  # Simulate fast execution
            return Mock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = mock_subprocess_run
        mock_file = MagicMock()
        mock_file.__enter__.return_value = MagicMock()
        mock_file.__enter__.return_value.read.return_value = json.dumps({"findings": []})
        mock_open.return_value = mock_file

        adapter = AderynAdapter()
        result = adapter.analyze("/tmp/test.sol")

        # Aderyn should be fast (< 5s expected in docs)
        assert result['execution_time'] < 1.0  # Even with mock should be very fast

    @patch('subprocess.run')
    @patch('builtins.open', create=True)
    def test_execution_time_reported(self, mock_open, mock_run):
        """Test that execution time is always reported"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_file = MagicMock()
        mock_file.__enter__.return_value = MagicMock()
        mock_file.__enter__.return_value.read.return_value = json.dumps({"findings": []})
        mock_open.return_value = mock_file

        adapter = AderynAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert 'execution_time' in result
        assert isinstance(result['execution_time'], float)
        assert result['execution_time'] >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
