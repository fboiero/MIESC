"""
Comprehensive Test Suite for SolhintAdapter
============================================

Tests for Solhint linter adapter (Layer 2 - Dynamic Testing).

Autor: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Fecha: November 11, 2025
"""

import pytest
import tempfile
import os
import json
from pathlib import Path
from unittest.mock import Mock, patch
import subprocess

from src.core.tool_protocol import (
    ToolStatus, ToolCategory
)
from src.adapters.solhint_adapter import SolhintAdapter


# Sample Solidity contract for testing
SAMPLE_VULNERABLE_CONTRACT = """
pragma solidity ^0.8.0;

contract UnsafeContract {
    address owner;

    function withdraw(uint256 amount) public {
        // Missing visibility, avoid-call-value
        msg.sender.call{value: amount}("");
    }

    function checkOwner() public view returns (bool) {
        // tx.origin usage
        return tx.origin == owner;
    }
}
"""

# Sample Solhint JSON output
SAMPLE_SOLHINT_JSON = [
    {
        "filePath": "UnsafeContract.sol",
        "line": 7,
        "column": 9,
        "severity": "error",
        "message": "Avoid using call.value()",
        "ruleId": "avoid-call-value"
    },
    {
        "filePath": "UnsafeContract.sol",
        "line": 12,
        "column": 16,
        "severity": "warning",
        "message": "Use msg.sender instead of tx.origin",
        "ruleId": "avoid-tx-origin"
    },
    {
        "filePath": "UnsafeContract.sol",
        "line": 5,
        "column": 5,
        "severity": "warning",
        "message": "Explicitly define function visibility",
        "ruleId": "func-visibility"
    }
]

# Sample Solhint text output
SAMPLE_SOLHINT_TEXT = """
UnsafeContract.sol:7:9: [error] Avoid using call.value() (avoid-call-value)
UnsafeContract.sol:12:16: [warning] Use msg.sender instead of tx.origin (avoid-tx-origin)
UnsafeContract.sol:5:5: [warning] Explicitly define function visibility (func-visibility)
"""


class TestSolhintAdapterProtocol:
    """Test that SolhintAdapter implements Tool Adapter Protocol correctly"""

    def test_solhint_has_metadata(self):
        """Verify SolhintAdapter provides complete metadata"""
        adapter = SolhintAdapter()
        metadata = adapter.get_metadata()

        assert metadata.name == "solhint"
        assert metadata.version == "1.0.0"
        assert metadata.category == ToolCategory.DYNAMIC_TESTING
        assert metadata.author == "Protofire (Adapter by Fernando Boiero)"
        assert metadata.license == "MIT"
        assert metadata.homepage == "https://github.com/protofire/solhint"
        assert "npm install" in metadata.installation_cmd
        assert metadata.cost == 0.0
        assert metadata.requires_api_key is False

    def test_solhint_is_optional(self):
        """DPGA compliance: Solhint must be optional"""
        adapter = SolhintAdapter()
        metadata = adapter.get_metadata()
        assert metadata.is_optional is True

    def test_solhint_has_capabilities(self):
        """Verify Solhint declares its capabilities"""
        adapter = SolhintAdapter()
        metadata = adapter.get_metadata()

        assert len(metadata.capabilities) >= 3

        # Check for security linting capability
        security_cap = [c for c in metadata.capabilities if c.name == "security_linting"][0]
        assert "solidity" in security_cap.supported_languages
        assert "security_issues" in security_cap.detection_types

    def test_solhint_security_rules_defined(self):
        """Verify security rules are defined"""
        adapter = SolhintAdapter()

        assert len(adapter.SECURITY_RULES) >= 14
        assert "reentrancy" in adapter.SECURITY_RULES
        assert "avoid-call-value" in adapter.SECURITY_RULES


class TestSolhintAvailability:
    """Test Solhint availability checking"""

    @patch('subprocess.run')
    def test_solhint_available_when_installed(self, mock_run):
        """Test status when Solhint is installed"""
        mock_run.return_value = Mock(returncode=0, stdout="3.4.0")

        adapter = SolhintAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.AVAILABLE

    @patch('subprocess.run')
    def test_solhint_not_installed(self, mock_run):
        """Test status when Solhint is not installed"""
        mock_run.side_effect = FileNotFoundError("solhint not found")

        adapter = SolhintAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.NOT_INSTALLED

    @patch('subprocess.run')
    def test_solhint_configuration_error(self, mock_run):
        """Test status when Solhint returns non-zero exit code"""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="Error")

        adapter = SolhintAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.CONFIGURATION_ERROR


class TestSolhintAnalysis:
    """Test Solhint analysis functionality"""

    @patch('subprocess.run')
    def test_solhint_successful_analysis(self, mock_run):
        """Test successful Solhint analysis"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="3.4.0"),  # is_available
            Mock(returncode=0, stdout=json.dumps(SAMPLE_SOLHINT_JSON), stderr="")  # analyze
        ]

        adapter = SolhintAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            assert result['tool'] == 'solhint'
            assert result['status'] == 'success'
            assert 'findings' in result
            assert len(result['findings']) >= 3
            assert result['dpga_compliant'] is True

        finally:
            os.unlink(contract_path)

    @patch('subprocess.run')
    def test_solhint_not_available_during_analysis(self, mock_run):
        """Test analysis when Solhint is not available"""
        mock_run.side_effect = FileNotFoundError("solhint not found")

        adapter = SolhintAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert result['status'] == 'error'
        assert 'not available' in result['error'].lower()

    @patch('subprocess.run')
    def test_solhint_analysis_timeout(self, mock_run):
        """Test analysis timeout handling"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="3.4.0"),
            subprocess.TimeoutExpired("solhint", 60)
        ]

        adapter = SolhintAdapter()
        result = adapter.analyze("/tmp/test.sol", timeout=60)

        assert result['status'] == 'error'
        assert 'timeout' in result['error'].lower()


class TestSolhintFindingsNormalization:
    """Test Solhint findings normalization"""

    def test_parse_json_output(self):
        """Test JSON output parsing"""
        adapter = SolhintAdapter()
        findings = adapter._parse_output(json.dumps(SAMPLE_SOLHINT_JSON), "")

        assert len(findings) == 3

        # Check error severity mapping
        error_finding = [f for f in findings if f['rule'] == 'avoid-call-value'][0]
        assert error_finding['severity'] == 'high'

        # Check warning severity mapping
        warning_finding = [f for f in findings if f['rule'] == 'avoid-tx-origin'][0]
        assert warning_finding['severity'] == 'medium'

    def test_parse_text_output(self):
        """Test text output parsing (fallback)"""
        adapter = SolhintAdapter()
        findings = adapter._parse_text_output(SAMPLE_SOLHINT_TEXT, "")

        assert len(findings) >= 3

        for finding in findings:
            assert 'type' in finding
            assert 'severity' in finding
            assert 'rule' in finding
            assert 'description' in finding

    def test_security_vs_style_classification(self):
        """Test classification of security vs style issues"""
        adapter = SolhintAdapter()
        findings = adapter._parse_output(json.dumps(SAMPLE_SOLHINT_JSON), "")

        # avoid-call-value is a security rule
        security_finding = [f for f in findings if f['rule'] == 'avoid-call-value'][0]
        assert security_finding['type'] == 'security_issue'

        # func-visibility might be classified as style
        style_finding = [f for f in findings if f['rule'] == 'func-visibility'][0]
        # Could be either security or style depending on implementation
        assert style_finding['type'] in ['security_issue', 'style_violation']

    def test_get_recommendation(self):
        """Test recommendation generation for rules"""
        adapter = SolhintAdapter()

        # Test known security rules
        rec1 = adapter._get_recommendation("reentrancy")
        assert "checks-effects-interactions" in rec1

        rec2 = adapter._get_recommendation("avoid-call-value")
        assert "transfer()" in rec2 or "send()" in rec2

        # Test unknown rule
        rec3 = adapter._get_recommendation("unknown-rule")
        assert "unknown-rule" in rec3


class TestSolhintCanAnalyze:
    """Test can_analyze() method"""

    def test_can_analyze_solidity_file(self):
        """Test that Solhint can analyze .sol files"""
        adapter = SolhintAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            assert adapter.can_analyze(contract_path) is True
        finally:
            os.unlink(contract_path)

    def test_can_analyze_directory_with_sol_files(self):
        """Test that Solhint can analyze directories"""
        adapter = SolhintAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text(SAMPLE_VULNERABLE_CONTRACT)

            assert adapter.can_analyze(tmpdir) is True

    def test_cannot_analyze_non_solidity(self):
        """Test that Solhint cannot analyze non-.sol files"""
        adapter = SolhintAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Not Solidity")
            file_path = f.name

        try:
            assert adapter.can_analyze(file_path) is False
        finally:
            os.unlink(file_path)


class TestSolhintConfiguration:
    """Test Solhint configuration"""

    def test_get_default_config(self):
        """Test default configuration"""
        adapter = SolhintAdapter()
        config = adapter.get_default_config()

        assert 'formatter' in config
        assert 'max_warnings' in config
        assert 'timeout' in config
        assert config['formatter'] == 'json'
        assert config['timeout'] == 60

    @patch('subprocess.run')
    def test_custom_config_file(self, mock_run):
        """Test analysis with custom config file"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="3.4.0"),
            Mock(returncode=0, stdout="[]", stderr="")
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"rules": {"avoid-call-value": "error"}}')
            config_file = f.name

        try:
            adapter = SolhintAdapter(config={"config_file": config_file})
            result = adapter.analyze("/tmp/test.sol")

            # Verify config file was passed
            call_args = mock_run.call_args_list[1][0][0]
            assert '--config' in call_args
        finally:
            os.unlink(config_file)


class TestSolhintDPGACompliance:
    """Test DPGA compliance"""

    def test_solhint_is_optional(self):
        """DPGA: Solhint must be optional"""
        adapter = SolhintAdapter()
        metadata = adapter.get_metadata()
        assert metadata.is_optional is True

    def test_solhint_has_open_source_license(self):
        """DPGA: Solhint must have open source license"""
        adapter = SolhintAdapter()
        metadata = adapter.get_metadata()

        assert "MIT" in metadata.license

    @patch('subprocess.run')
    def test_graceful_degradation(self, mock_run):
        """DPGA: System must handle Solhint gracefully"""
        mock_run.side_effect = FileNotFoundError("solhint not found")

        adapter = SolhintAdapter()

        status = adapter.is_available()
        assert status == ToolStatus.NOT_INSTALLED

        result = adapter.analyze("/tmp/test.sol")
        assert result['status'] == 'error'
        assert isinstance(result, dict)

    def test_zero_cost(self):
        """DPGA: Solhint must be free"""
        adapter = SolhintAdapter()
        metadata = adapter.get_metadata()
        assert metadata.cost == 0.0

    def test_no_api_key_required(self):
        """DPGA: Solhint must not require API keys"""
        adapter = SolhintAdapter()
        metadata = adapter.get_metadata()
        assert metadata.requires_api_key is False


class TestSolhintSeverityMapping:
    """Test severity mapping"""

    def test_severity_map_complete(self):
        """Test that severity map covers all Solhint severities"""
        adapter = SolhintAdapter()

        assert 'error' in adapter.SEVERITY_MAP
        assert 'warning' in adapter.SEVERITY_MAP
        assert 'info' in adapter.SEVERITY_MAP

        assert adapter.SEVERITY_MAP['error'] == 'high'
        assert adapter.SEVERITY_MAP['warning'] == 'medium'
        assert adapter.SEVERITY_MAP['info'] == 'low'


class TestSolhintPerformance:
    """Test Solhint performance characteristics"""

    @patch('subprocess.run')
    def test_execution_time_reported(self, mock_run):
        """Test that execution time is reported"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="3.4.0"),
            Mock(returncode=0, stdout="[]", stderr="")
        ]

        adapter = SolhintAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert 'execution_time' in result
        assert isinstance(result['execution_time'], float)
        assert result['execution_time'] >= 0

    @patch('subprocess.run')
    def test_issue_count_reported(self, mock_run):
        """Test that issue counts are reported"""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="3.4.0"),
            Mock(returncode=0, stdout=json.dumps(SAMPLE_SOLHINT_JSON), stderr="")
        ]

        adapter = SolhintAdapter()
        result = adapter.analyze("/tmp/test.sol")

        assert 'total_issues' in result
        assert 'errors' in result
        assert 'warnings' in result
        assert result['total_issues'] == 3
        assert result['errors'] == 1
        assert result['warnings'] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
