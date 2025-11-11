"""
Comprehensive Test Suite for MedusaAdapter
===========================================

Tests for Medusa coverage-guided fuzzer adapter (2025 Security Enhancement).

Autor: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Fecha: November 10, 2025
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import subprocess

from src.core.tool_protocol import (
    ToolStatus, ToolCategory
)
from src.adapters.medusa_adapter import MedusaAdapter


# Sample Solidity contract for fuzzing
SAMPLE_FUZZABLE_CONTRACT = """
pragma solidity ^0.8.0;

contract FuzzableContract {
    uint256 public counter;
    mapping(address => uint256) public balances;

    // State invariant: counter should never exceed 100
    function increment(uint256 amount) public {
        require(counter + amount <= 100, "Counter overflow");
        counter += amount;
    }

    // State invariant: total supply should match sum of balances
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Edge case: division by zero possibility
    function divide(uint256 a, uint256 b) public pure returns (uint256) {
        return a / b;  // Medusa should find division by zero
    }

    // Race condition potential
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // Reentrancy vulnerability - Medusa should detect via property testing
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""

# Sample Medusa output for testing
SAMPLE_MEDUSA_OUTPUT = """
Medusa v0.3.0 - Coverage-Guided Fuzzer
======================================

Configuration:
- Test sequences: 10000
- Timeout: 300s
- Workers: 4
- Coverage target: 90%

Starting fuzzing campaign...

[RUNNING] Property testing enabled
[RUNNING] Assertion mode enabled
[RUNNING] Coverage tracking enabled

Tests run: 8547
Coverage: 87.5%
Paths explored: 1245
Corpus size: 342

Findings:
=========

[FAIL] Assertion violated at FuzzableContract.sol:18
Function: divide
Input: a=100, b=0
Error: Division by zero

[FAIL] Reentrancy vulnerability at FuzzableContract.sol:28
Function: withdraw
Detected cross-function reentrancy

[FAIL] Property violation at FuzzableContract.sol:12
Property: counter <= 100
Violated with inputs: amount=255 (integer overflow)

Campaign completed in 45.3s
"""


class TestMedusaAdapterProtocol:
    """Test that MedusaAdapter implements Tool Adapter Protocol correctly"""

    def test_medusa_has_metadata(self):
        """Verify MedusaAdapter provides complete metadata"""
        adapter = MedusaAdapter()
        metadata = adapter.get_metadata()

        assert metadata.name == "medusa"
        assert metadata.version == "0.3.0"
        assert metadata.category == ToolCategory.DYNAMIC_TESTING
        assert metadata.author == "Trail of Bits (Adapter by Fernando Boiero)"
        assert metadata.license == "MIT"
        assert metadata.homepage == "https://github.com/crytic/medusa"
        assert metadata.installation_cmd == "cargo install medusa"
        assert metadata.cost == 0.0
        assert metadata.requires_api_key is False

    def test_medusa_is_optional(self):
        """DPGA compliance: Medusa must be optional"""
        adapter = MedusaAdapter()
        metadata = adapter.get_metadata()
        assert metadata.is_optional is True

    def test_medusa_has_capabilities(self):
        """Verify Medusa declares its capabilities"""
        adapter = MedusaAdapter()
        metadata = adapter.get_metadata()

        assert len(metadata.capabilities) > 0
        cap = metadata.capabilities[0]
        assert cap.name == "coverage_guided_fuzzing"
        assert "solidity" in cap.supported_languages
        assert len(cap.detection_types) >= 7  # Medusa detects many issue types

    def test_medusa_detects_key_vulnerabilities(self):
        """Verify Medusa declares detection of key vulnerability types"""
        adapter = MedusaAdapter()
        metadata = adapter.get_metadata()

        detection_types = metadata.capabilities[0].detection_types

        # Check for key vulnerability types
        assert "assertion_violations" in detection_types
        assert "property_violations" in detection_types
        assert "reentrancy" in detection_types
        assert "integer_overflow" in detection_types
        assert "edge_case_vulnerabilities" in detection_types


class TestMedusaAvailability:
    """Test Medusa availability checking"""

    @patch('subprocess.run')
    def test_medusa_available_when_installed(self, mock_run):
        """Test status when Medusa is installed and working"""
        # Mock successful medusa version call
        mock_run.return_value = Mock(
            returncode=0,
            stdout="medusa v0.3.0"
        )

        adapter = MedusaAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.AVAILABLE
        mock_run.assert_called_once()
        assert "medusa" in mock_run.call_args[0][0]
        assert "version" in mock_run.call_args[0][0]

    @patch('subprocess.run')
    def test_medusa_not_installed(self, mock_run):
        """Test status when Medusa is not installed"""
        # Mock FileNotFoundError (medusa command not found)
        mock_run.side_effect = FileNotFoundError("medusa not found")

        adapter = MedusaAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.NOT_INSTALLED

    @patch('subprocess.run')
    def test_medusa_configuration_error(self, mock_run):
        """Test status when Medusa returns non-zero exit code"""
        # Mock failed medusa call
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Error: configuration issue"
        )

        adapter = MedusaAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.CONFIGURATION_ERROR

    @patch('subprocess.run')
    def test_medusa_timeout(self, mock_run):
        """Test status when version check times out"""
        # Mock timeout
        mock_run.side_effect = subprocess.TimeoutExpired("medusa", 5)

        adapter = MedusaAdapter()
        status = adapter.is_available()

        assert status == ToolStatus.CONFIGURATION_ERROR


class TestMedusaFuzzingCampaign:
    """Test Medusa fuzzing campaign functionality"""

    @patch('subprocess.run')
    def test_medusa_successful_fuzzing(self, mock_run):
        """Test successful Medusa fuzzing campaign"""
        # Mock successful medusa execution
        mock_run.return_value = Mock(
            returncode=0,
            stdout=SAMPLE_MEDUSA_OUTPUT,
            stderr=""
        )

        adapter = MedusaAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a Solidity file for testing
            contract_file = Path(tmpdir) / "Fuzzable.sol"
            contract_file.write_text(SAMPLE_FUZZABLE_CONTRACT)

            result = adapter.analyze(str(tmpdir))

            assert result['tool'] == 'medusa'
            assert result['version'] == '0.3.0'
            assert result['status'] == 'success'
            assert 'findings' in result
            assert 'metadata' in result
            assert 'execution_time' in result
            assert isinstance(result['execution_time'], float)

    @patch('subprocess.run')
    def test_medusa_not_available_during_analysis(self, mock_run):
        """Test analysis when Medusa is not available"""
        # Mock Medusa not installed
        mock_run.side_effect = FileNotFoundError("medusa not found")

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test")

        assert result['status'] == 'error'
        assert 'error' in result
        assert 'not available' in result['error'].lower()
        assert result['findings'] == []

    @patch('subprocess.run')
    def test_medusa_fuzzing_timeout(self, mock_run):
        """Test fuzzing campaign timeout handling"""
        # Mock timeout during fuzzing
        mock_run.side_effect = subprocess.TimeoutExpired("medusa", 300)

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test", timeout=300)

        assert result['status'] == 'error'
        assert 'timeout' in result['error'].lower()
        assert result['findings'] == []
        assert 'timeout' in result['metadata']
        assert result['metadata']['timeout'] == 300

    @patch('subprocess.run')
    def test_medusa_fuzzing_with_custom_config(self, mock_run):
        """Test fuzzing with custom configuration"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Coverage: 95%\nTests run: 20000",
            stderr=""
        )

        adapter = MedusaAdapter()
        result = adapter.analyze(
            "/tmp/test",
            test_limit=20000,
            coverage_target=95,
            workers=8,
            timeout=600
        )

        # Verify custom config was used
        call_args = mock_run.call_args[0][0]
        assert "--test-limit=20000" in call_args
        assert "--workers=8" in call_args

    @patch('subprocess.run')
    def test_medusa_with_corpus_dir(self, mock_run):
        """Test fuzzing with custom corpus directory"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        adapter = MedusaAdapter()
        result = adapter.analyze(
            "/tmp/test",
            corpus_dir="/tmp/my_corpus"
        )

        call_args = mock_run.call_args[0][0]
        assert "--corpus-dir=/tmp/my_corpus" in call_args


class TestMedusaFindingsNormalization:
    """Test Medusa findings normalization to MIESC standard format"""

    def test_normalize_medusa_findings(self):
        """Test normalization of Medusa output"""
        adapter = MedusaAdapter()
        normalized = adapter.normalize_findings(SAMPLE_MEDUSA_OUTPUT)

        assert isinstance(normalized, list)
        assert len(normalized) >= 3  # At least 3 findings in sample output

        # Check that findings have required fields
        for finding in normalized:
            assert 'id' in finding
            assert 'type' in finding
            assert 'severity' in finding
            assert 'confidence' in finding
            assert 'location' in finding
            assert 'message' in finding
            assert 'description' in finding
            assert 'recommendation' in finding

    def test_extract_finding_type_assertion(self):
        """Test extraction of assertion violation type"""
        adapter = MedusaAdapter()

        assert adapter._extract_finding_type("[FAIL] assertion violated") == "assertion_violation"
        assert adapter._extract_finding_type("Assertion failed at Test.sol:10") == "assertion_violation"

    def test_extract_finding_type_property(self):
        """Test extraction of property violation type"""
        adapter = MedusaAdapter()

        assert adapter._extract_finding_type("[FAIL] property violated") == "property_violation"
        assert adapter._extract_finding_type("Property check failed") == "property_violation"

    def test_extract_finding_type_overflow(self):
        """Test extraction of integer overflow type"""
        adapter = MedusaAdapter()

        assert adapter._extract_finding_type("Integer overflow detected") == "integer_overflow"
        assert adapter._extract_finding_type("Arithmetic overflow found") == "integer_overflow"

    def test_extract_finding_type_reentrancy(self):
        """Test extraction of reentrancy type"""
        adapter = MedusaAdapter()

        assert adapter._extract_finding_type("Reentrancy vulnerability at Test.sol") == "reentrancy"
        assert adapter._extract_finding_type("cross-function reentrancy") == "reentrancy"

    def test_determine_severity(self):
        """Test severity determination for different finding types"""
        adapter = MedusaAdapter()

        # Critical severities
        assert adapter._determine_severity("reentrancy") == "Critical"

        # High severities
        assert adapter._determine_severity("assertion_violation") == "High"
        assert adapter._determine_severity("property_violation") == "High"
        assert adapter._determine_severity("integer_overflow") == "High"
        assert adapter._determine_severity("access_control") == "High"

        # Unknown should default to Medium
        assert adapter._determine_severity("unknown_violation") == "Medium"

    def test_generate_description(self):
        """Test description generation for findings"""
        adapter = MedusaAdapter()

        desc_assertion = adapter._generate_description("assertion_violation", "test")
        assert "assertion" in desc_assertion.lower()
        assert "invariant" in desc_assertion.lower()

        desc_reentrancy = adapter._generate_description("reentrancy", "test")
        assert "reentrancy" in desc_reentrancy.lower()

    def test_get_recommendation(self):
        """Test remediation recommendations"""
        adapter = MedusaAdapter()

        rec_overflow = adapter._get_recommendation("integer_overflow")
        assert "SafeMath" in rec_overflow or "0.8" in rec_overflow

        rec_reentrancy = adapter._get_recommendation("reentrancy")
        assert "checks-effects-interactions" in rec_reentrancy.lower() or "reentrancyguard" in rec_reentrancy.lower()

    def test_map_to_swc(self):
        """Test mapping to SWC IDs"""
        adapter = MedusaAdapter()

        assert adapter._map_to_swc("integer_overflow") == "SWC-101"
        assert adapter._map_to_swc("reentrancy") == "SWC-107"
        assert adapter._map_to_swc("access_control") == "SWC-105"
        assert adapter._map_to_swc("unknown") is None

    def test_map_to_owasp(self):
        """Test mapping to OWASP categories"""
        adapter = MedusaAdapter()

        assert "Reentrancy" in adapter._map_to_owasp("reentrancy")
        assert "Access Control" in adapter._map_to_owasp("access_control")
        assert "Arithmetic" in adapter._map_to_owasp("integer_overflow")
        assert adapter._map_to_owasp("unknown_type") is None

    def test_normalize_empty_output(self):
        """Test normalization with empty output"""
        adapter = MedusaAdapter()

        empty_output = "No findings\nCoverage: 100%"
        normalized = adapter.normalize_findings(empty_output)

        assert isinstance(normalized, list)

    def test_extract_location(self):
        """Test location extraction from findings"""
        adapter = MedusaAdapter()

        lines = [
            "[FAIL] Assertion violated",
            "at FuzzableContract.sol:18",
            "Function: divide"
        ]

        location = adapter._extract_location(lines, 0)

        assert location['file'] == 'FuzzableContract.sol'
        assert location['line'] == 18

    def test_extract_location_missing(self):
        """Test location extraction when info is missing"""
        adapter = MedusaAdapter()

        lines = ["[FAIL] Some error"]
        location = adapter._extract_location(lines, 0)

        assert location['file'] == 'unknown'
        assert location['line'] == 0
        assert location['function'] == 'unknown'


class TestMedusaCoverageMetrics:
    """Test coverage metrics extraction"""

    def test_extract_coverage_metrics(self):
        """Test extraction of coverage metrics from output"""
        adapter = MedusaAdapter()

        output = """
        Coverage: 87.5%
        Tests: 8547
        Sequences: 10000
        Paths explored: 1245
        """

        metrics = adapter._extract_coverage_metrics(output)

        assert isinstance(metrics, dict)
        assert 'coverage_percentage' in metrics
        assert 'tests_run' in metrics
        assert metrics['coverage_percentage'] > 0

    def test_extract_coverage_percentage(self):
        """Test extraction of coverage percentage"""
        adapter = MedusaAdapter()

        output = "Coverage: 92.3%"
        metrics = adapter._extract_coverage_metrics(output)

        assert metrics['coverage_percentage'] == 92.3

    def test_extract_tests_run(self):
        """Test extraction of tests run count"""
        adapter = MedusaAdapter()

        output = "Tests: 15000"
        metrics = adapter._extract_coverage_metrics(output)

        assert metrics['tests_run'] == 15000

    def test_extract_metrics_missing_data(self):
        """Test metrics extraction when data is missing"""
        adapter = MedusaAdapter()

        output = "No metrics available"
        metrics = adapter._extract_coverage_metrics(output)

        assert metrics['coverage_percentage'] == 0
        assert metrics['tests_run'] == 0

    @patch('subprocess.run')
    def test_metadata_includes_coverage(self, mock_run):
        """Test that metadata includes coverage information"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Coverage: 88%\nTests: 9500",
            stderr=""
        )

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test")

        assert 'coverage_achieved' in result['metadata']
        assert 'actual_tests_run' in result['metadata']
        assert 'paths_explored' in result['metadata']


class TestMedusaCanAnalyze:
    """Test can_analyze() method"""

    def test_can_analyze_solidity_project(self):
        """Test that Medusa can analyze Solidity projects"""
        adapter = MedusaAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a .sol file
            sol_file = Path(tmpdir) / "Test.sol"
            sol_file.write_text(SAMPLE_FUZZABLE_CONTRACT)

            assert adapter.can_analyze(tmpdir) is True

    def test_can_analyze_solidity_file(self):
        """Test that Medusa can analyze individual .sol files"""
        adapter = MedusaAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_FUZZABLE_CONTRACT)
            contract_path = f.name

        try:
            assert adapter.can_analyze(contract_path) is True
        finally:
            os.unlink(contract_path)

    def test_cannot_analyze_non_solidity(self):
        """Test that Medusa cannot analyze non-Solidity files"""
        adapter = MedusaAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Not a Solidity contract")
            file_path = f.name

        try:
            assert adapter.can_analyze(file_path) is False
        finally:
            os.unlink(file_path)

    def test_cannot_analyze_empty_directory(self):
        """Test that Medusa cannot analyze empty directories"""
        adapter = MedusaAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            assert adapter.can_analyze(tmpdir) is False

    def test_cannot_analyze_nonexistent_path(self):
        """Test that Medusa cannot analyze nonexistent paths"""
        adapter = MedusaAdapter()
        assert adapter.can_analyze("/nonexistent/path") is False


class TestMedusaConfiguration:
    """Test Medusa configuration and default settings"""

    def test_get_default_config(self):
        """Test default configuration"""
        adapter = MedusaAdapter()
        config = adapter.get_default_config()

        assert isinstance(config, dict)
        assert config['test_limit'] == 10000
        assert config['timeout'] == 300
        assert config['coverage_target'] == 90
        assert config['corpus_dir'] == '.medusa_corpus'
        assert config['shrink_corpus'] is True
        assert config['assertion_testing'] is True
        assert config['workers'] == 4

    def test_default_config_values(self):
        """Test that DEFAULT_CONFIG has expected values"""
        assert MedusaAdapter.DEFAULT_CONFIG['test_limit'] == 10000
        assert MedusaAdapter.DEFAULT_CONFIG['timeout'] == 300
        assert MedusaAdapter.DEFAULT_CONFIG['workers'] == 4

    @patch('subprocess.run')
    def test_custom_test_limit(self, mock_run):
        """Test fuzzing with custom test limit"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test", test_limit=50000)

        call_args = mock_run.call_args[0][0]
        assert "--test-limit=50000" in call_args

    @patch('subprocess.run')
    def test_shrink_corpus_flag(self, mock_run):
        """Test shrink corpus flag"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test", shrink_corpus=True)

        call_args = mock_run.call_args[0][0]
        assert "--shrink-corpus" in call_args

    @patch('subprocess.run')
    def test_assertion_mode_flag(self, mock_run):
        """Test assertion testing mode flag"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test", assertion_testing=True)

        call_args = mock_run.call_args[0][0]
        assert "--assertion-mode" in call_args


class TestMedusaDPGACompliance:
    """Test DPGA compliance requirements"""

    def test_medusa_is_optional(self):
        """DPGA: Medusa must be marked as optional"""
        adapter = MedusaAdapter()
        metadata = adapter.get_metadata()
        assert metadata.is_optional is True

    def test_medusa_has_open_source_license(self):
        """DPGA: Medusa must have open source compatible license"""
        adapter = MedusaAdapter()
        metadata = adapter.get_metadata()

        open_source_licenses = ["MIT", "GPL", "Apache", "BSD"]
        assert any(lic in metadata.license for lic in open_source_licenses)

    @patch('subprocess.run')
    def test_graceful_degradation_when_not_installed(self, mock_run):
        """DPGA: System must handle Medusa not being installed gracefully"""
        mock_run.side_effect = FileNotFoundError("medusa not found")

        adapter = MedusaAdapter()

        # Should not raise exception
        status = adapter.is_available()
        assert status == ToolStatus.NOT_INSTALLED

        # Analysis should return error result, not raise exception
        result = adapter.analyze("/tmp/test")
        assert result['status'] == 'error'
        assert isinstance(result, dict)
        assert 'error' in result

    def test_zero_cost(self):
        """DPGA: Medusa must be free (zero cost)"""
        adapter = MedusaAdapter()
        metadata = adapter.get_metadata()
        assert metadata.cost == 0.0

    def test_no_api_key_required(self):
        """DPGA: Medusa must not require API keys"""
        adapter = MedusaAdapter()
        metadata = adapter.get_metadata()
        assert metadata.requires_api_key is False


class TestMedusaCoverageGuidedFuzzing:
    """Test Medusa's coverage-guided fuzzing capabilities"""

    def test_coverage_target_setting(self):
        """Test that coverage target can be configured"""
        adapter = MedusaAdapter()
        config = adapter.get_default_config()

        assert config['coverage_target'] == 90

    @patch('subprocess.run')
    def test_path_exploration_reporting(self, mock_run):
        """Test that path exploration is reported in metadata"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Paths explored: 2500\nCoverage: 92%",
            stderr=""
        )

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test")

        assert 'paths_explored' in result['metadata']

    @patch('subprocess.run')
    def test_corpus_management(self, mock_run):
        """Test corpus directory management"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test", corpus_dir="/custom/corpus")

        call_args = mock_run.call_args[0][0]
        assert "--corpus-dir=/custom/corpus" in call_args

    def test_high_confidence_findings(self):
        """Test that Medusa findings have high confidence due to coverage guidance"""
        adapter = MedusaAdapter()
        normalized = adapter.normalize_findings(SAMPLE_MEDUSA_OUTPUT)

        for finding in normalized:
            # Coverage-guided fuzzing should have high confidence
            assert finding['confidence'] >= 0.80


class TestMedusaPerformance:
    """Test Medusa performance characteristics"""

    @patch('subprocess.run')
    def test_execution_time_reported(self, mock_run):
        """Test that execution time is always reported"""
        import time

        def mock_subprocess_run(*args, **kwargs):
            time.sleep(0.1)
            return Mock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = mock_subprocess_run

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test")

        assert 'execution_time' in result
        assert isinstance(result['execution_time'], float)
        assert result['execution_time'] >= 0

    @patch('subprocess.run')
    def test_timeout_buffer(self, mock_run):
        """Test that subprocess timeout has buffer over campaign timeout"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test", timeout=300)

        # Subprocess timeout should be campaign timeout + 30s buffer
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs['timeout'] == 330  # 300 + 30

    @patch('subprocess.run')
    def test_worker_parallelization(self, mock_run):
        """Test that multiple workers can be configured for parallel fuzzing"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test", workers=8)

        call_args = mock_run.call_args[0][0]
        assert "--workers=8" in call_args


class TestMedusaEdgeCases:
    """Test Medusa adapter edge case handling"""

    @patch('subprocess.run')
    def test_non_zero_exit_with_findings(self, mock_run):
        """Test handling when Medusa exits non-zero but found issues"""
        # Exit code 1 with findings is acceptable (issues found)
        mock_run.return_value = Mock(
            returncode=1,
            stdout="[FAIL] Assertion violated\nCoverage: 80%",
            stderr=""
        )

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test")

        # Should be success because findings were produced
        assert result['status'] == 'success'
        assert len(result['findings']) > 0

    @patch('subprocess.run')
    def test_error_with_no_findings(self, mock_run):
        """Test handling when Medusa exits with error and no findings"""
        mock_run.return_value = Mock(
            returncode=2,
            stdout="",
            stderr="Fatal error: compilation failed"
        )

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test")

        assert result['status'] == 'error'

    @patch('subprocess.run')
    def test_unexpected_exception(self, mock_run):
        """Test handling of unexpected exceptions"""
        mock_run.side_effect = Exception("Unexpected error")

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test")

        assert result['status'] == 'error'
        assert 'unexpected error' in result['error'].lower()
        assert 'exception' in result['metadata']

    @patch('subprocess.run')
    def test_campaign_completed_flag(self, mock_run):
        """Test that campaign completion is tracked in metadata"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Campaign completed",
            stderr=""
        )

        adapter = MedusaAdapter()
        result = adapter.analyze("/tmp/test")

        assert 'campaign_completed' in result['metadata']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
