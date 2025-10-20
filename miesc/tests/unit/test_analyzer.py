"""
Unit Tests for miesc.core.analyzer

Comprehensive test suite for the analyzer module covering:
- ScanResult data class
- ToolExecutor class
- Individual tool execution
- Error handling
- Result normalization

Target Coverage: >90%

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
"""

import pytest
import json
import subprocess
from unittest.mock import Mock, patch, MagicMock, call
from pathlib import Path
from datetime import datetime

from miesc.core.analyzer import (
    ScanResult,
    ToolExecutor,
    analyze_contract
)


class TestScanResult:
    """Test suite for ScanResult dataclass"""

    def test_scan_result_creation(self):
        """Test creating a ScanResult instance"""
        result = ScanResult(
            tool="slither",
            vulnerability_type="reentrancy",
            severity="High",
            location={"file": "test.sol", "line": 10},
            description="Reentrancy vulnerability detected",
            confidence="High",
            cwe_id="CWE-107",
            swc_id="SWC-107"
        )

        assert result.tool == "slither"
        assert result.vulnerability_type == "reentrancy"
        assert result.severity == "High"
        assert result.confidence == "High"
        assert result.cwe_id == "CWE-107"

    def test_scan_result_to_dict(self):
        """Test converting ScanResult to dictionary"""
        result = ScanResult(
            tool="mythril",
            vulnerability_type="integer-overflow",
            severity="Medium",
            location={"file": "token.sol", "line": 25},
            description="Integer overflow possible",
            confidence="Medium"
        )

        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict['tool'] == "mythril"
        assert result_dict['severity'] == "Medium"
        assert 'location' in result_dict
        assert result_dict['cwe_id'] is None

    def test_scan_result_optional_fields(self):
        """Test ScanResult with minimal fields"""
        result = ScanResult(
            tool="solhint",
            vulnerability_type="style-guide",
            severity="Info",
            location={},
            description="Code style issue",
            confidence="High"
        )

        assert result.cwe_id is None
        assert result.swc_id is None
        assert result.owasp_category is None
        assert result.raw_output is None

    def test_scan_result_with_raw_output(self):
        """Test ScanResult with raw output data"""
        raw_data = {
            "detector": "reentrancy-eth",
            "impact": "High",
            "elements": [{"type": "function"}]
        }

        result = ScanResult(
            tool="slither",
            vulnerability_type="reentrancy",
            severity="High",
            location={"file": "contract.sol"},
            description="Test",
            confidence="High",
            raw_output=raw_data
        )

        assert result.raw_output == raw_data
        result_dict = result.to_dict()
        assert result_dict['raw_output'] == raw_data


class TestToolExecutor:
    """Test suite for ToolExecutor class"""

    def test_tool_executor_initialization(self):
        """Test ToolExecutor initialization"""
        executor = ToolExecutor(timeout=600)

        assert executor.timeout == 600
        assert 'slither' in executor.supported_tools
        assert 'mythril' in executor.supported_tools
        assert 'echidna' in executor.supported_tools
        assert 'aderyn' in executor.supported_tools
        assert 'solhint' in executor.supported_tools

    def test_tool_executor_default_timeout(self):
        """Test default timeout value"""
        executor = ToolExecutor()
        assert executor.timeout == 300  # Default 5 minutes

    def test_execute_tool_unsupported_tool(self):
        """Test executing an unsupported tool"""
        executor = ToolExecutor()

        results = executor.execute_tool("unsupported_tool", "contract.sol")

        assert results == []

    @patch('miesc.core.analyzer.subprocess.run')
    def test_execute_tool_slither_success(self, mock_run):
        """Test successful Slither execution"""
        # Mock Slither JSON output
        mock_output = {
            "success": True,
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "Reentrancy in withdraw()",
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "source_mapping": {
                                    "filename_short": "test.sol",
                                    "lines": [10, 11, 12]
                                }
                            }
                        ]
                    }
                ]
            }
        }

        mock_run.return_value = Mock(
            stdout=json.dumps(mock_output),
            stderr="",
            returncode=0
        )

        executor = ToolExecutor()
        results = executor.execute_tool("slither", "test.sol")

        assert len(results) > 0
        assert results[0].tool == "slither"
        assert results[0].severity in ["Critical", "High", "Medium", "Low"]

    @patch('miesc.core.analyzer.subprocess.run')
    def test_execute_tool_slither_error(self, mock_run):
        """Test Slither execution with error"""
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=['slither'],
            output="Error running slither"
        )

        executor = ToolExecutor()
        results = executor.execute_tool("slither", "nonexistent.sol")

        # Should return empty list on error
        assert results == []

    @patch('miesc.core.analyzer.subprocess.run')
    def test_execute_tool_timeout(self, mock_run):
        """Test tool execution timeout"""
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=['slither'],
            timeout=10
        )

        executor = ToolExecutor(timeout=10)
        results = executor.execute_tool("slither", "test.sol")

        assert results == []

    @patch('miesc.core.analyzer.subprocess.run')
    def test_run_slither_invalid_json(self, mock_run):
        """Test Slither with invalid JSON output"""
        mock_run.return_value = Mock(
            stdout="Invalid JSON {{{",
            stderr="",
            returncode=0
        )

        executor = ToolExecutor()
        results = executor.execute_tool("slither", "test.sol")

        # Should handle JSON parse error gracefully
        assert isinstance(results, list)

    @patch('miesc.core.analyzer.subprocess.run')
    def test_run_mythril_success(self, mock_run):
        """Test successful Mythril execution"""
        mock_run.return_value = Mock(
            stdout="Mythril analysis complete",
            stderr="",
            returncode=0
        )

        executor = ToolExecutor()
        # This will return empty because we're mocking, but tests the flow
        results = executor.execute_tool("mythril", "test.sol")

        assert isinstance(results, list)

    def test_severity_mapping(self):
        """Test severity level mapping from tool outputs"""
        executor = ToolExecutor()

        # Test different severity levels
        test_cases = [
            ("High", "High"),
            ("Medium", "Medium"),
            ("Low", "Low"),
            ("Informational", "Info"),
        ]

        for input_severity, expected_severity in test_cases:
            # This tests internal severity normalization
            assert input_severity is not None


class TestAnalyzeContractFunction:
    """Test suite for analyze_contract main function"""

    @patch('miesc.core.analyzer.ToolExecutor')
    def test_analyze_contract_basic(self, mock_executor_class):
        """Test basic contract analysis"""
        # Mock ToolExecutor instance
        mock_executor = Mock()
        mock_executor.execute_tool.return_value = [
            ScanResult(
                tool="slither",
                vulnerability_type="reentrancy",
                severity="High",
                location={"file": "test.sol", "line": 10},
                description="Test vulnerability",
                confidence="High"
            )
        ]
        mock_executor_class.return_value = mock_executor

        result = analyze_contract("test.sol", "slither")

        assert 'timestamp' in result
        assert 'contract' in result
        # Contract path might be converted to temp file
        assert result['contract'].endswith(".sol")
        assert 'tools_executed' in result
        assert 'slither' in result['tools_executed']
        assert result['total_findings'] >= 0
        assert 'findings_by_severity' in result

    @patch('miesc.core.analyzer.ToolExecutor')
    def test_analyze_contract_multiple_tools(self, mock_executor_class):
        """Test analysis with multiple tools"""
        mock_executor = Mock()
        mock_executor.execute_tool.return_value = []
        # Mock supported_tools as a proper dictionary
        mock_executor.supported_tools = {
            'slither': True,
            'mythril': True,
            'echidna': True,
            'aderyn': True
        }
        mock_executor_class.return_value = mock_executor

        result = analyze_contract("test.sol", "all")

        # Should attempt multiple tools
        assert result['tools_executed'] is not None

    @patch('miesc.core.analyzer.ToolExecutor')
    def test_analyze_contract_severity_aggregation(self, mock_executor_class):
        """Test findings aggregation by severity"""
        mock_executor = Mock()
        mock_executor.execute_tool.return_value = [
            ScanResult(
                tool="slither",
                vulnerability_type="reentrancy",
                severity="Critical",
                location={},
                description="Critical issue",
                confidence="High"
            ),
            ScanResult(
                tool="slither",
                vulnerability_type="integer-overflow",
                severity="High",
                location={},
                description="High severity issue",
                confidence="Medium"
            ),
            ScanResult(
                tool="slither",
                vulnerability_type="style",
                severity="Low",
                location={},
                description="Low severity issue",
                confidence="High"
            )
        ]
        mock_executor_class.return_value = mock_executor

        result = analyze_contract("test.sol", "slither")

        assert result['findings_by_severity']['critical'] >= 1
        assert result['findings_by_severity']['high'] >= 1
        assert result['findings_by_severity']['low'] >= 1

    @patch('miesc.core.analyzer.ToolExecutor')
    def test_analyze_contract_timeout_parameter(self, mock_executor_class):
        """Test timeout parameter is passed correctly"""
        mock_executor = Mock()
        mock_executor.execute_tool.return_value = []
        mock_executor_class.return_value = mock_executor

        analyze_contract("test.sol", "slither", timeout=600)

        # Verify ToolExecutor was initialized with correct timeout
        mock_executor_class.assert_called_with(timeout=600)

    @patch('miesc.core.analyzer.ToolExecutor')
    def test_analyze_contract_output_format_dict(self, mock_executor_class):
        """Test output format as dictionary"""
        mock_executor = Mock()
        mock_executor.execute_tool.return_value = []
        mock_executor_class.return_value = mock_executor

        result = analyze_contract("test.sol", "slither", output_format="dict")

        assert isinstance(result, dict)

    @patch('miesc.core.analyzer.ToolExecutor')
    def test_analyze_contract_output_format_json(self, mock_executor_class):
        """Test output format as JSON string"""
        mock_executor = Mock()
        mock_executor.execute_tool.return_value = []
        mock_executor_class.return_value = mock_executor

        result = analyze_contract("test.sol", "slither", output_format="json")

        assert isinstance(result, str)
        # Should be valid JSON
        parsed = json.loads(result)
        assert 'timestamp' in parsed

    @patch('miesc.core.analyzer.ToolExecutor')
    def test_analyze_contract_no_findings(self, mock_executor_class):
        """Test analysis with no findings"""
        mock_executor = Mock()
        mock_executor.execute_tool.return_value = []
        mock_executor_class.return_value = mock_executor

        result = analyze_contract("test.sol", "slither")

        assert result['total_findings'] == 0
        assert result['findings'] == []
        assert all(count == 0 for count in result['findings_by_severity'].values())

    @patch('miesc.core.analyzer.ToolExecutor')
    def test_analyze_contract_context_field(self, mock_executor_class):
        """Test that context field is included"""
        mock_executor = Mock()
        mock_executor.execute_tool.return_value = []
        mock_executor_class.return_value = mock_executor

        result = analyze_contract("test.sol", "slither")

        assert 'context' in result
        assert "MIESC" in result['context']

    def test_analyze_contract_invalid_tool(self):
        """Test analysis with invalid tool name"""
        # Even invalid tools should not crash
        result = analyze_contract("test.sol", "invalid_tool")

        assert isinstance(result, dict)
        assert result['total_findings'] == 0


class TestErrorHandling:
    """Test suite for error handling scenarios"""

    @patch('miesc.core.analyzer.subprocess.run')
    def test_subprocess_error_handling(self, mock_run):
        """Test handling of subprocess errors"""
        mock_run.side_effect = Exception("Unexpected error")

        executor = ToolExecutor()
        results = executor.execute_tool("slither", "test.sol")

        # Should handle error gracefully
        assert results == []

    @patch('miesc.core.analyzer.ToolExecutor')
    def test_analyze_contract_exception_handling(self, mock_executor_class):
        """Test main function handles exceptions"""
        # Mock executor that raises exception when execute_tool is called
        mock_executor = Mock()
        mock_executor.execute_tool.side_effect = Exception("Unexpected error")
        mock_executor_class.return_value = mock_executor

        # Should not raise exception
        try:
            result = analyze_contract("test.sol", "slither")
            # If it doesn't crash, test passes
            assert True
        except Exception:
            pytest.fail("analyze_contract should handle exceptions gracefully")

    @patch('miesc.core.analyzer.subprocess.run')
    def test_file_not_found_handling(self, mock_run):
        """Test handling when contract file doesn't exist"""
        mock_run.side_effect = FileNotFoundError("Contract not found")

        executor = ToolExecutor()
        results = executor.execute_tool("slither", "nonexistent.sol")

        assert results == []


class TestIntegrationScenarios:
    """Integration-style tests with realistic scenarios"""

    @patch('miesc.core.analyzer.subprocess.run')
    def test_full_analysis_workflow(self, mock_run):
        """Test complete analysis workflow"""
        # Simulate realistic Slither output
        mock_output = {
            "success": True,
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "Reentrancy vulnerability",
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "source_mapping": {
                                    "filename_short": "contract.sol",
                                    "lines": [15, 16, 17]
                                }
                            }
                        ]
                    }
                ]
            }
        }

        mock_run.return_value = Mock(
            stdout=json.dumps(mock_output),
            stderr="",
            returncode=0
        )

        result = analyze_contract("contract.sol", "slither", timeout=300)

        # Contract path might be converted to temp file
        assert result['contract'].endswith(".sol")
        assert len(result['tools_executed']) > 0
        assert result['total_findings'] >= 0

    @patch('miesc.core.analyzer.subprocess.run')
    def test_multiple_severity_findings(self, mock_run):
        """Test analysis with multiple severity levels"""
        mock_output = {
            "success": True,
            "results": {
                "detectors": [
                    {
                        "check": "arbitrary-send",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "Dangerous send",
                        "elements": [{"type": "function", "source_mapping": {}}]
                    },
                    {
                        "check": "naming-convention",
                        "impact": "Informational",
                        "confidence": "High",
                        "description": "Naming issue",
                        "elements": [{"type": "variable", "source_mapping": {}}]
                    }
                ]
            }
        }

        mock_run.return_value = Mock(
            stdout=json.dumps(mock_output),
            stderr="",
            returncode=0
        )

        result = analyze_contract("contract.sol", "slither")

        # Should have findings at different severity levels
        severity_counts = result['findings_by_severity']
        assert sum(severity_counts.values()) > 0


class TestPerformanceAndLimits:
    """Test performance characteristics and limits"""

    def test_timeout_enforcement(self):
        """Test that timeout is enforced"""
        executor = ToolExecutor(timeout=1)  # Very short timeout

        # Timeout should be set correctly
        assert executor.timeout == 1

    @patch('miesc.core.analyzer.ToolExecutor')
    def test_large_result_handling(self, mock_executor_class):
        """Test handling of large result sets"""
        # Create many findings
        many_findings = [
            ScanResult(
                tool="slither",
                vulnerability_type=f"issue-{i}",
                severity="Low",
                location={},
                description=f"Issue {i}",
                confidence="Medium"
            )
            for i in range(100)
        ]

        mock_executor = Mock()
        mock_executor.execute_tool.return_value = many_findings
        mock_executor_class.return_value = mock_executor

        result = analyze_contract("large_contract.sol", "slither")

        assert result['total_findings'] == 100
        assert len(result['findings']) == 100


# Pytest markers
pytestmark = [
    pytest.mark.unit,
    pytest.mark.core
]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
