"""
Unit Tests for MIESC Core Module

Test-Driven Development (TDD) approach:
1. Write tests first
2. Implement features to pass tests
3. Refactor with confidence

Author: Fernando Boiero
"""

import pytest
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from miesc_core import MIESCCore, ToolExecutor, ScanResult


class TestScanResult:
    """Test ScanResult dataclass"""

    def test_scan_result_creation(self):
        """Test creating a ScanResult object"""
        result = ScanResult(
            tool="slither",
            vulnerability_type="reentrancy",
            severity="High",
            location={"file": "test.sol", "line": 42},
            description="Test vulnerability",
            confidence="High"
        )

        assert result.tool == "slither"
        assert result.severity == "High"
        assert result.location["line"] == 42

    def test_scan_result_to_dict(self):
        """Test converting ScanResult to dictionary"""
        result = ScanResult(
            tool="mythril",
            vulnerability_type="access-control",
            severity="Critical",
            location={},
            description="Test",
            confidence="Medium"
        )

        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert result_dict["tool"] == "mythril"
        assert result_dict["severity"] == "Critical"


class TestToolExecutor:
    """Test ToolExecutor class"""

    def test_tool_executor_initialization(self):
        """Test ToolExecutor initialization"""
        executor = ToolExecutor(timeout=60)
        assert executor.timeout == 60
        assert "slither" in executor.supported_tools

    def test_unsupported_tool(self):
        """Test handling of unsupported tools"""
        executor = ToolExecutor()
        results = executor.execute_tool("nonexistent_tool", "test.sol")
        assert results == []

    @patch('subprocess.run')
    def test_slither_execution_success(self, mock_run):
        """Test successful Slither execution"""
        # Mock Slither output
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"results": {"detectors": []}}',
            stderr=''
        )

        executor = ToolExecutor()
        results = executor.execute_tool("slither", "test.sol")
        assert isinstance(results, list)

    def test_map_to_swc(self):
        """Test vulnerability to SWC mapping"""
        executor = ToolExecutor()
        swc = executor._map_to_swc("reentrancy-eth")
        assert swc == "SWC-107"

        swc = executor._map_to_swc("tx-origin")
        assert swc == "SWC-115"

    def test_map_to_owasp(self):
        """Test vulnerability to OWASP mapping"""
        executor = ToolExecutor()
        owasp = executor._map_to_owasp("reentrancy-eth")
        assert owasp == "SC01-Reentrancy"


class TestMIESCCore:
    """Test MIESCCore main class"""

    def test_miesc_core_initialization(self):
        """Test MIESCCore initialization"""
        core = MIESCCore()
        assert core.executor is not None
        assert isinstance(core.results_cache, dict)

    def test_hash_file(self, tmp_path):
        """Test file hashing functionality"""
        # Create temporary file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        core = MIESCCore()
        hash1 = core._hash_file(str(test_file))
        hash2 = core._hash_file(str(test_file))

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex length

    def test_count_by_severity(self):
        """Test severity counting"""
        results = [
            ScanResult("tool1", "vuln1", "Critical", {}, "desc", "High"),
            ScanResult("tool2", "vuln2", "High", {}, "desc", "High"),
            ScanResult("tool3", "vuln3", "Critical", {}, "desc", "Medium"),
        ]

        core = MIESCCore()
        counts = core._count_by_severity(results)

        assert counts["Critical"] == 2
        assert counts["High"] == 1
        assert counts["Medium"] == 0

    @patch.object(ToolExecutor, 'execute_tool')
    def test_scan_contract_basic(self, mock_execute, tmp_path):
        """Test basic contract scanning"""
        # Create test contract
        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Test {}")

        # Mock tool results
        mock_execute.return_value = [
            ScanResult("slither", "test-vuln", "Medium", {}, "Test finding", "High")
        ]

        core = MIESCCore()
        results = core.scan_contract(str(contract), tools=["slither"])

        assert results["total_findings"] == 1
        assert "slither" in results["tools_executed"]
        assert results["findings_by_severity"]["Medium"] == 1

    def test_scan_nonexistent_contract(self):
        """Test scanning non-existent contract"""
        core = MIESCCore()

        with pytest.raises(FileNotFoundError):
            core.scan_contract("nonexistent.sol")

    def test_export_results(self, tmp_path):
        """Test results export functionality"""
        output_file = tmp_path / "results.json"

        core = MIESCCore()
        test_results = {
            "contract": "test.sol",
            "findings": []
        }

        core.export_results(test_results, str(output_file))

        assert output_file.exists()
        import json
        data = json.loads(output_file.read_text())
        assert data["contract"] == "test.sol"


class TestIntegration:
    """Integration tests for MIESC Core"""

    @pytest.mark.slow
    @patch('subprocess.run')
    def test_full_scan_workflow(self, mock_run, tmp_path):
        """Test complete scan workflow"""
        # Create test contract
        contract = tmp_path / "vulnerable.sol"
        contract.write_text("""
        pragma solidity ^0.8.0;
        contract Vulnerable {
            function withdraw() public {
                // Reentrancy vulnerability
            }
        }
        """)

        # Mock tool outputs
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"results": {"detectors": []}}',
            stderr=''
        )

        core = MIESCCore()
        results = core.scan_contract(str(contract), tools=["slither"])

        assert "scan_timestamp" in results
        assert "contract_hash" in results
        assert results["total_findings"] >= 0


# Fixtures
@pytest.fixture
def sample_contract(tmp_path):
    """Create a sample Solidity contract for testing"""
    contract = tmp_path / "sample.sol"
    contract.write_text("""
    pragma solidity ^0.8.0;

    contract Sample {
        uint public value;

        function setValue(uint _value) public {
            value = _value;
        }
    }
    """)
    return contract


@pytest.fixture
def vulnerable_contract(tmp_path):
    """Create a vulnerable contract for testing"""
    contract = tmp_path / "vulnerable.sol"
    contract.write_text("""
    pragma solidity ^0.8.0;

    contract Vulnerable {
        mapping(address => uint) public balances;

        function withdraw() public {
            uint amount = balances[msg.sender];
            (bool success,) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] = 0;
        }
    }
    """)
    return contract


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
