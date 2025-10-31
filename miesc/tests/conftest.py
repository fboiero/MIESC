"""
Pytest Configuration and Shared Fixtures

Provides common test fixtures, markers, and configuration for MIESC tests.

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
"""

import pytest
import os
import tempfile
from pathlib import Path
from typing import Dict, Any


# ==================== Pytest Configuration ====================

def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "security: Security-focused tests")
    config.addinivalue_line("markers", "core: Tests for core modules")
    config.addinivalue_line("markers", "api: Tests for API layer")
    config.addinivalue_line("markers", "cli: Tests for CLI interface")
    config.addinivalue_line("markers", "slow: Slow-running tests")


# ==================== Sample Contracts ====================

@pytest.fixture
def simple_contract():
    """Simple valid Solidity contract"""
    return """
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private value;

    function setValue(uint256 _value) public {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }
}
"""


@pytest.fixture
def reentrancy_contract():
    """Contract with reentrancy vulnerability"""
    return """
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");

        // Vulnerable: external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;  // Too late!
    }
}
"""


@pytest.fixture
def integer_overflow_contract():
    """Contract with integer overflow vulnerability"""
    return """
pragma solidity ^0.7.0;  // Pre-0.8.0 for overflow

contract UnsafeToken {
    mapping(address => uint256) public balances;

    function mint(address to, uint256 amount) public {
        balances[to] += amount;  // Can overflow
    }
}
"""


@pytest.fixture
def multiple_vulnerabilities_contract():
    """Contract with multiple types of vulnerabilities"""
    return """
pragma solidity ^0.8.0;

contract BadContract {
    address public owner;
    mapping(address => uint256) public balances;

    // Missing constructor - owner not set

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        // Missing access control
        require(balances[msg.sender] >= amount);

        // Reentrancy vulnerability
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        balances[msg.sender] -= amount;
    }

    function dangerousDelegate(address target, bytes memory data) public {
        // Unchecked delegatecall
        (bool success, ) = target.delegatecall(data);
        require(success);
    }
}
"""


# ==================== File System Fixtures ====================

@pytest.fixture
def temp_contract_file(tmp_path: Path):
    """Create a temporary Solidity contract file"""
    def _create_file(content: str, filename: str = "test.sol") -> Path:
        file_path = tmp_path / filename
        file_path.write_text(content)
        return file_path
    return _create_file


@pytest.fixture
def temp_directory(tmp_path: Path):
    """Provide a temporary directory for tests"""
    return tmp_path


# ==================== Mock Data Fixtures ====================

@pytest.fixture
def mock_slither_output():
    """Mock Slither JSON output"""
    return {
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
                                "filename_absolute": "/path/to/test.sol",
                                "start": 100,
                                "length": 200,
                                "lines": [10, 11, 12, 13, 14]
                            }
                        }
                    ]
                }
            ]
        }
    }


@pytest.fixture
def mock_mythril_output():
    """Mock Mythril JSON output"""
    return {
        "error": None,
        "issues": [
            {
                "title": "Integer Overflow",
                "severity": "High",
                "description": "A possible integer overflow exists",
                "swc-id": "101",
                "address": 142,
                "function": "mint",
                "source_map": "142:5:0"
            }
        ]
    }


@pytest.fixture
def mock_analysis_result():
    """Mock complete analysis result"""
    return {
        "timestamp": "2025-10-20T14:00:00",
        "contract": "test.sol",
        "tools_executed": ["slither"],
        "total_findings": 2,
        "findings_by_severity": {
            "critical": 0,
            "high": 1,
            "medium": 1,
            "low": 0
        },
        "findings": [
            {
                "tool": "slither",
                "vulnerability_type": "reentrancy-eth",
                "severity": "High",
                "location": {"file": "test.sol", "line": 10},
                "description": "Reentrancy detected",
                "confidence": "Medium"
            },
            {
                "tool": "slither",
                "vulnerability_type": "naming-convention",
                "severity": "Medium",
                "location": {"file": "test.sol", "line": 5},
                "description": "Naming convention violated",
                "confidence": "High"
            }
        ],
        "context": "MIESC static/dynamic analysis"
    }


# ==================== API/Request Fixtures ====================

@pytest.fixture
def valid_analysis_request():
    """Valid analysis request payload"""
    return {
        "contract_code": "pragma solidity ^0.8.0; contract Test {}",
        "analysis_type": "slither",
        "timeout": 300
    }


@pytest.fixture
def valid_verify_request():
    """Valid verification request payload"""
    return {
        "contract_code": "pragma solidity ^0.8.0; contract Test {}",
        "verification_level": "basic",
        "properties": ["invariant balance >= 0"],
        "timeout": 600
    }


@pytest.fixture
def valid_classify_request(mock_analysis_result):
    """Valid classification request payload"""
    return {
        "report": mock_analysis_result,
        "enable_ai_triage": False
    }


# ==================== Environment Fixtures ====================

@pytest.fixture
def mock_env_variables(monkeypatch):
    """Mock environment variables"""
    def _set_env(vars_dict: Dict[str, str]):
        for key, value in vars_dict.items():
            monkeypatch.setenv(key, value)
    return _set_env


@pytest.fixture
def clean_env(monkeypatch):
    """Clean environment without sensitive variables"""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("API_KEY", raising=False)


# ==================== Performance Fixtures ====================

@pytest.fixture
def benchmark_timer():
    """Simple timer for performance testing"""
    import time

    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            self.start_time = time.time()

        def stop(self):
            self.end_time = time.time()

        @property
        def elapsed(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return 0

    return Timer()


# ==================== Test Data Generators ====================

@pytest.fixture
def generate_findings():
    """Generate test findings data"""
    def _generate(count: int, severity: str = "Medium"):
        from miesc.core.analyzer import ScanResult
        return [
            ScanResult(
                tool="slither",
                vulnerability_type=f"issue-{i}",
                severity=severity,
                location={"file": "test.sol", "line": i},
                description=f"Test finding {i}",
                confidence="High"
            )
            for i in range(count)
        ]
    return _generate


# ==================== Cleanup Fixtures ====================

@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """Automatically cleanup temporary files after tests"""
    yield
    # Cleanup code runs after each test
    # (pytest's tmp_path fixture already handles this)


# ==================== Logging Fixtures ====================

@pytest.fixture
def capture_logs(caplog):
    """Capture and provide access to logs"""
    import logging
    caplog.set_level(logging.DEBUG)
    return caplog


# ==================== Database/State Fixtures ====================

@pytest.fixture
def reset_state():
    """Reset any global state between tests"""
    yield
    # Reset code here if needed


# ==================== Skip Conditions ====================

def pytest_collection_modifyitems(config, items):
    """Modify test collection"""
    # Skip slow tests unless --run-slow is passed
    if not config.getoption("--run-slow", default=False):
        skip_slow = pytest.mark.skip(reason="Slow test (use --run-slow to run)")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)


def pytest_addoption(parser):
    """Add custom command line options"""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests"
    )
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests"
    )
