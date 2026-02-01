"""
MIESC Test Configuration
Shared fixtures and configuration for pytest.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# Sample contracts for testing
SIMPLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }
}
"""

VULNERABLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Reentrancy vulnerability
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
"""

TOKEN_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleToken {
    string public name = "SimpleToken";
    string public symbol = "STK";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balanceOf[msg.sender] >= _value, "Insufficient balance");
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(balanceOf[_from] >= _value, "Insufficient balance");
        require(allowance[_from][msg.sender] >= _value, "Allowance exceeded");
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
}
"""


@pytest.fixture
def simple_contract():
    """Create a temporary simple contract file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
        f.write(SIMPLE_CONTRACT)
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def vulnerable_contract():
    """Create a temporary vulnerable contract file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
        f.write(VULNERABLE_CONTRACT)
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def token_contract():
    """Create a temporary token contract file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
        f.write(TOKEN_CONTRACT)
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def contracts_directory():
    """Create a temporary directory with multiple contracts."""
    import shutil

    tmpdir = tempfile.mkdtemp()
    contracts = [
        ("Simple.sol", SIMPLE_CONTRACT),
        ("Vulnerable.sol", VULNERABLE_CONTRACT),
        ("Token.sol", TOKEN_CONTRACT),
    ]

    for name, content in contracts:
        path = os.path.join(tmpdir, name)
        with open(path, "w") as f:
            f.write(content)

    yield tmpdir
    shutil.rmtree(tmpdir)


@pytest.fixture
def nonexistent_file():
    """Return path to a non-existent file."""
    return "/tmp/miesc_test_nonexistent_12345.sol"


@pytest.fixture
def sample_findings():
    """Return sample findings for testing."""
    return [
        {
            "_id": "f1",
            "type": "reentrancy",
            "severity": "high",
            "message": "Reentrancy vulnerability in withdraw function",
            "location": {"file": "VulnerableBank.sol", "line": 15},
            "tool": "slither",
            "swc_id": "SWC-107",
            "cwe_id": "CWE-841",
        },
        {
            "_id": "f2",
            "type": "unchecked-call",
            "severity": "medium",
            "message": "Unchecked return value from external call",
            "location": {"file": "VulnerableBank.sol", "line": 18},
            "tool": "slither",
            "swc_id": "SWC-104",
            "cwe_id": "CWE-252",
        },
        {
            "_id": "f3",
            "type": "floating-pragma",
            "severity": "informational",
            "message": "Floating pragma version",
            "location": {"file": "VulnerableBank.sol", "line": 2},
            "tool": "solhint",
        },
        {
            "_id": "f4",
            "type": "integer-overflow",
            "severity": "high",
            "message": "Integer overflow possible",
            "location": {"file": "Token.sol", "line": 25},
            "tool": "mythril",
            "swc_id": "SWC-101",
            "cwe_id": "CWE-190",
        },
    ]


@pytest.fixture
def sample_tool_result():
    """Return sample tool result for testing."""
    return {
        "tool": "slither",
        "version": "0.9.0",
        "status": "success",
        "execution_time_ms": 1500,
        "findings": [
            {
                "type": "reentrancy",
                "severity": "high",
                "message": "Reentrancy vulnerability detected",
                "location": {"file": "test.sol", "line": 10},
            }
        ],
    }


@pytest.fixture
def cli_runner():
    """Click CLI test runner."""
    from click.testing import CliRunner

    return CliRunner()


@pytest.fixture
def multi_tool_findings():
    """Findings from multiple tools for the same contract."""
    return {
        "slither": [
            {
                "type": "reentrancy-eth",
                "severity": "high",
                "message": "Reentrancy in VulnerableBank.withdraw()",
                "location": {"file": "VulnerableBank.sol", "line": 15, "function": "withdraw"},
                "confidence": "high",
                "swc_id": "SWC-107",
                "cwe_id": "CWE-841",
            },
            {
                "type": "unchecked-lowlevel",
                "severity": "medium",
                "message": "Low level call in withdraw()",
                "location": {"file": "VulnerableBank.sol", "line": 18, "function": "withdraw"},
                "confidence": "medium",
                "swc_id": "SWC-104",
            },
        ],
        "mythril": [
            {
                "type": "reentrancy",
                "severity": "high",
                "message": "State change after external call in function withdraw",
                "location": {"file": "VulnerableBank.sol", "line": 15, "function": "withdraw"},
                "confidence": "high",
                "swc_id": "SWC-107",
            },
            {
                "type": "integer-overflow",
                "severity": "high",
                "message": "Integer overflow possible in deposit()",
                "location": {"file": "VulnerableBank.sol", "line": 8, "function": "deposit"},
                "confidence": "medium",
                "swc_id": "SWC-101",
                "cwe_id": "CWE-190",
            },
        ],
        "solhint": [
            {
                "type": "reentrancy",
                "severity": "high",
                "message": "Possible reentrancy vulnerability detected",
                "location": {"file": "VulnerableBank.sol", "line": 14, "function": "withdraw"},
                "confidence": "medium",
            },
            {
                "type": "pragma",
                "severity": "informational",
                "message": "Floating pragma version detected",
                "location": {"file": "VulnerableBank.sol", "line": 2},
                "confidence": "high",
            },
        ],
    }


@pytest.fixture
def correlation_engine():
    """Pre-configured correlation engine."""
    from src.ml.correlation_engine import SmartCorrelationEngine

    return SmartCorrelationEngine(min_tools_for_validation=2)


@pytest.fixture
def report_findings():
    """Findings suitable for report generation (using audit_report.Finding)."""
    from src.reports.audit_report import Finding

    return [
        Finding(
            id="MIESC-001",
            title="Reentrancy Vulnerability in withdraw()",
            severity="Critical",
            category="Reentrancy",
            description="The withdraw function makes an external call before updating state.",
            location="VulnerableBank.sol:15",
            line_number=15,
            tool="slither",
            layer=1,
            swc_id="SWC-107",
            cwe_id="CWE-841",
            remediation="Apply checks-effects-interactions pattern.",
        ),
        Finding(
            id="MIESC-002",
            title="Unchecked Return Value",
            severity="High",
            category="Unchecked Calls",
            description="Return value of external call is not checked.",
            location="VulnerableBank.sol:18",
            line_number=18,
            tool="slither",
            layer=1,
            swc_id="SWC-104",
            cwe_id="CWE-252",
            remediation="Check the return value of low-level calls.",
        ),
        Finding(
            id="MIESC-003",
            title="Floating Pragma",
            severity="Informational",
            category="Best Practices",
            description="Contract uses a floating pragma version.",
            location="VulnerableBank.sol:2",
            line_number=2,
            tool="solhint",
            layer=1,
        ),
    ]


@pytest.fixture
def report_metadata():
    """Pre-configured audit metadata for report tests."""
    from src.reports.audit_report import AuditMetadata

    return AuditMetadata(
        project_name="Test Project",
        contract_name="VulnerableBank.sol",
        version="1.0.0",
        auditor="Test Auditor",
        organization="MIESC Testing",
        audit_date="2026-01-27",
        report_id="TEST-20260127-001",
        contract_hash="abc123def456",
        solidity_version="0.8.0",
        lines_of_code=30,
    )


@pytest.fixture
def mock_orchestrator():
    """Create mock orchestrator for testing."""
    from unittest.mock import MagicMock

    orchestrator = MagicMock()
    orchestrator.analyze.return_value = MagicMock(
        original_findings=[],
        filtered_findings=[],
        clusters=[],
        execution_time_ms=100,
        ml_processing_time_ms=50,
        get_summary=lambda: {
            "total_findings": 0,
            "risk_level": "LOW",
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "fp_removed": 0,
            "reduction_rate": 0,
            "clusters": 0,
            "priority_actions": 0,
        },
    )
    return orchestrator


# Pytest configuration
def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "requires_tools: marks tests that require external tools")


def _check_foundry_available():
    """Check if Foundry (forge) is available."""
    import shutil

    return shutil.which("forge") is not None


def pytest_collection_modifyitems(config, items):
    """Modify test collection."""
    # Skip slow tests unless explicitly requested
    if not config.getoption("-m"):
        skip_slow = pytest.mark.skip(reason="use -m slow to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)

    # Skip requires_tools tests if Foundry is not available
    if not _check_foundry_available():
        skip_tools = pytest.mark.skip(reason="Foundry not installed")
        for item in items:
            if "requires_tools" in item.keywords:
                item.add_marker(skip_tools)
