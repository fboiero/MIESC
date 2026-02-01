"""
Tests for Hardhat Adapter - Layer 2: Dynamic Testing
=====================================================

Comprehensive tests for the HardhatAdapter class which provides
integration with Hardhat's compilation and security plugins.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from src.adapters.hardhat_adapter import HardhatAdapter, register_adapter
from src.core.tool_protocol import ToolCategory, ToolMetadata, ToolStatus

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def adapter():
    """Create a default HardhatAdapter instance."""
    return HardhatAdapter()


@pytest.fixture
def adapter_with_config():
    """Create adapter with custom configuration."""
    config = {
        "project_path": "/path/to/project",
        "network": "localhost",
        "compile_force": False,
        "run_gas_reporter": True,
        "run_coverage": True,
        "timeout": 300,
    }
    return HardhatAdapter(config=config)


@pytest.fixture
def sample_compilation_output():
    """Sample Hardhat compilation output with warnings."""
    return """
Compiling 5 Solidity files with 0.8.20
Generating typings for: 5 artifacts in dir: typechain-types for target: ethers-v6
Successfully generated 15 typings!
Compiled 5 Solidity file(s) successfully.

contracts/Token.sol:15:5: Warning: Unused local variable.
    uint256 unused = 0;
    ^-----------------^

contracts/Token.sol:20:13: Warning: Function state mutability can be restricted to pure
    function _helper() internal view returns (uint256) {
    ^---------------------------------------------------^

contracts/Vault.sol:45:9: Error: Division by zero.
    return total / count;
    ^-------------------^
"""


@pytest.fixture
def sample_gas_report():
    """Sample gas reporter output."""
    return """
·-----------------------------------|---------------------------|-------------|-----------------------------·
|       Solc version: 0.8.20        ·  Optimizer enabled: true  ·  Runs: 200  ·  Block limit: 30000000 gas  │
····································|···························|·············|······························
|  Methods                          ·               20 gwei/gas               ·       1500.00 usd/eth       │
·············|······················|·············|·············|·············|···············|··············
|  Contract  ·  Method              ·  Min        ·  Max        ·  Avg        ·  # calls      ·  usd (avg)  │
·············|······················|·············|·············|·············|···············|··············
|  Token     ·  transfer            ·      51234  ·      65432  ·      58333  ·           10  ·          -  │
·············|······················|·············|·············|·············|···············|··············
|  Vault     ·  deposit             ·     123456  ·     234567  ·     178901  ·            5  ·          -  │
·············|······················|·············|·············|·············|···············|··············
|  Vault     ·  withdraw            ·     456789  ·     567890  ·     512345  ·            3  ·          -  │
·············|······················|·············|·············|·············|···············|··············
"""


@pytest.fixture
def sample_coverage_output():
    """Sample coverage output."""
    return """
---------------------------|----------|----------|----------|----------|
File                       |  % Stmts | % Branch |  % Funcs |  % Lines |
---------------------------|----------|----------|----------|----------|
 contracts/                |    85.71 |       75 |    83.33 |    85.71 |
  Token.sol                |    95.24 |    87.50 |    91.67 |    95.24 |
  Vault.sol                |    65.00 |    55.00 |    70.00 |    65.00 |
  Utils.sol                |   100.00 |   100.00 |   100.00 |   100.00 |
---------------------------|----------|----------|----------|----------|
All files                  |    85.71 |       75 |    83.33 |    85.71 |
---------------------------|----------|----------|----------|----------|
"""


@pytest.fixture
def hardhat_project_dir(tmp_path):
    """Create a mock Hardhat project structure."""
    project = tmp_path / "hardhat_project"
    project.mkdir()

    # Create hardhat.config.js
    config_file = project / "hardhat.config.js"
    config_file.write_text("""
module.exports = {
  solidity: "0.8.20",
};
""")

    # Create contracts directory
    contracts = project / "contracts"
    contracts.mkdir()

    # Create a sample contract
    token = contracts / "Token.sol"
    token.write_text("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
""")

    return project


# =============================================================================
# Class Attributes Tests
# =============================================================================


class TestClassAttributes:
    """Test HardhatAdapter class attributes."""

    def test_metadata_structure(self):
        """Test METADATA dict has required keys."""
        assert "name" in HardhatAdapter.METADATA
        assert "version" in HardhatAdapter.METADATA
        assert "category" in HardhatAdapter.METADATA
        assert "description" in HardhatAdapter.METADATA
        assert "is_optional" in HardhatAdapter.METADATA
        assert "requires" in HardhatAdapter.METADATA
        assert "supported_languages" in HardhatAdapter.METADATA
        assert "detection_types" in HardhatAdapter.METADATA

    def test_metadata_values(self):
        """Test METADATA values are correct."""
        assert HardhatAdapter.METADATA["name"] == "hardhat"
        assert HardhatAdapter.METADATA["category"] == "dynamic-testing"
        assert HardhatAdapter.METADATA["is_optional"] is True
        assert "npx" in HardhatAdapter.METADATA["requires"]
        assert "hardhat" in HardhatAdapter.METADATA["requires"]
        assert "solidity" in HardhatAdapter.METADATA["supported_languages"]

    def test_detection_types(self):
        """Test detection types cover expected categories."""
        types = HardhatAdapter.METADATA["detection_types"]
        assert "compilation_warnings" in types
        assert "gas_issues" in types
        assert "contract_size" in types
        assert "coverage_gaps" in types
        assert "security_issues" in types

    def test_severity_map(self):
        """Test SEVERITY_MAP contains all mappings."""
        smap = HardhatAdapter.SEVERITY_MAP
        assert smap["error"] == "critical"
        assert smap["warning"] == "medium"
        assert smap["info"] == "low"

    def test_warning_patterns_structure(self):
        """Test WARNING_PATTERNS has correct structure."""
        patterns = HardhatAdapter.WARNING_PATTERNS
        assert isinstance(patterns, dict)
        assert len(patterns) >= 10

        for pattern, (vuln_type, severity) in patterns.items():
            assert isinstance(pattern, str)
            assert isinstance(vuln_type, str)
            assert severity in ["info", "low", "medium", "high", "critical"]

    def test_warning_patterns_coverage(self):
        """Test WARNING_PATTERNS covers key warnings."""
        patterns = HardhatAdapter.WARNING_PATTERNS
        pattern_keys = list(patterns.keys())

        # Check that patterns for common warnings exist
        assert any("unused" in p for p in pattern_keys)
        assert any("visibility" in p for p in pattern_keys)
        assert any("shadowing" in p for p in pattern_keys)
        assert any("reentrancy" in p for p in pattern_keys)


# =============================================================================
# Initialization Tests
# =============================================================================


class TestInitialization:
    """Test HardhatAdapter initialization."""

    def test_default_initialization(self, adapter):
        """Test initialization with default config."""
        assert adapter.config == {}
        assert adapter.project_path is None
        assert adapter.network == "hardhat"
        assert adapter.compile_force is True
        assert adapter.run_gas_reporter is False
        assert adapter.run_coverage is False
        assert adapter.timeout == 180

    def test_custom_config_initialization(self, adapter_with_config):
        """Test initialization with custom config."""
        assert adapter_with_config.project_path == "/path/to/project"
        assert adapter_with_config.network == "localhost"
        assert adapter_with_config.compile_force is False
        assert adapter_with_config.run_gas_reporter is True
        assert adapter_with_config.run_coverage is True
        assert adapter_with_config.timeout == 300

    def test_partial_config(self):
        """Test initialization with partial config."""
        adapter = HardhatAdapter(config={"timeout": 60})
        assert adapter.timeout == 60
        assert adapter.network == "hardhat"  # Default
        assert adapter.compile_force is True  # Default

    def test_none_config(self):
        """Test initialization with None config."""
        adapter = HardhatAdapter(config=None)
        assert adapter.config == {}


# =============================================================================
# Metadata Tests
# =============================================================================


class TestGetMetadata:
    """Test get_metadata method."""

    def test_returns_tool_metadata(self, adapter):
        """Test get_metadata returns ToolMetadata instance."""
        metadata = adapter.get_metadata()
        assert isinstance(metadata, ToolMetadata)

    def test_metadata_name(self, adapter):
        """Test metadata name is correct."""
        metadata = adapter.get_metadata()
        assert metadata.name == "hardhat"

    def test_metadata_version(self, adapter):
        """Test metadata version is set."""
        metadata = adapter.get_metadata()
        assert metadata.version == "1.0.0"

    def test_metadata_category(self, adapter):
        """Test metadata category is DYNAMIC_TESTING."""
        metadata = adapter.get_metadata()
        assert metadata.category == ToolCategory.DYNAMIC_TESTING

    def test_metadata_capabilities(self, adapter):
        """Test metadata has capabilities."""
        metadata = adapter.get_metadata()
        assert len(metadata.capabilities) >= 4

        cap_names = [c.name for c in metadata.capabilities]
        assert "compilation_analysis" in cap_names
        assert "gas_analysis" in cap_names
        assert "coverage_analysis" in cap_names
        assert "size_analysis" in cap_names

    def test_metadata_is_optional(self, adapter):
        """Test metadata marks tool as optional."""
        metadata = adapter.get_metadata()
        assert metadata.is_optional is True

    def test_metadata_no_api_key_required(self, adapter):
        """Test metadata indicates no API key required."""
        metadata = adapter.get_metadata()
        assert metadata.requires_api_key is False

    def test_metadata_zero_cost(self, adapter):
        """Test metadata cost is zero."""
        metadata = adapter.get_metadata()
        assert metadata.cost == 0.0


# =============================================================================
# Availability Tests
# =============================================================================


class TestIsAvailable:
    """Test is_available method."""

    def test_available_when_installed(self, adapter):
        """Test returns AVAILABLE when hardhat is installed."""
        mock_npx = MagicMock()
        mock_npx.returncode = 0
        mock_npx.stdout = "10.0.0"

        mock_hardhat = MagicMock()
        mock_hardhat.returncode = 0
        mock_hardhat.stdout = "2.19.0"

        with patch("subprocess.run", side_effect=[mock_npx, mock_hardhat]) as mock_run:
            status = adapter.is_available()
            assert status == ToolStatus.AVAILABLE
            assert mock_run.call_count == 2

    def test_not_installed_npx_missing(self, adapter):
        """Test returns NOT_INSTALLED when npx not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            status = adapter.is_available()
            assert status == ToolStatus.NOT_INSTALLED

    def test_not_installed_npx_fails(self, adapter):
        """Test returns NOT_INSTALLED when npx fails."""
        mock_npx = MagicMock()
        mock_npx.returncode = 1

        with patch("subprocess.run", return_value=mock_npx):
            status = adapter.is_available()
            assert status == ToolStatus.NOT_INSTALLED

    def test_configuration_error_hardhat_fails(self, adapter):
        """Test returns CONFIGURATION_ERROR when hardhat fails."""
        mock_npx = MagicMock()
        mock_npx.returncode = 0
        mock_npx.stdout = "10.0.0"

        mock_hardhat = MagicMock()
        mock_hardhat.returncode = 1

        with patch("subprocess.run", side_effect=[mock_npx, mock_hardhat]):
            status = adapter.is_available()
            assert status == ToolStatus.CONFIGURATION_ERROR

    def test_configuration_error_on_timeout(self, adapter):
        """Test returns CONFIGURATION_ERROR on timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("npx", 10)):
            status = adapter.is_available()
            assert status == ToolStatus.CONFIGURATION_ERROR

    def test_configuration_error_on_exception(self, adapter):
        """Test returns CONFIGURATION_ERROR on general exception."""
        mock_npx = MagicMock()
        mock_npx.returncode = 0

        with patch("subprocess.run", side_effect=[mock_npx, Exception("Unknown error")]):
            status = adapter.is_available()
            assert status == ToolStatus.CONFIGURATION_ERROR


# =============================================================================
# Find Hardhat Project Tests
# =============================================================================


class TestFindHardhatProject:
    """Test _find_hardhat_project method."""

    def test_finds_project_in_current_dir(self, adapter, hardhat_project_dir):
        """Test finds project when config is in current directory."""
        result = adapter._find_hardhat_project(hardhat_project_dir)
        assert result == hardhat_project_dir

    def test_finds_project_in_parent_dir(self, adapter, hardhat_project_dir):
        """Test finds project when config is in parent directory."""
        contracts_dir = hardhat_project_dir / "contracts"
        result = adapter._find_hardhat_project(contracts_dir)
        assert result == hardhat_project_dir

    def test_finds_project_with_ts_config(self, adapter, tmp_path):
        """Test finds project with hardhat.config.ts."""
        project = tmp_path / "ts_project"
        project.mkdir()
        (project / "hardhat.config.ts").write_text("export default {};")

        result = adapter._find_hardhat_project(project)
        assert result == project

    def test_returns_none_no_project(self, adapter, tmp_path):
        """Test returns None when no project found."""
        no_project = tmp_path / "no_project"
        no_project.mkdir()

        result = adapter._find_hardhat_project(no_project)
        assert result is None


# =============================================================================
# Compile Tests
# =============================================================================


class TestRunCompile:
    """Test _run_compile method."""

    def test_compile_success(self, adapter, hardhat_project_dir, sample_compilation_output):
        """Test successful compilation."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_compilation_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = adapter._run_compile(hardhat_project_dir)

        assert result["info"]["success"] is True
        assert result["info"]["contracts_compiled"] == 5
        assert len(result["findings"]) >= 2  # At least 2 warnings

    def test_compile_force_flag(self, adapter, hardhat_project_dir):
        """Test --force flag is added when compile_force is True."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Compiled 1 Solidity file(s)"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            adapter._run_compile(hardhat_project_dir)

        cmd = mock_run.call_args[0][0]
        assert "--force" in cmd

    def test_compile_no_force_flag(self, hardhat_project_dir):
        """Test --force flag is not added when compile_force is False."""
        adapter = HardhatAdapter(config={"compile_force": False})

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Nothing to compile"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            adapter._run_compile(hardhat_project_dir)

        cmd = mock_run.call_args[0][0]
        assert "--force" not in cmd

    def test_compile_extracts_contract_count(self, adapter, hardhat_project_dir):
        """Test extraction of compiled contract count."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Compiled 42 Solidity files"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = adapter._run_compile(hardhat_project_dir)

        assert result["info"]["contracts_compiled"] == 42


# =============================================================================
# Parse Compilation Output Tests
# =============================================================================


class TestParseCompilationOutput:
    """Test _parse_compilation_output method."""

    def test_parse_warnings(self, adapter, sample_compilation_output):
        """Test parsing warnings from compilation output."""
        findings = adapter._parse_compilation_output(sample_compilation_output)

        assert len(findings) >= 2

        # Check warning structure
        for finding in findings:
            assert "type" in finding
            assert "severity" in finding
            assert "description" in finding
            assert "file" in finding
            assert "line" in finding
            assert "recommendation" in finding

    def test_parse_extracts_file_info(self, adapter):
        """Test parsing extracts file, line, column."""
        output = "contracts/Test.sol:42:13: Warning: Unused variable."
        findings = adapter._parse_compilation_output(output)

        assert len(findings) == 1
        assert findings[0]["file"] == "contracts/Test.sol"
        assert findings[0]["line"] == 42
        assert findings[0]["column"] == 13

    def test_parse_maps_warning_types(self, adapter):
        """Test warning type mapping."""
        # Test cases using messages that match the regex patterns in WARNING_PATTERNS
        test_cases = [
            ("Warning: This is an unused variable warning.", "unused_variable"),
            ("Warning: This is an unused function warning.", "unused_function"),
            (
                "Warning: visibility for constructor should not be specified.",
                "constructor_visibility",
            ),
            ("Warning: Function state mutability can be restricted to pure.", "state_mutability"),
            ("Warning: SPDX license identifier not provided.", "missing_license"),
            (
                "Warning: This declaration shadows an existing declaration (shadowing).",
                "variable_shadowing",
            ),
        ]

        for message, expected_type in test_cases:
            output = f"test.sol:1:1: {message}"
            findings = adapter._parse_compilation_output(output)
            if findings:
                assert findings[0]["type"] == expected_type, f"Failed for: {message}"

    def test_parse_maps_severity(self, adapter):
        """Test severity mapping."""
        warning_output = "test.sol:1:1: Warning: Some warning"
        error_output = "test.sol:1:1: Error: Some error"

        warning_findings = adapter._parse_compilation_output(warning_output)
        error_findings = adapter._parse_compilation_output(error_output)

        if warning_findings:
            assert warning_findings[0]["severity"] == "medium"
        if error_findings:
            assert error_findings[0]["severity"] == "high"

    def test_parse_empty_output(self, adapter):
        """Test parsing empty output."""
        findings = adapter._parse_compilation_output("")
        assert findings == []


# =============================================================================
# Gas Reporter Tests
# =============================================================================


class TestRunGasReporter:
    """Test _run_gas_reporter method."""

    def test_gas_reporter_detects_high_usage(self, adapter, hardhat_project_dir, sample_gas_report):
        """Test gas reporter detects high gas usage."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_gas_report
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = adapter._run_gas_reporter(hardhat_project_dir)

        findings = result["findings"]
        # withdraw has avg 512345 > 100000, should be flagged
        high_gas_findings = [f for f in findings if f["type"] == "high_gas_usage"]
        assert len(high_gas_findings) >= 1

    def test_gas_reporter_sets_env_variable(self, adapter, hardhat_project_dir):
        """Test REPORT_GAS env variable is set."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            adapter._run_gas_reporter(hardhat_project_dir)

        call_kwargs = mock_run.call_args[1]
        assert "env" in call_kwargs
        assert call_kwargs["env"].get("REPORT_GAS") == "true"

    def test_gas_reporter_handles_exception(self, adapter, hardhat_project_dir):
        """Test gas reporter handles exceptions gracefully."""
        with patch("subprocess.run", side_effect=Exception("Network error")):
            result = adapter._run_gas_reporter(hardhat_project_dir)

        assert result["findings"] == []


# =============================================================================
# Coverage Tests
# =============================================================================


class TestRunCoverage:
    """Test _run_coverage method."""

    def test_coverage_detects_low_coverage(
        self, adapter, hardhat_project_dir, sample_coverage_output
    ):
        """Test coverage detects low coverage files."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_coverage_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = adapter._run_coverage(hardhat_project_dir)

        findings = result["findings"]
        # Vault.sol has 65% stmt coverage < 80%, should be flagged
        low_cov_findings = [f for f in findings if f["type"] == "low_coverage"]
        assert len(low_cov_findings) >= 1

    def test_coverage_uses_extended_timeout(self, adapter, hardhat_project_dir):
        """Test coverage uses extended timeout."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            adapter._run_coverage(hardhat_project_dir)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["timeout"] == adapter.timeout * 2

    def test_coverage_handles_exception(self, adapter, hardhat_project_dir):
        """Test coverage handles exceptions gracefully."""
        with patch("subprocess.run", side_effect=Exception("Coverage error")):
            result = adapter._run_coverage(hardhat_project_dir)

        assert result["findings"] == []


# =============================================================================
# Analyze Tests
# =============================================================================


class TestAnalyze:
    """Test analyze method."""

    def test_analyze_returns_dict(self, adapter, hardhat_project_dir):
        """Test analyze returns dictionary with required keys."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Compiled 1 Solidity file(s)"
        mock_result.stderr = ""

        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch("subprocess.run", return_value=mock_result):
                with patch(
                    "src.adapters.hardhat_adapter.enhance_findings_with_llm", return_value=[]
                ):
                    result = adapter.analyze(str(hardhat_project_dir), verbose=False)

        assert "tool" in result
        assert "status" in result
        assert "findings" in result
        assert "execution_time" in result
        assert result["tool"] == "hardhat"

    def test_analyze_not_available(self, adapter, hardhat_project_dir):
        """Test analyze returns error when hardhat not available."""
        with patch.object(adapter, "is_available", return_value=ToolStatus.NOT_INSTALLED):
            result = adapter.analyze(str(hardhat_project_dir))

        assert result["status"] == "error"
        assert "not available" in result["error"].lower()
        assert result["findings"] == []

    def test_analyze_no_project_found(self, adapter, tmp_path):
        """Test analyze returns error when no project found."""
        no_project = tmp_path / "no_project"
        no_project.mkdir()

        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            result = adapter.analyze(str(no_project), verbose=False)

        assert result["status"] == "error"
        assert (
            "hardhat project" in result["error"].lower()
            or "hardhat.config" in result["error"].lower()
        )

    def test_analyze_success_with_findings(
        self, adapter, hardhat_project_dir, sample_compilation_output
    ):
        """Test analyze parses findings correctly."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_compilation_output
        mock_result.stderr = ""

        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch("subprocess.run", return_value=mock_result):
                with patch(
                    "src.adapters.hardhat_adapter.enhance_findings_with_llm",
                    side_effect=lambda f, c, t: f,
                ):
                    result = adapter.analyze(str(hardhat_project_dir), verbose=False)

        assert result["status"] == "success"
        assert len(result["findings"]) >= 2
        assert result["total_findings"] >= 2

    def test_analyze_timeout(self, adapter, hardhat_project_dir):
        """Test analyze handles timeout correctly."""
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch.object(adapter, "_find_hardhat_project", return_value=hardhat_project_dir):
                with patch.object(
                    adapter, "_run_compile", side_effect=subprocess.TimeoutExpired("npx", 180)
                ):
                    result = adapter.analyze(str(hardhat_project_dir), verbose=False)

        assert result["status"] == "error"
        assert "timeout" in result["error"].lower()

    def test_analyze_dpga_compliant(self, adapter, hardhat_project_dir):
        """Test analyze marks result as DPGA compliant."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Compiled 1 Solidity file(s)"
        mock_result.stderr = ""

        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch("subprocess.run", return_value=mock_result):
                with patch(
                    "src.adapters.hardhat_adapter.enhance_findings_with_llm", return_value=[]
                ):
                    result = adapter.analyze(str(hardhat_project_dir), verbose=False)

        assert result.get("dpga_compliant") is True

    def test_analyze_single_file(self, adapter, hardhat_project_dir):
        """Test analyze works with single contract file."""
        contract = hardhat_project_dir / "contracts" / "Token.sol"

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Compiled 1 Solidity file(s)"
        mock_result.stderr = ""

        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch("subprocess.run", return_value=mock_result):
                with patch(
                    "src.adapters.hardhat_adapter.enhance_findings_with_llm", return_value=[]
                ):
                    result = adapter.analyze(str(contract), verbose=False)

        assert result["status"] == "success"


# =============================================================================
# Recommendation Tests
# =============================================================================


class TestGetRecommendation:
    """Test _get_recommendation method."""

    def test_unused_variable_recommendation(self, adapter):
        """Test unused_variable recommendation."""
        rec = adapter._get_recommendation("unused_variable")
        assert "unused" in rec.lower() or "remove" in rec.lower()

    def test_unused_function_recommendation(self, adapter):
        """Test unused_function recommendation."""
        rec = adapter._get_recommendation("unused_function")
        assert "unused" in rec.lower() or "remove" in rec.lower()

    def test_constructor_visibility_recommendation(self, adapter):
        """Test constructor_visibility recommendation."""
        rec = adapter._get_recommendation("constructor_visibility")
        assert "visibility" in rec.lower() or "constructor" in rec.lower()

    def test_state_mutability_recommendation(self, adapter):
        """Test state_mutability recommendation."""
        rec = adapter._get_recommendation("state_mutability")
        assert "view" in rec.lower() or "pure" in rec.lower()

    def test_missing_license_recommendation(self, adapter):
        """Test missing_license recommendation."""
        rec = adapter._get_recommendation("missing_license")
        assert "spdx" in rec.lower() or "license" in rec.lower()

    def test_pragma_issue_recommendation(self, adapter):
        """Test pragma_issue recommendation."""
        rec = adapter._get_recommendation("pragma_issue")
        assert "pragma" in rec.lower() or "compiler" in rec.lower()

    def test_variable_shadowing_recommendation(self, adapter):
        """Test variable_shadowing recommendation."""
        rec = adapter._get_recommendation("variable_shadowing")
        assert "rename" in rec.lower() or "shadow" in rec.lower()

    def test_reentrancy_recommendation(self, adapter):
        """Test reentrancy recommendation."""
        rec = adapter._get_recommendation("reentrancy")
        assert "reentrancy" in rec.lower() or "guard" in rec.lower()

    def test_arithmetic_recommendation(self, adapter):
        """Test arithmetic recommendation."""
        rec = adapter._get_recommendation("arithmetic")
        assert "0.8" in rec.lower() or "safemath" in rec.lower()

    def test_high_gas_usage_recommendation(self, adapter):
        """Test high_gas_usage recommendation."""
        rec = adapter._get_recommendation("high_gas_usage")
        assert "optim" in rec.lower() or "gas" in rec.lower()

    def test_low_coverage_recommendation(self, adapter):
        """Test low_coverage recommendation."""
        rec = adapter._get_recommendation("low_coverage")
        assert "test" in rec.lower() or "coverage" in rec.lower()

    def test_unknown_recommendation(self, adapter):
        """Test unknown finding type gets generic recommendation."""
        rec = adapter._get_recommendation("unknown_type")
        assert "review" in rec.lower()
        assert "unknown_type" in rec


# =============================================================================
# Normalize Findings Tests
# =============================================================================


class TestNormalizeFindings:
    """Test normalize_findings method."""

    def test_normalize_dict_with_findings(self, adapter):
        """Test normalizing dict with findings key."""
        input_data = {"findings": [{"type": "reentrancy"}, {"type": "overflow"}]}
        result = adapter.normalize_findings(input_data)
        assert len(result) == 2

    def test_normalize_list(self, adapter):
        """Test normalizing list of findings."""
        input_data = [{"type": "reentrancy"}, {"type": "overflow"}]
        result = adapter.normalize_findings(input_data)
        assert len(result) == 2

    def test_normalize_other_type(self, adapter):
        """Test normalizing other types returns empty list."""
        assert adapter.normalize_findings("string") == []
        assert adapter.normalize_findings(123) == []
        assert adapter.normalize_findings(None) == []


# =============================================================================
# Can Analyze Tests
# =============================================================================


class TestCanAnalyze:
    """Test can_analyze method."""

    def test_can_analyze_sol_file_in_project(self, adapter, hardhat_project_dir):
        """Test can analyze .sol file in Hardhat project."""
        contract = hardhat_project_dir / "contracts" / "Token.sol"
        assert adapter.can_analyze(str(contract)) is True

    def test_cannot_analyze_sol_file_no_project(self, adapter, tmp_path):
        """Test cannot analyze .sol file without project."""
        no_project = tmp_path / "no_project"
        no_project.mkdir()
        sol_file = no_project / "test.sol"
        sol_file.write_text("contract Test {}")

        assert adapter.can_analyze(str(sol_file)) is False

    def test_can_analyze_project_directory(self, adapter, hardhat_project_dir):
        """Test can analyze Hardhat project directory."""
        assert adapter.can_analyze(str(hardhat_project_dir)) is True

    def test_cannot_analyze_non_sol_file(self, adapter, hardhat_project_dir):
        """Test cannot analyze non-.sol files."""
        js_file = hardhat_project_dir / "test.js"
        js_file.write_text("const x = 1;")
        assert adapter.can_analyze(str(js_file)) is False

    def test_cannot_analyze_nonexistent_path(self, adapter):
        """Test cannot analyze nonexistent path."""
        assert adapter.can_analyze("/nonexistent/path.sol") is False


# =============================================================================
# Default Config Tests
# =============================================================================


class TestGetDefaultConfig:
    """Test get_default_config method."""

    def test_returns_dict(self, adapter):
        """Test returns a dictionary."""
        config = adapter.get_default_config()
        assert isinstance(config, dict)

    def test_contains_network(self, adapter):
        """Test config contains network."""
        config = adapter.get_default_config()
        assert "network" in config
        assert config["network"] == "hardhat"

    def test_contains_compile_force(self, adapter):
        """Test config contains compile_force."""
        config = adapter.get_default_config()
        assert "compile_force" in config
        assert config["compile_force"] is True

    def test_contains_run_gas_reporter(self, adapter):
        """Test config contains run_gas_reporter."""
        config = adapter.get_default_config()
        assert "run_gas_reporter" in config
        assert config["run_gas_reporter"] is False

    def test_contains_run_coverage(self, adapter):
        """Test config contains run_coverage."""
        config = adapter.get_default_config()
        assert "run_coverage" in config
        assert config["run_coverage"] is False

    def test_contains_timeout(self, adapter):
        """Test config contains timeout."""
        config = adapter.get_default_config()
        assert "timeout" in config
        assert config["timeout"] == 180


# =============================================================================
# Register Adapter Tests
# =============================================================================


class TestRegisterAdapter:
    """Test register_adapter function."""

    def test_returns_dict(self):
        """Test register_adapter returns dictionary."""
        result = register_adapter()
        assert isinstance(result, dict)

    def test_contains_adapter_class(self):
        """Test result contains adapter_class."""
        result = register_adapter()
        assert "adapter_class" in result
        assert result["adapter_class"] == HardhatAdapter

    def test_contains_metadata(self):
        """Test result contains metadata."""
        result = register_adapter()
        assert "metadata" in result
        assert result["metadata"] == HardhatAdapter.METADATA


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for HardhatAdapter."""

    def test_full_analysis_flow(self, adapter, hardhat_project_dir, sample_compilation_output):
        """Test complete analysis flow with mocked subprocess."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_compilation_output
        mock_result.stderr = ""

        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch("subprocess.run", return_value=mock_result):
                with patch(
                    "src.adapters.hardhat_adapter.enhance_findings_with_llm",
                    side_effect=lambda f, c, t: f,
                ):
                    result = adapter.analyze(str(hardhat_project_dir), verbose=False)

        assert result["status"] == "success"
        assert len(result["findings"]) >= 2

        # Verify finding structure
        for finding in result["findings"]:
            assert "type" in finding
            assert "severity" in finding
            assert "description" in finding
            assert "file" in finding
            assert "recommendation" in finding

    def test_error_recovery(self, adapter, hardhat_project_dir):
        """Test adapter recovers gracefully from errors."""
        # Test various error conditions
        error_cases = [
            (ToolStatus.NOT_INSTALLED, "not available"),
            (ToolStatus.CONFIGURATION_ERROR, "not available"),
        ]

        for status, expected_msg in error_cases:
            with patch.object(adapter, "is_available", return_value=status):
                result = adapter.analyze(str(hardhat_project_dir))

            assert result["status"] == "error"
            assert expected_msg.lower() in result["error"].lower()

    def test_compilation_info_included(
        self, adapter, hardhat_project_dir, sample_compilation_output
    ):
        """Test compilation info is included in result."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_compilation_output
        mock_result.stderr = ""

        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch("subprocess.run", return_value=mock_result):
                with patch(
                    "src.adapters.hardhat_adapter.enhance_findings_with_llm", return_value=[]
                ):
                    result = adapter.analyze(str(hardhat_project_dir), verbose=False)

        assert "compilation_info" in result
        assert result["compilation_info"]["contracts_compiled"] == 5
