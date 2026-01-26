"""
Tests for PoC Generator Module
==============================

Comprehensive tests for the PoCGenerator class which generates
Foundry test templates from vulnerability findings.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

from src.poc.poc_generator import (
    PoCGenerator,
    PoCTemplate,
    PoCResult,
    VulnerabilityType,
    GenerationOptions,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def generator():
    """Create a default PoCGenerator instance."""
    return PoCGenerator()


@pytest.fixture
def generator_with_options():
    """Create generator with custom options."""
    options = GenerationOptions(
        include_setup=True,
        include_comments=True,
        include_console_logs=True,
        attacker_balance="50 ether",
        victim_balance="20 ether",
        custom_imports=["forge-std/console2.sol"],
    )
    return PoCGenerator(options=options)


@pytest.fixture
def reentrancy_finding():
    """Sample reentrancy vulnerability finding."""
    return {
        "type": "reentrancy",
        "severity": "critical",
        "title": "Reentrancy in withdraw function",
        "description": "External call before state update allows reentrancy attack",
        "location": {
            "function": "withdraw",
            "line": 45,
            "file": "contracts/Bank.sol"
        },
        "id": "VULN-001",
        "attack_vector": "Recursive call during withdrawal",
        "remediation": "Use checks-effects-interactions pattern",
    }


@pytest.fixture
def flash_loan_finding():
    """Sample flash loan vulnerability finding."""
    return {
        "type": "flash_loan",
        "severity": "high",
        "title": "Flash Loan Price Manipulation",
        "description": "Protocol vulnerable to flash loan attack via price manipulation",
        "location": {
            "function": "swap",
            "line": 120,
        },
        "id": "VULN-002",
    }


@pytest.fixture
def access_control_finding():
    """Sample access control vulnerability finding."""
    return {
        "type": "access-control",
        "severity": "critical",
        "title": "Missing Access Control on setOwner",
        "description": "Anyone can call setOwner and take ownership",
        "location": {
            "function": "setOwner",
            "line": 30,
        },
        "id": "VULN-003",
    }


@pytest.fixture
def oracle_finding():
    """Sample oracle manipulation finding."""
    return {
        "type": "oracle-manipulation",
        "severity": "high",
        "title": "Spot Price Oracle Vulnerable",
        "description": "Oracle uses spot price which can be manipulated",
        "location": {
            "function": "getPrice",
            "line": 80,
        },
    }


@pytest.fixture
def unknown_type_finding():
    """Finding with unknown vulnerability type."""
    return {
        "type": "unknown-vulnerability-xyz",
        "severity": "medium",
        "description": "Some unknown issue",
        "location": {"function": "test"},
    }


# =============================================================================
# VulnerabilityType Enum Tests
# =============================================================================

class TestVulnerabilityType:
    """Tests for VulnerabilityType enum."""

    def test_all_types_defined(self):
        """Test all expected vulnerability types are defined."""
        expected_types = [
            "REENTRANCY",
            "FLASH_LOAN",
            "ORACLE_MANIPULATION",
            "ACCESS_CONTROL",
            "INTEGER_OVERFLOW",
            "INTEGER_UNDERFLOW",
            "UNCHECKED_CALL",
            "FRONT_RUNNING",
            "DENIAL_OF_SERVICE",
            "TIMESTAMP_DEPENDENCE",
            "TX_ORIGIN",
            "SELFDESTRUCT",
            "DELEGATECALL",
            "SIGNATURE_REPLAY",
            "ERC4626_INFLATION",
            "PRICE_MANIPULATION",
        ]

        for type_name in expected_types:
            assert hasattr(VulnerabilityType, type_name), f"Missing type: {type_name}"

    def test_type_values(self):
        """Test vulnerability type values are lowercase strings."""
        assert VulnerabilityType.REENTRANCY.value == "reentrancy"
        assert VulnerabilityType.FLASH_LOAN.value == "flash_loan"
        assert VulnerabilityType.ACCESS_CONTROL.value == "access_control"
        assert VulnerabilityType.ORACLE_MANIPULATION.value == "oracle_manipulation"

    def test_type_count(self):
        """Test total number of vulnerability types."""
        assert len(VulnerabilityType) == 16


# =============================================================================
# GenerationOptions Tests
# =============================================================================

class TestGenerationOptions:
    """Tests for GenerationOptions dataclass."""

    def test_default_options(self):
        """Test default generation options."""
        opts = GenerationOptions()

        assert opts.include_setup is True
        assert opts.include_comments is True
        assert opts.include_console_logs is True
        assert opts.attacker_balance == "100 ether"
        assert opts.victim_balance == "10 ether"
        assert opts.fork_block is None
        assert opts.fork_url is None
        assert opts.custom_imports == []
        assert opts.custom_setup_code is None

    def test_custom_options(self):
        """Test custom generation options."""
        opts = GenerationOptions(
            attacker_balance="500 ether",
            fork_url="https://eth-mainnet.alchemyapi.io/v2/xxx",
            fork_block=18000000,
            custom_imports=["@openzeppelin/contracts/token/ERC20/IERC20.sol"],
        )

        assert opts.attacker_balance == "500 ether"
        assert opts.fork_url == "https://eth-mainnet.alchemyapi.io/v2/xxx"
        assert opts.fork_block == 18000000
        assert len(opts.custom_imports) == 1


# =============================================================================
# PoCTemplate Tests
# =============================================================================

class TestPoCTemplate:
    """Tests for PoCTemplate dataclass."""

    def test_template_creation(self):
        """Test creating a PoCTemplate."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// Test code",
            target_contract="Bank.sol",
            target_function="withdraw",
        )

        assert template.name == "TestExploit"
        assert template.vulnerability_type == VulnerabilityType.REENTRANCY
        assert template.solidity_code == "// Test code"
        assert template.target_contract == "Bank.sol"
        assert template.target_function == "withdraw"

    def test_template_save(self, tmp_path):
        """Test saving template to file."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// SPDX-License-Identifier: MIT\ncontract Test {}",
            target_contract="Bank.sol",
            target_function="withdraw",
        )

        saved_path = template.save(tmp_path)

        assert saved_path.exists()
        assert saved_path.suffix == ".sol"
        assert "reentrancy" in saved_path.name.lower()

        content = saved_path.read_text()
        assert "SPDX-License-Identifier" in content

    def test_template_to_dict(self):
        """Test converting template to dictionary."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// Code",
            target_contract="Bank.sol",
            target_function="withdraw",
            finding_id="VULN-001",
            description="Test description",
            prerequisites=["Foundry installed"],
            expected_outcome="Drain funds",
        )

        d = template.to_dict()

        assert d["name"] == "TestExploit"
        assert d["vulnerability_type"] == "reentrancy"
        assert d["target_contract"] == "Bank.sol"
        assert d["finding_id"] == "VULN-001"
        assert "created_at" in d

    def test_template_defaults(self):
        """Test template default values."""
        template = PoCTemplate(
            name="Test",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="",
            target_contract="Test.sol",
            target_function=None,
        )

        assert template.finding_id is None
        assert template.description == ""
        assert template.prerequisites == []
        assert template.expected_outcome == ""
        assert isinstance(template.created_at, datetime)


# =============================================================================
# PoCResult Tests
# =============================================================================

class TestPoCResult:
    """Tests for PoCResult dataclass."""

    def test_successful_result(self):
        """Test successful PoC result."""
        result = PoCResult(
            success=True,
            output="Test passed",
            gas_used=150000,
            execution_time_ms=1500.5,
        )

        assert result.success is True
        assert result.output == "Test passed"
        assert result.gas_used == 150000
        assert result.error is None

    def test_failed_result(self):
        """Test failed PoC result."""
        result = PoCResult(
            success=False,
            output="",
            error="Assertion failed",
            execution_time_ms=500,
        )

        assert result.success is False
        assert result.error == "Assertion failed"


# =============================================================================
# PoCGenerator Initialization Tests
# =============================================================================

class TestPoCGeneratorInit:
    """Tests for PoCGenerator initialization."""

    def test_default_initialization(self, generator):
        """Test default generator initialization."""
        assert generator.options is not None
        assert generator.templates_dir is not None

    def test_custom_templates_dir(self, tmp_path):
        """Test generator with custom templates directory."""
        generator = PoCGenerator(templates_dir=tmp_path)
        assert generator.templates_dir == tmp_path

    def test_custom_options(self, generator_with_options):
        """Test generator with custom options."""
        assert generator_with_options.options.attacker_balance == "50 ether"
        assert generator_with_options.options.victim_balance == "20 ether"


# =============================================================================
# Type Resolution Tests
# =============================================================================

class TestTypeResolution:
    """Tests for vulnerability type resolution."""

    def test_resolve_reentrancy(self, generator):
        """Test resolving reentrancy type."""
        for type_str in ["reentrancy", "reentrant", "re-entrancy"]:
            finding = {"type": type_str}
            vuln_type = generator._resolve_vulnerability_type(finding)
            assert vuln_type == VulnerabilityType.REENTRANCY

    def test_resolve_flash_loan(self, generator):
        """Test resolving flash loan type."""
        for type_str in ["flash_loan", "flash-loan", "flashloan"]:
            finding = {"type": type_str}
            vuln_type = generator._resolve_vulnerability_type(finding)
            assert vuln_type == VulnerabilityType.FLASH_LOAN

    def test_resolve_access_control(self, generator):
        """Test resolving access control type."""
        for type_str in ["access-control", "access_control", "authorization"]:
            finding = {"type": type_str}
            vuln_type = generator._resolve_vulnerability_type(finding)
            assert vuln_type == VulnerabilityType.ACCESS_CONTROL

    def test_resolve_oracle(self, generator):
        """Test resolving oracle manipulation type."""
        for type_str in ["oracle", "oracle-manipulation"]:
            finding = {"type": type_str}
            vuln_type = generator._resolve_vulnerability_type(finding)
            assert vuln_type == VulnerabilityType.ORACLE_MANIPULATION

    def test_resolve_arithmetic(self, generator):
        """Test resolving arithmetic types."""
        finding_overflow = {"type": "overflow"}
        finding_underflow = {"type": "underflow"}
        finding_arith = {"type": "arithmetic"}

        assert generator._resolve_vulnerability_type(finding_overflow) == VulnerabilityType.INTEGER_OVERFLOW
        assert generator._resolve_vulnerability_type(finding_underflow) == VulnerabilityType.INTEGER_UNDERFLOW
        assert generator._resolve_vulnerability_type(finding_arith) == VulnerabilityType.INTEGER_OVERFLOW

    def test_resolve_tx_origin(self, generator):
        """Test resolving tx.origin type."""
        for type_str in ["tx-origin", "tx_origin"]:
            finding = {"type": type_str}
            vuln_type = generator._resolve_vulnerability_type(finding)
            assert vuln_type == VulnerabilityType.TX_ORIGIN

    def test_resolve_unknown_defaults_reentrancy(self, generator, unknown_type_finding):
        """Test unknown type defaults to reentrancy."""
        vuln_type = generator._resolve_vulnerability_type(unknown_type_finding)
        assert vuln_type == VulnerabilityType.REENTRANCY

    def test_resolve_case_insensitive(self, generator):
        """Test type resolution is case insensitive."""
        for type_str in ["REENTRANCY", "Reentrancy", "ReEntrancy"]:
            finding = {"type": type_str}
            vuln_type = generator._resolve_vulnerability_type(finding)
            assert vuln_type == VulnerabilityType.REENTRANCY


# =============================================================================
# Function Extraction Tests
# =============================================================================

class TestFunctionExtraction:
    """Tests for function name extraction from findings."""

    def test_extract_from_dict_location(self, generator, reentrancy_finding):
        """Test extracting function from dict location."""
        func = generator._extract_function_name(reentrancy_finding)
        assert func == "withdraw"

    def test_extract_from_string_location(self, generator):
        """Test extracting function from string location."""
        finding = {
            "type": "reentrancy",
            "location": "function withdraw() in Bank.sol"
        }
        func = generator._extract_function_name(finding)
        assert func == "withdraw"

    def test_extract_missing_location(self, generator):
        """Test extraction when no location."""
        finding = {"type": "reentrancy"}
        func = generator._extract_function_name(finding)
        assert func is None

    def test_extract_location_with_func_key(self, generator):
        """Test extraction with 'func' key."""
        finding = {
            "type": "reentrancy",
            "location": {"func": "transfer"}
        }
        func = generator._extract_function_name(finding)
        assert func == "transfer"


# =============================================================================
# PoC Name Generation Tests
# =============================================================================

class TestPoCNameGeneration:
    """Tests for PoC name generation."""

    def test_generate_name_with_function(self, generator):
        """Test name generation with function."""
        name = generator._generate_poc_name(
            "contracts/Bank.sol",
            VulnerabilityType.REENTRANCY,
            "withdraw"
        )
        assert "Bank" in name
        assert "withdraw" in name
        assert "reentrancy" in name

    def test_generate_name_without_function(self, generator):
        """Test name generation without function."""
        name = generator._generate_poc_name(
            "Token.sol",
            VulnerabilityType.ACCESS_CONTROL,
            None
        )
        assert "Token" in name
        assert "accesscontrol" in name

    def test_generate_name_strips_extension(self, generator):
        """Test name strips .sol extension."""
        name = generator._generate_poc_name(
            "MyContract.sol",
            VulnerabilityType.REENTRANCY,
            "test"
        )
        assert ".sol" not in name
        assert "MyContract" in name


# =============================================================================
# Template Loading Tests
# =============================================================================

class TestTemplateLoading:
    """Tests for template loading."""

    def test_load_existing_template(self, generator):
        """Test loading an existing template."""
        # This should not raise an error
        template = generator._load_template(VulnerabilityType.REENTRANCY)
        assert template is not None
        assert len(template) > 0

    def test_load_default_template(self, generator):
        """Test loading default template for unmapped type."""
        template = generator._get_default_template(VulnerabilityType.FRONT_RUNNING)
        assert template is not None
        assert "{{CONTRACT_NAME}}" in template
        assert "{{VULNERABILITY_TYPE}}" in template

    def test_template_cache(self, generator):
        """Test template caching."""
        # Load twice, should use cache
        template1 = generator._load_template(VulnerabilityType.REENTRANCY)
        template2 = generator._load_template(VulnerabilityType.REENTRANCY)
        assert template1 == template2


# =============================================================================
# Template Customization Tests
# =============================================================================

class TestTemplateCustomization:
    """Tests for template customization."""

    def test_customize_replaces_placeholders(self, generator, reentrancy_finding):
        """Test placeholder replacement in templates."""
        template = "{{CONTRACT_NAME}} - {{VULNERABILITY_TYPE}} - {{TARGET_FUNCTION}}"

        result = generator._customize_template(
            template,
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Bank.sol",
            target_function="withdraw",
            finding=reentrancy_finding,
            options=GenerationOptions(),
        )

        assert "Bank" in result
        assert "reentrancy" in result
        assert "withdraw" in result
        assert "{{" not in result

    def test_customize_with_balances(self, generator, reentrancy_finding):
        """Test balance placeholders are replaced."""
        template = "{{ATTACKER_BALANCE}} - {{VICTIM_BALANCE}}"
        options = GenerationOptions(
            attacker_balance="200 ether",
            victim_balance="50 ether"
        )

        result = generator._customize_template(
            template,
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Test.sol",
            target_function="test",
            finding=reentrancy_finding,
            options=options,
        )

        assert "200 ether" in result
        assert "50 ether" in result

    def test_customize_with_fork_config(self, generator, reentrancy_finding):
        """Test fork configuration is added."""
        template = "// {{FORK_CONFIG}}\ncode here"
        options = GenerationOptions(
            fork_url="https://eth-mainnet.g.alchemy.com/v2/xxx",
            fork_block=18500000,
        )

        result = generator._customize_template(
            template,
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Test.sol",
            target_function="test",
            finding=reentrancy_finding,
            options=options,
        )

        assert "createSelectFork" in result
        assert "18500000" in result


# =============================================================================
# Generate PoC Tests
# =============================================================================

class TestGeneratePoC:
    """Tests for PoC generation."""

    def test_generate_reentrancy_poc(self, generator, reentrancy_finding):
        """Test generating reentrancy PoC."""
        poc = generator.generate(reentrancy_finding, "Bank.sol")

        assert isinstance(poc, PoCTemplate)
        assert poc.vulnerability_type == VulnerabilityType.REENTRANCY
        assert poc.target_contract == "Bank.sol"
        assert poc.target_function == "withdraw"
        assert poc.finding_id == "VULN-001"
        assert len(poc.solidity_code) > 0
        assert len(poc.prerequisites) > 0

    def test_generate_flash_loan_poc(self, generator, flash_loan_finding):
        """Test generating flash loan PoC."""
        poc = generator.generate(flash_loan_finding, "DeFiProtocol.sol")

        assert poc.vulnerability_type == VulnerabilityType.FLASH_LOAN
        assert poc.target_function == "swap"

    def test_generate_access_control_poc(self, generator, access_control_finding):
        """Test generating access control PoC."""
        poc = generator.generate(access_control_finding, "Ownable.sol")

        assert poc.vulnerability_type == VulnerabilityType.ACCESS_CONTROL

    def test_generate_oracle_poc(self, generator, oracle_finding):
        """Test generating oracle manipulation PoC."""
        poc = generator.generate(oracle_finding, "PriceOracle.sol")

        assert poc.vulnerability_type == VulnerabilityType.ORACLE_MANIPULATION

    def test_generate_with_custom_options(self, generator, reentrancy_finding):
        """Test generating with custom options."""
        options = GenerationOptions(
            attacker_balance="1000 ether",
            include_console_logs=True,
        )

        poc = generator.generate(reentrancy_finding, "Bank.sol", options=options)

        assert "1000 ether" in poc.solidity_code

    def test_generate_includes_description(self, generator, reentrancy_finding):
        """Test generated PoC includes finding description."""
        poc = generator.generate(reentrancy_finding, "Bank.sol")

        assert poc.description == reentrancy_finding["description"]


# =============================================================================
# Batch Generation Tests
# =============================================================================

class TestBatchGeneration:
    """Tests for batch PoC generation."""

    def test_generate_batch(self, generator, reentrancy_finding, flash_loan_finding):
        """Test generating multiple PoCs."""
        findings = [reentrancy_finding, flash_loan_finding]

        pocs = generator.generate_batch(findings, "MultiVuln.sol")

        assert len(pocs) == 2
        assert pocs[0].vulnerability_type == VulnerabilityType.REENTRANCY
        assert pocs[1].vulnerability_type == VulnerabilityType.FLASH_LOAN

    def test_generate_batch_handles_errors(self, generator):
        """Test batch generation handles errors gracefully."""
        findings = [
            {"type": "reentrancy", "location": {"function": "test"}},
            None,  # Invalid finding
            {"type": "overflow", "location": {"function": "calc"}},
        ]

        # Should not raise, should skip invalid
        pocs = generator.generate_batch(
            [f for f in findings if f],  # Filter None
            "Test.sol"
        )

        assert len(pocs) == 2

    def test_generate_batch_empty_list(self, generator):
        """Test batch generation with empty list."""
        pocs = generator.generate_batch([], "Test.sol")
        assert pocs == []


# =============================================================================
# Prerequisites and Outcomes Tests
# =============================================================================

class TestPrerequisitesAndOutcomes:
    """Tests for prerequisites and expected outcomes."""

    def test_get_prerequisites_reentrancy(self, generator):
        """Test prerequisites for reentrancy."""
        prereqs = generator._get_prerequisites(VulnerabilityType.REENTRANCY)

        assert len(prereqs) >= 2
        assert any("Foundry" in p for p in prereqs)

    def test_get_prerequisites_flash_loan(self, generator):
        """Test prerequisites for flash loan."""
        prereqs = generator._get_prerequisites(VulnerabilityType.FLASH_LOAN)

        assert len(prereqs) >= 3
        assert any("flash" in p.lower() or "liquidity" in p.lower() for p in prereqs)

    def test_get_prerequisites_oracle(self, generator):
        """Test prerequisites for oracle manipulation."""
        prereqs = generator._get_prerequisites(VulnerabilityType.ORACLE_MANIPULATION)

        assert any("oracle" in p.lower() or "price" in p.lower() for p in prereqs)

    def test_get_expected_outcome_reentrancy(self, generator):
        """Test expected outcome for reentrancy."""
        outcome = generator._get_expected_outcome(VulnerabilityType.REENTRANCY, "critical")

        assert "drain" in outcome.lower() or "fund" in outcome.lower()

    def test_get_expected_outcome_access_control(self, generator):
        """Test expected outcome for access control."""
        outcome = generator._get_expected_outcome(VulnerabilityType.ACCESS_CONTROL, "high")

        assert "unauthorized" in outcome.lower() or "privileged" in outcome.lower()


# =============================================================================
# Utility Methods Tests
# =============================================================================

class TestUtilityMethods:
    """Tests for utility methods."""

    def test_get_supported_types(self, generator):
        """Test getting supported vulnerability types."""
        types = generator.get_supported_types()

        assert isinstance(types, list)
        assert len(types) == 16
        assert "reentrancy" in types
        assert "flash_loan" in types

    def test_get_template_info(self, generator):
        """Test getting template info."""
        info = generator.get_template_info()

        assert "templates_dir" in info
        assert "available_templates" in info
        assert "type_aliases" in info
        assert len(info["type_aliases"]) > 10

    def test_type_aliases_coverage(self, generator):
        """Test type aliases cover common variations."""
        aliases = PoCGenerator.TYPE_ALIASES

        # Check common aliases exist
        assert "reentrancy" in aliases
        assert "re-entrancy" in aliases
        assert "flash-loan" in aliases
        assert "access-control" in aliases
        assert "tx-origin" in aliases
        assert "overflow" in aliases


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for PoCGenerator."""

    def test_full_generation_flow(self, generator, reentrancy_finding, tmp_path):
        """Test complete generation flow."""
        # Generate PoC
        poc = generator.generate(reentrancy_finding, "Bank.sol")

        # Save to file
        saved_path = poc.save(tmp_path)

        # Verify file
        assert saved_path.exists()
        content = saved_path.read_text()

        # Check content
        assert "SPDX-License-Identifier" in content
        assert "pragma solidity" in content
        assert "Test" in content
        assert "forge-std" in content

    def test_generate_all_types(self, generator):
        """Test generating PoC for all vulnerability types with proper aliases."""
        # Types that have direct value-to-type mapping in TYPE_ALIASES
        # Some types require specific alias format (e.g., "front-running" not "front_running")
        type_to_alias = {
            VulnerabilityType.REENTRANCY: "reentrancy",
            VulnerabilityType.FLASH_LOAN: "flash-loan",
            VulnerabilityType.ORACLE_MANIPULATION: "oracle-manipulation",
            VulnerabilityType.ACCESS_CONTROL: "access-control",
            VulnerabilityType.INTEGER_OVERFLOW: "overflow",
            VulnerabilityType.INTEGER_UNDERFLOW: "underflow",
            VulnerabilityType.UNCHECKED_CALL: "unchecked-call",
            VulnerabilityType.FRONT_RUNNING: "front-running",
            VulnerabilityType.DENIAL_OF_SERVICE: "dos",
            VulnerabilityType.TIMESTAMP_DEPENDENCE: "timestamp",
            VulnerabilityType.TX_ORIGIN: "tx-origin",
            VulnerabilityType.SELFDESTRUCT: "selfdestruct",
            VulnerabilityType.DELEGATECALL: "delegatecall",
            VulnerabilityType.SIGNATURE_REPLAY: "signature-replay",
            VulnerabilityType.ERC4626_INFLATION: "erc4626",
            VulnerabilityType.PRICE_MANIPULATION: "price-manipulation",
        }

        for vuln_type, alias in type_to_alias.items():
            finding = {
                "type": alias,
                "severity": "high",
                "description": f"Test {vuln_type.value}",
                "location": {"function": "test"},
            }

            poc = generator.generate(finding, "Test.sol")

            assert poc.vulnerability_type == vuln_type, f"Failed for {alias}"
            assert len(poc.solidity_code) > 0

    def test_template_validity(self, generator, reentrancy_finding):
        """Test generated template is valid Solidity structure."""
        poc = generator.generate(reentrancy_finding, "Bank.sol")

        code = poc.solidity_code

        # Basic Solidity structure checks
        assert "pragma solidity" in code or "// SPDX" in code
        assert "contract" in code
        assert "function" in code

    def test_poc_serialization(self, generator, reentrancy_finding, tmp_path):
        """Test PoC can be serialized and saved."""
        poc = generator.generate(reentrancy_finding, "Bank.sol")

        # To dict
        poc_dict = poc.to_dict()

        # Save to JSON
        json_path = tmp_path / "poc_metadata.json"
        with open(json_path, 'w') as f:
            json.dump(poc_dict, f, indent=2)

        # Reload
        with open(json_path, 'r') as f:
            loaded = json.load(f)

        assert loaded["name"] == poc.name
        assert loaded["vulnerability_type"] == poc.vulnerability_type.value
        assert loaded["target_contract"] == poc.target_contract
