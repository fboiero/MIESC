"""
Tests for PoC Generator Module
==============================

Comprehensive tests for the PoCGenerator class which generates
Foundry test templates from vulnerability findings.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

import miesc.poc.poc_generator as poc_generator_module
from miesc.poc.poc_generator import (
    GenerationOptions,
    PoCGenerator,
    PoCResult,
    PoCTemplate,
    VulnerabilityType,
    _normalize_type_label,
    _safe_contract_text,
    _safe_filename_part,
    _safe_import_path,
    _safe_isoformat,
    _safe_optional_text,
    _safe_text_list,
    _safe_vulnerability_type_value,
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
        "location": {"function": "withdraw", "line": 45, "file": "contracts/Bank.sol"},
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

        content = saved_path.read_text(encoding="utf-8")
        assert "SPDX-License-Identifier" in content

    @pytest.mark.parametrize("output_dir", [None, {"path": "bad"}, "  "])
    def test_template_save_rejects_malformed_output_dir(self, output_dir):
        """Malformed output dirs are rejected before Path coercion."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// SPDX-License-Identifier: MIT\ncontract Test {}",
            target_contract="Bank.sol",
            target_function="withdraw",
        )

        with pytest.raises(ValueError, match="Malformed PoC output directory"):
            template.save(output_dir)

    def test_template_save_sanitizes_filename_segments(self, tmp_path):
        """Template names should not create nested paths or unsafe filenames."""
        template = PoCTemplate(
            name="../Exploit:One",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// SPDX-License-Identifier: MIT\ncontract Test {}",
            target_contract="Bank.sol",
            target_function="withdraw",
        )

        saved_path = template.save(tmp_path)

        assert saved_path.parent == tmp_path
        assert saved_path.name == "PoC_reentrancy_ExploitOne.t.sol"

    def test_template_save_defaults_empty_safe_filename_segment(self, tmp_path):
        """Template names that sanitize to empty should use the filename fallback."""
        template = PoCTemplate(
            name="////",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// SPDX-License-Identifier: MIT\ncontract Test {}",
            target_contract="Bank.sol",
            target_function="withdraw",
        )

        saved_path = template.save(tmp_path)

        assert saved_path.name == "PoC_reentrancy_template.t.sol"

    def test_template_save_bounds_overlong_name_segment(self, tmp_path):
        """Overlong template names should be bounded before file creation."""
        template = PoCTemplate(
            name="Exploit" + ("A" * 500),
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// SPDX-License-Identifier: MIT\ncontract Test {}",
            target_contract="Bank.sol",
            target_function="withdraw",
        )

        saved_path = template.save(tmp_path)

        assert saved_path.parent == tmp_path
        assert len(saved_path.name) < 120
        assert saved_path.name.endswith(".t.sol")

    def test_template_save_rejects_output_dir_with_null_byte(self):
        """Malformed path text is rejected before filesystem calls."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// SPDX-License-Identifier: MIT\ncontract Test {}",
            target_contract="Bank.sol",
            target_function="withdraw",
        )

        with pytest.raises(ValueError, match="Malformed PoC output directory"):
            template.save("bad\x00dir")

    def test_template_save_rejects_path_object_with_control_chars(self):
        """Path objects with control chars should be rejected before filesystem calls."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// SPDX-License-Identifier: MIT\ncontract Test {}",
            target_contract="Bank.sol",
            target_function="withdraw",
        )

        with pytest.raises(ValueError, match="Malformed PoC output directory"):
            template.save(Path("bad\ndir"))

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

    def test_template_to_dict_defaults_malformed_text_fields(self):
        """Malformed template fields should not leak container reprs into metadata."""
        template = PoCTemplate(
            name=["TestExploit"],
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// Code",
            target_contract={"path": "Bank.sol"},
            target_function=["withdraw"],
            finding_id={"id": "VULN-001"},
            description=["Test description"],
            prerequisites=["Foundry installed", {"bad": "entry"}],
            expected_outcome={"outcome": "Drain funds"},
        )

        d = template.to_dict()

        assert d["name"] == "template"
        assert d["target_contract"] == ""
        assert d["target_function"] is None
        assert d["finding_id"] is None
        assert d["description"] == ""
        assert d["prerequisites"] == ["Foundry installed"]
        assert d["expected_outcome"] == ""

    def test_template_to_dict_rejects_control_chars_in_description_and_expected_outcome(
        self,
    ):
        """String metadata with control chars should not be exported."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// Code",
            target_contract="Bank.sol",
            target_function=None,
            description="bad\ndescription",
            expected_outcome="bad\x7foutcome",
        )

        d = template.to_dict()

        assert d["description"] == ""
        assert d["expected_outcome"] == ""

    def test_template_to_dict_bounds_large_description_fields(self):
        """Huge metadata fields should not balloon serialized PoC output."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// Code",
            target_contract="Bank.sol",
            target_function=None,
            description="x" * (poc_generator_module._TEXT_FIELD_LIMIT + 1),
            expected_outcome="y" * (poc_generator_module._TEXT_FIELD_LIMIT + 1),
            prerequisites=[f"step-{i}" for i in range(poc_generator_module._LIST_FIELD_LIMIT + 25)],
        )

        d = template.to_dict()

        assert d["description"] == ""
        assert d["expected_outcome"] == ""
        assert len(d["prerequisites"]) == poc_generator_module._LIST_FIELD_LIMIT

    def test_template_to_dict_strips_and_skips_blank_prerequisites(self):
        """Blank prerequisite entries should not be exported."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// Code",
            target_contract="Bank.sol",
            target_function=None,
            prerequisites=[" Foundry installed ", "  ", "\n", "anvil ready"],
        )

        d = template.to_dict()

        assert d["prerequisites"] == ["Foundry installed", "anvil ready"]

    def test_template_to_dict_defaults_malformed_created_at(self):
        """Malformed template timestamps should not break metadata export."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// Code",
            target_contract="Bank.sol",
            target_function="withdraw",
        )
        template.created_at = ["2026-01-01"]

        d = template.to_dict()

        assert d["created_at"] == ""

    def test_template_to_dict_defaults_malformed_vulnerability_type(self):
        """Malformed vulnerability type metadata should not break export."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// Code",
            target_contract="Bank.sol",
            target_function="withdraw",
        )
        template.vulnerability_type = {"type": "reentrancy"}

        d = template.to_dict()

        assert d["vulnerability_type"] == "unknown"

    def test_template_save_defaults_malformed_vulnerability_type(self, tmp_path):
        """Malformed vulnerability types should still produce a safe filename."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code="// Code",
            target_contract="Bank.sol",
            target_function="withdraw",
        )
        template.vulnerability_type = {"type": "reentrancy"}

        saved_path = template.save(tmp_path)

        assert saved_path.name == "PoC_unknown_TestExploit.t.sol"

    def test_template_save_defaults_malformed_solidity_code(self, tmp_path):
        """Malformed Solidity payloads should not leak reprs into saved files."""
        template = PoCTemplate(
            name="TestExploit",
            vulnerability_type=VulnerabilityType.REENTRANCY,
            solidity_code={"code": "contract Exploit {}"},
            target_contract="Bank.sol",
            target_function=None,
        )

        saved_path = template.save(tmp_path)

        assert saved_path.read_text(encoding="utf-8") == ""

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

    @pytest.mark.parametrize("templates_dir", [None, {"path": "bad"}, ["templates"], "  "])
    def test_malformed_templates_dir_uses_default(self, templates_dir, caplog):
        """Malformed templates_dir values should not become Path inputs."""
        with caplog.at_level("WARNING"):
            generator = PoCGenerator(templates_dir=templates_dir)

        assert generator.templates_dir == PoCGenerator.TEMPLATES_DIR
        if templates_dir is not None:
            assert "Ignoring malformed templates_dir for PoC generator" in caplog.text

    @pytest.mark.parametrize("templates_dir", ["bad\x00path", "bad\u2028path", "bad\npath"])
    def test_malformed_templates_dir_rejects_control_chars_and_null_bytes(
        self, templates_dir, caplog
    ):
        """Template directory text should reject null/control/unicode separators."""
        with caplog.at_level("WARNING"):
            generator = PoCGenerator(templates_dir=templates_dir)

        assert generator.templates_dir == PoCGenerator.TEMPLATES_DIR
        assert "Ignoring malformed templates_dir for PoC generator" in caplog.text

    @pytest.mark.parametrize("options", [{"attacker_balance": "1 ether"}, ["bad"], object()])
    def test_malformed_init_options_use_default(self, options, caplog):
        """Malformed init options should be replaced with GenerationOptions."""
        with caplog.at_level("WARNING"):
            generator = PoCGenerator(options=options)

        assert isinstance(generator.options, GenerationOptions)
        assert generator.options.attacker_balance == "100 ether"
        assert "Ignoring malformed PoC generation options" in caplog.text


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

    def test_resolve_rejects_overlong_alias_like_type(self, generator):
        """Overlong finding types should not be partially matched."""
        finding = {"type": "reentrancy" + ("x" * 121)}

        assert generator._resolve_vulnerability_type(finding) == VulnerabilityType.REENTRANCY

    @pytest.mark.parametrize("finding", [None, ["type", "reentrancy"], "reentrancy"])
    def test_resolve_rejects_malformed_finding_container(self, generator, finding):
        """Malformed type resolution input should default safely."""
        assert generator._resolve_vulnerability_type(finding) == VulnerabilityType.REENTRANCY

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

        assert (
            generator._resolve_vulnerability_type(finding_overflow)
            == VulnerabilityType.INTEGER_OVERFLOW
        )
        assert (
            generator._resolve_vulnerability_type(finding_underflow)
            == VulnerabilityType.INTEGER_UNDERFLOW
        )
        assert (
            generator._resolve_vulnerability_type(finding_arith)
            == VulnerabilityType.INTEGER_OVERFLOW
        )

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

    def test_resolve_resets_malformed_type_aliases_state(self, generator):
        """Malformed alias state should not crash type resolution."""
        generator.TYPE_ALIASES = ["reentrancy"]

        assert generator._resolve_vulnerability_type({"type": "reentrancy"}) == (
            VulnerabilityType.REENTRANCY
        )

    def test_resolve_ignores_hostile_finding_get_accessor(self, generator):
        """Type resolution should not call custom dict.get implementations."""

        class ExplodingGetDict(dict):
            def get(self, *_args, **_kwargs):  # pragma: no cover - must not be called
                raise AssertionError("get should not be called")

        finding = ExplodingGetDict(type="flash-loan")

        assert generator._resolve_vulnerability_type(finding) == VulnerabilityType.FLASH_LOAN

    def test_resolve_non_string_type_defaults_reentrancy(self, generator):
        """Test non-string finding type defaults to reentrancy."""
        for type_value in [None, ["reentrancy"], {"name": "reentrancy"}]:
            vuln_type = generator._resolve_vulnerability_type({"type": type_value})
            assert vuln_type == VulnerabilityType.REENTRANCY

    def test_resolve_case_insensitive(self, generator):
        """Test type resolution is case insensitive."""
        for type_str in ["REENTRANCY", "Reentrancy", "ReEntrancy"]:
            finding = {"type": type_str}
            vuln_type = generator._resolve_vulnerability_type(finding)
            assert vuln_type == VulnerabilityType.REENTRANCY

    @pytest.mark.parametrize(
        ("type_str", "expected"),
        [
            ("Agentic Invariant Access Control", VulnerabilityType.ACCESS_CONTROL),
            ("agentic_invariant_access_control", VulnerabilityType.ACCESS_CONTROL),
            ("privilegedAccessControl", VulnerabilityType.ACCESS_CONTROL),
            ("Accounting Invariant", VulnerabilityType.ERC4626_INFLATION),
            ("assetAccountingConservation", VulnerabilityType.ERC4626_INFLATION),
            ("capBoundaryInvariant", VulnerabilityType.INTEGER_OVERFLOW),
            ("counterexampleValidation", VulnerabilityType.REENTRANCY),
            ("Counterexample Found", VulnerabilityType.REENTRANCY),
            ("SWC-101", VulnerabilityType.INTEGER_OVERFLOW),
            ("swc 104", VulnerabilityType.UNCHECKED_CALL),
            ("SWC_105", VulnerabilityType.ACCESS_CONTROL),
            ("SWC-107", VulnerabilityType.REENTRANCY),
            ("swc 115", VulnerabilityType.TX_ORIGIN),
        ],
    )
    def test_resolve_agentic_and_swc_aliases(self, generator, type_str, expected):
        """Agentic and SWC labels should map deterministically to PoC types."""
        assert generator._resolve_vulnerability_type({"type": type_str}) == expected

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("flash_loan", "flash-loan"),
            ("Agentic Invariant Access Control", "agentic-invariant-access-control"),
            ("privilegedAccessControl", "privileged-access-control"),
            ("SWC_107", "swc-107"),
            ("bad\nlabel", ""),
        ],
    )
    def test_normalize_type_label(self, value, expected):
        """Type label normalization should be deterministic and bounded."""
        assert _normalize_type_label(value) == expected


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
        finding = {"type": "reentrancy", "location": "function withdraw() in Bank.sol"}
        func = generator._extract_function_name(finding)
        assert func == "withdraw"

    def test_extract_missing_location(self, generator):
        """Test extraction when no location."""
        finding = {"type": "reentrancy"}
        func = generator._extract_function_name(finding)
        assert func is None

    def test_extract_from_string_location_without_function_name(self, generator):
        """Test extraction from string location without a function signature."""
        finding = {"type": "reentrancy", "location": "contracts/Bank.sol:45"}
        func = generator._extract_function_name(finding)
        assert func is None

    def test_extract_location_with_func_key(self, generator):
        """Test extraction with 'func' key."""
        finding = {"type": "reentrancy", "location": {"func": "transfer"}}
        func = generator._extract_function_name(finding)
        assert func == "transfer"

    def test_extract_ignores_hostile_location_get_accessor(self, generator):
        """Function extraction should not call custom location.get implementations."""

        class ExplodingGetDict(dict):
            def get(self, *_args, **_kwargs):  # pragma: no cover - must not be called
                raise AssertionError("get should not be called")

        finding = ExplodingGetDict(location=ExplodingGetDict(function="withdraw"))

        assert generator._extract_function_name(finding) == "withdraw"

    def test_extract_ignores_non_string_function_name(self, generator):
        """Test extraction ignores non-string function values."""
        for location in [
            {"function": ["withdraw"]},
            {"func": {"name": "withdraw"}},
        ]:
            func = generator._extract_function_name({"type": "reentrancy", "location": location})
            assert func is None

    def test_extract_strips_and_rejects_control_chars(self, generator):
        """Test extraction trims clean function names and rejects control chars."""
        clean = generator._extract_function_name(
            {"type": "reentrancy", "location": {"function": " withdraw "}}
        )
        malformed = generator._extract_function_name(
            {"type": "reentrancy", "location": {"function": "withdraw\nshadow"}}
        )

        assert clean == "withdraw"
        assert malformed is None

    @pytest.mark.parametrize(
        "function_name",
        ["123bad", "withdraw-hack", "withdraw()", "with space"],
    )
    def test_extract_rejects_non_solidity_identifiers(self, generator, function_name):
        """Function extraction should reject invalid Solidity identifiers."""
        assert (
            generator._extract_function_name(
                {"type": "reentrancy", "location": {"function": function_name}}
            )
            is None
        )

    def test_extract_rejects_malformed_string_location_boundaries(self, generator):
        """String locations with unsafe names or oversized text are ignored."""
        assert generator._extract_function_name({"location": "function 123bad()"}) is None
        assert generator._extract_function_name({"location": "function withdraw\n()"}) is None
        assert (
            generator._extract_function_name({"location": "function withdraw() " + ("x" * 2001)})
            is None
        )

    def test_safe_contract_text_strips_and_rejects_control_chars(self):
        assert _safe_contract_text("  contracts/Bank.sol  ") == "contracts/Bank.sol"
        assert _safe_contract_text("Bank\n.sol") == ""

    def test_safe_filename_part_rejects_control_chars(self):
        assert _safe_filename_part("  valid_name-1  ") == "valid_name-1"
        assert _safe_filename_part("bad\nname") == "template"

    def test_safe_optional_text_and_text_list_reject_control_chars(self):
        assert _safe_optional_text("  notes  ") == "notes"
        assert _safe_optional_text("bad\nnotes") is None
        assert _safe_text_list([" a ", "bad\nx", "b"]) == ["a", "b"]

    def test_finding_text_field_and_function_name_helpers_strip_and_reject_control_chars(
        self, generator
    ):
        finding = {"title": "  Withdraw funds  ", "location": {"function": "  withdraw  "}}
        assert generator._finding_text_field(finding, "title", default=None) == "Withdraw funds"
        assert generator._finding_text_field({"title": "bad\ntext"}, "title", default=None) is None
        assert generator._extract_function_name(finding) == "withdraw"
        assert generator._extract_function_name({"location": {"function": "bad\nname"}}) is None

    def test_safe_import_path_rejects_control_chars(self):
        assert _safe_import_path("forge-std/console.sol") is True
        assert _safe_import_path("forge-std/conso\x7fle.sol") is False

    @pytest.mark.parametrize(
        "path",
        [
            "README.md",
            "package.json",
            "contracts/I.sol.txt",
            "bad path.sol",
            "bad{path}.sol",
            "bad?x.sol",
            "bad#x.sol",
            "bad`x.sol",
        ],
    )
    def test_safe_import_path_rejects_non_solidity_and_non_allowlisted_chars(self, path):
        assert _safe_import_path(path) is False

    def test_safe_isoformat_and_vulnerability_type_value_sanitize_text(self):
        class FakeTimestamp:
            def isoformat(self):
                return " 2026-07-06T12:13:00 "

        class BadTimestamp:
            def isoformat(self):
                return "2026-07-06\n12:13:00"

        class FakeType:
            value = "  custom_type  "

        class BadType:
            value = "custom\n_type"

        assert _safe_isoformat(FakeTimestamp()) == "2026-07-06T12:13:00"
        assert _safe_isoformat(BadTimestamp()) == ""
        assert _safe_vulnerability_type_value(VulnerabilityType.REENTRANCY) == "reentrancy"
        assert _safe_vulnerability_type_value(FakeType()) == "custom_type"
        assert _safe_vulnerability_type_value(BadType()) == "unknown"


# =============================================================================
# PoC Name Generation Tests
# =============================================================================


class TestPoCNameGeneration:
    """Tests for PoC name generation."""

    def test_generate_name_with_function(self, generator):
        """Test name generation with function."""
        name = generator._generate_poc_name(
            "contracts/Bank.sol", VulnerabilityType.REENTRANCY, "withdraw"
        )
        assert "Bank" in name
        assert "withdraw" in name
        assert "reentrancy" in name

    def test_generate_name_without_function(self, generator):
        """Test name generation without function."""
        name = generator._generate_poc_name("Token.sol", VulnerabilityType.ACCESS_CONTROL, None)
        assert "Token" in name
        assert "accesscontrol" in name

    def test_generate_name_strips_extension(self, generator):
        """Test name strips .sol extension."""
        name = generator._generate_poc_name("MyContract.sol", VulnerabilityType.REENTRANCY, "test")
        assert ".sol" not in name
        assert "MyContract" in name

    def test_generate_name_defaults_malformed_target_contract(self, generator):
        """Malformed contract/function names should not leak reprs into PoC names."""
        name = generator._generate_poc_name(
            {"path": "Bank.sol"},
            VulnerabilityType.REENTRANCY,
            "../withdraw()",
        )

        assert name == "contract_withdraw()_reentrancy"
        assert "{'path'" not in name

    def test_generate_name_defaults_malformed_vulnerability_type(self, generator):
        """Malformed vulnerability types should not crash PoC name generation."""
        name = generator._generate_poc_name("Bank.sol", {"type": "reentrancy"}, "withdraw")

        assert name == "Bank_withdraw_unknown"


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

    def test_mapped_template_files_exist(self, generator):
        """Every mapped template should exist on disk."""
        for template_name in set(generator.TEMPLATE_MAP.values()):
            assert (generator.templates_dir / template_name).is_file(), template_name

    @pytest.mark.parametrize(
        ("vuln_type", "template_name"),
        sorted(PoCGenerator.TEMPLATE_MAP.items(), key=lambda item: item[0].value),
    )
    def test_mapped_types_load_disk_templates(self, generator, vuln_type, template_name):
        """Mapped vulnerability types should not silently use embedded fallback content."""
        template = generator._load_template(vuln_type)

        assert template == (generator.templates_dir / template_name).read_text(encoding="utf-8")

    @pytest.mark.parametrize(
        "vuln_type",
        [
            VulnerabilityType.FRONT_RUNNING,
            VulnerabilityType.DENIAL_OF_SERVICE,
            VulnerabilityType.TIMESTAMP_DEPENDENCE,
            VulnerabilityType.SIGNATURE_REPLAY,
            VulnerabilityType.ERC4626_INFLATION,
        ],
    )
    def test_generic_mapped_types_are_explicit(self, generator, vuln_type):
        """Generic PoC coverage should be explicit in TEMPLATE_MAP, not accidental fallback."""
        assert generator.TEMPLATE_MAP[vuln_type] == "generic.t.sol"
        assert generator._load_template(vuln_type) == (
            generator.templates_dir / "generic.t.sol"
        ).read_text(encoding="utf-8")

    def test_price_manipulation_reuses_oracle_template(self, generator):
        """Price manipulation should use the oracle-specific template family."""
        assert generator.TEMPLATE_MAP[VulnerabilityType.PRICE_MANIPULATION] == (
            "oracle_manipulation.t.sol"
        )
        assert "Oracle" in generator._load_template(VulnerabilityType.PRICE_MANIPULATION)

    def test_template_cache(self, generator):
        """Test template caching."""
        # Load twice, should use cache
        template1 = generator._load_template(VulnerabilityType.REENTRANCY)
        template2 = generator._load_template(VulnerabilityType.REENTRANCY)
        assert template1 == template2

    def test_load_template_uses_utf8(self, tmp_path):
        """Test loading template files with explicit UTF-8 encoding."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        template_path = template_dir / "reentrancy.t.sol"
        template_path.write_text("// cafe accented: café\n", encoding="utf-8")

        generator = PoCGenerator(templates_dir=template_dir)

        assert "café" in generator._load_template(VulnerabilityType.REENTRANCY)

    def test_load_template_resets_malformed_cache_state(self, generator):
        """Malformed template cache state should be recreated before lookup."""
        generator._template_cache = ["bad"]

        template = generator._load_template(VulnerabilityType.REENTRANCY)

        assert isinstance(generator._template_cache, dict)
        assert "contract" in template

    def test_load_template_resets_malformed_templates_dir_state(self, generator, caplog):
        """Mutated templates_dir state should fall back to the default template path."""
        generator.templates_dir = {"path": "bad"}

        with caplog.at_level("WARNING"):
            template = generator._load_template(VulnerabilityType.REENTRANCY)

        assert generator.templates_dir == PoCGenerator.TEMPLATES_DIR
        assert "Resetting malformed PoC templates_dir state" in caplog.text
        assert "contract" in template

    def test_templates_dir_file_path_falls_back_to_default(self, tmp_path, caplog):
        """A file path should not be treated as a templates directory."""
        template_file = tmp_path / "not-a-dir"
        template_file.write_text("bad", encoding="utf-8")

        with caplog.at_level("WARNING"):
            generator = PoCGenerator(templates_dir=template_file)

        assert generator.templates_dir == PoCGenerator.TEMPLATES_DIR
        assert "Ignoring malformed templates_dir for PoC generator" in caplog.text

    def test_templates_dir_missing_path_falls_back_to_default(self, tmp_path, caplog):
        """A missing custom templates directory should not become active state."""
        missing_dir = tmp_path / "missing"

        with caplog.at_level("WARNING"):
            generator = PoCGenerator(templates_dir=missing_dir)

        assert generator.templates_dir == PoCGenerator.TEMPLATES_DIR
        assert "Ignoring malformed templates_dir for PoC generator" in caplog.text

    def test_load_template_ignores_malformed_template_map_entry(self, generator, caplog):
        """Malformed template map entries should fall back to generic templates."""
        original = generator.TEMPLATE_MAP[VulnerabilityType.REENTRANCY]
        generator.TEMPLATE_MAP[VulnerabilityType.REENTRANCY] = "../bad.t.sol"
        try:
            with caplog.at_level("WARNING"):
                template = generator._load_template(VulnerabilityType.REENTRANCY)
        finally:
            generator.TEMPLATE_MAP[VulnerabilityType.REENTRANCY] = original

        assert "Ignoring malformed PoC template name" in caplog.text
        assert "contract" in template

    def test_load_template_ignores_non_solidity_template_map_entry(self, generator, caplog):
        """Template map entries must remain Solidity template paths."""
        original = generator.TEMPLATE_MAP[VulnerabilityType.REENTRANCY]
        generator.TEMPLATE_MAP[VulnerabilityType.REENTRANCY] = "README.md"
        try:
            with caplog.at_level("WARNING"):
                template = generator._load_template(VulnerabilityType.REENTRANCY)
        finally:
            generator.TEMPLATE_MAP[VulnerabilityType.REENTRANCY] = original

        assert "Ignoring malformed PoC template name" in caplog.text
        assert "contract" in template

    def test_load_template_ignores_cached_non_string_template_body(self, generator):
        """Malformed cache entries should not bypass template loading fallback."""
        generator._template_cache = {"reentrancy.t.sol": {"body": "bad"}}

        template = generator._load_template(VulnerabilityType.REENTRANCY)

        assert isinstance(template, str)
        assert "{'body': 'bad'}" not in template
        assert isinstance(generator._template_cache["reentrancy.t.sol"], str)

    def test_load_template_rejects_oversized_cached_template_body(self, generator):
        """Oversized cached template bodies should not bypass size limits."""
        generator._template_cache = {
            "reentrancy.t.sol": "x" * (poc_generator_module._TEMPLATE_BODY_LIMIT + 1)
        }

        template = generator._load_template(VulnerabilityType.REENTRANCY)

        assert isinstance(template, str)
        assert len(template) <= poc_generator_module._TEMPLATE_BODY_LIMIT

    def test_load_template_rejects_oversized_template_file(self, tmp_path, caplog):
        """Oversized template files should fall back to embedded defaults."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "reentrancy.t.sol").write_text(
            "x" * (poc_generator_module._TEMPLATE_BODY_LIMIT + 1),
            encoding="utf-8",
        )
        generator = PoCGenerator(templates_dir=template_dir)

        with caplog.at_level("WARNING"):
            template = generator._load_template(VulnerabilityType.REENTRANCY)

        assert "{{CONTRACT_NAME}}" in template
        assert "Falling back from unreadable PoC template" in caplog.text

    def test_load_template_falls_back_on_unicode_decode_error(self, tmp_path, caplog):
        """Unreadable UTF-8 templates should fall back to embedded defaults."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "reentrancy.t.sol").write_bytes(b"\xff\xfe\xfd")
        generator = PoCGenerator(templates_dir=template_dir)

        with caplog.at_level("WARNING"):
            template = generator._load_template(VulnerabilityType.REENTRANCY)

        assert "{{CONTRACT_NAME}}" in template
        assert "Falling back from unreadable PoC template" in caplog.text

    def test_load_template_resets_malformed_template_map_state(self, generator):
        """Malformed template-map state should fall back to generic template names."""
        generator.TEMPLATE_MAP = ["bad"]

        template = generator._load_template(VulnerabilityType.REENTRANCY)

        assert isinstance(template, str)
        assert "contract" in template


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
        options = GenerationOptions(attacker_balance="200 ether", victim_balance="50 ether")

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

    def test_customize_uses_default_for_malformed_template_body(
        self, generator, reentrancy_finding, caplog
    ):
        """Malformed template bodies should use the embedded default template."""
        with caplog.at_level("WARNING"):
            result = generator._customize_template(
                {"template": "{{CONTRACT_NAME}}"},
                vuln_type=VulnerabilityType.REENTRANCY,
                target_contract="Bank.sol",
                target_function="withdraw",
                finding=reentrancy_finding,
                options=GenerationOptions(),
            )

        assert "Bank Exploit PoC" in result
        assert "Using default template for malformed PoC template body" in caplog.text

    def test_customize_defaults_malformed_vulnerability_type(self, generator, reentrancy_finding):
        """Malformed vulnerability types should not leak reprs into test names."""
        result = generator._customize_template(
            "{{TEST_NAME}} {{VULNERABILITY_TYPE}}",
            vuln_type={"type": "reentrancy"},
            target_contract="Bank.sol",
            target_function="withdraw",
            finding=reentrancy_finding,
            options=GenerationOptions(),
        )

        assert result == "test_exploit_unknown unknown"

    def test_customize_resets_malformed_options_state(self, generator, reentrancy_finding, caplog):
        """Mutated generator options state should be reset before template use."""
        generator.options = {"attacker_balance": "1 ether"}

        with caplog.at_level("WARNING"):
            result = generator._customize_template(
                "{{ATTACKER_BALANCE}}",
                vuln_type=VulnerabilityType.REENTRANCY,
                target_contract="Bank.sol",
                target_function="withdraw",
                finding=reentrancy_finding,
                options=None,
            )

        assert result == "100 ether"
        assert "Resetting malformed PoC generator options state" in caplog.text

    def test_option_text_field_rejects_solidity_literal_injection(self, generator):
        """Balance fields should reject quote/semicolon Solidity injection."""
        options = GenerationOptions(attacker_balance='1 ether"); evil(); //')

        assert generator._option_text_field(options, "attacker_balance", "100 ether") == (
            "100 ether"
        )

    def test_finding_text_field_rejects_malformed_key(self, generator):
        """Malformed lookup keys should not hit dict.get with unhashable values."""
        assert generator._finding_text_field({"description": "ok"}, ["description"], "") == ""

    def test_custom_import_lines_deduplicates_and_rejects_long_paths(self, generator):
        """Custom imports should be normalized and deduplicated before emission."""
        options = GenerationOptions(
            custom_imports=[
                " forge-std/console.sol ",
                "forge-std/console.sol",
                "forge-std/console2.sol",
                "x" * 121,
            ]
        )

        assert generator._custom_import_lines(options) == (
            'import "forge-std/console.sol";\nimport "forge-std/console2.sol";'
        )

    @pytest.mark.parametrize(
        "custom_import",
        [
            'forge-std/Test.sol"; import "evil.sol',
            "forge-std/Test.sol; import evil",
            "forge-std/Test.sol\u2028evil",
        ],
    )
    def test_custom_import_lines_rejects_solidity_import_injection(self, generator, custom_import):
        """Import paths should not be able to break out of generated import strings."""
        options = GenerationOptions(custom_imports=["forge-std/Test.sol", custom_import])

        assert generator._custom_import_lines(options) == 'import "forge-std/Test.sol";'

    def test_custom_import_lines_handles_hostile_options_accessor(self, generator):
        """Hostile custom_imports accessors should not break import generation."""

        class HostileOptions(GenerationOptions):
            def __getattribute__(self, name):
                if name == "custom_imports":
                    raise RuntimeError("no imports")
                return super().__getattribute__(name)

        assert generator._custom_import_lines(HostileOptions()) == ""

    @pytest.mark.parametrize(
        "fork_url, fork_block",
        [
            ("  ", 18500000),
            (["https://rpc.example"], 18500000),
            ("https://rpc.example", 0),
            ("https://rpc.example", True),
            ("https://rpc.example/" + ("a" * 2050), 18500000),
            ("https://rpc.example/\n", 18500000),
            ("https://user:pass@rpc.example", 18500000),
            ("ftp://rpc.example", 18500000),
            ("https://rpc.example/\u2028bad", 18500000),
            ("http://localhost:8545", 18500000),
            ("http://127.0.0.1:8545", 18500000),
            ("http://[::1]:8545", 18500000),
            ("http://10.0.0.1", 18500000),
            ("http://172.16.0.1", 18500000),
            ("http://192.168.1.1", 18500000),
            ("http://169.254.1.1", 18500000),
        ],
    )
    def test_customize_skips_malformed_fork_config(
        self, generator, reentrancy_finding, fork_url, fork_block
    ):
        """Malformed fork options should not reach generated Solidity."""
        template = "// {{FORK_CONFIG}}\ncode here"
        options = GenerationOptions(fork_url=fork_url, fork_block=fork_block)

        result = generator._customize_template(
            template,
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Test.sol",
            target_function="test",
            finding=reentrancy_finding,
            options=options,
        )

        assert "createSelectFork" not in result
        assert "{{FORK_CONFIG}}" not in result

    def test_fork_config_handles_hostile_options_accessors(self, generator):
        """Hostile fork option accessors should skip config instead of raising."""

        class HostileOptions(GenerationOptions):
            def __getattribute__(self, name):
                if name in {"fork_url", "fork_block"}:
                    raise RuntimeError("no fork")
                return super().__getattribute__(name)

        assert generator._fork_config(HostileOptions()) == ""

    def test_customize_strips_fork_url(self, generator, reentrancy_finding):
        """Fork URL text is normalized before it is inserted into the template."""
        template = "// {{FORK_CONFIG}}\ncode here"
        options = GenerationOptions(fork_url=" https://rpc.example ", fork_block=18500000)

        result = generator._customize_template(
            template,
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Test.sol",
            target_function="test",
            finding=reentrancy_finding,
            options=options,
        )

        assert 'vm.createSelectFork("https://rpc.example", 18500000);' in result

    def test_customize_rejects_target_function_path_like_name(self, generator, reentrancy_finding):
        """Direct template customization should require Solidity identifiers."""
        result = generator._customize_template(
            "{{TARGET_FUNCTION}}",
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Bank.sol",
            target_function="../withdraw()",
            finding=reentrancy_finding,
            options=GenerationOptions(),
        )

        assert result == "vulnerable"

    def test_customize_rejects_custom_setup_with_control_chars(self, generator, reentrancy_finding):
        """Unsafe setup payloads should not cross into generated Solidity."""
        result = generator._customize_template(
            "// {{CUSTOM_SETUP}}\nbody",
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Bank.sol",
            target_function="withdraw",
            finding=reentrancy_finding,
            options=GenerationOptions(custom_setup_code="token = new Mock();\nunsafe();"),
        )

        assert "unsafe()" not in result
        assert "{{CUSTOM_SETUP}}" not in result

    @pytest.mark.parametrize(
        "custom_setup_code",
        [
            "} function pwn() public {} //",
            "function pwn() public {}",
            "contract Evil {}",
        ],
    )
    def test_customize_rejects_custom_setup_block_escape(
        self, generator, reentrancy_finding, custom_setup_code
    ):
        """Custom setup code should not be able to inject declarations or escape blocks."""
        result = generator._customize_template(
            "// {{CUSTOM_SETUP}}\nbody",
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Bank.sol",
            target_function="withdraw",
            finding=reentrancy_finding,
            options=GenerationOptions(custom_setup_code=custom_setup_code),
        )

        assert "pwn" not in result
        assert "Evil" not in result
        assert "{{CUSTOM_SETUP}}" not in result

    def test_custom_import_lines_caps_valid_imports(self, generator):
        """Custom imports should be capped after validation and deduplication."""
        options = GenerationOptions(
            custom_imports=[
                f"contracts/interfaces/I{i}.sol"
                for i in range(poc_generator_module._LIST_FIELD_LIMIT + 25)
            ]
        )

        lines = generator._custom_import_lines(options).splitlines()

        assert len(lines) == poc_generator_module._LIST_FIELD_LIMIT
        assert lines[0] == 'import "contracts/interfaces/I0.sol";'

    @pytest.mark.parametrize(
        "fork_url, fork_block",
        [
            ('https://rpc.example/"bad', 18500000),
            ("https://rpc.example\\bad", 18500000),
            ("https://rpc.example", poc_generator_module._MAX_FORK_BLOCK + 1),
        ],
    )
    def test_customize_skips_fork_quote_and_oversized_block_boundaries(
        self, generator, reentrancy_finding, fork_url, fork_block
    ):
        """Fork config should reject quote/backslash injection and oversized blocks."""
        result = generator._customize_template(
            "// {{FORK_CONFIG}}\nbody",
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Bank.sol",
            target_function="withdraw",
            finding=reentrancy_finding,
            options=GenerationOptions(fork_url=fork_url, fork_block=fork_block),
        )

        assert "createSelectFork" not in result

    def test_customize_respects_include_console_logs_false(self, generator, reentrancy_finding):
        """Console imports and log statements should be removable on request."""
        template = """// SPDX-License-Identifier: MIT
import "forge-std/Test.sol";
import "forge-std/console.sol";

contract {{CONTRACT_NAME}}Test is Test {
    function {{TEST_NAME}}() public {
        string memory url = "https://rpc.example//keep";
        console.log(
            "target",
            url
        );
        assertTrue(bytes(url).length > 0);
    }
}
"""

        result = generator._customize_template(
            template,
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Bank.sol",
            target_function="withdraw",
            finding=reentrancy_finding,
            options=GenerationOptions(include_console_logs=False),
        )

        assert "console.log" not in result
        assert "forge-std/console.sol" not in result
        assert "https://rpc.example//keep" in result
        assert "assertTrue" in result

    def test_customize_respects_include_comments_false_preserves_spdx(
        self, generator, reentrancy_finding
    ):
        """Comment removal should keep SPDX and avoid corrupting string literals."""
        template = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * block comment
 */
contract {{CONTRACT_NAME}}Test {
    string public url = "https://rpc.example//not-a-comment";
    // line comment
    function {{TEST_NAME}}() public {
        string memory marker = "/* not a block comment */";
    }
}
"""

        result = generator._customize_template(
            template,
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Bank.sol",
            target_function="withdraw",
            finding=reentrancy_finding,
            options=GenerationOptions(include_comments=False),
        )

        assert "// SPDX-License-Identifier: MIT" in result
        assert "* block comment" not in result
        assert "line comment" not in result
        assert "https://rpc.example//not-a-comment" in result
        assert '"/* not a block comment */"' in result

    def test_customize_respects_include_setup_false(self, generator, reentrancy_finding):
        """Setup removal should skip fork/custom setup insertion and preserve functions."""
        template = """// SPDX-License-Identifier: MIT
contract {{CONTRACT_NAME}}Test {
    function setUp() public {
        if (true) {
            string memory marker = "{not a brace}";
        }
        // {{FORK_CONFIG}}
        // {{CUSTOM_SETUP}}
    }

    function {{TEST_NAME}}() public {
        assertTrue(true);
    }
}
"""
        options = GenerationOptions(
            include_setup=False,
            fork_url="https://eth-mainnet.g.alchemy.com/v2/xxx",
            fork_block=18500000,
            custom_setup_code="target = address(1);",
        )

        result = generator._customize_template(
            template,
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Bank.sol",
            target_function="withdraw",
            finding=reentrancy_finding,
            options=options,
        )

        assert "function setUp() public {}" in result
        assert "createSelectFork" not in result
        assert "target = address(1);" not in result
        assert "assertTrue(true)" in result
        assert "{{" not in result

    def test_customize_malformed_bool_options_default_safely(self, generator, reentrancy_finding):
        """Only real bool option values should alter generated output."""
        template = generator._get_default_template(VulnerabilityType.REENTRANCY)
        options = GenerationOptions()
        options.include_setup = "false"
        options.include_comments = "false"
        options.include_console_logs = "false"

        result = generator._customize_template(
            template,
            vuln_type=VulnerabilityType.REENTRANCY,
            target_contract="Bank.sol",
            target_function="withdraw",
            finding=reentrancy_finding,
            options=options,
        )

        assert "function setUp() public {" in result
        assert "Target contract" in result
        assert "console.log" in result
        assert 'import "forge-std/console.sol";' in result


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

    def test_generate_agentic_invariant_access_control_poc(self, generator):
        """Agentic invariant findings should generate the corresponding PoC family."""
        finding = {
            "type": "Agentic Invariant Access Control",
            "severity": "high",
            "description": "Privileged state changes should require authorized callers",
            "location": {"function": "setOwner"},
            "id": "agentic-invariant-001",
        }

        poc = generator.generate(finding, "GovernanceVault.sol")

        assert poc.vulnerability_type == VulnerabilityType.ACCESS_CONTROL
        assert poc.target_function == "setOwner"
        assert poc.finding_id == "agentic-invariant-001"

    def test_generate_with_custom_options(self, generator, reentrancy_finding):
        """Test generating with custom options."""
        options = GenerationOptions(
            attacker_balance="1000 ether",
            include_console_logs=True,
        )

        poc = generator.generate(reentrancy_finding, "Bank.sol", options=options)

        assert "1000 ether" in poc.solidity_code

    def test_generate_with_output_options_removes_logs_comments_and_setup(
        self, generator, reentrancy_finding
    ):
        """Combined output options should apply to disk-backed templates."""
        options = GenerationOptions(
            include_setup=False,
            include_comments=False,
            include_console_logs=False,
        )

        poc = generator.generate(reentrancy_finding, "Bank.sol", options=options)

        assert "// SPDX-License-Identifier: MIT" in poc.solidity_code
        assert "console.log" not in poc.solidity_code
        assert "forge-std/console.sol" not in poc.solidity_code
        assert "Generated by MIESC PoC Generator" not in poc.solidity_code
        assert "function setUp() public {}" in poc.solidity_code

    def test_generate_includes_description(self, generator, reentrancy_finding):
        """Test generated PoC includes finding description."""
        poc = generator.generate(reentrancy_finding, "Bank.sol")

        assert poc.description == reentrancy_finding["description"]

    def test_generate_ignores_malformed_text_field_shapes(self, generator):
        """Test malformed text fields do not leak container reprs into PoC output."""
        finding = {
            "type": "reentrancy",
            "severity": {"level": "critical"},
            "description": ["external call before state update"],
            "id": {"value": "VULN-001"},
            "rule": ["reentrancy-rule"],
            "location": {"function": "withdraw"},
        }

        poc = generator.generate(finding, "Bank.sol")

        assert poc.description == ""
        assert poc.finding_id is None
        assert "medium" in poc.solidity_code
        assert "['external call before state update']" not in poc.solidity_code
        assert "{'level': 'critical'}" not in poc.solidity_code

    def test_generate_defaults_malformed_target_contract_shape(self, generator):
        """Malformed target contracts should not leak reprs into the generated PoC."""
        finding = {"type": "reentrancy", "severity": "high", "description": "Test"}

        poc = generator.generate(finding, {"path": "contracts/Token.sol"})

        assert poc.target_contract == ""
        assert "{'path': 'contracts/Token.sol'}" not in poc.solidity_code
        assert "{'path': 'contracts/Token.sol'}" not in poc.name

    @pytest.mark.parametrize("finding", [None, ["type", "reentrancy"], "reentrancy"])
    def test_generate_rejects_malformed_finding_container(self, generator, finding):
        """Direct generation should reject malformed finding containers cleanly."""
        with pytest.raises(ValueError, match="Malformed vulnerability finding"):
            generator.generate(finding, "Bank.sol")

    @pytest.mark.parametrize("options", [{"attacker_balance": "1 ether"}, ["bad"], object()])
    def test_generate_ignores_malformed_options_container(self, generator, options, caplog):
        """Malformed options overrides should fall back to safe defaults."""
        finding = {"type": "reentrancy", "severity": "high", "description": "Test"}

        with caplog.at_level("WARNING"):
            poc = generator.generate(finding, "Bank.sol", options)

        assert "100 ether" in poc.solidity_code
        assert "Ignoring malformed PoC generation options override" in caplog.text

    def test_generate_strips_finding_id_from_rule_fallback(self, generator):
        """The rule fallback should be normalized like direct finding IDs."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "description": "Test",
            "rule": "  reentrancy-rule  ",
        }

        poc = generator.generate(finding, "Bank.sol")

        assert poc.finding_id == "reentrancy-rule"

    def test_generate_rejects_control_chars_in_rule_fallback(self, generator):
        """Malformed rule IDs should not leak into PoC metadata."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "description": "Test",
            "rule": "bad\nrule",
        }

        poc = generator.generate(finding, "Bank.sol")

        assert poc.finding_id is None

    def test_generate_uses_safe_target_contract_text_for_path_object(self, generator):
        """Path target contracts should be accepted without leaking reprs."""
        finding = {"type": "reentrancy", "severity": "high", "description": "Test"}

        poc = generator.generate(finding, Path("contracts/Bank.sol"))

        assert poc.target_contract == "contracts/Bank.sol"
        assert "{'path':" not in poc.solidity_code

    def test_generate_defaults_target_contract_with_control_chars(self, generator):
        """Unsafe contract path text should not reach generated code or metadata."""
        finding = {"type": "reentrancy", "severity": "high", "description": "Test"}

        poc = generator.generate(finding, "Bank\n.sol")

        assert poc.target_contract == ""
        assert "Bank\n.sol" not in poc.solidity_code


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

    def test_generate_batch_preserves_agentic_and_swc_alias_order(self, generator):
        """Batch generation should preserve order after normalized alias resolution."""
        findings = [
            {"type": "Accounting Invariant", "location": {"function": "deposit"}},
            {"type": "SWC-104", "location": {"function": "transfer"}},
            {"type": "counterexampleValidation", "location": {"function": "withdraw"}},
        ]

        pocs = generator.generate_batch(findings, "Vault.sol")

        assert [poc.vulnerability_type for poc in pocs] == [
            VulnerabilityType.ERC4626_INFLATION,
            VulnerabilityType.UNCHECKED_CALL,
            VulnerabilityType.REENTRANCY,
        ]
        assert [poc.target_function for poc in pocs] == ["deposit", "transfer", "withdraw"]

    def test_generate_batch_handles_errors(self, generator):
        """Test batch generation handles errors gracefully."""
        findings = [
            {"type": "reentrancy", "location": {"function": "test"}},
            None,  # Invalid finding
            {"type": "overflow", "location": {"function": "calc"}},
        ]

        # Should not raise, should skip invalid
        pocs = generator.generate_batch([f for f in findings if f], "Test.sol")  # Filter None

        assert len(pocs) == 2

    def test_generate_batch_skips_malformed_entries_before_generation(
        self, generator, reentrancy_finding, caplog
    ):
        """Test malformed batch entries are skipped before generate is called."""
        from unittest.mock import patch

        findings = [
            reentrancy_finding,
            None,
            ["type", "overflow"],
            "reentrancy",
            {"type": "overflow", "location": {"function": "calc"}},
        ]

        original_generate = generator.generate

        with patch.object(generator, "generate", wraps=original_generate) as generate_spy:
            pocs = generator.generate_batch(findings, "Test.sol")

        assert len(pocs) == 2
        assert generate_spy.call_count == 2
        assert [call.args[0] for call in generate_spy.call_args_list] == [
            reentrancy_finding,
            {"type": "overflow", "location": {"function": "calc"}},
        ]
        assert "Skipping malformed finding entry in PoC batch" in caplog.text

    @pytest.mark.parametrize("findings", [None, {"type": "reentrancy"}, "reentrancy"])
    def test_generate_batch_rejects_malformed_top_level_container(
        self, generator, findings, caplog
    ):
        """Test malformed top-level findings containers return no PoCs."""
        from unittest.mock import patch

        with patch.object(generator, "generate", wraps=generator.generate) as generate_spy:
            pocs = generator.generate_batch(findings, "Test.sol")

        assert pocs == []
        assert generate_spy.call_count == 0
        assert "Skipping malformed findings container in PoC batch" in caplog.text

    def test_generate_batch_empty_list(self, generator):
        """Test batch generation with empty list."""
        pocs = generator.generate_batch([], "Test.sol")
        assert pocs == []

    def test_generate_batch_caps_successful_outputs(self, generator, reentrancy_finding):
        """Batch generation should cap successful PoCs from oversized inputs."""
        findings = [
            {**reentrancy_finding, "id": f"VULN-{i}"}
            for i in range(poc_generator_module._LIST_FIELD_LIMIT + 25)
        ]

        pocs = generator.generate_batch(findings, "Test.sol")

        assert len(pocs) == poc_generator_module._LIST_FIELD_LIMIT


# =============================================================================
# Prerequisites and Outcomes Tests
# =============================================================================


class TestPrerequisitesAndOutcomes:
    """Tests for prerequisites and expected outcomes."""

    def test_get_prerequisites_reentrancy(self, generator):
        """Test prerequisites for reentrancy."""
        prereqs = generator._get_prerequisites(VulnerabilityType.REENTRANCY)

        assert len(prereqs) >= 2
        assert all(isinstance(prereq, str) for prereq in prereqs)
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

    def test_get_expected_outcome_defaults_malformed_severity(self, generator):
        """Test malformed severity values do not affect outcome generation."""
        outcome = generator._get_expected_outcome(VulnerabilityType.REENTRANCY, ["critical"])

        assert "drain" in outcome.lower() or "fund" in outcome.lower()


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
        assert len(types) == len(set(types))
        assert "reentrancy" in types
        assert "flash_loan" in types

    def test_get_template_info(self, generator):
        """Test getting template info."""
        info = generator.get_template_info()

        assert "templates_dir" in info
        assert "available_templates" in info
        assert "type_aliases" in info
        assert len(info["type_aliases"]) > 10
        assert all(isinstance(template, str) for template in info["available_templates"])
        assert "reentrancy" in info["available_templates"]

    def test_get_template_info_filters_malformed_alias_entries(self, generator):
        """Malformed alias entries should not break template metadata export."""
        original_aliases = generator.TYPE_ALIASES
        generator.TYPE_ALIASES = {
            **original_aliases,
            "bad\nkey": VulnerabilityType.REENTRANCY,
            "bad-value": {"type": "reentrancy"},
        }
        try:
            info = generator.get_template_info()
        finally:
            generator.TYPE_ALIASES = original_aliases

        assert "bad\nkey" not in info["type_aliases"]
        assert info["type_aliases"]["bad-value"] == "unknown"

    def test_get_template_info_handles_mutated_mapping_state(self, generator):
        """Template info should not crash or leak reprs when state is malformed."""
        generator.TEMPLATE_MAP = ["bad"]
        generator.TYPE_ALIASES = ["bad"]
        generator.templates_dir = {"path": "bad"}

        info = generator.get_template_info()

        assert info == {
            "templates_dir": "",
            "available_templates": [],
            "type_aliases": {},
        }

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
        content = saved_path.read_text(encoding="utf-8")

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
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(poc_dict, f, indent=2)

        # Reload
        with open(json_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded["name"] == poc.name
        assert loaded["vulnerability_type"] == poc.vulnerability_type.value
        assert loaded["target_contract"] == poc.target_contract


# =============================================================================
# Additional Coverage Tests (Lines 292-293, 314-377, 395, 489-494, 618-629)
# =============================================================================


class TestBatchGenerateExceptionHandling:
    """Tests for exception handling in generate_batch (lines 292-293)."""

    @pytest.fixture
    def generator(self):
        """Create a default PoCGenerator."""
        return PoCGenerator()

    def test_generate_batch_skips_failed_findings(self, generator):
        """Test generate_batch continues when individual generation fails."""
        from unittest.mock import patch

        findings = [
            {"type": "reentrancy", "severity": "high", "description": "Test 1"},
            {"type": "invalid-type-that-fails", "severity": "high"},
            {"type": "overflow", "severity": "medium", "description": "Test 2"},
        ]

        # Mock generate to fail on second finding
        original_generate = generator.generate
        call_count = [0]

        def mock_generate(finding, target, options=None):
            call_count[0] += 1
            if "invalid-type-that-fails" in str(finding.get("type", "")):
                raise ValueError("Cannot process this finding")
            return original_generate(finding, target, options)

        with patch.object(generator, "generate", side_effect=mock_generate):
            results = generator.generate_batch(findings, "Test.sol")

        # Should have 2 successful results (first and third)
        assert len(results) == 2

    def test_generate_batch_all_fail(self, generator):
        """Test generate_batch when all findings fail."""
        from unittest.mock import patch

        findings = [
            {"type": "test1"},
            {"type": "test2"},
        ]

        with patch.object(generator, "generate", side_effect=ValueError("Always fails")):
            results = generator.generate_batch(findings, "Test.sol")

        assert results == []


class TestPoCRunMethod:
    """Tests for PoCGenerator.run method (lines 314-377)."""

    import subprocess
    from unittest.mock import MagicMock, patch

    @pytest.fixture
    def generator(self):
        """Create a default PoCGenerator."""
        return PoCGenerator()

    @pytest.fixture
    def sample_poc(self, generator):
        """Create a sample PoC template."""
        finding = {
            "type": "reentrancy",
            "severity": "critical",
            "description": "Test reentrancy",
        }
        return generator.generate(finding, "Bank.sol")

    def test_run_success(self, generator, sample_poc, tmp_path):
        """Test successful PoC run."""
        from unittest.mock import MagicMock, patch

        # Create project structure
        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "[PASS] test_exploit() (gas: 123456)"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert isinstance(result, PoCResult)
        assert result.success is True
        assert result.error is None

    def test_run_failure(self, generator, sample_poc, tmp_path):
        """Test failed PoC run."""
        from unittest.mock import MagicMock, patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Assertion failed"

        with patch("subprocess.run", return_value=mock_result):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.success is False
        assert "Assertion failed" in result.error

    def test_run_normalizes_malformed_subprocess_output_shapes(
        self, generator, sample_poc, tmp_path
    ):
        """Test malformed stdout/stderr shapes do not leak reprs into PoC results."""
        from unittest.mock import MagicMock, patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        mock_result = MagicMock()
        mock_result.returncode = "0"
        mock_result.stdout = b"[PASS] test_exploit() (gas: 12,345)"
        mock_result.stderr = {"error": "bad"}

        with patch("subprocess.run", return_value=mock_result):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.success is False
        assert result.output == "[PASS] test_exploit() (gas: 12,345)"
        assert result.gas_used == 12345
        assert result.error == ""
        assert "{'error': 'bad'}" not in result.output

    def test_run_result_bounds_large_stdout_stderr_output(self, generator, sample_poc, tmp_path):
        """Run results should not return unbounded forge logs."""
        from unittest.mock import MagicMock, patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "o" * (poc_generator_module._RUN_OUTPUT_LIMIT + 100)
        mock_result.stderr = "e" * (poc_generator_module._RUN_OUTPUT_LIMIT + 100)

        with patch("subprocess.run", return_value=mock_result):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert len(result.output) == poc_generator_module._RUN_OUTPUT_LIMIT * 2
        assert len(result.error) == poc_generator_module._RUN_OUTPUT_LIMIT

    def test_run_result_error_uses_normalized_stderr_only_for_failure(
        self, generator, sample_poc, tmp_path
    ):
        """Non-string stderr should normalize to an empty failure error."""
        from unittest.mock import MagicMock, patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "[FAIL]"
        mock_result.stderr = {"error": "bad"}

        with patch("subprocess.run", return_value=mock_result):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.success is False
        assert result.output == "[FAIL]"
        assert result.error == ""
        assert "{'error': 'bad'}" not in result.output

    def test_run_save_exception_is_sanitized(self, generator, sample_poc, tmp_path):
        """PoC save failures should become bounded run errors."""
        from unittest.mock import patch

        with patch.object(sample_poc, "save", side_effect=ValueError("bad\npath")):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.success is False
        assert result.output == ""
        assert "\\n" in result.error

    def test_run_treats_bool_returncode_as_failure(self, generator, sample_poc, tmp_path):
        """Bool returncodes should not be accepted as subprocess success integers."""
        from unittest.mock import MagicMock, patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        mock_result = MagicMock()
        mock_result.returncode = False
        mock_result.stdout = "[PASS]"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.success is False

    def test_run_rejects_malformed_poc_template(self, generator, tmp_path):
        """Test malformed PoC template objects are rejected before save()."""
        result = generator.run({"name": "bad"}, tmp_path, verbose=False)

        assert result.success is False
        assert result.output == ""
        assert result.error == "Malformed PoC template"

    def test_run_rejects_malformed_project_dir(self, generator, sample_poc):
        """Test malformed project dirs are rejected before Path coercion or save()."""
        result = generator.run(sample_poc, {"path": "bad"}, verbose=False)

        assert result.success is False
        assert result.output == ""
        assert result.error == "Malformed project directory"

    def test_run_rejects_empty_project_dir(self, generator, sample_poc):
        """Test empty project dirs do not resolve implicitly to the current directory."""
        result = generator.run(sample_poc, "  ", verbose=False)

        assert result.success is False
        assert result.output == ""
        assert result.error == "Malformed project directory"

    def test_run_rejects_path_object_project_dir_with_control_chars_before_save(
        self, generator, sample_poc
    ):
        """Path objects with control chars should be rejected before save/subprocess."""
        from unittest.mock import patch

        with patch.object(sample_poc, "save") as save_mock, patch("subprocess.run") as run_mock:
            result = generator.run(sample_poc, Path("bad\ndir"), verbose=False)

        assert result.success is False
        assert result.output == ""
        assert result.error == "Malformed project directory"
        save_mock.assert_not_called()
        run_mock.assert_not_called()

    def test_run_timeout(self, generator, sample_poc, tmp_path):
        """Test PoC run timeout (lines 362-368)."""
        import subprocess
        from unittest.mock import patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("forge", 300)):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.success is False
        assert "timed out" in result.error.lower()

    def test_run_foundry_not_installed(self, generator, sample_poc, tmp_path):
        """Test PoC run when Foundry not installed (lines 369-375)."""
        from unittest.mock import patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.success is False
        assert "not installed" in result.error.lower()

    def test_run_generic_exception(self, generator, sample_poc, tmp_path):
        """Test PoC run with generic exception (lines 376-382)."""
        from unittest.mock import patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        with patch("subprocess.run", side_effect=RuntimeError("Unexpected error")):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.success is False
        assert "Unexpected error" in result.error

    def test_run_sanitizes_generic_exception_text(self, generator, sample_poc, tmp_path):
        """Generic subprocess errors should be bounded and printable."""
        from unittest.mock import patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        with patch("subprocess.run", side_effect=RuntimeError("bad\nerror\x01" + ("x" * 600))):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.success is False
        assert "\\n" in result.error
        assert "\\x01" in result.error
        assert result.error.endswith("...<truncated>")

    def test_run_timeout_execution_time_is_nonnegative(self, generator, sample_poc, tmp_path):
        """Clock skew during timeout handling should not return negative duration."""
        import itertools
        import subprocess
        from unittest.mock import patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        # The first time.time() call is the start timestamp (10.0); every later
        # call (there may be any number, e.g. logging in the minimal env vs CI)
        # returns 9.0, so end < start reproduces the clock-skew and exercises the
        # negative-duration clamp regardless of how many times time.time() runs.
        skewed_clock = itertools.chain([10.0], itertools.repeat(9.0))
        with patch("time.time", side_effect=skewed_clock):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("forge", 300)):
                result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.success is False
        assert result.execution_time_ms == 0

    def test_run_verbose_output(self, generator, sample_poc, tmp_path, capsys):
        """Test verbose output during run (line 334)."""
        from unittest.mock import MagicMock, patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "[PASS]"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            generator.run(sample_poc, tmp_path, verbose=True)

        captured = capsys.readouterr()
        assert "Running:" in captured.out

    def test_run_malformed_verbose_does_not_print(self, generator, sample_poc, tmp_path, capsys):
        """Test malformed verbose values do not unexpectedly print command lines."""
        from unittest.mock import MagicMock, patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "[PASS]"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            generator.run(sample_poc, tmp_path, verbose="yes")

        captured = capsys.readouterr()
        assert "Running:" not in captured.out


class TestResolveVulnerabilityTypePartialMatch:
    """Tests for partial matching in _resolve_vulnerability_type (line 395)."""

    @pytest.fixture
    def generator(self):
        """Create a default PoCGenerator."""
        return PoCGenerator()

    def test_partial_match_alias_in_finding_type(self, generator):
        """Test partial matching when alias is in finding type."""
        finding = {"type": "some-reentrancy-variant", "severity": "high"}
        vuln_type = generator._resolve_vulnerability_type(finding)
        assert vuln_type == VulnerabilityType.REENTRANCY

    def test_partial_match_finding_type_in_alias(self, generator):
        """Test partial matching when finding type is in alias."""
        finding = {"type": "overflow", "severity": "high"}
        vuln_type = generator._resolve_vulnerability_type(finding)
        assert vuln_type == VulnerabilityType.INTEGER_OVERFLOW

    def test_unknown_type_defaults_to_reentrancy(self, generator):
        """Test unknown vulnerability type defaults to reentrancy."""
        finding = {"type": "totally-unknown-xyz", "severity": "high"}
        vuln_type = generator._resolve_vulnerability_type(finding)
        assert vuln_type == VulnerabilityType.REENTRANCY


class TestHelperInputNormalization:
    """Tests for PoC helper text normalization."""

    @pytest.fixture
    def generator(self):
        """Create a default PoCGenerator."""
        return PoCGenerator()

    def test_resolve_vulnerability_type_and_option_text_handle_bytes_and_control_chars(
        self, generator
    ):
        """Text helpers should keep bytes and reject control characters."""
        assert (
            generator._resolve_vulnerability_type({"type": b"  flash_loan  "})
            == VulnerabilityType.FLASH_LOAN
        )
        assert generator._resolve_vulnerability_type({"type": "flash_loan\x7f"}) == (
            VulnerabilityType.REENTRANCY
        )

        options = GenerationOptions(
            attacker_balance=b" 25 ether ",
            victim_balance="20 ether\x7f",
        )
        assert generator._option_text_field(options, "attacker_balance", "100 ether") == "25 ether"
        assert generator._option_text_field(options, "victim_balance", "100 ether") == "100 ether"

    def test_generate_poc_name_is_bounded(self, generator):
        """Generated names should stay bounded even with long inputs."""
        name = generator._generate_poc_name(
            "contracts/" + ("A" * 200) + ".sol",
            VulnerabilityType.ACCESS_CONTROL,
            "withdraw" + ("B" * 200),
        )

        assert len(name) <= 120
        assert "accesscontrol" in name

    def test_customize_template_and_outcome_helpers_bound_inputs(self, generator):
        """Template helpers should sanitize malformed function and severity inputs."""
        options = GenerationOptions(
            attacker_balance=b" 25 ether ",
            victim_balance="20 ether\x7f",
        )
        template = generator._get_default_template(VulnerabilityType.REENTRANCY)
        customized = generator._customize_template(
            template,
            VulnerabilityType.REENTRANCY,
            "contracts/Bank.sol",
            "withdraw\nowner",
            {"description": "test", "severity": "HIGH"},
            options,
        )

        assert "withdraw\nowner" not in customized
        assert "vulnerable" in customized
        assert generator._get_prerequisites("bad") == [
            "Foundry installed (forge, cast, anvil)",
            "Target contract deployed or source available",
        ]
        assert (
            generator._get_expected_outcome(VulnerabilityType.ACCESS_CONTROL, b" high ")
            == "Execute privileged functions without authorization"
        )


class TestCustomizePoCTemplate:
    """Tests for template customization (lines 489-494)."""

    @pytest.fixture
    def generator(self):
        """Create a default PoCGenerator."""
        return PoCGenerator()

    def test_custom_imports_replacement(self, generator):
        """Test custom imports are added to template (lines 489-490)."""
        options = GenerationOptions(
            custom_imports=["@openzeppelin/contracts/token/ERC20/IERC20.sol"]
        )

        finding = {"type": "reentrancy", "severity": "high", "description": "Test"}
        poc = generator.generate(finding, "Token.sol", options)

        assert "IERC20.sol" in poc.solidity_code

    def test_custom_setup_code_replacement(self, generator):
        """Test custom setup code is added (line 494)."""
        options = GenerationOptions(custom_setup_code="token = new MockToken();")

        finding = {"type": "reentrancy", "severity": "high", "description": "Test"}
        poc = generator.generate(finding, "Token.sol", options)

        assert "token = new MockToken();" in poc.solidity_code

    def test_multiple_custom_imports(self, generator):
        """Test multiple custom imports are added."""
        options = GenerationOptions(
            custom_imports=[
                "@openzeppelin/contracts/token/ERC20/IERC20.sol",
                "forge-std/Vm.sol",
                "./interfaces/IVault.sol",
            ]
        )

        finding = {"type": "flash-loan", "severity": "critical", "description": "Test"}
        poc = generator.generate(finding, "Vault.sol", options)

        assert "IERC20.sol" in poc.solidity_code
        assert "Vm.sol" in poc.solidity_code
        assert "IVault.sol" in poc.solidity_code

    def test_malformed_custom_imports_container_is_ignored(self, generator, caplog):
        """Test scalar custom imports do not become per-character import lines."""
        options = GenerationOptions(custom_imports="forge-std/Vm.sol")

        finding = {"type": "reentrancy", "severity": "high", "description": "Test"}
        with caplog.at_level("WARNING"):
            poc = generator.generate(finding, "Token.sol", options)

        assert 'import "f";' not in poc.solidity_code
        assert "forge-std/Vm.sol" not in poc.solidity_code
        assert "Skipping malformed custom imports container in PoC options" in caplog.text

    def test_malformed_custom_import_entries_and_setup_code_are_ignored(self, generator, caplog):
        """Test malformed custom option entries do not leak reprs into templates."""
        options = GenerationOptions(
            custom_imports=[
                "forge-std/Vm.sol",
                {"path": "bad/Import.sol"},
                ["nested/Import.sol"],
            ],
            custom_setup_code={"line": "token = new MockToken();"},
        )

        finding = {"type": "reentrancy", "severity": "high", "description": "Test"}
        with caplog.at_level("WARNING"):
            poc = generator.generate(finding, "Token.sol", options)

        assert 'import "forge-std/Vm.sol";' in poc.solidity_code
        assert "{'path': 'bad/Import.sol'}" not in poc.solidity_code
        assert "['nested/Import.sol']" not in poc.solidity_code
        assert "{'line': 'token = new MockToken();'}" not in poc.solidity_code
        assert "token = new MockToken();" not in poc.solidity_code
        assert "Skipping malformed custom import entry in PoC options" in caplog.text

    def test_malformed_custom_import_paths_are_ignored(self, generator, caplog):
        """Unsafe custom import path strings should not reach generated Solidity."""
        options = GenerationOptions(
            custom_imports=[
                "@openzeppelin/contracts/token/ERC20/IERC20.sol",
                "../Secrets.sol",
                "http://evil/import.sol",
                "bad\npath.sol",
            ]
        )
        finding = {"type": "reentrancy", "severity": "high", "description": "Test"}

        with caplog.at_level("WARNING"):
            poc = generator.generate(finding, "Token.sol", options)

        assert "IERC20.sol" in poc.solidity_code
        assert "../Secrets.sol" not in poc.solidity_code
        assert "http://evil" not in poc.solidity_code
        assert "Skipping malformed custom import entry in PoC options" in caplog.text

    def test_malformed_fork_options_are_ignored(self, generator, caplog):
        """Test malformed fork options do not leak container reprs into templates."""
        options = GenerationOptions(
            fork_url={"url": "https://eth-mainnet.example"},
            fork_block=["18500000"],
        )

        finding = {"type": "reentrancy", "severity": "high", "description": "Test"}
        with caplog.at_level("WARNING"):
            poc = generator.generate(finding, "Token.sol", options)

        assert "createSelectFork" not in poc.solidity_code
        assert "{'url': 'https://eth-mainnet.example'}" not in poc.solidity_code
        assert "['18500000']" not in poc.solidity_code
        assert "Skipping malformed fork configuration in PoC options" in caplog.text


class TestGasAndTraceExtraction:
    """Tests for gas and trace extraction (lines 618-621, 626-629)."""

    @pytest.fixture
    def generator(self):
        """Create a default PoCGenerator."""
        return PoCGenerator()

    def test_extract_gas_from_output(self, generator):
        """Test gas extraction from forge output (lines 618-621)."""
        output = "[PASS] test_exploit() (gas: 123456)"
        gas = generator._extract_gas_from_output(output)
        assert gas == 123456

    def test_extract_gas_with_thousands_separators(self, generator):
        """Test gas extraction normalizes comma-separated forge gas values."""
        output = "[PASS] test_exploit() (gas: 1,234,567)"
        gas = generator._extract_gas_from_output(output)
        assert gas == 1234567

    def test_extract_gas_ignores_oversized_values(self, generator):
        """Test unrealistic gas values are ignored at the output boundary."""
        assert generator._extract_gas_from_output("gas: 999,999,999,999") is None

    def test_extract_gas_ignores_bool_output_shape(self, generator):
        """Bool output containers should not be parsed as gas telemetry."""
        assert generator._extract_gas_from_output(True) is None

    def test_extract_gas_no_match(self, generator):
        """Test gas extraction returns None when no match."""
        output = "[PASS] test_exploit()"
        gas = generator._extract_gas_from_output(output)
        assert gas is None

    def test_extract_gas_ignores_malformed_output_shape(self, generator):
        """Malformed gas output containers should not leak reprs into parsing."""
        assert generator._extract_gas_from_output(["gas: 123"]) is None

    @pytest.mark.parametrize("output", ["gas: 1,,234", "gas: ,123", "gas: 12,34"])
    def test_extract_gas_ignores_malformed_comma_grouping(self, generator, output):
        """Malformed comma grouping should not be normalized into valid gas telemetry."""
        assert generator._extract_gas_from_output(output) is None

    def test_extract_gas_multiple_values(self, generator):
        """Test gas extraction picks first match."""
        output = "gas: 100\ngas: 200\ngas: 300"
        gas = generator._extract_gas_from_output(output)
        assert gas == 100

    def test_extract_traces_found(self, generator):
        """Test trace extraction when traces exist (lines 626-628)."""
        output = """
[PASS] test_exploit()
Traces:
  [CALL] Bank.withdraw(100)
    [CALL] Attacker.receive()
"""
        traces = generator._extract_traces(output)
        assert traces is not None
        assert "Traces:" in traces
        assert "Bank.withdraw" in traces

    def test_extract_traces_bounds_large_output(self, generator):
        """Trace extraction should bound very large forge outputs."""
        traces = generator._extract_traces("prefix\nTraces:\n" + ("x" * 30_000))

        assert traces.startswith("Traces:")
        assert len(traces) == 20_000

    def test_extract_traces_rejects_control_chars(self, generator):
        """Trace extraction should reject unsafe control-character payloads."""
        assert generator._extract_traces("Traces:\n bad\x00trace") is None

    def test_extract_traces_not_found(self, generator):
        """Test trace extraction returns None when no traces (line 629)."""
        output = "[PASS] test_exploit() (gas: 123456)"
        traces = generator._extract_traces(output)
        assert traces is None

    @pytest.mark.parametrize("output", [None, b"Traces:\n  [CALL] x()", ["Traces:"]])
    def test_extract_traces_ignores_malformed_output_shapes(self, generator, output):
        """Test malformed trace output shapes do not leak reprs or crash."""
        assert generator._extract_traces(output) is None


class TestPoCResultWithGasAndTraces:
    """Tests for PoCResult with gas and traces from run method."""

    @pytest.fixture
    def generator(self):
        """Create a default PoCGenerator."""
        return PoCGenerator()

    @pytest.fixture
    def sample_poc(self, generator):
        """Create a sample PoC template."""
        finding = {
            "type": "reentrancy",
            "severity": "critical",
            "description": "Test reentrancy",
        }
        return generator.generate(finding, "Bank.sol")

    def test_run_extracts_gas(self, generator, sample_poc, tmp_path):
        """Test run extracts gas from output."""
        from unittest.mock import MagicMock, patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "[PASS] test_exploit() (gas: 999888)"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.gas_used == 999888

    def test_run_extracts_traces(self, generator, sample_poc, tmp_path):
        """Test run extracts traces from output."""
        from unittest.mock import MagicMock, patch

        test_dir = tmp_path / "test" / "exploits"
        test_dir.mkdir(parents=True)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """[PASS] test_exploit() (gas: 123)
Traces:
  [CALL] Victim.withdraw()
"""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = generator.run(sample_poc, tmp_path, verbose=False)

        assert result.traces is not None
        assert "Traces:" in result.traces
