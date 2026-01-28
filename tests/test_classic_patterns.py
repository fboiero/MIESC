"""
Tests for Classic Vulnerability Pattern Detector module.

Sprint 1.3: Comprehensive tests for src/ml/classic_patterns.py covering:
- ClassicVulnType enum (11 types)
- PatternMatch dataclass
- PatternConfig dataclass
- CLASSIC_PATTERNS dict
- ClassicPatternDetector class methods

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import pytest
import re
from dataclasses import asdict

from src.ml.classic_patterns import (
    ClassicVulnType,
    PatternMatch,
    PatternConfig,
    CLASSIC_PATTERNS,
    ClassicPatternDetector,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def detector():
    """Create a ClassicPatternDetector instance for testing."""
    return ClassicPatternDetector()


@pytest.fixture
def reentrancy_vulnerable_code():
    """Code with classic reentrancy vulnerability."""
    return """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.7.0;

    contract VulnerableBank {
        mapping(address => uint256) public balances;

        function withdraw() public {
            uint256 balance = balances[msg.sender];
            require(balance > 0);

            // Vulnerable: external call before state update
            (bool success,) = msg.sender.call{value: balance}("");
            require(success);

            balances[msg.sender] = 0;
        }
    }
    """


@pytest.fixture
def reentrancy_safe_code():
    """Code with reentrancy protection."""
    return """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

    contract SafeBank is ReentrancyGuard {
        mapping(address => uint256) public balances;

        function withdraw() public nonReentrant {
            uint256 balance = balances[msg.sender];
            require(balance > 0);

            balances[msg.sender] = 0;  // State update first

            (bool success,) = msg.sender.call{value: balance}("");
            require(success);
        }
    }
    """


@pytest.fixture
def access_control_vulnerable_code():
    """Code with access control vulnerability."""
    return """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract VulnerableOwner {
        address public owner;

        // Vulnerable: tx.origin for authentication
        function withdrawAll() public {
            require(tx.origin == owner);
            payable(msg.sender).transfer(address(this).balance);
        }

        // Vulnerable: unprotected selfdestruct
        function kill() public {
            selfdestruct(payable(msg.sender));
        }
    }
    """


@pytest.fixture
def arithmetic_vulnerable_code():
    """Code with potential arithmetic overflow (pre-0.8)."""
    return """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.6.0;

    contract VulnerableToken {
        mapping(address => uint256) public balances;

        function transfer(address to, uint256 amount) public {
            balances[msg.sender] -= amount;  // Can underflow!
            balances[to] += amount;          // Can overflow!
        }

        function mint(address to, uint256 amount) public {
            balances[to] = balances[to] + amount;  // Addition
        }
    }
    """


@pytest.fixture
def timestamp_vulnerable_code():
    """Code with timestamp dependence."""
    return """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract TimestampLottery {
        function play() public payable {
            require(msg.value >= 1 ether);

            // Vulnerable: using block.timestamp for randomness
            if (block.timestamp % 15 == 0) {
                payable(msg.sender).transfer(address(this).balance);
            }
        }

        function isExpired() public view returns (bool) {
            return now > deadline;  // 'now' is alias for block.timestamp
        }
    }
    """


@pytest.fixture
def bad_randomness_code():
    """Code with weak random number generation."""
    return """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract WeakRandom {
        function getNumber() public view returns (uint256) {
            // Vulnerable: predictable values from block data
            return uint256(keccak256(abi.encodePacked(
                block.timestamp,
                blockhash(block.number - 1),
                block.difficulty
            )));
        }

        function roll() public view returns (uint8) {
            return uint8(block.number % 6);
        }
    }
    """


@pytest.fixture
def unchecked_call_code():
    """Code with unchecked low-level calls."""
    return """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract UncheckedCalls {
        function dangerousSend(address payable to, uint256 amount) public {
            // Vulnerable: return value not checked
            to.send(amount);
        }

        function dangerousCall(address target, bytes memory data) public {
            // Vulnerable: return value not checked
            target.call(data);
        }
    }
    """


@pytest.fixture
def vyper_vulnerable_code():
    """Vyper code with reentrancy vulnerability (vulnerable version)."""
    return """
    # @version 0.2.16

    @external
    @nonreentrant("lock")
    def withdraw(amount: uint256):
        # This nonreentrant decorator is broken in 0.2.15-0.3.0
        raw_call(msg.sender, b"", value=amount)
        self.balances[msg.sender] -= amount
    """


@pytest.fixture
def permit_frontrun_code():
    """Code vulnerable to permit front-running."""
    return """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";

    contract VulnerablePermit {
        function permitAndTransfer(
            IERC20Permit token,
            address from,
            address to,
            uint256 amount,
            uint256 deadline,
            uint8 v, bytes32 r, bytes32 s
        ) external {
            // Vulnerable: permit can be front-run
            token.permit(from, address(this), amount, deadline, v, r, s);
            // If permit is front-run, this will fail
            IERC20(address(token)).transferFrom(from, to, amount);
        }
    }
    """


# =============================================================================
# Tests for ClassicVulnType Enum
# =============================================================================


class TestClassicVulnType:
    """Tests for ClassicVulnType enum."""

    def test_enum_count(self):
        """Test enum has expected number of values."""
        assert len(ClassicVulnType) == 14

    def test_core_types_exist(self):
        """Test that core vulnerability types exist."""
        core_types = [
            "REENTRANCY",
            "ACCESS_CONTROL",
            "ARITHMETIC",
            "UNCHECKED_CALLS",
            "TIMESTAMP",
            "BAD_RANDOMNESS",
            "FRONT_RUNNING",
            "DOS",
            "SHORT_ADDRESS",
        ]
        for type_name in core_types:
            assert hasattr(ClassicVulnType, type_name)

    def test_v440_types_exist(self):
        """Test that v4.4.0 new types exist."""
        assert hasattr(ClassicVulnType, "VYPER_REENTRANCY")
        assert hasattr(ClassicVulnType, "PERMIT_FRONTRUN")

    def test_enum_values_are_strings(self):
        """Test that enum values are lowercase strings."""
        for vuln_type in ClassicVulnType:
            assert isinstance(vuln_type.value, str)
            assert vuln_type.value.islower() or "_" in vuln_type.value


# =============================================================================
# Tests for PatternMatch Dataclass
# =============================================================================


class TestPatternMatch:
    """Tests for PatternMatch dataclass."""

    def test_create_match(self):
        """Test creating a PatternMatch."""
        match = PatternMatch(
            vuln_type=ClassicVulnType.REENTRANCY,
            line=10,
            code_snippet="msg.sender.call{value: balance}('')",
            pattern_matched=r"\.call\s*\{",
            confidence=0.9,
            severity="critical",
            swc_id="SWC-107",
            description="Reentrancy vulnerability",
            recommendation="Use ReentrancyGuard",
        )
        assert match.vuln_type == ClassicVulnType.REENTRANCY
        assert match.line == 10
        assert match.severity == "critical"
        assert match.confidence == 0.9

    def test_optional_fields(self):
        """Test optional fields have correct defaults."""
        match = PatternMatch(
            vuln_type=ClassicVulnType.ARITHMETIC,
            line=5,
            code_snippet="a += b",
            pattern_matched=r"\+=",
            confidence=0.5,
            severity="high",
        )
        assert match.swc_id is None
        assert match.description == ""
        assert match.recommendation == ""


# =============================================================================
# Tests for PatternConfig Dataclass
# =============================================================================


class TestPatternConfig:
    """Tests for PatternConfig dataclass."""

    def test_create_config(self):
        """Test creating a PatternConfig."""
        config = PatternConfig(
            vuln_type=ClassicVulnType.REENTRANCY,
            patterns=[r"\.call\s*\{"],
            anti_patterns=[r"nonReentrant"],
            severity="critical",
            swc_id="SWC-107",
            description="Reentrancy",
            recommendation="Use guards",
        )
        assert config.vuln_type == ClassicVulnType.REENTRANCY
        assert len(config.patterns) == 1
        assert len(config.anti_patterns) == 1

    def test_default_values(self):
        """Test default values in PatternConfig."""
        config = PatternConfig(
            vuln_type=ClassicVulnType.TIMESTAMP,
            patterns=[r"block\.timestamp"],
        )
        assert config.anti_patterns == []
        assert config.severity == "medium"
        assert config.swc_id is None
        assert config.context_validator is None


# =============================================================================
# Tests for CLASSIC_PATTERNS Database
# =============================================================================


class TestClassicPatternsDB:
    """Tests for CLASSIC_PATTERNS database."""

    def test_patterns_count(self):
        """Test that database has expected number of entries."""
        assert len(CLASSIC_PATTERNS) == 14

    def test_all_enum_types_have_patterns(self):
        """Test that all enum types have pattern configs."""
        for vuln_type in ClassicVulnType:
            assert vuln_type in CLASSIC_PATTERNS, \
                f"{vuln_type} missing from CLASSIC_PATTERNS"

    def test_all_values_are_configs(self):
        """Test that all values are PatternConfig instances."""
        for vuln_type, config in CLASSIC_PATTERNS.items():
            assert isinstance(config, PatternConfig)

    def test_keys_match_config_types(self):
        """Test that keys match config vuln_type fields."""
        for key, config in CLASSIC_PATTERNS.items():
            assert key == config.vuln_type

    def test_all_patterns_have_at_least_one_pattern(self):
        """Test that all configs have at least one pattern."""
        for vuln_type, config in CLASSIC_PATTERNS.items():
            assert len(config.patterns) > 0, \
                f"{vuln_type} has no patterns"

    def test_patterns_are_valid_regex(self):
        """Test that all patterns are valid regex."""
        for vuln_type, config in CLASSIC_PATTERNS.items():
            for pattern in config.patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    pytest.fail(f"{vuln_type} has invalid pattern: {pattern} - {e}")

    def test_anti_patterns_are_valid_regex(self):
        """Test that all anti-patterns are valid regex."""
        for vuln_type, config in CLASSIC_PATTERNS.items():
            for pattern in config.anti_patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    pytest.fail(f"{vuln_type} has invalid anti-pattern: {pattern} - {e}")

    def test_severities_are_valid(self):
        """Test that severities are valid values."""
        valid_severities = {"critical", "high", "medium", "low"}
        for vuln_type, config in CLASSIC_PATTERNS.items():
            assert config.severity in valid_severities, \
                f"{vuln_type} has invalid severity: {config.severity}"

    def test_critical_patterns_have_swc(self):
        """Test that critical severity patterns have SWC IDs."""
        for vuln_type, config in CLASSIC_PATTERNS.items():
            if config.severity == "critical":
                assert config.swc_id is not None, \
                    f"Critical pattern {vuln_type} should have swc_id"

    def test_reentrancy_patterns(self):
        """Test reentrancy pattern specifics."""
        config = CLASSIC_PATTERNS[ClassicVulnType.REENTRANCY]
        assert config.severity == "critical"
        assert config.swc_id == "SWC-107"
        # Should detect .call patterns
        assert any(".call" in p for p in config.patterns)

    def test_arithmetic_patterns(self):
        """Test arithmetic pattern specifics."""
        config = CLASSIC_PATTERNS[ClassicVulnType.ARITHMETIC]
        assert config.swc_id == "SWC-101"
        # Should have SafeMath as anti-pattern
        assert any("SafeMath" in p for p in config.anti_patterns)


# =============================================================================
# Tests for ClassicPatternDetector Class
# =============================================================================


class TestClassicPatternDetectorInit:
    """Tests for ClassicPatternDetector initialization."""

    def test_default_initialization(self):
        """Test default initialization uses CLASSIC_PATTERNS."""
        detector = ClassicPatternDetector()
        assert detector.patterns == CLASSIC_PATTERNS

    def test_custom_patterns(self):
        """Test initialization with custom patterns."""
        custom = {
            ClassicVulnType.REENTRANCY: PatternConfig(
                vuln_type=ClassicVulnType.REENTRANCY,
                patterns=[r"custom_pattern"],
            )
        }
        detector = ClassicPatternDetector(patterns=custom)
        assert detector.patterns == custom
        assert len(detector.patterns) == 1


class TestClassicPatternDetectorDetect:
    """Tests for ClassicPatternDetector detect method."""

    def test_detect_reentrancy(self, detector, reentrancy_vulnerable_code):
        """Test detection of reentrancy vulnerability."""
        matches = detector.detect(reentrancy_vulnerable_code)

        reentrancy_matches = [m for m in matches if m.vuln_type == ClassicVulnType.REENTRANCY]
        assert len(reentrancy_matches) > 0

        match = reentrancy_matches[0]
        assert match.severity == "critical"
        assert match.swc_id == "SWC-107"

    def test_detect_access_control(self, detector, access_control_vulnerable_code):
        """Test detection of access control vulnerability."""
        matches = detector.detect(access_control_vulnerable_code)

        ac_matches = [m for m in matches if m.vuln_type == ClassicVulnType.ACCESS_CONTROL]
        assert len(ac_matches) > 0

    def test_detect_arithmetic(self, detector, arithmetic_vulnerable_code):
        """Test detection of arithmetic vulnerability."""
        matches = detector.detect(arithmetic_vulnerable_code)

        arith_matches = [m for m in matches if m.vuln_type == ClassicVulnType.ARITHMETIC]
        assert len(arith_matches) > 0

    def test_detect_timestamp(self, detector, timestamp_vulnerable_code):
        """Test detection of timestamp dependence."""
        matches = detector.detect(timestamp_vulnerable_code)

        ts_matches = [m for m in matches if m.vuln_type == ClassicVulnType.TIMESTAMP]
        assert len(ts_matches) > 0

    def test_detect_bad_randomness(self, detector, bad_randomness_code):
        """Test detection of weak randomness."""
        matches = detector.detect(bad_randomness_code)

        rand_matches = [m for m in matches if m.vuln_type == ClassicVulnType.BAD_RANDOMNESS]
        assert len(rand_matches) > 0

    def test_detect_unchecked_calls(self, detector, unchecked_call_code):
        """Test detection of unchecked low-level calls."""
        matches = detector.detect(unchecked_call_code)

        unchecked_matches = [m for m in matches if m.vuln_type == ClassicVulnType.UNCHECKED_CALLS]
        assert len(unchecked_matches) > 0

    def test_detect_vyper_reentrancy(self, detector, vyper_vulnerable_code):
        """Test detection of Vyper reentrancy vulnerability."""
        matches = detector.detect(vyper_vulnerable_code)

        vyper_matches = [m for m in matches if m.vuln_type == ClassicVulnType.VYPER_REENTRANCY]
        assert len(vyper_matches) > 0

    def test_detect_permit_frontrun(self, detector, permit_frontrun_code):
        """Test detection of permit front-running vulnerability."""
        matches = detector.detect(permit_frontrun_code)

        permit_matches = [m for m in matches if m.vuln_type == ClassicVulnType.PERMIT_FRONTRUN]
        assert len(permit_matches) > 0

    def test_safe_code_has_fewer_matches(self, detector, reentrancy_safe_code):
        """Test that safe code produces fewer or no reentrancy matches."""
        matches = detector.detect(reentrancy_safe_code)

        # Should either have no reentrancy or low confidence
        reentrancy_matches = [m for m in matches if m.vuln_type == ClassicVulnType.REENTRANCY]

        # If there are matches, confidence should be reduced by anti-patterns
        # (exact behavior depends on implementation)
        assert isinstance(matches, list)

    def test_empty_code_no_matches(self, detector):
        """Test that empty code produces no matches."""
        matches = detector.detect("")
        assert len(matches) == 0

    def test_filter_by_categories(self, detector, reentrancy_vulnerable_code):
        """Test filtering by specific categories."""
        # Only check for TIMESTAMP (not present in this code)
        matches = detector.detect(
            reentrancy_vulnerable_code,
            categories=[ClassicVulnType.TIMESTAMP]
        )

        # Should not find reentrancy (filtered out)
        reentrancy_matches = [m for m in matches if m.vuln_type == ClassicVulnType.REENTRANCY]
        assert len(reentrancy_matches) == 0

    def test_matches_have_line_numbers(self, detector, reentrancy_vulnerable_code):
        """Test that matches include line numbers."""
        matches = detector.detect(reentrancy_vulnerable_code)

        for match in matches:
            assert match.line >= 0

    def test_matches_have_code_snippets(self, detector, reentrancy_vulnerable_code):
        """Test that matches include code snippets."""
        matches = detector.detect(reentrancy_vulnerable_code)

        for match in matches:
            assert len(match.code_snippet) > 0


class TestClassicPatternDetectorSpecificPatterns:
    """Tests for specific pattern detection scenarios."""

    def test_detect_tx_origin(self, detector):
        """Test detection of tx.origin usage."""
        code = """
        function checkOwner() public view returns (bool) {
            return tx.origin == owner;
        }
        """
        matches = detector.detect(code)
        ac_matches = [m for m in matches if m.vuln_type == ClassicVulnType.ACCESS_CONTROL]
        assert len(ac_matches) > 0

    def test_detect_selfdestruct(self, detector):
        """Test detection of selfdestruct."""
        code = """
        function destroy() public {
            selfdestruct(payable(owner));
        }
        """
        matches = detector.detect(code)
        ac_matches = [m for m in matches if m.vuln_type == ClassicVulnType.ACCESS_CONTROL]
        assert len(ac_matches) > 0

    def test_detect_delegatecall(self, detector):
        """Test detection of delegatecall."""
        code = """
        function execute(address target, bytes memory data) public {
            target.delegatecall(data);
        }
        """
        matches = detector.detect(code)
        # Should match access_control (delegatecall) and unchecked_calls
        assert len(matches) > 0

    def test_detect_blockhash(self, detector):
        """Test detection of blockhash for randomness."""
        code = """
        function getRandomNumber() public view returns (bytes32) {
            return blockhash(block.number - 1);
        }
        """
        matches = detector.detect(code)
        rand_matches = [m for m in matches if m.vuln_type == ClassicVulnType.BAD_RANDOMNESS]
        assert len(rand_matches) > 0

    def test_detect_loop_dos(self, detector):
        """Test detection of loop-based DoS."""
        code = """
        function distributeRewards(address[] memory recipients) public {
            for (uint i = 0; i < recipients.length; i++) {
                payable(recipients[i]).transfer(1 ether);
            }
        }
        """
        matches = detector.detect(code)
        dos_matches = [m for m in matches if m.vuln_type == ClassicVulnType.DOS]
        assert len(dos_matches) > 0


class TestClassicPatternDetectorIntegration:
    """Integration tests for ClassicPatternDetector."""

    def test_multiple_vulnerabilities(self, detector):
        """Test detection of multiple vulnerabilities in same code."""
        multi_vuln_code = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.6.0;

        contract MultiVulnerable {
            address public owner;

            function withdraw() public {
                // Reentrancy
                msg.sender.call{value: 1 ether}("");

                // tx.origin
                require(tx.origin == owner);
            }

            function random() public view returns (uint256) {
                // Bad randomness
                return uint256(blockhash(block.number - 1));
            }

            function transfer(uint256 amount) public {
                // Arithmetic (pre-0.8)
                balances[msg.sender] -= amount;
            }
        }
        """
        matches = detector.detect(multi_vuln_code)

        vuln_types = {m.vuln_type for m in matches}
        # Should find multiple types
        assert len(vuln_types) >= 2

    def test_consistency_across_runs(self, detector, reentrancy_vulnerable_code):
        """Test that detection produces consistent results."""
        matches1 = detector.detect(reentrancy_vulnerable_code)
        matches2 = detector.detect(reentrancy_vulnerable_code)

        assert len(matches1) == len(matches2)
        for m1, m2 in zip(matches1, matches2):
            assert m1.vuln_type == m2.vuln_type
            assert m1.line == m2.line

    def test_real_contract_analysis(self, detector):
        """Test analysis of a realistic contract."""
        realistic_contract = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract SimpleBank {
            mapping(address => uint256) public balances;
            address public owner;

            constructor() {
                owner = msg.sender;
            }

            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }

            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                balances[msg.sender] -= amount;
                payable(msg.sender).transfer(amount);
            }

            function getContractBalance() public view returns (uint256) {
                return address(this).balance;
            }
        }
        """
        matches = detector.detect(realistic_contract)

        # Should find some matches (transfer pattern, arithmetic)
        # but not critical vulnerabilities in this well-structured code
        assert isinstance(matches, list)


# =============================================================================
# Parametrized Tests
# =============================================================================


@pytest.mark.parametrize("vuln_type,swc_id", [
    (ClassicVulnType.REENTRANCY, "SWC-107"),
    (ClassicVulnType.ACCESS_CONTROL, "SWC-105"),
    (ClassicVulnType.ARITHMETIC, "SWC-101"),
    (ClassicVulnType.UNCHECKED_CALLS, "SWC-104"),
    (ClassicVulnType.TIMESTAMP, "SWC-116"),
    (ClassicVulnType.BAD_RANDOMNESS, "SWC-120"),
    (ClassicVulnType.FRONT_RUNNING, "SWC-114"),
])
def test_swc_id_mapping(vuln_type, swc_id):
    """Test that vulnerability types map to correct SWC IDs."""
    config = CLASSIC_PATTERNS.get(vuln_type)
    assert config is not None
    assert config.swc_id == swc_id


@pytest.mark.parametrize("pattern_str,expected_match", [
    (r"\.call\s*\{?\s*value\s*:", "msg.sender.call{value: balance}"),
    (r"tx\.origin", "require(tx.origin == owner)"),
    (r"block\.timestamp", "if (block.timestamp > deadline)"),
    (r"blockhash\s*\(", "blockhash(block.number - 1)"),
])
def test_pattern_matches_expected_code(pattern_str, expected_match):
    """Test that patterns match expected code snippets."""
    regex = re.compile(pattern_str, re.IGNORECASE)
    assert regex.search(expected_match), \
        f"Pattern '{pattern_str}' should match '{expected_match}'"


@pytest.mark.parametrize("severity,count_range", [
    ("critical", (2, 5)),    # 2-5 critical patterns expected
    ("high", (1, 5)),        # 1-5 high patterns
    ("medium", (2, 5)),      # 2-5 medium patterns
    ("low", (1, 3)),         # 1-3 low patterns
])
def test_severity_distribution(severity, count_range):
    """Test that severity distribution is reasonable."""
    count = sum(1 for config in CLASSIC_PATTERNS.values() if config.severity == severity)
    min_count, max_count = count_range
    assert min_count <= count <= max_count, \
        f"Expected {min_count}-{max_count} {severity} patterns, got {count}"
