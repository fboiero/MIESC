"""
Tests for MIESC FP Filter Module (src/ml/fp_filter.py)

Tests for ML-enhanced false positive reduction with pattern matching.

Author: Fernando Boiero
License: AGPL-3.0
"""

import pytest
from unittest.mock import MagicMock, patch

from src.ml.fp_filter import (
    FalsePositiveFilter,
    FilterResult,
    FPCategory,
    FPMatch,
    filter_false_positives,
)


class TestFPCategory:
    """Tests for FPCategory enum."""

    def test_all_categories_exist(self):
        """Test that all expected categories exist."""
        assert FPCategory.LIBRARY_SAFE.value == "library_safe"
        assert FPCategory.PATTERN_SAFE.value == "pattern_safe"
        assert FPCategory.CONTEXT_SAFE.value == "context_safe"
        assert FPCategory.TEST_FILE.value == "test_file"
        assert FPCategory.MOCK_CONTRACT.value == "mock_contract"
        assert FPCategory.INTERFACE.value == "interface"
        assert FPCategory.ABSTRACT.value == "abstract"

    def test_category_count(self):
        """Test that we have the expected number of categories."""
        assert len(FPCategory) == 7


class TestFPMatch:
    """Tests for FPMatch dataclass."""

    def test_creation(self):
        """Test creating FPMatch with required fields."""
        match = FPMatch(
            category=FPCategory.LIBRARY_SAFE,
            pattern="@openzeppelin",
            confidence=0.9,
            reason="Uses OpenZeppelin library",
        )

        assert match.category == FPCategory.LIBRARY_SAFE
        assert match.pattern == "@openzeppelin"
        assert match.confidence == 0.9
        assert match.reason == "Uses OpenZeppelin library"
        assert match.matched_text is None

    def test_creation_with_matched_text(self):
        """Test creating FPMatch with matched text."""
        match = FPMatch(
            category=FPCategory.PATTERN_SAFE,
            pattern=r"nonReentrant",
            confidence=0.8,
            reason="Has reentrancy guard",
            matched_text="nonReentrant modifier",
        )

        assert match.matched_text == "nonReentrant modifier"


class TestFilterResult:
    """Tests for FilterResult dataclass."""

    def test_creation_with_defaults(self):
        """Test creating FilterResult with default values."""
        result = FilterResult(
            is_likely_fp=False,
            fp_probability=0.3,
        )

        assert result.is_likely_fp is False
        assert result.fp_probability == 0.3
        assert result.matches == []
        assert result.original_confidence == 0.0
        assert result.adjusted_confidence == 0.0
        assert result.should_report is True
        assert result.filter_reason is None

    def test_creation_with_all_fields(self):
        """Test creating FilterResult with all fields."""
        matches = [
            FPMatch(
                category=FPCategory.LIBRARY_SAFE,
                pattern="test",
                confidence=0.8,
                reason="test reason",
            )
        ]

        result = FilterResult(
            is_likely_fp=True,
            fp_probability=0.75,
            matches=matches,
            original_confidence=0.9,
            adjusted_confidence=0.225,
            should_report=False,
            filter_reason="Uses audited library code",
        )

        assert result.is_likely_fp is True
        assert result.fp_probability == 0.75
        assert len(result.matches) == 1
        assert result.original_confidence == 0.9
        assert result.adjusted_confidence == 0.225
        assert result.should_report is False
        assert result.filter_reason == "Uses audited library code"


class TestFalsePositiveFilter:
    """Tests for FalsePositiveFilter class."""

    @pytest.fixture
    def fp_filter(self):
        """Create FalsePositiveFilter instance without RAG."""
        return FalsePositiveFilter(use_rag=False)

    @pytest.fixture
    def fp_filter_with_settings(self):
        """Create FalsePositiveFilter with custom settings."""
        return FalsePositiveFilter(
            fp_threshold=0.6,
            filter_test_files=True,
            filter_interfaces=True,
            filter_informational=True,
            use_rag=False,
        )

    def test_initialization(self, fp_filter):
        """Test filter initialization."""
        assert fp_filter.fp_threshold == 0.50
        assert fp_filter.filter_test_files is True
        assert fp_filter.filter_interfaces is True
        assert fp_filter.filter_informational is True

    def test_initialization_custom_threshold(self):
        """Test initialization with custom threshold."""
        fp_filter = FalsePositiveFilter(fp_threshold=0.7, use_rag=False)
        assert fp_filter.fp_threshold == 0.7

    def test_compile_patterns(self, fp_filter):
        """Test that patterns are compiled."""
        assert "library" in fp_filter._compiled_patterns
        assert "reentrancy" in fp_filter._compiled_patterns
        assert "access_control" in fp_filter._compiled_patterns
        assert "safe_math" in fp_filter._compiled_patterns
        assert "safe_transfer" in fp_filter._compiled_patterns
        assert "test_file" in fp_filter._compiled_patterns
        assert "mock" in fp_filter._compiled_patterns
        assert "interface" in fp_filter._compiled_patterns

    def test_safe_library_patterns(self, fp_filter):
        """Test that safe library patterns are defined."""
        assert len(fp_filter.SAFE_LIBRARY_PATTERNS) > 0
        # Check some expected patterns
        patterns_str = " ".join(fp_filter.SAFE_LIBRARY_PATTERNS)
        assert "openzeppelin" in patterns_str.lower()
        assert "solmate" in patterns_str.lower()
        assert "solady" in patterns_str.lower()
        assert "chainlink" in patterns_str.lower()

    def test_reentrancy_safe_patterns(self, fp_filter):
        """Test reentrancy safe patterns."""
        assert len(fp_filter.REENTRANCY_SAFE_PATTERNS) > 0
        patterns_str = " ".join(fp_filter.REENTRANCY_SAFE_PATTERNS)
        assert "ReentrancyGuard" in patterns_str
        assert "nonReentrant" in patterns_str

    def test_access_control_patterns(self, fp_filter):
        """Test access control patterns."""
        assert len(fp_filter.ACCESS_CONTROL_SAFE_PATTERNS) > 0
        patterns_str = " ".join(fp_filter.ACCESS_CONTROL_SAFE_PATTERNS)
        assert "onlyOwner" in patterns_str
        assert "AccessControl" in patterns_str

    def test_check_file_patterns_test_file(self, fp_filter):
        """Test detection of test files."""
        matches = fp_filter._check_file_patterns("tests/TestContract.t.sol")
        assert len(matches) >= 1
        assert any(m.category == FPCategory.TEST_FILE for m in matches)

    def test_check_file_patterns_mock(self, fp_filter):
        """Test detection of mock contracts."""
        matches = fp_filter._check_file_patterns("mocks/MockToken.sol")
        assert len(matches) >= 1
        assert any(m.category == FPCategory.MOCK_CONTRACT for m in matches)

    def test_check_file_patterns_interface(self, fp_filter):
        """Test detection of interfaces."""
        matches = fp_filter._check_file_patterns("contracts/interfaces/IToken.sol")
        assert len(matches) >= 1
        assert any(m.category == FPCategory.INTERFACE for m in matches)

    def test_check_file_patterns_normal_contract(self, fp_filter):
        """Test that normal contracts don't match file patterns."""
        matches = fp_filter._check_file_patterns("contracts/Token.sol")
        assert len(matches) == 0

    def test_check_code_patterns_reentrancy_guard(self, fp_filter):
        """Test detection of reentrancy guard in code."""
        code = """
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

        contract Safe is ReentrancyGuard {
            function withdraw() external nonReentrant {
                // safe
            }
        }
        """

        matches = fp_filter._check_code_patterns(code, "reentrancy")
        assert len(matches) >= 1
        assert any(m.category == FPCategory.PATTERN_SAFE for m in matches)

    def test_check_code_patterns_access_control(self, fp_filter):
        """Test detection of access control in code."""
        code = """
        import "@openzeppelin/contracts/access/Ownable.sol";

        contract Owned is Ownable {
            function privileged() external onlyOwner {
                // protected
            }
        }
        """

        matches = fp_filter._check_code_patterns(code, "access-control")
        assert len(matches) >= 1

    def test_check_code_patterns_safe_math(self, fp_filter):
        """Test detection of SafeMath usage."""
        code = """
        using SafeMath for uint256;

        function add(uint256 a, uint256 b) public pure returns (uint256) {
            return a.add(b);
        }
        """

        matches = fp_filter._check_code_patterns(code, "arithmetic")
        assert len(matches) >= 1

    def test_check_code_patterns_solidity_08(self, fp_filter):
        """Test detection of Solidity 0.8+ version."""
        code = """
        pragma solidity ^0.8.20;

        contract Counter {
            uint256 count;

            function increment() external {
                count += 1;  // Safe in 0.8+
            }
        }
        """

        matches = fp_filter._check_code_patterns(code, "arithmetic")
        assert len(matches) >= 1

    def test_check_code_patterns_pausable(self, fp_filter):
        """Test detection of pausable pattern."""
        code = """
        import "@openzeppelin/contracts/security/Pausable.sol";

        contract PausableToken is Pausable {
            function transfer() external whenNotPaused {
                // transfer logic
            }
        }
        """

        matches = fp_filter._check_code_patterns(code, "")
        assert len(matches) >= 1
        assert any("pausable" in m.reason.lower() for m in matches)

    def test_check_code_patterns_input_validation(self, fp_filter):
        """Test detection of input validation."""
        code = """
        function setOwner(address newOwner) external {
            require(newOwner != address(0), "Zero address");
            owner = newOwner;
        }
        """

        matches = fp_filter._check_code_patterns(code, "")
        assert len(matches) >= 1
        assert any("validation" in m.reason.lower() for m in matches)

    def test_check_library_patterns(self, fp_filter):
        """Test detection of library imports in message."""
        text = "Import from @openzeppelin/contracts/token/ERC20/ERC20.sol"
        matches = fp_filter._check_library_patterns(text)
        assert len(matches) >= 1
        assert any(m.category == FPCategory.LIBRARY_SAFE for m in matches)

    def test_calculate_fp_probability_no_matches(self, fp_filter):
        """Test FP probability calculation with no matches."""
        prob = fp_filter._calculate_fp_probability([], 0.9)
        # High confidence, no matches = low FP probability
        assert prob < 0.3

    def test_calculate_fp_probability_with_matches(self, fp_filter):
        """Test FP probability calculation with matches."""
        matches = [
            FPMatch(
                category=FPCategory.LIBRARY_SAFE,
                pattern="test",
                confidence=0.8,
                reason="Uses library",
            ),
            FPMatch(
                category=FPCategory.PATTERN_SAFE,
                pattern="test2",
                confidence=0.6,
                reason="Has guard",
            ),
        ]

        prob = fp_filter._calculate_fp_probability(matches, 0.7)
        assert prob > 0.3  # Should have higher FP probability

    def test_calculate_fp_probability_cap(self, fp_filter):
        """Test that FP probability is capped at 0.95."""
        matches = [
            FPMatch(
                category=FPCategory.TEST_FILE,
                pattern="test",
                confidence=0.9,
                reason="Test file",
            ),
            FPMatch(
                category=FPCategory.MOCK_CONTRACT,
                pattern="mock",
                confidence=0.9,
                reason="Mock contract",
            ),
            FPMatch(
                category=FPCategory.LIBRARY_SAFE,
                pattern="lib",
                confidence=0.9,
                reason="Library",
            ),
        ]

        prob = fp_filter._calculate_fp_probability(matches, 0.5)
        assert prob <= 0.95

    def test_filter_finding_likely_fp(self, fp_filter):
        """Test filtering a likely false positive."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "confidence": 0.7,
            "message": "Reentrancy detected",
        }

        code = """
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        contract Safe is ReentrancyGuard {
            function withdraw() external nonReentrant {}
        }
        """

        result = fp_filter.filter_finding(finding, code, "Safe.sol")

        # With guard, should have higher FP probability
        assert result.fp_probability > 0
        assert len(result.matches) > 0

    def test_filter_finding_likely_tp(self, fp_filter):
        """Test filtering a likely true positive."""
        finding = {
            "type": "reentrancy",
            "severity": "critical",
            "confidence": 0.95,
            "message": "Reentrancy vulnerability",
        }

        code = """
        contract Vulnerable {
            function withdraw(uint amount) external {
                msg.sender.call{value: amount}("");
                balances[msg.sender] -= amount;
            }
        }
        """

        result = fp_filter.filter_finding(finding, code, "Vulnerable.sol")

        # Without protection, should have lower FP probability
        assert result.should_report is True

    def test_filter_finding_test_file(self, fp_filter):
        """Test filtering finding in test file."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "confidence": 0.8,
        }

        result = fp_filter.filter_finding(finding, "", "tests/TestVault.t.sol")

        assert any(m.category == FPCategory.TEST_FILE for m in result.matches)
        # Test file should have elevated FP probability (> 0.3)
        assert result.fp_probability > 0.3

    def test_filter_finding_informational(self, fp_filter):
        """Test filtering informational severity."""
        finding = {
            "type": "naming-convention",
            "severity": "info",
            "confidence": 0.6,
        }

        result = fp_filter.filter_finding(finding, "", "Token.sol")

        # Informational should be filtered
        assert result.is_likely_fp is True
        assert result.fp_probability >= 0.6

    def test_filter_finding_adjusts_confidence(self, fp_filter):
        """Test that confidence is adjusted properly."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "confidence": 0.9,
        }

        code = """
        contract Safe is ReentrancyGuard {
            function withdraw() external nonReentrant {}
        }
        """

        result = fp_filter.filter_finding(finding, code, "Safe.sol")

        # Adjusted confidence should be lower than original
        assert result.adjusted_confidence < result.original_confidence
        assert result.adjusted_confidence == result.original_confidence * (
            1 - result.fp_probability
        )

    def test_filter_findings_batch(self, fp_filter):
        """Test batch filtering of multiple findings."""
        findings = [
            {
                "type": "reentrancy",
                "severity": "critical",
                "confidence": 0.95,
                "location": {"file": "Vault.sol"},
            },
            {
                "type": "naming-convention",
                "severity": "informational",
                "confidence": 0.6,
                "location": {"file": "Token.sol"},
            },
            {
                "type": "unused-state",
                "severity": "info",
                "confidence": 0.5,
                "location": {"file": "tests/TestVault.t.sol"},
            },
        ]

        filtered, removed, stats = fp_filter.filter_findings(findings)

        assert len(filtered) + len(removed) == 3
        assert stats["total"] == 3
        assert stats["remaining"] == len(filtered)
        assert stats["filtered"] == len(removed)

    def test_filter_findings_with_code_contexts(self, fp_filter):
        """Test batch filtering with code contexts."""
        findings = [
            {
                "type": "reentrancy",
                "severity": "high",
                "location": {"file": "Safe.sol"},
            }
        ]

        code_contexts = {"Safe.sol": """
            import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
            contract Safe is ReentrancyGuard {}
            """}

        filtered, removed, stats = fp_filter.filter_findings(findings, code_contexts)

        # Should use code context for analysis
        assert stats["total"] == 1

    def test_filter_findings_enriches_findings(self, fp_filter):
        """Test that findings are enriched with FP analysis."""
        findings = [
            {
                "type": "reentrancy",
                "severity": "high",
                "location": {"file": "Test.sol"},
            }
        ]

        filtered, removed, stats = fp_filter.filter_findings(findings)

        all_findings = filtered + removed
        for finding in all_findings:
            assert "_fp_analysis" in finding
            assert "is_likely_fp" in finding["_fp_analysis"]
            assert "fp_probability" in finding["_fp_analysis"]
            assert "adjusted_confidence" in finding["_fp_analysis"]

    def test_filter_findings_statistics(self, fp_filter):
        """Test that statistics are properly computed."""
        findings = [
            {"type": "reentrancy", "severity": "high", "location": {"file": "A.sol"}},
            {"type": "info", "severity": "info", "location": {"file": "B.sol"}},
            {"type": "test", "severity": "low", "location": {"file": "tests/C.t.sol"}},
        ]

        _, _, stats = fp_filter.filter_findings(findings)

        assert "total" in stats
        assert "filtered" in stats
        assert "remaining" in stats
        assert "filter_rate" in stats
        assert "by_category" in stats
        assert "by_severity" in stats

    def test_get_statistics(self, fp_filter):
        """Test get_statistics method."""
        stats = fp_filter.get_statistics()

        assert "total_patterns" in stats
        assert "by_category" in stats
        assert "fp_threshold" in stats
        assert stats["total_patterns"] > 0

    def test_vuln_specific_patterns(self, fp_filter):
        """Test vulnerability-specific safe patterns."""
        vuln_patterns = fp_filter.VULN_SPECIFIC_SAFE_PATTERNS

        assert "reentrancy" in vuln_patterns
        assert "access-control" in vuln_patterns
        assert "arithmetic" in vuln_patterns
        assert "unchecked-call" in vuln_patterns

    def test_pattern_confidence_boost(self, fp_filter):
        """Test pattern confidence boost values."""
        boosts = fp_filter.PATTERN_CONFIDENCE_BOOST

        assert FPCategory.LIBRARY_SAFE in boosts
        assert FPCategory.PATTERN_SAFE in boosts
        assert FPCategory.TEST_FILE in boosts

        # Test file boost should be high
        assert boosts[FPCategory.TEST_FILE] >= 0.4

    def test_rag_initialization(self):
        """Test RAG initialization state."""
        # When RAG is disabled, it should not be available
        fp_filter = FalsePositiveFilter(use_rag=False)
        assert fp_filter._rag_available is False

        # Test that filter works regardless of RAG state
        finding = {"type": "test", "severity": "medium"}
        result = fp_filter.filter_finding(finding, "", "Test.sol")
        assert result is not None

    def test_rag_disabled(self):
        """Test filter works when RAG is disabled."""
        fp_filter = FalsePositiveFilter(use_rag=False)

        finding = {
            "type": "reentrancy",
            "severity": "high",
            "confidence": 0.8,
        }

        result = fp_filter.filter_finding(finding, "", "Test.sol")

        # Should work without RAG
        assert result is not None
        assert isinstance(result, FilterResult)

    def test_check_severity_mismatch(self, fp_filter):
        """Test severity mismatch detection."""
        # Significant mismatch (more than 1 level)
        assert fp_filter._check_severity_mismatch("critical", "low") is True
        assert fp_filter._check_severity_mismatch("high", "info") is True

        # Not significant mismatch
        assert fp_filter._check_severity_mismatch("high", "medium") is False
        assert fp_filter._check_severity_mismatch("medium", "low") is False

    def test_extract_fix_keywords(self, fp_filter):
        """Test extraction of fix keywords."""
        fixed_code = """
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        using SafeMath for uint256;

        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }

        function safeTransfer() {
            // logic
        }
        """

        keywords = fp_filter._extract_fix_keywords(fixed_code)

        assert "nonreentrant" in keywords or "safemath" in keywords or "onlyowner" in keywords


class TestConvenienceFunction:
    """Tests for filter_false_positives convenience function."""

    @pytest.fixture
    def fp_filter_no_rag(self):
        """Create FalsePositiveFilter without RAG for convenience function tests."""
        return FalsePositiveFilter(use_rag=False)

    def test_filter_false_positives_basic(self, fp_filter_no_rag):
        """Test basic usage of filter_findings method."""
        findings = [
            {
                "type": "reentrancy",
                "severity": "high",
                "confidence": 0.8,
                "location": {"file": "Test.sol"},
            },
            {
                "type": "naming-convention",
                "severity": "info",
                "confidence": 0.5,
                "location": {"file": "Token.sol"},
            },
        ]

        # Use the filter method directly with RAG disabled
        filtered, removed, stats = fp_filter_no_rag.filter_findings(findings)

        assert len(filtered) + len(removed) == len(findings)
        assert "total" in stats
        assert "filtered" in stats

    def test_filter_false_positives_with_threshold(self):
        """Test filter with different thresholds."""
        findings = [
            {
                "type": "reentrancy",
                "severity": "high",
                "confidence": 0.8,
                "location": {"file": "Test.sol"},
            },
        ]

        # Low threshold filter
        fp_filter_low = FalsePositiveFilter(fp_threshold=0.3, use_rag=False)
        filtered_low, _, _ = fp_filter_low.filter_findings(findings)

        # High threshold filter
        fp_filter_high = FalsePositiveFilter(fp_threshold=0.9, use_rag=False)
        filtered_high, _, _ = fp_filter_high.filter_findings(findings)

        # Higher threshold = fewer filtered (more kept)
        assert len(filtered_high) >= len(filtered_low)

    def test_filter_false_positives_with_code_contexts(self, fp_filter_no_rag):
        """Test filter with code contexts."""
        findings = [
            {
                "type": "reentrancy",
                "severity": "high",
                "location": {"file": "Safe.sol"},
            },
        ]

        code_contexts = {"Safe.sol": "contract Safe is ReentrancyGuard {}"}

        # Use the filter method with code contexts
        filtered, removed, stats = fp_filter_no_rag.filter_findings(findings, code_contexts)

        assert stats["total"] == 1


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.fixture
    def fp_filter(self):
        """Create filter for edge case tests."""
        return FalsePositiveFilter(use_rag=False)

    def test_empty_findings_list(self, fp_filter):
        """Test filtering empty list."""
        filtered, removed, stats = fp_filter.filter_findings([])

        assert filtered == []
        assert removed == []
        assert stats["total"] == 0

    def test_finding_without_location(self, fp_filter):
        """Test finding without location field."""
        findings = [
            {
                "type": "test",
                "severity": "medium",
                "confidence": 0.7,
            }
        ]

        filtered, removed, stats = fp_filter.filter_findings(findings)

        assert len(filtered) + len(removed) == 1

    def test_finding_with_empty_code_context(self, fp_filter):
        """Test filtering with empty code context."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
        }

        result = fp_filter.filter_finding(finding, "", "")

        assert result is not None

    def test_finding_with_snippet_in_location(self, fp_filter):
        """Test using snippet from location when no code context provided."""
        findings = [
            {
                "type": "reentrancy",
                "severity": "high",
                "location": {
                    "file": "Test.sol",
                    "snippet": "function withdraw() external nonReentrant {}",
                },
            }
        ]

        filtered, removed, stats = fp_filter.filter_findings(findings)

        # Should use snippet for analysis
        assert stats["total"] == 1

    def test_very_long_code_context(self, fp_filter):
        """Test with very long code context."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
        }

        # Generate very long code
        long_code = "contract Test {" + "uint x;" * 10000 + "}"

        result = fp_filter.filter_finding(finding, long_code, "Test.sol")

        # Should handle without error
        assert result is not None

    def test_special_characters_in_path(self, fp_filter):
        """Test file path with special characters."""
        matches = fp_filter._check_file_patterns("contracts/Test Contract (v2).sol")

        # Should not crash
        assert isinstance(matches, list)

    def test_unicode_in_code(self, fp_filter):
        """Test code with unicode characters."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
        }

        code = """
        // 这是一个注释 (This is a comment)
        contract Test {
            string public name = "Token 🪙";
        }
        """

        result = fp_filter.filter_finding(finding, code, "Test.sol")

        # Should handle unicode without error
        assert result is not None

    def test_malformed_finding(self, fp_filter):
        """Test with malformed finding structure."""
        findings = [
            {},  # Empty finding
            {"type": "test"},  # Missing fields
            {"severity": "high"},  # Missing type
        ]

        # Should not crash
        filtered, removed, stats = fp_filter.filter_findings(findings)

        assert stats["total"] == 3

    def test_rag_disabled_filtering(self):
        """Test filtering works correctly with RAG disabled."""
        fp_filter = FalsePositiveFilter(use_rag=False)

        finding = {
            "type": "reentrancy",
            "severity": "high",
            "confidence": 0.9,
        }

        # Should work without RAG
        result = fp_filter.filter_finding(finding, "", "Vault.sol")

        assert result is not None
        assert isinstance(result, FilterResult)
        # RAG should not be available
        assert fp_filter._rag_available is False

    def test_concurrent_filtering(self, fp_filter):
        """Test that filter can handle rapid successive calls."""
        findings = [{"type": f"test-{i}", "severity": "medium"} for i in range(100)]

        for finding in findings:
            result = fp_filter.filter_finding(finding, "", "Test.sol")
            assert result is not None
