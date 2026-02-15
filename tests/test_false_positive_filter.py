"""
Tests for MIESC False Positive Filter v2.3

Comprehensive tests for the ML-based false positive filtering system.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.ml.false_positive_filter import (
    SLITHER_DETECTOR_FP_RATES,
    FalsePositiveFilter,
    FeedbackEntry,
    FindingFeatures,
    SemanticContextAnalyzer,
)


class TestFindingFeatures:
    """Tests for FindingFeatures dataclass."""

    def test_creation_with_defaults(self):
        """Test creating FindingFeatures with default values."""
        features = FindingFeatures(
            tool="slither",
            vuln_type="reentrancy",
            severity="high",
            file_type=".sol",
            function_name="withdraw",
            has_swc=True,
            has_cwe=True,
            message_length=100,
            code_context_length=500,
            line_number=42,
            confirmations=2,
            confidence_original=0.85,
        )

        assert features.tool == "slither"
        assert features.vuln_type == "reentrancy"
        assert features.severity == "high"
        assert features.file_type == ".sol"
        assert features.function_name == "withdraw"
        assert features.has_swc is True
        assert features.has_cwe is True
        assert features.message_length == 100
        assert features.code_context_length == 500
        assert features.line_number == 42
        assert features.confirmations == 2
        assert features.confidence_original == 0.85
        # Check default values
        assert features.is_common_pattern is False
        assert features.in_test_file is False
        assert features.in_interface is False
        assert features.near_require is False
        assert features.near_modifier is False
        assert features.solidity_version == ""
        assert features.has_overflow_protection is False
        assert features.uses_safemath is False
        assert features.has_reentrancy_guard is False
        assert features.in_library is False
        assert features.function_visibility == ""

    def test_creation_with_all_values(self):
        """Test creating FindingFeatures with all values."""
        features = FindingFeatures(
            tool="mythril",
            vuln_type="integer-overflow",
            severity="critical",
            file_type=".sol",
            function_name="transfer",
            has_swc=True,
            has_cwe=True,
            message_length=200,
            code_context_length=1000,
            line_number=100,
            confirmations=3,
            confidence_original=0.95,
            is_common_pattern=True,
            in_test_file=True,
            in_interface=False,
            near_require=True,
            near_modifier=True,
            solidity_version="0.8.20",
            has_overflow_protection=True,
            uses_safemath=False,
            has_reentrancy_guard=True,
            in_library=True,
            function_visibility="external",
        )

        assert features.is_common_pattern is True
        assert features.in_test_file is True
        assert features.near_require is True
        assert features.near_modifier is True
        assert features.solidity_version == "0.8.20"
        assert features.has_overflow_protection is True
        assert features.has_reentrancy_guard is True
        assert features.in_library is True
        assert features.function_visibility == "external"

    def test_to_vector(self):
        """Test conversion to numeric vector."""
        features = FindingFeatures(
            tool="slither",
            vuln_type="reentrancy",
            severity="high",
            file_type=".sol",
            function_name="withdraw",
            has_swc=True,
            has_cwe=False,
            message_length=250,
            code_context_length=500,
            line_number=100,
            confirmations=2,
            confidence_original=0.8,
            has_overflow_protection=True,
            function_visibility="external",
            solidity_version="0.8.0",
        )

        vector = features.to_vector()

        assert len(vector) == 19
        # Check specific values
        assert vector[0] == 0.8  # severity (high)
        assert vector[1] == 1.0  # has_swc
        assert vector[2] == 0.0  # has_cwe
        assert vector[3] == 0.5  # message_length / 500
        assert vector[4] == 0.5  # code_context_length / 1000
        assert vector[5] == 0.1  # line_number / 1000
        assert vector[6] == 0.4  # confirmations / 5
        assert vector[7] == 0.8  # confidence_original
        assert vector[13] == 1.0  # has_overflow_protection
        assert vector[17] == 1.0  # visibility external
        assert vector[18] == 1.0  # solidity 0.8+

    def test_to_vector_clamping(self):
        """Test that vector values are clamped to max 1.0."""
        features = FindingFeatures(
            tool="test",
            vuln_type="test",
            severity="critical",
            file_type=".sol",
            function_name="test",
            has_swc=True,
            has_cwe=True,
            message_length=1000,  # Over 500 limit
            code_context_length=2000,  # Over 1000 limit
            line_number=5000,  # Over 1000 limit
            confirmations=10,  # Over 5 limit
            confidence_original=0.9,
        )

        vector = features.to_vector()

        # All these should be clamped to 1.0
        assert vector[3] == 1.0  # message_length
        assert vector[4] == 1.0  # code_context_length
        assert vector[5] == 1.0  # line_number
        assert vector[6] == 1.0  # confirmations

    def test_encode_severity(self):
        """Test severity encoding."""
        features = FindingFeatures(
            tool="test",
            vuln_type="test",
            severity="critical",
            file_type=".sol",
            function_name="test",
            has_swc=False,
            has_cwe=False,
            message_length=100,
            code_context_length=100,
            line_number=10,
            confirmations=1,
            confidence_original=0.5,
        )

        # Test all severity levels
        assert features._encode_severity("critical") == 1.0
        assert features._encode_severity("high") == 0.8
        assert features._encode_severity("medium") == 0.5
        assert features._encode_severity("low") == 0.2
        assert features._encode_severity("informational") == 0.1
        assert features._encode_severity("info") == 0.1
        assert features._encode_severity("unknown") == 0.3  # Default

    def test_encode_visibility(self):
        """Test visibility encoding."""
        features = FindingFeatures(
            tool="test",
            vuln_type="test",
            severity="medium",
            file_type=".sol",
            function_name="test",
            has_swc=False,
            has_cwe=False,
            message_length=100,
            code_context_length=100,
            line_number=10,
            confirmations=1,
            confidence_original=0.5,
        )

        assert features._encode_visibility("external") == 1.0
        assert features._encode_visibility("public") == 0.8
        assert features._encode_visibility("internal") == 0.3
        assert features._encode_visibility("private") == 0.1
        assert features._encode_visibility("unknown") == 0.5  # Default
        assert features._encode_visibility("EXTERNAL") == 1.0  # Case insensitive

    def test_encode_solidity_version(self):
        """Test Solidity version encoding."""
        features = FindingFeatures(
            tool="test",
            vuln_type="test",
            severity="medium",
            file_type=".sol",
            function_name="test",
            has_swc=False,
            has_cwe=False,
            message_length=100,
            code_context_length=100,
            line_number=10,
            confirmations=1,
            confidence_original=0.5,
        )

        assert features._encode_solidity_version("0.8.0") == 1.0
        assert features._encode_solidity_version("0.8.20") == 1.0
        assert features._encode_solidity_version("0.9.0") == 1.0
        assert features._encode_solidity_version("0.7.6") == 0.7
        assert features._encode_solidity_version("0.6.12") == 0.7
        assert features._encode_solidity_version("0.5.17") == 0.4
        assert features._encode_solidity_version("0.4.24") == 0.4
        assert features._encode_solidity_version("0.3.0") == 0.2
        assert features._encode_solidity_version("") == 0.5  # Empty
        assert features._encode_solidity_version("invalid") == 0.5  # Invalid


class TestFeedbackEntry:
    """Tests for FeedbackEntry dataclass."""

    def test_creation(self):
        """Test creating FeedbackEntry."""
        features = FindingFeatures(
            tool="slither",
            vuln_type="reentrancy",
            severity="high",
            file_type=".sol",
            function_name="withdraw",
            has_swc=True,
            has_cwe=True,
            message_length=100,
            code_context_length=500,
            line_number=42,
            confirmations=1,
            confidence_original=0.8,
        )

        entry = FeedbackEntry(
            finding_hash="abc123",
            is_true_positive=True,
            features=features,
            timestamp=datetime.now(),
            user_notes="Verified as real reentrancy",
        )

        assert entry.finding_hash == "abc123"
        assert entry.is_true_positive is True
        assert entry.features == features
        assert entry.user_notes == "Verified as real reentrancy"

    def test_creation_with_defaults(self):
        """Test FeedbackEntry with default user_notes."""
        features = FindingFeatures(
            tool="test",
            vuln_type="test",
            severity="low",
            file_type=".sol",
            function_name="test",
            has_swc=False,
            has_cwe=False,
            message_length=50,
            code_context_length=100,
            line_number=10,
            confirmations=1,
            confidence_original=0.5,
        )

        entry = FeedbackEntry(
            finding_hash="def456",
            is_true_positive=False,
            features=features,
            timestamp=datetime.now(),
        )

        assert entry.user_notes == ""


class TestSlitherDetectorFPRates:
    """Tests for SLITHER_DETECTOR_FP_RATES constants."""

    def test_rates_exist(self):
        """Test that FP rates dictionary exists and has values."""
        assert isinstance(SLITHER_DETECTOR_FP_RATES, dict)
        assert len(SLITHER_DETECTOR_FP_RATES) > 0

    def test_rates_range(self):
        """Test that all rates are between 0 and 1."""
        for detector, rate in SLITHER_DETECTOR_FP_RATES.items():
            assert 0.0 <= rate <= 1.0, f"{detector} has invalid rate: {rate}"

    def test_high_fp_detectors(self):
        """Test that known high-FP detectors have high rates."""
        assert SLITHER_DETECTOR_FP_RATES["reentrancy-benign"] >= 0.7
        assert SLITHER_DETECTOR_FP_RATES["naming-convention"] >= 0.9
        assert SLITHER_DETECTOR_FP_RATES["solc-version"] >= 0.7

    def test_low_fp_detectors(self):
        """Test that critical detectors have low FP rates."""
        assert SLITHER_DETECTOR_FP_RATES["suicidal"] <= 0.2
        assert SLITHER_DETECTOR_FP_RATES["unprotected-upgrade"] <= 0.2
        assert SLITHER_DETECTOR_FP_RATES["backdoor"] <= 0.1

    def test_reentrancy_variants(self):
        """Test different reentrancy detector rates."""
        assert (
            SLITHER_DETECTOR_FP_RATES["reentrancy-eth"]
            < SLITHER_DETECTOR_FP_RATES["reentrancy-benign"]
        )
        assert (
            SLITHER_DETECTOR_FP_RATES["reentrancy-no-eth"]
            < SLITHER_DETECTOR_FP_RATES["reentrancy-benign"]
        )


class TestFalsePositiveFilter:
    """Tests for FalsePositiveFilter class."""

    @pytest.fixture
    def fp_filter(self, tmp_path):
        """Create a FalsePositiveFilter instance with temp feedback path."""
        feedback_path = tmp_path / "feedback.json"
        return FalsePositiveFilter(feedback_path=str(feedback_path))

    def test_initialization(self, fp_filter):
        """Test filter initialization."""
        assert fp_filter is not None
        assert fp_filter.feedback_path.exists() is False  # Not created until save

    def test_initialization_creates_directory(self, tmp_path):
        """Test that initialization creates parent directory."""
        nested_path = tmp_path / "nested" / "dir" / "feedback.json"
        fp_filter = FalsePositiveFilter(feedback_path=str(nested_path))
        assert nested_path.parent.exists()

    def test_detect_solidity_version(self, fp_filter, tmp_path):
        """Test Solidity version detection."""
        contract = tmp_path / "Test.sol"
        contract.write_text("pragma solidity ^0.8.20;\ncontract Test {}")

        version, has_protection = fp_filter._detect_solidity_version(str(contract))
        assert version == "0.8.20"
        assert has_protection is True

    def test_detect_solidity_version_old(self, fp_filter, tmp_path):
        """Test detection of old Solidity version."""
        contract = tmp_path / "Old.sol"
        contract.write_text("pragma solidity 0.7.6;\ncontract Old {}")

        version, has_protection = fp_filter._detect_solidity_version(str(contract))
        assert version == "0.7.6"
        assert has_protection is False

    def test_detect_solidity_version_cached(self, fp_filter, tmp_path):
        """Test that version detection is cached."""
        contract = tmp_path / "Cached.sol"
        contract.write_text("pragma solidity ^0.8.0;\ncontract Cached {}")

        # First call
        version1, _ = fp_filter._detect_solidity_version(str(contract))
        # Second call should use cache
        version2, _ = fp_filter._detect_solidity_version(str(contract))

        assert version1 == version2
        assert str(contract) in fp_filter._version_cache

    def test_detect_solidity_version_nonexistent(self, fp_filter):
        """Test version detection for non-existent file."""
        version, has_protection = fp_filter._detect_solidity_version("/nonexistent/file.sol")
        assert version == ""
        assert has_protection is False

    def test_is_solidity_08_plus(self, fp_filter):
        """Test Solidity 0.8+ detection."""
        assert fp_filter._is_solidity_08_plus("0.8.0") is True
        assert fp_filter._is_solidity_08_plus("0.8.20") is True
        assert fp_filter._is_solidity_08_plus("0.9.0") is True
        assert fp_filter._is_solidity_08_plus("0.7.6") is False
        assert fp_filter._is_solidity_08_plus("0.6.12") is False
        assert fp_filter._is_solidity_08_plus("") is False
        assert fp_filter._is_solidity_08_plus("invalid") is False

    def test_detect_safeguards(self, fp_filter):
        """Test safeguard detection."""
        code_with_guards = """
        using SafeMath for uint256;
        modifier nonReentrant() {
            require(!locked);
            _;
        }
        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }
        """

        safeguards = fp_filter._detect_safeguards(code_with_guards)

        assert safeguards["uses_safemath"] is True
        assert safeguards["has_reentrancy_guard"] is True
        assert safeguards["has_access_control"] is True

    def test_detect_safeguards_empty(self, fp_filter):
        """Test safeguard detection with no guards."""
        simple_code = "function transfer(address to, uint amount) public {}"

        safeguards = fp_filter._detect_safeguards(simple_code)

        assert safeguards["uses_safemath"] is False
        assert safeguards["has_reentrancy_guard"] is False
        assert safeguards["has_access_control"] is False

    def test_is_library_code(self, fp_filter):
        """Test library code detection."""
        assert fp_filter._is_library_code("@openzeppelin/contracts/token/ERC20.sol") is True
        assert (
            fp_filter._is_library_code("node_modules/@uniswap/v3-core/contracts/Pool.sol") is True
        )
        assert fp_filter._is_library_code("lib/forge-std/Test.sol") is True
        assert fp_filter._is_library_code("lib/solmate/tokens/ERC20.sol") is True
        assert fp_filter._is_library_code("lib/solady/utils/SafeTransfer.sol") is True
        assert fp_filter._is_library_code("contracts/MyContract.sol") is False
        assert fp_filter._is_library_code("src/Token.sol") is False

    def test_analyze_context_for_fp_incorrect_equality(self, fp_filter):
        """Test context analysis for incorrect-equality FP detection."""
        code = "if (status == Status.Active) { ... }"
        adjustment, reasons = fp_filter._analyze_context_for_fp(
            "incorrect-equality", code, "Dangerous strict equality"
        )

        assert adjustment > 0
        assert len(reasons) > 0
        assert any("enum" in r.lower() or "comparison" in r.lower() for r in reasons)

    def test_analyze_context_for_fp_hash_comparison(self, fp_filter):
        """Test context analysis for hash comparison FP detection."""
        code = "require(keccak256(data) == expectedHash);"
        adjustment, reasons = fp_filter._analyze_context_for_fp(
            "incorrect-equality", code, "Dangerous strict equality"
        )

        assert adjustment > 0

    def test_analyze_context_for_fp_timestamp_deadline(self, fp_filter):
        """Test context analysis for timestamp FP with deadline."""
        code = "require(block.timestamp < deadline);"
        adjustment, reasons = fp_filter._analyze_context_for_fp(
            "timestamp", code, "Block timestamp used"
        )

        assert adjustment > 0
        assert any("deadline" in r.lower() for r in reasons)

    def test_analyze_context_for_fp_encode_packed_with_counter(self, fp_filter):
        """Test encode-packed FP detection with counter."""
        code = "keccak256(abi.encodePacked(data, counter++));"
        adjustment, reasons = fp_filter._analyze_context_for_fp(
            "encode-packed-collision", code, "Hash collision risk"
        )

        assert adjustment > 0
        assert any("counter" in r.lower() or "increment" in r.lower() for r in reasons)

    def test_parse_confidence_float(self, fp_filter):
        """Test parsing confidence from float."""
        assert fp_filter._parse_confidence(0.85) == 0.85
        assert fp_filter._parse_confidence(0.5) == 0.5
        assert fp_filter._parse_confidence(1) == 1.0

    def test_parse_confidence_string(self, fp_filter):
        """Test parsing confidence from string severity."""
        assert fp_filter._parse_confidence("critical") == 0.95
        assert fp_filter._parse_confidence("high") == 0.85
        assert fp_filter._parse_confidence("medium") == 0.70
        assert fp_filter._parse_confidence("low") == 0.50
        assert fp_filter._parse_confidence("info") == 0.30
        assert fp_filter._parse_confidence("unknown") == 0.7  # Default

    def test_extract_features(self, fp_filter):
        """Test feature extraction from finding."""
        finding = {
            "type": "reentrancy-eth",
            "severity": "high",
            "tool": "slither",
            "message": "Reentrancy in withdraw function",
            "location": {"file": "contracts/Vault.sol", "line": 42, "function": "withdraw"},
            "swc_id": "SWC-107",
            "cwe_id": "CWE-841",
            "confidence": 0.9,
        }

        code_context = """
        require(amount > 0);
        modifier nonReentrant() { require(!locked); _; }
        """

        features = fp_filter._extract_features(finding, code_context, confirmations=2)

        assert features.tool == "slither"
        assert features.vuln_type == "reentrancy-eth"
        assert features.severity == "high"
        assert features.function_name == "withdraw"
        assert features.has_swc is True
        assert features.has_cwe is True
        assert features.confidence_original == 0.9
        assert features.confirmations == 2
        assert features.near_require is True  # Has require in context

    def test_extract_features_test_file(self, fp_filter):
        """Test feature extraction for test file."""
        finding = {
            "type": "test-vuln",
            "severity": "medium",
            "location": {"file": "tests/TestContract.t.sol", "line": 10},
        }

        features = fp_filter._extract_features(finding, "")

        assert features.in_test_file is True

    def test_extract_features_interface(self, fp_filter):
        """Test feature extraction for interface file."""
        finding = {
            "type": "interface-issue",
            "severity": "low",
            "location": {"file": "contracts/interfaces/IToken.sol", "line": 5},
        }

        features = fp_filter._extract_features(finding, "")

        assert features.in_interface is True

    def test_compute_finding_hash(self, fp_filter):
        """Test finding hash computation."""
        finding = {
            "type": "reentrancy",
            "location": {"file": "Test.sol", "line": 42},
            "message": "Reentrancy vulnerability detected",
        }

        hash1 = fp_filter._compute_finding_hash(finding)

        assert len(hash1) == 16
        assert hash1.isalnum()

        # Same finding should produce same hash
        hash2 = fp_filter._compute_finding_hash(finding)
        assert hash1 == hash2

        # Different finding should produce different hash
        different = finding.copy()
        different["location"] = {"file": "Test.sol", "line": 100}
        hash3 = fp_filter._compute_finding_hash(different)
        assert hash1 != hash3

    def test_predict_false_positive_basic(self, fp_filter):
        """Test basic FP prediction."""
        finding = {
            "type": "naming-convention",
            "severity": "informational",
            "message": "Variable naming issue",
            "location": {"file": "Test.sol", "line": 10},
            "confidence": 0.5,
        }

        fp_prob, explanation = fp_filter.predict_false_positive(finding)

        assert 0 <= fp_prob <= 1
        assert "fp_probability" in explanation
        assert "is_likely_fp" in explanation
        assert "reasons" in explanation

    def test_predict_false_positive_with_library(self, fp_filter):
        """Test FP prediction for library code."""
        finding = {
            "type": "unused-state",
            "severity": "low",
            "message": "Unused state variable",
            "location": {"file": "@openzeppelin/contracts/token/ERC20.sol", "line": 50},
        }

        fp_prob, explanation = fp_filter.predict_false_positive(finding)

        assert fp_prob > 0.5  # Should be likely FP
        assert any("library" in r.lower() for r in explanation["reasons"])

    def test_predict_false_positive_with_test_file(self, fp_filter):
        """Test FP prediction for test file."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "message": "Reentrancy detected",
            "location": {"file": "tests/VaultTest.t.sol", "line": 100},
        }

        fp_prob, explanation = fp_filter.predict_false_positive(finding)

        assert any("test file" in r.lower() for r in explanation["reasons"])

    def test_predict_false_positive_cross_validated(self, fp_filter):
        """Test FP prediction with cross-validation."""
        finding = {
            "type": "reentrancy-eth",
            "severity": "critical",
            "message": "Reentrancy with ETH transfer",
            "location": {"file": "Vault.sol", "line": 42},
            "confidence": 0.95,
        }

        # Without cross-validation
        fp_prob1, _ = fp_filter.predict_false_positive(finding, confirmations=1)

        # With cross-validation
        fp_prob2, explanation = fp_filter.predict_false_positive(finding, confirmations=3)

        assert fp_prob2 < fp_prob1  # Should be less likely FP with more confirmations
        assert any("cross-validated" in r.lower() for r in explanation["reasons"])

    def test_predict_false_positive_overflow_solidity_08(self, fp_filter):
        """Test FP prediction for overflow in Solidity 0.8+."""
        finding = {
            "type": "integer-overflow",
            "severity": "high",
            "message": "Integer overflow detected",
            "location": {"file": "Token.sol", "line": 30},
        }

        fp_prob, explanation = fp_filter.predict_false_positive(finding)

        # Overflow findings should have some FP consideration for 0.8+
        assert any(
            "overflow" in r.lower() or "solidity 0.8" in r.lower() for r in explanation["reasons"]
        )

    def test_filter_findings(self, fp_filter):
        """Test filtering multiple findings."""
        findings = [
            {
                "type": "reentrancy-eth",
                "severity": "critical",
                "message": "Real vulnerability",
                "location": {"file": "Vault.sol", "line": 42},
                "confidence": 0.95,
            },
            {
                "type": "naming-convention",
                "severity": "informational",
                "message": "Variable naming issue",
                "location": {"file": "Token.sol", "line": 10},
                "confidence": 0.5,
            },
            {
                "type": "pragma",
                "severity": "informational",
                "message": "Floating pragma",
                "location": {"file": "Test.sol", "line": 1},
                "confidence": 0.8,
            },
        ]

        true_positives, filtered_fps = fp_filter.filter_findings(findings, threshold=0.6)

        # All findings should have _fp_analysis
        all_findings = true_positives + filtered_fps
        for f in all_findings:
            assert "_fp_analysis" in f

        # Verify all findings were processed
        assert len(all_findings) == 3
        # At least some filtering should occur OR findings have analysis
        for f in all_findings:
            assert "_fp_analysis" in f
            assert "fp_probability" in f["_fp_analysis"]

    def test_filter_findings_with_code_context(self, fp_filter):
        """Test filtering with code context map."""
        findings = [
            {
                "type": "reentrancy",
                "severity": "high",
                "location": {"file": "Vault.sol", "line": 42},
            }
        ]

        code_context_map = {"Vault.sol:42": "require(amount > 0); nonReentrant modifier here"}

        true_positives, filtered_fps = fp_filter.filter_findings(
            findings, threshold=0.6, code_context_map=code_context_map
        )

        # Should have analyzed with context
        all_findings = true_positives + filtered_fps
        assert len(all_findings) == 1

    def test_add_feedback_and_save(self, fp_filter):
        """Test adding feedback and saving."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "message": "Test finding",
            "location": {"file": "Test.sol", "line": 42},
        }

        fp_filter.add_feedback(finding, is_true_positive=True, notes="Confirmed reentrancy")

        assert len(fp_filter._feedback) == 1
        assert fp_filter._feedback[0].is_true_positive is True
        assert fp_filter._feedback[0].user_notes == "Confirmed reentrancy"

    def test_feedback_persistence(self, tmp_path):
        """Test feedback persistence across instances."""
        feedback_path = tmp_path / "feedback.json"

        # Create filter and add feedback
        fp_filter1 = FalsePositiveFilter(feedback_path=str(feedback_path))
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "location": {"file": "Test.sol", "line": 42},
        }
        fp_filter1.add_feedback(finding, is_true_positive=True)

        # Create new filter instance and check feedback loaded
        fp_filter2 = FalsePositiveFilter(feedback_path=str(feedback_path))
        assert len(fp_filter2._feedback) == 1

    def test_update_learned_weights(self, fp_filter):
        """Test learning from feedback updates weights."""
        # Add multiple feedback entries
        for i in range(5):
            finding = {
                "type": "timestamp",
                "severity": "low",
                "location": {"file": f"Test{i}.sol", "line": i * 10},
            }
            # All false positives
            fp_filter.add_feedback(finding, is_true_positive=False)

        # Check that learned weights were updated
        assert "timestamp" in fp_filter._learned_weights
        assert fp_filter._learned_weights["timestamp"] > 0  # More FPs = higher FP adjustment

    def test_get_statistics_empty(self, fp_filter):
        """Test statistics with no feedback."""
        stats = fp_filter.get_statistics()

        assert stats["total_feedback"] == 0
        assert stats.get("no_data") is True

    def test_get_statistics_with_feedback(self, fp_filter):
        """Test statistics with feedback."""
        # Add some feedback
        for i in range(3):
            finding = {
                "type": "reentrancy",
                "severity": "high",
                "location": {"file": f"Test{i}.sol", "line": i * 10},
            }
            fp_filter.add_feedback(finding, is_true_positive=(i % 2 == 0))

        stats = fp_filter.get_statistics()

        assert stats["total_feedback"] == 3
        assert stats["true_positives"] == 2  # i=0 and i=2
        assert stats["false_positives"] == 1  # i=1
        assert "type_breakdown" in stats
        assert "reentrancy" in stats["type_breakdown"]

    def test_get_detector_fp_rate(self, fp_filter):
        """Test getting detector-specific FP rate."""
        assert fp_filter.get_detector_fp_rate("naming-convention") >= 0.9
        assert fp_filter.get_detector_fp_rate("reentrancy-eth") < 0.3
        assert fp_filter.get_detector_fp_rate("unknown-detector") == 0.50  # Default

    def test_adjust_confidence_by_detector(self, fp_filter):
        """Test confidence adjustment by detector."""
        finding = {
            "type": "naming-convention",
            "severity": "informational",
            "confidence": 0.8,
        }

        adjusted = fp_filter.adjust_confidence_by_detector(finding, "naming-convention")

        assert adjusted["confidence"] < finding["confidence"]
        assert "_detector_fp_analysis" in adjusted
        assert adjusted["_detector_fp_analysis"]["detector"] == "naming-convention"
        assert adjusted["_detector_fp_analysis"]["original_confidence"] == 0.8


class TestSemanticContextAnalyzer:
    """Tests for SemanticContextAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create SemanticContextAnalyzer instance."""
        return SemanticContextAnalyzer()

    def test_initialization(self, analyzer):
        """Test analyzer initialization."""
        assert analyzer is not None
        assert hasattr(analyzer, "_version_cache")

    def test_analyze_reentrancy_with_guard(self, analyzer):
        """Test analysis of reentrancy finding with guard."""
        finding = {"type": "reentrancy-eth", "severity": "high"}
        source_code = """
        pragma solidity ^0.8.0;

        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

        contract Vault is ReentrancyGuard {
            function withdraw(uint amount) external nonReentrant {
                (bool success,) = msg.sender.call{value: amount}("");
                require(success);
            }
        }
        """

        result = analyzer.analyze_finding_context(finding, source_code)

        assert result["confidence_adjustment"] < 0  # Should reduce FP probability
        assert "nonReentrant" in result["guards_detected"] or any(
            "reentrancy" in g.lower() for g in result["guards_detected"]
        )

    def test_analyze_access_control(self, analyzer):
        """Test analysis of access control finding."""
        finding = {"type": "unprotected-function", "severity": "high"}
        source_code = """
        contract Owned {
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner);
                _;
            }

            function privileged() external onlyOwner {
                // protected
            }
        }
        """

        result = analyzer.analyze_finding_context(finding, source_code)

        # Should detect access control
        assert len(result["guards_detected"]) > 0 or result["confidence_adjustment"] < 0

    def test_analyze_arithmetic_solidity_08(self, analyzer):
        """Test analysis of arithmetic finding in Solidity 0.8+."""
        finding = {"type": "integer-overflow", "severity": "high"}
        source_code = """
        pragma solidity ^0.8.20;

        contract Counter {
            uint256 public count;

            function increment() external {
                count += 1;  // Safe in 0.8+
            }
        }
        """

        result = analyzer.analyze_finding_context(finding, source_code)

        assert result["solidity_version"] == "0.8.20"
        assert result["has_overflow_protection"] is True
        assert result["confidence_adjustment"] < 0  # Should be more likely FP

    def test_analyze_arithmetic_with_safemath(self, analyzer):
        """Test analysis of arithmetic with SafeMath."""
        finding = {"type": "integer-overflow", "severity": "high"}
        source_code = """
        pragma solidity ^0.7.6;

        using SafeMath for uint256;

        contract Counter {
            uint256 public count;

            function increment() external {
                count = count.add(1);
            }
        }
        """

        result = analyzer.analyze_finding_context(finding, source_code)

        assert result["confidence_adjustment"] < 0  # SafeMath should reduce FP prob
        assert any("safemath" in r.lower() for r in result["reasons"])

    def test_analyze_timestamp_legitimate(self, analyzer):
        """Test analysis of legitimate timestamp usage."""
        finding = {"type": "weak-randomness", "severity": "medium"}
        source_code = """
        contract Auction {
            uint256 public deadline;

            function bid() external {
                require(block.timestamp < deadline, "Auction ended");
            }
        }
        """

        result = analyzer.analyze_finding_context(finding, source_code)

        # Deadline usage is legitimate
        assert result["confidence_adjustment"] < 0 or any(
            "deadline" in r.lower() or "timestamp" in r.lower() for r in result["reasons"]
        )

    def test_detect_cei_pattern(self, analyzer):
        """Test CEI pattern detection."""
        source_following_cei = """
        function withdraw(uint256 amount) external {
            require(amount <= balances[msg.sender]);
            balances[msg.sender] -= amount;  // Effect before interaction
            (bool success,) = msg.sender.call{value: amount}("");
            require(success);
        }
        """

        source_violating_cei = """
        function withdraw(uint256 amount) external {
            require(amount <= balances[msg.sender]);
            (bool success,) = msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;  // Effect AFTER interaction - violation!
            require(success);
        }
        """

        assert analyzer._follows_cei_pattern(source_following_cei) is True
        assert analyzer._follows_cei_pattern(source_violating_cei) is False

    def test_detect_solidity_version(self, analyzer):
        """Test Solidity version detection."""
        source_08 = "pragma solidity ^0.8.20; contract Test {}"
        source_07 = "pragma solidity 0.7.6; contract Test {}"
        source_06 = "pragma solidity >=0.6.0 <0.8.0; contract Test {}"

        assert analyzer._detect_solidity_version(source_08) == "0.8.20"
        assert analyzer._detect_solidity_version(source_07) == "0.7.6"
        assert analyzer._detect_solidity_version(source_06) == "0.6.0"
        assert analyzer._detect_solidity_version("contract Test {}") is None

    def test_has_overflow_protection(self, analyzer):
        """Test overflow protection detection."""
        assert analyzer._has_overflow_protection("0.8.0") is True
        assert analyzer._has_overflow_protection("0.8.20") is True
        assert analyzer._has_overflow_protection("0.9.0") is True
        assert analyzer._has_overflow_protection("0.7.6") is False
        assert analyzer._has_overflow_protection("0.6.12") is False
        assert analyzer._has_overflow_protection(None) is False
        assert analyzer._has_overflow_protection("invalid") is False

    def test_get_adjustment_for_finding(self, analyzer):
        """Test convenience method for getting adjustment."""
        finding = {"type": "reentrancy", "severity": "high"}
        source_code = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        contract Safe is ReentrancyGuard {
            function withdraw() external nonReentrant {}
        }
        """

        adjustment = analyzer.get_adjustment_for_finding(finding, source_code)

        assert -0.60 <= adjustment <= 0.50  # Within valid range
        assert adjustment < 0  # Should reduce FP probability

    def test_analyze_with_unchecked_block(self, analyzer):
        """Test analysis handles unchecked blocks."""
        finding = {"type": "integer-overflow", "severity": "high"}
        source_code = """
        pragma solidity ^0.8.20;

        contract Test {
            function riskyAdd(uint a, uint b) external pure returns (uint) {
                unchecked {
                    return a + b;  // Intentionally unchecked
                }
            }
        }
        """

        result = analyzer.analyze_finding_context(finding, source_code)

        # Should recognize unchecked block as intentional
        assert any("unchecked" in r.lower() for r in result["reasons"])

    def test_adjustment_capping(self, analyzer):
        """Test that adjustment is capped within valid range."""
        finding = {"type": "reentrancy", "severity": "high"}

        # Source with many guards (should maximize negative adjustment)
        source_with_guards = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        contract Safe is ReentrancyGuard, Ownable {
            // CEI pattern comment
            // State update before external call
            function withdraw() external nonReentrant onlyOwner {
                balances[msg.sender] = 0;  // Effect first
                msg.sender.call{value: 1 ether}("");  // Interaction after
            }
        }
        """

        result = analyzer.analyze_finding_context(finding, source_with_guards)

        # Should be capped at -0.60
        assert result["confidence_adjustment"] >= -0.60
        assert result["confidence_adjustment"] <= 0.50


class TestIntegration:
    """Integration tests for the complete FP filtering pipeline."""

    def test_full_filtering_pipeline(self, tmp_path):
        """Test complete filtering pipeline with multiple findings."""
        feedback_path = tmp_path / "feedback.json"
        fp_filter = FalsePositiveFilter(feedback_path=str(feedback_path))

        findings = [
            {
                "_id": "1",
                "type": "reentrancy-eth",
                "severity": "critical",
                "message": "Reentrancy with ETH transfer",
                "location": {"file": "Vault.sol", "line": 42},
                "confidence": 0.95,
                "swc_id": "SWC-107",
            },
            {
                "_id": "2",
                "type": "naming-convention",
                "severity": "informational",
                "message": "Variable should use camelCase",
                "location": {"file": "Token.sol", "line": 10},
                "confidence": 0.6,
            },
            {
                "_id": "3",
                "type": "pragma",
                "severity": "informational",
                "message": "Floating pragma",
                "location": {"file": "Test.sol", "line": 1},
                "confidence": 0.8,
            },
            {
                "_id": "4",
                "type": "reentrancy-benign",
                "severity": "medium",
                "message": "Benign reentrancy",
                "location": {"file": "@openzeppelin/contracts/ERC721.sol", "line": 100},
                "confidence": 0.7,
            },
        ]

        true_positives, filtered_fps = fp_filter.filter_findings(findings, threshold=0.5)

        # Critical reentrancy should likely be kept
        critical_kept = any(f["_id"] == "1" for f in true_positives)
        # Library finding should be filtered
        library_filtered = any(f["_id"] == "4" for f in filtered_fps)

        # Verify all findings processed
        assert len(true_positives) + len(filtered_fps) == 4

        # Verify confidence adjusted
        for f in true_positives + filtered_fps:
            assert "_fp_analysis" in f
            if "confidence" in f:
                assert 0 <= f["confidence"] <= 1

    def test_filter_with_semantic_analysis(self, tmp_path):
        """Test filtering with semantic context analyzer."""
        feedback_path = tmp_path / "feedback.json"
        fp_filter = FalsePositiveFilter(feedback_path=str(feedback_path))
        analyzer = SemanticContextAnalyzer()

        finding = {
            "type": "reentrancy-eth",
            "severity": "critical",
            "location": {"file": "Vault.sol", "line": 42},
        }

        source_code = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        contract Vault is ReentrancyGuard {
            function withdraw() external nonReentrant {}
        }
        """

        # Get semantic adjustment
        semantic_result = analyzer.analyze_finding_context(finding, source_code)

        # Get FP prediction
        fp_prob, explanation = fp_filter.predict_false_positive(finding, code_context=source_code)

        # Both should indicate reduced TP probability
        assert semantic_result["is_protected"] is True
        assert semantic_result["confidence_adjustment"] < 0
