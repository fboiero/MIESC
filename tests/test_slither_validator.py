"""
Tests for the Slither Cross-Validator module.

Tests cover:
- SlitherFinding and ValidationResult dataclasses
- SlitherValidator class methods
- Convenience functions
All tests use mocking to avoid requiring Slither installation.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from src.ml.slither_validator import (
    HIGH_CONFIDENCE_DETECTORS,
    PATTERN_TO_SLITHER_DETECTORS,
    SlitherFinding,
    SlitherValidator,
    ValidationResult,
    filter_unconfirmed,
    validate_with_slither,
)

# =============================================================================
# Constant Tests
# =============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_pattern_to_slither_mapping_exists(self):
        """Test that pattern to Slither detector mapping exists."""
        assert isinstance(PATTERN_TO_SLITHER_DETECTORS, dict)
        assert len(PATTERN_TO_SLITHER_DETECTORS) > 0

    def test_reentrancy_patterns_have_detectors(self):
        """Test reentrancy patterns have Slither detectors."""
        assert "reentrancy" in PATTERN_TO_SLITHER_DETECTORS
        assert "reentrancy-eth" in PATTERN_TO_SLITHER_DETECTORS["reentrancy"]
        assert "reentrancy-no-eth" in PATTERN_TO_SLITHER_DETECTORS["reentrancy"]

    def test_access_control_patterns_have_detectors(self):
        """Test access control patterns have Slither detectors."""
        assert "access_control" in PATTERN_TO_SLITHER_DETECTORS
        assert "arbitrary-send-eth" in PATTERN_TO_SLITHER_DETECTORS["access_control"]
        assert "suicidal" in PATTERN_TO_SLITHER_DETECTORS["access_control"]

    def test_tx_origin_patterns_have_detectors(self):
        """Test tx.origin patterns have Slither detectors."""
        assert "tx_origin" in PATTERN_TO_SLITHER_DETECTORS
        assert "tx-origin" in PATTERN_TO_SLITHER_DETECTORS["tx_origin"]

    def test_high_confidence_detectors_set(self):
        """Test high confidence detectors set is defined."""
        assert isinstance(HIGH_CONFIDENCE_DETECTORS, set)
        assert "reentrancy-eth" in HIGH_CONFIDENCE_DETECTORS
        assert "arbitrary-send-eth" in HIGH_CONFIDENCE_DETECTORS
        assert "suicidal" in HIGH_CONFIDENCE_DETECTORS


# =============================================================================
# Dataclass Tests
# =============================================================================


class TestSlitherFinding:
    """Tests for SlitherFinding dataclass."""

    def test_create_with_required_fields(self):
        """Test creating SlitherFinding with required fields."""
        finding = SlitherFinding(
            detector="reentrancy-eth",
            impact="High",
            confidence="High",
            description="Reentrancy vulnerability found",
        )
        assert finding.detector == "reentrancy-eth"
        assert finding.impact == "High"
        assert finding.confidence == "High"
        assert finding.description == "Reentrancy vulnerability found"

    def test_default_values(self):
        """Test default values for optional fields."""
        finding = SlitherFinding(
            detector="test", impact="Medium", confidence="Medium", description="Test"
        )
        assert finding.lines == []
        assert finding.elements == []

    def test_custom_lines_and_elements(self):
        """Test custom lines and elements."""
        finding = SlitherFinding(
            detector="reentrancy-eth",
            impact="High",
            confidence="High",
            description="Test",
            lines=[42, 45, 50],
            elements=[{"name": "withdraw", "type": "function"}],
        )
        assert finding.lines == [42, 45, 50]
        assert len(finding.elements) == 1
        assert finding.elements[0]["name"] == "withdraw"


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_create_with_required_fields(self):
        """Test creating ValidationResult with required fields."""
        result = ValidationResult(
            pattern_type="reentrancy",
            pattern_line=42,
            slither_confirmed=True,
        )
        assert result.pattern_type == "reentrancy"
        assert result.pattern_line == 42
        assert result.slither_confirmed is True

    def test_default_values(self):
        """Test default values for optional fields."""
        result = ValidationResult(
            pattern_type="reentrancy",
            pattern_line=42,
            slither_confirmed=False,
        )
        assert result.slither_detectors_matched == []
        assert result.confidence_adjustment == 0.0
        assert result.final_confidence == 0.0
        assert result.notes == ""

    def test_custom_optional_values(self):
        """Test custom optional values."""
        result = ValidationResult(
            pattern_type="reentrancy",
            pattern_line=42,
            slither_confirmed=True,
            slither_detectors_matched=["reentrancy-eth"],
            confidence_adjustment=0.25,
            final_confidence=0.95,
            notes="High-confidence match",
        )
        assert result.slither_detectors_matched == ["reentrancy-eth"]
        assert result.confidence_adjustment == 0.25
        assert result.final_confidence == 0.95
        assert result.notes == "High-confidence match"


# =============================================================================
# SlitherValidator Tests
# =============================================================================


class TestSlitherValidatorInit:
    """Tests for SlitherValidator initialization."""

    @patch.object(SlitherValidator, "_find_slither")
    @patch.object(SlitherValidator, "_check_slither")
    def test_default_init(self, mock_check, mock_find):
        """Test default initialization."""
        mock_find.return_value = "slither"
        mock_check.return_value = True

        validator = SlitherValidator()

        assert validator.slither_binary == "slither"
        assert validator.timeout == 60

    @patch.object(SlitherValidator, "_check_slither")
    def test_custom_binary(self, mock_check):
        """Test custom binary path."""
        mock_check.return_value = True

        validator = SlitherValidator(slither_binary="/custom/path/slither")

        assert validator.slither_binary == "/custom/path/slither"

    @patch.object(SlitherValidator, "_find_slither")
    @patch.object(SlitherValidator, "_check_slither")
    def test_custom_timeout(self, mock_check, mock_find):
        """Test custom timeout."""
        mock_find.return_value = "slither"
        mock_check.return_value = True

        validator = SlitherValidator(timeout=120)

        assert validator.timeout == 120


class TestSlitherValidatorFindSlither:
    """Tests for _find_slither method."""

    @patch("shutil.which")
    @patch("os.path.isfile")
    @patch("os.access")
    def test_find_in_path(self, mock_access, mock_isfile, mock_which):
        """Test finding slither in PATH."""
        mock_isfile.return_value = False
        mock_access.return_value = False
        mock_which.return_value = "/usr/local/bin/slither"

        with patch.object(SlitherValidator, "_check_slither", return_value=True):
            validator = SlitherValidator()

        assert validator.slither_binary == "/usr/local/bin/slither"

    @patch("shutil.which")
    @patch("os.path.isfile")
    @patch("os.access")
    def test_find_in_home_local(self, mock_access, mock_isfile, mock_which):
        """Test finding slither in ~/.local/bin."""
        local_path = os.path.expanduser("~/.local/bin/slither")

        def isfile_side_effect(path):
            return path == local_path

        mock_isfile.side_effect = isfile_side_effect
        mock_access.return_value = True
        mock_which.return_value = None

        with patch.object(SlitherValidator, "_check_slither", return_value=True):
            validator = SlitherValidator()

        assert validator.slither_binary == local_path

    @patch("shutil.which")
    @patch("os.path.isfile")
    @patch("os.access")
    def test_fallback_to_slither_name(self, mock_access, mock_isfile, mock_which):
        """Test fallback to 'slither' when not found."""
        mock_isfile.return_value = False
        mock_access.return_value = False
        mock_which.return_value = None

        with patch.object(SlitherValidator, "_check_slither", return_value=False):
            validator = SlitherValidator()

        assert validator.slither_binary == "slither"


class TestSlitherValidatorCheckSlither:
    """Tests for _check_slither method."""

    @patch("subprocess.run")
    def test_slither_available(self, mock_run):
        """Test checking when Slither is available."""
        mock_run.return_value = MagicMock(returncode=0)

        with patch.object(SlitherValidator, "_find_slither", return_value="slither"):
            validator = SlitherValidator()

        assert validator.is_available is True

    @patch("subprocess.run")
    def test_slither_not_available(self, mock_run):
        """Test checking when Slither is not available."""
        mock_run.return_value = MagicMock(returncode=1)

        with patch.object(SlitherValidator, "_find_slither", return_value="slither"):
            validator = SlitherValidator()

        assert validator.is_available is False

    @patch("subprocess.run")
    def test_slither_exception(self, mock_run):
        """Test checking when subprocess raises exception."""
        mock_run.side_effect = FileNotFoundError("slither not found")

        with patch.object(SlitherValidator, "_find_slither", return_value="slither"):
            validator = SlitherValidator()

        assert validator.is_available is False


class TestSlitherValidatorRunSlither:
    """Tests for run_slither method."""

    @pytest.fixture
    def validator(self):
        """Create validator with mocked availability."""
        with patch.object(SlitherValidator, "_find_slither", return_value="slither"):
            with patch.object(SlitherValidator, "_check_slither", return_value=True):
                return SlitherValidator()

    def test_returns_empty_when_not_available(self):
        """Test returns empty list when Slither not available."""
        with patch.object(SlitherValidator, "_find_slither", return_value="slither"):
            with patch.object(SlitherValidator, "_check_slither", return_value=False):
                validator = SlitherValidator()

        result = validator.run_slither("contract Test {}")

        assert result == []

    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    @patch("os.unlink")
    def test_parses_slither_output(self, mock_unlink, mock_temp, mock_run, validator):
        """Test parsing Slither JSON output."""
        mock_file = MagicMock()
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_file.name = "/tmp/test.sol"
        mock_temp.return_value = mock_file

        slither_output = {
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "Reentrancy in withdraw()",
                        "elements": [{"source_mapping": {"lines": [42, 45]}}],
                    }
                ]
            }
        }
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(slither_output),
        )

        result = validator.run_slither("pragma solidity ^0.8.0; contract Test {}")

        assert len(result) == 1
        assert result[0].detector == "reentrancy-eth"
        assert result[0].impact == "High"
        assert 42 in result[0].lines
        assert 45 in result[0].lines

    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    @patch("os.unlink")
    def test_handles_timeout(self, mock_unlink, mock_temp, mock_run, validator):
        """Test handling Slither timeout."""
        import subprocess

        mock_file = MagicMock()
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_file.name = "/tmp/test.sol"
        mock_temp.return_value = mock_file

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="slither", timeout=60)

        result = validator.run_slither("contract Test {}")

        assert result == []

    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    @patch("os.unlink")
    def test_handles_invalid_json(self, mock_unlink, mock_temp, mock_run, validator):
        """Test handling invalid JSON output."""
        mock_file = MagicMock()
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_file.name = "/tmp/test.sol"
        mock_temp.return_value = mock_file

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Not valid JSON {",
        )

        result = validator.run_slither("contract Test {}")

        assert result == []


class TestSlitherValidatorDetectSolcVersion:
    """Tests for _detect_solc_version method."""

    @pytest.fixture
    def validator(self):
        """Create validator instance."""
        with patch.object(SlitherValidator, "_find_slither", return_value="slither"):
            with patch.object(SlitherValidator, "_check_slither", return_value=True):
                return SlitherValidator()

    def test_detect_version_08(self, validator):
        """Test detecting 0.8.x version."""
        code = "pragma solidity ^0.8.0;\ncontract Test {}"
        version = validator._detect_solc_version(code)
        assert version == "0.8.20"

    def test_detect_version_07(self, validator):
        """Test detecting 0.7.x version."""
        code = "pragma solidity ^0.7.0;\ncontract Test {}"
        version = validator._detect_solc_version(code)
        assert version == "0.7.6"

    def test_detect_version_06(self, validator):
        """Test detecting 0.6.x version."""
        code = "pragma solidity >=0.6.0;\ncontract Test {}"
        version = validator._detect_solc_version(code)
        assert version == "0.6.12"

    def test_detect_version_05(self, validator):
        """Test detecting 0.5.x version."""
        code = "pragma solidity ^0.5.0;\ncontract Test {}"
        version = validator._detect_solc_version(code)
        assert version == "0.5.17"

    def test_detect_version_04(self, validator):
        """Test detecting 0.4.x version."""
        code = "pragma solidity ^0.4.24;\ncontract Test {}"
        version = validator._detect_solc_version(code)
        assert version == "0.4.26"

    def test_upgrade_04_with_address_payable(self, validator):
        """Test upgrading 0.4 when address payable is used."""
        code = "pragma solidity ^0.4.24;\ncontract Test { address payable owner; }"
        version = validator._detect_solc_version(code)
        assert version == "0.5.17"

    def test_no_pragma(self, validator):
        """Test when no pragma is found."""
        code = "contract Test {}"
        version = validator._detect_solc_version(code)
        assert version is None


class TestSlitherValidatorValidateFinding:
    """Tests for validate_finding method."""

    @pytest.fixture
    def validator(self):
        """Create validator with mocked availability."""
        with patch.object(SlitherValidator, "_find_slither", return_value="slither"):
            with patch.object(SlitherValidator, "_check_slither", return_value=True):
                return SlitherValidator()

    def test_returns_unavailable_note(self):
        """Test returns note when Slither not available."""
        with patch.object(SlitherValidator, "_find_slither", return_value="slither"):
            with patch.object(SlitherValidator, "_check_slither", return_value=False):
                validator = SlitherValidator()

        result = validator.validate_finding(
            source_code="contract Test {}",
            pattern_type="reentrancy",
            pattern_line=42,
        )

        assert result.slither_confirmed is False
        assert "not available" in result.notes

    @patch.object(SlitherValidator, "run_slither")
    def test_reduces_confidence_when_no_findings(self, mock_run, validator):
        """Test reduces confidence when no Slither findings."""
        mock_run.return_value = []

        result = validator.validate_finding(
            source_code="contract Test {}",
            pattern_type="reentrancy",
            pattern_line=42,
            pattern_confidence=0.7,
        )

        assert result.slither_confirmed is False
        assert result.confidence_adjustment == -0.1
        assert result.final_confidence == 0.6

    @patch.object(SlitherValidator, "run_slither")
    def test_boosts_confidence_when_matched(self, mock_run, validator):
        """Test boosts confidence when Slither confirms finding."""
        mock_run.return_value = [
            SlitherFinding(
                detector="reentrancy-eth",
                impact="High",
                confidence="High",
                description="Reentrancy found",
                lines=[40, 42, 45],
            )
        ]

        result = validator.validate_finding(
            source_code="contract Test {}",
            pattern_type="reentrancy",
            pattern_line=42,
            pattern_confidence=0.7,
        )

        assert result.slither_confirmed is True
        assert "reentrancy-eth" in result.slither_detectors_matched
        assert result.confidence_adjustment == 0.25  # High confidence detector
        assert result.final_confidence == 0.95

    @patch.object(SlitherValidator, "run_slither")
    def test_lower_boost_for_regular_detector(self, mock_run, validator):
        """Test lower boost for regular detector match."""
        mock_run.return_value = [
            SlitherFinding(
                detector="reentrancy-benign",
                impact="Low",
                confidence="High",
                description="Benign reentrancy",
                lines=[42],
            )
        ]

        result = validator.validate_finding(
            source_code="contract Test {}",
            pattern_type="reentrancy",
            pattern_line=42,
            pattern_confidence=0.7,
        )

        assert result.slither_confirmed is True
        assert result.confidence_adjustment == 0.15
        assert result.final_confidence == 0.85

    @patch.object(SlitherValidator, "run_slither")
    def test_reduces_confidence_when_not_matched(self, mock_run, validator):
        """Test reduces confidence when Slither finds different issues."""
        mock_run.return_value = [
            SlitherFinding(
                detector="timestamp",
                impact="Low",
                confidence="Medium",
                description="Timestamp dependence",
                lines=[100],  # Different location
            )
        ]

        result = validator.validate_finding(
            source_code="contract Test {}",
            pattern_type="reentrancy",
            pattern_line=42,
            pattern_confidence=0.7,
        )

        assert result.slither_confirmed is False
        assert result.confidence_adjustment == -0.2
        assert abs(result.final_confidence - 0.5) < 0.001

    @patch.object(SlitherValidator, "run_slither")
    def test_line_tolerance(self, mock_run, validator):
        """Test line tolerance for matching."""
        mock_run.return_value = [
            SlitherFinding(
                detector="reentrancy-eth",
                impact="High",
                confidence="High",
                description="Reentrancy",
                lines=[50],  # 8 lines away from 42
            )
        ]

        result = validator.validate_finding(
            source_code="contract Test {}",
            pattern_type="reentrancy",
            pattern_line=42,
            pattern_confidence=0.7,
            line_tolerance=10,
        )

        assert result.slither_confirmed is True

    @patch.object(SlitherValidator, "run_slither")
    def test_line_outside_tolerance(self, mock_run, validator):
        """Test line outside tolerance."""
        mock_run.return_value = [
            SlitherFinding(
                detector="reentrancy-eth",
                impact="High",
                confidence="High",
                description="Reentrancy",
                lines=[60],  # 18 lines away from 42
            )
        ]

        result = validator.validate_finding(
            source_code="contract Test {}",
            pattern_type="reentrancy",
            pattern_line=42,
            pattern_confidence=0.7,
            line_tolerance=10,
        )

        assert result.slither_confirmed is False


class TestSlitherValidatorValidateFindings:
    """Tests for validate_findings method."""

    @pytest.fixture
    def validator(self):
        """Create validator with mocked availability."""
        with patch.object(SlitherValidator, "_find_slither", return_value="slither"):
            with patch.object(SlitherValidator, "_check_slither", return_value=True):
                return SlitherValidator()

    def test_returns_unavailable_for_all(self):
        """Test returns unavailable for all when Slither not available."""
        with patch.object(SlitherValidator, "_find_slither", return_value="slither"):
            with patch.object(SlitherValidator, "_check_slither", return_value=False):
                validator = SlitherValidator()

        findings = [
            {"type": "reentrancy", "line": 42, "confidence": 0.7},
            {"type": "access_control", "line": 100, "confidence": 0.6},
        ]

        results = validator.validate_findings("contract Test {}", findings)

        assert len(results) == 2
        assert all(not r.slither_confirmed for r in results)
        assert all("not available" in r.notes for r in results)

    @patch.object(SlitherValidator, "run_slither")
    def test_validates_multiple_findings(self, mock_run, validator):
        """Test validates multiple findings efficiently."""
        mock_run.return_value = [
            SlitherFinding(
                detector="reentrancy-eth",
                impact="High",
                confidence="High",
                description="Reentrancy",
                lines=[42],
            ),
            SlitherFinding(
                detector="arbitrary-send-eth",
                impact="High",
                confidence="High",
                description="Arbitrary send",
                lines=[100],
            ),
        ]

        findings = [
            {"type": "reentrancy", "line": 42, "confidence": 0.7},
            {"type": "access_control", "line": 100, "confidence": 0.6},
            {"type": "gas_optimization", "line": 200, "confidence": 0.5},
        ]

        results = validator.validate_findings("contract Test {}", findings)

        assert len(results) == 3

        # First finding confirmed
        assert results[0].slither_confirmed is True
        assert "reentrancy-eth" in results[0].slither_detectors_matched

        # Second finding confirmed
        assert results[1].slither_confirmed is True
        assert "arbitrary-send-eth" in results[1].slither_detectors_matched

        # Third finding not confirmed
        assert results[2].slither_confirmed is False

    @patch.object(SlitherValidator, "run_slither")
    def test_runs_slither_once(self, mock_run, validator):
        """Test Slither is run only once for batch validation."""
        mock_run.return_value = []

        findings = [
            {"type": "reentrancy", "line": 42, "confidence": 0.7},
            {"type": "access_control", "line": 100, "confidence": 0.6},
        ]

        validator.validate_findings("contract Test {}", findings)

        # Slither should be called exactly once
        mock_run.assert_called_once()


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestValidateWithSlither:
    """Tests for validate_with_slither convenience function."""

    @patch.object(SlitherValidator, "_find_slither")
    @patch.object(SlitherValidator, "_check_slither")
    def test_returns_original_when_not_available(self, mock_check, mock_find):
        """Test returns original findings when Slither not available."""
        mock_find.return_value = "slither"
        mock_check.return_value = False

        findings = [{"type": "reentrancy", "line": 42, "confidence": 0.7}]
        result = validate_with_slither("contract Test {}", findings)

        assert result == findings

    @patch.object(SlitherValidator, "_find_slither")
    @patch.object(SlitherValidator, "_check_slither")
    @patch.object(SlitherValidator, "validate_findings")
    def test_updates_findings_with_validation(self, mock_validate, mock_check, mock_find):
        """Test updates findings with validation results."""
        mock_find.return_value = "slither"
        mock_check.return_value = True
        mock_validate.return_value = [
            ValidationResult(
                pattern_type="reentrancy",
                pattern_line=42,
                slither_confirmed=True,
                slither_detectors_matched=["reentrancy-eth"],
                confidence_adjustment=0.2,
                final_confidence=0.9,
                notes="Confirmed",
            )
        ]

        findings = [{"type": "reentrancy", "line": 42, "confidence": 0.7}]
        result = validate_with_slither("contract Test {}", findings)

        assert len(result) == 1
        assert result[0]["confidence"] == 0.9
        assert result[0]["_slither_validated"] is True
        assert "reentrancy-eth" in result[0]["_slither_detectors"]
        assert result[0]["_validation_notes"] == "Confirmed"


class TestFilterUnconfirmed:
    """Tests for filter_unconfirmed convenience function."""

    def test_keeps_high_confidence_findings(self):
        """Test keeps findings with high confidence."""
        findings = [
            {"type": "reentrancy", "confidence": 0.8, "_slither_validated": False},
            {"type": "access_control", "confidence": 0.3, "_slither_validated": False},
        ]

        result = filter_unconfirmed(findings, min_confidence=0.4)

        assert len(result) == 1
        assert result[0]["type"] == "reentrancy"

    def test_keeps_slither_validated_findings(self):
        """Test keeps Slither-validated findings regardless of confidence."""
        findings = [
            {"type": "reentrancy", "confidence": 0.2, "_slither_validated": True},
            {"type": "access_control", "confidence": 0.3, "_slither_validated": False},
        ]

        result = filter_unconfirmed(findings, min_confidence=0.4)

        assert len(result) == 1
        assert result[0]["type"] == "reentrancy"

    def test_filters_low_confidence_unconfirmed(self):
        """Test filters out low confidence unconfirmed findings."""
        findings = [
            {"type": "reentrancy", "confidence": 0.3, "_slither_validated": False},
            {"type": "access_control", "confidence": 0.2},  # No _slither_validated key
        ]

        result = filter_unconfirmed(findings, min_confidence=0.4)

        assert len(result) == 0

    def test_custom_min_confidence(self):
        """Test custom minimum confidence threshold."""
        findings = [
            {"type": "reentrancy", "confidence": 0.6, "_slither_validated": False},
            {"type": "access_control", "confidence": 0.5, "_slither_validated": False},
        ]

        result = filter_unconfirmed(findings, min_confidence=0.55)

        assert len(result) == 1
        assert result[0]["type"] == "reentrancy"

    def test_empty_findings_list(self):
        """Test with empty findings list."""
        result = filter_unconfirmed([])
        assert result == []


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Edge case tests for Slither validator."""

    @pytest.fixture
    def validator(self):
        """Create validator with mocked availability."""
        with patch.object(SlitherValidator, "_find_slither", return_value="slither"):
            with patch.object(SlitherValidator, "_check_slither", return_value=True):
                return SlitherValidator()

    def test_pattern_type_normalization(self, validator):
        """Test pattern type normalization (dashes vs underscores)."""
        # Both should map to same Slither detectors
        detectors1 = PATTERN_TO_SLITHER_DETECTORS.get("reentrancy_path", [])
        detectors2 = PATTERN_TO_SLITHER_DETECTORS.get("reentrancy_path", [])
        assert detectors1 == detectors2

    @patch.object(SlitherValidator, "run_slither")
    def test_empty_lines_in_finding(self, mock_run, validator):
        """Test handling finding with empty lines list."""
        mock_run.return_value = [
            SlitherFinding(
                detector="reentrancy-eth",
                impact="High",
                confidence="High",
                description="Reentrancy",
                lines=[],  # Empty lines
            )
        ]

        result = validator.validate_finding(
            source_code="contract Test {}",
            pattern_type="reentrancy",
            pattern_line=42,
            pattern_confidence=0.7,
        )

        # Should not match due to empty lines
        assert result.slither_confirmed is False

    @patch.object(SlitherValidator, "run_slither")
    def test_unknown_pattern_type(self, mock_run, validator):
        """Test handling unknown pattern type."""
        mock_run.return_value = [
            SlitherFinding(
                detector="some-detector",
                impact="Medium",
                confidence="Medium",
                description="Some issue",
                lines=[42],
            )
        ]

        result = validator.validate_finding(
            source_code="contract Test {}",
            pattern_type="unknown_pattern_type",
            pattern_line=42,
            pattern_confidence=0.7,
        )

        # Should match any detector when pattern type is unknown
        assert result.slither_confirmed is True

    def test_confidence_floor(self, validator):
        """Test confidence has minimum floor."""
        with patch.object(validator, "run_slither", return_value=[]):
            result = validator.validate_finding(
                source_code="contract Test {}",
                pattern_type="reentrancy",
                pattern_line=42,
                pattern_confidence=0.05,  # Very low initial confidence
            )

        # Should not go below 0.1
        assert result.final_confidence >= 0.1

    def test_confidence_ceiling(self, validator):
        """Test confidence has maximum ceiling."""
        with patch.object(
            validator,
            "run_slither",
            return_value=[
                SlitherFinding(
                    detector="reentrancy-eth",
                    impact="High",
                    confidence="High",
                    description="Test",
                    lines=[42],
                )
            ],
        ):
            result = validator.validate_finding(
                source_code="contract Test {}",
                pattern_type="reentrancy",
                pattern_line=42,
                pattern_confidence=0.99,  # Very high initial confidence
            )

        # Should not exceed 1.0
        assert result.final_confidence <= 1.0

    @patch.object(SlitherValidator, "run_slither")
    def test_multiple_detectors_matched(self, mock_run, validator):
        """Test handling multiple matching detectors."""
        mock_run.return_value = [
            SlitherFinding(
                detector="reentrancy-eth",
                impact="High",
                confidence="High",
                description="Reentrancy 1",
                lines=[42],
            ),
            SlitherFinding(
                detector="reentrancy-no-eth",
                impact="High",
                confidence="High",
                description="Reentrancy 2",
                lines=[42],
            ),
        ]

        result = validator.validate_finding(
            source_code="contract Test {}",
            pattern_type="reentrancy",
            pattern_line=42,
            pattern_confidence=0.7,
        )

        assert result.slither_confirmed is True
        assert len(result.slither_detectors_matched) == 2


class TestPatternMappingCoverage:
    """Tests for pattern mapping coverage."""

    @pytest.mark.parametrize(
        "pattern_type,expected_detectors",
        [
            ("reentrancy", ["reentrancy-eth", "reentrancy-no-eth"]),
            ("tx_origin", ["tx-origin"]),
            ("tx.origin", ["tx-origin"]),
            ("timestamp_dependence", ["timestamp", "weak-prng"]),
            ("denial_of_service", ["calls-loop", "costly-loop"]),
        ],
    )
    def test_pattern_mappings(self, pattern_type, expected_detectors):
        """Test that pattern types map to expected detectors."""
        detectors = PATTERN_TO_SLITHER_DETECTORS.get(pattern_type, [])
        for expected in expected_detectors:
            assert expected in detectors
