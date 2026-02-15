"""
Tests for the Hallucination Detection Module.

Tests cover:
- HallucinationDetector initialization and configuration
- Single finding validation
- Multiple findings validation
- Cross-validation with static analysis
- Code pattern verification
- Anomaly detection
- Confidence adjustment
- Convenience functions
"""

import pytest

from src.security.hallucination_detector import (
    CODE_PATTERNS,
    VULN_TYPE_ALIASES,
    HallucinationDetector,
    ValidatedFinding,
    ValidationResult,
    ValidationStatus,
    cross_validate_finding,
    filter_reliable_findings,
    validate_llm_findings,
)


class TestValidationStatus:
    """Tests for ValidationStatus enum."""

    def test_status_values(self):
        """Test all status values exist."""
        assert ValidationStatus.VALIDATED.value == "validated"
        assert ValidationStatus.PARTIAL.value == "partial"
        assert ValidationStatus.UNVALIDATED.value == "unvalidated"
        assert ValidationStatus.SUSPICIOUS.value == "suspicious"
        assert ValidationStatus.HALLUCINATION.value == "hallucination"


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_creation(self):
        """Test creating a ValidationResult."""
        result = ValidationResult(
            status=ValidationStatus.VALIDATED,
            original_confidence=0.8,
            adjusted_confidence=0.9,
            validation_sources=["static_analysis"],
            reasons=["Confirmed by tools"],
        )
        assert result.status == ValidationStatus.VALIDATED
        assert result.original_confidence == 0.8
        assert result.adjusted_confidence == 0.9
        assert result.validation_sources == ["static_analysis"]
        assert result.code_evidence is None

    def test_confidence_penalty(self):
        """Test confidence_penalty property."""
        result = ValidationResult(
            status=ValidationStatus.SUSPICIOUS,
            original_confidence=0.8,
            adjusted_confidence=0.3,
        )
        assert result.confidence_penalty == 0.5

    def test_with_code_evidence(self):
        """Test ValidationResult with code evidence."""
        result = ValidationResult(
            status=ValidationStatus.VALIDATED,
            original_confidence=0.7,
            adjusted_confidence=0.8,
            code_evidence=".call{value: amount}()",
        )
        assert result.code_evidence == ".call{value: amount}()"


class TestValidatedFinding:
    """Tests for ValidatedFinding dataclass."""

    def test_creation(self):
        """Test creating a ValidatedFinding."""
        finding = {"type": "reentrancy", "confidence": 0.8}
        validation = ValidationResult(
            status=ValidationStatus.VALIDATED,
            original_confidence=0.8,
            adjusted_confidence=0.9,
        )
        validated = ValidatedFinding(
            finding=finding, validation=validation, is_reliable=True
        )
        assert validated.finding == finding
        assert validated.is_reliable is True
        assert validated.adjusted_confidence == 0.9


class TestHallucinationDetectorInit:
    """Tests for HallucinationDetector initialization."""

    def test_default_init(self):
        """Test default initialization."""
        detector = HallucinationDetector()
        assert detector.confidence_penalty_unvalidated == 0.3
        assert detector.confidence_penalty_suspicious == 0.5
        assert detector.min_confidence_threshold == 0.1

    def test_custom_init(self):
        """Test custom initialization."""
        detector = HallucinationDetector(
            confidence_penalty_unvalidated=0.4,
            confidence_penalty_suspicious=0.6,
            min_confidence_threshold=0.2,
        )
        assert detector.confidence_penalty_unvalidated == 0.4
        assert detector.confidence_penalty_suspicious == 0.6
        assert detector.min_confidence_threshold == 0.2


class TestNormalizeType:
    """Tests for type normalization."""

    def test_normalize_simple(self):
        """Test normalizing simple types."""
        detector = HallucinationDetector()
        assert detector._normalize_type("reentrancy") == "reentrancy"
        assert detector._normalize_type("REENTRANCY") == "reentrancy"
        assert detector._normalize_type("  reentrancy  ") == "reentrancy"

    def test_normalize_with_separators(self):
        """Test normalizing types with separators."""
        detector = HallucinationDetector()
        assert detector._normalize_type("access-control") == "accesscontrol"
        assert detector._normalize_type("access_control") == "accesscontrol"
        assert detector._normalize_type("integer-overflow") == "integeroverflow"


class TestExtractFindingTypes:
    """Tests for extracting finding types."""

    def test_extract_from_type_field(self):
        """Test extracting from type field."""
        detector = HallucinationDetector()
        findings = [
            {"type": "reentrancy"},
            {"type": "access-control"},
        ]
        types = detector._extract_finding_types(findings)
        assert "reentrancy" in types
        assert "accesscontrol" in types

    def test_extract_from_category_field(self):
        """Test extracting from category field."""
        detector = HallucinationDetector()
        findings = [{"category": "integer-overflow"}]
        types = detector._extract_finding_types(findings)
        assert "integeroverflow" in types

    def test_extract_from_check_field(self):
        """Test extracting from check field."""
        detector = HallucinationDetector()
        findings = [{"check": "unchecked-return"}]
        types = detector._extract_finding_types(findings)
        assert "uncheckedreturn" in types

    def test_extract_empty(self):
        """Test extracting from empty findings."""
        detector = HallucinationDetector()
        types = detector._extract_finding_types([])
        assert len(types) == 0


class TestIsTypeInStatic:
    """Tests for type matching with static findings."""

    def test_direct_match(self):
        """Test direct type match."""
        detector = HallucinationDetector()
        static_types = {"reentrancy", "accesscontrol"}
        assert detector._is_type_in_static("reentrancy", static_types) is True
        assert detector._is_type_in_static("overflow", static_types) is False

    def test_alias_match(self):
        """Test matching via aliases."""
        detector = HallucinationDetector()
        static_types = {"reentrancy"}
        # "re-entrancy" should match "reentrancy" via aliases
        assert detector._is_type_in_static("reentrant", static_types) is True

    def test_no_match(self):
        """Test no match found."""
        detector = HallucinationDetector()
        static_types = {"somethingelse"}
        assert detector._is_type_in_static("reentrancy", static_types) is False


class TestExtractLineFromString:
    """Tests for extracting line numbers from strings."""

    def test_extract_with_colon(self):
        """Test extracting line with colon format."""
        detector = HallucinationDetector()
        assert detector._extract_line_from_string("file.sol:42") == 42
        assert detector._extract_line_from_string("contract.sol:100:5") == 100

    def test_extract_with_line_keyword(self):
        """Test extracting line with line keyword."""
        detector = HallucinationDetector()
        assert detector._extract_line_from_string("line 42") == 42
        assert detector._extract_line_from_string("Line: 100") == 100

    def test_extract_no_line(self):
        """Test extraction when no line present."""
        detector = HallucinationDetector()
        assert detector._extract_line_from_string("no line here") is None
        assert detector._extract_line_from_string("") is None


class TestCheckLocationMatch:
    """Tests for location matching."""

    def test_exact_match(self):
        """Test exact line number match."""
        detector = HallucinationDetector()
        llm_finding = {"location": {"line": 42}}
        static_findings = [{"location": {"line": 42}}]
        assert detector._check_location_match(llm_finding, static_findings) is True

    def test_close_match(self):
        """Test close line number match (within 5 lines)."""
        detector = HallucinationDetector()
        llm_finding = {"location": {"line": 42}}
        static_findings = [{"location": {"line": 45}}]
        assert detector._check_location_match(llm_finding, static_findings) is True

    def test_no_match(self):
        """Test no location match."""
        detector = HallucinationDetector()
        llm_finding = {"location": {"line": 42}}
        static_findings = [{"location": {"line": 100}}]
        assert detector._check_location_match(llm_finding, static_findings) is False

    def test_string_location(self):
        """Test with string location."""
        detector = HallucinationDetector()
        llm_finding = {"location": "file.sol:42"}
        static_findings = [{"location": {"line": 44}}]
        assert detector._check_location_match(llm_finding, static_findings) is True

    def test_missing_location(self):
        """Test with missing location."""
        detector = HallucinationDetector()
        llm_finding = {"location": {}}
        static_findings = [{"location": {"line": 42}}]
        assert detector._check_location_match(llm_finding, static_findings) is False

    def test_line_start_field(self):
        """Test with line_start field."""
        detector = HallucinationDetector()
        llm_finding = {"location": {"line_start": 42}}
        static_findings = [{"location": {"line_start": 44}}]
        assert detector._check_location_match(llm_finding, static_findings) is True


class TestVerifyCodePattern:
    """Tests for code pattern verification."""

    def test_reentrancy_pattern(self):
        """Test detecting reentrancy pattern in code."""
        detector = HallucinationDetector()
        code = """
        function withdraw(uint amount) external {
            require(balances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] -= amount;
        }
        """
        finding = {"type": "reentrancy"}
        match, evidence = detector._verify_code_pattern(finding, code)
        assert match is True
        assert evidence is not None
        assert "call" in evidence.lower()

    def test_access_control_pattern(self):
        """Test detecting access control pattern."""
        detector = HallucinationDetector()
        code = """
        modifier onlyOwner() {
            require(msg.sender == owner, "Not owner");
            _;
        }
        function mint() external onlyOwner {}
        """
        finding = {"type": "access-control"}
        match, evidence = detector._verify_code_pattern(finding, code)
        assert match is True
        assert "onlyOwner" in evidence

    def test_no_pattern_match(self):
        """Test no pattern match."""
        detector = HallucinationDetector()
        code = "contract Simple { uint x; }"
        finding = {"type": "reentrancy"}
        match, evidence = detector._verify_code_pattern(finding, code)
        assert match is False
        assert evidence is None

    def test_delegatecall_pattern(self):
        """Test delegatecall pattern."""
        detector = HallucinationDetector()
        code = """
        function execute(address target) external {
            target.delegatecall(abi.encode(data));
        }
        """
        finding = {"type": "delegatecall"}
        match, evidence = detector._verify_code_pattern(finding, code)
        assert match is True

    def test_oracle_pattern(self):
        """Test oracle manipulation pattern."""
        detector = HallucinationDetector()
        code = """
        function getPrice() external view returns (uint) {
            return oracle.latestAnswer();
        }
        """
        finding = {"type": "oracle-manipulation"}
        match, evidence = detector._verify_code_pattern(finding, code)
        assert match is True


class TestDetectAnomalies:
    """Tests for anomaly detection."""

    def test_high_confidence_short_description(self):
        """Test detecting high confidence with short description."""
        detector = HallucinationDetector()
        finding = {
            "confidence": 0.95,
            "description": "Short desc",
        }
        anomalies = detector._detect_anomalies(finding)
        assert len(anomalies) > 0
        assert any("minimal description" in a.lower() for a in anomalies)

    def test_generic_description(self):
        """Test detecting generic description."""
        detector = HallucinationDetector()
        finding = {
            "confidence": 0.7,
            "description": "This vulnerability allows an attacker could exploit may lead to issues",
        }
        anomalies = detector._detect_anomalies(finding)
        assert any("generic" in a.lower() for a in anomalies)

    def test_missing_location(self):
        """Test detecting missing location."""
        detector = HallucinationDetector()
        finding = {"confidence": 0.7, "description": "A valid description here"}
        anomalies = detector._detect_anomalies(finding)
        assert any("location" in a.lower() for a in anomalies)

    def test_critical_without_scenario(self):
        """Test critical severity without attack scenario."""
        detector = HallucinationDetector()
        finding = {
            "confidence": 0.7,
            "severity": "critical",
            "description": "Critical vulnerability found",
            "location": {"line": 42},
        }
        anomalies = detector._detect_anomalies(finding)
        assert any("attack scenario" in a.lower() for a in anomalies)

    def test_no_anomalies(self):
        """Test finding with no anomalies."""
        detector = HallucinationDetector()
        finding = {
            "confidence": 0.7,
            "description": "A detailed description of the vulnerability with specific details about what went wrong and how it can be exploited.",
            "location": {"line": 42},
            "attack_scenario": "Step 1...",
        }
        anomalies = detector._detect_anomalies(finding)
        assert len(anomalies) == 0


class TestCalculateStatusAndConfidence:
    """Tests for status and confidence calculation."""

    def test_validated_multiple_sources(self):
        """Test validated status with multiple sources."""
        detector = HallucinationDetector()
        status, conf = detector._calculate_status_and_confidence(
            original_confidence=0.8,
            validation_sources=2,
            has_anomalies=False,
            has_code_evidence=True,
        )
        assert status == ValidationStatus.VALIDATED
        assert conf == 0.9  # Boosted

    def test_partial_single_source(self):
        """Test partial status with single source."""
        detector = HallucinationDetector()
        status, conf = detector._calculate_status_and_confidence(
            original_confidence=0.8,
            validation_sources=1,
            has_anomalies=False,
            has_code_evidence=True,
        )
        assert status == ValidationStatus.PARTIAL
        assert conf == 0.8  # No change

    def test_unvalidated_with_evidence(self):
        """Test unvalidated with code evidence."""
        detector = HallucinationDetector()
        status, conf = detector._calculate_status_and_confidence(
            original_confidence=0.8,
            validation_sources=0,
            has_anomalies=False,
            has_code_evidence=True,
        )
        assert status == ValidationStatus.UNVALIDATED
        assert conf == 0.5  # Penalized

    def test_suspicious_with_anomalies(self):
        """Test suspicious status with anomalies."""
        detector = HallucinationDetector()
        status, conf = detector._calculate_status_and_confidence(
            original_confidence=0.8,
            validation_sources=0,
            has_anomalies=True,
            has_code_evidence=False,
        )
        assert status == ValidationStatus.SUSPICIOUS
        assert abs(conf - 0.3) < 0.01  # Heavily penalized (float tolerance)

    def test_hallucination_low_confidence(self):
        """Test hallucination when confidence drops too low."""
        detector = HallucinationDetector(
            confidence_penalty_suspicious=0.9,
        )
        status, conf = detector._calculate_status_and_confidence(
            original_confidence=0.5,
            validation_sources=0,
            has_anomalies=True,
            has_code_evidence=False,
        )
        assert status == ValidationStatus.HALLUCINATION
        assert conf < 0.1


class TestValidateFindings:
    """Tests for validating multiple findings."""

    def test_validate_empty(self):
        """Test validating empty findings."""
        detector = HallucinationDetector()
        results = detector.validate_findings([])
        assert len(results) == 0

    def test_validate_with_static_match(self):
        """Test validation with static analysis match."""
        detector = HallucinationDetector()
        llm_findings = [
            {"type": "reentrancy", "confidence": 0.8, "location": {"line": 42}}
        ]
        static_findings = [{"type": "reentrancy", "location": {"line": 42}}]
        code = "msg.sender.call{value: amount}('')"

        results = detector.validate_findings(llm_findings, static_findings, code)

        assert len(results) == 1
        assert results[0].is_reliable is True
        assert results[0].validation.status in [
            ValidationStatus.VALIDATED,
            ValidationStatus.PARTIAL,
        ]

    def test_validate_hallucination(self):
        """Test detecting hallucination."""
        detector = HallucinationDetector()
        llm_findings = [
            {
                "type": "nonexistent-vuln",
                "confidence": 0.95,
                "description": "Bad",
            }
        ]
        results = detector.validate_findings(llm_findings, [], "contract Simple {}")

        assert len(results) == 1
        # Should be marked suspicious or hallucination due to anomalies
        assert results[0].validation.adjusted_confidence < 0.95


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_validate_llm_findings(self):
        """Test validate_llm_findings function."""
        llm_findings = [{"type": "reentrancy", "confidence": 0.8}]
        static_findings = [{"type": "reentrancy"}]

        results = validate_llm_findings(llm_findings, static_findings)

        assert len(results) == 1
        assert isinstance(results[0], ValidatedFinding)

    def test_cross_validate_finding(self):
        """Test cross_validate_finding function."""
        finding = {"type": "reentrancy", "confidence": 0.8, "location": {"line": 42}}
        static_findings = [{"type": "reentrancy", "location": {"line": 42}}]

        result = cross_validate_finding(finding, static_findings)

        assert isinstance(result, ValidationResult)
        assert result.original_confidence == 0.8

    def test_cross_validate_empty_finding(self):
        """Test cross_validate_finding with empty result."""
        finding = {"type": "test", "confidence": 0.5}
        result = cross_validate_finding(finding, [])
        assert isinstance(result, ValidationResult)

    def test_filter_reliable_findings(self):
        """Test filter_reliable_findings function."""
        validated_findings = [
            ValidatedFinding(
                finding={"type": "reentrancy", "confidence": 0.8},
                validation=ValidationResult(
                    status=ValidationStatus.VALIDATED,
                    original_confidence=0.8,
                    adjusted_confidence=0.9,
                    validation_sources=["static"],
                ),
                is_reliable=True,
            ),
            ValidatedFinding(
                finding={"type": "fake", "confidence": 0.3},
                validation=ValidationResult(
                    status=ValidationStatus.HALLUCINATION,
                    original_confidence=0.3,
                    adjusted_confidence=0.05,
                ),
                is_reliable=False,
            ),
        ]

        reliable = filter_reliable_findings(validated_findings)

        assert len(reliable) == 1
        assert reliable[0]["type"] == "reentrancy"
        assert reliable[0]["confidence"] == 0.9
        assert reliable[0]["validation_status"] == "validated"

    def test_filter_with_min_confidence(self):
        """Test filter with minimum confidence threshold."""
        validated_findings = [
            ValidatedFinding(
                finding={"type": "test"},
                validation=ValidationResult(
                    status=ValidationStatus.UNVALIDATED,
                    original_confidence=0.5,
                    adjusted_confidence=0.25,
                ),
                is_reliable=True,
            ),
        ]

        reliable = filter_reliable_findings(validated_findings, min_confidence=0.3)
        assert len(reliable) == 0  # Below threshold

        reliable = filter_reliable_findings(validated_findings, min_confidence=0.2)
        assert len(reliable) == 1  # Above threshold


class TestCodePatterns:
    """Tests for CODE_PATTERNS constant."""

    def test_patterns_exist(self):
        """Test that all pattern categories exist."""
        assert "reentrancy" in CODE_PATTERNS
        assert "access_control" in CODE_PATTERNS
        assert "integer_overflow" in CODE_PATTERNS
        assert "delegatecall" in CODE_PATTERNS
        assert "selfdestruct" in CODE_PATTERNS

    def test_patterns_are_valid_regex(self):
        """Test that all patterns are valid regex."""
        import re

        for category, patterns in CODE_PATTERNS.items():
            for pattern in patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    pytest.fail(f"Invalid regex in {category}: {pattern} - {e}")


class TestVulnTypeAliases:
    """Tests for VULN_TYPE_ALIASES constant."""

    def test_aliases_exist(self):
        """Test that aliases exist for main types."""
        assert "reentrancy" in VULN_TYPE_ALIASES
        assert "access_control" in VULN_TYPE_ALIASES
        assert "flash_loan" in VULN_TYPE_ALIASES

    def test_aliases_are_lists(self):
        """Test that all aliases are lists."""
        for vuln_type, aliases in VULN_TYPE_ALIASES.items():
            assert isinstance(aliases, list), f"{vuln_type} aliases should be a list"
            assert len(aliases) > 0, f"{vuln_type} should have at least one alias"
