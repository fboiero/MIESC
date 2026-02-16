"""
Tests for src/security/llm_output_validator.py

Comprehensive tests for LLM output validation including:
- Severity and Confidence enums
- ValidationResult dataclass
- Pydantic models: CodeLocation, VulnerabilityFinding, AnalysisResponse, VerificatorResponse
- JSON parsing and repair functions
- Validation helper functions
"""

import pytest

from src.security.llm_output_validator import (
    Severity,
    Confidence,
    ValidationResult,
    CodeLocation,
    VulnerabilityFinding,
    AnalysisResponse,
    VerificatorResponse,
    extract_json_from_text,
    repair_common_json_errors,
    safe_parse_llm_json,
    validate_vulnerability_finding,
    validate_analysis_response,
    create_safe_fallback_finding,
)


class TestSeverityEnum:
    """Tests for Severity enum."""

    def test_values(self):
        """Test enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"
        assert Severity.INFORMATIONAL.value == "informational"

    def test_normalize_valid(self):
        """Test normalizing valid severity strings."""
        assert Severity.normalize("CRITICAL") == Severity.CRITICAL
        assert Severity.normalize("high") == Severity.HIGH
        assert Severity.normalize("  medium  ") == Severity.MEDIUM
        assert Severity.normalize("LOW") == Severity.LOW

    def test_normalize_info_variants(self):
        """Test normalizing info/informational variants."""
        assert Severity.normalize("info") == Severity.INFO
        assert Severity.normalize("informational") == Severity.INFO

    def test_normalize_unknown(self):
        """Test normalizing unknown severity defaults to INFO."""
        assert Severity.normalize("unknown") == Severity.INFO
        assert Severity.normalize("invalid") == Severity.INFO
        assert Severity.normalize("") == Severity.INFO


class TestConfidenceEnum:
    """Tests for Confidence enum."""

    def test_values(self):
        """Test enum values."""
        assert Confidence.HIGH.value == "high"
        assert Confidence.MEDIUM.value == "medium"
        assert Confidence.LOW.value == "low"


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_valid_result(self):
        """Test valid result creation."""
        result = ValidationResult(is_valid=True, data="test")
        assert result.is_valid is True
        assert result.data == "test"
        assert result.errors == []
        assert result.warnings == []

    def test_invalid_result(self):
        """Test invalid result creation."""
        result = ValidationResult(is_valid=False, errors=["Error 1", "Error 2"])
        assert result.is_valid is False
        assert result.data is None
        assert len(result.errors) == 2

    def test_has_warnings(self):
        """Test has_warnings property."""
        no_warnings = ValidationResult(is_valid=True)
        assert no_warnings.has_warnings is False

        with_warnings = ValidationResult(is_valid=True, warnings=["Warning"])
        assert with_warnings.has_warnings is True


class TestCodeLocation:
    """Tests for CodeLocation model."""

    def test_default_values(self):
        """Test default values."""
        loc = CodeLocation()
        assert loc.file is None
        assert loc.line is None
        assert loc.function is None
        assert loc.contract is None

    def test_with_values(self):
        """Test with all values."""
        loc = CodeLocation(
            file="contract.sol",
            line=42,
            function="transfer",
            contract="Token",
        )
        assert loc.file == "contract.sol"
        assert loc.line == 42
        assert loc.function == "transfer"
        assert loc.contract == "Token"

    def test_sanitize_string_removes_dangerous_chars(self):
        """Test that dangerous characters are removed."""
        loc = CodeLocation(
            function="transfer<script>alert('xss')</script>",
            contract="Token\"malicious';--",
        )
        assert "<" not in loc.function
        assert ">" not in loc.function
        assert '"' not in loc.contract
        assert "'" not in loc.contract
        assert ";" not in loc.contract

    def test_sanitize_string_truncates(self):
        """Test string truncation to 500 chars."""
        long_name = "x" * 600
        loc = CodeLocation(function=long_name)
        assert len(loc.function) == 500

    def test_sanitize_non_string(self):
        """Test converting non-string values."""
        loc = CodeLocation(function=123)
        assert loc.function == "123"


class TestVulnerabilityFinding:
    """Tests for VulnerabilityFinding model."""

    def test_minimal_creation(self):
        """Test creating with minimal required fields."""
        finding = VulnerabilityFinding(
            type="reentrancy",
            severity="high",
            title="Reentrancy vulnerability",
        )
        assert finding.type == "reentrancy"
        assert finding.severity == "high"
        assert finding.title == "Reentrancy vulnerability"
        assert finding.confidence == 0.5  # Default

    def test_normalize_severity(self):
        """Test severity normalization."""
        finding = VulnerabilityFinding(
            type="test",
            severity="CRITICAL",
            title="Test",
        )
        assert finding.severity == "critical"

    def test_normalize_invalid_severity(self):
        """Test invalid severity defaults to info."""
        finding = VulnerabilityFinding(
            type="test",
            severity="unknown",
            title="Test",
        )
        assert finding.severity == "info"

    def test_normalize_confidence_float(self):
        """Test confidence normalization from float."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            confidence=0.85,
        )
        assert finding.confidence == 0.85

    def test_normalize_confidence_clamped(self):
        """Test confidence is clamped to 0-1."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            confidence=1.5,
        )
        assert finding.confidence == 1.0

    def test_normalize_confidence_percentage(self):
        """Test confidence from percentage string."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            confidence="85%",
        )
        assert finding.confidence == 0.85

    def test_normalize_confidence_string_number(self):
        """Test confidence from string number."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            confidence="0.7",
        )
        assert finding.confidence == 0.7

    def test_normalize_confidence_invalid(self):
        """Test invalid confidence defaults to 0.5."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            confidence="invalid",
        )
        assert finding.confidence == 0.5

    def test_sanitize_type_title(self):
        """Test type and title sanitization."""
        finding = VulnerabilityFinding(
            type="<script>alert</script>",
            severity="high",
            title="Title with {braces} and ;semicolons",
        )
        assert "<" not in finding.type
        assert "{" not in finding.title
        assert ";" not in finding.title

    def test_sanitize_type_non_string(self):
        """Test type with non-string converts."""
        finding = VulnerabilityFinding(
            type=123,
            severity="high",
            title="Test",
        )
        assert finding.type == "123"

    def test_sanitize_description(self):
        """Test description sanitization removes script tags."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            description="Before<script>malicious</script>After",
        )
        assert "script" not in finding.description.lower()
        assert "malicious" not in finding.description

    def test_sanitize_description_none(self):
        """Test description None becomes empty string."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            description=None,
        )
        assert finding.description == ""

    def test_swc_id_valid(self):
        """Test valid SWC ID patterns."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            swc_id="SWC-107",
        )
        assert finding.swc_id == "SWC-107"

    def test_swc_id_normalized(self):
        """Test SWC ID is uppercased."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            swc_id="swc-107",
        )
        assert finding.swc_id == "SWC-107"

    def test_swc_id_invalid(self):
        """Test invalid SWC ID becomes None."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            swc_id="107",  # Just a number
        )
        assert finding.swc_id is None

    def test_cwe_id_valid(self):
        """Test valid CWE ID patterns."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            cwe_id="CWE-284",
        )
        assert finding.cwe_id == "CWE-284"


class TestAnalysisResponse:
    """Tests for AnalysisResponse model."""

    def test_empty_response(self):
        """Test empty response with defaults."""
        response = AnalysisResponse()
        assert response.vulnerabilities == []
        assert response.findings is None

    def test_with_vulnerabilities(self):
        """Test with vulnerability list."""
        response = AnalysisResponse(
            vulnerabilities=[
                VulnerabilityFinding(type="test", severity="high", title="Test"),
            ]
        )
        assert len(response.vulnerabilities) == 1

    def test_merge_findings_to_vulnerabilities(self):
        """Test merging findings into vulnerabilities."""
        response = AnalysisResponse(
            findings=[
                VulnerabilityFinding(type="test", severity="high", title="Test"),
            ]
        )
        assert len(response.vulnerabilities) == 1

    def test_normalize_risk_level(self):
        """Test risk level normalization."""
        response = AnalysisResponse(risk_level="HIGH")
        assert response.risk_level == "high"

    def test_normalize_risk_level_invalid(self):
        """Test invalid risk level becomes None."""
        response = AnalysisResponse(risk_level="unknown")
        assert response.risk_level is None


class TestVerificatorResponse:
    """Tests for VerificatorResponse model."""

    def test_valid_response(self):
        """Test valid response creation."""
        response = VerificatorResponse(
            is_valid=True,
            confidence=0.9,
            reasoning="Confirmed vulnerability",
        )
        assert response.is_valid is True
        assert response.confidence == 0.9

    def test_coerce_bool_string_true(self):
        """Test bool coercion from true strings."""
        response = VerificatorResponse(is_valid="true")
        assert response.is_valid is True

        response = VerificatorResponse(is_valid="yes")
        assert response.is_valid is True

        response = VerificatorResponse(is_valid="1")
        assert response.is_valid is True

        response = VerificatorResponse(is_valid="valid")
        assert response.is_valid is True

    def test_coerce_bool_string_false(self):
        """Test bool coercion from false strings."""
        response = VerificatorResponse(is_valid="false")
        assert response.is_valid is False

        response = VerificatorResponse(is_valid="no")
        assert response.is_valid is False

    def test_coerce_bool_int(self):
        """Test bool coercion from int."""
        response = VerificatorResponse(is_valid=1)
        assert response.is_valid is True

        response = VerificatorResponse(is_valid=0)
        assert response.is_valid is False


class TestExtractJsonFromText:
    """Tests for extract_json_from_text function."""

    def test_empty_text(self):
        """Test with empty text."""
        assert extract_json_from_text("") is None
        assert extract_json_from_text(None) is None

    def test_json_in_code_block(self):
        """Test extracting JSON from code block."""
        text = '''Here's the analysis:
```json
{"severity": "high", "title": "Test"}
```
End of analysis.'''
        result = extract_json_from_text(text)
        assert result == '{"severity": "high", "title": "Test"}'

    def test_json_without_json_marker(self):
        """Test extracting JSON from unmarked code block."""
        text = '''Analysis:
```
{"type": "reentrancy"}
```'''
        result = extract_json_from_text(text)
        assert result == '{"type": "reentrancy"}'

    def test_plain_json(self):
        """Test extracting plain JSON object."""
        text = 'Before {"data": "value"} After'
        result = extract_json_from_text(text)
        assert result == '{"data": "value"}'

    def test_nested_braces(self):
        """Test with nested braces."""
        text = '{"outer": {"inner": "value"}}'
        result = extract_json_from_text(text)
        assert result == '{"outer": {"inner": "value"}}'

    def test_no_json(self):
        """Test with no JSON content."""
        text = "This is just plain text without any JSON."
        result = extract_json_from_text(text)
        assert result is None


class TestRepairCommonJsonErrors:
    """Tests for repair_common_json_errors function."""

    def test_empty_string(self):
        """Test with empty string."""
        assert repair_common_json_errors("") == ""
        assert repair_common_json_errors(None) is None

    def test_trailing_comma_object(self):
        """Test removing trailing comma in object."""
        json_str = '{"key": "value",}'
        result = repair_common_json_errors(json_str)
        assert result == '{"key": "value"}'

    def test_trailing_comma_array(self):
        """Test removing trailing comma in array."""
        json_str = '["a", "b", "c",]'
        result = repair_common_json_errors(json_str)
        assert result == '["a", "b", "c"]'

    def test_single_quotes(self):
        """Test replacing single quotes with double quotes."""
        json_str = "{'key': 'value'}"
        result = repair_common_json_errors(json_str)
        assert '"key"' in result
        assert '"value"' in result

    def test_unquoted_keys(self):
        """Test quoting unquoted keys."""
        json_str = '{key: "value", another_key: 123}'
        result = repair_common_json_errors(json_str)
        assert '"key"' in result
        assert '"another_key"' in result


class TestSafeParseLlmJson:
    """Tests for safe_parse_llm_json function."""

    def test_empty_content(self):
        """Test with empty content."""
        result = safe_parse_llm_json("", AnalysisResponse)
        assert result.is_valid is False
        assert "Empty content" in result.errors[0]

    def test_valid_json(self):
        """Test with valid JSON."""
        content = '{"vulnerabilities": []}'
        result = safe_parse_llm_json(content, AnalysisResponse)
        assert result.is_valid is True
        assert result.data is not None

    def test_json_in_text(self):
        """Test extracting JSON from surrounding text."""
        content = '''Analysis complete.
{"vulnerabilities": [], "summary": "No issues found"}
End of report.'''
        result = safe_parse_llm_json(content, AnalysisResponse)
        assert result.is_valid is True

    def test_invalid_json(self):
        """Test with invalid JSON."""
        content = "This is not JSON at all"
        result = safe_parse_llm_json(content, AnalysisResponse)
        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_repaired_json(self):
        """Test JSON repair is applied."""
        content = "{'vulnerabilities': [],}"  # Single quotes and trailing comma
        result = safe_parse_llm_json(content, AnalysisResponse)
        assert result.is_valid is True

    def test_strict_mode_fails(self):
        """Test strict mode fails on validation errors."""
        content = '{"vulnerabilities": "not_an_array"}'
        result = safe_parse_llm_json(content, AnalysisResponse, strict=True)
        assert result.is_valid is False

    def test_lenient_mode_partial(self):
        """Test lenient mode creates partial data."""
        # Missing required fields but has some data
        content = '{"summary": "Test summary"}'
        result = safe_parse_llm_json(content, AnalysisResponse, strict=False)
        # Should succeed in lenient mode
        assert result.is_valid is True


class TestValidateVulnerabilityFinding:
    """Tests for validate_vulnerability_finding function."""

    def test_valid_finding(self):
        """Test validating a valid finding."""
        data = {
            "type": "reentrancy",
            "severity": "high",
            "title": "Reentrancy in withdraw",
        }
        result = validate_vulnerability_finding(data)
        assert result.is_valid is True
        assert result.data.type == "reentrancy"

    def test_invalid_finding(self):
        """Test validating an invalid finding."""
        data = {
            # Missing required fields
            "description": "Some description",
        }
        result = validate_vulnerability_finding(data)
        assert result.is_valid is False
        assert len(result.errors) > 0


class TestValidateAnalysisResponse:
    """Tests for validate_analysis_response function."""

    def test_valid_response(self):
        """Test validating a valid response."""
        content = '''
        {
            "vulnerabilities": [
                {"type": "test", "severity": "low", "title": "Test finding"}
            ],
            "summary": "One issue found"
        }
        '''
        result = validate_analysis_response(content)
        assert result.is_valid is True
        assert len(result.data.vulnerabilities) == 1


class TestCreateSafeFallbackFinding:
    """Tests for create_safe_fallback_finding function."""

    def test_creates_fallback(self):
        """Test creating fallback finding."""
        raw_data = {
            "type": "reentrancy",
            "title": "Reentrancy vulnerability",
            "description": "Found a reentrancy issue",
        }
        finding = create_safe_fallback_finding(raw_data)
        assert finding.type == "reentrancy"
        assert finding.severity == "info"  # Default safe severity
        assert finding.confidence == 0.3  # Low confidence for fallback

    def test_fallback_with_missing_fields(self):
        """Test fallback with missing fields."""
        raw_data = {}
        finding = create_safe_fallback_finding(raw_data)
        assert finding.type == "unknown"
        assert finding.title == "Unvalidated Finding"

    def test_fallback_includes_reason(self):
        """Test fallback includes reason in description."""
        raw_data = {"description": "Original description"}
        finding = create_safe_fallback_finding(raw_data, reason="parse_error")
        assert "[parse_error]" in finding.description

    def test_fallback_truncates_long_values(self):
        """Test fallback truncates long values."""
        raw_data = {
            "type": "x" * 300,
            "description": "y" * 6000,
        }
        finding = create_safe_fallback_finding(raw_data)
        assert len(finding.type) <= 200


class TestEdgeCases:
    """Edge case tests."""

    def test_finding_with_location_object(self):
        """Test finding with location object."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            location=CodeLocation(line=42, function="transfer"),
        )
        assert finding.location.line == 42

    def test_finding_with_attack_steps(self):
        """Test finding with attack steps list."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            attack_steps=["Step 1", "Step 2"],
        )
        assert len(finding.attack_steps) == 2

    def test_response_with_all_fields(self):
        """Test response with all optional fields."""
        response = AnalysisResponse(
            vulnerabilities=[],
            summary="Summary text",
            risk_score=75.5,
            risk_level="high",
            recommendation="Fix issues",
            model="gpt-4",
            analysis_time=5.5,
            contract_name="Token",
        )
        assert response.risk_score == 75.5
        assert response.model == "gpt-4"

    def test_unicode_in_fields(self):
        """Test handling of unicode characters."""
        finding = VulnerabilityFinding(
            type="测试",
            severity="high",
            title="Test with unicode: 中文",
        )
        assert "中文" in finding.title

    def test_cvss_score_validation(self):
        """Test CVSS score validation."""
        finding = VulnerabilityFinding(
            type="test",
            severity="high",
            title="Test",
            cvss_score=7.5,
        )
        assert finding.cvss_score == 7.5
