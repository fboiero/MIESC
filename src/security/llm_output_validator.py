"""
LLM Output Validation Module

Provides strict validation of LLM responses using Pydantic schemas to:
1. Ensure response structure matches expected format
2. Validate field types and ranges
3. Reject malformed or suspicious outputs
4. Provide safe fallbacks for invalid responses

CRITICAL: All LLM JSON outputs MUST be validated before use.

Usage:
    from src.security.llm_output_validator import (
        validate_vulnerability_finding,
        validate_analysis_response,
        safe_parse_llm_json,
        ValidationResult,
    )

    # Parse and validate LLM response
    result = safe_parse_llm_json(llm_output, AnalysisResponse)
    if result.is_valid:
        analysis = result.data
    else:
        logger.warning(f"Invalid LLM output: {result.errors}")
"""

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Generic, List, Literal, Optional, Type, TypeVar, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class Severity(str, Enum):
    """Valid severity levels for vulnerability findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    INFORMATIONAL = "informational"

    @classmethod
    def normalize(cls, value: str) -> "Severity":
        """Normalize severity string to enum value."""
        value = value.lower().strip()
        if value in ("informational", "info"):
            return cls.INFO
        try:
            return cls(value)
        except ValueError:
            return cls.INFO  # Default to INFO for unknown


class Confidence(str, Enum):
    """Confidence levels for findings."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ValidationResult(Generic[T]):
    """Result of LLM output validation."""

    is_valid: bool
    data: Optional[T] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    raw_content: str = ""

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0


class CodeLocation(BaseModel):
    """Location of vulnerability in code."""

    model_config = ConfigDict(extra="ignore")

    file: Optional[str] = Field(default=None, description="Source file path")
    line: Optional[int] = Field(default=None, ge=0, le=1_000_000, description="Line number")
    line_start: Optional[int] = Field(default=None, ge=0, le=1_000_000)
    line_end: Optional[int] = Field(default=None, ge=0, le=1_000_000)
    function: Optional[str] = Field(default=None, max_length=500, description="Function name")
    contract: Optional[str] = Field(default=None, max_length=500, description="Contract name")

    @field_validator("function", "contract", "file", mode="before")
    @classmethod
    def sanitize_string(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        if not isinstance(v, str):
            v = str(v)
        # Remove potentially dangerous characters
        v = re.sub(r"[<>\"'`;]", "", v)
        return v[:500] if len(v) > 500 else v


class VulnerabilityFinding(BaseModel):
    """
    Validated vulnerability finding from LLM analysis.

    All fields are validated and sanitized.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    # Required fields
    type: str = Field(..., min_length=1, max_length=200, description="Vulnerability type")
    severity: str = Field(..., description="Severity level")
    title: str = Field(..., min_length=1, max_length=500, description="Finding title")

    # Optional fields with defaults
    description: str = Field(default="", max_length=5000, description="Detailed description")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence score 0-1")
    confidence_level: Optional[str] = Field(default=None, description="Confidence as string")

    # Location
    location: Optional[CodeLocation] = Field(default=None)
    line: Optional[int] = Field(default=None, ge=0, le=1_000_000)
    function: Optional[str] = Field(default=None, max_length=500)
    contract: Optional[str] = Field(default=None, max_length=500)

    # Code context
    vulnerable_code: Optional[str] = Field(default=None, max_length=10000)
    fixed_code: Optional[str] = Field(default=None, max_length=10000)
    remediation: Optional[str] = Field(default=None, max_length=5000)

    # Attack details
    attack_scenario: Optional[str] = Field(default=None, max_length=5000)
    attack_steps: Optional[List[str]] = Field(default=None, max_items=20)
    impact: Optional[str] = Field(default=None, max_length=2000)

    # References
    swc_id: Optional[str] = Field(default=None, pattern=r"^SWC-\d{1,4}$|^$")
    cwe_id: Optional[str] = Field(default=None, pattern=r"^CWE-\d{1,5}$|^$")
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> str:
        if isinstance(v, str):
            normalized = v.lower().strip()
            valid = {"critical", "high", "medium", "low", "info", "informational"}
            if normalized in valid:
                return normalized
        return "info"  # Safe default

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, v: Any) -> float:
        if isinstance(v, (int, float)):
            return max(0.0, min(1.0, float(v)))
        if isinstance(v, str):
            try:
                # Handle percentage strings like "85%"
                if "%" in v:
                    return max(0.0, min(1.0, float(v.replace("%", "")) / 100))
                return max(0.0, min(1.0, float(v)))
            except ValueError:
                pass
        return 0.5  # Safe default

    @field_validator("type", "title", mode="before")
    @classmethod
    def sanitize_required_string(cls, v: Any) -> str:
        if not isinstance(v, str):
            v = str(v) if v is not None else "unknown"
        # Remove potentially dangerous characters
        v = re.sub(r"[<>\"'`;{}]", "", v)
        return v.strip()[:500] if v else "unknown"

    @field_validator("description", "remediation", "attack_scenario", "impact", mode="before")
    @classmethod
    def sanitize_optional_string(cls, v: Any) -> str:
        if v is None:
            return ""
        if not isinstance(v, str):
            v = str(v)
        # Remove script tags and dangerous patterns
        v = re.sub(r"<script[^>]*>.*?</script>", "", v, flags=re.IGNORECASE | re.DOTALL)
        v = re.sub(r"[<>]", "", v)
        return v.strip()

    @field_validator("swc_id", "cwe_id", mode="before")
    @classmethod
    def normalize_id(cls, v: Any) -> Optional[str]:
        if v is None or v == "":
            return None
        if not isinstance(v, str):
            v = str(v)
        v = v.upper().strip()
        # Try to fix common formats
        if re.match(r"^\d+$", v):
            return None  # Just a number, not valid
        return v if re.match(r"^(SWC|CWE)-\d+$", v) else None


class AnalysisResponse(BaseModel):
    """
    Validated analysis response from LLM.

    Represents the full response structure from SmartLLM or similar adapters.
    """

    model_config = ConfigDict(extra="ignore")

    # Findings list
    vulnerabilities: List[VulnerabilityFinding] = Field(
        default_factory=list,
        max_length=100,
        description="List of detected vulnerabilities",
    )
    findings: Optional[List[VulnerabilityFinding]] = Field(
        default=None,
        max_length=100,
        description="Alternative key for vulnerabilities",
    )

    # Summary
    summary: Optional[str] = Field(default=None, max_length=5000)
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    risk_level: Optional[str] = Field(default=None)
    recommendation: Optional[str] = Field(default=None, max_length=5000)

    # Metadata
    model: Optional[str] = Field(default=None, max_length=200)
    analysis_time: Optional[float] = Field(default=None, ge=0.0)
    contract_name: Optional[str] = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def merge_findings(self) -> "AnalysisResponse":
        """Merge 'findings' into 'vulnerabilities' if present."""
        if self.findings and not self.vulnerabilities:
            self.vulnerabilities = self.findings
        return self

    @field_validator("risk_level", mode="before")
    @classmethod
    def normalize_risk_level(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        if isinstance(v, str):
            v = v.lower().strip()
            valid = {"critical", "high", "medium", "low", "info", "safe"}
            return v if v in valid else None
        return None


class VerificatorResponse(BaseModel):
    """Response from the verificator stage."""

    model_config = ConfigDict(extra="ignore")

    is_valid: bool = Field(..., description="Whether finding is valid")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    reasoning: Optional[str] = Field(default=None, max_length=2000)
    adjusted_severity: Optional[str] = Field(default=None)
    false_positive_reason: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("is_valid", mode="before")
    @classmethod
    def coerce_bool(cls, v: Any) -> bool:
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower().strip() in ("true", "yes", "1", "valid")
        if isinstance(v, (int, float)):
            return bool(v)
        return False  # Safe default


def extract_json_from_text(text: str) -> Optional[str]:
    """
    Safely extract JSON from LLM text response.

    Handles common LLM output patterns like:
    - JSON in code blocks
    - JSON with trailing text
    - Multiple JSON objects (takes first)
    """
    if not text:
        return None

    # Try code block extraction first
    code_block_match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
    if code_block_match:
        return code_block_match.group(1)

    # Find JSON object boundaries
    brace_count = 0
    start_idx = None
    end_idx = None

    for i, char in enumerate(text):
        if char == "{":
            if brace_count == 0:
                start_idx = i
            brace_count += 1
        elif char == "}":
            brace_count -= 1
            if brace_count == 0 and start_idx is not None:
                end_idx = i + 1
                break

    if start_idx is not None and end_idx is not None:
        return text[start_idx:end_idx]

    return None


def repair_common_json_errors(json_str: str) -> str:
    """
    Attempt to repair common JSON formatting errors from LLMs.

    Fixes:
    - Trailing commas
    - Single quotes instead of double
    - Unquoted keys
    - Missing quotes on string values
    """
    if not json_str:
        return json_str

    # Remove trailing commas before } or ]
    json_str = re.sub(r",\s*([}\]])", r"\1", json_str)

    # Replace single quotes with double quotes (carefully)
    # Only if not inside a string value
    json_str = re.sub(r"(?<![\\])\'", '"', json_str)

    # Fix unquoted keys
    json_str = re.sub(r"(\{|\,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:", r'\1"\2":', json_str)

    return json_str


def safe_parse_llm_json(
    content: str,
    model_class: Type[T],
    strict: bool = False,
) -> ValidationResult[T]:
    """
    Safely parse and validate LLM JSON output.

    This is the PRIMARY function for parsing LLM responses.

    Args:
        content: Raw LLM output text
        model_class: Pydantic model class to validate against
        strict: If True, fail on any validation error

    Returns:
        ValidationResult with parsed data or errors

    Example:
        >>> result = safe_parse_llm_json(llm_output, AnalysisResponse)
        >>> if result.is_valid:
        ...     for vuln in result.data.vulnerabilities:
        ...         print(f"{vuln.severity}: {vuln.title}")
        >>> else:
        ...     print(f"Parse failed: {result.errors}")
    """
    errors = []
    warnings = []

    if not content:
        return ValidationResult(
            is_valid=False,
            errors=["Empty content"],
            raw_content="",
        )

    # Extract JSON from text
    json_str = extract_json_from_text(content)
    if not json_str:
        # Try the whole content as JSON
        json_str = content.strip()

    # Attempt to repair common errors
    json_str = repair_common_json_errors(json_str)

    # Parse JSON
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.warning(f"JSON parse error: {e}")
        return ValidationResult(
            is_valid=False,
            errors=[f"JSON parse error: {e}"],
            raw_content=content,
        )

    # Validate with Pydantic
    try:
        validated = model_class.model_validate(data)
        return ValidationResult(
            is_valid=True,
            data=validated,
            warnings=warnings,
            raw_content=content,
        )
    except ValidationError as e:
        error_messages = []
        for error in e.errors():
            loc = ".".join(str(x) for x in error["loc"])
            msg = error["msg"]
            error_messages.append(f"{loc}: {msg}")

        if strict:
            return ValidationResult(
                is_valid=False,
                errors=error_messages,
                raw_content=content,
            )

        # Try lenient parsing - extract what we can
        logger.warning(f"Validation errors (lenient mode): {error_messages}")
        warnings.extend(error_messages)

        try:
            # Use model_construct for partial data
            partial = model_class.model_construct(**data)
            return ValidationResult(
                is_valid=True,
                data=partial,
                warnings=warnings,
                raw_content=content,
            )
        except Exception:
            return ValidationResult(
                is_valid=False,
                errors=error_messages,
                warnings=warnings,
                raw_content=content,
            )


def validate_vulnerability_finding(data: Dict[str, Any]) -> ValidationResult[VulnerabilityFinding]:
    """
    Validate a single vulnerability finding dictionary.

    Args:
        data: Finding dictionary from LLM

    Returns:
        ValidationResult with validated finding or errors
    """
    try:
        finding = VulnerabilityFinding.model_validate(data)
        return ValidationResult(is_valid=True, data=finding)
    except ValidationError as e:
        errors = [f"{'.'.join(str(x) for x in err['loc'])}: {err['msg']}" for err in e.errors()]
        return ValidationResult(is_valid=False, errors=errors)


def validate_analysis_response(content: str) -> ValidationResult[AnalysisResponse]:
    """
    Validate a full analysis response from LLM.

    Convenience wrapper for safe_parse_llm_json with AnalysisResponse.

    Args:
        content: Raw LLM output

    Returns:
        ValidationResult with validated response or errors
    """
    return safe_parse_llm_json(content, AnalysisResponse)


def create_safe_fallback_finding(
    raw_data: Dict[str, Any],
    reason: str = "validation_fallback",
) -> VulnerabilityFinding:
    """
    Create a safe fallback finding when validation fails but we want to preserve data.

    Args:
        raw_data: Original data that failed validation
        reason: Reason for creating fallback

    Returns:
        VulnerabilityFinding with safe defaults
    """
    return VulnerabilityFinding(
        type=str(raw_data.get("type", "unknown"))[:200],
        severity="info",  # Default to lowest severity for safety
        title=str(raw_data.get("title", "Unvalidated Finding"))[:500],
        description=f"[{reason}] " + str(raw_data.get("description", ""))[:4900],
        confidence=0.3,  # Low confidence for fallback
    )
