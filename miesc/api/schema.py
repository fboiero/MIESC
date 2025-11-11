"""
MIESC API Schema - Pydantic models for request/response validation

Defines data models for MCP-compatible API with comprehensive security validation.

Security Features:
- Input validation (path traversal, command injection prevention)
- Size limits (DoS prevention)
- Whitelist validation (only allowed values)
- Sanitization (XSS, null bytes, unicode attacks)

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
"""

from pydantic import BaseModel, Field, validator, field_validator
from typing import Dict, List, Any, Optional
from datetime import datetime
import re
import os


# Security constants
MAX_CONTRACT_SIZE = 1_000_000  # 1MB max contract size
MIN_TIMEOUT = 10  # Minimum 10 seconds
MAX_TIMEOUT = 3600  # Maximum 1 hour
ALLOWED_ANALYSIS_TYPES = {"slither", "mythril", "all"}
ALLOWED_VERIFICATION_LEVELS = {"basic", "smt", "certora", "halmos"}


class AnalysisRequest(BaseModel):
    """
    Request model for contract analysis with security validation.

    Security Requirements:
    - SR-001: Path traversal prevention
    - SR-002: Command injection prevention
    - SR-004: Resource exhaustion prevention
    - SR-005: Whitelist validation
    """
    contract_code: str = Field(
        ...,
        description="Solidity source code or file path",
        max_length=MAX_CONTRACT_SIZE,
        min_length=1
    )
    analysis_type: str = Field(
        default="slither",
        description="Tool to use (slither, mythril, all)"
    )
    timeout: int = Field(
        default=300,
        description="Maximum execution time in seconds",
        ge=MIN_TIMEOUT,
        le=MAX_TIMEOUT
    )

    @field_validator('contract_code')
    @classmethod
    def validate_contract_code(cls, v: str) -> str:
        """
        Validate contract code for security issues.

        Prevents:
        - Path traversal attacks
        - Command injection
        - Null byte injection
        - Dangerous unicode characters

        Note: Error messages are sanitized to prevent information leakage.
        """
        # Remove null bytes
        if '\x00' in v:
            raise ValueError("Invalid input: contains forbidden characters")

        # Check for path traversal patterns
        dangerous_patterns = [
            '../',
            '..\\',
            '/etc/',
            '/root/',
            '/home/',
            '/var/',
            'C:\\',
            'D:\\',
            '%2e%2e',  # URL encoded ..
            '..../',   # Double dots
        ]

        v_lower = v.lower()
        for pattern in dangerous_patterns:
            if pattern.lower() in v_lower:
                # Generic error message - don't leak what we detected
                raise ValueError("Invalid input: contains forbidden patterns")

        # Check for command injection characters
        # Note: semicolons are allowed for Solidity code syntax
        dangerous_chars = ['|', '&', '$', '`']
        for char in dangerous_chars:
            if char in v:
                raise ValueError("Invalid input: contains forbidden characters")

        # Remove dangerous unicode (right-to-left override, zero-width spaces, etc.)
        dangerous_unicode = [
            '\u202e',  # Right-to-left override
            '\u200b',  # Zero-width space
            '\ufeff',  # Zero-width no-break space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
        ]
        for unicode_char in dangerous_unicode:
            if unicode_char in v:
                raise ValueError("Invalid input: contains forbidden characters")

        # Check for script tags (XSS prevention)
        if re.search(r'<script|javascript:|onerror=|onload=', v, re.IGNORECASE):
            raise ValueError("Invalid input: contains forbidden patterns")

        return v

    @field_validator('analysis_type')
    @classmethod
    def validate_analysis_type(cls, v: str) -> str:
        """Validate analysis type against whitelist."""
        if v not in ALLOWED_ANALYSIS_TYPES:
            raise ValueError(
                f"Invalid analysis type. Must be one of: {', '.join(ALLOWED_ANALYSIS_TYPES)}"
            )
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "contract_code": "pragma solidity ^0.8.0; contract Example { ... }",
                "analysis_type": "slither",
                "timeout": 300
            }
        }


class AnalysisResponse(BaseModel):
    """Response model for contract analysis"""
    timestamp: str
    contract: str
    tools_executed: List[str]
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings: List[Dict[str, Any]]
    context: str

    class Config:
        schema_extra = {
            "example": {
                "timestamp": "2025-01-20T12:00:00",
                "contract": "example.sol",
                "tools_executed": ["slither"],
                "total_findings": 3,
                "findings_by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 0},
                "findings": [],
                "context": "MIESC static analysis"
            }
        }


class VerifyRequest(BaseModel):
    """
    Request model for formal verification with security validation.

    Security Requirements:
    - SR-001: Path traversal prevention
    - SR-002: Command injection prevention
    - SR-004: Resource exhaustion prevention
    - SR-005: Whitelist validation
    """
    contract_code: str = Field(
        ...,
        description="Solidity source code or file path",
        max_length=MAX_CONTRACT_SIZE,
        min_length=1
    )
    verification_level: str = Field(
        default="basic",
        description="Level: basic, smt, certora, halmos"
    )
    properties: Optional[List[str]] = Field(
        default=None,
        description="Properties to verify",
        max_length=100  # Max 100 properties
    )
    timeout: int = Field(
        default=600,
        description="Maximum verification time in seconds",
        ge=MIN_TIMEOUT,
        le=MAX_TIMEOUT
    )

    @field_validator('contract_code')
    @classmethod
    def validate_contract_code(cls, v: str) -> str:
        """Reuse AnalysisRequest validation logic."""
        return AnalysisRequest.validate_contract_code(v)

    @field_validator('verification_level')
    @classmethod
    def validate_verification_level(cls, v: str) -> str:
        """Validate verification level against whitelist."""
        if v not in ALLOWED_VERIFICATION_LEVELS:
            raise ValueError(
                f"Invalid verification level. Must be one of: {', '.join(ALLOWED_VERIFICATION_LEVELS)}"
            )
        return v

    @field_validator('properties')
    @classmethod
    def validate_properties(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate properties for security issues."""
        if v is None:
            return v

        # Limit number of properties to prevent DoS
        if len(v) > 100:
            raise ValueError("Maximum 100 properties allowed")

        # Validate each property for injection attacks
        for prop in v:
            # Check for command injection
            if any(char in prop for char in [';', '|', '&', '$', '`']):
                raise ValueError("Potentially malicious characters in property")

            # Check length
            if len(prop) > 1000:
                raise ValueError("Property too long (max 1000 characters)")

        return v

    class Config:
        json_schema_extra = {
            "example": {
                "contract_code": "pragma solidity ^0.8.0; contract Example { ... }",
                "verification_level": "basic",
                "properties": ["invariant balance >= 0"],
                "timeout": 600
            }
        }


class VerifyResponse(BaseModel):
    """Response model for formal verification"""
    status: str
    level: Optional[str] = None
    method: Optional[str] = None
    properties_verified: Optional[int] = None
    warnings: Optional[List[Dict[str, Any]]] = None
    timestamp: str
    context: str

    class Config:
        schema_extra = {
            "example": {
                "status": "completed",
                "level": "basic",
                "method": "SMTChecker",
                "properties_verified": 1,
                "warnings": [],
                "timestamp": "2025-01-20T12:00:00",
                "context": "MIESC formal verification"
            }
        }


class ClassifyRequest(BaseModel):
    """
    Request model for vulnerability classification with security validation.

    Security Requirements:
    - SR-004: Resource exhaustion prevention
    - SR-011: Secrets management (API keys)
    """
    report: Dict[str, Any] = Field(
        ...,
        description="Analysis report to classify"
    )
    enable_ai_triage: bool = Field(
        default=False,
        description="Enable AI-powered triage"
    )
    ai_api_key: Optional[str] = Field(
        default=None,
        description="OpenAI API key for AI triage",
        max_length=200,  # Reasonable API key length
        min_length=20    # Minimum valid API key length
    )

    @field_validator('report')
    @classmethod
    def validate_report(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate report structure and size."""
        # Convert to string to check size
        import json
        report_str = json.dumps(v)

        # Limit report size to prevent DoS (10MB max)
        if len(report_str) > 10_000_000:
            raise ValueError("Report too large (max 10MB)")

        # Ensure findings key exists if provided
        if 'findings' in v:
            if not isinstance(v['findings'], list):
                raise ValueError("Findings must be a list")

            # Limit number of findings
            if len(v['findings']) > 10000:
                raise ValueError("Too many findings (max 10000)")

        return v

    @field_validator('ai_api_key')
    @classmethod
    def validate_api_key(cls, v: Optional[str]) -> Optional[str]:
        """Validate API key format (basic validation)."""
        if v is None:
            return v

        # Check for suspicious patterns
        if any(char in v for char in ['\n', '\r', '\x00']):
            raise ValueError("Invalid API key format")

        # API keys should be alphanumeric with some special chars
        if not re.match(r'^[a-zA-Z0-9\-_\.]+$', v):
            raise ValueError("Invalid API key format")

        return v

    class Config:
        json_schema_extra = {
            "example": {
                "report": {
                    "findings": [
                        {
                            "tool": "slither",
                            "vulnerability_type": "reentrancy",
                            "severity": "High",
                            "swc_id": "SWC-107"
                        }
                    ]
                },
                "enable_ai_triage": False
            }
        }


class ClassifyResponse(BaseModel):
    """Response model for vulnerability classification"""
    classified_findings: List[Dict[str, Any]]
    statistics: Dict[str, Any]
    ai_triage_enabled: bool
    timestamp: str
    context: str

    class Config:
        schema_extra = {
            "example": {
                "classified_findings": [],
                "statistics": {
                    "total_findings": 1,
                    "by_severity": {"High": 1},
                    "avg_cvss": 8.5
                },
                "ai_triage_enabled": False,
                "timestamp": "2025-01-20T12:00:00",
                "context": "MIESC AI vulnerability classification"
            }
        }


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    timestamp: str
    capabilities: List[str]


class MCPCapabilitiesResponse(BaseModel):
    """MCP capabilities endpoint response"""
    name: str
    version: str
    description: str
    capabilities: List[str]
    endpoints: Dict[str, Dict[str, str]]
