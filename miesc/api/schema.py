"""
MIESC API Schema - Pydantic models for request/response validation

Defines data models for MCP-compatible API
"""

from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime


class AnalysisRequest(BaseModel):
    """Request model for contract analysis"""
    contract_code: str = Field(..., description="Solidity source code or file path")
    analysis_type: str = Field(default="slither", description="Tool to use (slither, mythril, all)")
    timeout: int = Field(default=300, description="Maximum execution time in seconds")

    class Config:
        schema_extra = {
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
    """Request model for formal verification"""
    contract_code: str = Field(..., description="Solidity source code or file path")
    verification_level: str = Field(default="basic", description="Level: basic, smt, certora, halmos")
    properties: Optional[List[str]] = Field(default=None, description="Properties to verify")
    timeout: int = Field(default=600, description="Maximum verification time in seconds")

    class Config:
        schema_extra = {
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
    """Request model for vulnerability classification"""
    report: Dict[str, Any] = Field(..., description="Analysis report to classify")
    enable_ai_triage: bool = Field(default=False, description="Enable AI-powered triage")
    ai_api_key: Optional[str] = Field(default=None, description="OpenAI API key for AI triage")

    class Config:
        schema_extra = {
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
