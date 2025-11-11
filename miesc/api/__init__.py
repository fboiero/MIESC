"""
MIESC API - MCP-compatible REST API for smart contract security

Provides FastAPI-based endpoints for:
- Contract analysis
- Formal verification
- Vulnerability classification
- MCP protocol support
"""

from miesc.api.server import app
from miesc.api.schema import (
    AnalysisRequest,
    AnalysisResponse,
    VerifyRequest,
    VerifyResponse,
    ClassifyRequest,
    ClassifyResponse
)

__all__ = [
    "app",
    "AnalysisRequest",
    "AnalysisResponse",
    "VerifyRequest",
    "VerifyResponse",
    "ClassifyRequest",
    "ClassifyResponse",
]
