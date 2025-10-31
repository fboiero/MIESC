"""
MIESC API Server - FastAPI-based MCP-compatible service

Provides REST API endpoints for smart contract security analysis
with full MCP (Model Context Protocol) support.

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
License: GPL-3.0
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
from datetime import datetime

from miesc.core.analyzer import analyze_contract
from miesc.core.verifier import verify_contract
from miesc.core.classifier import classify_vulnerabilities
from miesc.api.schema import (
    AnalysisRequest,
    AnalysisResponse,
    VerifyRequest,
    VerifyResponse,
    ClassifyRequest,
    ClassifyResponse,
    HealthResponse,
    MCPCapabilitiesResponse
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="MIESC MCP Service",
    description="Multi-layer Intelligent Evaluation for Smart Contracts - MCP-compatible API",
    version="3.3.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint - health check"""
    return {
        "status": "operational",
        "version": "3.3.0",
        "timestamp": datetime.now().isoformat(),
        "capabilities": ["analyze", "verify", "classify", "mcp"]
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "3.3.0",
        "timestamp": datetime.now().isoformat(),
        "capabilities": ["analyze", "verify", "classify", "mcp"]
    }


@app.get("/mcp/capabilities", response_model=MCPCapabilitiesResponse)
async def mcp_capabilities():
    """
    MCP capabilities endpoint

    Returns metadata about this MCP-compatible service
    """
    return {
        "name": "miesc",
        "version": "3.3.0",
        "description": "MIESC MCP-compatible audit and formal analysis service for smart contracts",
        "capabilities": [
            "audit",
            "formal_verification",
            "vulnerability_scoring",
            "multi_tool_analysis"
        ],
        "endpoints": {
            "analyze": {
                "method": "POST",
                "path": "/analyze",
                "description": "Static/dynamic analysis of smart contracts"
            },
            "verify": {
                "method": "POST",
                "path": "/verify",
                "description": "Formal verification of smart contract properties"
            },
            "classify": {
                "method": "POST",
                "path": "/classify",
                "description": "AI-powered vulnerability classification and scoring"
            }
        }
    }


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(req: AnalysisRequest):
    """
    Analyze smart contract for vulnerabilities

    Executes static/dynamic analysis using tools like Slither, Mythril, etc.

    Args:
        req: AnalysisRequest with contract code and parameters

    Returns:
        AnalysisResponse with findings and metadata
    """
    try:
        logger.info(f"Received analysis request for tool: {req.analysis_type}")

        result = analyze_contract(
            contract_code=req.contract_code,
            analysis_type=req.analysis_type,
            timeout=req.timeout
        )

        logger.info(f"Analysis completed: {result.get('total_findings', 0)} findings")

        return result

    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@app.post("/verify", response_model=VerifyResponse)
async def verify(req: VerifyRequest):
    """
    Verify smart contract properties using formal methods

    Executes formal verification using SMTChecker, Z3, Certora, or Halmos

    Args:
        req: VerifyRequest with contract code and verification level

    Returns:
        VerifyResponse with verification results
    """
    try:
        logger.info(f"Received verification request: level={req.verification_level}")

        result = verify_contract(
            contract_code=req.contract_code,
            verification_level=req.verification_level,
            properties=req.properties,
            timeout=req.timeout
        )

        logger.info(f"Verification completed: status={result.get('status')}")

        return result

    except Exception as e:
        logger.error(f"Verification error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Verification failed: {str(e)}"
        )


@app.post("/classify", response_model=ClassifyResponse)
async def classify(req: ClassifyRequest):
    """
    Classify and score vulnerabilities using AI/ML

    Enhances vulnerability reports with CVSS scores, OWASP mappings,
    and optional AI-powered false positive reduction.

    Args:
        req: ClassifyRequest with analysis report

    Returns:
        ClassifyResponse with classified findings and statistics
    """
    try:
        logger.info(f"Received classification request: AI={req.enable_ai_triage}")

        result = classify_vulnerabilities(
            report=req.report,
            enable_ai_triage=req.enable_ai_triage,
            ai_api_key=req.ai_api_key
        )

        logger.info(f"Classification completed: {len(result.get('classified_findings', []))} findings")

        return result

    except Exception as e:
        logger.error(f"Classification error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Classification failed: {str(e)}"
        )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting MIESC MCP Service")
    logger.info("API Documentation: http://localhost:8000/docs")
    logger.info("MCP Capabilities: http://localhost:8000/mcp/capabilities")

    # Secure default: bind to localhost only (use MIESC_HOST env var to override)
    # For Docker/production: set MIESC_HOST=0.0.0.0 explicitly
    host = os.getenv("MIESC_HOST", "127.0.0.1")
    port = int(os.getenv("MIESC_PORT", "8000"))

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )
