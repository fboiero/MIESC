"""
LLM Integration Module - MIESC v4.1.0
=====================================

Sovereign LLM integration using multiple backends (Ollama, OpenAI, Anthropic)
for intelligent post-processing of security analysis results across all layers.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: December 2025
Version: 2.0.0
"""

# v4.3.0+ New LLM Components (2025-2026 Improvements)
from .ensemble_detector import (
    EnsembleFinding,
    EnsembleResult,
    LLMEnsembleDetector,
    VotingStrategy,
    detect_with_ensemble,
)
from .finding_validator import (
    LLMFindingValidator,
    LLMValidation,
    ValidationResult,
    ValidatorConfig,
    validate_findings_sync,
)
from .llm_orchestrator import (
    AnthropicBackend,
    LLMBackend,
    LLMConfig,
    LLMOrchestrator,
    LLMProvider,
    LLMResponse,
    OllamaBackend,
    OpenAIBackend,
    VulnerabilityAnalysis,
    analyze_solidity,
)
from .openllama_helper import (
    OpenLLaMAHelper,
    enhance_findings_with_llm,
    explain_technical_output,
    generate_remediation_advice,
    prioritize_findings,
)
from .remediation_generator import (
    REMEDIATION_PATTERNS,
    Remediation,
    RemediationGenerator,
    RemediationResult,
    generate_fix,
    get_quick_fix,
)
from .vulnerability_rag import (
    EXPLOIT_EXAMPLES,
    SWC_REGISTRY,
    EnhancedFinding,
    SimilarVuln,
    VulnerabilityExample,
    VulnerabilityRAG,
)

# v5.1.0+ Embedding RAG with ChromaDB (optional dependencies)
try:
    from .embedding_rag import (
        VULNERABILITY_KNOWLEDGE_BASE,
        EmbeddingRAG,
        HybridRAG,
        RetrievalResult,
        VulnerabilityDocument,
        get_context_for_finding,
        get_rag,
        search_vulnerabilities,
    )

    _EMBEDDING_RAG_AVAILABLE = True
except ImportError:
    # ChromaDB/sentence-transformers not installed
    _EMBEDDING_RAG_AVAILABLE = False
    EmbeddingRAG = None
    HybridRAG = None
    RetrievalResult = None
    VulnerabilityDocument = None
    VULNERABILITY_KNOWLEDGE_BASE = None
    get_rag = None
    search_vulnerabilities = None
    get_context_for_finding = None

__all__ = [
    # Legacy OpenLLaMA helpers
    "OpenLLaMAHelper",
    "enhance_findings_with_llm",
    "explain_technical_output",
    "prioritize_findings",
    "generate_remediation_advice",
    # New LLM Orchestrator
    "LLMProvider",
    "LLMConfig",
    "LLMResponse",
    "VulnerabilityAnalysis",
    "LLMBackend",
    "OllamaBackend",
    "OpenAIBackend",
    "AnthropicBackend",
    "LLMOrchestrator",
    "analyze_solidity",
    # LLM Finding Validator
    "LLMFindingValidator",
    "LLMValidation",
    "ValidationResult",
    "ValidatorConfig",
    "validate_findings_sync",
    # v4.3.0+ LLM Ensemble Detector
    "LLMEnsembleDetector",
    "EnsembleFinding",
    "EnsembleResult",
    "VotingStrategy",
    "detect_with_ensemble",
    # v4.3.0+ Vulnerability RAG (keyword-based)
    "VulnerabilityRAG",
    "VulnerabilityExample",
    "SimilarVuln",
    "EnhancedFinding",
    "SWC_REGISTRY",
    "EXPLOIT_EXAMPLES",
    # v4.3.0+ Remediation Generator
    "RemediationGenerator",
    "Remediation",
    "RemediationResult",
    "REMEDIATION_PATTERNS",
    "generate_fix",
    "get_quick_fix",
    # v5.1.0+ Embedding RAG with ChromaDB (optional)
    "EmbeddingRAG",
    "HybridRAG",
    "RetrievalResult",
    "VulnerabilityDocument",
    "VULNERABILITY_KNOWLEDGE_BASE",
    "get_rag",
    "search_vulnerabilities",
    "get_context_for_finding",
    "_EMBEDDING_RAG_AVAILABLE",
]
