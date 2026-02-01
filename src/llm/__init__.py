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
    # v4.3.0+ Vulnerability RAG
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
]
