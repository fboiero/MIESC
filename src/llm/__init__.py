"""
LLM Integration Module - MIESC v4.1.0
=====================================

Sovereign LLM integration using multiple backends (Ollama, OpenAI, Anthropic)
for intelligent post-processing of security analysis results across all layers.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: December 2025
Version: 2.0.0
"""

from .openllama_helper import (
    OpenLLaMAHelper,
    enhance_findings_with_llm,
    explain_technical_output,
    prioritize_findings,
    generate_remediation_advice
)

from .llm_orchestrator import (
    LLMProvider,
    LLMConfig,
    LLMResponse,
    VulnerabilityAnalysis,
    LLMBackend,
    OllamaBackend,
    OpenAIBackend,
    AnthropicBackend,
    LLMOrchestrator,
    analyze_solidity
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
]
