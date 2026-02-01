"""
MIESC LLM Module

Re-exports from src/llm for backward compatibility.
Provides multi-backend LLM orchestration for security analysis.
"""

try:
    from src.llm import (
        AnthropicBackend,
        LLMBackend,
        LLMConfig,
        LLMOrchestrator,
        # New LLM Orchestrator
        LLMProvider,
        LLMResponse,
        OllamaBackend,
        OpenAIBackend,
        # Legacy helpers
        OpenLLaMAHelper,
        VulnerabilityAnalysis,
        analyze_solidity,
        enhance_findings_with_llm,
        explain_technical_output,
        generate_remediation_advice,
        prioritize_findings,
    )
except ImportError:
    OpenLLaMAHelper = None
    enhance_findings_with_llm = None
    explain_technical_output = None
    prioritize_findings = None
    generate_remediation_advice = None
    LLMProvider = None
    LLMConfig = None
    LLMResponse = None
    VulnerabilityAnalysis = None
    LLMBackend = None
    OllamaBackend = None
    OpenAIBackend = None
    AnthropicBackend = None
    LLMOrchestrator = None
    analyze_solidity = None

__all__ = [
    "OpenLLaMAHelper",
    "enhance_findings_with_llm",
    "explain_technical_output",
    "prioritize_findings",
    "generate_remediation_advice",
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
