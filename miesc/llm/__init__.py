"""
MIESC LLM Module

Re-exports from src/llm for backward compatibility.
Provides multi-backend LLM orchestration for security analysis.
"""

try:
    from src.llm import (
        AgentCapability,
        AnthropicBackend,
        CounterexampleEvidence,
        DPGAgentConfig,
        InvariantCandidate,
        InvariantCategory,
        InvariantExtractionAgent,
        LLMBackend,
        LLMConfig,
        LLMOrchestrator,
        LLMOrchestratorReasoningProvider,
        # New LLM Orchestrator
        LLMProvider,
        LLMResponse,
        LocalHeuristicReasoningProvider,
        OllamaBackend,
        OpenAIBackend,
        # Legacy helpers
        OpenLLaMAHelper,
        ReasoningProvider,
        ReasoningProviderRoute,
        ReasoningResult,
        ReasoningTask,
        VulnerabilityAnalysis,
        analyze_solidity,
        auto_reasoning_provider,
        enhance_findings_with_llm,
        explain_technical_output,
        generate_remediation_advice,
        parse_invariant_candidates,
        prioritize_findings,
    )
except ImportError:
    AgentCapability = None
    CounterexampleEvidence = None
    DPGAgentConfig = None
    InvariantCandidate = None
    InvariantCategory = None
    InvariantExtractionAgent = None
    LLMOrchestratorReasoningProvider = None
    LocalHeuristicReasoningProvider = None
    OpenLLaMAHelper = None
    ReasoningProvider = None
    ReasoningProviderRoute = None
    ReasoningResult = None
    ReasoningTask = None
    auto_reasoning_provider = None
    enhance_findings_with_llm = None
    explain_technical_output = None
    prioritize_findings = None
    generate_remediation_advice = None
    parse_invariant_candidates = None
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
    "AgentCapability",
    "CounterexampleEvidence",
    "DPGAgentConfig",
    "InvariantCandidate",
    "InvariantCategory",
    "InvariantExtractionAgent",
    "LLMOrchestratorReasoningProvider",
    "LocalHeuristicReasoningProvider",
    "OpenLLaMAHelper",
    "ReasoningProvider",
    "ReasoningProviderRoute",
    "ReasoningResult",
    "ReasoningTask",
    "auto_reasoning_provider",
    "enhance_findings_with_llm",
    "explain_technical_output",
    "prioritize_findings",
    "generate_remediation_advice",
    "parse_invariant_candidates",
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
