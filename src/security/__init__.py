"""
Security Module for MIESC Framework

Provides input validation, rate limiting, security utilities,
LLM security (prompt sanitization, output validation),
reproducibility utilities, and remediation suggestions.
"""

from .api_limiter import APIQuotaManager, RateLimiter, RateLimitExceeded
from .hallucination_detector import (
    HallucinationDetector,
    ValidatedFinding,
    ValidationResult,
    ValidationStatus,
    cross_validate_finding,
    filter_reliable_findings,
    validate_llm_findings,
)
from .input_validator import (
    SecurityError,
    validate_contract_path,
    validate_function_name,
    validate_solc_version,
)
from .llm_output_validator import (
    AnalysisResponse,
    VulnerabilityFinding,
    safe_parse_llm_json,
    validate_analysis_response,
    validate_vulnerability_finding,
)
from .llm_output_validator import (
    ValidationResult as LLMValidationResult,
)
from .prompt_sanitizer import (
    InjectionDetectionResult,
    InjectionRiskLevel,
    PromptInjectionWarning,
    build_safe_prompt,
    detect_prompt_injection,
    sanitize_code_for_prompt,
    sanitize_context,
    sanitize_finding_text,
)
from .remediation_engine import (
    EnrichedFinding,
    FixEffort,
    FixRisk,
    RemediationEngine,
    RemediationReport,
    enrich_with_remediations,
)
from .remediations import (
    Remediation,
    get_all_remediations,
    get_remediation,
    get_remediation_by_type,
    get_security_checklist,
)
from .reproducibility import (
    ExperimentLogger,
    ModelVersion,
    create_reproducibility_report,
    ensure_reproducibility,
    get_global_seed,
    get_model_version,
    set_global_seeds,
)
from .secure_logging import SecureFormatter, setup_secure_logging

__all__ = [
    # Input validation
    "validate_contract_path",
    "validate_solc_version",
    "validate_function_name",
    "SecurityError",
    # Rate limiting
    "RateLimiter",
    "APIQuotaManager",
    "RateLimitExceeded",
    # Logging
    "SecureFormatter",
    "setup_secure_logging",
    # Prompt sanitization (LLM security)
    "sanitize_code_for_prompt",
    "sanitize_context",
    "sanitize_finding_text",
    "detect_prompt_injection",
    "build_safe_prompt",
    "InjectionRiskLevel",
    "InjectionDetectionResult",
    "PromptInjectionWarning",
    # LLM output validation
    "safe_parse_llm_json",
    "validate_analysis_response",
    "validate_vulnerability_finding",
    "LLMValidationResult",
    "VulnerabilityFinding",
    "AnalysisResponse",
    # Reproducibility
    "set_global_seeds",
    "get_global_seed",
    "get_model_version",
    "ModelVersion",
    "ExperimentLogger",
    "create_reproducibility_report",
    "ensure_reproducibility",
    # Hallucination detection
    "HallucinationDetector",
    "validate_llm_findings",
    "cross_validate_finding",
    "filter_reliable_findings",
    "ValidatedFinding",
    "ValidationResult",
    "ValidationStatus",
    # Remediations
    "Remediation",
    "get_remediation",
    "get_remediation_by_type",
    "get_all_remediations",
    "get_security_checklist",
    # Remediation Engine
    "RemediationEngine",
    "EnrichedFinding",
    "RemediationReport",
    "FixEffort",
    "FixRisk",
    "enrich_with_remediations",
]

__version__ = "1.2.0"
