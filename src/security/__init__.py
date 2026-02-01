"""
Security Module for MIESC Framework

Provides input validation, rate limiting, security utilities,
and remediation suggestions for smart contract vulnerabilities.
"""

from .api_limiter import APIQuotaManager, RateLimiter, RateLimitExceeded
from .input_validator import (
    SecurityError,
    validate_contract_path,
    validate_function_name,
    validate_solc_version,
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

__version__ = "1.1.0"
