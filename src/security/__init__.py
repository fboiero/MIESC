"""
Security Module for MIESC Framework

Provides input validation, rate limiting, security utilities,
and remediation suggestions for smart contract vulnerabilities.
"""

from .input_validator import (
    validate_contract_path,
    validate_solc_version,
    validate_function_name,
    SecurityError
)

from .api_limiter import (
    RateLimiter,
    APIQuotaManager,
    RateLimitExceeded
)

from .secure_logging import (
    SecureFormatter,
    setup_secure_logging
)

from .remediations import (
    Remediation,
    get_remediation,
    get_remediation_by_type,
    get_all_remediations,
    get_security_checklist,
)

from .remediation_engine import (
    RemediationEngine,
    EnrichedFinding,
    RemediationReport,
    FixEffort,
    FixRisk,
    enrich_with_remediations,
)

__all__ = [
    # Input validation
    'validate_contract_path',
    'validate_solc_version',
    'validate_function_name',
    'SecurityError',
    # Rate limiting
    'RateLimiter',
    'APIQuotaManager',
    'RateLimitExceeded',
    # Logging
    'SecureFormatter',
    'setup_secure_logging',
    # Remediations
    'Remediation',
    'get_remediation',
    'get_remediation_by_type',
    'get_all_remediations',
    'get_security_checklist',
    # Remediation Engine
    'RemediationEngine',
    'EnrichedFinding',
    'RemediationReport',
    'FixEffort',
    'FixRisk',
    'enrich_with_remediations',
]

__version__ = '1.1.0'
