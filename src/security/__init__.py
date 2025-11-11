"""
Security Module for MIESC Framework

Provides input validation, rate limiting, and security utilities
to prevent common vulnerabilities in smart contract analysis workflows.
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

__all__ = [
    'validate_contract_path',
    'validate_solc_version',
    'validate_function_name',
    'SecurityError',
    'RateLimiter',
    'APIQuotaManager',
    'RateLimitExceeded',
    'SecureFormatter',
    'setup_secure_logging'
]

__version__ = '1.0.0'
