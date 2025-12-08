# MIESC Security Module

**English** | [Español](README_ES.md)

## Overview

Comprehensive security module for the MIESC framework providing:
- Input validation and sanitization
- API rate limiting and quota management
- Secure logging with automatic credential redaction

## Modules

### `input_validator.py`

Validates and sanitizes all user inputs to prevent:
- Path traversal attacks
- Command injection
- Invalid parameter exploitation

**Key Functions:**
```python
from src.security import validate_contract_path, validate_solc_version

# Validate contract path (prevents path traversal)
safe_path = validate_contract_path("examples/contract.sol")

# Validate Solidity version (prevents command injection)
safe_version = validate_solc_version("0.8.20")

# Validate all inputs at once
validated = validate_analysis_inputs(
    contract_path="examples/contract.sol",
    solc_version="0.8.20",
    timeout=300,
    functions=["transfer", "withdraw"]
)
```

### `api_limiter.py`

Manages API rate limits and quotas to prevent:
- API quota exhaustion
- Economic DoS attacks
- Cost overruns

**Key Classes:**
```python
from src.security import RateLimiter, APIQuotaManager

# Rate limiting decorator
@RateLimiter(max_calls=60, period=60)
def call_openai_api(prompt):
    return openai.ChatCompletion.create(...)

# Quota management
quota = APIQuotaManager(
    daily_limit=1000,
    daily_cost_limit=100.0,
    cost_per_call={'gpt-4': 0.03}
)

quota.check_quota('gpt-4')  # Raises RateLimitExceeded if exceeded
quota.record_call('gpt-4')  # Track usage
stats = quota.get_usage_stats()  # Get statistics
```

### `secure_logging.py`

Automatic redaction of sensitive information from logs:
- API keys (OpenAI, Anthropic, HuggingFace)
- Passwords and secrets
- JWT tokens
- Private keys
- Credit card numbers

**Setup:**
```python
from src.security import setup_secure_logging

logger = setup_secure_logging('miesc', level=logging.INFO)

# API keys are automatically redacted
logger.info("Using key: sk-1234567890abcdef")
# Output: "Using key: sk-***REDACTED***"
```

## Integration Examples

### Secure Agent Implementation

```python
from src.agents.base_agent import BaseAgent
from src.security import (
    validate_contract_path,
    validate_solc_version,
    RateLimiter,
    setup_secure_logging
)

class SecureStaticAgent(BaseAgent):
    def __init__(self):
        super().__init__("SecureStaticAgent", ["static_analysis"], "static")

        # Setup secure logging
        self.logger = setup_secure_logging(f'miesc.{self.agent_name}')

        # Setup rate limiting
        self.rate_limiter = RateLimiter(max_calls=100, period=60)

    def analyze(self, contract_path: str, **kwargs):
        # Validate inputs
        safe_path = validate_contract_path(contract_path)
        solc_version = kwargs.get('solc_version', '0.8.20')
        safe_version = validate_solc_version(solc_version)

        # Apply rate limiting
        self.rate_limiter._check_rate_limit()

        # Proceed with analysis
        self.logger.info(f"Analyzing {safe_path} with Solidity {safe_version}")
        # ... analysis code ...
```

### Secure API Calls

```python
from src.security import rate_limited_openai_call, openai_quota

@rate_limited_openai_call
def analyze_with_gpt(contract_code: str):
    """Rate limited and quota managed GPT analysis"""

    # Check quota before expensive operation
    openai_quota.check_quota('gpt-4')

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": contract_code}]
    )

    # Record usage
    openai_quota.record_call('gpt-4')

    return response
```

## Configuration

### Environment Variables

```bash
# Rate limiting
export MIESC_RATE_LIMIT_CALLS=60
export MIESC_RATE_LIMIT_PERIOD=60

# Quota management
export MIESC_DAILY_API_LIMIT=1000
export MIESC_DAILY_COST_LIMIT=100.0

# Logging
export MIESC_LOG_LEVEL=INFO
export MIESC_REDACT_EMAILS=false
export MIESC_REDACT_IPS=false
```

### Allowed Directories Configuration

By default, contract paths are restricted to:
- Current working directory
- `examples/`
- `contracts/`
- `tests/`

To customize:
```python
from src.security import validate_contract_path

allowed_dirs = [
    "/app/production_contracts",
    "/app/user_uploads"
]

safe_path = validate_contract_path(
    contract_path="user_contract.sol",
    allowed_base_dirs=allowed_dirs
)
```

## Security Best Practices

### 1. Always Validate Inputs

```python
# ❌ VULNERABLE
def analyze(contract_path):
    with open(contract_path, 'r') as f:  # No validation!
        return analyze_code(f.read())

# ✅ SECURE
def analyze(contract_path):
    safe_path = validate_contract_path(contract_path)
    with open(safe_path, 'r') as f:
        return analyze_code(f.read())
```

### 2. Use Rate Limiting for External APIs

```python
# ❌ VULNERABLE - No rate limiting
def call_api(data):
    return openai.ChatCompletion.create(...)

# ✅ SECURE
@RateLimiter(max_calls=60, period=60)
def call_api(data):
    return openai.ChatCompletion.create(...)
```

### 3. Enable Secure Logging

```python
# ❌ VULNERABLE - Logs may contain API keys
import logging
logger = logging.getLogger(__name__)
logger.info(f"Using API key: {api_key}")

# ✅ SECURE - Automatic redaction
from src.security import setup_secure_logging
logger = setup_secure_logging(__name__)
logger.info(f"Using API key: {api_key}")  # Automatically redacted
```

## Testing

Run security tests:
```bash
python -m pytest tests/security/ -v
```

Test input validation:
```bash
python -c "from src.security import validate_contract_path; \
           print(validate_contract_path('examples/reentrancy.sol'))"
```

Test secure logging:
```bash
python src/security/secure_logging.py
```

## Compliance

This security module helps achieve compliance with:

- **ISO/IEC 27001:2022**
  - A.8.8: Management of technical vulnerabilities
  - A.8.15: Logging
  - A.14.2.5: Secure system engineering principles

- **NIST SP 800-218 (SSDF)**
  - PW.8: Protect all forms of code from unauthorized access
  - RV.1.1: Identify and confirm vulnerabilities

- **OWASP Top 10 2021**
  - A03: Injection (prevented by input validation)
  - A09: Security Logging and Monitoring (secure logging)

## Changelog

### v1.0.0 (2024-10)
- Initial release
- Input validation module
- Rate limiting and quota management
- Secure logging with credential redaction

## License

AGPL-3.0 (same as MIESC framework)
