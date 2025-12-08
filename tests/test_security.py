"""
MIESC Security Module Tests
Tests for input validation, rate limiting, and secure logging.
"""

import pytest
import time
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import logging


# =============================================================================
# INPUT VALIDATOR TESTS
# =============================================================================

class TestInputValidator:
    """Tests for input validation module."""

    def test_import_module(self):
        """Test that security module can be imported."""
        from src.security.input_validator import (
            validate_contract_path,
            SecurityError
        )
        assert callable(validate_contract_path)
        assert issubclass(SecurityError, Exception)

    def test_validate_existing_sol_file(self):
        """Test validation of existing .sol file."""
        from src.security.input_validator import validate_contract_path

        # Create a temporary .sol file
        with tempfile.NamedTemporaryFile(suffix='.sol', delete=False) as f:
            f.write(b'pragma solidity ^0.8.0; contract Test {}')
            temp_path = f.name

        try:
            # Should succeed with the temp file in allowed dirs
            result = validate_contract_path(
                temp_path,
                allowed_base_dirs=[os.path.dirname(temp_path)]
            )
            assert result == temp_path or result == str(Path(temp_path).resolve())
        finally:
            os.unlink(temp_path)

    def test_validate_nonexistent_file(self):
        """Test validation fails for non-existent file."""
        from src.security.input_validator import validate_contract_path, SecurityError

        # Non-existent file outside allowed dirs raises SecurityError
        with pytest.raises((FileNotFoundError, SecurityError)):
            validate_contract_path('/nonexistent/path/contract.sol')

    def test_validate_wrong_extension(self):
        """Test validation fails for wrong file extension."""
        from src.security.input_validator import validate_contract_path, SecurityError

        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'not a solidity file')
            temp_path = f.name

        try:
            with pytest.raises(SecurityError):
                validate_contract_path(
                    temp_path,
                    allowed_extensions=['.sol'],
                    allowed_base_dirs=[os.path.dirname(temp_path)]
                )
        finally:
            os.unlink(temp_path)

    def test_path_traversal_detection(self):
        """Test that path traversal attempts are blocked."""
        from src.security.input_validator import validate_contract_path, SecurityError

        # Attempt path traversal
        with pytest.raises((SecurityError, FileNotFoundError)):
            validate_contract_path('../../../etc/passwd')

    def test_custom_allowed_extensions(self):
        """Test validation with custom allowed extensions."""
        from src.security.input_validator import validate_contract_path

        with tempfile.NamedTemporaryFile(suffix='.vy', delete=False) as f:
            f.write(b'# Vyper contract')
            temp_path = f.name

        try:
            result = validate_contract_path(
                temp_path,
                allowed_extensions=['.vy', '.sol'],
                allowed_base_dirs=[os.path.dirname(temp_path)]
            )
            assert result is not None
        finally:
            os.unlink(temp_path)


# =============================================================================
# RATE LIMITER TESTS
# =============================================================================

class TestRateLimiter:
    """Tests for rate limiting module."""

    def test_import_module(self):
        """Test that rate limiter module can be imported."""
        from src.security.api_limiter import RateLimiter, RateLimitExceeded
        assert callable(RateLimiter)
        assert issubclass(RateLimitExceeded, Exception)

    def test_rate_limiter_initialization(self):
        """Test rate limiter can be initialized."""
        from src.security.api_limiter import RateLimiter

        limiter = RateLimiter(max_calls=10, period=60)
        assert limiter.max_calls == 10
        assert limiter.period == 60

    def test_rate_limiter_allows_calls_under_limit(self):
        """Test that calls under limit are allowed."""
        from src.security.api_limiter import RateLimiter

        limiter = RateLimiter(max_calls=5, period=60)

        @limiter
        def test_func():
            return "success"

        # Should allow 5 calls
        for _ in range(5):
            result = test_func()
            assert result == "success"

    def test_rate_limiter_blocks_excess_calls(self):
        """Test that calls over limit are blocked."""
        from src.security.api_limiter import RateLimiter, RateLimitExceeded

        limiter = RateLimiter(max_calls=3, period=60)

        @limiter
        def test_func():
            return "success"

        # First 3 calls should succeed
        for _ in range(3):
            test_func()

        # 4th call should raise
        with pytest.raises(RateLimitExceeded):
            test_func()

    def test_rate_limiter_with_burst(self):
        """Test rate limiter with burst allowance."""
        from src.security.api_limiter import RateLimiter

        limiter = RateLimiter(max_calls=5, period=60, burst_size=10)
        assert limiter.burst_size == 10


# =============================================================================
# SECURE LOGGING TESTS
# =============================================================================

class TestSecureLogging:
    """Tests for secure logging module."""

    def test_import_module(self):
        """Test that secure logging module can be imported."""
        from src.security.secure_logging import SecureFormatter
        assert issubclass(SecureFormatter, logging.Formatter)

    def test_secure_formatter_initialization(self):
        """Test SecureFormatter can be initialized."""
        from src.security.secure_logging import SecureFormatter

        formatter = SecureFormatter()
        assert formatter is not None

    def test_redacts_openai_api_key(self):
        """Test that OpenAI API keys are redacted."""
        from src.security.secure_logging import SecureFormatter

        formatter = SecureFormatter()

        # Create a log record with API key
        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='test.py',
            lineno=1,
            msg='Using API key: sk-1234567890abcdef1234567890abcdef1234567890abcdef',
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        assert 'sk-1234567890abcdef' not in formatted
        assert 'REDACTED' in formatted

    def test_redacts_password(self):
        """Test that passwords are redacted."""
        from src.security.secure_logging import SecureFormatter

        formatter = SecureFormatter()

        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='test.py',
            lineno=1,
            msg='password=mysecretpassword123',
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        assert 'mysecretpassword123' not in formatted
        assert 'REDACTED' in formatted

    def test_redacts_jwt_token(self):
        """Test that JWT tokens are redacted."""
        from src.security.secure_logging import SecureFormatter

        formatter = SecureFormatter()

        # Sample JWT structure
        jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'

        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='test.py',
            lineno=1,
            msg=f'Token: {jwt}',
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        assert jwt not in formatted

    def test_safe_message_unchanged(self):
        """Test that safe messages are not modified."""
        from src.security.secure_logging import SecureFormatter

        formatter = SecureFormatter()

        safe_msg = 'Analyzing contract: MyToken.sol'
        record = logging.LogRecord(
            name='test',
            level=logging.INFO,
            pathname='test.py',
            lineno=1,
            msg=safe_msg,
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        assert 'MyToken.sol' in formatted


# =============================================================================
# SECURITY ERROR TESTS
# =============================================================================

class TestSecurityError:
    """Tests for SecurityError exception."""

    def test_security_error_is_exception(self):
        """Test SecurityError is proper exception."""
        from src.security.input_validator import SecurityError

        error = SecurityError("test message")
        assert isinstance(error, Exception)
        assert str(error) == "test message"

    def test_security_error_can_be_raised(self):
        """Test SecurityError can be raised and caught."""
        from src.security.input_validator import SecurityError

        with pytest.raises(SecurityError) as exc_info:
            raise SecurityError("Path traversal detected")

        assert "Path traversal" in str(exc_info.value)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestSecurityIntegration:
    """Integration tests for security module."""

    def test_all_security_modules_importable(self):
        """Test all security modules can be imported."""
        from src.security import input_validator
        from src.security import api_limiter
        from src.security import secure_logging

        assert input_validator is not None
        assert api_limiter is not None
        assert secure_logging is not None

    def test_validate_real_contract_path(self):
        """Test validation with real contract in repo."""
        from src.security.input_validator import validate_contract_path

        # Test with actual contract file if it exists
        contract_path = Path('contracts/audit/VulnerableBank.sol')
        if contract_path.exists():
            result = validate_contract_path(str(contract_path))
            assert result is not None
            assert 'VulnerableBank.sol' in result


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
