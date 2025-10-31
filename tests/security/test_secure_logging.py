"""
Tests for Secure Logging Module

Validates that sensitive information is redacted from logs.
"""

import pytest
import logging
from io import StringIO

from src.security.secure_logging import SecureFormatter, setup_secure_logging


class TestSecureFormatter:
    """Tests for SecureFormatter class"""

    @pytest.fixture
    def log_stream(self):
        """Create a StringIO stream to capture log output"""
        return StringIO()

    @pytest.fixture
    def logger(self, log_stream):
        """Create a logger with SecureFormatter"""
        logger = logging.getLogger('test_secure_logger')
        logger.setLevel(logging.INFO)
        logger.handlers.clear()

        handler = logging.StreamHandler(log_stream)
        handler.setFormatter(SecureFormatter())
        logger.addHandler(handler)

        return logger

    def test_redacts_openai_api_keys(self, logger, log_stream):
        """Should redact OpenAI API keys"""
        logger.info("Using API key: sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab")

        output = log_stream.getvalue()
        assert "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab" not in output
        assert "sk-***REDACTED***" in output

    def test_redacts_anthropic_api_keys(self, logger, log_stream):
        """Should redact Anthropic API keys"""
        logger.info("Using key: sk-ant-api03-test123456789012345")

        output = log_stream.getvalue()
        assert "sk-ant-api03-test123456789012345" not in output
        assert "sk-ant-***REDACTED***" in output

    def test_redacts_huggingface_tokens(self, logger, log_stream):
        """Should redact HuggingFace tokens"""
        logger.info("Token: hf_1234567890abcdefghijklmnopqrstuvwxyz")

        output = log_stream.getvalue()
        assert "hf_1234567890abcdefghijklmnopqrstuvwxyz" not in output
        assert "hf_***REDACTED***" in output

    def test_redacts_passwords(self, logger, log_stream):
        """Should redact passwords"""
        test_cases = [
            "password: SuperSecret123",
            "passwd=test1234",
            "pwd: mypassword"
        ]

        for test_case in test_cases:
            log_stream.truncate(0)
            log_stream.seek(0)

            logger.info(test_case)
            output = log_stream.getvalue()

            # Password value should be redacted
            assert "***REDACTED***" in output

    def test_redacts_jwt_tokens(self, logger, log_stream):
        """Should redact JWT tokens"""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        logger.info(f"JWT token: {jwt}")

        output = log_stream.getvalue()
        assert jwt not in output
        assert "eyJ***REDACTED_JWT***" in output

    def test_redacts_private_keys(self, logger, log_stream):
        """Should redact private keys"""
        private_key = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...
-----END PRIVATE KEY-----"""

        logger.info(private_key)

        output = log_stream.getvalue()
        assert "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC..." not in output
        assert "***REDACTED PRIVATE KEY***" in output

    def test_redacts_credit_cards(self, logger, log_stream):
        """Should redact credit card numbers"""
        test_cases = [
            "Card: 4532-1234-5678-9010",
            "CC: 4532 1234 5678 9010",
            "4532123456789010"
        ]

        for test_case in test_cases:
            log_stream.truncate(0)
            log_stream.seek(0)

            logger.info(test_case)
            output = log_stream.getvalue()

            # Credit card should be redacted
            assert "4532" not in output or "****-****-****-****" in output

    def test_redacts_database_connection_strings(self, logger, log_stream):
        """Should redact passwords in connection strings"""
        test_cases = [
            "postgresql://user:password123@localhost:5432/db",
            "mysql://root:secret@127.0.0.1/mydb",
            "mongodb://admin:pass@mongodb.local:27017"
        ]

        for conn_str in test_cases:
            log_stream.truncate(0)
            log_stream.seek(0)

            logger.info(f"Connecting to: {conn_str}")
            output = log_stream.getvalue()

            # Password should be redacted
            assert "***REDACTED***" in output

    def test_redacts_aws_credentials(self, logger, log_stream):
        """Should redact AWS credentials"""
        logger.info("AWS Key: AKIAIOSFODNN7EXAMPLE")

        output = log_stream.getvalue()
        assert "AKIAIOSFODNN7EXAMPLE" not in output
        assert "AKIA***REDACTED***" in output

    def test_preserves_non_sensitive_data(self, logger, log_stream):
        """Should not redact non-sensitive data"""
        logger.info("Analyzing contract.sol")

        output = log_stream.getvalue()
        assert "Analyzing contract.sol" in output

    def test_multiple_secrets_in_one_message(self, logger, log_stream):
        """Should redact multiple secrets in one log message"""
        logger.info(
            "Config: api_key=sk-test123, password=secret, "
            "token=eyJhbGciOiJIUzI1NiJ9.test.signature"
        )

        output = log_stream.getvalue()

        # All secrets should be redacted
        assert "sk-test123" not in output
        assert "secret" not in output
        assert "signature" not in output
        assert "***REDACTED***" in output

    def test_static_redact_string_method(self):
        """Should redact strings without logging"""
        text = "API key: sk-test123 and password: secret123"

        redacted = SecureFormatter.redact_string(text)

        assert "sk-test123" not in redacted
        assert "secret123" not in redacted
        assert "***REDACTED***" in redacted


class TestSetupSecureLogging:
    """Tests for setup_secure_logging convenience function"""

    def test_setup_creates_logger_with_redaction(self):
        """Should create logger with secure formatter"""
        logger = setup_secure_logging('test_logger', level=logging.DEBUG)

        # Capture output
        import io
        stream = io.StringIO()
        logger.handlers[0].stream = stream

        logger.info("API key: sk-test123")

        output = stream.getvalue()
        assert "sk-***REDACTED***" in output

    def test_setup_respects_log_level(self):
        """Should respect configured log level"""
        logger = setup_secure_logging('test_logger', level=logging.WARNING)

        # Capture output
        import io
        stream = io.StringIO()
        logger.handlers[0].stream = stream

        logger.info("Info message")
        logger.warning("Warning message")

        output = stream.getvalue()

        # Info should not appear, warning should
        assert "Info message" not in output
        assert "Warning message" in output


class TestEdgeCases:
    """Tests for edge cases and special scenarios"""

    @pytest.fixture
    def logger(self):
        stream = StringIO()
        logger = logging.getLogger('edge_case_logger')
        logger.setLevel(logging.INFO)
        logger.handlers.clear()

        handler = logging.StreamHandler(stream)
        handler.setFormatter(SecureFormatter())
        logger.addHandler(handler)

        return logger, stream

    def test_empty_log_message(self, logger):
        """Should handle empty messages"""
        log, stream = logger
        log.info("")

        # Should not crash
        output = stream.getvalue()
        assert output is not None

    def test_very_long_message(self, logger):
        """Should handle very long messages"""
        log, stream = logger

        long_message = "x" * 10000 + " api_key=sk-test123 " + "y" * 10000

        log.info(long_message)

        output = stream.getvalue()
        assert "sk-test123" not in output

    def test_unicode_in_secrets(self, logger):
        """Should handle unicode in secrets"""
        log, stream = logger

        log.info("Password: p@ssw0rd™")

        output = stream.getvalue()
        assert "p@ssw0rd™" not in output or "***REDACTED***" in output

    def test_nested_json_with_secrets(self, logger):
        """Should redact secrets in JSON"""
        log, stream = logger

        json_str = '{"config": {"api_key": "sk-test123", "timeout": 30}}'
        log.info(json_str)

        output = stream.getvalue()
        assert "sk-test123" not in output


class TestPerformance:
    """Performance tests for secure logging"""

    def test_redaction_performance(self):
        """Redaction should not significantly slow down logging"""
        import time

        logger = setup_secure_logging('perf_test')
        stream = StringIO()
        logger.handlers[0].stream = stream

        start = time.time()

        # Log 1000 messages
        for i in range(1000):
            logger.info(f"Test message {i}")

        duration = time.time() - start

        # Should complete in reasonable time (< 1 second)
        assert duration < 1.0, f"Logging too slow: {duration}s for 1000 messages"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
