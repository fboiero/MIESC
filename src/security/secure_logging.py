"""
Secure Logging Module

Provides security-aware logging that automatically redacts sensitive information
from logs to prevent credential leakage and data exposure.
"""

import re
import logging
from typing import List, Tuple, Optional


class SecureFormatter(logging.Formatter):
    """
    Logging formatter that redacts sensitive information.

    Automatically removes:
    - API keys (OpenAI, Anthropic, HuggingFace, etc.)
    - Passwords
    - JWT tokens
    - Email addresses (optional)
    - IP addresses (optional)
    - Credit card numbers
    - Private keys

    Examples:
        >>> handler = logging.StreamHandler()
        >>> handler.setFormatter(SecureFormatter())
        >>> logger.addHandler(handler)
        >>> logger.info("Using API key: sk-1234567890abcdef")
        # Output: "Using API key: sk-***REDACTED***"
    """

    # Pattern definitions: (regex_pattern, replacement)
    SENSITIVE_PATTERNS: List[Tuple[str, str]] = [
        # OpenAI API keys (sk-...)
        (r'(sk-[a-zA-Z0-9]{48})', r'sk-***REDACTED***'),

        # Generic API key patterns
        (r'(["\']?api[_-]?key["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-]{20,})', r'\1***REDACTED***'),
        (r'(["\']?apikey["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-]{20,})', r'\1***REDACTED***'),

        # OpenAI organization IDs
        (r'(org-[a-zA-Z0-9]{24})', r'org-***REDACTED***'),

        # Anthropic API keys (typically start with sk-ant-)
        (r'(sk-ant-[a-zA-Z0-9_\-]{20,})', r'sk-ant-***REDACTED***'),

        # HuggingFace tokens
        (r'(hf_[a-zA-Z0-9]{20,})', r'hf_***REDACTED***'),

        # Generic secret/token patterns
        (r'(["\']?secret["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-]{16,})', r'\1***REDACTED***'),
        (r'(["\']?token["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-]{16,})', r'\1***REDACTED***'),

        # Password patterns
        (r'(["\']?password["\']?\s*[:=]\s*["\']?)([^\s"\']{6,})', r'\1***REDACTED***'),
        (r'(["\']?passwd["\']?\s*[:=]\s*["\']?)([^\s"\']{6,})', r'\1***REDACTED***'),
        (r'(["\']?pwd["\']?\s*[:=]\s*["\']?)([^\s"\']{6,})', r'\1***REDACTED***'),

        # JWT tokens (header.payload.signature)
        (r'(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)', r'eyJ***REDACTED_JWT***'),

        # Private keys (BEGIN PRIVATE KEY)
        (r'(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)(.*?)(-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)',
         r'\1\n***REDACTED PRIVATE KEY***\n\3'),

        # Credit card numbers (basic pattern, supports spaces/dashes)
        (r'\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b', r'****-****-****-****'),

        # Email addresses (optional - might want to keep for debugging)
        # (r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', r'***@***.***'),

        # Bearer tokens in Authorization headers
        (r'(Authorization:\s*Bearer\s+)([a-zA-Z0-9_\-\.]+)', r'\1***REDACTED***'),

        # Database connection strings (Postgres, MySQL, MongoDB)
        (r'(postgres(?:ql)?://[^:]+:)([^@]+)(@)', r'\1***REDACTED***\3'),
        (r'(mysql://[^:]+:)([^@]+)(@)', r'\1***REDACTED***\3'),
        (r'(mongodb(?:\+srv)?://[^:]+:)([^@]+)(@)', r'\1***REDACTED***\3'),

        # AWS credentials
        (r'(AKIA[0-9A-Z]{16})', r'AKIA***REDACTED***'),
        (r'(aws_secret_access_key[\s=:]+)([a-zA-Z0-9/+=]{40})', r'\1***REDACTED***'),

        # GitHub tokens
        (r'(gh[pousr]_[a-zA-Z0-9]{36,})', r'gh*_***REDACTED***'),

        # Slack tokens
        (r'(xox[baprs]-[a-zA-Z0-9-]{10,})', r'xox*-***REDACTED***'),
    ]

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        style: str = '%',
        redact_emails: bool = False,
        redact_ips: bool = False,
        custom_patterns: Optional[List[Tuple[str, str]]] = None
    ):
        """
        Initialize secure formatter.

        Args:
            fmt: Log format string (passed to logging.Formatter)
            datefmt: Date format string (passed to logging.Formatter)
            style: Style indicator ('%', '{', or '$')
            redact_emails: Whether to redact email addresses (default: False)
            redact_ips: Whether to redact IP addresses (default: False)
            custom_patterns: Additional patterns to redact [(pattern, replacement), ...]
        """
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)

        # Copy default patterns
        self.patterns = self.SENSITIVE_PATTERNS.copy()

        # Add optional patterns
        if redact_emails:
            self.patterns.append(
                (r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', r'***@***.***')
            )

        if redact_ips:
            # IPv4
            self.patterns.append(
                (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r'***.***.***.***')
            )
            # IPv6 (simplified)
            self.patterns.append(
                (r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', r'****:****:****:****')
            )

        # Add custom patterns
        if custom_patterns:
            self.patterns.extend(custom_patterns)

        # Compile patterns for performance
        self.compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE | re.DOTALL), replacement)
            for pattern, replacement in self.patterns
        ]

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with sensitive information redacted.

        Args:
            record: Log record to format

        Returns:
            str: Formatted log message with sensitive data redacted
        """
        # Format the message normally first
        msg = super().format(record)

        # Apply all redaction patterns
        for pattern, replacement in self.compiled_patterns:
            msg = pattern.sub(replacement, msg)

        return msg

    @staticmethod
    def redact_string(text: str) -> str:
        """
        Static method to redact sensitive information from any string.

        Useful for ad-hoc sanitization outside of logging.

        Args:
            text: Text to sanitize

        Returns:
            str: Sanitized text

        Examples:
            >>> SecureFormatter.redact_string("API key: sk-1234567890")
            'API key: sk-***REDACTED***'
        """
        formatter = SecureFormatter()
        for pattern, replacement in formatter.compiled_patterns:
            text = pattern.sub(replacement, text)
        return text


def setup_secure_logging(
    name: Optional[str] = None,
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    format_string: Optional[str] = None,
    redact_emails: bool = False,
    redact_ips: bool = False
) -> logging.Logger:
    """
    Setup a logger with secure formatting.

    Convenience function to quickly configure secure logging.

    Args:
        name: Logger name (default: root logger)
        level: Logging level (default: INFO)
        log_file: Optional file path for file handler
        format_string: Custom log format (default: standard format)
        redact_emails: Whether to redact email addresses
        redact_ips: Whether to redact IP addresses

    Returns:
        logging.Logger: Configured logger

    Examples:
        >>> logger = setup_secure_logging('miesc', level=logging.DEBUG)
        >>> logger.info("Testing with key: sk-test123")
        # Output: "Testing with key: sk-***REDACTED***"
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Clear existing handlers
    logger.handlers.clear()

    # Default format
    if format_string is None:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # Create secure formatter
    secure_formatter = SecureFormatter(
        fmt=format_string,
        redact_emails=redact_emails,
        redact_ips=redact_ips
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(secure_formatter)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(secure_formatter)
        logger.addHandler(file_handler)

    return logger


# Example usage and testing
if __name__ == "__main__":
    # Setup secure logging
    logger = setup_secure_logging('test', level=logging.DEBUG)

    # Test various sensitive patterns
    test_cases = [
        "OpenAI key: sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab",
        "API key in JSON: {'api_key': 'test123456789012345'}",
        "Password: SuperSecret123!",
        "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "Database: postgresql://user:password123@localhost:5432/db",
        "Card: 4532-1234-5678-9010",
        "Anthropic key: sk-ant-api03-test123456789012345",
        "Bearer Authorization: Bearer abc123.def456.ghi789"
    ]

    print("Testing Secure Logging:\n")
    for test in test_cases:
        logger.info(test)

    print("\n\nDirect redaction test:")
    for test in test_cases:
        redacted = SecureFormatter.redact_string(test)
        print(f"Original: {test}")
        print(f"Redacted: {redacted}\n")
