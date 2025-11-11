"""
Tests for Input Validation Module

Validates that input sanitization prevents:
- Path traversal attacks
- Command injection
- Invalid parameter exploitation
"""

import pytest
import os
import tempfile
from pathlib import Path

from src.security.input_validator import (
    validate_contract_path,
    validate_solc_version,
    validate_function_name,
    validate_timeout,
    validate_analysis_inputs,
    SecurityError
)


class TestPathValidation:
    """Tests for contract path validation"""

    @pytest.fixture
    def temp_contract(self):
        """Create a temporary contract file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write("pragma solidity ^0.8.0;\ncontract Test {}")
            temp_path = f.name

        yield temp_path

        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def test_valid_path(self, temp_contract):
        """Valid path should pass validation"""
        # Allow the temp directory
        allowed_dirs = [os.path.dirname(temp_contract)]
        result = validate_contract_path(temp_contract, allowed_base_dirs=allowed_dirs)
        assert result == str(Path(temp_contract).resolve())

    def test_path_traversal_attack(self):
        """Path traversal should be blocked"""
        with pytest.raises(SecurityError, match="Path traversal"):
            validate_contract_path("../../../etc/passwd")

    def test_invalid_extension(self, temp_contract):
        """Non-.sol files should be rejected"""
        # Create file with wrong extension
        wrong_ext = temp_contract.replace('.sol', '.txt')
        os.rename(temp_contract, wrong_ext)

        try:
            with pytest.raises(SecurityError, match="Invalid file extension"):
                allowed_dirs = [os.path.dirname(wrong_ext)]
                validate_contract_path(wrong_ext, allowed_base_dirs=allowed_dirs)
        finally:
            if os.path.exists(wrong_ext):
                os.unlink(wrong_ext)

    def test_nonexistent_file(self):
        """Non-existent file should raise FileNotFoundError"""
        with pytest.raises(FileNotFoundError):
            validate_contract_path("/nonexistent/contract.sol")

    def test_directory_not_file(self):
        """Directory should be rejected"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(SecurityError, match="not a file"):
                allowed_dirs = [tmpdir]
                validate_contract_path(tmpdir, allowed_base_dirs=allowed_dirs)

    def test_symlink_escape(self, temp_contract):
        """Symlink escaping allowed directory should be blocked"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create symlink pointing outside allowed directory
            link_path = os.path.join(tmpdir, "escape.sol")
            os.symlink(temp_contract, link_path)

            with pytest.raises(SecurityError, match="Path traversal"):
                # Only allow tmpdir
                validate_contract_path(link_path, allowed_base_dirs=[tmpdir])


class TestSolcVersionValidation:
    """Tests for Solidity version validation"""

    def test_valid_versions(self):
        """Valid version formats should pass"""
        valid_versions = [
            "0.8.20",
            "0.8.0",
            "0.4.26",
            "0.7.6",
            "0.8.20+commit.a1b2c3d4"
        ]

        for version in valid_versions:
            result = validate_solc_version(version)
            assert result == version

    def test_invalid_version_format(self):
        """Invalid version formats should be rejected"""
        invalid_versions = [
            "1.0.0",  # Wrong major version
            "0.3.0",  # Too old
            "0.9.0",  # Too new (doesn't exist yet)
            "0.8",    # Incomplete
            "0.8.20; rm -rf /",  # Command injection attempt
            "0.8.20 && cat /etc/passwd",  # Command injection
            "../../../etc/passwd",  # Path traversal
        ]

        for version in invalid_versions:
            with pytest.raises(SecurityError, match="Invalid Solidity version"):
                validate_solc_version(version)


class TestFunctionNameValidation:
    """Tests for function name validation"""

    def test_valid_function_names(self):
        """Valid function names should pass"""
        valid_names = [
            "transfer",
            "transferFrom",
            "approve",
            "balanceOf",
            "_internalFunction",
            "function123",
            "myFunction_v2"
        ]

        for name in valid_names:
            result = validate_function_name(name)
            assert result == name

    def test_invalid_function_names(self):
        """Invalid function names should be rejected"""
        invalid_names = [
            "transfer(); DROP TABLE users;--",  # SQL injection
            "transfer; rm -rf /",  # Command injection
            "transfer&& cat /etc/passwd",  # Command injection
            "123function",  # Starts with number
            "function-name",  # Contains dash
            "function name",  # Contains space
            "function.name",  # Contains dot
        ]

        for name in invalid_names:
            with pytest.raises(SecurityError, match="Invalid function name"):
                validate_function_name(name)

    def test_function_name_too_long(self):
        """Function names over 100 characters should be rejected"""
        long_name = "a" * 101
        with pytest.raises(SecurityError, match="too long"):
            validate_function_name(long_name)


class TestTimeoutValidation:
    """Tests for timeout validation"""

    def test_valid_timeouts(self):
        """Valid timeout values should pass"""
        valid_timeouts = [1, 60, 300, 3600]

        for timeout in valid_timeouts:
            result = validate_timeout(timeout)
            assert result == timeout

    def test_invalid_timeout_types(self):
        """Non-integer timeouts should be rejected"""
        invalid_timeouts = ["not_a_number", None, 3.14, [60], {"timeout": 60}]

        for timeout in invalid_timeouts:
            with pytest.raises(SecurityError, match="Invalid timeout"):
                validate_timeout(timeout)

    def test_timeout_out_of_bounds(self):
        """Timeouts outside bounds should be rejected"""
        with pytest.raises(SecurityError, match="out of bounds"):
            validate_timeout(0)

        with pytest.raises(SecurityError, match="out of bounds"):
            validate_timeout(99999)


class TestAnalysisInputsValidation:
    """Tests for complete analysis inputs validation"""

    @pytest.fixture
    def temp_contract(self):
        """Create a temporary contract file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write("pragma solidity ^0.8.0;\ncontract Test {}")
            temp_path = f.name

        yield temp_path

        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def test_valid_complete_inputs(self, temp_contract):
        """All valid inputs should pass"""
        allowed_dirs = [os.path.dirname(temp_contract)]

        # Temporarily allow the temp directory
        original_path = validate_contract_path.__code__

        result = validate_analysis_inputs(
            contract_path=temp_contract,
            solc_version="0.8.20",
            timeout=300,
            functions=["transfer", "approve"]
        )

        assert 'contract_path' in result
        assert result['solc_version'] == "0.8.20"
        assert result['timeout'] == 300
        assert len(result['functions']) == 2

    def test_partial_inputs(self, temp_contract):
        """Optional parameters should work"""
        # Just contract path
        result = validate_analysis_inputs(contract_path=temp_contract)
        assert 'contract_path' in result
        assert 'solc_version' not in result

    def test_invalid_function_in_list(self, temp_contract):
        """Invalid function in list should raise error"""
        with pytest.raises(SecurityError, match="Invalid function name"):
            validate_analysis_inputs(
                contract_path=temp_contract,
                functions=["transfer", "'; DROP TABLE users;--"]
            )


class TestSecurityBypass:
    """Tests for attempted security bypasses"""

    def test_null_byte_injection(self):
        """Null byte injection should not bypass validation"""
        with pytest.raises((SecurityError, ValueError)):
            validate_contract_path("/etc/passwd\x00.sol")

    def test_unicode_bypass(self):
        """Unicode characters should not bypass validation"""
        with pytest.raises((SecurityError, FileNotFoundError)):
            validate_contract_path("../../../etc/passwd\u202e.sol")

    def test_double_encoding(self):
        """Double-encoded paths should not bypass validation"""
        with pytest.raises((SecurityError, FileNotFoundError)):
            validate_contract_path("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
