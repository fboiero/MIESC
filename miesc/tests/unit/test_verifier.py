"""
Unit Tests for miesc.core.verifier

Comprehensive test suite for formal verification module.
Target Coverage: >90%

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from miesc.core.verifier import FormalVerifier, verify_contract


class TestFormalVerifier:
    """Test suite for FormalVerifier class"""

    def test_verifier_initialization(self):
        """Test FormalVerifier initialization"""
        verifier = FormalVerifier(timeout=1200)

        assert verifier.timeout == 1200
        assert 'basic' in verifier.verification_methods
        assert 'smt' in verifier.verification_methods
        assert 'certora' in verifier.verification_methods
        assert 'halmos' in verifier.verification_methods

    def test_verifier_default_timeout(self):
        """Test default timeout value"""
        verifier = FormalVerifier()
        assert verifier.timeout == 600  # 10 minutes

    @patch('tempfile.NamedTemporaryFile')
    @patch('miesc.core.verifier.subprocess.run')
    def test_verify_basic_success(self, mock_run, mock_temp):
        """Test successful basic verification"""
        # Mock temp file
        mock_file = Mock()
        mock_file.name = '/tmp/test.sol'
        mock_file.write = Mock()
        mock_file.flush = Mock()
        mock_temp.return_value.__enter__.return_value = mock_file

        # Mock subprocess
        mock_run.return_value = Mock(
            stdout="",
            stderr="Warning: Assertion violation\nline 10",
            returncode=0
        )

        verifier = FormalVerifier()
        result = verifier.verify("contract Test {}", "basic")

        assert result['status'] == 'completed'
        assert result['method'] == 'SMTChecker'
        assert 'warnings' in result

    @patch('miesc.core.verifier.subprocess.run')
    def test_verify_basic_timeout(self, mock_run):
        """Test verification timeout"""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired('solc', 600)

        verifier = FormalVerifier(timeout=1)
        result = verifier.verify("contract Test {}", "basic")

        assert result['status'] == 'timeout'

    def test_verify_unknown_level(self):
        """Test verification with unknown level"""
        verifier = FormalVerifier()
        result = verifier.verify("contract Test {}", "unknown_level")

        # Should default to basic
        assert result['status'] in ['completed', 'error']

    def test_verify_smt_level(self):
        """Test SMT-level verification"""
        verifier = FormalVerifier()
        result = verifier.verify("contract Test {}", "smt", ["balance >= 0"])

        assert result['level'] == 'smt'
        assert result['method'] == 'Z3 Solver'

    def test_verify_certora_level(self):
        """Test Certora verification"""
        verifier = FormalVerifier()
        result = verifier.verify("contract Test {}", "certora")

        assert result['level'] == 'certora'

    def test_verify_halmos_level(self):
        """Test Halmos verification"""
        verifier = FormalVerifier()
        result = verifier.verify("contract Test {}", "halmos")

        assert result['level'] == 'halmos'

    def test_verify_with_properties(self):
        """Test verification with properties"""
        verifier = FormalVerifier()
        properties = [
            "invariant balance >= 0",
            "require msg.value > 0"
        ]
        result = verifier.verify("contract Test {}", "basic", properties)

        assert result['properties_verified'] == 2

    def test_verify_error_handling(self):
        """Test error handling in verification"""
        with patch('miesc.core.verifier.subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Unexpected error")

            verifier = FormalVerifier()
            result = verifier.verify("contract Test {}", "basic")

            assert result['status'] == 'error'
            assert 'message' in result


class TestVerifyContractFunction:
    """Test suite for verify_contract main function"""

    @patch('miesc.core.verifier.FormalVerifier')
    def test_verify_contract_basic(self, mock_verifier_class):
        """Test basic contract verification"""
        mock_verifier = Mock()
        mock_verifier.verify.return_value = {
            'status': 'completed',
            'level': 'basic',
            'warnings': []
        }
        mock_verifier_class.return_value = mock_verifier

        result = verify_contract("contract Test {}", "basic")

        assert result['status'] == 'completed'
        assert result['level'] == 'basic'

    @patch('miesc.core.verifier.FormalVerifier')
    def test_verify_contract_with_timeout(self, mock_verifier_class):
        """Test verification with custom timeout"""
        mock_verifier = Mock()
        mock_verifier.verify.return_value = {'status': 'completed'}
        mock_verifier_class.return_value = mock_verifier

        verify_contract("contract Test {}", "basic", timeout=1200)

        mock_verifier_class.assert_called_with(timeout=1200)


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
