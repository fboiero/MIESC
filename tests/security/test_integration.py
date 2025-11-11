"""
Integration Tests for Security Module

Tests complete security workflows combining multiple components.
"""

import pytest
import tempfile
import os
from pathlib import Path

try:
    from src.security import (
        validate_contract_path,
        validate_solc_version,
        RateLimiter,
        APIQuotaManager,
        setup_secure_logging,
        SecurityError,
        RateLimitExceeded
    )
    SECURITY_IMPORTS_AVAILABLE = True
except ImportError:
    SECURITY_IMPORTS_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not SECURITY_IMPORTS_AVAILABLE,
    reason="Security module imports not available"
)


class TestSecureAnalysisWorkflow:
    """Test complete analysis workflow with security"""

    @pytest.fixture
    def temp_contract(self):
        """Create a temporary contract file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write("""
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint) public balances;

    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
            """)
            temp_path = f.name

        yield temp_path

        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def test_complete_secure_analysis(self, temp_contract):
        """Test complete analysis with all security measures"""

        # 1. Setup secure logging
        logger = setup_secure_logging('test_analysis')

        # 2. Validate inputs
        allowed_dirs = [os.path.dirname(temp_contract)]
        safe_path = validate_contract_path(temp_contract, allowed_base_dirs=allowed_dirs)
        safe_version = validate_solc_version("0.8.20")

        logger.info(f"Analyzing {safe_path} with Solidity {safe_version}")

        # 3. Setup rate limiting
        limiter = RateLimiter(max_calls=10, period=60)
        quota = APIQuotaManager(daily_limit=100, daily_cost_limit=10.0)

        # 4. Simulate analysis with rate limiting
        @limiter
        def analyze_contract(path):
            quota.check_quota('slither')
            quota.record_call('slither', cost=0.0)
            return {"findings": ["Reentrancy vulnerability"]}

        # 5. Run analysis
        result = analyze_contract(safe_path)

        # 6. Verify
        assert result['findings']
        logger.info(f"Analysis complete: {len(result['findings'])} findings")

    def test_security_blocks_malicious_inputs(self, temp_contract):
        """Test that security measures block malicious inputs"""

        # Path traversal attempt
        with pytest.raises((SecurityError, FileNotFoundError)):
            validate_contract_path("../../../etc/passwd")

        # Command injection attempt
        with pytest.raises(SecurityError):
            validate_solc_version("0.8.20; rm -rf /")

        # Rate limit bypass attempt
        limiter = RateLimiter(max_calls=3, period=60)

        # Use up quota
        for i in range(3):
            limiter._check_rate_limit()

        # Should be blocked
        with pytest.raises(RateLimitExceeded):
            limiter._check_rate_limit()

    def test_security_allows_legitimate_usage(self, temp_contract):
        """Test that security doesn't break legitimate usage"""

        # Setup
        logger = setup_secure_logging('legit_test')
        allowed_dirs = [os.path.dirname(temp_contract)]

        # Validate legitimate inputs
        safe_path = validate_contract_path(temp_contract, allowed_base_dirs=allowed_dirs)
        safe_version = validate_solc_version("0.8.20")

        # Should work without errors
        assert Path(safe_path).exists()
        assert safe_version == "0.8.20"

        logger.info("Legitimate analysis proceeding")


class TestSecurityLayerInteraction:
    """Test interaction between security layers"""

    def test_logging_redacts_during_validation_errors(self):
        """Logs should redact secrets even in error messages"""
        logger = setup_secure_logging('error_test')

        try:
            # Attempt something that might leak secrets
            raise Exception("Failed with API key: sk-test123")
        except Exception as e:
            # Log the error
            import io
            stream = io.StringIO()
            logger.handlers[0].stream = stream

            logger.error(str(e))

            output = stream.getvalue()

            # Secret should be redacted even in error
            assert "sk-test123" not in output

    def test_rate_limiter_works_with_validated_inputs(self):
        """Rate limiter should work correctly after input validation"""

        limiter = RateLimiter(max_calls=5, period=1)

        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write("contract Test {}")
            temp_path = f.name

        try:
            # Validate input
            allowed_dirs = [os.path.dirname(temp_path)]
            safe_path = validate_contract_path(temp_path, allowed_base_dirs=allowed_dirs)

            # Use rate limiter
            @limiter
            def process_contract(path):
                return {"status": "success", "path": path}

            # Should work
            result = process_contract(safe_path)
            assert result['status'] == "success"

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class TestSecurityMetrics:
    """Test security monitoring and metrics"""

    def test_rate_limiter_metrics(self):
        """Should provide accurate metrics"""
        limiter = RateLimiter(max_calls=10, period=60)

        # Make some calls
        for i in range(5):
            limiter._check_rate_limit()

        stats = limiter.get_stats()

        assert stats['calls_used'] == 5
        assert stats['calls_remaining'] == 5
        assert stats['max_calls'] == 10

    def test_quota_manager_metrics(self):
        """Should track quota usage"""
        quota = APIQuotaManager(
            daily_limit=100,
            cost_per_call={'model-a': 0.01, 'model-b': 0.02}
        )

        # Record some usage
        quota.record_call('model-a', cost=0.01)
        quota.record_call('model-a', cost=0.01)
        quota.record_call('model-b', cost=0.02)

        stats = quota.get_usage_stats()

        assert stats['daily']['calls'] == 3
        assert stats['by_model']['model-a']['calls'] == 2
        assert stats['by_model']['model-b']['calls'] == 1


class TestSecurityBestPractices:
    """Test adherence to security best practices"""

    def test_principle_of_least_privilege(self, temp_file=None):
        """Should enforce principle of least privilege"""

        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write("contract Test {}")
            temp_path = f.name

        try:
            # Should only allow access to specific directories
            allowed_dirs = [os.path.dirname(temp_path)]

            # This should work
            safe_path = validate_contract_path(temp_path, allowed_base_dirs=allowed_dirs)

            # This should fail (different directory)
            with pytest.raises((SecurityError, FileNotFoundError)):
                validate_contract_path("/etc/passwd", allowed_base_dirs=allowed_dirs)

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_defense_in_depth(self):
        """Should implement defense in depth"""

        # Multiple layers of protection
        layers_tested = []

        # Layer 1: Input validation
        try:
            validate_solc_version("0.8.20; rm -rf /")
        except SecurityError:
            layers_tested.append('input_validation')

        # Layer 2: Rate limiting
        limiter = RateLimiter(max_calls=1, period=60)
        limiter._check_rate_limit()
        try:
            limiter._check_rate_limit()
        except RateLimitExceeded:
            layers_tested.append('rate_limiting')

        # Layer 3: Quota management
        quota = APIQuotaManager(daily_limit=1)
        quota.record_call('test')
        try:
            quota.check_quota()
        except RateLimitExceeded:
            layers_tested.append('quota_management')

        # All layers should have been tested
        assert 'input_validation' in layers_tested
        assert 'rate_limiting' in layers_tested
        assert 'quota_management' in layers_tested

    def test_fail_secure(self):
        """Should fail securely (deny by default)"""

        # If validation fails, should raise error (not allow)
        with pytest.raises((SecurityError, FileNotFoundError)):
            validate_contract_path("/nonexistent/file.sol")

        # If rate limit exceeded, should deny (not allow)
        limiter = RateLimiter(max_calls=1, period=60)
        limiter._check_rate_limit()

        with pytest.raises(RateLimitExceeded):
            limiter._check_rate_limit()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
