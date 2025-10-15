"""
Tests for Rate Limiting Module

Validates that rate limiting prevents:
- API quota exhaustion
- Economic DoS attacks
- Cost overruns
"""

import pytest
import time
from unittest.mock import Mock

from src.security.api_limiter import (
    RateLimiter,
    APIQuotaManager,
    RateLimitExceeded
)


class TestRateLimiter:
    """Tests for RateLimiter class"""

    def test_rate_limit_allows_within_limit(self):
        """Should allow calls within rate limit"""
        limiter = RateLimiter(max_calls=5, period=1)

        # Should allow 5 calls
        for i in range(5):
            limiter._check_rate_limit()  # Should not raise

    def test_rate_limit_blocks_exceeding_calls(self):
        """Should block calls exceeding rate limit"""
        limiter = RateLimiter(max_calls=3, period=1)

        # Allow 3 calls
        for i in range(3):
            limiter._check_rate_limit()

        # 4th call should be blocked
        with pytest.raises(RateLimitExceeded, match="Rate limit exceeded"):
            limiter._check_rate_limit()

    def test_rate_limit_resets_after_period(self):
        """Should reset after time period"""
        limiter = RateLimiter(max_calls=2, period=1)

        # Use up the limit
        limiter._check_rate_limit()
        limiter._check_rate_limit()

        # Should be blocked
        with pytest.raises(RateLimitExceeded):
            limiter._check_rate_limit()

        # Wait for period to expire
        time.sleep(1.1)

        # Should work again
        limiter._check_rate_limit()  # Should not raise

    def test_decorator_applies_rate_limit(self):
        """Decorator should apply rate limiting to function"""
        limiter = RateLimiter(max_calls=2, period=1)

        @limiter
        def test_function():
            return "success"

        # First 2 calls should work
        assert test_function() == "success"
        assert test_function() == "success"

        # 3rd call should be blocked
        with pytest.raises(RateLimitExceeded):
            test_function()

    def test_get_stats(self):
        """Should return accurate statistics"""
        limiter = RateLimiter(max_calls=5, period=60)

        # Make some calls
        for i in range(3):
            limiter._check_rate_limit()

        stats = limiter.get_stats()

        assert stats['calls_used'] == 3
        assert stats['calls_remaining'] == 2
        assert stats['max_calls'] == 5
        assert stats['period'] == 60

    def test_reset(self):
        """Should clear rate limit history"""
        limiter = RateLimiter(max_calls=2, period=60)

        # Use up limit
        limiter._check_rate_limit()
        limiter._check_rate_limit()

        # Reset
        limiter.reset()

        # Should work again without waiting
        limiter._check_rate_limit()  # Should not raise


class TestAPIQuotaManager:
    """Tests for APIQuotaManager class"""

    def test_check_quota_passes_within_limits(self):
        """Should pass when within quotas"""
        quota = APIQuotaManager(daily_limit=10, monthly_limit=100)

        # Should not raise
        assert quota.check_quota() == True

    def test_daily_limit_enforcement(self):
        """Should enforce daily limits"""
        quota = APIQuotaManager(daily_limit=3)

        # Use up daily limit
        for i in range(3):
            quota.record_call('test-model')

        # Next call should be blocked
        with pytest.raises(RateLimitExceeded, match="Daily API quota exceeded"):
            quota.check_quota()

    def test_monthly_limit_enforcement(self):
        """Should enforce monthly limits"""
        quota = APIQuotaManager(monthly_limit=5)

        # Use up monthly limit
        for i in range(5):
            quota.record_call('test-model')

        # Next call should be blocked
        with pytest.raises(RateLimitExceeded, match="Monthly API quota exceeded"):
            quota.check_quota()

    def test_cost_limit_enforcement(self):
        """Should enforce daily cost limits"""
        quota = APIQuotaManager(
            daily_cost_limit=1.0,
            cost_per_call={'expensive-model': 0.5}
        )

        # Make 2 expensive calls (0.5 each = 1.0 total)
        quota.record_call('expensive-model')
        quota.record_call('expensive-model')

        # 3rd call would exceed cost limit
        with pytest.raises(RateLimitExceeded, match="Daily cost quota exceeded"):
            quota.check_quota('expensive-model')

    def test_record_call_tracks_usage(self):
        """Should accurately track API usage"""
        quota = APIQuotaManager()

        quota.record_call('gpt-4', cost=0.03)
        quota.record_call('gpt-3.5-turbo', cost=0.002)

        stats = quota.get_usage_stats()

        assert stats['daily']['calls'] == 2
        assert stats['by_model']['gpt-4']['calls'] == 1
        assert stats['by_model']['gpt-3.5-turbo']['calls'] == 1

    def test_reset_daily(self):
        """Should reset daily counters"""
        quota = APIQuotaManager(daily_limit=5)

        # Use some quota
        for i in range(3):
            quota.record_call('test-model')

        # Reset
        quota.reset_daily()

        stats = quota.get_usage_stats()
        assert stats['daily']['calls'] == 0


class TestRateLimitedOpenAICall:
    """Tests for OpenAI-specific rate limiting"""

    def test_rate_limited_decorator(self):
        """Decorated function should be rate limited"""
        from src.security.api_limiter import rate_limited_openai_call, openai_limiter

        # Reset limiter
        openai_limiter.reset()

        @rate_limited_openai_call
        def mock_api_call(model='gpt-4'):
            return {"result": "success"}

        # Should work initially
        result = mock_api_call(model='gpt-4')
        assert result['result'] == "success"


class TestConcurrency:
    """Tests for thread safety"""

    def test_concurrent_rate_limit_checks(self):
        """Rate limiter should be thread-safe"""
        import threading

        limiter = RateLimiter(max_calls=50, period=1)
        success_count = [0]
        fail_count = [0]
        lock = threading.Lock()

        def make_call():
            try:
                limiter._check_rate_limit()
                with lock:
                    success_count[0] += 1
            except RateLimitExceeded:
                with lock:
                    fail_count[0] += 1

        # Create 100 threads trying to make calls
        threads = [threading.Thread(target=make_call) for _ in range(100)]

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join()

        # Should have allowed exactly 50 calls
        assert success_count[0] == 50
        assert fail_count[0] == 50


class TestPerformance:
    """Performance tests for rate limiting"""

    def test_rate_limit_check_performance(self):
        """Rate limit checks should be fast"""
        limiter = RateLimiter(max_calls=1000, period=60)

        start = time.time()

        # Make 1000 checks
        for i in range(1000):
            limiter._check_rate_limit()

        duration = time.time() - start

        # Should complete in less than 1 second
        assert duration < 1.0, f"Too slow: {duration}s for 1000 checks"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
