"""
API Rate Limiting Module

Provides rate limiting and quota management for external API calls (OpenAI, Anthropic, etc.)
to prevent:
- API quota exhaustion
- Economic DoS attacks
- Cost overruns
"""

import time
import threading
from functools import wraps
from typing import Callable, Dict, Optional
from collections import deque
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Raised when API rate limit is exceeded"""
    pass


class RateLimiter:
    """
    Thread-safe rate limiter using sliding window algorithm.

    Examples:
        >>> @RateLimiter(max_calls=60, period=60)
        ... def call_openai_api(prompt):
        ...     return openai.ChatCompletion.create(...)

        >>> # Allows 60 calls per 60 seconds
        >>> for i in range(100):
        ...     try:
        ...         call_openai_api("test")
        ...     except RateLimitExceeded as e:
        ...         print(f"Rate limited: {e}")
        ...         time.sleep(1)
    """

    def __init__(self, max_calls: int, period: int, burst_size: Optional[int] = None):
        """
        Initialize rate limiter.

        Args:
            max_calls: Maximum number of calls allowed
            period: Time period in seconds
            burst_size: Optional burst allowance (default: max_calls)
        """
        self.max_calls = max_calls
        self.period = period
        self.burst_size = burst_size or max_calls
        self.calls = deque(maxlen=max_calls * 2)  # Store call timestamps
        self.lock = threading.Lock()

        logger.info(
            f"RateLimiter initialized: {max_calls} calls per {period}s "
            f"(burst: {self.burst_size})"
        )

    def __call__(self, func: Callable) -> Callable:
        """
        Decorator to apply rate limiting to a function.

        Args:
            func: Function to rate limit

        Returns:
            Wrapped function with rate limiting
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            self._check_rate_limit()
            return func(*args, **kwargs)
        return wrapper

    def _check_rate_limit(self):
        """
        Check if rate limit allows another call.

        Raises:
            RateLimitExceeded: If rate limit exceeded
        """
        with self.lock:
            now = time.time()

            # Remove calls outside the time window
            while self.calls and self.calls[0] < now - self.period:
                self.calls.popleft()

            # Check if we can make another call
            if len(self.calls) >= self.max_calls:
                # Calculate when next call will be allowed
                oldest_call = self.calls[0]
                wait_time = self.period - (now - oldest_call)

                logger.warning(
                    f"Rate limit exceeded: {len(self.calls)}/{self.max_calls} calls. "
                    f"Retry in {wait_time:.1f}s"
                )

                raise RateLimitExceeded(
                    f"Rate limit exceeded. Maximum {self.max_calls} calls per {self.period}s. "
                    f"Retry after {wait_time:.1f} seconds."
                )

            # Record this call
            self.calls.append(now)
            logger.debug(
                f"Rate limit check passed: {len(self.calls)}/{self.max_calls} calls used"
            )

    def get_stats(self) -> Dict:
        """
        Get current rate limit statistics.

        Returns:
            dict: Statistics including calls_used, calls_remaining, reset_time
        """
        with self.lock:
            now = time.time()

            # Remove expired calls
            while self.calls and self.calls[0] < now - self.period:
                self.calls.popleft()

            calls_used = len(self.calls)
            calls_remaining = self.max_calls - calls_used

            # Calculate when limit resets (when oldest call expires)
            if self.calls:
                reset_time = self.calls[0] + self.period
                time_until_reset = reset_time - now
            else:
                time_until_reset = 0

            return {
                'calls_used': calls_used,
                'calls_remaining': calls_remaining,
                'max_calls': self.max_calls,
                'period': self.period,
                'time_until_reset': time_until_reset,
                'reset_at': datetime.fromtimestamp(now + time_until_reset).isoformat()
            }

    def reset(self):
        """Clear all rate limit history."""
        with self.lock:
            self.calls.clear()
            logger.info("Rate limiter reset")


class APIQuotaManager:
    """
    Manages API quotas and costs across multiple API providers.

    Tracks:
    - Daily/monthly API call limits
    - Estimated costs
    - Multi-provider quotas

    Examples:
        >>> quota = APIQuotaManager(
        ...     daily_limit=1000,
        ...     cost_per_call={'gpt-4': 0.03, 'gpt-3.5-turbo': 0.002}
        ... )
        >>> quota.check_quota('gpt-4')  # Raises if exceeded
        >>> quota.record_call('gpt-4', tokens=500)
    """

    def __init__(
        self,
        daily_limit: Optional[int] = None,
        monthly_limit: Optional[int] = None,
        cost_per_call: Optional[Dict[str, float]] = None,
        daily_cost_limit: Optional[float] = None
    ):
        """
        Initialize quota manager.

        Args:
            daily_limit: Maximum API calls per day (optional)
            monthly_limit: Maximum API calls per month (optional)
            cost_per_call: Cost per call for each model (optional)
            daily_cost_limit: Maximum cost per day in USD (optional)
        """
        self.daily_limit = daily_limit
        self.monthly_limit = monthly_limit
        self.cost_per_call = cost_per_call or {}
        self.daily_cost_limit = daily_cost_limit

        # Call tracking
        self.daily_calls = {}  # {date: count}
        self.monthly_calls = {}  # {month: count}
        self.daily_costs = {}  # {date: cost}

        # Model-specific tracking
        self.model_calls = {}  # {model: count}
        self.model_costs = {}  # {model: total_cost}

        self.lock = threading.Lock()

        logger.info(
            f"APIQuotaManager initialized - Daily limit: {daily_limit}, "
            f"Monthly limit: {monthly_limit}, Cost limit: ${daily_cost_limit}/day"
        )

    def check_quota(self, model: Optional[str] = None) -> bool:
        """
        Check if quota allows another API call.

        Args:
            model: Model name for cost calculation (optional)

        Returns:
            bool: True if quota available

        Raises:
            RateLimitExceeded: If quota exceeded
        """
        with self.lock:
            today = datetime.now().date()
            this_month = today.replace(day=1)

            # Check daily limit
            if self.daily_limit:
                daily_count = self.daily_calls.get(today, 0)
                if daily_count >= self.daily_limit:
                    raise RateLimitExceeded(
                        f"Daily API quota exceeded: {daily_count}/{self.daily_limit} calls. "
                        f"Quota resets at midnight."
                    )

            # Check monthly limit
            if self.monthly_limit:
                monthly_count = self.monthly_calls.get(this_month, 0)
                if monthly_count >= self.monthly_limit:
                    raise RateLimitExceeded(
                        f"Monthly API quota exceeded: {monthly_count}/{self.monthly_limit} calls. "
                        f"Quota resets on 1st of next month."
                    )

            # Check daily cost limit
            if self.daily_cost_limit and model:
                daily_cost = self.daily_costs.get(today, 0)
                call_cost = self.cost_per_call.get(model, 0)

                if daily_cost + call_cost > self.daily_cost_limit:
                    raise RateLimitExceeded(
                        f"Daily cost quota exceeded: ${daily_cost:.2f}/${self.daily_cost_limit:.2f}. "
                        f"This call would cost ${call_cost:.4f}."
                    )

            return True

    def record_call(self, model: str, tokens: Optional[int] = None, cost: Optional[float] = None):
        """
        Record an API call for quota tracking.

        Args:
            model: Model name
            tokens: Number of tokens used (optional)
            cost: Actual cost in USD (optional, will estimate if not provided)
        """
        with self.lock:
            today = datetime.now().date()
            this_month = today.replace(day=1)

            # Increment daily count
            self.daily_calls[today] = self.daily_calls.get(today, 0) + 1

            # Increment monthly count
            self.monthly_calls[this_month] = self.monthly_calls.get(this_month, 0) + 1

            # Track by model
            self.model_calls[model] = self.model_calls.get(model, 0) + 1

            # Track cost
            if cost is None:
                cost = self.cost_per_call.get(model, 0)

            if cost > 0:
                self.daily_costs[today] = self.daily_costs.get(today, 0) + cost
                self.model_costs[model] = self.model_costs.get(model, 0) + cost

            logger.debug(
                f"API call recorded - Model: {model}, Cost: ${cost:.4f}, "
                f"Daily: {self.daily_calls[today]}, Monthly: {self.monthly_calls[this_month]}"
            )

    def get_usage_stats(self) -> Dict:
        """
        Get comprehensive usage statistics.

        Returns:
            dict: Usage statistics including calls, costs, and limits
        """
        with self.lock:
            today = datetime.now().date()
            this_month = today.replace(day=1)

            daily_calls = self.daily_calls.get(today, 0)
            monthly_calls = self.monthly_calls.get(this_month, 0)
            daily_cost = self.daily_costs.get(today, 0)

            return {
                'daily': {
                    'calls': daily_calls,
                    'limit': self.daily_limit,
                    'remaining': self.daily_limit - daily_calls if self.daily_limit else None,
                    'cost': daily_cost,
                    'cost_limit': self.daily_cost_limit,
                    'cost_remaining': self.daily_cost_limit - daily_cost if self.daily_cost_limit else None
                },
                'monthly': {
                    'calls': monthly_calls,
                    'limit': self.monthly_limit,
                    'remaining': self.monthly_limit - monthly_calls if self.monthly_limit else None
                },
                'by_model': {
                    model: {
                        'calls': self.model_calls.get(model, 0),
                        'cost': self.model_costs.get(model, 0)
                    }
                    for model in set(list(self.model_calls.keys()) + list(self.model_costs.keys()))
                }
            }

    def reset_daily(self):
        """Clear daily quota counters (typically called at midnight)."""
        with self.lock:
            today = datetime.now().date()
            yesterday = today - timedelta(days=1)

            # Clean up old data (keep last 7 days)
            cutoff = today - timedelta(days=7)
            self.daily_calls = {k: v for k, v in self.daily_calls.items() if k >= cutoff}
            self.daily_costs = {k: v for k, v in self.daily_costs.items() if k >= cutoff}

            logger.info(f"Daily quota reset. Yesterday's usage: {self.daily_calls.get(yesterday, 0)} calls")


# Global instances for common use cases
# Users can override with custom limits

# OpenAI rate limits (as of 2024)
# GPT-4: 500 requests/min (Tier 1), 10,000/day
# GPT-3.5: 3,500 requests/min (Tier 1), 200,000/day
openai_limiter = RateLimiter(max_calls=60, period=60)  # Conservative: 60/min

# Cost tracking (OpenAI pricing as of 2024)
openai_quota = APIQuotaManager(
    daily_limit=1000,  # 1000 API calls per day
    monthly_limit=30000,  # 30k per month
    cost_per_call={
        'gpt-4': 0.03,  # Approximate per call
        'gpt-4-turbo': 0.01,
        'gpt-3.5-turbo': 0.002
    },
    daily_cost_limit=100.0  # $100 per day max
)


def rate_limited_openai_call(func: Callable) -> Callable:
    """
    Convenience decorator for OpenAI API calls with rate limiting and quota management.

    Examples:
        >>> @rate_limited_openai_call
        ... def analyze_with_gpt4(contract):
        ...     return openai.ChatCompletion.create(
        ...         model="gpt-4",
        ...         messages=[...]
        ...     )
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check quota before making call
        model = kwargs.get('model', 'gpt-4')
        openai_quota.check_quota(model)

        # Apply rate limiting
        openai_limiter._check_rate_limit()

        # Make the actual call
        result = func(*args, **kwargs)

        # Record the call for quota tracking
        openai_quota.record_call(model)

        return result

    return wrapper
