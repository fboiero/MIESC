"""
MIESC LLM Configuration Helper
Provides centralized access to LLM configuration from miesc.yaml

Usage:
    from miesc.core.llm_config import get_model, get_ollama_host, get_generation_options

    # Get model for specific use case
    model = get_model("code_analysis")  # Returns configured model or default

    # Get Ollama host
    host = get_ollama_host()

    # Get generation options for a role
    options = get_generation_options("verificator")

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
Version: 4.2.3
"""

import copy
import math
import os
from collections.abc import Mapping
from functools import lru_cache
from typing import Any, Dict, Iterable, Optional, cast

MAX_CONFIG_MERGE_DEPTH = 8
MAX_CONFIG_MERGE_ITEMS = 200
MAX_FALLBACK_MODELS = 20
MAX_TEXT_CHARS = 512
MAX_ROLE_OPTIONS = 50
MAX_RETRY_ATTEMPTS = 10
MAX_RETRY_DELAY_SECONDS = 300
MAX_CACHE_TTL_SECONDS = 86_400
MAX_CACHE_ENTRIES = 100_000
MIN_CONTEXT_TOKENS = 256
MAX_CONTEXT_TOKENS = 200_000
MIN_PREDICT_TOKENS = 1
MAX_PREDICT_TOKENS = 100_000

# Default configuration (used if YAML not available)
DEFAULT_CONFIG = {
    "provider": "ollama",
    "host": "http://localhost:11434",
    "default_model": "qwen2.5-coder:32b",
    "models": {
        "code_analysis": "qwen2.5-coder:32b",
        "property_generation": "qwen2.5-coder:14b",
        "verification": "qwen2.5-coder:32b",
        "correlation": "qwen2.5-coder:14b",
        "remediation": "qwen2.5-coder:14b",
    },
    "fallback_models": ["qwen2.5-coder:14b", "deepseek-coder:6.7b", "codellama:13b"],
    "retry_attempts": 3,
    "retry_delay": 5,
    "options": {
        "temperature": 0.1,
        "top_p": 0.95,
        "num_ctx": 16384,
        "num_predict": 4096,
    },
    "roles": {
        "generator": {
            "temperature": 0.2,
            "system_prompt": "You are an expert smart contract security auditor.",
        },
        "verificator": {
            "temperature": 0.1,
            "system_prompt": "You are a critical reviewer verifying security findings.",
        },
    },
    "cache": {
        "enabled": True,
        "ttl_seconds": 3600,
        "max_entries": 1000,
    },
}


@lru_cache(maxsize=1)
def _load_config() -> Dict[str, Any]:
    """Load LLM configuration from config_loader or use defaults."""
    try:
        from miesc.core.config_loader import get_config

        config = get_config()
        llm_config = config.get_llm_config()
        if isinstance(llm_config, Mapping) and llm_config:
            # Merge with defaults to ensure all keys exist
            merged = copy.deepcopy(DEFAULT_CONFIG)
            _deep_merge(merged, llm_config)
            return merged
    except Exception:
        pass
    return copy.deepcopy(DEFAULT_CONFIG)


def _mapping_items(value: Mapping[Any, Any]) -> Iterable[tuple[Any, Any]]:
    """Return bounded mapping items without trusting custom accessors."""
    try:
        return list(value.items())[:MAX_CONFIG_MERGE_ITEMS]
    except Exception:
        return []


def _has_unsafe_chars(text: str, *, multiline: bool = False) -> bool:
    if any(ch in {"\u2028", "\u2029"} for ch in text):
        return True
    allowed = {"\n", "\r", "\t"} if multiline else set()
    return any((ord(ch) < 32 and ch not in allowed) or ord(ch) == 127 for ch in text)


def _safe_text(
    value: Any, default: str = "", *, max_chars: int = MAX_TEXT_CHARS, multiline: bool = False
) -> str:
    if not isinstance(value, str):
        return default
    text = value.strip()
    if not text or len(text) > max_chars or _has_unsafe_chars(text, multiline=multiline):
        return default
    return text


def _bounded_int(value: Any, default: int, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(number):
        return default
    return max(minimum, min(maximum, int(number)))


def _bounded_float(value: Any, default: float, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(number):
        return default
    return max(minimum, min(maximum, number))


def _deep_merge(base: Dict, override: Mapping, *, _depth: int = 0) -> None:
    """Deep merge override into base dict."""
    if _depth >= MAX_CONFIG_MERGE_DEPTH:
        return
    if not isinstance(override, Mapping):
        return
    for key, value in _mapping_items(override):
        if key in base and isinstance(base[key], dict) and isinstance(value, Mapping):
            _deep_merge(base[key], value, _depth=_depth + 1)
        else:
            base[key] = value


def get_llm_config() -> Dict[str, Any]:
    """Get the complete LLM configuration."""
    return copy.deepcopy(_load_config())


def get_ollama_host() -> str:
    """Get the Ollama API host URL.

    Returns:
        str: Ollama host URL (e.g., 'http://localhost:11434')
    """
    # Environment variable takes precedence
    env_host = _safe_text(os.environ.get("OLLAMA_HOST"), max_chars=MAX_TEXT_CHARS)
    if env_host:
        return env_host
    return _safe_text(_load_config().get("host"), cast(str, DEFAULT_CONFIG["host"]))


def get_default_model() -> str:
    """Get the default model name.

    Returns:
        str: Default model name (e.g., 'deepseek-coder:6.7b')
    """
    # Environment variable takes precedence
    env_model = _safe_text(os.environ.get("MIESC_LLM_MODEL"), max_chars=MAX_TEXT_CHARS)
    if env_model:
        return env_model
    return _safe_text(
        _load_config().get("default_model"),
        cast(str, DEFAULT_CONFIG["default_model"]),
    )


def get_model(use_case: str) -> str:
    """Get the configured model for a specific use case.

    Args:
        use_case: One of 'code_analysis', 'property_generation', 'verification',
                  'correlation', 'remediation'

    Returns:
        str: Model name for the use case, or default if not configured
    """
    # A global env override takes precedence over per-use-case config, so a whole
    # run can be pinned to one model (e.g. a faster model for a benchmark sweep).
    env_model = os.environ.get("MIESC_LLM_MODEL")
    if env_model:
        return env_model
    config = _load_config()
    models = config.get("models", {})
    if not isinstance(models, Mapping):
        return get_default_model()
    safe_use_case = _safe_text(use_case)
    if not safe_use_case:
        return get_default_model()
    return _safe_text(models.get(safe_use_case), get_default_model())


def get_fallback_models() -> list:
    """Get the list of fallback models.

    Returns:
        list: List of fallback model names in order of preference
    """
    models = _load_config().get("fallback_models", DEFAULT_CONFIG["fallback_models"])
    if not isinstance(models, list):
        return list(DEFAULT_CONFIG["fallback_models"])
    safe_models = [
        safe_model
        for model in models[:MAX_FALLBACK_MODELS]
        if (safe_model := _safe_text(model, max_chars=MAX_TEXT_CHARS))
    ]
    return safe_models or list(DEFAULT_CONFIG["fallback_models"])


def _sanitize_generation_options(options: Any) -> Dict[str, Any]:
    defaults = cast(Dict[str, Any], DEFAULT_CONFIG["options"])
    if not isinstance(options, Mapping):
        options = defaults

    sanitized: Dict[str, Any] = {}
    for key, value in _mapping_items(options):
        safe_key = _safe_text(key)
        if not safe_key or len(sanitized) >= MAX_ROLE_OPTIONS:
            continue
        if safe_key in {"temperature", "top_p"}:
            sanitized[safe_key] = _bounded_float(
                value,
                float(defaults.get(safe_key, 0.1)),
                minimum=0.0,
                maximum=1.0,
            )
        elif safe_key == "num_ctx":
            sanitized[safe_key] = _bounded_int(
                value,
                int(defaults["num_ctx"]),
                minimum=MIN_CONTEXT_TOKENS,
                maximum=MAX_CONTEXT_TOKENS,
            )
        elif safe_key == "num_predict":
            sanitized[safe_key] = _bounded_int(
                value,
                int(defaults["num_predict"]),
                minimum=MIN_PREDICT_TOKENS,
                maximum=MAX_PREDICT_TOKENS,
            )
        elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
            sanitized[safe_key] = value
    return sanitized or copy.deepcopy(defaults)


def get_generation_options(role: Optional[str] = None) -> Dict[str, Any]:
    """Get generation options, optionally for a specific role.

    Args:
        role: Optional role name ('generator' or 'verificator')

    Returns:
        dict: Generation options (temperature, top_p, etc.)
    """
    config = _load_config()
    base_options = _sanitize_generation_options(config.get("options", DEFAULT_CONFIG["options"]))

    if role:
        roles = config.get("roles", {})
        safe_role = _safe_text(role)
        if isinstance(roles, Mapping) and safe_role:
            role_config = roles.get(safe_role, {})
            # Override base options with role-specific ones
            role_items = _mapping_items(role_config) if isinstance(role_config, Mapping) else []
            for key, value in role_items:
                if _safe_text(key) != "system_prompt":
                    base_options.update(_sanitize_generation_options({key: value}))

    return cast(Dict[str, Any], base_options)


def get_role_system_prompt(role: str) -> str:
    """Get the system prompt for a specific role.

    Args:
        role: Role name ('generator' or 'verificator')

    Returns:
        str: System prompt for the role
    """
    config = _load_config()
    roles = config.get("roles", DEFAULT_CONFIG["roles"])
    safe_role = _safe_text(role)
    if not isinstance(roles, Mapping) or not safe_role:
        return ""
    role_config = roles.get(safe_role, {})
    if not isinstance(role_config, Mapping):
        return ""
    return _safe_text(role_config.get("system_prompt"), multiline=True)


def get_retry_config() -> Dict[str, int]:
    """Get retry configuration.

    Returns:
        dict: {'attempts': int, 'delay': int}
    """
    config = _load_config()
    return {
        "attempts": _bounded_int(
            config.get("retry_attempts"),
            cast(int, DEFAULT_CONFIG["retry_attempts"]),
            minimum=1,
            maximum=MAX_RETRY_ATTEMPTS,
        ),
        "delay": _bounded_int(
            config.get("retry_delay"),
            cast(int, DEFAULT_CONFIG["retry_delay"]),
            minimum=0,
            maximum=MAX_RETRY_DELAY_SECONDS,
        ),
    }


def get_cache_config() -> Dict[str, Any]:
    """Get cache configuration.

    Returns:
        dict: {'enabled': bool, 'ttl_seconds': int, 'max_entries': int}
    """
    config = _load_config()
    cache = config.get("cache", DEFAULT_CONFIG["cache"])
    if not isinstance(cache, Mapping):
        cache = DEFAULT_CONFIG["cache"]
    default_cache = cast(Dict[str, Any], DEFAULT_CONFIG["cache"])
    return {
        "enabled": cache.get("enabled")
        if isinstance(cache.get("enabled"), bool)
        else default_cache["enabled"],
        "ttl_seconds": _bounded_int(
            cache.get("ttl_seconds"),
            int(default_cache["ttl_seconds"]),
            minimum=1,
            maximum=MAX_CACHE_TTL_SECONDS,
        ),
        "max_entries": _bounded_int(
            cache.get("max_entries"),
            int(default_cache["max_entries"]),
            minimum=1,
            maximum=MAX_CACHE_ENTRIES,
        ),
    }


def clear_config_cache() -> None:
    """Clear the configuration cache (useful for testing or config reload)."""
    _load_config.cache_clear()


# Convenience constants for use case names
USE_CASE_CODE_ANALYSIS = "code_analysis"
USE_CASE_PROPERTY_GENERATION = "property_generation"
USE_CASE_VERIFICATION = "verification"
USE_CASE_CORRELATION = "correlation"
USE_CASE_REMEDIATION = "remediation"

# Convenience constants for role names
ROLE_GENERATOR = "generator"
ROLE_VERIFICATOR = "verificator"
