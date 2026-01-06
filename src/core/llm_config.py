"""
MIESC LLM Configuration Helper
Provides centralized access to LLM configuration from miesc.yaml

Usage:
    from src.core.llm_config import get_model, get_ollama_host, get_generation_options

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

import os
from functools import lru_cache
from typing import Any, Dict, Optional

# Default configuration (used if YAML not available)
DEFAULT_CONFIG = {
    "provider": "ollama",
    "host": "http://localhost:11434",
    "default_model": "deepseek-coder:6.7b",
    "models": {
        "code_analysis": "deepseek-coder:6.7b",
        "property_generation": "deepseek-coder:6.7b",
        "verification": "deepseek-coder:6.7b",
        "correlation": "deepseek-coder:6.7b",
        "remediation": "deepseek-coder:6.7b",
    },
    "fallback_models": ["codellama:13b", "codellama:7b", "llama3:8b"],
    "retry_attempts": 3,
    "retry_delay": 5,
    "options": {
        "temperature": 0.1,
        "top_p": 0.95,
        "num_ctx": 8192,
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
        from src.core.config_loader import get_config

        config = get_config()
        llm_config = config.get_llm_config()
        if llm_config:
            # Merge with defaults to ensure all keys exist
            merged = DEFAULT_CONFIG.copy()
            _deep_merge(merged, llm_config)
            return merged
    except Exception:
        pass
    return DEFAULT_CONFIG


def _deep_merge(base: Dict, override: Dict) -> None:
    """Deep merge override into base dict."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def get_llm_config() -> Dict[str, Any]:
    """Get the complete LLM configuration."""
    return _load_config()


def get_ollama_host() -> str:
    """Get the Ollama API host URL.

    Returns:
        str: Ollama host URL (e.g., 'http://localhost:11434')
    """
    # Environment variable takes precedence
    env_host = os.environ.get("OLLAMA_HOST")
    if env_host:
        return env_host
    return _load_config().get("host", DEFAULT_CONFIG["host"])


def get_default_model() -> str:
    """Get the default model name.

    Returns:
        str: Default model name (e.g., 'deepseek-coder:6.7b')
    """
    # Environment variable takes precedence
    env_model = os.environ.get("MIESC_LLM_MODEL")
    if env_model:
        return env_model
    return _load_config().get("default_model", DEFAULT_CONFIG["default_model"])


def get_model(use_case: str) -> str:
    """Get the configured model for a specific use case.

    Args:
        use_case: One of 'code_analysis', 'property_generation', 'verification',
                  'correlation', 'remediation'

    Returns:
        str: Model name for the use case, or default if not configured
    """
    config = _load_config()
    models = config.get("models", {})
    return models.get(use_case, get_default_model())


def get_fallback_models() -> list:
    """Get the list of fallback models.

    Returns:
        list: List of fallback model names in order of preference
    """
    return _load_config().get("fallback_models", DEFAULT_CONFIG["fallback_models"])


def get_generation_options(role: Optional[str] = None) -> Dict[str, Any]:
    """Get generation options, optionally for a specific role.

    Args:
        role: Optional role name ('generator' or 'verificator')

    Returns:
        dict: Generation options (temperature, top_p, etc.)
    """
    config = _load_config()
    base_options = config.get("options", DEFAULT_CONFIG["options"]).copy()

    if role:
        roles = config.get("roles", {})
        role_config = roles.get(role, {})
        # Override base options with role-specific ones
        for key, value in role_config.items():
            if key != "system_prompt":
                base_options[key] = value

    return base_options


def get_role_system_prompt(role: str) -> str:
    """Get the system prompt for a specific role.

    Args:
        role: Role name ('generator' or 'verificator')

    Returns:
        str: System prompt for the role
    """
    config = _load_config()
    roles = config.get("roles", DEFAULT_CONFIG["roles"])
    role_config = roles.get(role, {})
    return role_config.get("system_prompt", "")


def get_retry_config() -> Dict[str, int]:
    """Get retry configuration.

    Returns:
        dict: {'attempts': int, 'delay': int}
    """
    config = _load_config()
    return {
        "attempts": config.get("retry_attempts", DEFAULT_CONFIG["retry_attempts"]),
        "delay": config.get("retry_delay", DEFAULT_CONFIG["retry_delay"]),
    }


def get_cache_config() -> Dict[str, Any]:
    """Get cache configuration.

    Returns:
        dict: {'enabled': bool, 'ttl_seconds': int, 'max_entries': int}
    """
    config = _load_config()
    return config.get("cache", DEFAULT_CONFIG["cache"])


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
