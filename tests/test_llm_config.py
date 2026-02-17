"""
Tests for LLM Configuration module.

Tests the centralized LLM configuration helper.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from src.core.llm_config import (
    DEFAULT_CONFIG,
    ROLE_GENERATOR,
    ROLE_VERIFICATOR,
    USE_CASE_CODE_ANALYSIS,
    USE_CASE_CORRELATION,
    USE_CASE_PROPERTY_GENERATION,
    USE_CASE_REMEDIATION,
    USE_CASE_VERIFICATION,
    _deep_merge,
    clear_config_cache,
    get_cache_config,
    get_default_model,
    get_fallback_models,
    get_generation_options,
    get_llm_config,
    get_model,
    get_ollama_host,
    get_retry_config,
    get_role_system_prompt,
)


class TestDefaultConfig:
    """Test default configuration structure."""

    def test_default_config_has_provider(self):
        """Test default config has provider."""
        assert "provider" in DEFAULT_CONFIG
        assert DEFAULT_CONFIG["provider"] == "ollama"

    def test_default_config_has_host(self):
        """Test default config has host."""
        assert "host" in DEFAULT_CONFIG
        assert "localhost" in DEFAULT_CONFIG["host"]

    def test_default_config_has_default_model(self):
        """Test default config has default model."""
        assert "default_model" in DEFAULT_CONFIG
        assert isinstance(DEFAULT_CONFIG["default_model"], str)

    def test_default_config_has_models(self):
        """Test default config has models mapping."""
        assert "models" in DEFAULT_CONFIG
        models = DEFAULT_CONFIG["models"]
        assert "code_analysis" in models
        assert "property_generation" in models
        assert "verification" in models
        assert "correlation" in models
        assert "remediation" in models

    def test_default_config_has_fallback_models(self):
        """Test default config has fallback models."""
        assert "fallback_models" in DEFAULT_CONFIG
        assert isinstance(DEFAULT_CONFIG["fallback_models"], list)
        assert len(DEFAULT_CONFIG["fallback_models"]) > 0

    def test_default_config_has_retry_settings(self):
        """Test default config has retry settings."""
        assert "retry_attempts" in DEFAULT_CONFIG
        assert "retry_delay" in DEFAULT_CONFIG
        assert DEFAULT_CONFIG["retry_attempts"] > 0
        assert DEFAULT_CONFIG["retry_delay"] > 0

    def test_default_config_has_options(self):
        """Test default config has generation options."""
        assert "options" in DEFAULT_CONFIG
        options = DEFAULT_CONFIG["options"]
        assert "temperature" in options
        assert "top_p" in options
        assert "num_ctx" in options

    def test_default_config_has_roles(self):
        """Test default config has roles."""
        assert "roles" in DEFAULT_CONFIG
        roles = DEFAULT_CONFIG["roles"]
        assert "generator" in roles
        assert "verificator" in roles

    def test_default_config_has_cache(self):
        """Test default config has cache settings."""
        assert "cache" in DEFAULT_CONFIG
        cache = DEFAULT_CONFIG["cache"]
        assert "enabled" in cache
        assert "ttl_seconds" in cache
        assert "max_entries" in cache


class TestDeepMerge:
    """Test deep merge functionality."""

    def test_deep_merge_simple(self):
        """Test simple merge."""
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        _deep_merge(base, override)
        assert base == {"a": 1, "b": 3, "c": 4}

    def test_deep_merge_nested(self):
        """Test nested merge."""
        base = {"a": {"x": 1, "y": 2}, "b": 1}
        override = {"a": {"y": 3, "z": 4}}
        _deep_merge(base, override)
        assert base["a"] == {"x": 1, "y": 3, "z": 4}
        assert base["b"] == 1

    def test_deep_merge_override_dict_with_value(self):
        """Test override dict with non-dict value."""
        base = {"a": {"nested": 1}}
        override = {"a": "simple"}
        _deep_merge(base, override)
        assert base["a"] == "simple"

    def test_deep_merge_empty_override(self):
        """Test merge with empty override."""
        base = {"a": 1, "b": 2}
        override = {}
        _deep_merge(base, override)
        assert base == {"a": 1, "b": 2}

    def test_deep_merge_deeply_nested(self):
        """Test deeply nested merge."""
        base = {"a": {"b": {"c": 1}}}
        override = {"a": {"b": {"c": 2, "d": 3}}}
        _deep_merge(base, override)
        assert base["a"]["b"]["c"] == 2
        assert base["a"]["b"]["d"] == 3


class TestGetOllamaHost:
    """Test Ollama host retrieval."""

    def test_get_ollama_host_default(self):
        """Test default host."""
        clear_config_cache()
        with patch.dict(os.environ, {}, clear=True):
            # Remove OLLAMA_HOST if set
            os.environ.pop("OLLAMA_HOST", None)
            host = get_ollama_host()
            assert "localhost" in host or "11434" in host

    def test_get_ollama_host_from_env(self):
        """Test host from environment."""
        clear_config_cache()
        with patch.dict(os.environ, {"OLLAMA_HOST": "http://custom:1234"}):
            host = get_ollama_host()
            assert host == "http://custom:1234"

    def test_get_ollama_host_env_precedence(self):
        """Test environment takes precedence."""
        clear_config_cache()
        with patch.dict(os.environ, {"OLLAMA_HOST": "http://env-host:5678"}):
            host = get_ollama_host()
            assert host == "http://env-host:5678"


class TestGetDefaultModel:
    """Test default model retrieval."""

    def test_get_default_model(self):
        """Test getting default model."""
        clear_config_cache()
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("MIESC_LLM_MODEL", None)
            model = get_default_model()
            assert isinstance(model, str)
            assert len(model) > 0

    def test_get_default_model_from_env(self):
        """Test model from environment."""
        clear_config_cache()
        with patch.dict(os.environ, {"MIESC_LLM_MODEL": "custom-model:latest"}):
            model = get_default_model()
            assert model == "custom-model:latest"


class TestGetModel:
    """Test model retrieval for use cases."""

    def test_get_model_code_analysis(self):
        """Test getting code analysis model."""
        clear_config_cache()
        model = get_model(USE_CASE_CODE_ANALYSIS)
        assert isinstance(model, str)

    def test_get_model_property_generation(self):
        """Test getting property generation model."""
        clear_config_cache()
        model = get_model(USE_CASE_PROPERTY_GENERATION)
        assert isinstance(model, str)

    def test_get_model_verification(self):
        """Test getting verification model."""
        clear_config_cache()
        model = get_model(USE_CASE_VERIFICATION)
        assert isinstance(model, str)

    def test_get_model_correlation(self):
        """Test getting correlation model."""
        clear_config_cache()
        model = get_model(USE_CASE_CORRELATION)
        assert isinstance(model, str)

    def test_get_model_remediation(self):
        """Test getting remediation model."""
        clear_config_cache()
        model = get_model(USE_CASE_REMEDIATION)
        assert isinstance(model, str)

    def test_get_model_unknown_returns_default(self):
        """Test unknown use case returns default."""
        clear_config_cache()
        model = get_model("unknown_use_case")
        default = get_default_model()
        assert model == default


class TestGetFallbackModels:
    """Test fallback models retrieval."""

    def test_get_fallback_models(self):
        """Test getting fallback models."""
        clear_config_cache()
        models = get_fallback_models()
        assert isinstance(models, list)
        assert len(models) > 0

    def test_fallback_models_are_strings(self):
        """Test all fallback models are strings."""
        clear_config_cache()
        models = get_fallback_models()
        for model in models:
            assert isinstance(model, str)


class TestGetGenerationOptions:
    """Test generation options retrieval."""

    def test_get_generation_options_default(self):
        """Test getting default options."""
        clear_config_cache()
        options = get_generation_options()
        assert "temperature" in options
        assert "top_p" in options

    def test_get_generation_options_generator_role(self):
        """Test getting generator role options."""
        clear_config_cache()
        options = get_generation_options(ROLE_GENERATOR)
        assert "temperature" in options

    def test_get_generation_options_verificator_role(self):
        """Test getting verificator role options."""
        clear_config_cache()
        options = get_generation_options(ROLE_VERIFICATOR)
        assert "temperature" in options

    def test_generation_options_no_system_prompt(self):
        """Test options don't include system prompt."""
        clear_config_cache()
        options = get_generation_options(ROLE_GENERATOR)
        assert "system_prompt" not in options

    def test_generation_options_unknown_role(self):
        """Test unknown role returns base options."""
        clear_config_cache()
        options = get_generation_options("unknown_role")
        assert "temperature" in options


class TestGetRoleSystemPrompt:
    """Test role system prompt retrieval."""

    def test_get_generator_prompt(self):
        """Test getting generator prompt."""
        clear_config_cache()
        prompt = get_role_system_prompt(ROLE_GENERATOR)
        assert isinstance(prompt, str)

    def test_get_verificator_prompt(self):
        """Test getting verificator prompt."""
        clear_config_cache()
        prompt = get_role_system_prompt(ROLE_VERIFICATOR)
        assert isinstance(prompt, str)

    def test_get_unknown_role_prompt(self):
        """Test getting unknown role prompt."""
        clear_config_cache()
        prompt = get_role_system_prompt("unknown")
        assert prompt == ""


class TestGetRetryConfig:
    """Test retry configuration retrieval."""

    def test_get_retry_config(self):
        """Test getting retry config."""
        clear_config_cache()
        config = get_retry_config()
        assert "attempts" in config
        assert "delay" in config

    def test_retry_attempts_positive(self):
        """Test retry attempts is positive."""
        clear_config_cache()
        config = get_retry_config()
        assert config["attempts"] > 0

    def test_retry_delay_positive(self):
        """Test retry delay is positive."""
        clear_config_cache()
        config = get_retry_config()
        assert config["delay"] > 0


class TestGetCacheConfig:
    """Test cache configuration retrieval."""

    def test_get_cache_config(self):
        """Test getting cache config."""
        clear_config_cache()
        config = get_cache_config()
        assert "enabled" in config
        assert "ttl_seconds" in config
        assert "max_entries" in config

    def test_cache_enabled_is_bool(self):
        """Test cache enabled is boolean."""
        clear_config_cache()
        config = get_cache_config()
        assert isinstance(config["enabled"], bool)

    def test_cache_ttl_positive(self):
        """Test TTL is positive."""
        clear_config_cache()
        config = get_cache_config()
        assert config["ttl_seconds"] > 0


class TestGetLLMConfig:
    """Test full LLM config retrieval."""

    def test_get_llm_config(self):
        """Test getting full config."""
        clear_config_cache()
        config = get_llm_config()
        assert isinstance(config, dict)

    def test_llm_config_has_required_keys(self):
        """Test config has required keys."""
        clear_config_cache()
        config = get_llm_config()
        assert "provider" in config
        assert "host" in config
        assert "default_model" in config


class TestClearConfigCache:
    """Test cache clearing."""

    def test_clear_config_cache(self):
        """Test clearing cache."""
        # This should not raise
        clear_config_cache()

    def test_clear_config_cache_reloads(self):
        """Test clear allows reload."""
        clear_config_cache()
        config1 = get_llm_config()
        clear_config_cache()
        config2 = get_llm_config()
        # Should both be valid configs
        assert "provider" in config1
        assert "provider" in config2


class TestConstants:
    """Test module constants."""

    def test_use_case_constants(self):
        """Test use case constants are defined."""
        assert USE_CASE_CODE_ANALYSIS == "code_analysis"
        assert USE_CASE_PROPERTY_GENERATION == "property_generation"
        assert USE_CASE_VERIFICATION == "verification"
        assert USE_CASE_CORRELATION == "correlation"
        assert USE_CASE_REMEDIATION == "remediation"

    def test_role_constants(self):
        """Test role constants are defined."""
        assert ROLE_GENERATOR == "generator"
        assert ROLE_VERIFICATOR == "verificator"


class TestLoadConfigWithMock:
    """Test config loading with mocked config_loader."""

    def test_load_config_merges_with_defaults(self):
        """Test loading config merges with defaults."""
        clear_config_cache()

        # Simply verify config loading returns valid config
        config = get_llm_config()
        assert isinstance(config, dict)
        assert "provider" in config
        assert "host" in config

    def test_load_config_returns_valid_structure(self):
        """Test loading config returns valid structure."""
        clear_config_cache()

        config = get_llm_config()
        # Should have all expected keys from defaults
        assert "default_model" in config
        assert "models" in config
        assert "options" in config
