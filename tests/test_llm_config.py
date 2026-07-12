"""
Tests for LLM Configuration module.

Tests the centralized LLM configuration helper.
"""

import os
from unittest.mock import patch

import miesc.core.llm_config as llm_config_module
from miesc.core.llm_config import (
    DEFAULT_CONFIG,
    MAX_CACHE_ENTRIES,
    MAX_CACHE_TTL_SECONDS,
    MAX_CONFIG_MERGE_DEPTH,
    MAX_CONFIG_MERGE_ITEMS,
    MAX_CONTEXT_TOKENS,
    MAX_FALLBACK_MODELS,
    MAX_RETRY_ATTEMPTS,
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

    def test_deep_merge_ignores_hostile_items_accessor(self):
        """Test hostile mappings are ignored instead of breaking load."""

        class HostileMapping(dict):
            def items(self):
                raise RuntimeError("no items")

        base = {"a": 1}
        _deep_merge(base, HostileMapping({"a": 2}))
        assert base == {"a": 1}

    def test_deep_merge_caps_item_count(self):
        """Test deep merge ignores excessive mapping items."""
        base = {}
        override = {f"k{i}": i for i in range(MAX_CONFIG_MERGE_ITEMS + 25)}
        _deep_merge(base, override)
        assert len(base) == MAX_CONFIG_MERGE_ITEMS

    def test_deep_merge_caps_nested_depth(self):
        """Test deeply nested overrides stop at the configured depth."""
        base = current_base = {}
        override = current_override = {}
        for index in range(MAX_CONFIG_MERGE_DEPTH + 3):
            current_base["child"] = {}
            current_override["child"] = {"value": index}
            current_base = current_base["child"]
            current_override = current_override["child"]

        _deep_merge(base, override)

        node = base
        for _ in range(MAX_CONFIG_MERGE_DEPTH):
            assert "child" in node
            node = node["child"]
        assert "value" not in node


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

    def test_get_ollama_host_rejects_control_chars_and_oversize_env(self):
        """Test malformed env hosts fall back to config."""
        clear_config_cache()
        with patch.dict(os.environ, {"OLLAMA_HOST": "http://bad\u2028host"}):
            assert get_ollama_host() == DEFAULT_CONFIG["host"]

        clear_config_cache()
        with patch.dict(os.environ, {"OLLAMA_HOST": "x" * 600}):
            assert get_ollama_host() == DEFAULT_CONFIG["host"]


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

    def test_get_default_model_rejects_control_chars_and_oversize_env(self):
        """Test malformed env model falls back to config."""
        clear_config_cache()
        with patch.dict(os.environ, {"MIESC_LLM_MODEL": "bad\nmodel"}):
            assert get_default_model() == DEFAULT_CONFIG["default_model"]

        clear_config_cache()
        with patch.dict(os.environ, {"MIESC_LLM_MODEL": "x" * 600}):
            assert get_default_model() == DEFAULT_CONFIG["default_model"]


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

    def test_get_model_falls_back_for_malformed_models_mapping(self, monkeypatch):
        """Test malformed model maps use the default model."""
        monkeypatch.setattr(
            llm_config_module,
            "_load_config",
            lambda: {**DEFAULT_CONFIG, "models": ["bad"]},
        )
        with patch.dict(os.environ, {}, clear=True):
            assert get_model(USE_CASE_CODE_ANALYSIS) == DEFAULT_CONFIG["default_model"]

    def test_get_model_falls_back_for_bad_use_case_or_value(self, monkeypatch):
        """Test malformed use cases and model values use defaults."""
        monkeypatch.setattr(
            llm_config_module,
            "_load_config",
            lambda: {
                **DEFAULT_CONFIG,
                "models": {USE_CASE_CODE_ANALYSIS: 123, "bad\ncase": "unsafe"},
            },
        )
        with patch.dict(os.environ, {}, clear=True):
            assert get_model(USE_CASE_CODE_ANALYSIS) == DEFAULT_CONFIG["default_model"]
            assert get_model("bad\ncase") == DEFAULT_CONFIG["default_model"]


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

    def test_fallback_models_are_sanitized_capped_and_defensive_copy(self, monkeypatch):
        """Test fallback models are filtered, capped, and copied."""
        raw_models = ["safe-model"] + [f"m{i}" for i in range(MAX_FALLBACK_MODELS + 5)]
        raw_models.extend([123, "bad\u2028model"])
        config = {**DEFAULT_CONFIG, "fallback_models": raw_models}
        monkeypatch.setattr(llm_config_module, "_load_config", lambda: config)

        first = get_fallback_models()
        first.append("mutated")
        second = get_fallback_models()

        assert len(second) == MAX_FALLBACK_MODELS
        assert "safe-model" in second
        assert "mutated" not in second
        assert all(isinstance(model, str) for model in second)


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

    def test_generation_options_fall_back_for_malformed_options_roles(self, monkeypatch):
        """Test malformed options and roles do not break option loading."""
        monkeypatch.setattr(
            llm_config_module,
            "_load_config",
            lambda: {**DEFAULT_CONFIG, "options": ["bad"], "roles": ["bad"]},
        )
        options = get_generation_options(ROLE_GENERATOR)
        assert options["temperature"] == DEFAULT_CONFIG["options"]["temperature"]

    def test_generation_options_handles_hostile_role_items(self, monkeypatch):
        """Test hostile role mappings are ignored safely."""

        class HostileRole(dict):
            def items(self):
                raise RuntimeError("no items")

        monkeypatch.setattr(
            llm_config_module,
            "_load_config",
            lambda: {
                **DEFAULT_CONFIG,
                "roles": {ROLE_GENERATOR: HostileRole({"temperature": 0.9})},
            },
        )
        options = get_generation_options(ROLE_GENERATOR)
        assert options["temperature"] == DEFAULT_CONFIG["options"]["temperature"]

    def test_generation_options_clamp_numeric_bounds(self, monkeypatch):
        """Test known generation options are bounded."""
        monkeypatch.setattr(
            llm_config_module,
            "_load_config",
            lambda: {
                **DEFAULT_CONFIG,
                "options": {
                    "temperature": 3,
                    "top_p": -1,
                    "num_ctx": 999_999_999,
                    "num_predict": -5,
                },
                "roles": {ROLE_GENERATOR: {"temperature": float("nan")}},
            },
        )
        options = get_generation_options(ROLE_GENERATOR)
        assert options["temperature"] == DEFAULT_CONFIG["options"]["temperature"]
        assert options["top_p"] == 0.0
        assert options["num_ctx"] == MAX_CONTEXT_TOKENS
        assert options["num_predict"] == 1


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

    def test_role_prompt_handles_malformed_roles_and_sanitizes_prompt(self, monkeypatch):
        """Test malformed prompt config returns an empty prompt."""
        monkeypatch.setattr(
            llm_config_module, "_load_config", lambda: {**DEFAULT_CONFIG, "roles": ["bad"]}
        )
        assert get_role_system_prompt(ROLE_GENERATOR) == ""

        monkeypatch.setattr(
            llm_config_module,
            "_load_config",
            lambda: {
                **DEFAULT_CONFIG,
                "roles": {ROLE_GENERATOR: {"system_prompt": "bad\u2028prompt"}},
            },
        )
        assert get_role_system_prompt(ROLE_GENERATOR) == ""


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

    def test_retry_config_bounds_malformed_values(self, monkeypatch):
        """Test retry numbers are bounded and non-numeric values fall back."""
        monkeypatch.setattr(
            llm_config_module,
            "_load_config",
            lambda: {**DEFAULT_CONFIG, "retry_attempts": 999, "retry_delay": float("inf")},
        )
        config = get_retry_config()
        assert config["attempts"] == MAX_RETRY_ATTEMPTS
        assert config["delay"] == DEFAULT_CONFIG["retry_delay"]

        monkeypatch.setattr(
            llm_config_module,
            "_load_config",
            lambda: {**DEFAULT_CONFIG, "retry_attempts": 0, "retry_delay": -5},
        )
        config = get_retry_config()
        assert config["attempts"] == 1
        assert config["delay"] == 0


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

    def test_cache_config_handles_malformed_mapping_and_bounds_values(self, monkeypatch):
        """Test malformed cache config falls back and numeric values are bounded."""
        monkeypatch.setattr(
            llm_config_module, "_load_config", lambda: {**DEFAULT_CONFIG, "cache": ["bad"]}
        )
        assert get_cache_config() == DEFAULT_CONFIG["cache"]

        monkeypatch.setattr(
            llm_config_module,
            "_load_config",
            lambda: {
                **DEFAULT_CONFIG,
                "cache": {"enabled": "yes", "ttl_seconds": 999_999_999, "max_entries": 999_999_999},
            },
        )
        config = get_cache_config()
        assert config["enabled"] is DEFAULT_CONFIG["cache"]["enabled"]
        assert config["ttl_seconds"] == MAX_CACHE_TTL_SECONDS
        assert config["max_entries"] == MAX_CACHE_ENTRIES


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

    def test_get_llm_config_returns_defensive_copy(self):
        """Test callers cannot mutate cached config state."""
        clear_config_cache()
        config = get_llm_config()
        original_model = config["models"]["code_analysis"]
        config["models"]["code_analysis"] = "mutated"
        assert get_llm_config()["models"]["code_analysis"] == original_model


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

    def test_load_config_does_not_mutate_default_config_nested_models(self, monkeypatch):
        """Test config merges use deep copies of default config."""

        class FakeConfig:
            def get_llm_config(self):
                return {"models": {"code_analysis": "custom-model"}}

        import miesc.core.config_loader as config_loader_module

        clear_config_cache()
        monkeypatch.setattr(config_loader_module, "get_config", lambda: FakeConfig())
        config = llm_config_module._load_config()

        assert config["models"]["code_analysis"] == "custom-model"
        assert DEFAULT_CONFIG["models"]["code_analysis"] != "custom-model"

    def test_load_config_falls_back_for_non_mapping_and_exceptions(self, monkeypatch):
        """Test invalid config_loader outputs fall back to defaults."""

        class NonMappingConfig:
            def get_llm_config(self):
                return ["bad"]

        class RaisingConfig:
            def get_llm_config(self):
                raise RuntimeError("boom")

        import miesc.core.config_loader as config_loader_module

        clear_config_cache()
        monkeypatch.setattr(config_loader_module, "get_config", lambda: NonMappingConfig())
        assert llm_config_module._load_config()["provider"] == DEFAULT_CONFIG["provider"]

        clear_config_cache()
        monkeypatch.setattr(config_loader_module, "get_config", lambda: RaisingConfig())
        assert llm_config_module._load_config()["provider"] == DEFAULT_CONFIG["provider"]
