"""
Tests for Config Loader module.

Tests the centralized configuration loading from YAML files.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from src.core.config_loader import (
    AdapterConfig,
    LayerConfig,
    MIESCConfig,
    get_config,
)


class TestAdapterConfig:
    """Test AdapterConfig dataclass."""

    def test_create_adapter_config(self):
        """Test creating adapter config."""
        config = AdapterConfig(
            name="slither",
            enabled=True,
            layer="static_analysis",
            timeout=120,
            options={"solc_version": "0.8.19"},
        )
        assert config.name == "slither"
        assert config.enabled is True
        assert config.layer == "static_analysis"
        assert config.timeout == 120
        assert config.options["solc_version"] == "0.8.19"

    def test_adapter_config_defaults(self):
        """Test adapter config defaults."""
        config = AdapterConfig(name="test")
        assert config.enabled is True
        assert config.layer == "static_analysis"
        assert config.timeout == 60
        assert config.options == {}


class TestLayerConfig:
    """Test LayerConfig dataclass."""

    def test_create_layer_config(self):
        """Test creating layer config."""
        config = LayerConfig(
            name="static_analysis",
            enabled=True,
            priority=1,
            tools=["slither", "aderyn"],
        )
        assert config.name == "static_analysis"
        assert config.enabled is True
        assert config.priority == 1
        assert len(config.tools) == 2

    def test_layer_config_defaults(self):
        """Test layer config defaults."""
        config = LayerConfig(name="test")
        assert config.enabled is True
        assert config.priority == 1
        assert config.tools == []


class TestMIESCConfig:
    """Test MIESCConfig class."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton between tests."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_singleton_pattern(self, reset_singleton):
        """Test singleton pattern."""
        config1 = MIESCConfig()
        config2 = MIESCConfig()
        assert config1 is config2

    def test_version_property(self, reset_singleton):
        """Test version property."""
        config = MIESCConfig()
        version = config.version
        assert isinstance(version, str)

    def test_global_config_property(self, reset_singleton):
        """Test global config property."""
        config = MIESCConfig()
        global_cfg = config.global_config
        assert isinstance(global_cfg, dict)

    def test_max_workers_property(self, reset_singleton):
        """Test max workers property."""
        config = MIESCConfig()
        workers = config.max_workers
        assert isinstance(workers, int)
        assert workers > 0

    def test_cache_enabled_property(self, reset_singleton):
        """Test cache enabled property."""
        config = MIESCConfig()
        enabled = config.cache_enabled
        assert isinstance(enabled, bool)

    def test_log_level_property(self, reset_singleton):
        """Test log level property."""
        config = MIESCConfig()
        level = config.log_level
        assert isinstance(level, str)


class TestMIESCConfigAdapters:
    """Test adapter configuration methods."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_get_adapter_config(self, reset_singleton):
        """Test getting adapter config."""
        config = MIESCConfig()
        adapter = config.get_adapter_config("slither")
        assert isinstance(adapter, AdapterConfig)
        assert adapter.name == "slither"

    def test_get_adapter_config_unknown(self, reset_singleton):
        """Test getting unknown adapter config."""
        config = MIESCConfig()
        adapter = config.get_adapter_config("unknown_adapter")
        assert adapter.name == "unknown_adapter"
        assert adapter.enabled is True  # Default

    def test_get_enabled_adapters(self, reset_singleton):
        """Test getting enabled adapters."""
        config = MIESCConfig()
        adapters = config.get_enabled_adapters()
        assert isinstance(adapters, list)

    def test_get_adapters_by_layer(self, reset_singleton):
        """Test getting adapters by layer."""
        config = MIESCConfig()
        adapters = config.get_adapters_by_layer("static_analysis")
        assert isinstance(adapters, list)


class TestMIESCConfigLayers:
    """Test layer configuration methods."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_get_layer_config(self, reset_singleton):
        """Test getting layer config."""
        config = MIESCConfig()
        layer = config.get_layer_config("static_analysis")
        assert isinstance(layer, LayerConfig)
        assert layer.name == "static_analysis"

    def test_get_layer_config_unknown(self, reset_singleton):
        """Test getting unknown layer config."""
        config = MIESCConfig()
        layer = config.get_layer_config("unknown_layer")
        assert layer.name == "unknown_layer"
        assert layer.enabled is True  # Default

    def test_get_all_layers(self, reset_singleton):
        """Test getting all layers."""
        config = MIESCConfig()
        layers = config.get_all_layers()
        assert isinstance(layers, list)


class TestMIESCConfigLLM:
    """Test LLM configuration methods."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_get_llm_config(self, reset_singleton):
        """Test getting LLM config."""
        config = MIESCConfig()
        llm = config.get_llm_config()
        assert isinstance(llm, dict)
        assert "provider" in llm

    def test_get_llm_config_has_host(self, reset_singleton):
        """Test LLM config has host."""
        config = MIESCConfig()
        llm = config.get_llm_config()
        assert "host" in llm


class TestMIESCConfigResults:
    """Test results configuration methods."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_get_results_config(self, reset_singleton):
        """Test getting results config."""
        config = MIESCConfig()
        results = config.get_results_config()
        assert isinstance(results, dict)
        assert "deduplication" in results
        assert "cross_validation" in results


class TestMIESCConfigCompliance:
    """Test compliance configuration methods."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_get_compliance_frameworks(self, reset_singleton):
        """Test getting compliance frameworks."""
        config = MIESCConfig()
        frameworks = config.get_compliance_frameworks()
        assert isinstance(frameworks, list)


class TestMIESCConfigChains:
    """Test chain configuration methods."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_get_chain_config(self, reset_singleton):
        """Test getting chain config."""
        config = MIESCConfig()
        chain = config.get_chain_config("ethereum")
        assert isinstance(chain, dict)

    def test_get_chain_config_default(self, reset_singleton):
        """Test getting default chain config."""
        config = MIESCConfig()
        chain = config.get_chain_config()
        assert isinstance(chain, dict)

    def test_get_enabled_chains(self, reset_singleton):
        """Test getting enabled chains."""
        config = MIESCConfig()
        chains = config.get_enabled_chains()
        assert isinstance(chains, list)


class TestMIESCConfigLicense:
    """Test license configuration methods."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_get_license_plan_config(self, reset_singleton):
        """Test getting license plan config."""
        config = MIESCConfig()
        plan = config.get_license_plan_config("PROFESSIONAL")
        assert isinstance(plan, dict)

    def test_get_license_plan_config_unknown(self, reset_singleton):
        """Test getting unknown license plan."""
        config = MIESCConfig()
        plan = config.get_license_plan_config("UNKNOWN")
        assert plan == {}


class TestMIESCConfigMethods:
    """Test misc methods."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_reload(self, reset_singleton):
        """Test reloading config."""
        config = MIESCConfig()
        # Should not raise
        config.reload()

    def test_to_dict(self, reset_singleton):
        """Test exporting to dict."""
        config = MIESCConfig()
        d = config.to_dict()
        assert isinstance(d, dict)


class TestGetConfig:
    """Test get_config function."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_get_config(self, reset_singleton):
        """Test getting config singleton."""
        config = get_config()
        assert isinstance(config, MIESCConfig)

    def test_get_config_singleton(self, reset_singleton):
        """Test get_config returns same instance."""
        config1 = get_config()
        config2 = get_config()
        assert config1 is config2


class TestMIESCConfigWithYAML:
    """Test config loading with actual YAML file."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    @pytest.fixture
    def config_file(self, tmp_path):
        """Create test config file."""
        config = {
            "version": "5.0.0",
            "global": {
                "log_level": "DEBUG",
                "max_workers": 8,
                "cache_enabled": False,
            },
            "adapters": {
                "slither": {
                    "enabled": True,
                    "layer": "static_analysis",
                    "timeout": 120,
                },
                "mythril": {
                    "enabled": False,
                    "layer": "symbolic_execution",
                    "timeout": 300,
                },
            },
            "layers": {
                "static_analysis": {
                    "enabled": True,
                    "priority": 1,
                    "tools": ["slither"],
                },
            },
            "llm": {
                "provider": "ollama",
                "host": "http://custom:9999",
                "default_model": "custom-model",
            },
            "chains": {
                "default": "ethereum",
                "ethereum": {"name": "Ethereum", "chain_id": 1, "enabled": True},
            },
        }
        config_path = tmp_path / "miesc.yaml"
        with open(config_path, "w") as f:
            yaml.dump(config, f)
        return config_path

    def test_load_from_env_path(self, reset_singleton, config_file):
        """Test loading config from env path."""
        with patch.dict(os.environ, {"MIESC_CONFIG": str(config_file)}):
            MIESCConfig._instance = None
            config = MIESCConfig()
            assert config.version == "5.0.0"
            assert config.log_level == "DEBUG"
            assert config.max_workers == 8

    def test_adapter_config_from_file(self, reset_singleton, config_file):
        """Test adapter config from file."""
        with patch.dict(os.environ, {"MIESC_CONFIG": str(config_file)}):
            MIESCConfig._instance = None
            config = MIESCConfig()
            slither = config.get_adapter_config("slither")
            assert slither.enabled is True
            assert slither.timeout == 120

            mythril = config.get_adapter_config("mythril")
            assert mythril.enabled is False

    def test_layer_config_from_file(self, reset_singleton, config_file):
        """Test layer config from file."""
        with patch.dict(os.environ, {"MIESC_CONFIG": str(config_file)}):
            MIESCConfig._instance = None
            config = MIESCConfig()
            layer = config.get_layer_config("static_analysis")
            assert layer.enabled is True
            assert layer.priority == 1
            assert "slither" in layer.tools


class TestMIESCConfigFindPath:
    """Test config file path finding."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_find_config_file_returns_path(self, reset_singleton):
        """Test finding config file returns a path."""
        config = MIESCConfig()
        path = config._find_config_file()
        assert isinstance(path, Path)

    def test_default_config_fallback(self, reset_singleton):
        """Test default config is used as fallback."""
        with patch.dict(os.environ, {"MIESC_CONFIG": "/nonexistent/path.yaml"}):
            MIESCConfig._instance = None
            config = MIESCConfig()
            default = config._get_default_config()
            assert "version" in default
            assert "global" in default


class TestMIESCConfigEdgeCases:
    """Test edge cases."""

    @pytest.fixture
    def reset_singleton(self):
        """Reset singleton."""
        MIESCConfig._instance = None
        yield
        MIESCConfig._instance = None

    def test_empty_config_file(self, reset_singleton, tmp_path):
        """Test handling empty config file."""
        empty_config = tmp_path / "empty.yaml"
        empty_config.write_text("")

        with patch.dict(os.environ, {"MIESC_CONFIG": str(empty_config)}):
            MIESCConfig._instance = None
            config = MIESCConfig()
            # Should fall back to defaults
            assert config.version is not None

    def test_invalid_yaml_fallback(self, reset_singleton, tmp_path):
        """Test handling invalid YAML."""
        invalid_config = tmp_path / "invalid.yaml"
        invalid_config.write_text("this: is: not: valid: yaml: [[[")

        with patch.dict(os.environ, {"MIESC_CONFIG": str(invalid_config)}):
            MIESCConfig._instance = None
            # Should handle gracefully (may use defaults or raise)
            try:
                config = MIESCConfig()
                # If it doesn't raise, should have some config
                assert config is not None
            except yaml.YAMLError:
                # This is acceptable behavior
                pass

    def test_get_adapters_by_layer_empty(self, reset_singleton):
        """Test getting adapters for nonexistent layer."""
        config = MIESCConfig()
        adapters = config.get_adapters_by_layer("nonexistent_layer")
        assert adapters == []

    def test_get_all_layers_sorted(self, reset_singleton, tmp_path):
        """Test layers are sorted by priority."""
        config_data = {
            "version": "5.0.0",
            "layers": {
                "layer_b": {"priority": 3},
                "layer_a": {"priority": 1},
                "layer_c": {"priority": 2},
            },
        }
        config_path = tmp_path / "sorted.yaml"
        with open(config_path, "w") as f:
            yaml.dump(config_data, f)

        with patch.dict(os.environ, {"MIESC_CONFIG": str(config_path)}):
            MIESCConfig._instance = None
            config = MIESCConfig()
            layers = config.get_all_layers()
            # Should be sorted by priority
            priorities = [l.priority for l in layers]
            assert priorities == sorted(priorities)
