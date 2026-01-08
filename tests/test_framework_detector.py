"""
Tests for MIESC Framework Detector

Tests the automatic detection of Solidity development frameworks.

Author: Fernando Boiero
License: AGPL-3.0
"""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from src.core.framework_detector import (
    Framework,
    FrameworkConfig,
    FrameworkDetector,
    detect_framework,
    get_framework_name,
    is_foundry_project,
    is_hardhat_project,
)


class TestFrameworkEnum:
    """Tests for Framework enum."""

    def test_framework_values(self):
        """Test Framework enum values."""
        assert Framework.FOUNDRY.value == "foundry"
        assert Framework.HARDHAT.value == "hardhat"
        assert Framework.TRUFFLE.value == "truffle"
        assert Framework.BROWNIE.value == "brownie"
        assert Framework.UNKNOWN.value == "unknown"


class TestFrameworkConfig:
    """Tests for FrameworkConfig dataclass."""

    def test_config_creation(self):
        """Test creating FrameworkConfig."""
        config = FrameworkConfig(
            framework=Framework.FOUNDRY,
            root_path=Path("/test"),
            solc_version="0.8.20",
            optimizer_enabled=True,
            optimizer_runs=200,
        )

        assert config.framework == Framework.FOUNDRY
        assert config.root_path == Path("/test")
        assert config.solc_version == "0.8.20"
        assert config.optimizer_enabled is True
        assert config.optimizer_runs == 200

    def test_config_defaults(self):
        """Test FrameworkConfig default values."""
        config = FrameworkConfig(
            framework=Framework.UNKNOWN,
            root_path=Path("/test"),
        )

        assert config.config_file is None
        assert config.solc_version is None
        assert config.evm_version is None
        assert config.optimizer_enabled is False
        assert config.optimizer_runs == 200
        assert config.remappings == []
        assert config.lib_paths == []

    def test_config_to_dict(self):
        """Test FrameworkConfig serialization."""
        config = FrameworkConfig(
            framework=Framework.FOUNDRY,
            root_path=Path("/test/project"),
            config_file=Path("/test/project/foundry.toml"),
            solc_version="0.8.20",
            remappings=["@openzeppelin/=lib/openzeppelin/"],
            lib_paths=[Path("/test/project/lib")],
        )

        data = config.to_dict()

        assert data["framework"] == "foundry"
        assert data["root_path"] == "/test/project"
        assert data["config_file"] == "/test/project/foundry.toml"
        assert data["solc_version"] == "0.8.20"
        assert "@openzeppelin/=lib/openzeppelin/" in data["remappings"]


class TestFrameworkDetector:
    """Tests for FrameworkDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a fresh detector instance."""
        return FrameworkDetector()

    def test_detector_initialization(self, detector):
        """Test FrameworkDetector initialization."""
        assert detector._cache == {}

    def test_detect_unknown_framework(self, detector):
        """Test detection returns UNKNOWN for empty directory."""
        with TemporaryDirectory() as tmpdir:
            config = detector.detect(tmpdir)

            assert config.framework == Framework.UNKNOWN
            # Use resolve() to handle macOS /var -> /private/var symlink
            assert config.root_path.resolve() == Path(tmpdir).resolve()

    def test_detect_foundry_project(self, detector):
        """Test detecting Foundry project."""
        with TemporaryDirectory() as tmpdir:
            # Create foundry.toml
            foundry_toml = Path(tmpdir) / "foundry.toml"
            foundry_toml.write_text(
                """
[profile.default]
src = 'src'
out = 'out'
libs = ['lib']
solc = '0.8.20'
optimizer = true
optimizer_runs = 200
"""
            )

            config = detector.detect(tmpdir)

            assert config.framework == Framework.FOUNDRY
            # Use resolve() to handle macOS symlinks
            assert config.config_file.resolve() == foundry_toml.resolve()

    def test_detect_hardhat_project(self, detector):
        """Test detecting Hardhat project."""
        with TemporaryDirectory() as tmpdir:
            # Create hardhat.config.js
            hardhat_config = Path(tmpdir) / "hardhat.config.js"
            hardhat_config.write_text("module.exports = { solidity: '0.8.20' };")

            config = detector.detect(tmpdir)

            assert config.framework == Framework.HARDHAT
            assert config.config_file.resolve() == hardhat_config.resolve()

    def test_detect_truffle_project(self, detector):
        """Test detecting Truffle project."""
        with TemporaryDirectory() as tmpdir:
            # Create truffle-config.js
            truffle_config = Path(tmpdir) / "truffle-config.js"
            truffle_config.write_text("module.exports = {};")

            config = detector.detect(tmpdir)

            assert config.framework == Framework.TRUFFLE
            assert config.config_file.resolve() == truffle_config.resolve()

    def test_detect_brownie_project(self, detector):
        """Test detecting Brownie project."""
        with TemporaryDirectory() as tmpdir:
            # Create brownie-config.yaml
            brownie_config = Path(tmpdir) / "brownie-config.yaml"
            brownie_config.write_text("compiler:\n  solc:\n    version: '0.8.20'")

            config = detector.detect(tmpdir)

            assert config.framework == Framework.BROWNIE
            assert config.config_file.resolve() == brownie_config.resolve()

    def test_detect_from_file_path(self, detector):
        """Test detection from file path uses parent directory."""
        with TemporaryDirectory() as tmpdir:
            # Create foundry.toml
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")

            # Create a source file
            src_dir = Path(tmpdir) / "src"
            src_dir.mkdir()
            contract_file = src_dir / "Token.sol"
            contract_file.write_text("// SPDX-License-Identifier: MIT")

            config = detector.detect(str(contract_file))

            assert config.framework == Framework.FOUNDRY

    def test_detect_searches_parent_directories(self, detector):
        """Test that detection searches parent directories."""
        with TemporaryDirectory() as tmpdir:
            # Create foundry.toml at root
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")

            # Create nested directory
            nested = Path(tmpdir) / "src" / "contracts" / "nested"
            nested.mkdir(parents=True)

            config = detector.detect(str(nested))

            assert config.framework == Framework.FOUNDRY

    def test_cache_results(self, detector):
        """Test that results are cached."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")

            config1 = detector.detect(tmpdir, use_cache=True)
            config2 = detector.detect(tmpdir, use_cache=True)

            assert config1 is config2

    def test_bypass_cache(self, detector):
        """Test bypassing cache."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")

            config1 = detector.detect(tmpdir, use_cache=True)
            config2 = detector.detect(tmpdir, use_cache=False)

            # New instance when cache bypassed
            assert config1 is not config2

    def test_clear_cache(self, detector):
        """Test clearing the cache."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")

            detector.detect(tmpdir)
            assert len(detector._cache) == 1

            detector.clear_cache()
            assert len(detector._cache) == 0

    def test_parse_foundry_config(self, detector):
        """Test parsing Foundry configuration."""
        with TemporaryDirectory() as tmpdir:
            foundry_toml = Path(tmpdir) / "foundry.toml"
            foundry_toml.write_text(
                """
[profile.default]
src = 'src'
out = 'out'
libs = ['lib', 'node_modules']
solc = '0.8.20'
evm_version = 'paris'
optimizer = true
optimizer_runs = 500
via_ir = true
ffi = false
remappings = ['@openzeppelin/=lib/openzeppelin-contracts/']

[profile.default.fuzz]
runs = 1000

[profile.default.invariant]
runs = 512
"""
            )

            config = detector.detect(tmpdir)

            assert config.solc_version == "0.8.20"
            assert config.evm_version == "paris"
            assert config.optimizer_enabled is True
            assert config.optimizer_runs == 500
            assert "@openzeppelin/=lib/openzeppelin-contracts/" in config.remappings
            assert config.extra_config.get("via_ir") is True
            assert config.extra_config.get("fuzz_runs") == 1000

    def test_parse_foundry_reads_remappings_file(self, detector):
        """Test that Foundry parser reads remappings.txt."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")
            Path(tmpdir, "remappings.txt").write_text(
                """
forge-std/=lib/forge-std/src/
@openzeppelin/=lib/openzeppelin-contracts/
# This is a comment
"""
            )

            config = detector.detect(tmpdir)

            # Should include remappings from file
            assert any("forge-std" in r for r in config.remappings)

    def test_hardhat_default_paths(self, detector):
        """Test Hardhat default paths."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "hardhat.config.js").write_text("module.exports = {};")

            config = detector.detect(tmpdir)

            # Use resolve() to handle macOS symlinks
            assert config.src_path.resolve() == (Path(tmpdir) / "contracts").resolve()
            assert config.test_path.resolve() == (Path(tmpdir) / "test").resolve()
            assert config.out_path.resolve() == (Path(tmpdir) / "artifacts").resolve()

    def test_truffle_default_paths(self, detector):
        """Test Truffle default paths."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "truffle-config.js").write_text("module.exports = {};")

            config = detector.detect(tmpdir)

            # Use resolve() to handle macOS symlinks
            assert config.src_path.resolve() == (Path(tmpdir) / "contracts").resolve()
            assert config.test_path.resolve() == (Path(tmpdir) / "test").resolve()
            assert config.out_path.resolve() == (Path(tmpdir) / "build" / "contracts").resolve()

    def test_get_solc_args(self, detector):
        """Test generating solc arguments."""
        config = FrameworkConfig(
            framework=Framework.FOUNDRY,
            root_path=Path("/test"),
            evm_version="paris",
            optimizer_enabled=True,
            optimizer_runs=200,
            remappings=["@oz/=lib/oz/"],
        )

        args = detector.get_solc_args(config)

        assert "--evm-version" in args
        assert "paris" in args
        assert "--optimize" in args
        assert "--optimize-runs" in args
        assert "200" in args
        assert "@oz/=lib/oz/" in args

    def test_get_slither_args_foundry(self, detector):
        """Test generating Slither arguments for Foundry."""
        with TemporaryDirectory() as tmpdir:
            config = FrameworkConfig(
                framework=Framework.FOUNDRY,
                root_path=Path(tmpdir),
                out_path=Path(tmpdir) / "out",
                solc_version="0.8.20",
                remappings=["@oz/=lib/oz/"],
            )

            args = detector.get_slither_args(config)

            assert "--solc-solcs-select" in args
            assert "0.8.20" in args
            assert "--foundry-out-directory" in args

    def test_get_slither_args_hardhat(self, detector):
        """Test generating Slither arguments for Hardhat."""
        with TemporaryDirectory() as tmpdir:
            config = FrameworkConfig(
                framework=Framework.HARDHAT,
                root_path=Path(tmpdir),
                out_path=Path(tmpdir) / "artifacts",
                solc_version="0.8.20",
            )

            args = detector.get_slither_args(config)

            assert "--hardhat-artifacts-directory" in args


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def setup_method(self):
        """Reset module-level detector."""
        import src.core.framework_detector as fd

        fd._detector = None

    def test_detect_framework(self):
        """Test detect_framework convenience function."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")

            config = detect_framework(tmpdir)

            assert config.framework == Framework.FOUNDRY

    def test_get_framework_name(self):
        """Test get_framework_name convenience function."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "hardhat.config.js").write_text("module.exports = {};")

            name = get_framework_name(tmpdir)

            assert name == "hardhat"

    def test_is_foundry_project(self):
        """Test is_foundry_project convenience function."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")

            assert is_foundry_project(tmpdir) is True

    def test_is_hardhat_project(self):
        """Test is_hardhat_project convenience function."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "hardhat.config.ts").write_text("export default {};")

            assert is_hardhat_project(tmpdir) is True


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.fixture
    def detector(self):
        return FrameworkDetector()

    def test_invalid_toml_fallback(self, detector):
        """Test fallback when TOML parsing fails."""
        with TemporaryDirectory() as tmpdir:
            # Create invalid TOML
            Path(tmpdir, "foundry.toml").write_text("invalid [ toml content")

            config = detector.detect(tmpdir)

            # Should still detect as Foundry with defaults
            assert config.framework == Framework.FOUNDRY
            # Use resolve() to handle macOS symlinks
            assert config.src_path.resolve() == (Path(tmpdir) / "src").resolve()

    def test_foundry_precedence_over_hardhat(self, detector):
        """Test that Foundry takes precedence when both configs exist."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")
            Path(tmpdir, "hardhat.config.js").write_text("module.exports = {};")

            config = detector.detect(tmpdir)

            # Foundry should be detected first
            assert config.framework == Framework.FOUNDRY

    def test_empty_remappings_file(self, detector):
        """Test handling empty remappings.txt."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")
            Path(tmpdir, "remappings.txt").write_text("")

            config = detector.detect(tmpdir)

            assert config.framework == Framework.FOUNDRY

    @patch("subprocess.run")
    def test_forge_remappings_timeout(self, mock_run, detector):
        """Test handling forge remappings timeout."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("forge", 10)

        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")

            config = detector.detect(tmpdir)

            # Should still work without forge remappings
            assert config.framework == Framework.FOUNDRY

    @patch("subprocess.run")
    def test_forge_not_found(self, mock_run, detector):
        """Test handling forge command not found."""
        mock_run.side_effect = FileNotFoundError()

        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")

            config = detector.detect(tmpdir)

            assert config.framework == Framework.FOUNDRY

    @patch("subprocess.run")
    def test_forge_generic_exception(self, mock_run, detector):
        """Test handling generic exception from forge command."""
        mock_run.side_effect = OSError("Unexpected error")

        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")

            config = detector.detect(tmpdir)

            # Should still work despite forge error
            assert config.framework == Framework.FOUNDRY

    def test_remappings_file_read_error(self, detector):
        """Test handling error reading remappings file."""
        with TemporaryDirectory() as tmpdir:
            Path(tmpdir, "foundry.toml").write_text("[profile.default]")
            # Create remappings.txt with invalid UTF-8
            remappings = Path(tmpdir, "remappings.txt")
            remappings.write_bytes(b"\x80\x81\x82")

            config = detector.detect(tmpdir)

            # Should still work despite read error
            assert config.framework == Framework.FOUNDRY

    def test_no_tomllib_fallback(self, detector):
        """Test fallback when tomllib module is not available."""
        with TemporaryDirectory() as tmpdir:
            foundry_toml = Path(tmpdir, "foundry.toml")
            foundry_toml.write_text("[profile.default]")

            # Patch tomllib to None to simulate unavailability
            with patch("src.core.framework_detector.tomllib", None):
                config = detector.detect(tmpdir)

                assert config.framework == Framework.FOUNDRY
                # Should have default paths
                assert config.src_path.resolve() == (Path(tmpdir) / "src").resolve()
                assert config.test_path.resolve() == (Path(tmpdir) / "test").resolve()
                assert config.out_path.resolve() == (Path(tmpdir) / "out").resolve()
