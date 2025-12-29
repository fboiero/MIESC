"""
MIESC Framework Auto-Detection
==============================

Automatically detects Solidity development frameworks (Foundry, Hardhat, Truffle)
and extracts their configuration for optimized analysis.

Features:
- Foundry detection via foundry.toml
- Hardhat detection via hardhat.config.js/ts
- Truffle detection via truffle-config.js
- Brownie detection via brownie-config.yaml
- Automatic solc version extraction
- Remappings and dependencies resolution

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: December 2025
Version: 1.0.0
"""

import os
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # Fallback for older Python
    except ImportError:
        tomllib = None

logger = logging.getLogger(__name__)


class Framework(Enum):
    """Supported Solidity development frameworks."""
    FOUNDRY = "foundry"
    HARDHAT = "hardhat"
    TRUFFLE = "truffle"
    BROWNIE = "brownie"
    UNKNOWN = "unknown"


@dataclass
class FrameworkConfig:
    """Configuration extracted from a detected framework."""
    framework: Framework
    root_path: Path
    config_file: Optional[Path] = None
    solc_version: Optional[str] = None
    evm_version: Optional[str] = None
    optimizer_enabled: bool = False
    optimizer_runs: int = 200
    remappings: List[str] = field(default_factory=list)
    lib_paths: List[Path] = field(default_factory=list)
    src_path: Optional[Path] = None
    test_path: Optional[Path] = None
    out_path: Optional[Path] = None
    extra_config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "framework": self.framework.value,
            "root_path": str(self.root_path),
            "config_file": str(self.config_file) if self.config_file else None,
            "solc_version": self.solc_version,
            "evm_version": self.evm_version,
            "optimizer_enabled": self.optimizer_enabled,
            "optimizer_runs": self.optimizer_runs,
            "remappings": self.remappings,
            "lib_paths": [str(p) for p in self.lib_paths],
            "src_path": str(self.src_path) if self.src_path else None,
            "test_path": str(self.test_path) if self.test_path else None,
            "out_path": str(self.out_path) if self.out_path else None,
            "extra_config": self.extra_config,
        }


class FrameworkDetector:
    """
    Detects Solidity development frameworks and extracts configuration.

    Usage:
        detector = FrameworkDetector()
        config = detector.detect("/path/to/project")

        if config.framework == Framework.FOUNDRY:
            print(f"Foundry project with solc {config.solc_version}")
    """

    # Framework detection files in order of precedence
    DETECTION_FILES = {
        Framework.FOUNDRY: ["foundry.toml"],
        Framework.HARDHAT: ["hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs"],
        Framework.TRUFFLE: ["truffle-config.js", "truffle.js"],
        Framework.BROWNIE: ["brownie-config.yaml"],
    }

    def __init__(self):
        """Initialize the framework detector."""
        self._cache: Dict[str, FrameworkConfig] = {}

    def detect(self, path: str, use_cache: bool = True) -> FrameworkConfig:
        """
        Detect framework at the given path and extract configuration.

        Args:
            path: Path to project directory or file
            use_cache: Whether to use cached results

        Returns:
            FrameworkConfig with detected framework and settings
        """
        path = Path(path).resolve()

        # If it's a file, use parent directory
        if path.is_file():
            path = path.parent

        cache_key = str(path)
        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        # Search for framework config files
        framework, config_file = self._find_framework(path)

        # Extract configuration based on framework
        if framework == Framework.FOUNDRY:
            config = self._parse_foundry(path, config_file)
        elif framework == Framework.HARDHAT:
            config = self._parse_hardhat(path, config_file)
        elif framework == Framework.TRUFFLE:
            config = self._parse_truffle(path, config_file)
        elif framework == Framework.BROWNIE:
            config = self._parse_brownie(path, config_file)
        else:
            config = FrameworkConfig(
                framework=Framework.UNKNOWN,
                root_path=path,
            )

        # Cache result
        self._cache[cache_key] = config

        logger.info(f"Detected framework: {config.framework.value} at {path}")
        if config.solc_version:
            logger.info(f"  Solc version: {config.solc_version}")
        if config.remappings:
            logger.debug(f"  Remappings: {len(config.remappings)} entries")

        return config

    def _find_framework(self, path: Path) -> Tuple[Framework, Optional[Path]]:
        """
        Search for framework configuration files.

        Args:
            path: Directory to search

        Returns:
            Tuple of (Framework, config_file_path)
        """
        # Search current directory and up to 5 parent directories
        current = path
        for _ in range(6):
            for framework, files in self.DETECTION_FILES.items():
                for filename in files:
                    config_path = current / filename
                    if config_path.exists():
                        return framework, config_path

            parent = current.parent
            if parent == current:  # Reached root
                break
            current = parent

        return Framework.UNKNOWN, None

    def _parse_foundry(self, root: Path, config_file: Path) -> FrameworkConfig:
        """
        Parse Foundry configuration from foundry.toml.

        Example foundry.toml:
            [profile.default]
            src = 'src'
            out = 'out'
            libs = ['lib']
            solc = '0.8.19'
            evm_version = 'paris'
            optimizer = true
            optimizer_runs = 200
        """
        config = FrameworkConfig(
            framework=Framework.FOUNDRY,
            root_path=root,
            config_file=config_file,
        )

        if not tomllib:
            logger.warning("TOML parser not available, using defaults for Foundry")
            config.src_path = root / "src"
            config.test_path = root / "test"
            config.out_path = root / "out"
            config.lib_paths = [root / "lib"]
            return config

        try:
            with open(config_file, "rb") as f:
                data = tomllib.load(f)

            # Get default profile settings
            profile = data.get("profile", {}).get("default", {})

            # Extract paths
            config.src_path = root / profile.get("src", "src")
            config.test_path = root / profile.get("test", "test")
            config.out_path = root / profile.get("out", "out")

            # Extract lib paths
            libs = profile.get("libs", ["lib"])
            config.lib_paths = [root / lib for lib in libs]

            # Extract compiler settings
            config.solc_version = profile.get("solc") or profile.get("solc_version")
            config.evm_version = profile.get("evm_version", "paris")
            config.optimizer_enabled = profile.get("optimizer", False)
            config.optimizer_runs = profile.get("optimizer_runs", 200)

            # Extract remappings from config or remappings.txt
            remappings = profile.get("remappings", [])
            if not remappings:
                remappings = self._read_remappings_file(root)

            # Also get auto-detected remappings from forge
            forge_remappings = self._get_forge_remappings(root)
            config.remappings = list(set(remappings + forge_remappings))

            # Store extra config
            config.extra_config = {
                "via_ir": profile.get("via_ir", False),
                "ffi": profile.get("ffi", False),
                "fuzz_runs": profile.get("fuzz", {}).get("runs", 256),
                "invariant_runs": profile.get("invariant", {}).get("runs", 256),
            }

        except Exception as e:
            logger.warning(f"Error parsing foundry.toml: {e}")
            config.src_path = root / "src"
            config.test_path = root / "test"
            config.out_path = root / "out"
            config.lib_paths = [root / "lib"]

        return config

    def _read_remappings_file(self, root: Path) -> List[str]:
        """Read remappings from remappings.txt if it exists."""
        remappings_file = root / "remappings.txt"
        if remappings_file.exists():
            try:
                with open(remappings_file) as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception as e:
                logger.debug(f"Error reading remappings.txt: {e}")
        return []

    def _get_forge_remappings(self, root: Path) -> List[str]:
        """Get remappings from forge command."""
        try:
            result = subprocess.run(
                ["forge", "remappings"],
                capture_output=True,
                text=True,
                cwd=root,
                timeout=10,
            )
            if result.returncode == 0:
                return [line.strip() for line in result.stdout.split("\n") if line.strip()]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception as e:
            logger.debug(f"Error getting forge remappings: {e}")
        return []

    def _parse_hardhat(self, root: Path, config_file: Path) -> FrameworkConfig:
        """
        Parse Hardhat configuration.

        Hardhat config is JavaScript/TypeScript, so we extract via node.
        Falls back to common defaults if parsing fails.
        """
        config = FrameworkConfig(
            framework=Framework.HARDHAT,
            root_path=root,
            config_file=config_file,
        )

        # Set common Hardhat paths
        config.src_path = root / "contracts"
        config.test_path = root / "test"
        config.out_path = root / "artifacts"
        config.lib_paths = [root / "node_modules"]

        # Try to extract solc version using node
        try:
            # Create a temp script to extract config
            extract_script = """
            const config = require('./hardhat.config');
            const solidity = config.solidity || {};
            const output = {
                version: typeof solidity === 'string' ? solidity : (solidity.version || null),
                compilers: solidity.compilers || [],
                settings: solidity.settings || {},
            };
            console.log(JSON.stringify(output));
            """

            result = subprocess.run(
                ["node", "-e", extract_script],
                capture_output=True,
                text=True,
                cwd=root,
                timeout=10,
            )

            if result.returncode == 0:
                data = json.loads(result.stdout)

                # Get solc version
                if data.get("version"):
                    config.solc_version = data["version"]
                elif data.get("compilers"):
                    # Use latest version from compilers list
                    versions = [c.get("version") for c in data["compilers"] if c.get("version")]
                    if versions:
                        config.solc_version = max(versions)

                # Get optimizer settings
                settings = data.get("settings", {})
                optimizer = settings.get("optimizer", {})
                config.optimizer_enabled = optimizer.get("enabled", False)
                config.optimizer_runs = optimizer.get("runs", 200)
                config.evm_version = settings.get("evmVersion")

        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        except Exception as e:
            logger.debug(f"Error extracting Hardhat config: {e}")

        return config

    def _parse_truffle(self, root: Path, config_file: Path) -> FrameworkConfig:
        """Parse Truffle configuration."""
        config = FrameworkConfig(
            framework=Framework.TRUFFLE,
            root_path=root,
            config_file=config_file,
        )

        # Common Truffle paths
        config.src_path = root / "contracts"
        config.test_path = root / "test"
        config.out_path = root / "build" / "contracts"
        config.lib_paths = [root / "node_modules"]

        # Try to extract config via node (similar to Hardhat)
        try:
            extract_script = """
            const config = require('./truffle-config');
            const compilers = config.compilers || {};
            const solc = compilers.solc || {};
            console.log(JSON.stringify({
                version: solc.version,
                optimizer: solc.settings?.optimizer || {},
                evmVersion: solc.settings?.evmVersion,
            }));
            """

            result = subprocess.run(
                ["node", "-e", extract_script],
                capture_output=True,
                text=True,
                cwd=root,
                timeout=10,
            )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                config.solc_version = data.get("version")
                optimizer = data.get("optimizer", {})
                config.optimizer_enabled = optimizer.get("enabled", False)
                config.optimizer_runs = optimizer.get("runs", 200)
                config.evm_version = data.get("evmVersion")

        except Exception as e:
            logger.debug(f"Error extracting Truffle config: {e}")

        return config

    def _parse_brownie(self, root: Path, config_file: Path) -> FrameworkConfig:
        """Parse Brownie configuration from brownie-config.yaml."""
        config = FrameworkConfig(
            framework=Framework.BROWNIE,
            root_path=root,
            config_file=config_file,
        )

        # Common Brownie paths
        config.src_path = root / "contracts"
        config.test_path = root / "tests"
        config.out_path = root / "build"

        try:
            import yaml
            with open(config_file) as f:
                data = yaml.safe_load(f)

            compiler = data.get("compiler", {})
            solc = compiler.get("solc", {})

            config.solc_version = solc.get("version")
            config.evm_version = solc.get("evm_version")
            config.optimizer_enabled = solc.get("optimizer", {}).get("enabled", False)
            config.optimizer_runs = solc.get("optimizer", {}).get("runs", 200)
            config.remappings = solc.get("remappings", [])

        except ImportError:
            logger.debug("PyYAML not installed, cannot parse brownie-config.yaml")
        except Exception as e:
            logger.debug(f"Error parsing brownie-config.yaml: {e}")

        return config

    def get_solc_args(self, config: FrameworkConfig) -> List[str]:
        """
        Generate solc command-line arguments from framework config.

        Args:
            config: Framework configuration

        Returns:
            List of solc command-line arguments
        """
        args = []

        if config.evm_version:
            args.extend(["--evm-version", config.evm_version])

        if config.optimizer_enabled:
            args.append("--optimize")
            args.extend(["--optimize-runs", str(config.optimizer_runs)])

        for remapping in config.remappings:
            args.append(remapping)

        for lib_path in config.lib_paths:
            if lib_path.exists():
                args.extend(["--include-path", str(lib_path)])

        if config.src_path and config.src_path.exists():
            args.extend(["--base-path", str(config.src_path.parent)])

        return args

    def get_slither_args(self, config: FrameworkConfig) -> List[str]:
        """
        Generate Slither command-line arguments from framework config.

        Args:
            config: Framework configuration

        Returns:
            List of Slither command-line arguments
        """
        args = []

        if config.solc_version:
            args.extend(["--solc-solcs-select", config.solc_version])

        if config.framework == Framework.FOUNDRY:
            args.append("--foundry-out-directory")
            args.append(str(config.out_path or config.root_path / "out"))

            if config.remappings:
                for remap in config.remappings:
                    args.extend(["--solc-remaps", remap])

        elif config.framework == Framework.HARDHAT:
            args.append("--hardhat-artifacts-directory")
            args.append(str(config.out_path or config.root_path / "artifacts"))

        return args

    def clear_cache(self):
        """Clear the detection cache."""
        self._cache.clear()


# Module-level convenience function
_detector = None


def detect_framework(path: str) -> FrameworkConfig:
    """
    Detect framework at the given path.

    This is a convenience function that uses a module-level detector instance.

    Args:
        path: Path to project directory or file

    Returns:
        FrameworkConfig with detected framework and settings
    """
    global _detector
    if _detector is None:
        _detector = FrameworkDetector()
    return _detector.detect(path)


def get_framework_name(path: str) -> str:
    """Get the name of the detected framework."""
    config = detect_framework(path)
    return config.framework.value


def is_foundry_project(path: str) -> bool:
    """Check if path is a Foundry project."""
    return detect_framework(path).framework == Framework.FOUNDRY


def is_hardhat_project(path: str) -> bool:
    """Check if path is a Hardhat project."""
    return detect_framework(path).framework == Framework.HARDHAT


__all__ = [
    "Framework",
    "FrameworkConfig",
    "FrameworkDetector",
    "detect_framework",
    "get_framework_name",
    "is_foundry_project",
    "is_hardhat_project",
]
