"""
Reproducibility Module for AI/ML Analysis

Provides utilities for reproducible AI analysis:
1. Random seed management for deterministic behavior
2. Model version tracking and pinning
3. Experiment logging and metadata capture
4. Environment fingerprinting

Usage:
    from src.security.reproducibility import (
        set_global_seeds,
        get_model_version,
        ExperimentLogger,
        create_reproducibility_report,
    )

    # Set seeds at startup
    set_global_seeds(42)

    # Track experiment
    logger = ExperimentLogger("audit_2026_02_13")
    logger.log_model("deepseek-coder:6.7b", "ollama")
    logger.log_input("contract.sol", hash="abc123")
    logger.save()
"""

import hashlib
import json
import logging
import os
import platform
import random
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Global seed value for tracking
_GLOBAL_SEED: Optional[int] = None


def set_global_seeds(seed: int = 42) -> None:
    """
    Set random seeds for reproducibility across all relevant libraries.

    This should be called at the start of any analysis pipeline
    to ensure deterministic behavior.

    Args:
        seed: Random seed value (default: 42)

    Example:
        >>> from src.security.reproducibility import set_global_seeds
        >>> set_global_seeds(42)  # Call at program start
    """
    global _GLOBAL_SEED
    _GLOBAL_SEED = seed

    # Python's random
    random.seed(seed)

    # NumPy (if available)
    try:
        import numpy as np
        np.random.seed(seed)
        logger.debug(f"NumPy seed set to {seed}")
    except ImportError:
        pass

    # PyTorch (if available)
    try:
        import torch
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
            # For complete reproducibility (may impact performance)
            torch.backends.cudnn.deterministic = True
            torch.backends.cudnn.benchmark = False
        logger.debug(f"PyTorch seed set to {seed}")
    except ImportError:
        pass

    # TensorFlow (if available)
    try:
        import tensorflow as tf
        tf.random.set_seed(seed)
        logger.debug(f"TensorFlow seed set to {seed}")
    except ImportError:
        pass

    # Set environment variables for additional reproducibility
    os.environ["PYTHONHASHSEED"] = str(seed)

    logger.info(f"Global seeds set to {seed}")


def get_global_seed() -> Optional[int]:
    """Get the current global seed value."""
    return _GLOBAL_SEED


@dataclass
class ModelVersion:
    """Information about a model version."""

    name: str
    provider: str
    version: Optional[str] = None
    digest: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def full_name(self) -> str:
        """Get full model identifier."""
        parts = [self.provider, self.name]
        if self.version:
            parts.append(self.version)
        return ":".join(parts)


def get_ollama_model_version(model_name: str) -> Optional[ModelVersion]:
    """
    Get version information for an Ollama model.

    Args:
        model_name: Name of the Ollama model (e.g., "deepseek-coder:6.7b")

    Returns:
        ModelVersion with digest and metadata, or None if not found
    """
    try:
        result = subprocess.run(
            ["ollama", "show", model_name, "--modelfile"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            logger.warning(f"Failed to get Ollama model info: {result.stderr}")
            return ModelVersion(name=model_name, provider="ollama")

        # Parse modelfile for metadata
        modelfile = result.stdout
        digest = None
        parameters = {}

        # Extract digest from FROM line
        for line in modelfile.split("\n"):
            if line.startswith("FROM"):
                parts = line.split("@")
                if len(parts) > 1:
                    digest = parts[1].strip()
            elif line.startswith("PARAMETER"):
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    parameters[parts[1]] = parts[2]

        return ModelVersion(
            name=model_name,
            provider="ollama",
            digest=digest,
            parameters=parameters if parameters else None,
        )
    except FileNotFoundError:
        logger.warning("Ollama not found")
        return ModelVersion(name=model_name, provider="ollama")
    except subprocess.TimeoutExpired:
        logger.warning("Ollama command timed out")
        return ModelVersion(name=model_name, provider="ollama")
    except Exception as e:
        logger.warning(f"Error getting Ollama model version: {e}")
        return ModelVersion(name=model_name, provider="ollama")


def get_openai_model_version(model_name: str) -> ModelVersion:
    """
    Get version information for an OpenAI model.

    Note: OpenAI models are versioned by date suffix (e.g., gpt-4-0613)
    """
    # OpenAI models have implicit versioning in the name
    return ModelVersion(
        name=model_name,
        provider="openai",
        version=model_name.split("-")[-1] if "-" in model_name else None,
    )


def get_anthropic_model_version(model_name: str) -> ModelVersion:
    """Get version information for an Anthropic model."""
    return ModelVersion(
        name=model_name,
        provider="anthropic",
        version=model_name.split("-")[-1] if "-" in model_name else None,
    )


def get_model_version(model_name: str, provider: str) -> ModelVersion:
    """
    Get version information for any supported model.

    Args:
        model_name: Model name/identifier
        provider: Provider name (ollama, openai, anthropic)

    Returns:
        ModelVersion with available metadata
    """
    provider = provider.lower()

    if provider == "ollama":
        return get_ollama_model_version(model_name) or ModelVersion(name=model_name, provider=provider)
    elif provider == "openai":
        return get_openai_model_version(model_name)
    elif provider == "anthropic":
        return get_anthropic_model_version(model_name)
    else:
        return ModelVersion(name=model_name, provider=provider)


@dataclass
class EnvironmentFingerprint:
    """Fingerprint of the execution environment."""

    python_version: str
    platform: str
    platform_version: str
    machine: str
    miesc_version: str
    packages: Dict[str, str]
    env_vars: Dict[str, str]
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_environment_fingerprint() -> EnvironmentFingerprint:
    """
    Capture a fingerprint of the current environment.

    Useful for debugging reproducibility issues.
    """
    # Get relevant package versions
    packages = {}
    package_names = [
        "sentence-transformers",
        "chromadb",
        "openai",
        "anthropic",
        "pydantic",
        "slither-analyzer",
        "torch",
        "numpy",
    ]

    for pkg in package_names:
        try:
            import importlib.metadata
            packages[pkg] = importlib.metadata.version(pkg)
        except Exception:
            packages[pkg] = "not installed"

    # Get MIESC version
    try:
        from miesc import __version__ as miesc_version
    except ImportError:
        miesc_version = "unknown"

    # Get relevant environment variables
    env_vars = {}
    relevant_env = [
        "OLLAMA_HOST",
        "OPENAI_API_KEY",  # Just presence, not value
        "ANTHROPIC_API_KEY",
        "CUDA_VISIBLE_DEVICES",
        "PYTHONHASHSEED",
    ]
    for var in relevant_env:
        value = os.environ.get(var)
        if value:
            # Mask API keys
            if "KEY" in var or "SECRET" in var:
                env_vars[var] = "***SET***"
            else:
                env_vars[var] = value

    return EnvironmentFingerprint(
        python_version=sys.version,
        platform=platform.system(),
        platform_version=platform.version(),
        machine=platform.machine(),
        miesc_version=miesc_version,
        packages=packages,
        env_vars=env_vars,
    )


@dataclass
class InputRecord:
    """Record of an input file."""

    path: str
    hash: str
    size: int
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ExperimentRecord:
    """Complete record of an experiment for reproducibility."""

    experiment_id: str
    seed: Optional[int]
    start_time: str
    end_time: Optional[str] = None
    environment: Optional[EnvironmentFingerprint] = None
    models: List[ModelVersion] = field(default_factory=list)
    inputs: List[InputRecord] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "experiment_id": self.experiment_id,
            "seed": self.seed,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "parameters": self.parameters,
            "outputs": self.outputs,
            "metrics": self.metrics,
        }
        if self.environment:
            data["environment"] = self.environment.to_dict()
        data["models"] = [m.to_dict() for m in self.models]
        data["inputs"] = [asdict(i) for i in self.inputs]
        return data


class ExperimentLogger:
    """
    Logger for tracking experiments for reproducibility.

    Usage:
        logger = ExperimentLogger("audit_001")
        logger.log_model("deepseek-coder:6.7b", "ollama")
        logger.log_input("contract.sol")
        logger.log_parameter("temperature", 0.1)
        logger.log_output("findings_count", 5)
        logger.log_metric("precision", 0.95)
        logger.save()
    """

    def __init__(
        self,
        experiment_id: Optional[str] = None,
        output_dir: Optional[Path] = None,
        capture_environment: bool = True,
    ):
        """
        Initialize experiment logger.

        Args:
            experiment_id: Unique experiment identifier (auto-generated if None)
            output_dir: Directory for saving logs (default: ~/.miesc/experiments/)
            capture_environment: Whether to capture environment fingerprint
        """
        self.experiment_id = experiment_id or self._generate_id()
        self.output_dir = output_dir or Path.home() / ".miesc" / "experiments"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.record = ExperimentRecord(
            experiment_id=self.experiment_id,
            seed=get_global_seed(),
            start_time=datetime.utcnow().isoformat(),
            environment=get_environment_fingerprint() if capture_environment else None,
        )

    def _generate_id(self) -> str:
        """Generate a unique experiment ID."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        random_suffix = hashlib.md5(str(random.random()).encode()).hexdigest()[:6]
        return f"exp_{timestamp}_{random_suffix}"

    def log_model(
        self,
        model_name: str,
        provider: str,
        **kwargs: Any,
    ) -> None:
        """Log a model used in the experiment."""
        version = get_model_version(model_name, provider)
        if kwargs:
            version.parameters = version.parameters or {}
            version.parameters.update(kwargs)
        self.record.models.append(version)
        logger.debug(f"Logged model: {version.full_name}")

    def log_input(
        self,
        path: str,
        hash_value: Optional[str] = None,
    ) -> None:
        """Log an input file."""
        file_path = Path(path)

        if hash_value is None and file_path.exists():
            # Calculate hash
            with open(file_path, "rb") as f:
                hash_value = hashlib.sha256(f.read()).hexdigest()
            size = file_path.stat().st_size
        else:
            hash_value = hash_value or "unknown"
            size = 0

        self.record.inputs.append(InputRecord(
            path=str(path),
            hash=hash_value,
            size=size,
        ))
        logger.debug(f"Logged input: {path}")

    def log_parameter(self, name: str, value: Any) -> None:
        """Log a parameter value."""
        self.record.parameters[name] = value

    def log_output(self, name: str, value: Any) -> None:
        """Log an output value."""
        self.record.outputs[name] = value

    def log_metric(self, name: str, value: float) -> None:
        """Log a metric value."""
        self.record.metrics[name] = value

    def finish(self) -> None:
        """Mark experiment as finished."""
        self.record.end_time = datetime.utcnow().isoformat()

    def save(self, filename: Optional[str] = None) -> Path:
        """
        Save experiment record to file.

        Args:
            filename: Output filename (default: {experiment_id}.json)

        Returns:
            Path to saved file
        """
        self.finish()
        filename = filename or f"{self.experiment_id}.json"
        output_path = self.output_dir / filename

        with open(output_path, "w") as f:
            json.dump(self.record.to_dict(), f, indent=2, default=str)

        logger.info(f"Experiment saved: {output_path}")
        return output_path

    def get_record(self) -> ExperimentRecord:
        """Get the current experiment record."""
        return self.record


def create_reproducibility_report(
    experiment_logger: ExperimentLogger,
) -> Dict[str, Any]:
    """
    Create a reproducibility report from an experiment.

    Returns a dictionary suitable for including in audit reports.
    """
    record = experiment_logger.get_record()

    report = {
        "reproducibility": {
            "experiment_id": record.experiment_id,
            "random_seed": record.seed,
            "timestamp": record.start_time,
            "models": [
                {
                    "name": m.full_name,
                    "digest": m.digest,
                }
                for m in record.models
            ],
            "inputs": [
                {
                    "file": i.path,
                    "sha256": i.hash,
                }
                for i in record.inputs
            ],
            "environment": {
                "python": record.environment.python_version.split()[0] if record.environment else "unknown",
                "platform": record.environment.platform if record.environment else "unknown",
                "miesc_version": record.environment.miesc_version if record.environment else "unknown",
            },
            "parameters": record.parameters,
        }
    }

    return report


def ensure_reproducibility(seed: int = 42) -> ExperimentLogger:
    """
    Convenience function to set up reproducibility for an analysis.

    Args:
        seed: Random seed

    Returns:
        ExperimentLogger ready for use

    Example:
        >>> logger = ensure_reproducibility(42)
        >>> # ... run analysis ...
        >>> logger.save()
    """
    set_global_seeds(seed)
    return ExperimentLogger(capture_environment=True)
