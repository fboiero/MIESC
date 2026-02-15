"""
Tests for the Reproducibility Module.

Tests cover:
- set_global_seeds and get_global_seed functions
- ModelVersion dataclass
- get_model_version function family
- EnvironmentFingerprint
- InputRecord and ExperimentRecord
- ExperimentLogger
- create_reproducibility_report
- ensure_reproducibility
"""

import json
import os
import random
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.security.reproducibility import (
    EnvironmentFingerprint,
    ExperimentLogger,
    ExperimentRecord,
    InputRecord,
    ModelVersion,
    create_reproducibility_report,
    ensure_reproducibility,
    get_anthropic_model_version,
    get_environment_fingerprint,
    get_global_seed,
    get_model_version,
    get_ollama_model_version,
    get_openai_model_version,
    set_global_seeds,
)


class TestSetGlobalSeeds:
    """Tests for set_global_seeds function."""

    def test_sets_python_random(self):
        """Test that Python random is seeded."""
        set_global_seeds(42)
        val1 = random.random()
        set_global_seeds(42)
        val2 = random.random()
        assert val1 == val2

    def test_sets_global_seed_value(self):
        """Test that global seed is stored."""
        set_global_seeds(123)
        assert get_global_seed() == 123

    def test_sets_pythonhashseed(self):
        """Test that PYTHONHASHSEED is set."""
        set_global_seeds(456)
        assert os.environ.get("PYTHONHASHSEED") == "456"

    def test_default_seed(self):
        """Test default seed value."""
        set_global_seeds()
        assert get_global_seed() == 42


class TestGetGlobalSeed:
    """Tests for get_global_seed function."""

    def test_returns_none_initially(self):
        """Test returns None before any seed is set."""
        # Reset global seed
        import src.security.reproducibility as repro

        repro._GLOBAL_SEED = None
        assert get_global_seed() is None

    def test_returns_seed_after_set(self):
        """Test returns seed after setting."""
        set_global_seeds(999)
        assert get_global_seed() == 999


class TestModelVersion:
    """Tests for ModelVersion dataclass."""

    def test_creation(self):
        """Test creating ModelVersion."""
        mv = ModelVersion(name="gpt-4", provider="openai", version="0613")
        assert mv.name == "gpt-4"
        assert mv.provider == "openai"
        assert mv.version == "0613"

    def test_default_values(self):
        """Test default values."""
        mv = ModelVersion(name="test", provider="test")
        assert mv.version is None
        assert mv.digest is None
        assert mv.parameters is None
        assert mv.timestamp is not None

    def test_full_name(self):
        """Test full_name property."""
        mv = ModelVersion(name="gpt-4", provider="openai", version="0613")
        assert mv.full_name == "openai:gpt-4:0613"

    def test_full_name_no_version(self):
        """Test full_name without version."""
        mv = ModelVersion(name="model", provider="provider")
        assert mv.full_name == "provider:model"

    def test_to_dict(self):
        """Test to_dict method."""
        mv = ModelVersion(name="test", provider="ollama", digest="abc123")
        d = mv.to_dict()
        assert d["name"] == "test"
        assert d["provider"] == "ollama"
        assert d["digest"] == "abc123"


class TestGetOllamaModelVersion:
    """Tests for get_ollama_model_version function."""

    @patch("subprocess.run")
    def test_successful_fetch(self, mock_run):
        """Test successful model info fetch."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="FROM model@sha256:abc123\nPARAMETER temperature 0.7",
        )
        result = get_ollama_model_version("deepseek-coder")
        assert result is not None
        assert result.name == "deepseek-coder"
        assert result.provider == "ollama"
        assert result.digest == "sha256:abc123"
        assert result.parameters["temperature"] == "0.7"

    @patch("subprocess.run")
    def test_failed_fetch(self, mock_run):
        """Test failed model info fetch."""
        mock_run.return_value = MagicMock(returncode=1, stderr="Error")
        result = get_ollama_model_version("nonexistent")
        assert result is not None
        assert result.name == "nonexistent"
        assert result.digest is None

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_ollama_not_found(self, mock_run):
        """Test when Ollama is not installed."""
        result = get_ollama_model_version("model")
        assert result is not None
        assert result.provider == "ollama"

    @patch("subprocess.run", side_effect=Exception("Unknown error"))
    def test_generic_error(self, mock_run):
        """Test generic error handling."""
        result = get_ollama_model_version("model")
        assert result is not None


class TestGetOpenaiModelVersion:
    """Tests for get_openai_model_version function."""

    def test_model_with_version(self):
        """Test model with version in name."""
        result = get_openai_model_version("gpt-4-0613")
        assert result.name == "gpt-4-0613"
        assert result.provider == "openai"
        assert result.version == "0613"

    def test_model_without_version(self):
        """Test model without version in name."""
        result = get_openai_model_version("gpt-4")
        assert result.version == "4"


class TestGetAnthropicModelVersion:
    """Tests for get_anthropic_model_version function."""

    def test_model_with_version(self):
        """Test model with version in name."""
        result = get_anthropic_model_version("claude-3-opus-20240229")
        assert result.name == "claude-3-opus-20240229"
        assert result.provider == "anthropic"
        assert result.version == "20240229"


class TestGetModelVersion:
    """Tests for get_model_version function."""

    def test_openai_provider(self):
        """Test with openai provider."""
        result = get_model_version("gpt-4", "openai")
        assert result.provider == "openai"

    def test_anthropic_provider(self):
        """Test with anthropic provider."""
        result = get_model_version("claude-3", "anthropic")
        assert result.provider == "anthropic"

    def test_ollama_provider(self):
        """Test with ollama provider."""
        with patch(
            "src.security.reproducibility.get_ollama_model_version"
        ) as mock:
            mock.return_value = ModelVersion(name="test", provider="ollama")
            result = get_model_version("test", "ollama")
            assert result.provider == "ollama"

    def test_unknown_provider(self):
        """Test with unknown provider."""
        result = get_model_version("model", "custom")
        assert result.name == "model"
        assert result.provider == "custom"

    def test_case_insensitive_provider(self):
        """Test provider is case insensitive."""
        result = get_model_version("gpt-4", "OPENAI")
        assert result.provider == "openai"


class TestEnvironmentFingerprint:
    """Tests for EnvironmentFingerprint dataclass."""

    def test_creation(self):
        """Test creating EnvironmentFingerprint."""
        fp = EnvironmentFingerprint(
            python_version="3.12.0",
            platform="Darwin",
            platform_version="23.0.0",
            machine="arm64",
            miesc_version="5.1.1",
            packages={"numpy": "1.24.0"},
            env_vars={"OLLAMA_HOST": "localhost"},
        )
        assert fp.python_version == "3.12.0"
        assert fp.platform == "Darwin"

    def test_to_dict(self):
        """Test to_dict method."""
        fp = EnvironmentFingerprint(
            python_version="3.12.0",
            platform="Linux",
            platform_version="5.4.0",
            machine="x86_64",
            miesc_version="5.1.1",
            packages={},
            env_vars={},
        )
        d = fp.to_dict()
        assert d["python_version"] == "3.12.0"
        assert d["platform"] == "Linux"


class TestGetEnvironmentFingerprint:
    """Tests for get_environment_fingerprint function."""

    def test_returns_fingerprint(self):
        """Test that function returns valid fingerprint."""
        fp = get_environment_fingerprint()
        assert isinstance(fp, EnvironmentFingerprint)
        assert fp.python_version != ""
        assert fp.platform != ""
        assert isinstance(fp.packages, dict)
        assert isinstance(fp.env_vars, dict)

    def test_masks_api_keys(self):
        """Test that API keys are masked."""
        os.environ["TEST_API_KEY"] = "secret123"
        try:
            fp = get_environment_fingerprint()
            if "TEST_API_KEY" in fp.env_vars:
                assert fp.env_vars["TEST_API_KEY"] == "***SET***"
        finally:
            del os.environ["TEST_API_KEY"]


class TestInputRecord:
    """Tests for InputRecord dataclass."""

    def test_creation(self):
        """Test creating InputRecord."""
        ir = InputRecord(path="/path/to/file.sol", hash="abc123", size=1024)
        assert ir.path == "/path/to/file.sol"
        assert ir.hash == "abc123"
        assert ir.size == 1024
        assert ir.timestamp is not None


class TestExperimentRecord:
    """Tests for ExperimentRecord dataclass."""

    def test_creation(self):
        """Test creating ExperimentRecord."""
        record = ExperimentRecord(
            experiment_id="test_001",
            seed=42,
            start_time="2026-02-15T12:00:00",
        )
        assert record.experiment_id == "test_001"
        assert record.seed == 42
        assert record.end_time is None
        assert record.models == []
        assert record.inputs == []

    def test_to_dict(self):
        """Test to_dict method."""
        record = ExperimentRecord(
            experiment_id="test_001",
            seed=42,
            start_time="2026-02-15T12:00:00",
        )
        record.models.append(ModelVersion(name="gpt-4", provider="openai"))
        record.inputs.append(
            InputRecord(path="test.sol", hash="abc", size=100)
        )
        record.parameters = {"temperature": 0.7}

        d = record.to_dict()
        assert d["experiment_id"] == "test_001"
        assert d["seed"] == 42
        assert len(d["models"]) == 1
        assert len(d["inputs"]) == 1
        assert d["parameters"]["temperature"] == 0.7


class TestExperimentLogger:
    """Tests for ExperimentLogger class."""

    def test_init_default(self):
        """Test default initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(output_dir=Path(tmpdir))
            assert logger.experiment_id is not None
            assert logger.experiment_id.startswith("exp_")

    def test_init_custom_id(self):
        """Test initialization with custom ID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(
                experiment_id="my_experiment", output_dir=Path(tmpdir)
            )
            assert logger.experiment_id == "my_experiment"

    def test_init_without_environment(self):
        """Test initialization without environment capture."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(
                output_dir=Path(tmpdir), capture_environment=False
            )
            assert logger.record.environment is None

    def test_log_model(self):
        """Test logging a model."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(output_dir=Path(tmpdir))
            logger.log_model("gpt-4", "openai", temperature=0.7)
            assert len(logger.record.models) == 1
            assert logger.record.models[0].name == "gpt-4"

    def test_log_input_with_file(self):
        """Test logging an input file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            test_file = Path(tmpdir) / "test.sol"
            test_file.write_text("contract Test {}")

            logger = ExperimentLogger(output_dir=Path(tmpdir))
            logger.log_input(str(test_file))

            assert len(logger.record.inputs) == 1
            assert logger.record.inputs[0].hash != "unknown"
            assert logger.record.inputs[0].size > 0

    def test_log_input_nonexistent(self):
        """Test logging nonexistent file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(output_dir=Path(tmpdir))
            logger.log_input("/nonexistent/file.sol", hash_value="provided")
            assert logger.record.inputs[0].hash == "provided"

    def test_log_parameter(self):
        """Test logging a parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(output_dir=Path(tmpdir))
            logger.log_parameter("temperature", 0.7)
            assert logger.record.parameters["temperature"] == 0.7

    def test_log_output(self):
        """Test logging an output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(output_dir=Path(tmpdir))
            logger.log_output("findings_count", 10)
            assert logger.record.outputs["findings_count"] == 10

    def test_log_metric(self):
        """Test logging a metric."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(output_dir=Path(tmpdir))
            logger.log_metric("precision", 0.95)
            assert logger.record.metrics["precision"] == 0.95

    def test_finish(self):
        """Test finishing an experiment."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(output_dir=Path(tmpdir))
            assert logger.record.end_time is None
            logger.finish()
            assert logger.record.end_time is not None

    def test_save(self):
        """Test saving experiment record."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(
                experiment_id="test_save", output_dir=Path(tmpdir)
            )
            logger.log_parameter("test", 123)
            output_path = logger.save()

            assert output_path.exists()
            with open(output_path) as f:
                data = json.load(f)
            assert data["experiment_id"] == "test_save"
            assert data["parameters"]["test"] == 123

    def test_save_custom_filename(self):
        """Test saving with custom filename."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(output_dir=Path(tmpdir))
            output_path = logger.save("custom.json")
            assert output_path.name == "custom.json"

    def test_get_record(self):
        """Test getting experiment record."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ExperimentLogger(output_dir=Path(tmpdir))
            record = logger.get_record()
            assert isinstance(record, ExperimentRecord)
            assert record.experiment_id == logger.experiment_id


class TestCreateReproducibilityReport:
    """Tests for create_reproducibility_report function."""

    def test_creates_report(self):
        """Test creating a reproducibility report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            set_global_seeds(42)
            logger = ExperimentLogger(output_dir=Path(tmpdir))
            logger.log_model("gpt-4", "openai")
            logger.log_input("/path/to/contract.sol", hash_value="abc123")
            logger.log_parameter("temperature", 0.7)

            report = create_reproducibility_report(logger)

            assert "reproducibility" in report
            assert report["reproducibility"]["random_seed"] == 42
            assert len(report["reproducibility"]["models"]) == 1
            assert len(report["reproducibility"]["inputs"]) == 1
            assert report["reproducibility"]["parameters"]["temperature"] == 0.7


class TestEnsureReproducibility:
    """Tests for ensure_reproducibility function."""

    def test_sets_seed_and_returns_logger(self):
        """Test that it sets seed and returns logger."""
        with tempfile.TemporaryDirectory():
            with patch(
                "src.security.reproducibility.ExperimentLogger"
            ) as MockLogger:
                MockLogger.return_value = MagicMock()
                ensure_reproducibility(123)
                assert get_global_seed() == 123
                MockLogger.assert_called_once_with(capture_environment=True)

    def test_default_seed(self):
        """Test default seed value."""
        ensure_reproducibility()
        assert get_global_seed() == 42
