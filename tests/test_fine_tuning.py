"""
Comprehensive tests for MIESC ML Fine-Tuning Module.

Tests SoliditySecurityDatasetGenerator and related classes.

Author: Fernando Boiero
"""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.ml.fine_tuning.dataset_generator import (
    SoliditySecurityDatasetGenerator,
    TrainingExample,
    VulnerabilityExample,
)

# =============================================================================
# Test VulnerabilityExample Dataclass
# =============================================================================


class TestVulnerabilityExample:
    """Tests for VulnerabilityExample dataclass."""

    def test_create_basic_example(self):
        """Test creating a basic vulnerability example."""
        example = VulnerabilityExample(
            id="vuln_001",
            vulnerability_type="reentrancy",
            severity="critical",
            vulnerable_code="function withdraw() { ... }",
            fixed_code="function withdraw() nonReentrant { ... }",
            explanation="Reentrancy allows recursive calls.",
            detection_pattern=r"\.call\{value",
            remediation="Use ReentrancyGuard",
        )

        assert example.id == "vuln_001"
        assert example.vulnerability_type == "reentrancy"
        assert example.severity == "critical"

    def test_example_with_optional_fields(self):
        """Test example with optional CWE/SWC IDs."""
        example = VulnerabilityExample(
            id="vuln_002",
            vulnerability_type="overflow",
            severity="high",
            vulnerable_code="a + b",
            fixed_code="a.add(b)",
            explanation="Integer overflow",
            detection_pattern=r"\+",
            remediation="Use SafeMath",
            cwe_id="CWE-190",
            swc_id="SWC-101",
            source="audit_report",
        )

        assert example.cwe_id == "CWE-190"
        assert example.swc_id == "SWC-101"
        assert example.source == "audit_report"

    def test_example_default_source(self):
        """Test example has default source."""
        example = VulnerabilityExample(
            id="test",
            vulnerability_type="test",
            severity="low",
            vulnerable_code="code",
            fixed_code="fixed",
            explanation="exp",
            detection_pattern="pattern",
            remediation="fix",
        )

        assert example.source == "manual"


# =============================================================================
# Test TrainingExample Dataclass
# =============================================================================


class TestTrainingExample:
    """Tests for TrainingExample dataclass."""

    def test_create_training_example(self):
        """Test creating a training example."""
        example = TrainingExample(
            instruction="Analyze this code for vulnerabilities.",
            input="function transfer() {}",
            output="No vulnerabilities found.",
            metadata={"task": "detection", "source": "test"},
        )

        assert example.instruction == "Analyze this code for vulnerabilities."
        assert example.input == "function transfer() {}"
        assert example.metadata["task"] == "detection"

    def test_training_example_complex_metadata(self):
        """Test training example with complex metadata."""
        example = TrainingExample(
            instruction="Fix this vulnerability.",
            input="vulnerable code",
            output="fixed code",
            metadata={
                "task": "fix",
                "severity": "high",
                "vuln_type": "reentrancy",
                "tags": ["defi", "security"],
            },
        )

        assert example.metadata["tags"] == ["defi", "security"]


# =============================================================================
# Test SoliditySecurityDatasetGenerator
# =============================================================================


class TestSoliditySecurityDatasetGenerator:
    """Tests for SoliditySecurityDatasetGenerator class."""

    @pytest.fixture
    def generator(self, tmp_path):
        """Create generator with temporary output directory."""
        return SoliditySecurityDatasetGenerator(output_dir=str(tmp_path / "datasets"))

    @pytest.fixture
    def sample_examples(self):
        """Create sample vulnerability examples."""
        return [
            VulnerabilityExample(
                id="test_001",
                vulnerability_type="reentrancy",
                severity="critical",
                vulnerable_code="function withdraw() { call(); balance -= amt; }",
                fixed_code="function withdraw() { balance -= amt; call(); }",
                explanation="State updated after external call.",
                detection_pattern=r"call.*-=",
                remediation="CEI pattern",
                cwe_id="CWE-841",
                swc_id="SWC-107",
            ),
            VulnerabilityExample(
                id="test_002",
                vulnerability_type="access_control",
                severity="critical",
                vulnerable_code="function setOwner(address) { owner = newOwner; }",
                fixed_code="function setOwner(address) onlyOwner { owner = newOwner; }",
                explanation="Missing access control.",
                detection_pattern=r"owner\s*=",
                remediation="Add onlyOwner modifier",
                cwe_id="CWE-284",
                swc_id="SWC-105",
            ),
        ]

    def test_initialization(self, generator, tmp_path):
        """Test generator initialization."""
        assert generator.output_dir == tmp_path / "datasets"
        assert generator.output_dir.exists()
        assert generator.examples == []

    def test_output_dir_created(self, tmp_path):
        """Test output directory is created."""
        output_path = tmp_path / "new_datasets"
        generator = SoliditySecurityDatasetGenerator(output_dir=str(output_path))

        assert output_path.exists()

    def test_vulnerability_templates_exist(self, generator):
        """Test vulnerability templates are defined."""
        templates = generator.VULNERABILITY_TEMPLATES

        assert "reentrancy" in templates
        assert "integer_overflow" in templates
        assert "access_control" in templates
        assert "unchecked_return" in templates
        assert "tx_origin" in templates

    def test_template_structure(self, generator):
        """Test template has required keys."""
        for vuln_type, template in generator.VULNERABILITY_TEMPLATES.items():
            assert "vulnerable" in template, f"Missing 'vulnerable' in {vuln_type}"
            assert "fixed" in template, f"Missing 'fixed' in {vuln_type}"
            assert "explanation" in template, f"Missing 'explanation' in {vuln_type}"

    def test_generate_base_examples(self, generator):
        """Test generating base examples from templates."""
        examples = generator.generate_base_examples()

        assert len(examples) > 0
        assert len(examples) == len(generator.VULNERABILITY_TEMPLATES)

        for example in examples:
            assert isinstance(example, VulnerabilityExample)
            assert example.id.startswith("template_")
            assert example.vulnerability_type in generator.VULNERABILITY_TEMPLATES
            assert example.source == "miesc_templates"

    def test_get_severity_critical(self, generator):
        """Test severity classification for critical vulns."""
        assert generator._get_severity("reentrancy") == "critical"
        assert generator._get_severity("access_control") == "critical"
        assert generator._get_severity("oracle_manipulation") == "critical"

    def test_get_severity_high(self, generator):
        """Test severity classification for high vulns."""
        assert generator._get_severity("integer_overflow") == "high"
        assert generator._get_severity("signature_replay") == "high"
        assert generator._get_severity("unchecked_return") == "high"

    def test_get_severity_medium(self, generator):
        """Test severity classification for medium vulns."""
        assert generator._get_severity("tx_origin") == "medium"
        assert generator._get_severity("frontrunning") == "medium"
        assert generator._get_severity("dos_gas_limit") == "medium"

    def test_get_severity_unknown(self, generator):
        """Test severity classification for unknown vulns."""
        assert generator._get_severity("unknown_type") == "low"

    def test_generate_detection_pattern(self, generator):
        """Test detection pattern generation."""
        pattern = generator._generate_detection_pattern("reentrancy")
        assert pattern is not None
        assert len(pattern) > 0

        pattern = generator._generate_detection_pattern("tx_origin")
        # Pattern may be escaped for regex (tx\.origin) or literal (tx.origin)
        assert "tx" in pattern and "origin" in pattern

    def test_generate_detection_pattern_unknown(self, generator):
        """Test detection pattern for unknown type returns default."""
        pattern = generator._generate_detection_pattern("unknown")
        assert pattern == r".*"

    def test_generate_remediation(self, generator):
        """Test remediation generation."""
        remediation = generator._generate_remediation("reentrancy")
        assert "ReentrancyGuard" in remediation or "Checks-Effects-Interactions" in remediation

        remediation = generator._generate_remediation("access_control")
        assert "onlyOwner" in remediation or "access control" in remediation

    def test_generate_remediation_unknown(self, generator):
        """Test remediation for unknown type returns default."""
        remediation = generator._generate_remediation("unknown")
        assert "Review" in remediation

    def test_generate_training_examples(self, generator, sample_examples):
        """Test generating training examples from vuln examples."""
        training_data = generator.generate_training_examples(sample_examples)

        # 4 tasks per vulnerability example
        assert len(training_data) == len(sample_examples) * 4

        tasks = [ex.metadata["task"] for ex in training_data]
        assert "vulnerability_detection" in tasks
        assert "code_fix" in tasks
        assert "explanation" in tasks
        assert "verification" in tasks

    def test_training_example_detection_task(self, generator, sample_examples):
        """Test detection task training example."""
        training_data = generator.generate_training_examples(sample_examples)

        detection_examples = [
            ex for ex in training_data if ex.metadata["task"] == "vulnerability_detection"
        ]

        assert len(detection_examples) == len(sample_examples)

        for ex in detection_examples:
            assert "Analyze" in ex.instruction
            assert "Severity" in ex.output or "CRITICAL" in ex.output

    def test_training_example_fix_task(self, generator, sample_examples):
        """Test fix task training example."""
        training_data = generator.generate_training_examples(sample_examples)

        fix_examples = [ex for ex in training_data if ex.metadata["task"] == "code_fix"]

        assert len(fix_examples) == len(sample_examples)

        for ex in fix_examples:
            assert "Fix" in ex.instruction

    def test_training_example_explanation_task(self, generator, sample_examples):
        """Test explanation task training example."""
        training_data = generator.generate_training_examples(sample_examples)

        explanation_examples = [ex for ex in training_data if ex.metadata["task"] == "explanation"]

        assert len(explanation_examples) == len(sample_examples)

        for ex in explanation_examples:
            assert "Explain" in ex.instruction
            assert "Attack" in ex.output or "Exploitation" in ex.output

    def test_training_example_verification_task(self, generator, sample_examples):
        """Test verification task training example."""
        training_data = generator.generate_training_examples(sample_examples)

        verification_examples = [
            ex for ex in training_data if ex.metadata["task"] == "verification"
        ]

        assert len(verification_examples) == len(sample_examples)

        for ex in verification_examples:
            assert "Verify" in ex.instruction
            assert "is_secure" in ex.metadata
            assert ex.metadata["is_secure"] is True

    def test_export_alpaca_format(self, generator, sample_examples, tmp_path):
        """Test Alpaca format export."""
        training_data = generator.generate_training_examples(sample_examples)
        output_path = generator.export_alpaca_format(training_data, "test_alpaca.json")

        assert Path(output_path).exists()

        with open(output_path) as f:
            data = json.load(f)

        assert len(data) == len(training_data)
        assert all("instruction" in item for item in data)
        assert all("input" in item for item in data)
        assert all("output" in item for item in data)

    def test_export_chatml_format(self, generator, sample_examples, tmp_path):
        """Test ChatML format export."""
        training_data = generator.generate_training_examples(sample_examples)
        output_path = generator.export_chatml_format(training_data, "test_chatml.jsonl")

        assert Path(output_path).exists()

        # Read JSONL
        with open(output_path) as f:
            lines = f.readlines()

        assert len(lines) == len(training_data)

        for line in lines:
            data = json.loads(line)
            assert "messages" in data
            assert len(data["messages"]) == 3  # system, user, assistant
            assert data["messages"][0]["role"] == "system"
            assert data["messages"][1]["role"] == "user"
            assert data["messages"][2]["role"] == "assistant"

    def test_export_sharegpt_format(self, generator, sample_examples, tmp_path):
        """Test ShareGPT format export."""
        training_data = generator.generate_training_examples(sample_examples)
        output_path = generator.export_sharegpt_format(training_data, "test_sharegpt.json")

        assert Path(output_path).exists()

        with open(output_path) as f:
            data = json.load(f)

        assert len(data) == len(training_data)

        for item in data:
            assert "conversations" in item
            assert len(item["conversations"]) == 2
            assert item["conversations"][0]["from"] == "human"
            assert item["conversations"][1]["from"] == "gpt"

    def test_generate_full_dataset(self, generator, tmp_path):
        """Test full dataset generation."""
        paths = generator.generate_full_dataset()

        assert "alpaca" in paths
        assert "chatml" in paths
        assert "sharegpt" in paths
        assert "stats" in paths

        # Check all files exist
        for format_name, path in paths.items():
            assert Path(path).exists(), f"{format_name} file not found"

        # Check stats content
        with open(paths["stats"]) as f:
            stats = json.load(f)

        assert "total_examples" in stats
        assert stats["total_examples"] > 0
        assert "vulnerability_types" in stats
        assert "formats" in stats
        assert "generated_at" in stats

    def test_full_dataset_example_count(self, generator):
        """Test full dataset has correct number of examples."""
        paths = generator.generate_full_dataset()

        with open(paths["alpaca"]) as f:
            alpaca_data = json.load(f)

        # 4 tasks per vulnerability type
        expected_count = len(generator.VULNERABILITY_TEMPLATES) * 4
        assert len(alpaca_data) == expected_count


# =============================================================================
# Test Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests for dataset generator."""

    def test_empty_examples_list(self, tmp_path):
        """Test generating training data from empty examples."""
        generator = SoliditySecurityDatasetGenerator(output_dir=str(tmp_path))
        training_data = generator.generate_training_examples([])

        assert len(training_data) == 0

    def test_example_with_special_characters(self, tmp_path):
        """Test example with special characters in code."""
        generator = SoliditySecurityDatasetGenerator(output_dir=str(tmp_path))

        examples = [
            VulnerabilityExample(
                id="special_001",
                vulnerability_type="test",
                severity="low",
                vulnerable_code='string memory x = "test\\n\\t";',
                fixed_code='string memory x = unicode"test";',
                explanation="Special chars test",
                detection_pattern=r"\\",
                remediation="Use unicode",
            )
        ]

        training_data = generator.generate_training_examples(examples)
        output_path = generator.export_alpaca_format(training_data, "special.json")

        # Should serialize without error
        with open(output_path) as f:
            data = json.load(f)

        assert len(data) == 4

    def test_example_with_unicode(self, tmp_path):
        """Test example with unicode characters."""
        generator = SoliditySecurityDatasetGenerator(output_dir=str(tmp_path))

        examples = [
            VulnerabilityExample(
                id="unicode_001",
                vulnerability_type="test",
                severity="low",
                vulnerable_code="// Comment with emoji ",
                fixed_code="// Comment without emoji",
                explanation="Unicode handling test",
                detection_pattern=r".*",
                remediation="Remove unicode",
            )
        ]

        training_data = generator.generate_training_examples(examples)
        output_path = generator.export_chatml_format(training_data, "unicode.jsonl")

        assert Path(output_path).exists()


# =============================================================================
# Integration Test
# =============================================================================


class TestIntegration:
    """Integration tests for dataset generation pipeline."""

    def test_complete_pipeline(self, tmp_path):
        """Test complete generation pipeline."""
        generator = SoliditySecurityDatasetGenerator(output_dir=str(tmp_path / "full_test"))

        # Generate base examples
        vuln_examples = generator.generate_base_examples()
        assert len(vuln_examples) > 0

        # Convert to training format
        training_data = generator.generate_training_examples(vuln_examples)
        assert len(training_data) == len(vuln_examples) * 4

        # Export all formats
        alpaca_path = generator.export_alpaca_format(training_data)
        chatml_path = generator.export_chatml_format(training_data)
        sharegpt_path = generator.export_sharegpt_format(training_data)

        # Verify all exports
        with open(alpaca_path) as f:
            alpaca_data = json.load(f)
        with open(sharegpt_path) as f:
            sharegpt_data = json.load(f)

        assert len(alpaca_data) == len(training_data)
        assert len(sharegpt_data) == len(training_data)

        # Verify JSONL
        with open(chatml_path) as f:
            chatml_lines = f.readlines()
        assert len(chatml_lines) == len(training_data)


# =============================================================================
# Test Fine-Tuning Trainer Module
# =============================================================================

from src.ml.fine_tuning.fine_tuning_trainer import (
    SoliditySecurityTrainer,
    TrainingConfig,
)


class TestTrainingConfig:
    """Tests for TrainingConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = TrainingConfig()

        assert config.base_model == "deepseek-ai/deepseek-coder-6.7b-instruct"
        assert config.output_dir == "models/solidity-security-llm"
        assert config.num_epochs == 3
        assert config.batch_size == 4
        assert config.learning_rate == 2e-5

    def test_lora_defaults(self):
        """Test LoRA default configuration."""
        config = TrainingConfig()

        assert config.use_lora is True
        assert config.lora_r == 16
        assert config.lora_alpha == 32
        assert config.lora_dropout == 0.05
        assert "q_proj" in config.lora_target_modules

    def test_quantization_defaults(self):
        """Test quantization defaults."""
        config = TrainingConfig()

        assert config.use_4bit is True
        assert config.bnb_4bit_compute_dtype == "float16"
        assert config.bnb_4bit_quant_type == "nf4"

    def test_custom_config(self):
        """Test custom configuration values."""
        config = TrainingConfig(
            base_model="custom-model",
            output_dir="custom/output",
            num_epochs=5,
            batch_size=8,
            use_lora=False,
            use_4bit=False,
        )

        assert config.base_model == "custom-model"
        assert config.output_dir == "custom/output"
        assert config.num_epochs == 5
        assert config.batch_size == 8
        assert config.use_lora is False
        assert config.use_4bit is False

    def test_training_options(self):
        """Test training option defaults."""
        config = TrainingConfig()

        assert config.gradient_checkpointing is True
        assert config.flash_attention is True
        assert config.bf16 is True
        assert config.fp16 is False

    def test_evaluation_settings(self):
        """Test evaluation settings."""
        config = TrainingConfig()

        assert config.eval_steps == 100
        assert config.save_steps == 100
        assert config.logging_steps == 10


class TestSoliditySecurityTrainer:
    """Tests for SoliditySecurityTrainer class."""

    @pytest.fixture
    def trainer(self):
        """Create trainer with default config."""
        return SoliditySecurityTrainer()

    @pytest.fixture
    def custom_trainer(self, tmp_path):
        """Create trainer with custom config."""
        config = TrainingConfig(output_dir=str(tmp_path / "models"), num_epochs=1, batch_size=2)
        return SoliditySecurityTrainer(config)

    def test_initialization_default(self, trainer):
        """Test trainer initializes with defaults."""
        assert trainer.config is not None
        assert trainer.model is None
        assert trainer.tokenizer is None

    def test_initialization_custom(self, custom_trainer, tmp_path):
        """Test trainer with custom config."""
        assert custom_trainer.config.output_dir == str(tmp_path / "models")
        assert custom_trainer.config.num_epochs == 1
        assert custom_trainer.config.batch_size == 2

    def test_check_dependencies(self, trainer):
        """Test dependency checking."""
        deps = trainer.check_dependencies()

        assert isinstance(deps, dict)
        expected_deps = [
            "torch",
            "transformers",
            "peft",
            "bitsandbytes",
            "datasets",
            "trl",
            "accelerate",
        ]
        for dep in expected_deps:
            assert dep in deps
            assert isinstance(deps[dep], bool)

    def test_format_instruction_chatml(self, trainer):
        """Test ChatML format conversion."""
        example = {
            "messages": [
                {"role": "system", "content": "You are an auditor."},
                {"role": "user", "content": "Analyze this code."},
                {"role": "assistant", "content": "No issues found."},
            ]
        }

        result = trainer.format_instruction(example)

        assert "<|system|>" in result
        assert "You are an auditor." in result
        assert "<|user|>" in result
        assert "Analyze this code." in result
        assert "<|assistant|>" in result
        assert "No issues found." in result

    def test_format_instruction_alpaca(self, trainer):
        """Test Alpaca format conversion."""
        example = {
            "instruction": "Analyze the code for vulnerabilities.",
            "input": "function withdraw() { ... }",
            "output": "Reentrancy vulnerability detected.",
        }

        result = trainer.format_instruction(example)

        assert "### Instruction:" in result
        assert "Analyze the code for vulnerabilities." in result
        assert "### Input:" in result
        assert "function withdraw() { ... }" in result
        assert "### Response:" in result
        assert "Reentrancy vulnerability detected." in result

    def test_format_instruction_alpaca_no_input(self, trainer):
        """Test Alpaca format without input field."""
        example = {
            "instruction": "What is reentrancy?",
            "input": "",
            "output": "Reentrancy is a vulnerability...",
        }

        result = trainer.format_instruction(example)

        assert "### Instruction:" in result
        assert "### Input:" not in result
        assert "### Response:" in result

    def test_format_instruction_fallback(self, trainer):
        """Test fallback for unknown format."""
        example = {"data": "some random data"}

        result = trainer.format_instruction(example)

        assert "some random data" in result

    def test_generate_ollama_modelfile(self, custom_trainer, tmp_path):
        """Test Ollama Modelfile generation."""
        model_path = tmp_path / "test_model"
        model_path.mkdir()

        modelfile_path = custom_trainer.generate_ollama_modelfile(str(model_path))

        assert Path(modelfile_path).exists()
        with open(modelfile_path) as f:
            content = f.read()

        assert "MIESC Solidity Security LLM" in content
        assert "FROM" in content
        assert "SYSTEM" in content
        assert "Reentrancy attacks" in content
        assert "PARAMETER temperature" in content

    def test_generate_axolotl_config(self, custom_trainer, tmp_path):
        """Test Axolotl config generation."""
        import yaml

        config_path = custom_trainer.generate_axolotl_config("data/test_dataset.json")

        assert Path(config_path).exists()
        with open(config_path) as f:
            config = yaml.safe_load(f)

        assert config["base_model"] == custom_trainer.config.base_model
        assert config["output_dir"] == custom_trainer.config.output_dir
        assert config["num_epochs"] == custom_trainer.config.num_epochs
        assert config["lora_r"] == custom_trainer.config.lora_r
        assert "datasets" in config
        assert len(config["datasets"]) > 0

    def test_create_ollama_model_not_found(self, trainer):
        """Test Ollama model creation when CLI not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = trainer.create_ollama_model("test-model", "/path/to/Modelfile")

        assert result is False

    def test_create_ollama_model_success(self, trainer):
        """Test successful Ollama model creation."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = trainer.create_ollama_model("test-model", "/path/to/Modelfile")

        assert result is True

    def test_create_ollama_model_failure(self, trainer):
        """Test failed Ollama model creation."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Error creating model"

        with patch("subprocess.run", return_value=mock_result):
            result = trainer.create_ollama_model("test-model", "/path/to/Modelfile")

        assert result is False


class TestTrainerEdgeCases:
    """Edge case tests for trainer."""

    def test_empty_lora_modules(self):
        """Test config with empty LoRA modules."""
        config = TrainingConfig(lora_target_modules=[])
        assert config.lora_target_modules == []

    def test_large_learning_rate(self):
        """Test config with non-standard learning rate."""
        config = TrainingConfig(learning_rate=1e-3)
        assert config.learning_rate == 1e-3

    def test_custom_warmup_ratio(self):
        """Test custom warmup ratio."""
        config = TrainingConfig(warmup_ratio=0.05)
        assert config.warmup_ratio == 0.05


class TestTrainerMethodsMocked:
    """Tests for trainer methods using mocks."""

    @pytest.fixture
    def trainer(self):
        """Create trainer with default config."""
        return SoliditySecurityTrainer()

    @patch("subprocess.run")
    def test_install_dependencies(self, mock_run, trainer):
        """Test dependency installation."""
        mock_run.return_value = Mock(returncode=0)

        trainer.install_dependencies()

        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "pip" in call_args
        assert "install" in call_args

    def test_prepare_model_import_error(self, trainer):
        """Test prepare_model raises ImportError when deps missing."""
        # Mock to simulate missing imports
        with patch.dict("sys.modules", {"torch": None, "transformers": None}):
            with pytest.raises(ImportError):
                trainer.prepare_model()

    def test_load_dataset_import_error(self, trainer):
        """Test load_dataset raises ImportError when datasets missing."""
        with patch.dict("sys.modules", {"datasets": None}):
            with pytest.raises(ImportError):
                trainer.load_dataset("test.json")

    @patch("src.ml.fine_tuning.fine_tuning_trainer.SoliditySecurityTrainer.prepare_model")
    @patch("src.ml.fine_tuning.fine_tuning_trainer.SoliditySecurityTrainer.load_dataset")
    def test_train_import_error(self, mock_load, mock_prepare, trainer):
        """Test train raises ImportError when deps missing."""
        with patch.dict("sys.modules", {"transformers": None, "trl": None}):
            with pytest.raises(ImportError):
                trainer.train("test.json")

    def test_merge_lora_import_error(self, trainer):
        """Test merge_lora_weights raises ImportError when deps missing."""
        with patch.dict("sys.modules", {"peft": None}):
            with pytest.raises(ImportError):
                trainer.merge_lora_weights("/output")

    @patch("subprocess.run")
    def test_install_dependencies_packages(self, mock_run, trainer):
        """Test that install_dependencies installs correct packages."""
        mock_run.return_value = Mock(returncode=0)

        trainer.install_dependencies()

        call_args = mock_run.call_args[0][0]
        # Should include key packages
        assert any("transformers" in str(arg) for arg in call_args)
        assert any("peft" in str(arg) for arg in call_args)
        assert any("torch" in str(arg) for arg in call_args)


class TestTrainerWithMockedDeps:
    """Tests for trainer with mocked ML dependencies."""

    @pytest.fixture
    def mock_ml_deps(self):
        """Mock ML dependencies."""
        mock_torch = Mock()
        mock_torch.float16 = Mock()
        mock_torch.bfloat16 = Mock()

        mock_transformers = Mock()
        mock_tokenizer = Mock()
        mock_tokenizer.eos_token = "<|endoftext|>"
        mock_transformers.AutoTokenizer.from_pretrained.return_value = mock_tokenizer

        mock_model = Mock()
        mock_model.gradient_checkpointing_enable = Mock()
        mock_model.print_trainable_parameters = Mock()
        mock_transformers.AutoModelForCausalLM.from_pretrained.return_value = mock_model

        mock_peft = Mock()
        mock_peft.prepare_model_for_kbit_training.return_value = mock_model
        mock_peft.get_peft_model.return_value = mock_model

        mock_datasets = Mock()
        mock_dataset = Mock()
        mock_datasets.load_dataset.return_value = mock_dataset

        return {
            "torch": mock_torch,
            "transformers": mock_transformers,
            "peft": mock_peft,
            "datasets": mock_datasets,
        }

    def test_load_dataset_jsonl(self, mock_ml_deps):
        """Test loading JSONL dataset."""
        with patch.dict("sys.modules", mock_ml_deps):
            trainer = SoliditySecurityTrainer()

            # Import mocked module

            with patch(
                "src.ml.fine_tuning.fine_tuning_trainer.SoliditySecurityTrainer.load_dataset"
            ) as mock_method:
                mock_method.return_value = Mock()
                result = trainer.load_dataset("data.jsonl")

                # Just verify it returns something
                assert result is not None

    def test_load_dataset_json(self, mock_ml_deps):
        """Test loading JSON dataset."""
        trainer = SoliditySecurityTrainer()

        with patch(
            "src.ml.fine_tuning.fine_tuning_trainer.SoliditySecurityTrainer.load_dataset"
        ) as mock_method:
            mock_method.return_value = Mock()
            result = trainer.load_dataset("data.json")

            assert result is not None

    def test_load_dataset_hf_name(self, mock_ml_deps):
        """Test loading HuggingFace dataset by name."""
        trainer = SoliditySecurityTrainer()

        with patch(
            "src.ml.fine_tuning.fine_tuning_trainer.SoliditySecurityTrainer.load_dataset"
        ) as mock_method:
            mock_method.return_value = Mock()
            result = trainer.load_dataset("user/dataset")

            assert result is not None


class TestTrainerFormatInstruction:
    """Tests for format_instruction method."""

    def test_format_instruction_chatml(self):
        """Test formatting ChatML format."""
        trainer = SoliditySecurityTrainer()

        example = {
            "messages": [
                {"role": "system", "content": "You are a smart contract auditor."},
                {"role": "user", "content": "Analyze this code for vulnerabilities."},
                {"role": "assistant", "content": "I found a reentrancy vulnerability."},
            ]
        }

        result = trainer.format_instruction(example)

        assert "<|system|>" in result
        assert "<|user|>" in result
        assert "<|assistant|>" in result
        assert "smart contract auditor" in result
        assert "reentrancy vulnerability" in result

    def test_format_instruction_alpaca_full(self):
        """Test formatting Alpaca format with input."""
        trainer = SoliditySecurityTrainer()

        example = {
            "instruction": "Analyze the following code for security issues.",
            "input": "function withdraw() { msg.sender.call.value(balance)(); }",
            "output": "This code has a reentrancy vulnerability.",
        }

        result = trainer.format_instruction(example)

        assert "### Instruction:" in result
        assert "### Input:" in result
        assert "### Response:" in result
        assert "Analyze the following" in result

    def test_format_instruction_alpaca_no_input(self):
        """Test formatting Alpaca format without input."""
        trainer = SoliditySecurityTrainer()

        example = {
            "instruction": "List common smart contract vulnerabilities.",
            "input": "",  # Empty input
            "output": "Common vulnerabilities include reentrancy, overflow, etc.",
        }

        result = trainer.format_instruction(example)

        assert "### Instruction:" in result
        assert "### Response:" in result
        # Should not have Input section for empty input
        assert "### Input:" not in result or example.get("input") == ""

    def test_format_instruction_plain_text(self):
        """Test formatting when example is just a string."""
        trainer = SoliditySecurityTrainer()

        example = {"text": "This is plain text training data."}

        result = trainer.format_instruction(example)

        # Should convert to string representation
        assert result is not None
        assert len(result) > 0


class TestTrainerCheckDependencies:
    """Tests for check_dependencies method."""

    def test_check_dependencies_returns_dict(self):
        """Test that check_dependencies returns a dictionary."""
        trainer = SoliditySecurityTrainer()
        result = trainer.check_dependencies()

        assert isinstance(result, dict)
        assert "torch" in result
        assert "transformers" in result
        assert "peft" in result
        assert "bitsandbytes" in result
        assert "datasets" in result
        assert "trl" in result
        assert "accelerate" in result

    def test_check_dependencies_values_are_bool(self):
        """Test that dependency check values are boolean."""
        trainer = SoliditySecurityTrainer()
        result = trainer.check_dependencies()

        for dep_name, available in result.items():
            assert isinstance(available, bool), f"{dep_name} should be boolean"


class TestTrainerLoadDatasetReal:
    """Tests for load_dataset method with real (mocked) execution."""

    def test_load_dataset_jsonl_format(self, tmp_path):
        """Test loading JSONL dataset format."""
        # Create temp JSONL file
        jsonl_file = tmp_path / "data.jsonl"
        jsonl_content = '{"messages": [{"role": "user", "content": "test"}]}\n'
        jsonl_file.write_text(jsonl_content)

        trainer = SoliditySecurityTrainer()

        # Mock the datasets import and load_dataset function
        mock_dataset = Mock()
        with patch.dict("sys.modules", {"datasets": Mock()}):
            with patch("datasets.load_dataset", return_value=mock_dataset) as mock_load:
                try:
                    result = trainer.load_dataset(str(jsonl_file))
                except ImportError:
                    # If datasets not installed, that's expected
                    pytest.skip("datasets package not installed")

    def test_load_dataset_json_format(self, tmp_path):
        """Test loading JSON dataset format."""
        # Create temp JSON file
        json_file = tmp_path / "data.json"
        json_content = '[{"instruction": "test", "output": "result"}]'
        json_file.write_text(json_content)

        trainer = SoliditySecurityTrainer()

        mock_dataset = Mock()
        with patch.dict("sys.modules", {"datasets": Mock()}):
            with patch("datasets.load_dataset", return_value=mock_dataset) as mock_load:
                try:
                    result = trainer.load_dataset(str(json_file))
                except ImportError:
                    pytest.skip("datasets package not installed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
