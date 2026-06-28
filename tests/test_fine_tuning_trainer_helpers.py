"""Tests for SoliditySecurityTrainer pure helpers (no torch/GPU).

The heavy paths (prepare_model/train/merge_lora) need the ML training stack and
are out of scope; these cover dependency checks, instruction formatting, and
config/Modelfile generation.
"""

from __future__ import annotations

from src.ml.fine_tuning.fine_tuning_trainer import SoliditySecurityTrainer, TrainingConfig


def _trainer():
    return SoliditySecurityTrainer()


class TestTrainingConfig:
    def test_defaults(self):
        cfg = TrainingConfig()
        assert cfg is not None

    def test_custom_config_used(self):
        cfg = TrainingConfig()
        t = SoliditySecurityTrainer(config=cfg)
        assert t.config is cfg


class TestDependencyCheck:
    def test_returns_bool_map(self):
        deps = _trainer().check_dependencies()
        assert isinstance(deps, dict)
        for key in ("torch", "transformers", "peft"):
            assert key in deps
            assert isinstance(deps[key], bool)


class TestFormatInstruction:
    def test_includes_input_and_output(self):
        t = _trainer()
        ex = {"instruction": "Find bugs", "input": "contract C {}", "output": "reentrancy"}
        out = t.format_instruction(ex)
        assert "contract C {}" in out
        assert "reentrancy" in out

    def test_chatml_format(self):
        t = _trainer()
        ex = {"messages": [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "usr"},
            {"role": "assistant", "content": "asst"},
        ]}
        out = t.format_instruction(ex)
        assert "<|system|>" in out and "<|user|>" in out and "<|assistant|>" in out

    def test_fallback_format(self):
        t = _trainer()
        out = t.format_instruction({"unknown_key": 1})
        assert isinstance(out, str)


class TestGeneration:
    def test_ollama_modelfile_written(self, tmp_path):
        t = _trainer()
        path = t.generate_ollama_modelfile(str(tmp_path))
        content = open(path).read()
        assert "FROM" in content

    def test_axolotl_config_returns_yaml_path(self, tmp_path):
        t = SoliditySecurityTrainer(config=TrainingConfig(output_dir=str(tmp_path)))
        path = t.generate_axolotl_config("data.jsonl")
        assert path.endswith(".yml")
