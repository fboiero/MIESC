"""Tests for SoliditySecurityDatasetGenerator (fine-tuning dataset builder).

Pure builders + full-dataset export to a temp dir; no external services.
"""

from __future__ import annotations

from miesc.ml.fine_tuning.dataset_generator import SoliditySecurityDatasetGenerator


def _gen(tmp_path):
    return SoliditySecurityDatasetGenerator(output_dir=str(tmp_path))


class TestBuilders:
    def test_base_examples(self, tmp_path):
        base = _gen(tmp_path).generate_base_examples()
        assert len(base) >= 5

    def test_severity_map(self, tmp_path):
        g = _gen(tmp_path)
        assert g._get_severity("reentrancy") == "critical"
        assert g._get_severity("totally_unknown") == "low"

    def test_detection_pattern_nonempty(self, tmp_path):
        assert len(_gen(tmp_path)._generate_detection_pattern("reentrancy")) > 0

    def test_remediation_nonempty(self, tmp_path):
        assert len(_gen(tmp_path)._generate_remediation("reentrancy")) > 0

    def test_training_examples_from_base(self, tmp_path):
        g = _gen(tmp_path)
        base = g.generate_base_examples()
        te = g.generate_training_examples(base)
        assert len(te) > 0


class TestFullDataset:
    def test_generate_full_dataset_writes_files(self, tmp_path):
        g = _gen(tmp_path)
        paths = g.generate_full_dataset()
        assert isinstance(paths, dict)
        assert len(paths) > 0
        # every reported path should exist on disk
        from pathlib import Path

        for p in paths.values():
            assert Path(p).exists()
