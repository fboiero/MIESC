"""Tests for src.ml.fp_ml_classifier — Auditor-trained FP classifier."""

import json

import pytest

from src.ml.fp_ml_classifier import (
    KNOWN_TOOLS,
    AuditorFindingFeatures,
    AuditorTrainedFPClassifier,
    create_sample_dataset,
    extract_features,
)


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


class TestExtractFeatures:
    def test_severity_mapping(self):
        for sev, expected in [
            ("critical", 4),
            ("HIGH", 3),
            ("Medium", 2),
            ("low", 1),
            ("info", 0),
            ("informational", 0),
            ("unknown-severity", 0),
        ]:
            f = extract_features({"severity": sev}, "")
            assert f.severity_ord == expected

    def test_confidence_default(self):
        f = extract_features({}, "")
        assert f.confidence == 0.5

    def test_confidence_parsed(self):
        f = extract_features({"confidence": 0.9}, "")
        assert f.confidence == 0.9

    def test_confidence_invalid_falls_back(self):
        f = extract_features({"confidence": "not-a-number"}, "")
        assert f.confidence == 0.5

    def test_has_swc(self):
        f = extract_features({"swc_id": "SWC-107"}, "")
        assert f.has_swc == 1
        assert extract_features({}, "").has_swc == 0

    def test_tool_one_hot(self):
        f = extract_features({"tool": "slither"}, "")
        idx = KNOWN_TOOLS.index("slither")
        assert f.tool_onehot[idx] == 1
        # All others should be zero
        assert sum(f.tool_onehot) == 1

    def test_tool_unknown_all_zero(self):
        f = extract_features({"tool": "exotic-tool-xyz"}, "")
        assert sum(f.tool_onehot) == 0

    def test_context_length_buckets(self):
        assert extract_features({}, "").context_length_bucket == 0
        assert extract_features({}, "x" * 1500).context_length_bucket == 1
        assert extract_features({}, "x" * 5000).context_length_bucket == 2
        assert extract_features({}, "x" * 20000).context_length_bucket == 3

    def test_library_detection(self):
        ctx = "import openzeppelin/contracts/security/ReentrancyGuard.sol;"
        f = extract_features({}, ctx)
        assert f.has_library == 1

    def test_solidity_version_detection(self):
        ctx = "pragma solidity ^0.8.20;"
        f = extract_features({}, ctx)
        assert f.solidity_0_8_plus == 1

    def test_old_solidity_version(self):
        ctx = "pragma solidity ^0.6.0;"
        f = extract_features({}, ctx)
        assert f.solidity_0_8_plus == 0

    def test_to_vector_has_consistent_length(self):
        v1 = extract_features({"severity": "high", "tool": "slither"}, "").to_vector()
        v2 = extract_features({}, "").to_vector()
        assert len(v1) == len(v2)
        # 7 scalar features + len(KNOWN_TOOLS) one-hot
        assert len(v1) == 7 + len(KNOWN_TOOLS)


# ---------------------------------------------------------------------------
# Heuristic fallback
# ---------------------------------------------------------------------------


class TestHeuristicFallback:
    def test_high_severity_real_bug_scores_low(self):
        clf = AuditorTrainedFPClassifier()
        # Force no model so we exercise the heuristic path.
        clf.model = None
        finding = {
            "severity": "high",
            "confidence": 0.9,
            "swc_id": "SWC-107",
            "tool": "slither",
            "type": "reentrancy-eth",
        }
        prob = clf.predict_fp_probability(finding, "")
        assert 0.0 <= prob <= 1.0
        # High-confidence, high-severity, has SWC → should NOT be flagged as FP
        assert prob < 0.5

    def test_low_severity_noise_scores_high(self):
        clf = AuditorTrainedFPClassifier()
        clf.model = None
        finding = {
            "severity": "info",
            "confidence": 0.2,
            "tool": "slither",
            "type": "naming-convention",
        }
        prob = clf.predict_fp_probability(finding, "")
        assert prob > 0.5

    def test_heuristic_bounded(self):
        clf = AuditorTrainedFPClassifier()
        clf.model = None
        feats = AuditorFindingFeatures(
            severity_ord=0, confidence=0.0, has_swc=0, has_library=1, solidity_0_8_plus=1
        )
        # Accumulated flags should not exceed 1.0
        assert clf._heuristic_fp_probability(feats) <= 1.0


# ---------------------------------------------------------------------------
# Sample dataset generation
# ---------------------------------------------------------------------------


class TestSampleDataset:
    def test_creates_expected_count(self, tmp_path):
        out = tmp_path / "labels.jsonl"
        n = create_sample_dataset(out, n=20)
        assert n == 20
        assert out.exists()
        lines = [l for l in out.read_text().splitlines() if l.strip()]
        assert len(lines) == 20

    def test_sample_rows_parseable(self, tmp_path):
        out = tmp_path / "labels.jsonl"
        create_sample_dataset(out, n=10)
        for line in out.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            assert "finding" in row
            assert "context" in row
            assert "label" in row
            assert isinstance(row["label"], bool)

    def test_dataset_is_balanced(self, tmp_path):
        out = tmp_path / "labels.jsonl"
        create_sample_dataset(out, n=20)
        labels = [json.loads(l)["label"] for l in out.read_text().splitlines() if l.strip()]
        # Half true, half false (roughly)
        assert 8 <= sum(labels) <= 12


# ---------------------------------------------------------------------------
# Training + prediction (requires sklearn)
# ---------------------------------------------------------------------------


sklearn = pytest.importorskip("sklearn")


class TestTraining:
    def test_train_produces_metrics(self, tmp_path):
        data = tmp_path / "labels.jsonl"
        create_sample_dataset(data, n=40)

        clf = AuditorTrainedFPClassifier(model_path=tmp_path / "model.pkl")
        metrics = clf.train(str(data))

        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1" in metrics
        assert metrics["train_samples"] + metrics["test_samples"] == 40
        assert clf.is_trained()

    def test_train_rejects_tiny_datasets(self, tmp_path):
        tiny = tmp_path / "tiny.jsonl"
        tiny.write_text('{"finding":{},"context":"","label":true}\n')
        clf = AuditorTrainedFPClassifier(model_path=tmp_path / "m.pkl")
        with pytest.raises(ValueError, match="at least 10"):
            clf.train(str(tiny))

    def test_model_persistence_roundtrip(self, tmp_path):
        data = tmp_path / "labels.jsonl"
        create_sample_dataset(data, n=40)

        model_path = tmp_path / "model.pkl"
        clf1 = AuditorTrainedFPClassifier(model_path=model_path)
        clf1.train(str(data))

        clf2 = AuditorTrainedFPClassifier(model_path=model_path)
        assert clf2.is_trained()

        finding = {"severity": "info", "tool": "slither", "type": "naming-convention"}
        p1 = clf1.predict_fp_probability(finding, "")
        p2 = clf2.predict_fp_probability(finding, "")
        # Same model + same inputs → same prediction
        assert abs(p1 - p2) < 1e-6

    def test_prediction_is_probability(self, tmp_path):
        data = tmp_path / "labels.jsonl"
        create_sample_dataset(data, n=40)
        clf = AuditorTrainedFPClassifier(model_path=tmp_path / "m.pkl")
        clf.train(str(data))

        finding = {"severity": "high", "tool": "slither", "type": "reentrancy-eth"}
        p = clf.predict_fp_probability(finding, "pragma solidity ^0.8.20;")
        assert 0.0 <= p <= 1.0
