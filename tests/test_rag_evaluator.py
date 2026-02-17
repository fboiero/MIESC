"""
Tests for RAG Evaluator module.

Tests the RAG evaluation system for measuring effectiveness.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.evaluation.rag_evaluator import (
    RAGEvaluationResult,
    RAGEvaluator,
    RAGRetrievalResult,
    create_sample_ground_truth,
)
from src.evaluation.metrics import EvaluationMetrics, Finding


class TestRAGRetrievalResult:
    """Test RAGRetrievalResult dataclass."""

    def test_create_result(self):
        """Test creating retrieval result."""
        result = RAGRetrievalResult(
            query="reentrancy vulnerability",
            retrieved_docs=[
                {"swc_id": "SWC-107", "title": "Reentrancy", "score": 0.95},
                {"swc_id": "SWC-106", "title": "Unprotected", "score": 0.75},
            ],
            retrieval_time_ms=50.5,
            relevance_scores=[0.95, 0.75],
        )
        assert result.query == "reentrancy vulnerability"
        assert len(result.retrieved_docs) == 2
        assert result.retrieval_time_ms == 50.5

    def test_avg_relevance(self):
        """Test average relevance calculation."""
        result = RAGRetrievalResult(
            query="test",
            retrieved_docs=[],
            retrieval_time_ms=10.0,
            relevance_scores=[0.9, 0.8, 0.7],
        )
        assert abs(result.avg_relevance - 0.8) < 0.0001

    def test_avg_relevance_empty(self):
        """Test average relevance with no scores."""
        result = RAGRetrievalResult(
            query="test",
            retrieved_docs=[],
            retrieval_time_ms=10.0,
            relevance_scores=[],
        )
        assert result.avg_relevance == 0.0

    def test_top_relevance(self):
        """Test top relevance score."""
        result = RAGRetrievalResult(
            query="test",
            retrieved_docs=[],
            retrieval_time_ms=10.0,
            relevance_scores=[0.95, 0.8, 0.6],
        )
        assert result.top_relevance == 0.95

    def test_top_relevance_empty(self):
        """Test top relevance with no scores."""
        result = RAGRetrievalResult(
            query="test",
            retrieved_docs=[],
            retrieval_time_ms=10.0,
            relevance_scores=[],
        )
        assert result.top_relevance == 0.0


class TestRAGEvaluationResult:
    """Test RAGEvaluationResult dataclass."""

    @pytest.fixture
    def sample_metrics_with_rag(self):
        """Create sample metrics with RAG."""
        return EvaluationMetrics(
            true_positives=80,
            false_positives=10,
            false_negatives=20,
            precision=0.889,
            recall=0.8,
            f1_score=0.842,
            rag_enabled=True,
        )

    @pytest.fixture
    def sample_metrics_without_rag(self):
        """Create sample metrics without RAG."""
        return EvaluationMetrics(
            true_positives=60,
            false_positives=20,
            false_negatives=40,
            precision=0.75,
            recall=0.6,
            f1_score=0.667,
            rag_enabled=False,
        )

    def test_create_result(self, sample_metrics_with_rag, sample_metrics_without_rag):
        """Test creating evaluation result."""
        result = RAGEvaluationResult(
            metrics_with_rag=sample_metrics_with_rag,
            metrics_without_rag=sample_metrics_without_rag,
        )
        assert result.metrics_with_rag.true_positives == 80
        assert result.metrics_without_rag.true_positives == 60

    def test_default_values(self, sample_metrics_with_rag, sample_metrics_without_rag):
        """Test default values."""
        result = RAGEvaluationResult(
            metrics_with_rag=sample_metrics_with_rag,
            metrics_without_rag=sample_metrics_without_rag,
        )
        assert result.avg_retrieval_time_ms == 0.0
        assert result.total_retrievals == 0
        assert result.adapter_results == {}
        assert result.retrievals == []
        assert result.num_contracts == 0

    def test_comparison_computed(self, sample_metrics_with_rag, sample_metrics_without_rag):
        """Test comparison is computed on init."""
        result = RAGEvaluationResult(
            metrics_with_rag=sample_metrics_with_rag,
            metrics_without_rag=sample_metrics_without_rag,
        )
        # Check for actual keys used by compare_metrics
        assert "precision_change_pct" in result.comparison
        assert "recall_change_pct" in result.comparison

    def test_to_dict(self, sample_metrics_with_rag, sample_metrics_without_rag):
        """Test dictionary conversion."""
        result = RAGEvaluationResult(
            metrics_with_rag=sample_metrics_with_rag,
            metrics_without_rag=sample_metrics_without_rag,
            num_contracts=10,
            adapters_tested=["smartllm", "gptscan"],
            timestamp="2026-02-17 10:00:00",
        )
        d = result.to_dict()
        assert "summary" in d
        assert d["summary"]["num_contracts"] == 10
        assert d["summary"]["adapters_tested"] == ["smartllm", "gptscan"]
        assert "rag_metrics" in d
        assert "with_rag" in d
        assert "without_rag" in d
        assert "comparison" in d

    def test_save_to_file(self, sample_metrics_with_rag, sample_metrics_without_rag, tmp_path):
        """Test saving results to file."""
        result = RAGEvaluationResult(
            metrics_with_rag=sample_metrics_with_rag,
            metrics_without_rag=sample_metrics_without_rag,
        )
        filepath = tmp_path / "results.json"
        result.save_to_file(str(filepath))

        assert filepath.exists()
        with open(filepath) as f:
            data = json.load(f)
        assert "with_rag" in data


class TestRAGEvaluator:
    """Test RAGEvaluator class."""

    @pytest.fixture
    def evaluator(self, tmp_path):
        """Create evaluator instance."""
        return RAGEvaluator(
            ground_truth_dir=str(tmp_path),
            results_dir=str(tmp_path / "results"),
        )

    def test_init_default(self):
        """Test default initialization."""
        evaluator = RAGEvaluator()
        assert evaluator.ground_truth_dir is None
        assert evaluator.results_dir.exists()

    def test_init_creates_results_dir(self, tmp_path):
        """Test results directory creation."""
        results_dir = tmp_path / "new_results"
        evaluator = RAGEvaluator(results_dir=str(results_dir))
        assert results_dir.exists()

    def test_get_adapter_unknown(self, evaluator):
        """Test getting unknown adapter."""
        adapter = evaluator._get_adapter("unknown_adapter")
        assert adapter is None

    @patch("importlib.import_module")
    def test_get_adapter_import_error(self, mock_import, evaluator):
        """Test adapter import error handling."""
        mock_import.side_effect = ImportError("Module not found")
        adapter = evaluator._get_adapter("smartllm")
        assert adapter is None

    def test_parse_findings(self, evaluator):
        """Test parsing findings from result."""
        result = {
            "findings": [
                {
                    "id": "f1",
                    "swc_id": "SWC-107",
                    "title": "Reentrancy",
                    "severity": "HIGH",
                    "confidence": 0.9,
                },
                {
                    "swc": "SWC-105",
                    "name": "Unprotected",
                    "severity": "CRITICAL",
                },
            ]
        }
        findings = evaluator._parse_findings(result)

        assert len(findings) == 2
        assert findings[0].swc_id == "SWC-107"
        assert findings[0].title == "Reentrancy"
        assert findings[1].swc_id == "SWC-105"

    def test_parse_findings_empty(self, evaluator):
        """Test parsing empty findings."""
        result = {"findings": []}
        findings = evaluator._parse_findings(result)
        assert findings == []

    def test_parse_findings_no_key(self, evaluator):
        """Test parsing when findings key missing."""
        result = {}
        findings = evaluator._parse_findings(result)
        assert findings == []

    @patch.object(RAGEvaluator, "_get_embedding_rag")
    def test_evaluate_retrieval_quality_no_rag(self, mock_get_rag, evaluator):
        """Test retrieval quality when RAG unavailable."""
        mock_get_rag.return_value = None
        result = evaluator.evaluate_retrieval_quality(["test query"])
        assert "error" in result

    @patch.object(RAGEvaluator, "_get_embedding_rag")
    def test_evaluate_retrieval_quality_success(self, mock_get_rag, evaluator):
        """Test retrieval quality evaluation."""
        # Mock RAG
        mock_rag = MagicMock()
        mock_search_result = MagicMock()
        mock_search_result.similarity_score = 0.85
        mock_search_result.document.swc_id = "SWC-107"
        mock_search_result.document.title = "Reentrancy"
        mock_rag.search.return_value = [mock_search_result]
        mock_get_rag.return_value = mock_rag

        result = evaluator.evaluate_retrieval_quality(
            ["reentrancy vulnerability"],
            expected_swcs=[["SWC-107"]],
        )

        assert result["num_queries"] == 1
        assert "avg_retrieval_time_ms" in result
        assert "hit_rate" in result

    @patch.object(RAGEvaluator, "_get_embedding_rag")
    def test_evaluate_retrieval_quality_empty_queries(self, mock_get_rag, evaluator):
        """Test retrieval with empty queries."""
        mock_rag = MagicMock()
        mock_get_rag.return_value = mock_rag

        result = evaluator.evaluate_retrieval_quality([])

        assert result["num_queries"] == 0
        assert result["avg_retrieval_time_ms"] == 0

    @patch.object(RAGEvaluator, "_get_adapter")
    def test_evaluate_adapter_with_rag_no_adapter(self, mock_get_adapter, evaluator):
        """Test adapter evaluation when adapter unavailable."""
        mock_get_adapter.return_value = None
        ground_truth = [Finding(id="1", title="Test")]

        with_rag, without_rag = evaluator.evaluate_adapter_with_rag(
            "unknown", "/path/contract.sol", ground_truth
        )

        assert with_rag.true_positives == 0
        assert without_rag.true_positives == 0


class TestCreateSampleGroundTruth:
    """Test create_sample_ground_truth function."""

    def test_creates_samples(self):
        """Test sample creation."""
        samples = create_sample_ground_truth()
        assert len(samples) > 0
        assert all(isinstance(s, tuple) for s in samples)
        assert all(len(s) == 2 for s in samples)

    def test_sample_structure(self):
        """Test sample structure."""
        samples = create_sample_ground_truth()
        for contract_path, findings in samples:
            assert isinstance(contract_path, str)
            assert isinstance(findings, list)
            assert all(isinstance(f, Finding) for f in findings)

    def test_sample_has_reentrancy(self):
        """Test sample includes reentrancy example."""
        samples = create_sample_ground_truth()
        contract_names = [s[0] for s in samples]
        assert any("reentrancy" in name for name in contract_names)


class TestRAGEvaluatorIntegration:
    """Integration tests for RAGEvaluator."""

    @pytest.fixture
    def evaluator(self, tmp_path):
        """Create evaluator."""
        return RAGEvaluator(results_dir=str(tmp_path / "results"))

    @patch.object(RAGEvaluator, "_get_adapter")
    @patch.object(RAGEvaluator, "_parse_findings")
    def test_run_full_evaluation(self, mock_parse, mock_get_adapter, evaluator):
        """Test full evaluation run."""
        # Mock adapter
        mock_adapter = MagicMock()
        mock_adapter.analyze.return_value = {"findings": []}
        mock_get_adapter.return_value = mock_adapter
        mock_parse.return_value = []

        contracts = [("/path/contract1.sol", [Finding(id="1", title="Test")])]

        result = evaluator.run_full_evaluation(
            contracts,
            adapters=["smartllm"],
            timeout=60,
        )

        assert isinstance(result, RAGEvaluationResult)
        assert result.num_contracts == 1
        assert "smartllm" in result.adapters_tested

    @patch.object(RAGEvaluator, "_get_adapter")
    def test_run_full_evaluation_adapter_error(self, mock_get_adapter, evaluator):
        """Test full evaluation with adapter error."""
        mock_adapter = MagicMock()
        mock_adapter.analyze.side_effect = Exception("Analysis failed")
        mock_get_adapter.return_value = mock_adapter

        contracts = [("/path/contract.sol", [Finding(id="1", title="Test")])]

        # Should not raise, just log error
        result = evaluator.run_full_evaluation(contracts, adapters=["smartllm"])
        assert isinstance(result, RAGEvaluationResult)


class TestRAGEvaluatorEdgeCases:
    """Edge case tests."""

    def test_result_with_empty_metrics(self):
        """Test result with empty metrics."""
        result = RAGEvaluationResult(
            metrics_with_rag=EvaluationMetrics(),
            metrics_without_rag=EvaluationMetrics(),
        )
        d = result.to_dict()
        # Check for actual structure from to_dict
        assert "with_rag" in d
        assert isinstance(d["with_rag"], dict)

    def test_retrieval_result_long_query(self):
        """Test retrieval result with long query."""
        long_query = "x" * 200
        result = RAGRetrievalResult(
            query=long_query,
            retrieved_docs=[],
            retrieval_time_ms=10.0,
            relevance_scores=[],
        )
        assert len(result.query) == 200
