"""
RAG Evaluator for MIESC.

Evaluates the effectiveness of the Retrieval-Augmented Generation system
by comparing LLM analysis results with and without RAG context enrichment.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: February 2026
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .metrics import (
    EvaluationMetrics,
    Finding,
    compare_metrics,
    evaluate_findings,
)

logger = logging.getLogger(__name__)


@dataclass
class RAGRetrievalResult:
    """Result of a single RAG retrieval operation."""

    query: str
    retrieved_docs: List[Dict[str, Any]]
    retrieval_time_ms: float
    relevance_scores: List[float]

    @property
    def avg_relevance(self) -> float:
        """Average relevance score of retrieved documents."""
        if not self.relevance_scores:
            return 0.0
        return sum(self.relevance_scores) / len(self.relevance_scores)

    @property
    def top_relevance(self) -> float:
        """Relevance of the top retrieved document."""
        return self.relevance_scores[0] if self.relevance_scores else 0.0


@dataclass
class RAGEvaluationResult:
    """Complete result of RAG evaluation across multiple contracts."""

    # Core metrics
    metrics_with_rag: EvaluationMetrics
    metrics_without_rag: EvaluationMetrics

    # RAG-specific metrics
    avg_retrieval_time_ms: float = 0.0
    avg_context_relevance: float = 0.0
    total_retrievals: int = 0
    retrieval_hit_rate: float = 0.0  # % of retrievals that returned relevant docs

    # Per-adapter results
    adapter_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Individual retrievals
    retrievals: List[RAGRetrievalResult] = field(default_factory=list)

    # Comparison summary
    comparison: Dict[str, Any] = field(default_factory=dict)

    # Test configuration
    num_contracts: int = 0
    adapters_tested: List[str] = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self):
        """Compute comparison after initialization."""
        if self.metrics_with_rag and self.metrics_without_rag:
            self.comparison = compare_metrics(
                self.metrics_without_rag,
                self.metrics_with_rag
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": {
                "num_contracts": self.num_contracts,
                "adapters_tested": self.adapters_tested,
                "timestamp": self.timestamp,
            },
            "rag_metrics": {
                "avg_retrieval_time_ms": round(self.avg_retrieval_time_ms, 2),
                "avg_context_relevance": round(self.avg_context_relevance, 4),
                "total_retrievals": self.total_retrievals,
                "retrieval_hit_rate": round(self.retrieval_hit_rate, 4),
            },
            "with_rag": self.metrics_with_rag.to_dict() if self.metrics_with_rag else {},
            "without_rag": self.metrics_without_rag.to_dict() if self.metrics_without_rag else {},
            "comparison": self.comparison,
            "adapter_results": self.adapter_results,
        }

    def save_to_file(self, filepath: str) -> None:
        """Save results to JSON file."""
        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info(f"RAG evaluation results saved to {filepath}")


class RAGEvaluator:
    """
    Evaluator for RAG system effectiveness.

    Performs A/B testing between RAG-enabled and RAG-disabled analysis
    to measure the impact of retrieval-augmented generation.
    """

    def __init__(
        self,
        ground_truth_dir: Optional[str] = None,
        results_dir: Optional[str] = None,
    ):
        """
        Initialize RAG evaluator.

        Args:
            ground_truth_dir: Directory containing labeled contracts
            results_dir: Directory to save evaluation results
        """
        self.ground_truth_dir = Path(ground_truth_dir) if ground_truth_dir else None
        self.results_dir = Path(results_dir) if results_dir else Path("./evaluation_results")
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self._embedding_rag = None
        self._adapters: Dict[str, Any] = {}

    def _get_embedding_rag(self):
        """Lazy initialization of EmbeddingRAG."""
        if self._embedding_rag is None:
            try:
                from src.llm.embedding_rag import EmbeddingRAG
                self._embedding_rag = EmbeddingRAG()
            except ImportError:
                logger.warning("EmbeddingRAG not available")
        return self._embedding_rag

    def _get_adapter(self, adapter_name: str):
        """Get or create an adapter instance."""
        if adapter_name not in self._adapters:
            # Dynamic import based on adapter name
            adapter_map = {
                "smartllm": ("src.adapters.smartllm_adapter", "SmartLLMAdapter"),
                "gptscan": ("src.adapters.gptscan_adapter", "GPTScanAdapter"),
                "gptlens": ("src.adapters.gptlens_adapter", "GPTLensAdapter"),
                "llmbugscanner": ("src.adapters.llmbugscanner_adapter", "LLMBugScannerAdapter"),
                "llmsmartaudit": ("src.adapters.llmsmartaudit_adapter", "LLMSmartAuditAdapter"),
            }

            if adapter_name not in adapter_map:
                logger.error(f"Unknown adapter: {adapter_name}")
                return None

            module_name, class_name = adapter_map[adapter_name]
            try:
                import importlib
                module = importlib.import_module(module_name)
                adapter_class = getattr(module, class_name)
                self._adapters[adapter_name] = adapter_class()
            except ImportError as e:
                logger.error(f"Could not import {adapter_name}: {e}")
                return None

        return self._adapters.get(adapter_name)

    def evaluate_retrieval_quality(
        self,
        queries: List[str],
        expected_swcs: Optional[List[List[str]]] = None,
        k: int = 5,
    ) -> Dict[str, Any]:
        """
        Evaluate the quality of RAG retrieval.

        Args:
            queries: List of query strings (code snippets or vulnerability descriptions)
            expected_swcs: Optional list of expected SWC IDs for each query
            k: Number of results to retrieve per query

        Returns:
            Dictionary with retrieval quality metrics.
        """
        rag = self._get_embedding_rag()
        if not rag:
            return {"error": "EmbeddingRAG not available"}

        results = []
        total_time = 0.0
        hits = 0

        for i, query in enumerate(queries):
            start = time.time()
            search_results = rag.search(query, n_results=k)
            elapsed_ms = (time.time() - start) * 1000

            relevance_scores = [r.score for r in search_results]
            retrieved_swcs = [r.document.swc_id for r in search_results if r.document.swc_id]

            result = RAGRetrievalResult(
                query=query[:100] + "..." if len(query) > 100 else query,
                retrieved_docs=[
                    {
                        "swc_id": r.document.swc_id,
                        "title": r.document.title,
                        "score": r.score,
                    }
                    for r in search_results
                ],
                retrieval_time_ms=elapsed_ms,
                relevance_scores=relevance_scores,
            )
            results.append(result)
            total_time += elapsed_ms

            # Check if we got a hit (relevant document in top k)
            if expected_swcs and i < len(expected_swcs):
                if any(swc in retrieved_swcs for swc in expected_swcs[i]):
                    hits += 1
            elif relevance_scores and max(relevance_scores) > 0.5:
                hits += 1

        avg_time = total_time / len(queries) if queries else 0
        hit_rate = hits / len(queries) if queries else 0
        avg_top_relevance = (
            sum(r.top_relevance for r in results) / len(results) if results else 0
        )

        return {
            "num_queries": len(queries),
            "avg_retrieval_time_ms": round(avg_time, 2),
            "hit_rate": round(hit_rate, 4),
            "avg_top_relevance": round(avg_top_relevance, 4),
            "results": [
                {
                    "query": r.query,
                    "top_doc": r.retrieved_docs[0] if r.retrieved_docs else None,
                    "avg_relevance": round(r.avg_relevance, 4),
                    "time_ms": round(r.retrieval_time_ms, 2),
                }
                for r in results
            ],
        }

    def evaluate_adapter_with_rag(
        self,
        adapter_name: str,
        contract_path: str,
        ground_truth: List[Finding],
        timeout: int = 120,
    ) -> Tuple[EvaluationMetrics, EvaluationMetrics]:
        """
        Evaluate a single adapter with and without RAG.

        Args:
            adapter_name: Name of the adapter to test
            contract_path: Path to the Solidity contract
            ground_truth: List of known vulnerabilities
            timeout: Timeout for each analysis run

        Returns:
            Tuple of (metrics_with_rag, metrics_without_rag)
        """
        adapter = self._get_adapter(adapter_name)
        if not adapter:
            return EvaluationMetrics(), EvaluationMetrics()

        # Test with RAG enabled
        os.environ.pop("MIESC_DISABLE_RAG", None)
        start = time.time()
        result_with_rag = adapter.analyze(contract_path, timeout=timeout)
        time_with_rag = (time.time() - start) * 1000

        findings_with_rag = self._parse_findings(result_with_rag)
        metrics_with_rag = evaluate_findings(findings_with_rag, ground_truth)
        metrics_with_rag.rag_enabled = True
        metrics_with_rag.adapter_name = adapter_name
        metrics_with_rag.inference_time_ms = time_with_rag

        # Test with RAG disabled
        os.environ["MIESC_DISABLE_RAG"] = "1"
        start = time.time()
        result_without_rag = adapter.analyze(contract_path, timeout=timeout)
        time_without_rag = (time.time() - start) * 1000

        findings_without_rag = self._parse_findings(result_without_rag)
        metrics_without_rag = evaluate_findings(findings_without_rag, ground_truth)
        metrics_without_rag.rag_enabled = False
        metrics_without_rag.adapter_name = adapter_name
        metrics_without_rag.inference_time_ms = time_without_rag

        # Clean up
        os.environ.pop("MIESC_DISABLE_RAG", None)

        return metrics_with_rag, metrics_without_rag

    def _parse_findings(self, result: Dict[str, Any]) -> List[Finding]:
        """Parse adapter result into Finding objects."""
        findings = []

        raw_findings = result.get("findings", [])
        for i, f in enumerate(raw_findings):
            finding = Finding(
                id=f.get("id", f"finding-{i}"),
                swc_id=f.get("swc_id") or f.get("swc"),
                cwe_id=f.get("cwe_id") or f.get("cwe"),
                title=f.get("title", f.get("name", "")),
                severity=f.get("severity", "MEDIUM"),
                location=f.get("location"),
                confidence=f.get("confidence", 0.5),
            )
            findings.append(finding)

        return findings

    def run_full_evaluation(
        self,
        contracts: List[Tuple[str, List[Finding]]],
        adapters: Optional[List[str]] = None,
        timeout: int = 120,
    ) -> RAGEvaluationResult:
        """
        Run full RAG evaluation across multiple contracts and adapters.

        Args:
            contracts: List of (contract_path, ground_truth_findings) tuples
            adapters: List of adapter names to test (default: all LLM adapters)
            timeout: Timeout per analysis

        Returns:
            Complete RAGEvaluationResult with all metrics.
        """
        if adapters is None:
            adapters = ["smartllm", "gptscan", "llmsmartaudit"]

        # Aggregate metrics
        all_tp_with, all_fp_with, all_fn_with = 0, 0, 0
        all_tp_without, all_fp_without, all_fn_without = 0, 0, 0
        total_time_with, total_time_without = 0.0, 0.0

        adapter_results: Dict[str, Dict[str, Any]] = {}

        for adapter_name in adapters:
            logger.info(f"Evaluating adapter: {adapter_name}")
            adapter_results[adapter_name] = {
                "with_rag": {"tp": 0, "fp": 0, "fn": 0},
                "without_rag": {"tp": 0, "fp": 0, "fn": 0},
                "contracts_tested": 0,
            }

            for contract_path, ground_truth in contracts:
                try:
                    m_with, m_without = self.evaluate_adapter_with_rag(
                        adapter_name, contract_path, ground_truth, timeout
                    )

                    # Accumulate
                    all_tp_with += m_with.true_positives
                    all_fp_with += m_with.false_positives
                    all_fn_with += m_with.false_negatives
                    total_time_with += m_with.inference_time_ms

                    all_tp_without += m_without.true_positives
                    all_fp_without += m_without.false_positives
                    all_fn_without += m_without.false_negatives
                    total_time_without += m_without.inference_time_ms

                    # Per-adapter accumulation
                    adapter_results[adapter_name]["with_rag"]["tp"] += m_with.true_positives
                    adapter_results[adapter_name]["with_rag"]["fp"] += m_with.false_positives
                    adapter_results[adapter_name]["with_rag"]["fn"] += m_with.false_negatives
                    adapter_results[adapter_name]["without_rag"]["tp"] += m_without.true_positives
                    adapter_results[adapter_name]["without_rag"]["fp"] += m_without.false_positives
                    adapter_results[adapter_name]["without_rag"]["fn"] += m_without.false_negatives
                    adapter_results[adapter_name]["contracts_tested"] += 1

                except Exception as e:
                    logger.error(f"Error evaluating {adapter_name} on {contract_path}: {e}")

        # Compute final aggregated metrics
        from .metrics import compute_f1, compute_precision, compute_recall

        metrics_with_rag = EvaluationMetrics(
            true_positives=all_tp_with,
            false_positives=all_fp_with,
            false_negatives=all_fn_with,
            rag_enabled=True,
        )
        metrics_with_rag.precision = compute_precision(all_tp_with, all_fp_with)
        metrics_with_rag.recall = compute_recall(all_tp_with, all_fn_with)
        metrics_with_rag.f1_score = compute_f1(metrics_with_rag.precision, metrics_with_rag.recall)
        metrics_with_rag.inference_time_ms = total_time_with

        metrics_without_rag = EvaluationMetrics(
            true_positives=all_tp_without,
            false_positives=all_fp_without,
            false_negatives=all_fn_without,
            rag_enabled=False,
        )
        metrics_without_rag.precision = compute_precision(all_tp_without, all_fp_without)
        metrics_without_rag.recall = compute_recall(all_tp_without, all_fn_without)
        metrics_without_rag.f1_score = compute_f1(
            metrics_without_rag.precision, metrics_without_rag.recall
        )
        metrics_without_rag.inference_time_ms = total_time_without

        return RAGEvaluationResult(
            metrics_with_rag=metrics_with_rag,
            metrics_without_rag=metrics_without_rag,
            adapter_results=adapter_results,
            num_contracts=len(contracts),
            adapters_tested=adapters,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        )


def create_sample_ground_truth() -> List[Tuple[str, List[Finding]]]:
    """
    Create sample ground truth data for testing.

    Returns:
        List of (contract_path, findings) tuples.
    """
    # Example vulnerable contract patterns
    samples = [
        (
            "reentrancy_example.sol",
            [
                Finding(
                    id="gt-1",
                    swc_id="SWC-107",
                    title="Reentrancy",
                    severity="HIGH",
                    location={"line": 15, "function": "withdraw"},
                ),
            ],
        ),
        (
            "access_control_example.sol",
            [
                Finding(
                    id="gt-2",
                    swc_id="SWC-105",
                    title="Unprotected Ether Withdrawal",
                    severity="CRITICAL",
                    location={"line": 22, "function": "withdrawAll"},
                ),
            ],
        ),
    ]
    return samples


__all__ = [
    "RAGRetrievalResult",
    "RAGEvaluationResult",
    "RAGEvaluator",
    "create_sample_ground_truth",
]
