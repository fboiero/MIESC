#!/usr/bin/env python3
"""
RAG Evaluation Script for MIESC.

Evaluates the effectiveness of the RAG system by running A/B tests
comparing LLM analysis with and without RAG context enrichment.

Usage:
    python scripts/evaluate_rag.py --help
    python scripts/evaluate_rag.py retrieval --queries "reentrancy attack" "flash loan"
    python scripts/evaluate_rag.py benchmark --adapter smartllm --contract test.sol

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.evaluation import RAGEvaluator, EvaluationMetrics
from src.evaluation.metrics import Finding

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("rag_eval")


def evaluate_retrieval(args):
    """Evaluate RAG retrieval quality."""
    evaluator = RAGEvaluator()

    queries = args.queries
    if not queries:
        # Default test queries
        queries = [
            "function withdraw() external { msg.sender.call{value: balance}",
            "reentrancy vulnerability in withdraw function",
            "tx.origin authentication bypass",
            "unchecked external call return value",
            "integer overflow in token transfer",
            "flash loan attack vector",
            "oracle price manipulation",
            "delegatecall to untrusted contract",
        ]

    logger.info(f"Evaluating {len(queries)} queries...")

    results = evaluator.evaluate_retrieval_quality(
        queries=queries,
        k=args.top_k
    )

    print("\n" + "=" * 60)
    print("RAG RETRIEVAL EVALUATION RESULTS")
    print("=" * 60)

    print(f"\nQueries evaluated: {results['num_queries']}")
    print(f"Average retrieval time: {results['avg_retrieval_time_ms']:.2f} ms")
    print(f"Hit rate (relevant in top-{args.top_k}): {results['hit_rate'] * 100:.1f}%")
    print(f"Average top relevance score: {results['avg_top_relevance']:.4f}")

    print("\n" + "-" * 60)
    print("Per-Query Results:")
    print("-" * 60)

    for r in results["results"]:
        print(f"\nQuery: {r['query']}")
        if r["top_doc"]:
            print(f"  Top match: {r['top_doc']['swc_id']} - {r['top_doc']['title']}")
            print(f"  Score: {r['top_doc']['score']:.4f}")
        print(f"  Avg relevance: {r['avg_relevance']:.4f}")
        print(f"  Time: {r['time_ms']:.2f} ms")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {args.output}")


def run_benchmark(args):
    """Run A/B benchmark comparing RAG vs no-RAG."""
    evaluator = RAGEvaluator(results_dir=args.output_dir)

    # Load or create ground truth
    ground_truth = []
    if args.ground_truth:
        with open(args.ground_truth) as f:
            gt_data = json.load(f)
            for item in gt_data.get("findings", []):
                ground_truth.append(Finding(
                    id=item.get("id", ""),
                    swc_id=item.get("swc_id"),
                    title=item.get("title", ""),
                    severity=item.get("severity", "MEDIUM"),
                    location=item.get("location"),
                ))
    else:
        # Example ground truth for common vulnerabilities
        logger.warning("No ground truth provided, using example data")
        ground_truth = [
            Finding(id="example-1", swc_id="SWC-107", title="Reentrancy", severity="HIGH"),
        ]

    contracts = [(args.contract, ground_truth)]
    adapters = [args.adapter] if args.adapter else ["smartllm", "gptscan"]

    logger.info(f"Running benchmark with adapters: {adapters}")
    logger.info(f"Contract: {args.contract}")

    results = evaluator.run_full_evaluation(
        contracts=contracts,
        adapters=adapters,
        timeout=args.timeout,
    )

    print_benchmark_results(results)

    # Save results
    output_file = Path(args.output_dir) / f"rag_benchmark_{results.timestamp.replace(' ', '_').replace(':', '-')}.json"
    results.save_to_file(str(output_file))


def print_benchmark_results(results):
    """Print benchmark results in a formatted way."""
    print("\n" + "=" * 70)
    print("RAG BENCHMARK RESULTS")
    print("=" * 70)

    print(f"\nContracts tested: {results.num_contracts}")
    print(f"Adapters tested: {', '.join(results.adapters_tested)}")
    print(f"Timestamp: {results.timestamp}")

    print("\n" + "-" * 70)
    print("COMPARISON: WITH RAG vs WITHOUT RAG")
    print("-" * 70)

    m_with = results.metrics_with_rag
    m_without = results.metrics_without_rag

    print(f"\n{'Metric':<25} {'Without RAG':<15} {'With RAG':<15} {'Change':<15}")
    print("-" * 70)

    def fmt_change(val):
        if val > 0:
            return f"+{val:.1f}%"
        elif val < 0:
            return f"{val:.1f}%"
        return "0%"

    comparison = results.comparison

    print(f"{'Precision':<25} {m_without.precision:.4f}{'':<9} {m_with.precision:.4f}{'':<9} {fmt_change(comparison.get('precision_change_pct', 0))}")
    print(f"{'Recall':<25} {m_without.recall:.4f}{'':<9} {m_with.recall:.4f}{'':<9} {fmt_change(comparison.get('recall_change_pct', 0))}")
    print(f"{'F1 Score':<25} {m_without.f1_score:.4f}{'':<9} {m_with.f1_score:.4f}{'':<9} {fmt_change(comparison.get('f1_change_pct', 0))}")
    print(f"{'True Positives':<25} {m_without.true_positives:<15} {m_with.true_positives:<15}")
    print(f"{'False Positives':<25} {m_without.false_positives:<15} {m_with.false_positives:<15} {comparison.get('fp_reduction', 0):+d}")
    print(f"{'False Negatives':<25} {m_without.false_negatives:<15} {m_with.false_negatives:<15} {comparison.get('fn_reduction', 0):+d}")
    print(f"{'Inference Time (ms)':<25} {m_without.inference_time_ms:.0f}{'':<12} {m_with.inference_time_ms:.0f}")

    print("\n" + "-" * 70)
    print("RECOMMENDATION")
    print("-" * 70)
    print(f"\n{comparison.get('recommendation', 'No recommendation available')}")

    if results.adapter_results:
        print("\n" + "-" * 70)
        print("PER-ADAPTER BREAKDOWN")
        print("-" * 70)

        for adapter, data in results.adapter_results.items():
            print(f"\n{adapter}:")
            print(f"  Contracts tested: {data['contracts_tested']}")
            print(f"  With RAG:    TP={data['with_rag']['tp']}, FP={data['with_rag']['fp']}, FN={data['with_rag']['fn']}")
            print(f"  Without RAG: TP={data['without_rag']['tp']}, FP={data['without_rag']['fp']}, FN={data['without_rag']['fn']}")


def show_architecture(args):
    """Display RAG architecture information."""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         MIESC LLM & RAG Architecture                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  ┌──────────────┐                                                            ║
║  │ Contract.sol │                                                            ║
║  └──────┬───────┘                                                            ║
║         │                                                                    ║
║         ▼                                                                    ║
║  ┌──────────────────────────────────────────────────────────────────────┐   ║
║  │                        LLM ADAPTER LAYER                              │   ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐    │   ║
║  │  │ SmartLLM │ │ GPTLens  │ │ GPTScan  │ │BugScanner│ │SmartAudit│    │   ║
║  │  │  (RAG✓)  │ │  (RAG-)  │ │  (RAG✓)  │ │  (RAG✓)  │ │  (RAG✓)  │    │   ║
║  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘    │   ║
║  └───────┼────────────┼────────────┼────────────┼────────────┼──────────┘   ║
║          │            │            │            │            │              ║
║          └────────────┴────────────┼────────────┴────────────┘              ║
║                                    ▼                                        ║
║  ┌──────────────────────────────────────────────────────────────────────┐   ║
║  │                      RAG ENRICHMENT LAYER                             │   ║
║  │                                                                       │   ║
║  │  ┌─────────────────────────┐    ┌─────────────────────────┐          │   ║
║  │  │     EmbeddingRAG        │    │      HybridRAG          │          │   ║
║  │  │  ┌─────────────────┐    │    │  (Embedding + BM25)     │          │   ║
║  │  │  │  ChromaDB       │    │    │                         │          │   ║
║  │  │  │  (Vector Store) │    │    │  70% semantic           │          │   ║
║  │  │  └─────────────────┘    │    │  30% lexical            │          │   ║
║  │  │  ┌─────────────────┐    │    │                         │          │   ║
║  │  │  │ all-MiniLM-L6-v2│    │    └─────────────────────────┘          │   ║
║  │  │  │ (384-dim embed) │    │                                         │   ║
║  │  │  └─────────────────┘    │                                         │   ║
║  │  └─────────────────────────┘                                         │   ║
║  └──────────────────────────────────────────────────────────────────────┘   ║
║                                    │                                        ║
║                                    ▼                                        ║
║  ┌──────────────────────────────────────────────────────────────────────┐   ║
║  │                    VULNERABILITY KNOWLEDGE BASE                       │   ║
║  │                                                                       │   ║
║  │  30+ Patterns: SWC-107, SWC-105, SWC-115, Flash Loan, Oracle...      │   ║
║  │  Each pattern contains: title, description, vulnerable_code,          │   ║
║  │  fixed_code, attack_scenario, severity, real_exploit_refs            │   ║
║  └──────────────────────────────────────────────────────────────────────┘   ║
║                                    │                                        ║
║                                    ▼                                        ║
║  ┌──────────────────────────────────────────────────────────────────────┐   ║
║  │                       LLM BACKEND LAYER                               │   ║
║  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                   │   ║
║  │  │   Ollama    │  │   OpenAI    │  │  Anthropic  │                   │   ║
║  │  │  (local)    │  │   (cloud)   │  │   (cloud)   │                   │   ║
║  │  └─────────────┘  └─────────────┘  └─────────────┘                   │   ║
║  └──────────────────────────────────────────────────────────────────────┘   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

RAG INTEGRATION STATUS BY ADAPTER:
  ✓ SmartLLM      - EmbeddingRAG + Keyword RAG (smartllm_rag_knowledge)
  ✓ GPTScan       - EmbeddingRAG (optional, graceful fallback)
  ✓ LLMSmartAudit - EmbeddingRAG (optional, graceful fallback)
  ✓ LLMBugScanner - EmbeddingRAG (optional, graceful fallback)
  ✓ PropertyGPT   - EmbeddingRAG (optional, graceful fallback)
  - GPTLens       - Pattern-based only (no semantic RAG)
  - LlamaAudit    - Keyword RAG only (SWC mapping)

KEY METRICS TO MEASURE:
  1. Retrieval Quality: Hit rate, MRR, NDCG
  2. Detection Quality: Precision, Recall, F1
  3. RAG Impact: F1 improvement, FP reduction, latency overhead

COMMANDS:
  evaluate_rag.py retrieval  - Test RAG retrieval quality
  evaluate_rag.py benchmark  - Run A/B test (RAG vs no-RAG)
  evaluate_rag.py arch       - Show this architecture diagram
""")


def main():
    parser = argparse.ArgumentParser(
        description="RAG Evaluation for MIESC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s retrieval --queries "reentrancy" "flash loan"
  %(prog)s benchmark --adapter smartllm --contract test.sol
  %(prog)s arch
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Retrieval evaluation
    retrieval_parser = subparsers.add_parser(
        "retrieval",
        help="Evaluate RAG retrieval quality"
    )
    retrieval_parser.add_argument(
        "--queries", "-q",
        nargs="+",
        help="Query strings to test (default: use sample queries)"
    )
    retrieval_parser.add_argument(
        "--top-k", "-k",
        type=int,
        default=5,
        help="Number of results to retrieve per query (default: 5)"
    )
    retrieval_parser.add_argument(
        "--output", "-o",
        help="Output file for results (JSON)"
    )

    # Benchmark evaluation
    benchmark_parser = subparsers.add_parser(
        "benchmark",
        help="Run A/B benchmark (RAG vs no-RAG)"
    )
    benchmark_parser.add_argument(
        "--contract", "-c",
        required=True,
        help="Path to Solidity contract to analyze"
    )
    benchmark_parser.add_argument(
        "--adapter", "-a",
        help="Adapter to test (default: smartllm, gptscan)"
    )
    benchmark_parser.add_argument(
        "--ground-truth", "-g",
        help="Path to ground truth JSON file"
    )
    benchmark_parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=120,
        help="Timeout per analysis (seconds, default: 120)"
    )
    benchmark_parser.add_argument(
        "--output-dir", "-o",
        default="./evaluation_results",
        help="Directory for output files"
    )

    # Architecture display
    arch_parser = subparsers.add_parser(
        "arch",
        help="Display RAG architecture diagram"
    )

    args = parser.parse_args()

    if args.command == "retrieval":
        evaluate_retrieval(args)
    elif args.command == "benchmark":
        run_benchmark(args)
    elif args.command == "arch":
        show_architecture(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
