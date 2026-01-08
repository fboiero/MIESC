#!/usr/bin/env python3
"""
MIESC Benchmark Suite - Compare MIESC vs other security tools.

Runs benchmarks on public vulnerability datasets and compares:
- Detection accuracy (precision, recall, F1)
- Execution time
- False positive rates

Datasets used:
- SmartBugs Curated (https://github.com/smartbugs/smartbugs-curated)
- SWC Registry examples
- Custom MIESC test contracts

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-12-03
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core import get_ml_orchestrator, get_tool_discovery


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""

    tool: str
    contract: str
    vulnerability_type: str
    expected_findings: int
    actual_findings: int
    true_positives: int
    false_positives: int
    false_negatives: int
    execution_time_ms: float
    precision: float
    recall: float
    f1_score: float


@dataclass
class BenchmarkSummary:
    """Summary of all benchmark results for a tool."""

    tool: str
    total_contracts: int
    total_expected: int
    total_detected: int
    total_tp: int
    total_fp: int
    total_fn: int
    avg_precision: float
    avg_recall: float
    avg_f1: float
    avg_time_ms: float
    detection_rate: float


# =============================================================================
# Benchmark Dataset - Known Vulnerabilities
# =============================================================================

BENCHMARK_CONTRACTS = [
    {
        "name": "reentrancy_simple",
        "code": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0);
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success);
        balances[msg.sender] = 0;  // State update after external call
    }
}
""",
        "expected_vulnerabilities": ["reentrancy"],
        "expected_count": 1,
    },
    {
        "name": "unchecked_return",
        "code": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UncheckedReturn {
    function sendEther(address payable to) public {
        to.send(1 ether);  // Return value not checked
    }

    function callWithoutCheck(address to) public {
        to.call("");  // Return value ignored
    }
}
""",
        "expected_vulnerabilities": ["unchecked-return", "unchecked-call"],
        "expected_count": 2,
    },
    {
        "name": "access_control",
        "code": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControlMissing {
    address public owner;
    uint256 public secretValue;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address newOwner) public {
        owner = newOwner;  // No access control!
    }

    function setSecret(uint256 value) public {
        secretValue = value;  // Anyone can call
    }
}
""",
        "expected_vulnerabilities": ["missing-access-control", "unprotected-function"],
        "expected_count": 2,
    },
    {
        "name": "integer_overflow",
        "code": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;  // Pre-0.8.0 for overflow

contract IntegerOverflow {
    uint256 public count;

    function increment(uint256 amount) public {
        count += amount;  // Can overflow in Solidity < 0.8
    }

    function multiply(uint256 a, uint256 b) public pure returns (uint256) {
        return a * b;  // Can overflow
    }
}
""",
        "expected_vulnerabilities": ["integer-overflow", "arithmetic"],
        "expected_count": 2,
    },
    {
        "name": "timestamp_dependency",
        "code": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TimestampLottery {
    function play() public payable {
        require(msg.value == 1 ether);
        if (block.timestamp % 2 == 0) {
            payable(msg.sender).transfer(2 ether);
        }
    }

    function isLucky() public view returns (bool) {
        return block.number % 7 == 0;
    }
}
""",
        "expected_vulnerabilities": ["timestamp-dependency", "weak-randomness"],
        "expected_count": 2,
    },
    {
        "name": "delegatecall_injection",
        "code": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DelegatecallVuln {
    address public implementation;

    function setImplementation(address _impl) public {
        implementation = _impl;
    }

    function execute(bytes memory data) public {
        (bool success, ) = implementation.delegatecall(data);
        require(success);
    }
}
""",
        "expected_vulnerabilities": ["delegatecall", "controlled-delegatecall"],
        "expected_count": 1,
    },
    {
        "name": "safe_contract",
        "code": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeContract {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        balances[msg.sender] = 0;  // CEI pattern
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }

    function setOwner(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
""",
        "expected_vulnerabilities": [],
        "expected_count": 0,
    },
]


class MIESCBenchmark:
    """MIESC Benchmark Runner."""

    def __init__(self, output_dir: str = "benchmarks/results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.orchestrator = get_ml_orchestrator()
        self.discovery = get_tool_discovery()
        self.results: List[BenchmarkResult] = []

    def run_all_benchmarks(self, parallel: bool = False) -> Dict[str, Any]:
        """Run all benchmarks and return summary."""
        print("=" * 60)
        print("MIESC BENCHMARK SUITE")
        print("=" * 60)
        print(f"Contracts to test: {len(BENCHMARK_CONTRACTS)}")
        print(f"Mode: {'Parallel' if parallel else 'Sequential'}")
        print("=" * 60)

        start_time = time.time()

        if parallel:
            self._run_parallel()
        else:
            self._run_sequential()

        total_time = time.time() - start_time

        # Calculate summary
        summary = self._calculate_summary()
        summary["total_time_seconds"] = total_time
        summary["timestamp"] = datetime.now().isoformat()

        # Save results
        self._save_results(summary)

        return summary

    def _run_sequential(self):
        """Run benchmarks sequentially."""
        for i, contract in enumerate(BENCHMARK_CONTRACTS, 1):
            print(f"\n[{i}/{len(BENCHMARK_CONTRACTS)}] Testing: {contract['name']}")
            result = self._benchmark_contract(contract)
            self.results.append(result)
            print(f"  - Expected: {contract['expected_count']}, Found: {result.actual_findings}")
            print(f"  - Precision: {result.precision:.2f}, Recall: {result.recall:.2f}")
            print(f"  - Time: {result.execution_time_ms:.0f}ms")

    def _run_parallel(self):
        """Run benchmarks in parallel."""
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(self._benchmark_contract, c): c for c in BENCHMARK_CONTRACTS}

            for future in as_completed(futures):
                contract = futures[future]
                result = future.result()
                self.results.append(result)
                print(f"Completed: {contract['name']} - {result.actual_findings} findings")

    def _benchmark_contract(self, contract: Dict) -> BenchmarkResult:
        """Benchmark a single contract."""
        import tempfile

        # Write contract to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
            f.write(contract["code"])
            contract_path = f.name

        try:
            # Run MIESC analysis
            start = time.time()
            result = self.orchestrator.quick_scan(contract_path, timeout=60)
            exec_time = (time.time() - start) * 1000

            # Get findings
            findings = []
            if hasattr(result, "filtered_findings"):
                findings = result.filtered_findings
            elif hasattr(result, "findings"):
                findings = result.findings

            actual_count = len(findings)
            expected_count = contract["expected_count"]
            expected_vulns = set(contract["expected_vulnerabilities"])

            # Calculate metrics
            found_vulns = set()
            for f in findings:
                vuln_type = f.get("type", f.get("category", "")).lower()
                for expected in expected_vulns:
                    if expected.lower() in vuln_type or vuln_type in expected.lower():
                        found_vulns.add(expected)

            tp = len(found_vulns)
            fp = max(0, actual_count - tp)
            fn = max(0, expected_count - tp)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

            return BenchmarkResult(
                tool="miesc",
                contract=contract["name"],
                vulnerability_type=",".join(contract["expected_vulnerabilities"]) or "none",
                expected_findings=expected_count,
                actual_findings=actual_count,
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                execution_time_ms=exec_time,
                precision=precision,
                recall=recall,
                f1_score=f1,
            )

        finally:
            os.unlink(contract_path)

    def _calculate_summary(self) -> Dict[str, Any]:
        """Calculate summary statistics."""
        if not self.results:
            return {"error": "No results"}

        total_expected = sum(r.expected_findings for r in self.results)
        total_detected = sum(r.actual_findings for r in self.results)
        total_tp = sum(r.true_positives for r in self.results)
        total_fp = sum(r.false_positives for r in self.results)
        total_fn = sum(r.false_negatives for r in self.results)

        avg_precision = sum(r.precision for r in self.results) / len(self.results)
        avg_recall = sum(r.recall for r in self.results) / len(self.results)
        avg_f1 = sum(r.f1_score for r in self.results) / len(self.results)
        avg_time = sum(r.execution_time_ms for r in self.results) / len(self.results)

        detection_rate = total_tp / total_expected if total_expected > 0 else 0

        return {
            "tool": "MIESC v4.0.0",
            "total_contracts": len(self.results),
            "total_expected_vulnerabilities": total_expected,
            "total_detected": total_detected,
            "true_positives": total_tp,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "metrics": {
                "precision": round(avg_precision, 4),
                "recall": round(avg_recall, 4),
                "f1_score": round(avg_f1, 4),
                "detection_rate": round(detection_rate, 4),
                "fp_rate": round(total_fp / total_detected if total_detected > 0 else 0, 4),
            },
            "performance": {
                "avg_time_ms": round(avg_time, 2),
                "min_time_ms": round(min(r.execution_time_ms for r in self.results), 2),
                "max_time_ms": round(max(r.execution_time_ms for r in self.results), 2),
            },
            "per_contract_results": [asdict(r) for r in self.results],
        }

    def _save_results(self, summary: Dict[str, Any]):
        """Save benchmark results to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"benchmark_{timestamp}.json"

        with open(output_file, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"\nResults saved to: {output_file}")

        # Also save as latest
        latest_file = self.output_dir / "latest_benchmark.json"
        with open(latest_file, "w") as f:
            json.dump(summary, f, indent=2)


def main():
    """Run benchmark suite."""
    parser = argparse.ArgumentParser(description="MIESC Benchmark Suite")
    parser.add_argument("--parallel", action="store_true", help="Run in parallel")
    parser.add_argument("--output", default="benchmarks/results", help="Output directory")
    args = parser.parse_args()

    benchmark = MIESCBenchmark(output_dir=args.output)
    summary = benchmark.run_all_benchmarks(parallel=args.parallel)

    print("\n" + "=" * 60)
    print("BENCHMARK SUMMARY")
    print("=" * 60)
    print(f"Tool: {summary.get('tool', 'MIESC')}")
    print(f"Contracts Tested: {summary.get('total_contracts', 0)}")
    print("\nMetrics:")
    metrics = summary.get("metrics", {})
    print(f"  Precision: {metrics.get('precision', 0):.2%}")
    print(f"  Recall: {metrics.get('recall', 0):.2%}")
    print(f"  F1 Score: {metrics.get('f1_score', 0):.2%}")
    print(f"  Detection Rate: {metrics.get('detection_rate', 0):.2%}")
    print("\nPerformance:")
    perf = summary.get("performance", {})
    print(f"  Avg Time: {perf.get('avg_time_ms', 0):.0f}ms")
    print(f"  Min Time: {perf.get('min_time_ms', 0):.0f}ms")
    print(f"  Max Time: {perf.get('max_time_ms', 0):.0f}ms")
    print("=" * 60)


if __name__ == "__main__":
    main()
