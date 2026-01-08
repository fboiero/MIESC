#!/usr/bin/env python3
"""
MIESC v4.1 - Scalability Benchmark

Measures performance across different workloads:
- Single contract analysis time
- Batch processing throughput
- Memory usage
- Parallel execution efficiency

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import psutil

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

RESULTS_PATH = PROJECT_ROOT / "benchmarks" / "results"


@dataclass
class BenchmarkResult:
    """Results from a benchmark run."""

    benchmark_name: str
    contracts_analyzed: int
    total_time_seconds: float
    avg_time_per_contract: float
    throughput_contracts_per_minute: float
    memory_peak_mb: float
    cpu_percent: float
    parallel_workers: int
    errors: int
    timestamp: str


def get_sample_contracts(count: int = 10) -> List[Path]:
    """Get sample contracts from SmartBugs dataset."""
    dataset_path = PROJECT_ROOT / "benchmarks" / "datasets" / "smartbugs-curated" / "dataset"

    contracts = []
    for category in dataset_path.iterdir():
        if category.is_dir():
            for sol_file in category.glob("*.sol"):
                contracts.append(sol_file)
                if len(contracts) >= count:
                    return contracts

    return contracts


def generate_synthetic_contracts(count: int, complexity: str = "medium") -> List[Path]:
    """Generate synthetic contracts for stress testing."""
    contracts = []
    temp_dir = Path(tempfile.mkdtemp(prefix="miesc_bench_"))

    # Template based on complexity
    templates = {
        "simple": """
pragma solidity ^0.8.0;

contract SimpleContract{n} {{
    uint256 public value;

    function setValue(uint256 _value) public {{
        value = _value;
    }}

    function getValue() public view returns (uint256) {{
        return value;
    }}
}}
""",
        "medium": """
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

contract MediumContract{n} is Ownable {{
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() Ownable(msg.sender) {{
        totalSupply = 1000000;
        balances[msg.sender] = totalSupply;
    }}

    function transfer(address to, uint256 amount) public {{
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
    }}

    function withdraw() public onlyOwner {{
        payable(owner()).transfer(address(this).balance);
    }}
}}
""",
        "complex": """
pragma solidity ^0.8.0;

interface IUniswapV2Router02 {{
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
}}

contract ComplexContract{n} {{
    IUniswapV2Router02 public router;
    mapping(address => mapping(address => uint256)) public allowances;
    mapping(address => uint256) public balances;

    event Swap(address indexed user, uint256 amountIn, uint256 amountOut);
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    modifier nonReentrant() {{
        require(!locked, "No reentrancy");
        locked = true;
        _;
        locked = false;
    }}

    bool private locked;

    constructor(address _router) {{
        router = IUniswapV2Router02(_router);
    }}

    function deposit() external payable nonReentrant {{
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }}

    function withdraw(uint256 amount) external nonReentrant {{
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success,) = payable(msg.sender).call{{value: amount}}("");
        require(success, "Transfer failed");
        emit Withdraw(msg.sender, amount);
    }}

    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minOut
    ) external nonReentrant {{
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;

        uint[] memory amounts = router.swapExactTokensForTokens(
            amountIn,
            minOut,
            path,
            msg.sender,
            block.timestamp + 300
        );

        emit Swap(msg.sender, amountIn, amounts[1]);
    }}

    receive() external payable {{
        balances[msg.sender] += msg.value;
    }}
}}
""",
    }

    template = templates.get(complexity, templates["medium"])

    for i in range(count):
        contract_content = template.replace("{n}", str(i))
        contract_path = temp_dir / f"Contract{i}.sol"
        contract_path.write_text(contract_content)
        contracts.append(contract_path)

    return contracts


def analyze_contract_slither(contract_path: Path, timeout: int = 60) -> Dict:
    """Analyze a contract with Slither."""
    start_time = time.time()

    try:
        result = subprocess.run(
            ["slither", str(contract_path), "--json", "-"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        elapsed = time.time() - start_time

        if result.stdout:
            try:
                data = json.loads(result.stdout)
                findings = len(data.get("results", {}).get("detectors", []))
            except json.JSONDecodeError:
                findings = 0
        else:
            findings = 0

        return {"success": True, "time": elapsed, "findings": findings, "error": None}

    except subprocess.TimeoutExpired:
        return {"success": False, "time": timeout, "findings": 0, "error": "Timeout"}
    except Exception as e:
        return {"success": False, "time": time.time() - start_time, "findings": 0, "error": str(e)}


def run_sequential_benchmark(contracts: List[Path], name: str = "sequential") -> BenchmarkResult:
    """Run benchmark sequentially."""
    print(f"\n[Sequential] Analyzing {len(contracts)} contracts...")

    process = psutil.Process()
    start_memory = process.memory_info().rss / 1024 / 1024  # MB
    start_time = time.time()

    results = []
    for i, contract in enumerate(contracts):
        result = analyze_contract_slither(contract)
        results.append(result)

        if (i + 1) % 10 == 0:
            print(f"  Progress: {i+1}/{len(contracts)}")

    total_time = time.time() - start_time
    peak_memory = process.memory_info().rss / 1024 / 1024

    successful = sum(1 for r in results if r["success"])
    errors = len(results) - successful

    return BenchmarkResult(
        benchmark_name=name,
        contracts_analyzed=len(contracts),
        total_time_seconds=round(total_time, 2),
        avg_time_per_contract=round(total_time / len(contracts), 3),
        throughput_contracts_per_minute=round(len(contracts) / total_time * 60, 1),
        memory_peak_mb=round(peak_memory - start_memory, 1),
        cpu_percent=psutil.cpu_percent(),
        parallel_workers=1,
        errors=errors,
        timestamp=datetime.now().isoformat(),
    )


def run_parallel_benchmark(
    contracts: List[Path], workers: int = 4, name: str = "parallel"
) -> BenchmarkResult:
    """Run benchmark with parallel execution."""
    print(f"\n[Parallel] Analyzing {len(contracts)} contracts with {workers} workers...")

    process = psutil.Process()
    start_memory = process.memory_info().rss / 1024 / 1024
    start_time = time.time()

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(analyze_contract_slither, c): c for c in contracts}
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            results.append(result)

            if (i + 1) % 10 == 0:
                print(f"  Progress: {i+1}/{len(contracts)}")

    total_time = time.time() - start_time
    peak_memory = process.memory_info().rss / 1024 / 1024

    successful = sum(1 for r in results if r["success"])
    errors = len(results) - successful

    return BenchmarkResult(
        benchmark_name=name,
        contracts_analyzed=len(contracts),
        total_time_seconds=round(total_time, 2),
        avg_time_per_contract=round(total_time / len(contracts), 3),
        throughput_contracts_per_minute=round(len(contracts) / total_time * 60, 1),
        memory_peak_mb=round(peak_memory - start_memory, 1),
        cpu_percent=psutil.cpu_percent(),
        parallel_workers=workers,
        errors=errors,
        timestamp=datetime.now().isoformat(),
    )


def run_full_benchmark():
    """Run complete scalability benchmark suite."""
    print("\n" + "=" * 70)
    print("  MIESC v4.1 - Scalability Benchmark")
    print("=" * 70)

    results = []

    # Temporarily rename foundry.toml to avoid Foundry interference
    foundry_toml = PROJECT_ROOT / "foundry.toml"
    foundry_backup = PROJECT_ROOT / "foundry.toml.bak"
    if foundry_toml.exists():
        foundry_toml.rename(foundry_backup)

    try:
        # Get sample contracts
        print("\n[1/4] Loading SmartBugs contracts...")
        contracts = get_sample_contracts(50)
        print(f"      Loaded {len(contracts)} contracts")

        # Benchmark 1: Sequential (small)
        print("\n[2/4] Running sequential benchmark...")
        result = run_sequential_benchmark(contracts[:20], "sequential_small")
        results.append(result)
        print(f"      Completed: {result.throughput_contracts_per_minute} contracts/min")

        # Benchmark 2: Parallel 2 workers
        print("\n[3/4] Running parallel benchmark (2 workers)...")
        result = run_parallel_benchmark(contracts[:20], workers=2, name="parallel_2")
        results.append(result)
        print(f"      Completed: {result.throughput_contracts_per_minute} contracts/min")

        # Benchmark 3: Parallel 4 workers
        print("\n[4/4] Running parallel benchmark (4 workers)...")
        result = run_parallel_benchmark(contracts[:20], workers=4, name="parallel_4")
        results.append(result)
        print(f"      Completed: {result.throughput_contracts_per_minute} contracts/min")

    finally:
        # Restore foundry.toml
        if foundry_backup.exists():
            foundry_backup.rename(foundry_toml)

    # Generate report
    generate_report(results)

    return results


def generate_report(results: List[BenchmarkResult]):
    """Generate benchmark report."""
    print("\n" + "=" * 70)
    print("  BENCHMARK RESULTS")
    print("=" * 70)

    print(
        f"\n{'Benchmark':<20} {'Contracts':>10} {'Time(s)':>10} {'Throughput':>15} {'Memory(MB)':>12} {'Workers':>8}"
    )
    print("-" * 78)

    for r in results:
        print(
            f"{r.benchmark_name:<20} {r.contracts_analyzed:>10} {r.total_time_seconds:>10.1f} "
            f"{r.throughput_contracts_per_minute:>12.1f}/min {r.memory_peak_mb:>12.1f} {r.parallel_workers:>8}"
        )

    print("-" * 78)

    # Calculate speedup
    if len(results) >= 2:
        sequential = results[0]
        parallel = results[-1]
        speedup = sequential.avg_time_per_contract / parallel.avg_time_per_contract
        print(f"\nParallel Speedup: {speedup:.2f}x")

    # Save results
    RESULTS_PATH.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = RESULTS_PATH / f"scalability_benchmark_{timestamp}.json"

    with open(report_file, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)

    print(f"\nResults saved: {report_file}")

    # Generate summary markdown
    summary_file = RESULTS_PATH / f"SCALABILITY_REPORT_{timestamp}.md"
    with open(summary_file, "w") as f:
        f.write("# MIESC v4.1 Scalability Benchmark Report\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"**Platform:** {os.uname().sysname} {os.uname().release}\n\n")

        f.write("## Results Summary\n\n")
        f.write("| Benchmark | Contracts | Time (s) | Throughput | Memory (MB) | Workers |\n")
        f.write("|-----------|-----------|----------|------------|-------------|----------|\n")
        for r in results:
            f.write(
                f"| {r.benchmark_name} | {r.contracts_analyzed} | {r.total_time_seconds:.1f} | "
                f"{r.throughput_contracts_per_minute:.1f}/min | {r.memory_peak_mb:.1f} | {r.parallel_workers} |\n"
            )

        f.write("\n## Key Findings\n\n")
        if len(results) >= 2:
            f.write(
                f"- **Parallel Speedup:** {speedup:.2f}x with {parallel.parallel_workers} workers\n"
            )
        f.write(
            f"- **Peak Throughput:** {max(r.throughput_contracts_per_minute for r in results):.1f} contracts/minute\n"
        )
        f.write(f"- **Memory Efficiency:** Peak {max(r.memory_peak_mb for r in results):.1f} MB\n")

    print(f"Summary saved: {summary_file}")


if __name__ == "__main__":
    run_full_benchmark()
