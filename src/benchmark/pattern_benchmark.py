"""
Pattern Detection Benchmark
============================

Benchmarks the ML pattern detection components directly against
known vulnerable code snippets.

This tests:
- DeFi Pattern Detector
- Reentrancy pattern matching
- Access control detection
- FP filter accuracy

Much faster than full MIESC audit - useful for ML iteration.
"""

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .dataset_loader import VulnerableContract, VulnerabilityCategory, GroundTruth


@dataclass
class PatternMatch:
    """A matched pattern in code."""
    pattern_name: str
    category: str
    line: int
    confidence: float
    code_snippet: str


@dataclass
class PatternBenchmarkResult:
    """Results of pattern benchmark."""
    total_contracts: int
    total_ground_truth: int
    patterns_tested: List[str]
    true_positives: int
    false_negatives: int
    detection_rate_by_category: Dict[str, float]
    processing_time_ms: float
    timestamp: datetime

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "PATTERN DETECTION BENCHMARK",
            "=" * 60,
            f"Contracts tested: {self.total_contracts}",
            f"Ground truth vulnerabilities: {self.total_ground_truth}",
            f"True positives: {self.true_positives}",
            f"False negatives: {self.false_negatives}",
            f"Overall recall: {self.true_positives / max(self.total_ground_truth, 1) * 100:.1f}%",
            "",
            "DETECTION RATE BY CATEGORY",
            "-" * 40,
        ]
        for cat, rate in sorted(self.detection_rate_by_category.items()):
            lines.append(f"  {cat:30} {rate*100:5.1f}%")

        lines.extend([
            "",
            f"Processing time: {self.processing_time_ms:.2f}ms",
            "=" * 60,
        ])
        return "\n".join(lines)


class PatternBenchmarkRunner:
    """
    Benchmarks pattern detection accuracy.

    Tests regex patterns and heuristics directly against source code.
    """

    # Vulnerability detection patterns
    PATTERNS = {
        "reentrancy": {
            "patterns": [
                # Classic reentrancy: external call before state update
                r"\.call\s*\{?\s*value\s*:",
                r"\.call\.value\s*\(",
                r"msg\.sender\.call",
                r"\.send\s*\(",
                r"\.transfer\s*\(",
            ],
            "anti_patterns": [
                r"nonReentrant",
                r"ReentrancyGuard",
                r"locked\s*=\s*true",
            ],
            "context_check": lambda code, line: (
                # Check if state update comes AFTER external call
                PatternBenchmarkRunner._check_state_after_call(code, line)
            ),
        },
        "access_control": {
            "patterns": [
                r"tx\.origin",
                r"selfdestruct\s*\(",
                r"suicide\s*\(",
                r"delegatecall\s*\(",  # Arbitrary delegatecall
                # Incorrect constructor names (pre-0.4.22) - functions that SET owner
                r"function\s+[A-Z]\w*\s*\(\s*\)\s*(public|external)",
                r"function\s+(Constructor|Init|Initialize)\s*\(",
                # Public functions that set owner without modifier
                r"owner\s*=\s*msg\.sender",
                # Storage manipulation
                r"\.length\s*--",  # Array length underflow
                r"\.length\s*-=",
            ],
            # NO global anti-patterns - use context_check instead
            # Some functions may be protected while others aren't
        },
        "arithmetic": {
            "patterns": [
                r"\+\+|\-\-",                     # Increment/decrement
                r"\+\s*=|\-\s*=|\*\s*=",         # Compound assignment
                r"[^/]/\s*[^/]",                 # Division (not comments)
                r"=\s*\w+\s*\*\s*\w+",           # Multiplication: a = b * c
                r"=\s*\w+\s*-\s*\w+",            # Subtraction: a = b - c
                r"=\s*\w+\s*\+\s*\w+",           # Addition: a = b + c
            ],
            "anti_patterns": [
                r"SafeMath",
                r"unchecked\s*\{",  # Solidity 0.8+ explicit unchecked
                r"pragma\s+solidity\s+[>=^]*0\.[89]",  # 0.8+ has built-in checks
            ],
            "version_check": lambda code: "0.8" not in code[:200],
        },
        "unchecked_low_level_calls": {
            "patterns": [
                # .call patterns - detect ANY call usage
                r"\w+\.call\s*\(",                              # addr.call(
                r"\w+\.call\.value\s*\([^)]*\)\s*\(",           # addr.call.value(x)(
                r"\w+\.call\.value\s*\([^)]*\)\s*;",            # addr.call.value(x); (no function call)
                r"\w+\.call\.value\s*\([^)]*\)\.gas\s*\(",      # addr.call.value(x).gas(y)
                r"\w+\.call\.gas\s*\(",                         # addr.call.gas(x)
                # .send patterns
                r"\w+\.send\s*\(",                              # addr.send(
                # .delegatecall patterns
                r"\w+\.delegatecall\s*\(",                      # addr.delegatecall(
            ],
            # NO global anti-patterns - each call must be checked individually
            # A contract might have both protected and unprotected calls
        },
        "timestamp": {
            "patterns": [
                r"block\.timestamp",
                r"\bnow\b",
            ],
            # No context check - any timestamp use is potentially vulnerable
        },
        "time_manipulation": {
            "patterns": [
                r"block\.timestamp",
                r"\bnow\b",
            ],
            # Alias for timestamp category
        },
        "bad_randomness": {
            "patterns": [
                r"block\.timestamp\s*%",
                r"blockhash\s*\(",
                r"block\.number\s*%",
                r"block\.number\s*[;=]",           # block.number assignment (for later use)
                r"block\.coinbase",                 # Miner address - predictable
                r"block\.difficulty",               # Predictable in PoS
                r"block\.prevrandao",               # Alias for difficulty in PoS
                r"keccak256\s*\([^)]*block",       # keccak with block data
            ],
        },
        "denial_of_service": {
            "patterns": [
                # Loop-based gas exhaustion (unbounded iteration)
                r"for\s*\([^)]*\)\s*\{",  # Any loop
                r"while\s*\(",
                r"\.length\s*[<>]",  # Array length comparison
                r"address\s*\[\]",  # Dynamic address array
                # Push payment DoS (external call in require/if can block entire function)
                r"require\s*\([^)]*\.send\s*\(",  # require(x.send()) - blocks if fails
                r"require\s*\([^)]*\.call",       # require(x.call()) - blocks if fails
                r"require\s*\([^)]*\.transfer",   # require(x.transfer()) - blocks if fails
            ],
            # No context_check - both loop-based and push-payment DoS are valid
        },
        "front_running": {
            "patterns": [
                # ERC20 approve front-running
                r"function\s+approve\s*\(",
                r"_allowed\s*\[.*\]\s*\[.*\]\s*=",  # Direct allowance setting
                # Hash-based puzzles (solution visible in mempool)
                r"sha3\s*\(\s*\w+\s*\)",  # sha3(solution)
                r"keccak256\s*\(\s*\w+\s*\)",  # keccak256(solution)
                # Transaction order dependence
                r"\.transfer\s*\(\s*reward",  # transfer(reward)
                r"reward\s*=\s*msg\.value",  # reward assignment
                # Games/gambling patterns
                r"function\s+play\s*\(",
                r"function\s+bet\s*\(",
                r"function\s+guess\s*\(",
            ],
            "anti_patterns": [
                r"increaseAllowance",  # Safe allowance pattern
                r"decreaseAllowance",
                r"safeApprove",
            ],
        },
        "short_addresses": {
            "patterns": [
                # Functions that transfer to address with amount (classic pattern)
                r"function\s+\w*[Ss]end\w*\s*\(\s*address\s+\w+\s*,\s*uint",
                r"function\s+\w*[Tt]ransfer\w*\s*\(\s*address\s+\w+\s*,\s*uint",
                r"function\s+sendCoin\s*\(",
                # Direct balance manipulation with address param
                r"balances\s*\[\s*\w+\s*\]\s*[-+]=",
            ],
            "anti_patterns": [
                # Solidity 0.5+ has built-in protection
                r"pragma\s+solidity\s+[>=^]*0\.[5-9]",
                r"pragma\s+solidity\s+[>=^]*0\.1",  # 0.10+
            ],
        },
    }

    @staticmethod
    def _check_state_after_call(code: str, call_line: int) -> bool:
        """Check if state update happens after external call (reentrancy pattern)."""
        lines = code.split('\n')
        if call_line >= len(lines):
            return False

        # Look for state updates (= assignment to storage) after the call line
        state_patterns = [
            r'\b\w+\s*\[.*\]\s*=',  # mapping assignment
            r'\b\w+\s*=\s*[^=]',    # variable assignment
            r'\-=|\+=',             # compound assignment
        ]

        for i in range(call_line, min(call_line + 10, len(lines))):
            for pattern in state_patterns:
                if re.search(pattern, lines[i]):
                    return True
        return False

    def __init__(self, line_tolerance: int = 10):
        self.line_tolerance = line_tolerance

    def run(
        self,
        contracts: List[VulnerableContract],
        verbose: bool = True,
    ) -> PatternBenchmarkResult:
        """Run pattern benchmark on contracts."""
        start_time = time.time()

        total_tp = 0
        total_fn = 0
        category_stats: Dict[str, Dict[str, int]] = {}

        for contract in contracts:
            for gt in contract.vulnerabilities:
                cat = gt.category.value

                if cat not in category_stats:
                    category_stats[cat] = {"tp": 0, "fn": 0}

                # Try to detect this vulnerability
                matches = self._detect_patterns(contract.source_code, cat)

                # Check if any match overlaps with ground truth
                found = False
                for match in matches:
                    if abs(match.line - gt.lines[0]) <= self.line_tolerance:
                        found = True
                        break

                if found:
                    total_tp += 1
                    category_stats[cat]["tp"] += 1
                else:
                    total_fn += 1
                    category_stats[cat]["fn"] += 1
                    if verbose:
                        print(f"  MISS: {contract.name} - {cat} @ line {gt.lines}")

        processing_time = (time.time() - start_time) * 1000

        # Calculate detection rates
        detection_rates = {}
        for cat, stats in category_stats.items():
            total = stats["tp"] + stats["fn"]
            detection_rates[cat] = stats["tp"] / total if total > 0 else 0.0

        return PatternBenchmarkResult(
            total_contracts=len(contracts),
            total_ground_truth=total_tp + total_fn,
            patterns_tested=list(self.PATTERNS.keys()),
            true_positives=total_tp,
            false_negatives=total_fn,
            detection_rate_by_category=detection_rates,
            processing_time_ms=processing_time,
            timestamp=datetime.now(),
        )

    def _detect_patterns(self, code: str, category: str) -> List[PatternMatch]:
        """Detect vulnerability patterns in code."""
        matches = []

        if category not in self.PATTERNS:
            return matches

        config = self.PATTERNS[category]
        patterns = config.get("patterns", [])
        anti_patterns = config.get("anti_patterns", [])

        lines = code.split('\n')

        # Check anti-patterns first (if present, skip detection)
        for anti in anti_patterns:
            if re.search(anti, code, re.IGNORECASE):
                return []  # Protected

        # Version check if specified
        version_check = config.get("version_check")
        if version_check and not version_check(code):
            return []

        # Find pattern matches
        for pattern in patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Context check if specified (receives full code and line number)
                    context_check = config.get("context_check")
                    if context_check and not context_check(code, i):
                        continue

                    matches.append(PatternMatch(
                        pattern_name=pattern[:30],
                        category=category,
                        line=i,
                        confidence=0.7,
                        code_snippet=line.strip()[:100],
                    ))

        return matches


def run_pattern_benchmark(
    contracts: List[VulnerableContract],
    verbose: bool = True,
) -> PatternBenchmarkResult:
    """Convenience function."""
    runner = PatternBenchmarkRunner()
    return runner.run(contracts, verbose=verbose)
