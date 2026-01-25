"""
Dataset Loader for Benchmark Framework
=======================================

Loads and parses vulnerability datasets for benchmarking.

Supported formats:
- SmartBugs Curated (vulnerabilities.json)
- Damn Vulnerable DeFi (challenge structure)
- SWC Registry (markdown + test cases)
"""

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import re


class VulnerabilityCategory(Enum):
    """Standard vulnerability categories mapped to MIESC types."""

    # SmartBugs DASP categories
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"
    REENTRANCY = "reentrancy"
    UNCHECKED_LOW_LEVEL_CALLS = "unchecked_low_level_calls"
    DENIAL_OF_SERVICE = "denial_of_service"
    BAD_RANDOMNESS = "bad_randomness"
    FRONT_RUNNING = "front_running"
    TIME_MANIPULATION = "time_manipulation"
    SHORT_ADDRESSES = "short_addresses"
    OTHER = "other"

    # DeFi-specific
    FLASH_LOAN = "flash_loan"
    ORACLE_MANIPULATION = "oracle_manipulation"
    GOVERNANCE = "governance"
    PRICE_MANIPULATION = "price_manipulation"

    @classmethod
    def from_string(cls, s: str) -> "VulnerabilityCategory":
        """Convert string to category."""
        mapping = {
            "access_control": cls.ACCESS_CONTROL,
            "arithmetic": cls.ARITHMETIC,
            "reentrancy": cls.REENTRANCY,
            "unchecked_low_level_calls": cls.UNCHECKED_LOW_LEVEL_CALLS,
            "denial_of_service": cls.DENIAL_OF_SERVICE,
            "bad_randomness": cls.BAD_RANDOMNESS,
            "front_running": cls.FRONT_RUNNING,
            "time_manipulation": cls.TIME_MANIPULATION,
            "short_addresses": cls.SHORT_ADDRESSES,
            "other": cls.OTHER,
            "flash_loan": cls.FLASH_LOAN,
            "oracle_manipulation": cls.ORACLE_MANIPULATION,
            "governance": cls.GOVERNANCE,
            "price_manipulation": cls.PRICE_MANIPULATION,
        }
        return mapping.get(s.lower().replace("-", "_").replace(" ", "_"), cls.OTHER)


@dataclass
class GroundTruth:
    """Ground truth vulnerability annotation."""

    category: VulnerabilityCategory
    lines: List[int]
    severity: str = "unknown"
    description: str = ""
    swc_id: Optional[str] = None

    def overlaps_with(self, other_lines: List[int], tolerance: int = 5) -> bool:
        """Check if detected lines overlap with ground truth (with tolerance)."""
        for gt_line in self.lines:
            for det_line in other_lines:
                if abs(gt_line - det_line) <= tolerance:
                    return True
        return False


@dataclass
class VulnerableContract:
    """A contract with known vulnerabilities."""

    name: str
    path: str
    source_code: str
    pragma_version: str
    vulnerabilities: List[GroundTruth]
    source_url: str = ""
    dataset: str = ""

    @property
    def categories(self) -> Set[VulnerabilityCategory]:
        """Get unique vulnerability categories."""
        return {v.category for v in self.vulnerabilities}

    @property
    def total_vuln_count(self) -> int:
        """Total number of vulnerability instances."""
        return len(self.vulnerabilities)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "path": self.path,
            "pragma_version": self.pragma_version,
            "vulnerabilities": [
                {
                    "category": v.category.value,
                    "lines": v.lines,
                    "severity": v.severity,
                }
                for v in self.vulnerabilities
            ],
        }


class DatasetLoader:
    """Loads vulnerability datasets for benchmarking."""

    BENCHMARK_DIR = Path(__file__).parent.parent.parent / "data" / "benchmarks"

    # Category mappings from different sources to MIESC types
    MIESC_CATEGORY_MAP = {
        # SmartBugs -> MIESC
        "access_control": ["SWC-105", "SWC-106", "access-control"],
        "arithmetic": ["SWC-101", "integer-overflow"],
        "reentrancy": ["SWC-107", "reentrancy"],
        "unchecked_low_level_calls": ["SWC-104", "unchecked-call"],
        "denial_of_service": ["SWC-128", "dos"],
        "bad_randomness": ["SWC-120", "weak-randomness"],
        "front_running": ["SWC-114", "front-running"],
        "time_manipulation": ["SWC-116", "timestamp"],
        "short_addresses": ["SWC-102", "short-address"],
    }

    def __init__(self, benchmark_dir: Optional[Path] = None):
        self.benchmark_dir = benchmark_dir or self.BENCHMARK_DIR
        self._contracts: List[VulnerableContract] = []

    def load_smartbugs(self) -> List[VulnerableContract]:
        """Load SmartBugs Curated dataset."""
        dataset_path = self.benchmark_dir / "smartbugs-curated"
        vuln_file = dataset_path / "vulnerabilities.json"

        if not vuln_file.exists():
            raise FileNotFoundError(f"SmartBugs dataset not found at {vuln_file}")

        with open(vuln_file, "r") as f:
            vulnerabilities_data = json.load(f)

        contracts = []
        for entry in vulnerabilities_data:
            contract_path = dataset_path / entry["path"]

            if not contract_path.exists():
                continue

            source_code = contract_path.read_text()

            ground_truths = []
            for vuln in entry.get("vulnerabilities", []):
                gt = GroundTruth(
                    category=VulnerabilityCategory.from_string(vuln["category"]),
                    lines=vuln.get("lines", []),
                    description=vuln.get("description", ""),
                    swc_id=vuln.get("swc_id"),
                )
                ground_truths.append(gt)

            contract = VulnerableContract(
                name=entry["name"],
                path=str(contract_path),
                source_code=source_code,
                pragma_version=entry.get("pragma", "unknown"),
                vulnerabilities=ground_truths,
                source_url=entry.get("source", ""),
                dataset="smartbugs-curated",
            )
            contracts.append(contract)

        self._contracts.extend(contracts)
        return contracts

    def load_damn_vulnerable_defi(self) -> List[VulnerableContract]:
        """Load Damn Vulnerable DeFi challenges."""
        dvd_path = self.benchmark_dir / "damn-vulnerable-defi" / "src"

        if not dvd_path.exists():
            raise FileNotFoundError(f"DVDeFi dataset not found at {dvd_path}")

        # Challenge -> vulnerability type mapping
        challenge_vulns = {
            "unstoppable": [
                GroundTruth(VulnerabilityCategory.DENIAL_OF_SERVICE, [50], "high", "Flash loan griefing")
            ],
            "naive-receiver": [
                GroundTruth(VulnerabilityCategory.ACCESS_CONTROL, [40], "high", "Missing caller validation")
            ],
            "truster": [
                GroundTruth(VulnerabilityCategory.ACCESS_CONTROL, [28], "critical", "Arbitrary external call")
            ],
            "side-entrance": [
                GroundTruth(VulnerabilityCategory.REENTRANCY, [30], "critical", "Flash loan + deposit reentrancy")
            ],
            "the-rewarder": [
                GroundTruth(VulnerabilityCategory.FLASH_LOAN, [45], "high", "Flash loan reward manipulation")
            ],
            "selfie": [
                GroundTruth(VulnerabilityCategory.GOVERNANCE, [55], "critical", "Flash loan governance attack")
            ],
            "compromised": [
                GroundTruth(VulnerabilityCategory.ORACLE_MANIPULATION, [35], "critical", "Oracle price manipulation")
            ],
            "puppet": [
                GroundTruth(VulnerabilityCategory.ORACLE_MANIPULATION, [60], "critical", "Spot price oracle manipulation")
            ],
            "puppet-v2": [
                GroundTruth(VulnerabilityCategory.ORACLE_MANIPULATION, [45], "critical", "Uniswap V2 oracle manipulation")
            ],
            "puppet-v3": [
                GroundTruth(VulnerabilityCategory.ORACLE_MANIPULATION, [50], "high", "TWAP manipulation")
            ],
            "free-rider": [
                GroundTruth(VulnerabilityCategory.REENTRANCY, [70], "critical", "NFT flash loan exploit")
            ],
            "backdoor": [
                GroundTruth(VulnerabilityCategory.ACCESS_CONTROL, [25], "critical", "Gnosis Safe callback exploit")
            ],
            "climber": [
                GroundTruth(VulnerabilityCategory.ACCESS_CONTROL, [80], "critical", "Timelock execution before validation")
            ],
            "wallet-mining": [
                GroundTruth(VulnerabilityCategory.ACCESS_CONTROL, [40], "high", "Create2 address prediction")
            ],
            "abi-smuggling": [
                GroundTruth(VulnerabilityCategory.ACCESS_CONTROL, [55], "critical", "ABI encoding exploit")
            ],
            "shards": [
                GroundTruth(VulnerabilityCategory.ARITHMETIC, [65], "high", "Rounding error exploit")
            ],
            "curvy-puppet": [
                GroundTruth(VulnerabilityCategory.FLASH_LOAN, [90], "critical", "Curve pool manipulation")
            ],
            "withdrawal": [
                GroundTruth(VulnerabilityCategory.REENTRANCY, [50], "critical", "L1->L2 withdrawal exploit")
            ],
        }

        contracts = []
        for challenge_dir in dvd_path.iterdir():
            if not challenge_dir.is_dir() or challenge_dir.name.startswith("."):
                continue

            if challenge_dir.name in ["DamnValuableToken.sol", "DamnValuableNFT.sol"]:
                continue

            # Find main contract file
            sol_files = list(challenge_dir.glob("*.sol"))
            if not sol_files:
                continue

            # Use largest file as main contract
            main_file = max(sol_files, key=lambda f: f.stat().st_size)
            source_code = main_file.read_text()

            vulns = challenge_vulns.get(challenge_dir.name, [
                GroundTruth(VulnerabilityCategory.OTHER, [1], "unknown", "Unknown vulnerability")
            ])

            contract = VulnerableContract(
                name=main_file.name,
                path=str(main_file),
                source_code=source_code,
                pragma_version=self._extract_pragma(source_code),
                vulnerabilities=vulns,
                source_url="https://github.com/theredguild/damn-vulnerable-defi",
                dataset="damn-vulnerable-defi",
            )
            contracts.append(contract)

        self._contracts.extend(contracts)
        return contracts

    def load_all(self) -> List[VulnerableContract]:
        """Load all available datasets."""
        all_contracts = []

        try:
            all_contracts.extend(self.load_smartbugs())
        except FileNotFoundError as e:
            print(f"Warning: {e}")

        try:
            all_contracts.extend(self.load_damn_vulnerable_defi())
        except FileNotFoundError as e:
            print(f"Warning: {e}")

        return all_contracts

    def get_by_category(self, category: VulnerabilityCategory) -> List[VulnerableContract]:
        """Get contracts with specific vulnerability category."""
        return [
            c for c in self._contracts
            if category in c.categories
        ]

    def get_statistics(self) -> Dict:
        """Get dataset statistics."""
        stats = {
            "total_contracts": len(self._contracts),
            "total_vulnerabilities": sum(c.total_vuln_count for c in self._contracts),
            "by_category": {},
            "by_dataset": {},
        }

        for cat in VulnerabilityCategory:
            count = len(self.get_by_category(cat))
            if count > 0:
                stats["by_category"][cat.value] = count

        for contract in self._contracts:
            ds = contract.dataset
            stats["by_dataset"][ds] = stats["by_dataset"].get(ds, 0) + 1

        return stats

    def _extract_pragma(self, source: str) -> str:
        """Extract pragma version from source code."""
        match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        return match.group(1).strip() if match else "unknown"


def load_smartbugs(benchmark_dir: Optional[Path] = None) -> List[VulnerableContract]:
    """Convenience function to load SmartBugs dataset."""
    loader = DatasetLoader(benchmark_dir)
    return loader.load_smartbugs()


def load_dvd(benchmark_dir: Optional[Path] = None) -> List[VulnerableContract]:
    """Convenience function to load Damn Vulnerable DeFi dataset."""
    loader = DatasetLoader(benchmark_dir)
    return loader.load_damn_vulnerable_defi()
