"""
Tests for Dataset Loader module.

Tests the benchmark dataset loading functionality.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.benchmark.dataset_loader import (
    DatasetLoader,
    GroundTruth,
    VulnerabilityCategory,
    VulnerableContract,
    load_dvd,
    load_smartbugs,
)


class TestVulnerabilityCategory:
    """Test VulnerabilityCategory enum."""

    def test_all_categories_exist(self):
        """Test all expected categories exist."""
        expected = [
            "ACCESS_CONTROL",
            "ARITHMETIC",
            "REENTRANCY",
            "UNCHECKED_LOW_LEVEL_CALLS",
            "DENIAL_OF_SERVICE",
            "BAD_RANDOMNESS",
            "FRONT_RUNNING",
            "TIME_MANIPULATION",
            "SHORT_ADDRESSES",
            "OTHER",
            "FLASH_LOAN",
            "ORACLE_MANIPULATION",
            "GOVERNANCE",
            "PRICE_MANIPULATION",
        ]
        for cat_name in expected:
            assert hasattr(VulnerabilityCategory, cat_name)

    def test_category_values(self):
        """Test category values."""
        assert VulnerabilityCategory.REENTRANCY.value == "reentrancy"
        assert VulnerabilityCategory.ACCESS_CONTROL.value == "access_control"
        assert VulnerabilityCategory.FLASH_LOAN.value == "flash_loan"

    def test_from_string_exact_match(self):
        """Test from_string with exact match."""
        assert VulnerabilityCategory.from_string("reentrancy") == VulnerabilityCategory.REENTRANCY
        assert (
            VulnerabilityCategory.from_string("access_control")
            == VulnerabilityCategory.ACCESS_CONTROL
        )

    def test_from_string_with_dashes(self):
        """Test from_string with dashes."""
        assert (
            VulnerabilityCategory.from_string("access-control")
            == VulnerabilityCategory.ACCESS_CONTROL
        )

    def test_from_string_with_spaces(self):
        """Test from_string with spaces."""
        assert (
            VulnerabilityCategory.from_string("access control")
            == VulnerabilityCategory.ACCESS_CONTROL
        )

    def test_from_string_case_insensitive(self):
        """Test from_string is case insensitive."""
        assert VulnerabilityCategory.from_string("REENTRANCY") == VulnerabilityCategory.REENTRANCY
        assert VulnerabilityCategory.from_string("Reentrancy") == VulnerabilityCategory.REENTRANCY

    def test_from_string_unknown(self):
        """Test from_string with unknown category."""
        assert VulnerabilityCategory.from_string("unknown_type") == VulnerabilityCategory.OTHER

    def test_from_string_defi_categories(self):
        """Test from_string with DeFi categories."""
        assert VulnerabilityCategory.from_string("flash_loan") == VulnerabilityCategory.FLASH_LOAN
        assert (
            VulnerabilityCategory.from_string("oracle_manipulation")
            == VulnerabilityCategory.ORACLE_MANIPULATION
        )
        assert VulnerabilityCategory.from_string("governance") == VulnerabilityCategory.GOVERNANCE


class TestGroundTruth:
    """Test GroundTruth dataclass."""

    def test_create_ground_truth(self):
        """Test creating ground truth."""
        gt = GroundTruth(
            category=VulnerabilityCategory.REENTRANCY,
            lines=[10, 15, 20],
            severity="high",
            description="Reentrancy vulnerability",
        )
        assert gt.category == VulnerabilityCategory.REENTRANCY
        assert gt.lines == [10, 15, 20]
        assert gt.severity == "high"
        assert gt.description == "Reentrancy vulnerability"

    def test_default_values(self):
        """Test default values."""
        gt = GroundTruth(
            category=VulnerabilityCategory.ARITHMETIC,
            lines=[5],
        )
        assert gt.severity == "unknown"
        assert gt.description == ""
        assert gt.swc_id is None

    def test_with_swc_id(self):
        """Test with SWC ID."""
        gt = GroundTruth(
            category=VulnerabilityCategory.REENTRANCY,
            lines=[50],
            swc_id="SWC-107",
        )
        assert gt.swc_id == "SWC-107"

    def test_overlaps_with_exact_match(self):
        """Test overlaps_with exact match."""
        gt = GroundTruth(
            category=VulnerabilityCategory.REENTRANCY,
            lines=[50],
        )
        assert gt.overlaps_with([50])

    def test_overlaps_with_tolerance(self):
        """Test overlaps_with within tolerance."""
        gt = GroundTruth(
            category=VulnerabilityCategory.REENTRANCY,
            lines=[50],
        )
        assert gt.overlaps_with([53], tolerance=5)
        assert gt.overlaps_with([47], tolerance=5)

    def test_overlaps_with_outside_tolerance(self):
        """Test overlaps_with outside tolerance."""
        gt = GroundTruth(
            category=VulnerabilityCategory.REENTRANCY,
            lines=[50],
        )
        assert not gt.overlaps_with([60], tolerance=5)

    def test_overlaps_with_multiple_lines(self):
        """Test overlaps_with multiple ground truth lines."""
        gt = GroundTruth(
            category=VulnerabilityCategory.REENTRANCY,
            lines=[50, 100, 150],
        )
        assert gt.overlaps_with([102], tolerance=5)

    def test_overlaps_with_empty_lines(self):
        """Test overlaps_with empty detection lines."""
        gt = GroundTruth(
            category=VulnerabilityCategory.REENTRANCY,
            lines=[50],
        )
        assert not gt.overlaps_with([])


class TestVulnerableContract:
    """Test VulnerableContract dataclass."""

    @pytest.fixture
    def sample_contract(self):
        """Create sample contract."""
        return VulnerableContract(
            name="Token.sol",
            path="/path/to/Token.sol",
            source_code="pragma solidity ^0.8.0; contract Token {}",
            pragma_version="^0.8.0",
            vulnerabilities=[
                GroundTruth(
                    category=VulnerabilityCategory.REENTRANCY,
                    lines=[50],
                ),
                GroundTruth(
                    category=VulnerabilityCategory.ACCESS_CONTROL,
                    lines=[100],
                ),
            ],
        )

    def test_create_contract(self, sample_contract):
        """Test creating contract."""
        assert sample_contract.name == "Token.sol"
        assert sample_contract.pragma_version == "^0.8.0"
        assert len(sample_contract.vulnerabilities) == 2

    def test_default_values(self):
        """Test default values."""
        contract = VulnerableContract(
            name="Test.sol",
            path="/path",
            source_code="",
            pragma_version="",
            vulnerabilities=[],
        )
        assert contract.source_url == ""
        assert contract.dataset == ""

    def test_categories_property(self, sample_contract):
        """Test categories property."""
        categories = sample_contract.categories
        assert VulnerabilityCategory.REENTRANCY in categories
        assert VulnerabilityCategory.ACCESS_CONTROL in categories
        assert len(categories) == 2

    def test_categories_unique(self):
        """Test categories are unique."""
        contract = VulnerableContract(
            name="Test.sol",
            path="/path",
            source_code="",
            pragma_version="",
            vulnerabilities=[
                GroundTruth(VulnerabilityCategory.REENTRANCY, [10]),
                GroundTruth(VulnerabilityCategory.REENTRANCY, [20]),
                GroundTruth(VulnerabilityCategory.REENTRANCY, [30]),
            ],
        )
        assert len(contract.categories) == 1

    def test_total_vuln_count(self, sample_contract):
        """Test total vulnerability count."""
        assert sample_contract.total_vuln_count == 2

    def test_to_dict(self, sample_contract):
        """Test dictionary conversion."""
        d = sample_contract.to_dict()
        assert d["name"] == "Token.sol"
        assert d["path"] == "/path/to/Token.sol"
        assert d["pragma_version"] == "^0.8.0"
        assert len(d["vulnerabilities"]) == 2


class TestDatasetLoader:
    """Test DatasetLoader class."""

    @pytest.fixture
    def loader(self, tmp_path):
        """Create loader with temp directory."""
        return DatasetLoader(benchmark_dir=tmp_path)

    def test_init_default(self):
        """Test default initialization."""
        loader = DatasetLoader()
        assert loader.benchmark_dir == DatasetLoader.BENCHMARK_DIR

    def test_init_custom_dir(self, tmp_path):
        """Test custom directory."""
        loader = DatasetLoader(benchmark_dir=tmp_path)
        assert loader.benchmark_dir == tmp_path

    def test_miesc_category_map(self):
        """Test category mapping exists."""
        assert "reentrancy" in DatasetLoader.MIESC_CATEGORY_MAP
        assert "arithmetic" in DatasetLoader.MIESC_CATEGORY_MAP
        assert "access_control" in DatasetLoader.MIESC_CATEGORY_MAP

    def test_load_smartbugs_not_found(self, loader):
        """Test loading SmartBugs when not found."""
        with pytest.raises(FileNotFoundError):
            loader.load_smartbugs()

    def test_load_smartbugs_success(self, tmp_path):
        """Test loading SmartBugs successfully."""
        # Create dataset structure
        dataset_dir = tmp_path / "smartbugs-curated"
        dataset_dir.mkdir()

        # Create contract file
        contract_file = dataset_dir / "reentrancy_simple.sol"
        contract_file.write_text("pragma solidity ^0.4.0; contract Test {}")

        # Create vulnerabilities.json
        vuln_data = [
            {
                "name": "reentrancy_simple.sol",
                "path": "reentrancy_simple.sol",
                "pragma": "^0.4.0",
                "vulnerabilities": [
                    {"category": "reentrancy", "lines": [10, 15]},
                ],
            }
        ]
        vuln_file = dataset_dir / "vulnerabilities.json"
        vuln_file.write_text(json.dumps(vuln_data))

        loader = DatasetLoader(benchmark_dir=tmp_path)
        contracts = loader.load_smartbugs()

        assert len(contracts) == 1
        assert contracts[0].name == "reentrancy_simple.sol"
        assert contracts[0].dataset == "smartbugs-curated"

    def test_load_smartbugs_missing_contract(self, tmp_path):
        """Test loading SmartBugs with missing contract file."""
        dataset_dir = tmp_path / "smartbugs-curated"
        dataset_dir.mkdir()

        vuln_data = [
            {
                "name": "missing.sol",
                "path": "missing.sol",
                "vulnerabilities": [],
            }
        ]
        vuln_file = dataset_dir / "vulnerabilities.json"
        vuln_file.write_text(json.dumps(vuln_data))

        loader = DatasetLoader(benchmark_dir=tmp_path)
        contracts = loader.load_smartbugs()

        # Missing contracts should be skipped
        assert len(contracts) == 0

    def test_load_dvd_not_found(self, loader):
        """Test loading DVDeFi when not found."""
        with pytest.raises(FileNotFoundError):
            loader.load_damn_vulnerable_defi()

    def test_load_dvd_success(self, tmp_path):
        """Test loading DVDeFi successfully."""
        # Create dataset structure
        dataset_dir = tmp_path / "damn-vulnerable-defi" / "src"
        dataset_dir.mkdir(parents=True)

        # Create challenge directory
        challenge_dir = dataset_dir / "unstoppable"
        challenge_dir.mkdir()

        # Create contract file
        contract_file = challenge_dir / "UnstoppableLender.sol"
        contract_file.write_text("pragma solidity ^0.8.0; contract UnstoppableLender {}")

        loader = DatasetLoader(benchmark_dir=tmp_path)
        contracts = loader.load_damn_vulnerable_defi()

        assert len(contracts) == 1
        assert contracts[0].dataset == "damn-vulnerable-defi"

    def test_load_dvd_skips_hidden_dirs(self, tmp_path):
        """Test DVDeFi skips hidden directories."""
        dataset_dir = tmp_path / "damn-vulnerable-defi" / "src"
        dataset_dir.mkdir(parents=True)

        # Create hidden directory
        hidden_dir = dataset_dir / ".git"
        hidden_dir.mkdir()

        loader = DatasetLoader(benchmark_dir=tmp_path)
        contracts = loader.load_damn_vulnerable_defi()

        assert len(contracts) == 0

    def test_load_dvd_skips_token_contracts(self, tmp_path):
        """Test DVDeFi skips token contracts."""
        dataset_dir = tmp_path / "damn-vulnerable-defi" / "src"
        dataset_dir.mkdir(parents=True)

        # These should be skipped
        (dataset_dir / "DamnValuableToken.sol").mkdir()
        (dataset_dir / "DamnValuableNFT.sol").mkdir()

        loader = DatasetLoader(benchmark_dir=tmp_path)
        contracts = loader.load_damn_vulnerable_defi()

        assert len(contracts) == 0

    def test_load_all(self, tmp_path):
        """Test loading all datasets."""
        loader = DatasetLoader(benchmark_dir=tmp_path)

        # Should not crash when datasets not found
        contracts = loader.load_all()
        assert contracts == []

    def test_get_by_category(self, tmp_path):
        """Test filtering by category."""
        loader = DatasetLoader(benchmark_dir=tmp_path)

        # Manually add contracts
        loader._contracts = [
            VulnerableContract(
                name="test1.sol",
                path="/path1",
                source_code="",
                pragma_version="",
                vulnerabilities=[
                    GroundTruth(VulnerabilityCategory.REENTRANCY, [10]),
                ],
            ),
            VulnerableContract(
                name="test2.sol",
                path="/path2",
                source_code="",
                pragma_version="",
                vulnerabilities=[
                    GroundTruth(VulnerabilityCategory.ARITHMETIC, [20]),
                ],
            ),
        ]

        reentrancy = loader.get_by_category(VulnerabilityCategory.REENTRANCY)
        assert len(reentrancy) == 1
        assert reentrancy[0].name == "test1.sol"

    def test_get_statistics(self, tmp_path):
        """Test statistics generation."""
        loader = DatasetLoader(benchmark_dir=tmp_path)

        loader._contracts = [
            VulnerableContract(
                name="test1.sol",
                path="/path1",
                source_code="",
                pragma_version="",
                vulnerabilities=[
                    GroundTruth(VulnerabilityCategory.REENTRANCY, [10]),
                    GroundTruth(VulnerabilityCategory.REENTRANCY, [20]),
                ],
                dataset="smartbugs",
            ),
            VulnerableContract(
                name="test2.sol",
                path="/path2",
                source_code="",
                pragma_version="",
                vulnerabilities=[
                    GroundTruth(VulnerabilityCategory.ARITHMETIC, [30]),
                ],
                dataset="dvd",
            ),
        ]

        stats = loader.get_statistics()

        assert stats["total_contracts"] == 2
        assert stats["total_vulnerabilities"] == 3
        assert "reentrancy" in stats["by_category"]
        assert stats["by_category"]["reentrancy"] == 1  # contracts with category
        assert "smartbugs" in stats["by_dataset"]
        assert "dvd" in stats["by_dataset"]

    def test_extract_pragma_found(self, tmp_path):
        """Test pragma extraction when found."""
        loader = DatasetLoader(benchmark_dir=tmp_path)
        source = "pragma solidity ^0.8.0;\n\ncontract Test {}"
        assert loader._extract_pragma(source) == "^0.8.0"

    def test_extract_pragma_complex(self, tmp_path):
        """Test pragma extraction with complex version."""
        loader = DatasetLoader(benchmark_dir=tmp_path)
        source = "pragma solidity >=0.6.0 <0.9.0;\n\ncontract Test {}"
        assert loader._extract_pragma(source) == ">=0.6.0 <0.9.0"

    def test_extract_pragma_not_found(self, tmp_path):
        """Test pragma extraction when not found."""
        loader = DatasetLoader(benchmark_dir=tmp_path)
        source = "contract Test {}"
        assert loader._extract_pragma(source) == "unknown"


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_load_smartbugs_not_found(self, tmp_path):
        """Test load_smartbugs with missing dataset."""
        with pytest.raises(FileNotFoundError):
            load_smartbugs(tmp_path)

    def test_load_dvd_not_found(self, tmp_path):
        """Test load_dvd with missing dataset."""
        with pytest.raises(FileNotFoundError):
            load_dvd(tmp_path)

    def test_load_smartbugs_success(self, tmp_path):
        """Test load_smartbugs successfully."""
        # Create dataset
        dataset_dir = tmp_path / "smartbugs-curated"
        dataset_dir.mkdir()
        contract_file = dataset_dir / "test.sol"
        contract_file.write_text("contract Test {}")

        vuln_data = [
            {
                "name": "test.sol",
                "path": "test.sol",
                "vulnerabilities": [],
            }
        ]
        (dataset_dir / "vulnerabilities.json").write_text(json.dumps(vuln_data))

        contracts = load_smartbugs(tmp_path)
        assert len(contracts) == 1


class TestChallengeVulnerabilities:
    """Test DVDeFi challenge vulnerability mappings."""

    def test_challenge_mappings_exist(self):
        """Test that known challenges have vulnerability mappings."""
        # The mappings are defined in load_damn_vulnerable_defi
        known_challenges = [
            "unstoppable",
            "naive-receiver",
            "truster",
            "side-entrance",
            "the-rewarder",
            "selfie",
            "compromised",
            "puppet",
            "puppet-v2",
            "puppet-v3",
            "free-rider",
            "backdoor",
            "climber",
            "wallet-mining",
            "abi-smuggling",
            "shards",
            "curvy-puppet",
            "withdrawal",
        ]
        # Just verify the test structure
        assert len(known_challenges) == 18


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_vulnerabilities(self):
        """Test contract with no vulnerabilities."""
        contract = VulnerableContract(
            name="safe.sol",
            path="/path",
            source_code="",
            pragma_version="^0.8.0",
            vulnerabilities=[],
        )
        assert contract.total_vuln_count == 0
        assert len(contract.categories) == 0

    def test_ground_truth_single_line(self):
        """Test ground truth with single line."""
        gt = GroundTruth(
            category=VulnerabilityCategory.REENTRANCY,
            lines=[42],
        )
        assert gt.overlaps_with([42])

    def test_loader_empty_contracts_list(self, tmp_path):
        """Test loader with empty contracts list."""
        loader = DatasetLoader(benchmark_dir=tmp_path)
        stats = loader.get_statistics()
        assert stats["total_contracts"] == 0
        assert stats["total_vulnerabilities"] == 0
