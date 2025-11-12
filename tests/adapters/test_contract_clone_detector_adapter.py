"""
Comprehensive Test Suite for ContractCloneDetectorAdapter
==========================================================

Tests for Contract Clone Detector adapter (Layer 6 - ML-Based Detection).

Autor: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Fecha: November 11, 2025
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch

from src.adapters.contract_clone_detector_adapter import ContractCloneDetectorAdapter


# Sample Solidity contracts for testing
SAMPLE_CONTRACT_1 = """
pragma solidity ^0.8.0;

contract TokenSale {
    address public owner;
    uint256 public price;
    mapping(address => uint256) public balances;

    event Purchase(address buyer, uint256 amount);
    event Withdrawal(address owner, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(uint256 _price) {
        owner = msg.sender;
        price = _price;
    }

    function buyTokens() public payable {
        require(msg.value >= price, "Insufficient payment");
        uint256 tokens = msg.value / price;
        balances[msg.sender] += tokens;
        emit Purchase(msg.sender, tokens);
    }

    function withdraw() public onlyOwner {
        uint256 balance = address(this).balance;
        payable(owner).transfer(balance);
        emit Withdrawal(owner, balance);
    }
}
"""

# Exact clone (Type-1)
SAMPLE_CONTRACT_CLONE_EXACT = """
pragma solidity ^0.8.0;

contract TokenSale {
    address public owner;
    uint256 public price;
    mapping(address => uint256) public balances;

    event Purchase(address buyer, uint256 amount);
    event Withdrawal(address owner, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(uint256 _price) {
        owner = msg.sender;
        price = _price;
    }

    function buyTokens() public payable {
        require(msg.value >= price, "Insufficient payment");
        uint256 tokens = msg.value / price;
        balances[msg.sender] += tokens;
        emit Purchase(msg.sender, tokens);
    }

    function withdraw() public onlyOwner {
        uint256 balance = address(this).balance;
        payable(owner).transfer(balance);
        emit Withdrawal(owner, balance);
    }
}
"""

# Renamed clone (Type-2)
SAMPLE_CONTRACT_CLONE_RENAMED = """
pragma solidity ^0.8.0;

contract CoinSale {
    address public admin;
    uint256 public cost;
    mapping(address => uint256) public holdings;

    event Buy(address purchaser, uint256 qty);
    event Collect(address admin, uint256 qty);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor(uint256 _cost) {
        admin = msg.sender;
        cost = _cost;
    }

    function purchaseCoins() public payable {
        require(msg.value >= cost, "Insufficient payment");
        uint256 coins = msg.value / cost;
        holdings[msg.sender] += coins;
        emit Buy(msg.sender, coins);
    }

    function collect() public onlyAdmin {
        uint256 funds = address(this).balance;
        payable(admin).transfer(funds);
        emit Collect(admin, funds);
    }
}
"""

# Different contract (low similarity)
SAMPLE_DIFFERENT_CONTRACT = """
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private value;

    function store(uint256 newValue) public {
        value = newValue;
    }

    function retrieve() public view returns (uint256) {
        return value;
    }
}
"""


class TestContractCloneDetectorProtocol:
    """Test that ContractCloneDetectorAdapter implements required protocol"""

    def test_clone_detector_has_metadata(self):
        """Verify ContractCloneDetectorAdapter provides complete metadata"""
        adapter = ContractCloneDetectorAdapter()
        metadata = adapter.METADATA

        assert metadata["name"] == "contract_clone_detector"
        assert metadata["version"] == "1.0.0"
        assert metadata["category"] == "ml-based"
        assert metadata["is_optional"] is True
        assert "python" in metadata["requires"]
        assert "solidity" in metadata["supported_languages"]

    def test_clone_detector_is_optional(self):
        """DPGA compliance: Clone Detector must be optional"""
        adapter = ContractCloneDetectorAdapter()
        assert adapter.METADATA["is_optional"] is True

    def test_clone_detector_has_detection_types(self):
        """Verify Clone Detector declares its detection types"""
        adapter = ContractCloneDetectorAdapter()
        detection_types = adapter.METADATA["detection_types"]

        assert "exact_clone" in detection_types  # Type-1
        assert "renamed_clone" in detection_types  # Type-2
        assert "near_miss_clone" in detection_types  # Type-3
        assert "semantic_clone" in detection_types  # Type-4

    def test_clone_detector_has_similarity_methods(self):
        """Verify Clone Detector declares supported similarity methods"""
        adapter = ContractCloneDetectorAdapter()
        methods = adapter.METADATA["similarity_methods"]

        assert "token_based" in methods
        assert "ast_based" in methods
        assert "metric_based" in methods
        assert "hybrid" in methods


class TestContractCloneDetectorAvailability:
    """Test Clone Detector availability checking"""

    def test_clone_detector_always_available(self):
        """Test that Clone Detector is always available (pure Python)"""
        adapter = ContractCloneDetectorAdapter()
        status = adapter.check_availability()

        assert status["available"] is True
        assert status["version"] == "1.0.0"
        assert "token_based" in status["methods_available"]
        assert status["malicious_db_size"] >= 0

    def test_clone_detector_no_external_dependencies(self):
        """Test that Clone Detector requires no external dependencies"""
        adapter = ContractCloneDetectorAdapter()
        status = adapter.check_availability()

        # Should always be available (pure Python, no dependencies)
        assert status["available"] is True


class TestContractCloneDetectorAnalysis:
    """Test Contract Clone Detector analysis functionality"""

    def test_clone_detector_basic_analysis(self):
        """Test basic clone detection analysis"""
        adapter = ContractCloneDetectorAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_CONTRACT_1)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            assert result["success"] is True
            assert "contract_hash" in result
            assert "is_malicious" in result
            assert "uniqueness_score" in result
            assert "findings" in result
            assert result["dpga_compliant"] is True

        finally:
            os.unlink(contract_path)

    def test_clone_detector_exact_clone_detection(self):
        """Test detection of exact clones (Type-1)"""
        adapter = ContractCloneDetectorAdapter()

        # Create two identical contracts
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f1:
            f1.write(SAMPLE_CONTRACT_1)
            contract1_path = f1.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f2:
            f2.write(SAMPLE_CONTRACT_CLONE_EXACT)
            contract2_path = f2.name

        try:
            result = adapter.analyze(contract1_path, comparison_contracts=[contract2_path])

            assert result["success"] is True
            assert len(result["clones_found"]) > 0

            # Should detect very high similarity
            clone = result["clones_found"][0]
            assert clone["similarity"] > 0.95
            assert "Type-1" in clone["clone_type"] or "Type-2" in clone["clone_type"]

        finally:
            os.unlink(contract1_path)
            os.unlink(contract2_path)

    def test_clone_detector_renamed_clone_detection(self):
        """Test detection of renamed clones (Type-2)"""
        adapter = ContractCloneDetectorAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f1:
            f1.write(SAMPLE_CONTRACT_1)
            contract1_path = f1.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f2:
            f2.write(SAMPLE_CONTRACT_CLONE_RENAMED)
            contract2_path = f2.name

        try:
            result = adapter.analyze(contract1_path, comparison_contracts=[contract2_path])

            assert result["success"] is True
            # Should detect high similarity (renamed variables but same structure)
            assert len(result["clones_found"]) > 0

        finally:
            os.unlink(contract1_path)
            os.unlink(contract2_path)

    def test_clone_detector_different_contracts(self):
        """Test that different contracts have low similarity"""
        adapter = ContractCloneDetectorAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f1:
            f1.write(SAMPLE_CONTRACT_1)
            contract1_path = f1.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f2:
            f2.write(SAMPLE_DIFFERENT_CONTRACT)
            contract2_path = f2.name

        try:
            result = adapter.analyze(contract1_path, comparison_contracts=[contract2_path])

            assert result["success"] is True
            # Should have low similarity
            if result["clones_found"]:
                assert result["clones_found"][0]["similarity"] < 0.85

        finally:
            os.unlink(contract1_path)
            os.unlink(contract2_path)

    def test_clone_detector_uniqueness_score(self):
        """Test uniqueness score calculation"""
        adapter = ContractCloneDetectorAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_CONTRACT_1)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            assert "uniqueness_score" in result
            assert 0.0 <= result["uniqueness_score"] <= 1.0
            # No comparison contracts, should be unique
            assert result["uniqueness_score"] == 1.0

        finally:
            os.unlink(contract_path)

    def test_clone_detector_file_not_found(self):
        """Test analysis when contract file not found"""
        adapter = ContractCloneDetectorAdapter()
        result = adapter.analyze("/nonexistent/path/to/contract.sol")

        assert result["success"] is False
        assert "not found" in result["error"]
        assert result["findings"] == []


class TestContractCloneDetectorNormalization:
    """Test code normalization functionality"""

    def test_normalize_removes_comments(self):
        """Test that code normalization removes comments"""
        adapter = ContractCloneDetectorAdapter()

        code_with_comments = """
        // Single line comment
        pragma solidity ^0.8.0;

        /* Multi-line
           comment */
        contract Test {
            function foo() public {}  // Inline comment
        }
        """

        normalized = adapter._normalize_code(code_with_comments)

        assert "//" not in normalized
        assert "/*" not in normalized
        assert "*/" not in normalized

    def test_normalize_removes_whitespace(self):
        """Test that code normalization removes extra whitespace"""
        adapter = ContractCloneDetectorAdapter()

        code_with_whitespace = """
        pragma    solidity   ^0.8.0;

        contract    Test    {
            uint256    public    value;
        }
        """

        normalized = adapter._normalize_code(code_with_whitespace)

        # Should not have multiple consecutive spaces
        assert "    " not in normalized

    def test_normalize_removes_spdx_licenses(self):
        """Test that code normalization removes SPDX licenses"""
        adapter = ContractCloneDetectorAdapter()

        code_with_license = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract Test {}
        """

        normalized = adapter._normalize_code(code_with_license)

        assert "SPDX" not in normalized


class TestContractCloneDetectorSimilarity:
    """Test similarity calculation methods"""

    def test_jaccard_similarity_identical(self):
        """Test Jaccard similarity on identical text"""
        adapter = ContractCloneDetectorAdapter()

        text = "function foo() public returns (uint256)"
        similarity = adapter._jaccard_similarity(text, text)

        assert similarity == 1.0

    def test_jaccard_similarity_completely_different(self):
        """Test Jaccard similarity on completely different text"""
        adapter = ContractCloneDetectorAdapter()

        text1 = "function foo() public"
        text2 = "contract Bar storage"
        similarity = adapter._jaccard_similarity(text1, text2)

        assert similarity < 0.5

    def test_metric_similarity_same_contract(self):
        """Test metric-based similarity on same contract"""
        adapter = ContractCloneDetectorAdapter()

        features = adapter._extract_features(SAMPLE_CONTRACT_1)
        similarity = adapter._metric_similarity(features, features)

        assert similarity == 1.0

    def test_metric_similarity_different_contracts(self):
        """Test metric-based similarity on different contracts"""
        adapter = ContractCloneDetectorAdapter()

        features1 = adapter._extract_features(SAMPLE_CONTRACT_1)
        features2 = adapter._extract_features(SAMPLE_DIFFERENT_CONTRACT)
        similarity = adapter._metric_similarity(features1, features2)

        assert similarity < 1.0


class TestContractCloneDetectorFeatures:
    """Test feature extraction from contracts"""

    def test_extract_basic_metrics(self):
        """Test extraction of basic code metrics"""
        adapter = ContractCloneDetectorAdapter()
        features = adapter._extract_features(SAMPLE_CONTRACT_1)

        assert "loc" in features
        assert "num_functions" in features
        assert "num_modifiers" in features
        assert "num_events" in features

        assert features["loc"] > 0
        assert features["num_functions"] >= 2  # buyTokens, withdraw
        assert features["num_modifiers"] >= 1  # onlyOwner
        assert features["num_events"] >= 2  # Purchase, Withdrawal

    def test_extract_function_signatures(self):
        """Test extraction of function signatures"""
        adapter = ContractCloneDetectorAdapter()
        features = adapter._extract_features(SAMPLE_CONTRACT_1)

        assert "function_names" in features
        assert "buyTokens" in features["function_names"]
        assert "withdraw" in features["function_names"]

    def test_extract_event_signatures(self):
        """Test extraction of event signatures"""
        adapter = ContractCloneDetectorAdapter()
        features = adapter._extract_features(SAMPLE_CONTRACT_1)

        assert "event_names" in features
        assert "Purchase" in features["event_names"]
        assert "Withdrawal" in features["event_names"]

    def test_extract_complexity_indicators(self):
        """Test extraction of complexity indicators"""
        adapter = ContractCloneDetectorAdapter()

        code_with_assembly = """
        pragma solidity ^0.8.0;
        contract Test {
            function foo() public {
                assembly {
                    let x := 1
                }
            }
        }
        """

        features = adapter._extract_features(code_with_assembly)

        assert "has_assembly" in features
        assert features["has_assembly"] == 1


class TestContractCloneDetectorClassification:
    """Test clone type classification"""

    def test_classify_exact_clone(self):
        """Test classification of exact clones (Type-1)"""
        adapter = ContractCloneDetectorAdapter()

        clone_type = adapter._classify_clone_type(0.995)
        assert "Type-1" in clone_type
        assert "Exact" in clone_type

    def test_classify_renamed_clone(self):
        """Test classification of renamed clones (Type-2)"""
        adapter = ContractCloneDetectorAdapter()

        clone_type = adapter._classify_clone_type(0.97)
        assert "Type-2" in clone_type
        assert "Renamed" in clone_type

    def test_classify_near_miss_clone(self):
        """Test classification of near-miss clones (Type-3)"""
        adapter = ContractCloneDetectorAdapter()

        clone_type = adapter._classify_clone_type(0.90)
        assert "Type-3" in clone_type
        assert "Near-Miss" in clone_type

    def test_classify_semantic_clone(self):
        """Test classification of semantic clones (Type-4)"""
        adapter = ContractCloneDetectorAdapter()

        clone_type = adapter._classify_clone_type(0.70)
        assert "Type-4" in clone_type
        assert "Semantic" in clone_type


class TestContractCloneDetectorFindings:
    """Test security findings generation"""

    def test_generate_findings_unique_contract(self):
        """Test findings for unique contract"""
        adapter = ContractCloneDetectorAdapter()

        result = {
            "success": True,
            "contract_hash": "abc123",
            "is_malicious": False,
            "malicious_match": None,
            "clones_found": [],
            "uniqueness_score": 1.0
        }

        findings = adapter._generate_findings(result)

        # Should have minimal findings (unique contract)
        assert isinstance(findings, list)

    def test_generate_findings_low_uniqueness(self):
        """Test findings for low uniqueness contract"""
        adapter = ContractCloneDetectorAdapter()

        result = {
            "success": True,
            "contract_hash": "abc123",
            "is_malicious": False,
            "malicious_match": None,
            "clones_found": [{"similarity": 0.95, "clone_type": "Type-2"}],
            "uniqueness_score": 0.05
        }

        findings = adapter._generate_findings(result)

        # Should have low uniqueness finding
        assert len(findings) >= 1
        low_uniqueness_findings = [f for f in findings if f["type"] == "low_uniqueness"]
        assert len(low_uniqueness_findings) > 0

    def test_generate_findings_clones_detected(self):
        """Test findings when clones are detected"""
        adapter = ContractCloneDetectorAdapter()

        result = {
            "success": True,
            "contract_hash": "abc123",
            "is_malicious": False,
            "malicious_match": None,
            "clones_found": [
                {"similarity": 0.95, "clone_type": "Type-2"},
                {"similarity": 0.90, "clone_type": "Type-3"}
            ],
            "uniqueness_score": 0.05
        }

        findings = adapter._generate_findings(result)

        # Should have similar contracts finding
        clone_findings = [f for f in findings if f["type"] == "similar_contracts_found"]
        assert len(clone_findings) > 0
        assert clone_findings[0]["num_clones"] == 2


class TestContractCloneDetectorConfiguration:
    """Test Clone Detector configuration"""

    def test_default_configuration(self):
        """Test default configuration"""
        adapter = ContractCloneDetectorAdapter()

        assert adapter.similarity_threshold == 0.85
        assert adapter.check_malicious_db is True
        assert "token_based" in adapter.methods

    def test_custom_similarity_threshold(self):
        """Test custom similarity threshold"""
        adapter = ContractCloneDetectorAdapter(config={"similarity_threshold": 0.90})
        assert adapter.similarity_threshold == 0.90

    def test_disable_malicious_db_check(self):
        """Test disabling malicious database check"""
        adapter = ContractCloneDetectorAdapter(config={"check_malicious_db": False})
        assert adapter.check_malicious_db is False

    def test_custom_methods(self):
        """Test custom similarity methods"""
        adapter = ContractCloneDetectorAdapter(config={"methods": ["token_based", "ast_based"]})
        assert "token_based" in adapter.methods
        assert "ast_based" in adapter.methods


class TestContractCloneDetectorDPGACompliance:
    """Test DPGA compliance requirements"""

    def test_clone_detector_is_optional(self):
        """DPGA: Clone Detector must be marked as optional"""
        adapter = ContractCloneDetectorAdapter()
        assert adapter.METADATA["is_optional"] is True

    def test_clone_detector_no_external_dependencies(self):
        """DPGA: Clone Detector must work without external dependencies"""
        adapter = ContractCloneDetectorAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_CONTRACT_1)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            assert result["success"] is True
            assert result["dpga_compliant"] is True

        finally:
            os.unlink(contract_path)

    def test_graceful_degradation_on_error(self):
        """DPGA: System must handle errors gracefully"""
        adapter = ContractCloneDetectorAdapter()

        # Test with non-existent file
        result = adapter.analyze("/nonexistent/file.sol")

        # Should not raise exception
        assert result["success"] is False
        assert isinstance(result, dict)
        assert "error" in result

    def test_zero_cost(self):
        """DPGA: Clone Detector must be free (no costs)"""
        # No cost field in metadata means zero cost (all local execution)
        adapter = ContractCloneDetectorAdapter()
        assert "cost" not in adapter.METADATA or adapter.METADATA.get("cost", 0) == 0


class TestContractCloneDetectorHashCalculation:
    """Test contract hash calculation"""

    def test_hash_calculation(self):
        """Test hash calculation for contracts"""
        adapter = ContractCloneDetectorAdapter()

        hash1 = adapter._calculate_hash(SAMPLE_CONTRACT_1)
        hash2 = adapter._calculate_hash(SAMPLE_CONTRACT_1)

        # Same contract should produce same hash
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 produces 64 hex characters

    def test_different_contracts_different_hashes(self):
        """Test that different contracts produce different hashes"""
        adapter = ContractCloneDetectorAdapter()

        hash1 = adapter._calculate_hash(SAMPLE_CONTRACT_1)
        hash2 = adapter._calculate_hash(SAMPLE_DIFFERENT_CONTRACT)

        assert hash1 != hash2


class TestContractCloneDetectorMaliciousDetection:
    """Test malicious contract detection"""

    def test_known_malicious_contracts_database(self):
        """Test that known malicious contracts database exists"""
        adapter = ContractCloneDetectorAdapter()

        assert hasattr(adapter, "KNOWN_MALICIOUS_HASHES")
        assert isinstance(adapter.KNOWN_MALICIOUS_HASHES, dict)
        assert len(adapter.KNOWN_MALICIOUS_HASHES) >= 0

    def test_malicious_contract_detection_in_results(self):
        """Test that malicious contract detection is included in results"""
        adapter = ContractCloneDetectorAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_CONTRACT_1)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            assert "is_malicious" in result
            assert isinstance(result["is_malicious"], bool)

        finally:
            os.unlink(contract_path)


class TestContractCloneDetectorPerformance:
    """Test Clone Detector performance characteristics"""

    def test_analysis_completes_quickly(self):
        """Test that analysis completes in reasonable time"""
        import time

        adapter = ContractCloneDetectorAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_CONTRACT_1)
            contract_path = f.name

        try:
            start = time.time()
            result = adapter.analyze(contract_path)
            duration = time.time() - start

            assert result["success"] is True
            # Should complete in less than 2 seconds
            assert duration < 2.0

        finally:
            os.unlink(contract_path)

    def test_comparison_with_multiple_contracts(self):
        """Test performance with multiple comparison contracts"""
        import time

        adapter = ContractCloneDetectorAdapter()

        # Create main contract
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f1:
            f1.write(SAMPLE_CONTRACT_1)
            contract1_path = f1.name

        # Create comparison contracts
        comparison_files = []
        for i in range(5):
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                f.write(SAMPLE_CONTRACT_CLONE_RENAMED)
                comparison_files.append(f.name)

        try:
            start = time.time()
            result = adapter.analyze(contract1_path, comparison_contracts=comparison_files)
            duration = time.time() - start

            assert result["success"] is True
            # Should complete reasonably fast even with multiple comparisons
            assert duration < 5.0

        finally:
            os.unlink(contract1_path)
            for f in comparison_files:
                os.unlink(f)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
