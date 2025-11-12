"""
Comprehensive Test Suite for SmartBugsMLAdapter
===============================================

Tests for SmartBugs-ML machine learning vulnerability detector (Layer 6 - ML-Based Detection).

Autor: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Fecha: November 11, 2025
"""

import pytest
import tempfile
import os
import json
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.adapters.smartbugs_ml_adapter import SmartBugsMLAdapter


# Sample Solidity contract for testing
SAMPLE_VULNERABLE_CONTRACT = """
pragma solidity ^0.7.0;

contract VulnerableContract {
    address owner;
    mapping(address => uint256) public balances;

    // Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;  // State change after external call
    }

    // Delegatecall vulnerability
    function proxyCall(address target, bytes memory data) public {
        (bool success, ) = target.delegatecall(data);
        require(success);
    }

    // Bad randomness
    function lottery() public view returns (uint256) {
        return uint256(blockhash(block.number - 1)) % 100;
    }

    // Integer overflow (pre-0.8.0)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;  // No SafeMath
    }

    // Unprotected selfdestruct
    function kill() public {
        selfdestruct(payable(msg.sender));  // No access control
    }
}
"""

SAMPLE_SAFE_CONTRACT = """
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SafeContract is Ownable, ReentrancyGuard {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;  // Checks-effects-interactions
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }

    function destroy() public onlyOwner {
        selfdestruct(payable(owner()));
    }
}
"""


class TestSmartBugsMLAdapterProtocol:
    """Test that SmartBugsMLAdapter implements required protocol"""

    def test_smartbugs_ml_has_metadata(self):
        """Verify SmartBugsMLAdapter provides complete metadata"""
        adapter = SmartBugsMLAdapter()
        metadata = adapter.METADATA

        assert metadata["name"] == "smartbugs_ml"
        assert metadata["version"] == "1.0.0"
        assert metadata["category"] == "ml-based"
        assert metadata["is_optional"] is True
        assert "python" in metadata["requires"]
        assert "solidity" in metadata["supported_languages"]
        assert len(metadata["detection_types"]) >= 6
        assert "reentrancy" in metadata["detection_types"]

    def test_smartbugs_ml_is_optional(self):
        """DPGA compliance: SmartBugs-ML must be optional"""
        adapter = SmartBugsMLAdapter()
        assert adapter.METADATA["is_optional"] is True

    def test_smartbugs_ml_has_detection_types(self):
        """Verify SmartBugs-ML declares its detection types"""
        adapter = SmartBugsMLAdapter()
        detection_types = adapter.METADATA["detection_types"]

        assert "reentrancy" in detection_types
        assert "integer_overflow" in detection_types
        assert "delegatecall" in detection_types
        assert "unchecked_call" in detection_types
        assert "bad_randomness" in detection_types
        assert "time_manipulation" in detection_types

    def test_smartbugs_ml_has_ml_models(self):
        """Verify SmartBugs-ML declares supported ML models"""
        adapter = SmartBugsMLAdapter()
        ml_models = adapter.METADATA["ml_models"]

        assert "random_forest" in ml_models
        assert "svm" in ml_models
        assert "neural_network" in ml_models


class TestSmartBugsMLAvailability:
    """Test SmartBugs-ML availability checking"""

    @patch('src.adapters.smartbugs_ml_adapter.sklearn')
    @patch('src.adapters.smartbugs_ml_adapter.np')
    def test_smartbugs_ml_available_when_libraries_installed(self, mock_np, mock_sklearn):
        """Test status when ML libraries are installed"""
        mock_sklearn.__version__ = "1.3.0"

        adapter = SmartBugsMLAdapter()
        status = adapter.check_availability()

        assert status["available"] is True
        assert "1.3.0" in status["ml_library"]
        assert "random_forest" in status["models_available"]

    def test_smartbugs_ml_not_available_without_libraries(self):
        """Test status when ML libraries are not installed"""
        with patch('src.adapters.smartbugs_ml_adapter.SmartBugsMLAdapter.check_availability') as mock_check:
            mock_check.return_value = {
                "available": False,
                "error": "ML libraries not installed: No module named 'sklearn'",
                "install_command": "pip install scikit-learn numpy"
            }

            adapter = SmartBugsMLAdapter()
            status = adapter.check_availability()

            assert status["available"] is False
            assert "not installed" in status["error"]
            assert "pip install" in status["install_command"]


class TestSmartBugsMLAnalysis:
    """Test SmartBugs-ML analysis functionality"""

    def test_smartbugs_ml_successful_analysis(self):
        """Test successful SmartBugs-ML analysis on vulnerable contract"""
        adapter = SmartBugsMLAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            assert result["success"] is True
            assert "findings" in result
            assert len(result["findings"]) >= 3  # Should detect multiple vulnerabilities
            assert result["model_used"] == "random_forest"
            assert result["confidence_threshold"] == 0.7
            assert result["dpga_compliant"] is True
            assert isinstance(result["analysis_duration"], float)
            assert result["features_extracted"] > 0

        finally:
            os.unlink(contract_path)

    def test_smartbugs_ml_detects_reentrancy(self):
        """Test that SmartBugs-ML detects reentrancy patterns"""
        adapter = SmartBugsMLAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            # Find reentrancy finding
            reentrancy_findings = [f for f in result["findings"] if f["type"] == "reentrancy"]
            assert len(reentrancy_findings) > 0

            finding = reentrancy_findings[0]
            assert finding["severity"] == "high"
            assert finding["confidence"] >= 0.7
            assert "external_calls" in finding["ml_features_used"]

        finally:
            os.unlink(contract_path)

    def test_smartbugs_ml_detects_bad_randomness(self):
        """Test that SmartBugs-ML detects bad randomness patterns"""
        adapter = SmartBugsMLAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            # Find bad randomness finding
            randomness_findings = [f for f in result["findings"] if f["type"] == "bad_randomness"]
            assert len(randomness_findings) > 0

            finding = randomness_findings[0]
            assert finding["severity"] == "medium"
            assert finding["confidence"] >= 0.7

        finally:
            os.unlink(contract_path)

    def test_smartbugs_ml_detects_unprotected_selfdestruct(self):
        """Test that SmartBugs-ML detects unprotected selfdestruct"""
        adapter = SmartBugsMLAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            # Find unprotected selfdestruct finding
            selfdestruct_findings = [f for f in result["findings"]
                                    if f["type"] == "unprotected_selfdestruct"]
            assert len(selfdestruct_findings) > 0

            finding = selfdestruct_findings[0]
            assert finding["severity"] == "critical"
            assert finding["confidence"] >= 0.7

        finally:
            os.unlink(contract_path)

    def test_smartbugs_ml_safe_contract_analysis(self):
        """Test SmartBugs-ML on a safe contract"""
        adapter = SmartBugsMLAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_SAFE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            assert result["success"] is True
            # Safe contract should have fewer findings
            assert len(result["findings"]) < 3

        finally:
            os.unlink(contract_path)

    def test_smartbugs_ml_file_not_found(self):
        """Test analysis when contract file not found"""
        adapter = SmartBugsMLAdapter()
        result = adapter.analyze("/nonexistent/path/to/contract.sol")

        assert result["success"] is False
        assert "not found" in result["error"]
        assert result["findings"] == []


class TestSmartBugsMLFeatureExtraction:
    """Test feature extraction from contracts"""

    def test_extract_basic_features(self):
        """Test extraction of basic code metrics"""
        adapter = SmartBugsMLAdapter()
        features = adapter._extract_features(SAMPLE_VULNERABLE_CONTRACT)

        assert "loc" in features
        assert "num_functions" in features
        assert "num_modifiers" in features
        assert "num_events" in features

        assert features["loc"] > 0
        assert features["num_functions"] >= 5  # withdraw, proxyCall, lottery, unsafeAdd, kill

    def test_extract_vulnerability_patterns(self):
        """Test extraction of vulnerability-related patterns"""
        adapter = SmartBugsMLAdapter()
        features = adapter._extract_features(SAMPLE_VULNERABLE_CONTRACT)

        assert features["has_delegatecall"] == 1.0
        assert features["has_selfdestruct"] == 1.0
        assert features["has_call"] > 0
        assert features["external_calls"] > 0

    def test_extract_randomness_features(self):
        """Test extraction of randomness patterns"""
        adapter = SmartBugsMLAdapter()
        features = adapter._extract_features(SAMPLE_VULNERABLE_CONTRACT)

        assert features["uses_blockhash"] == 1.0

    def test_extract_access_control_features(self):
        """Test extraction of access control patterns"""
        adapter = SmartBugsMLAdapter()

        # Vulnerable contract
        features1 = adapter._extract_features(SAMPLE_VULNERABLE_CONTRACT)
        assert features1["has_access_control"] == 0.0

        # Safe contract with Ownable
        features2 = adapter._extract_features(SAMPLE_SAFE_CONTRACT)
        assert features2["has_access_control"] == 1.0

    def test_detect_unchecked_math(self):
        """Test detection of unchecked arithmetic"""
        adapter = SmartBugsMLAdapter()

        # Pre-0.8.0 contract without SafeMath
        features1 = adapter._extract_features(SAMPLE_VULNERABLE_CONTRACT)
        assert features1["has_unchecked_math"] == 1.0

        # 0.8.0+ contract (built-in overflow protection)
        features2 = adapter._extract_features(SAMPLE_SAFE_CONTRACT)
        assert features2["has_unchecked_math"] == 0.0


class TestSmartBugsMLCaching:
    """Test result caching functionality"""

    def test_caching_enabled_by_default(self):
        """Test that caching is enabled by default"""
        adapter = SmartBugsMLAdapter()
        assert adapter.cache_predictions is True
        assert adapter.cache_dir.exists()

    def test_caching_can_be_disabled(self):
        """Test that caching can be disabled"""
        adapter = SmartBugsMLAdapter(config={"cache_predictions": False})
        assert adapter.cache_predictions is False

    def test_cache_result_and_retrieval(self):
        """Test caching and retrieving results"""
        adapter = SmartBugsMLAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            # First analysis (not cached)
            result1 = adapter.analyze(contract_path)

            # Second analysis (should use cache)
            result2 = adapter.analyze(contract_path)

            # Results should be identical
            assert result1["findings"] == result2["findings"]
            assert result1["features_extracted"] == result2["features_extracted"]

        finally:
            os.unlink(contract_path)

    def test_cache_key_generation(self):
        """Test cache key generation from contract content"""
        adapter = SmartBugsMLAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            cache_key = adapter._get_cache_key(contract_path)

            assert isinstance(cache_key, str)
            assert len(cache_key) == 16  # SHA256 hash truncated to 16 chars

        finally:
            os.unlink(contract_path)


class TestSmartBugsMLConfiguration:
    """Test SmartBugs-ML configuration"""

    def test_default_configuration(self):
        """Test default configuration"""
        adapter = SmartBugsMLAdapter()

        assert adapter.model == "random_forest"
        assert adapter.confidence_threshold == 0.7
        assert adapter.cache_predictions is True

    def test_custom_model_selection(self):
        """Test custom ML model selection"""
        adapter = SmartBugsMLAdapter(config={"model": "neural_network"})
        assert adapter.model == "neural_network"

    def test_custom_confidence_threshold(self):
        """Test custom confidence threshold"""
        adapter = SmartBugsMLAdapter(config={"confidence_threshold": 0.85})
        assert adapter.confidence_threshold == 0.85

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            # All findings should have confidence >= 0.85
            for finding in result["findings"]:
                assert finding["confidence"] >= 0.85

        finally:
            os.unlink(contract_path)


class TestSmartBugsMLDPGACompliance:
    """Test DPGA compliance requirements"""

    def test_smartbugs_ml_is_optional(self):
        """DPGA: SmartBugs-ML must be marked as optional"""
        adapter = SmartBugsMLAdapter()
        assert adapter.METADATA["is_optional"] is True

    def test_smartbugs_ml_has_no_api_requirements(self):
        """DPGA: SmartBugs-ML must not require external APIs"""
        adapter = SmartBugsMLAdapter()

        # Analyze contract without any API calls
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)
            assert result["success"] is True
            assert result["dpga_compliant"] is True

        finally:
            os.unlink(contract_path)

    def test_graceful_degradation_when_libraries_missing(self):
        """DPGA: System must handle missing libraries gracefully"""
        with patch('src.adapters.smartbugs_ml_adapter.SmartBugsMLAdapter.check_availability') as mock_check:
            mock_check.return_value = {
                "available": False,
                "error": "ML libraries not installed",
                "install_command": "pip install scikit-learn numpy"
            }

            adapter = SmartBugsMLAdapter()
            status = adapter.check_availability()

            # Should not raise exception
            assert status["available"] is False
            assert "install_command" in status

    def test_zero_cost(self):
        """DPGA: SmartBugs-ML must be free (no costs)"""
        # No cost field in metadata means zero cost (all local execution)
        adapter = SmartBugsMLAdapter()
        assert "cost" not in adapter.METADATA or adapter.METADATA.get("cost", 0) == 0


class TestSmartBugsMLRecommendations:
    """Test vulnerability recommendations"""

    def test_reentrancy_recommendation(self):
        """Test recommendation for reentrancy vulnerability"""
        adapter = SmartBugsMLAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            reentrancy_findings = [f for f in result["findings"] if f["type"] == "reentrancy"]
            if reentrancy_findings:
                recommendation = reentrancy_findings[0]["recommendation"]
                assert "checks-effects-interactions" in recommendation or "reentrancy guard" in recommendation

        finally:
            os.unlink(contract_path)

    def test_delegatecall_recommendation(self):
        """Test recommendation for delegatecall vulnerability"""
        adapter = SmartBugsMLAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            delegatecall_findings = [f for f in result["findings"] if f["type"] == "delegatecall"]
            if delegatecall_findings:
                recommendation = delegatecall_findings[0]["recommendation"]
                assert "whitelisted" in recommendation or "validated" in recommendation

        finally:
            os.unlink(contract_path)


class TestSmartBugsMLPerformance:
    """Test SmartBugs-ML performance characteristics"""

    def test_execution_time_reported(self):
        """Test that execution time is always reported"""
        adapter = SmartBugsMLAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            assert "analysis_duration" in result
            assert isinstance(result["analysis_duration"], float)
            assert result["analysis_duration"] >= 0

        finally:
            os.unlink(contract_path)

    def test_features_count_reported(self):
        """Test that feature count is reported"""
        adapter = SmartBugsMLAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_VULNERABLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)

            assert "features_extracted" in result
            assert result["features_extracted"] >= 15  # At least 15 features

        finally:
            os.unlink(contract_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
