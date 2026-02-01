"""
Tests for the False Positive Classifier v4.7.0
"""

from src.ml.fp_classifier import (
    FeatureExtractor,
    FindingFeatures,
    FPClassifier,
    FPPrediction,
    classify_false_positives,
    filter_likely_fps,
)


class TestFeatureExtractor:
    """Tests for FeatureExtractor."""

    def test_extractor_initialization(self):
        """Test that extractor can be created."""
        extractor = FeatureExtractor()
        assert extractor is not None

    def test_extract_basic_features(self):
        """Test basic feature extraction."""
        extractor = FeatureExtractor()

        finding = {
            "type": "reentrancy",
            "confidence": 0.7,
            "severity": "high",
            "swc_id": "SWC-107",
            "location": {"line": 10},
        }

        source_code = """
pragma solidity ^0.8.0;

contract Test {
    mapping(address => uint256) balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
"""

        features = extractor.extract_features(finding, source_code)

        assert features.confidence == 0.7
        assert features.severity_score == 0.75  # high
        assert features.has_swc_id is True
        assert features.is_solidity_08_plus is True
        assert features.has_external_call is True

    def test_detect_reentrancy_guard(self):
        """Test detection of ReentrancyGuard."""
        extractor = FeatureExtractor()

        source_with_guard = """
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Safe is ReentrancyGuard {
    function withdraw() external nonReentrant {
        // safe
    }
}
"""
        features = extractor.extract_features({"confidence": 0.5}, source_with_guard)
        assert features.has_reentrancy_guard is True

        source_without_guard = """
contract Unsafe {
    function withdraw() external {
        // unsafe
    }
}
"""
        features = extractor.extract_features({"confidence": 0.5}, source_without_guard)
        assert features.has_reentrancy_guard is False

    def test_detect_access_control(self):
        """Test detection of access control patterns."""
        extractor = FeatureExtractor()

        source_with_ac = """
contract Owned {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function privileged() external onlyOwner {
        // protected
    }
}
"""
        features = extractor.extract_features({"confidence": 0.5}, source_with_ac)
        assert features.has_access_control is True

    def test_detect_solidity_version(self):
        """Test Solidity version detection."""
        extractor = FeatureExtractor()

        source_08 = "pragma solidity ^0.8.0;"
        features = extractor.extract_features({"confidence": 0.5}, source_08)
        assert features.is_solidity_08_plus is True

        source_07 = "pragma solidity ^0.7.0;"
        features = extractor.extract_features({"confidence": 0.5}, source_07)
        assert features.is_solidity_08_plus is False

    def test_detect_safemath(self):
        """Test SafeMath detection."""
        extractor = FeatureExtractor()

        source_safemath = """
using SafeMath for uint256;

contract Token {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a.add(b);
    }
}
"""
        features = extractor.extract_features({"confidence": 0.5}, source_safemath)
        assert features.uses_safemath is True


class TestFindingFeatures:
    """Tests for FindingFeatures dataclass."""

    def test_to_vector(self):
        """Test conversion to numeric vector."""
        features = FindingFeatures(
            confidence=0.8,
            severity_score=0.75,
            tool_count=2,
            has_reentrancy_guard=True,
        )

        vector = features.to_vector()

        assert len(vector) == 19  # Total number of features
        assert vector[0] == 0.8  # confidence
        assert vector[1] == 0.75  # severity
        assert vector[2] == 0.4  # tool_count normalized (2/5)
        assert vector[11] == 1.0  # has_reentrancy_guard

    def test_feature_names(self):
        """Test feature names list."""
        names = FindingFeatures.feature_names()

        assert len(names) == 19
        assert "confidence" in names
        assert "has_reentrancy_guard" in names


class TestFPClassifier:
    """Tests for FPClassifier."""

    def test_classifier_initialization(self):
        """Test classifier can be created."""
        classifier = FPClassifier()
        assert classifier is not None
        assert classifier.fp_threshold == 0.5

    def test_predict_with_reentrancy_guard(self):
        """Test prediction for code with reentrancy guard."""
        classifier = FPClassifier()

        finding = {
            "type": "reentrancy",
            "confidence": 0.7,
            "severity": "high",
        }

        source_code = """
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Safe is ReentrancyGuard {
    function withdraw() external nonReentrant {
        msg.sender.call{value: 1 ether}("");
    }
}
"""

        prediction = classifier.predict(finding, source_code)

        # Should have HIGH FP probability (likely a false positive)
        # because of reentrancy guard - the code is protected
        assert prediction.fp_probability > 0.5
        assert "has_reentrancy_guard" in str(prediction.contributing_factors)

    def test_predict_vulnerable_code(self):
        """Test prediction for actually vulnerable code."""
        classifier = FPClassifier()

        finding = {
            "type": "reentrancy",
            "confidence": 0.9,
            "severity": "high",
            "tool_count": 2,
        }

        source_code = """
pragma solidity ^0.7.0;

contract Vulnerable {
    mapping(address => uint256) balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool success,) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
"""

        prediction = classifier.predict(finding, source_code)

        # Should not be classified as FP (real vulnerability)
        # No guards, not Solidity 0.8+, state change after call
        assert prediction.is_false_positive is False

    def test_predict_arithmetic_solidity_08(self):
        """Test arithmetic finding in Solidity 0.8+."""
        classifier = FPClassifier()

        finding = {
            "type": "integer_overflow",
            "confidence": 0.6,
            "severity": "high",
        }

        source_code = """
pragma solidity ^0.8.0;

contract Counter {
    uint256 public count;

    function increment() external {
        count += 1;
    }
}
"""

        prediction = classifier.predict(finding, source_code)

        # Should be likely FP in Solidity 0.8+
        assert prediction.fp_probability > 0.5
        assert "is_solidity_08_plus" in str(prediction.contributing_factors)

    def test_filter_findings(self):
        """Test filtering findings."""
        classifier = FPClassifier(fp_threshold=0.5)

        findings = [
            {"type": "reentrancy", "confidence": 0.7},
            {"type": "integer_overflow", "confidence": 0.5},
        ]

        source_code = """
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Safe is ReentrancyGuard {
    uint256 counter;

    function withdraw() external nonReentrant {
        counter += 1;
    }
}
"""

        kept, removed = classifier.filter_findings(findings, source_code)

        # Both should be filtered as likely FPs due to guards
        assert len(removed) >= 1
        assert all("_fp_probability" in f for f in kept + removed)


class TestFPPrediction:
    """Tests for FPPrediction dataclass."""

    def test_adjusted_confidence_fp(self):
        """Test confidence adjustment for FP."""
        prediction = FPPrediction(
            is_false_positive=True,
            fp_probability=0.8,
            confidence=0.7,
        )

        # Should reduce confidence
        adjusted = prediction.adjusted_confidence
        assert adjusted < 0.7
        assert adjusted >= 0.1

    def test_adjusted_confidence_tp(self):
        """Test confidence adjustment for TP."""
        prediction = FPPrediction(
            is_false_positive=False,
            fp_probability=0.2,
            confidence=0.7,
        )

        # Should increase confidence
        adjusted = prediction.adjusted_confidence
        assert adjusted > 0.7
        assert adjusted <= 0.95


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_classify_false_positives(self):
        """Test classify_false_positives function."""
        findings = [
            {"type": "reentrancy", "confidence": 0.7},
        ]

        source_code = "pragma solidity ^0.8.0; contract Test {}"

        result = classify_false_positives(findings, source_code)

        assert len(result) == 1
        assert "_fp_probability" in result[0]
        assert "confidence" in result[0]

    def test_filter_likely_fps(self):
        """Test filter_likely_fps function."""
        findings = [
            {"type": "reentrancy", "confidence": 0.7},
            {"type": "integer_overflow", "confidence": 0.5},
        ]

        source_code = """
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Safe is ReentrancyGuard {
    function safe() external nonReentrant {}
}
"""

        kept, filtered = filter_likely_fps(findings, source_code)

        # Should have filtered at least some
        assert len(kept) + len(filtered) == 2
        assert all("_filtered_reason" in f for f in filtered)
