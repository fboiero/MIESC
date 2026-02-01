"""
MIESC Integration Tests - Benchmark Pipeline
Tests for SolidiFI benchmark flow including ground truth matching and metrics.
"""

import pytest

from src.ml.correlation_engine import SmartCorrelationEngine

# ============================================================================
# Inline helpers to avoid importing solidifi_benchmark.py directly
# (it uses direct module imports that would require special path setup)
# ============================================================================


def calculate_metrics(tp, fp, fn):
    """Calculate precision, recall, F1 from TP/FP/FN counts."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


def match_ground_truth(detections, ground_truth, tolerance=10):
    """
    Match detections against ground truth to produce TP/FP/FN.

    A detection is a TP if it matches any ground truth line within tolerance.
    """
    matched_gt = set()
    true_positives = 0
    false_positives = 0

    for det in detections:
        matched = False
        for i, gt in enumerate(ground_truth):
            if i in matched_gt:
                continue
            if abs(det["line"] - gt["line"]) <= tolerance:
                true_positives += 1
                matched_gt.add(i)
                matched = True
                break
        if not matched:
            false_positives += 1

    false_negatives = len(ground_truth) - len(matched_gt)
    return true_positives, false_positives, false_negatives


# ============================================================================
# TestBenchmarkPipeline - SolidiFI benchmark flow
# ============================================================================


@pytest.mark.integration
class TestBenchmarkPipeline:
    """Integration tests for benchmark pipeline validation."""

    def test_benchmark_processes_single_contract(self):
        """Single contract analysis should return expected structure."""
        # Simulate a single contract analysis result
        from src.ml.classic_patterns import ClassicPatternDetector

        source_code = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.4.24;

        contract VulnerableBank {
            mapping(address => uint256) public balances;

            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }

            function withdraw() public {
                uint256 balance = balances[msg.sender];
                require(balance > 0);
                (bool success, ) = msg.sender.call.value(balance)("");
                require(success);
                balances[msg.sender] = 0;
            }
        }
        """

        detector = ClassicPatternDetector()
        matches = detector.detect(source_code)

        # Should produce structured output
        assert isinstance(matches, list)

        # Each match should have expected attributes
        for match in matches:
            assert hasattr(match, "line")
            assert hasattr(match, "vuln_type")
            assert hasattr(match, "severity")
            assert hasattr(match, "confidence")
            assert match.confidence >= 0.0
            assert match.confidence <= 1.0

    def test_benchmark_ground_truth_matching(self):
        """Ground truth comparison should produce TP/FP/FN counts."""
        # Simulated ground truth (from BugLog CSV)
        ground_truth = [
            {"line": 15, "type": "reentrancy"},
            {"line": 17, "type": "unchecked-send"},
        ]

        # Simulated detections
        detections = [
            {"line": 15, "type": "reentrancy", "confidence": 0.9},
            {"line": 16, "type": "reentrancy", "confidence": 0.7},  # Near match to line 17
            {"line": 30, "type": "access-control", "confidence": 0.6},  # FP
        ]

        tp, fp, fn = match_ground_truth(detections, ground_truth, tolerance=3)

        # Line 15 matches exactly -> TP
        # Line 16 is within tolerance of 17 -> TP
        # Line 30 has no ground truth -> FP
        assert tp == 2
        assert fp == 1
        assert fn == 0

    def test_benchmark_category_breakdown(self):
        """Results should be broken down by vulnerability category."""
        categories = {
            "Re-entrancy": {"tp": 5, "fp": 2, "fn": 1},
            "Overflow-Underflow": {"tp": 3, "fp": 1, "fn": 2},
            "TOD": {"tp": 1, "fp": 0, "fn": 3},
            "Timestamp-Dependency": {"tp": 2, "fp": 1, "fn": 1},
            "Unchecked-Send": {"tp": 4, "fp": 3, "fn": 0},
        }

        # Each category should have valid metrics
        for _cat_name, counts in categories.items():
            tp = counts["tp"]
            fp = counts["fp"]
            fn = counts["fn"]

            precision, recall, f1 = calculate_metrics(tp, fp, fn)

            assert 0.0 <= precision <= 1.0
            assert 0.0 <= recall <= 1.0
            assert 0.0 <= f1 <= 1.0

            # F1 should be between precision and recall (harmonic mean property)
            if precision > 0 and recall > 0:
                assert f1 <= max(precision, recall)
                assert f1 >= min(precision, recall) * 0.5  # At least half of min

    def test_benchmark_metrics_calculation(self):
        """Precision/recall/F1 should be calculated correctly from TP/FP/FN."""
        # Perfect detection
        p, r, f1 = calculate_metrics(tp=10, fp=0, fn=0)
        assert p == 1.0
        assert r == 1.0
        assert f1 == 1.0

        # No detections
        p, r, f1 = calculate_metrics(tp=0, fp=0, fn=5)
        assert p == 0.0
        assert r == 0.0
        assert f1 == 0.0

        # Mixed results
        p, r, f1 = calculate_metrics(tp=8, fp=2, fn=2)
        assert abs(p - 0.8) < 0.01
        assert abs(r - 0.8) < 0.01
        assert abs(f1 - 0.8) < 0.01

        # High precision, low recall
        p, r, f1 = calculate_metrics(tp=5, fp=0, fn=15)
        assert p == 1.0
        assert r == 0.25
        assert abs(f1 - 0.4) < 0.01

        # Low precision, high recall
        p, r, f1 = calculate_metrics(tp=10, fp=30, fn=0)
        assert abs(p - 0.25) < 0.01
        assert r == 1.0
        assert abs(f1 - 0.4) < 0.01

    def test_slither_cross_validation_adjusts_confidence(self):
        """Cross-validation should modify confidence scores."""
        engine = SmartCorrelationEngine()

        # Finding from pattern detector only (single tool)
        engine.add_findings(
            "classic-pattern-detector",
            [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "message": "Reentrancy vulnerability in withdraw()",
                    "location": {"file": "test.sol", "line": 15, "function": "withdraw"},
                    "confidence": 0.85,
                },
            ],
        )

        correlated_single = engine.correlate()
        assert len(correlated_single) >= 1

        # Single-tool reentrancy should have capped confidence (cross-validation required)
        single_conf = correlated_single[0].final_confidence
        assert single_conf <= 0.60  # SINGLE_TOOL_MAX_CONFIDENCE

        # Now add confirming tool
        engine.clear()
        engine.add_findings(
            "classic-pattern-detector",
            [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "message": "Reentrancy vulnerability in withdraw()",
                    "location": {"file": "test.sol", "line": 15, "function": "withdraw"},
                    "confidence": 0.85,
                },
            ],
        )
        engine.add_findings(
            "slither",
            [
                {
                    "type": "reentrancy-eth",
                    "severity": "high",
                    "message": "Reentrancy in withdraw() detected by Slither",
                    "location": {"file": "test.sol", "line": 15, "function": "withdraw"},
                    "confidence": 0.9,
                },
            ],
        )

        correlated_multi = engine.correlate()
        assert len(correlated_multi) >= 1

        # Find the reentrancy finding
        reentrancy = [f for f in correlated_multi if f.canonical_type == "reentrancy"]
        assert len(reentrancy) >= 1

        multi_conf = reentrancy[0].final_confidence

        # Cross-validated should have higher confidence
        assert multi_conf > single_conf


# ============================================================================
# TestBenchmarkGroundTruthEdgeCases
# ============================================================================


@pytest.mark.integration
class TestBenchmarkGroundTruthEdgeCases:
    """Edge cases in ground truth matching."""

    def test_no_detections_all_false_negatives(self):
        """No detections should produce all false negatives."""
        ground_truth = [
            {"line": 10, "type": "reentrancy"},
            {"line": 20, "type": "overflow"},
        ]
        detections = []

        tp, fp, fn = match_ground_truth(detections, ground_truth)
        assert tp == 0
        assert fp == 0
        assert fn == 2

    def test_empty_ground_truth_all_false_positives(self):
        """Detections with no ground truth should all be FP."""
        ground_truth = []
        detections = [
            {"line": 10, "type": "reentrancy", "confidence": 0.8},
            {"line": 20, "type": "overflow", "confidence": 0.7},
        ]

        tp, fp, fn = match_ground_truth(detections, ground_truth)
        assert tp == 0
        assert fp == 2
        assert fn == 0

    def test_duplicate_detections_same_line(self):
        """Multiple detections at same line should only match once."""
        ground_truth = [
            {"line": 15, "type": "reentrancy"},
        ]
        detections = [
            {"line": 15, "type": "reentrancy", "confidence": 0.9},
            {"line": 15, "type": "reentrancy-eth", "confidence": 0.8},
        ]

        tp, fp, fn = match_ground_truth(detections, ground_truth)
        # First detection matches, second becomes FP since GT already matched
        assert tp == 1
        assert fp == 1
        assert fn == 0

    def test_cross_validation_with_deduplication(self):
        """Cross-validation combined with deduplication."""
        engine = SmartCorrelationEngine()

        # Add same finding from two tools
        engine.add_findings(
            "slither",
            [
                {
                    "type": "reentrancy-eth",
                    "severity": "high",
                    "message": "Reentrancy in withdraw()",
                    "location": {"file": "test.sol", "line": 15, "function": "withdraw"},
                    "confidence": 0.9,
                }
            ],
        )
        engine.add_findings(
            "mythril",
            [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "message": "State change after external call in withdraw",
                    "location": {"file": "test.sol", "line": 15, "function": "withdraw"},
                    "confidence": 0.85,
                }
            ],
        )

        correlated = engine.correlate()

        # Should deduplicate into single finding confirmed by both tools
        reentrancy = [f for f in correlated if f.canonical_type == "reentrancy"]
        assert len(reentrancy) == 1
        assert len(reentrancy[0].confirming_tools) == 2
        assert reentrancy[0].is_cross_validated


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
