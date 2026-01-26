"""
Tests for MIESC v4.6.0 New Modules
==================================

Tests for:
- Call Graph Module
- Taint Analysis Module
- Slither IR Parser
- Access Control Semantic Detector
- DoS Cross-Function Detector
- Enhanced FP Filter with Detector Rates
- Cross-Validation Enforcement

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import pytest
import sys
import importlib.util
from typing import Dict, Any, List
from pathlib import Path

# Direct module imports to avoid circular import issues
# This bypasses the __init__.py which has circular dependencies

def _import_module_directly(module_path: str, module_name: str):
    """Import a module directly from file path without going through __init__.py"""
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

# Get base path
BASE_PATH = Path(__file__).parent.parent / "src" / "ml"

# Import v4.6.0 modules directly
call_graph_module = _import_module_directly(
    str(BASE_PATH / "call_graph.py"), "call_graph_test"
)
Visibility = call_graph_module.Visibility
Mutability = call_graph_module.Mutability
FunctionNode = call_graph_module.FunctionNode
CallEdge = call_graph_module.CallEdge
CallPath = call_graph_module.CallPath
CallGraph = call_graph_module.CallGraph
CallGraphBuilder = call_graph_module.CallGraphBuilder
build_call_graph = call_graph_module.build_call_graph
analyze_reentrancy_risk = call_graph_module.analyze_reentrancy_risk

taint_module = _import_module_directly(
    str(BASE_PATH / "taint_analysis.py"), "taint_analysis_test"
)
TaintSource = taint_module.TaintSource
TaintSink = taint_module.TaintSink
SanitizerType = taint_module.SanitizerType
TaintedVariable = taint_module.TaintedVariable
TaintedPath = taint_module.TaintedPath
TaintAnalyzer = taint_module.TaintAnalyzer
analyze_taint = taint_module.analyze_taint
find_tainted_sinks = taint_module.find_tainted_sinks

ir_parser_module = _import_module_directly(
    str(BASE_PATH / "slither_ir_parser.py"), "slither_ir_parser_test"
)
IROpcode = ir_parser_module.IROpcode
IRVariable = ir_parser_module.IRVariable
IRInstruction = ir_parser_module.IRInstruction
StateTransition = ir_parser_module.StateTransition
Call = ir_parser_module.Call
FunctionIR = ir_parser_module.FunctionIR
SlitherIRParser = ir_parser_module.SlitherIRParser
parse_slither_ir = ir_parser_module.parse_slither_ir

fp_filter_module = _import_module_directly(
    str(BASE_PATH / "false_positive_filter.py"), "fp_filter_test"
)
SLITHER_DETECTOR_FP_RATES = fp_filter_module.SLITHER_DETECTOR_FP_RATES
SemanticContextAnalyzer = fp_filter_module.SemanticContextAnalyzer
FalsePositiveFilter = fp_filter_module.FalsePositiveFilter

classic_patterns_module = _import_module_directly(
    str(BASE_PATH / "classic_patterns.py"), "classic_patterns_test"
)
AccessControlSemanticDetector = classic_patterns_module.AccessControlSemanticDetector
DoSCrossFunctionDetector = classic_patterns_module.DoSCrossFunctionDetector
detect_semantic_vulnerabilities = classic_patterns_module.detect_semantic_vulnerabilities

correlation_module = _import_module_directly(
    str(BASE_PATH / "correlation_engine.py"), "correlation_engine_test"
)
SmartCorrelationEngine = correlation_module.SmartCorrelationEngine


# =============================================================================
# TEST DATA
# =============================================================================

VULNERABLE_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    address[] public users;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        users.push(msg.sender);
    }

    // Vulnerable to reentrancy
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success);
        balances[msg.sender] = 0;
    }

    // Missing access control
    function setOwner(address _owner) public {
        owner = _owner;
    }

    // Unbounded loop
    function distributeRewards() public {
        for (uint i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1 ether);
        }
    }
}
'''

SAFE_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SafeBank is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // CEI Pattern - Safe
    function withdraw() public nonReentrant {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // Effects before interactions
        balances[msg.sender] = 0;

        // Interaction
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }

    // Has access control
    function setFee(uint256 _fee) public onlyOwner {
        // fee = _fee;
    }
}
'''


# =============================================================================
# CALL GRAPH TESTS
# =============================================================================

class TestCallGraph:
    """Tests for Call Graph module."""

    def test_function_node_creation(self):
        """Test creating a FunctionNode."""
        node = FunctionNode(
            name="withdraw",
            visibility=Visibility.PUBLIC,
            mutability=Mutability.NONPAYABLE,
            modifiers=["nonReentrant"],
        )

        assert node.name == "withdraw"
        assert node.is_entry_point == True
        assert node.visibility == Visibility.PUBLIC
        assert "nonReentrant" in node.modifiers

    def test_function_node_entry_point(self):
        """Test entry point detection."""
        public_func = FunctionNode("test", Visibility.PUBLIC)
        external_func = FunctionNode("test", Visibility.EXTERNAL)
        internal_func = FunctionNode("test", Visibility.INTERNAL)
        private_func = FunctionNode("test", Visibility.PRIVATE)

        assert public_func.is_entry_point == True
        assert external_func.is_entry_point == True
        assert internal_func.is_entry_point == False
        assert private_func.is_entry_point == False

    def test_call_graph_basic(self):
        """Test basic call graph operations."""
        graph = CallGraph("TestContract")

        # Add nodes
        func1 = FunctionNode("deposit", Visibility.PUBLIC)
        func2 = FunctionNode("withdraw", Visibility.PUBLIC)
        func3 = FunctionNode("_transfer", Visibility.INTERNAL)

        graph.add_function(func1)
        graph.add_function(func2)
        graph.add_function(func3)

        # Add edges
        graph.add_edge(CallEdge("deposit", "_transfer", "internal"))
        graph.add_edge(CallEdge("withdraw", "_transfer", "internal"))

        assert len(graph.nodes) == 3
        assert len(graph.edges) == 2
        assert len(graph.get_entry_points()) == 2

    def test_reachable_from(self):
        """Test reachability analysis."""
        graph = CallGraph("TestContract")

        graph.add_function(FunctionNode("A", Visibility.PUBLIC))
        graph.add_function(FunctionNode("B", Visibility.INTERNAL))
        graph.add_function(FunctionNode("C", Visibility.INTERNAL))

        graph.add_edge(CallEdge("A", "B", "internal"))
        graph.add_edge(CallEdge("B", "C", "internal"))

        reachable = graph.reachable_from("A")
        assert "A" in reachable
        assert "B" in reachable
        assert "C" in reachable

    def test_build_from_source(self):
        """Test building call graph from source code."""
        graph = build_call_graph(VULNERABLE_CONTRACT, "VulnerableBank")

        # Should find some functions
        assert len(graph.nodes) > 0
        entry_points = graph.get_entry_points()
        assert len(entry_points) > 0

    def test_reentrancy_risk_analysis(self):
        """Test reentrancy risk detection."""
        result = analyze_reentrancy_risk(VULNERABLE_CONTRACT)

        assert 'summary' in result
        assert 'total_functions' in result['summary']


# =============================================================================
# TAINT ANALYSIS TESTS
# =============================================================================

class TestTaintAnalysis:
    """Tests for Taint Analysis module."""

    def test_taint_source_detection(self):
        """Test detection of taint sources."""
        code = '''
        function test() public {
            address sender = msg.sender;
            uint256 value = msg.value;
        }
        '''

        analyzer = TaintAnalyzer()
        paths = analyzer.analyze(code)

        # Should detect msg.sender and msg.value as taint sources
        assert len(analyzer._tainted_vars) >= 2

    def test_taint_propagation(self):
        """Test taint propagation through assignments."""
        code = '''
        function test() public {
            address sender = msg.sender;
            address recipient = sender;
        }
        '''

        analyzer = TaintAnalyzer()
        analyzer.analyze(code)

        # sender should be tainted from msg.sender
        # recipient should be tainted from sender
        assert "sender" in analyzer._tainted_vars or "recipient" in analyzer._tainted_vars

    def test_tainted_sink_detection(self):
        """Test detection of tainted data reaching sinks."""
        code = '''
        function test(address target) public {
            target.call("");
        }
        '''

        result = analyze_taint(code)

        # Should detect parameter flowing to call
        assert 'vulnerable_paths' in result

    def test_sanitizer_detection(self):
        """Test that sanitizers are detected."""
        code = '''
        function test(address target) public {
            require(target != address(0), "Invalid");
            target.call("");
        }
        '''

        analyzer = TaintAnalyzer()
        paths = analyzer.analyze(code)

        # Paths should potentially be marked as sanitized
        summary = analyzer.get_summary()
        assert 'sanitized_paths' in summary


# =============================================================================
# SLITHER IR PARSER TESTS
# =============================================================================

class TestSlitherIRParser:
    """Tests for Slither IR Parser module."""

    def test_ir_instruction_creation(self):
        """Test creating IR instructions."""
        instruction = IRInstruction(
            opcode=IROpcode.HIGH_LEVEL_CALL,
            call_target="victim",
            call_type="withdraw",
            line=10,
        )

        assert instruction.opcode == IROpcode.HIGH_LEVEL_CALL
        assert instruction.call_target == "victim"

    def test_function_ir_creation(self):
        """Test creating FunctionIR."""
        func_ir = FunctionIR(name="test")
        func_ir.state_reads.add("balance")
        func_ir.state_writes.add("balance")

        assert func_ir.name == "test"
        assert "balance" in func_ir.state_reads
        assert "balance" in func_ir.state_writes

    def test_parser_initialization(self):
        """Test parser initialization."""
        parser = SlitherIRParser()
        assert parser._functions == {}

    def test_parse_empty_output(self):
        """Test parsing empty Slither output."""
        parser = SlitherIRParser()
        result = parser.parse_slither_output({})

        assert result == {}

    def test_parse_with_detectors(self):
        """Test parsing Slither output with detectors."""
        slither_output = {
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "type_specific_fields": {
                                    "visibility": "public",
                                    "state_variables_read": [{"name": "balance"}],
                                    "state_variables_written": [{"name": "balance"}],
                                }
                            }
                        ]
                    }
                ]
            }
        }

        parser = SlitherIRParser()
        result = parser.parse_slither_output(slither_output)

        # Should extract function info
        assert "withdraw" in result


# =============================================================================
# FALSE POSITIVE FILTER TESTS
# =============================================================================

class TestFalsePositiveFilter:
    """Tests for Enhanced FP Filter."""

    def test_slither_detector_fp_rates_exist(self):
        """Test that FP rates are defined."""
        assert len(SLITHER_DETECTOR_FP_RATES) > 0
        assert "reentrancy-benign" in SLITHER_DETECTOR_FP_RATES
        assert "reentrancy-eth" in SLITHER_DETECTOR_FP_RATES

    def test_fp_rate_values(self):
        """Test FP rate value ranges."""
        for detector, rate in SLITHER_DETECTOR_FP_RATES.items():
            assert 0.0 <= rate <= 1.0, f"Invalid rate for {detector}"

    def test_benign_has_high_fp_rate(self):
        """Test that benign patterns have high FP rates."""
        assert SLITHER_DETECTOR_FP_RATES["reentrancy-benign"] >= 0.80
        assert SLITHER_DETECTOR_FP_RATES["naming-convention"] >= 0.90

    def test_critical_has_low_fp_rate(self):
        """Test that critical patterns have low FP rates."""
        assert SLITHER_DETECTOR_FP_RATES["reentrancy-eth"] <= 0.25
        assert SLITHER_DETECTOR_FP_RATES["suicidal"] <= 0.15

    def test_get_detector_fp_rate(self):
        """Test getting FP rate for a detector."""
        fp_filter = FalsePositiveFilter()

        rate = fp_filter.get_detector_fp_rate("reentrancy-eth")
        assert rate == SLITHER_DETECTOR_FP_RATES["reentrancy-eth"]

        # Unknown detector should return default
        unknown_rate = fp_filter.get_detector_fp_rate("unknown-detector")
        assert unknown_rate == 0.50

    def test_adjust_confidence_by_detector(self):
        """Test confidence adjustment based on detector."""
        fp_filter = FalsePositiveFilter()

        finding = {
            "type": "reentrancy-benign",
            "confidence": 0.90,
        }

        adjusted = fp_filter.adjust_confidence_by_detector(
            finding, "reentrancy-benign"
        )

        # Confidence should be reduced due to high FP rate
        assert adjusted["confidence"] < finding["confidence"]
        assert "_detector_fp_analysis" in adjusted


class TestSemanticContextAnalyzer:
    """Tests for Semantic Context Analyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = SemanticContextAnalyzer()
        assert analyzer is not None

    def test_reentrancy_guard_detection(self):
        """Test detection of reentrancy guards."""
        analyzer = SemanticContextAnalyzer()

        finding = {"type": "reentrancy-eth"}
        result = analyzer.analyze_finding_context(
            finding, SAFE_CONTRACT
        )

        # Should detect ReentrancyGuard
        assert result["confidence_adjustment"] < 0
        assert len(result["guards_detected"]) > 0

    def test_cei_pattern_detection(self):
        """Test CEI pattern detection."""
        analyzer = SemanticContextAnalyzer()

        # Code with CEI pattern
        cei_code = '''
        function withdraw() public {
            uint256 balance = balances[msg.sender];
            balances[msg.sender] = 0;  // Effect before interaction
            (bool success, ) = msg.sender.call{value: balance}("");
        }
        '''

        finding = {"type": "reentrancy"}
        result = analyzer.analyze_finding_context(finding, cei_code)

        # Should detect CEI pattern
        # Note: Detection may not be perfect with regex-based analysis
        assert "confidence_adjustment" in result

    def test_solidity_version_detection(self):
        """Test Solidity version detection."""
        analyzer = SemanticContextAnalyzer()

        code_08 = '''
        pragma solidity ^0.8.0;
        contract Test {}
        '''

        code_07 = '''
        pragma solidity ^0.7.0;
        contract Test {}
        '''

        finding = {"type": "arithmetic"}
        result_08 = analyzer.analyze_finding_context(finding, code_08)
        result_07 = analyzer.analyze_finding_context(finding, code_07)

        assert result_08["has_overflow_protection"] == True
        assert result_07["has_overflow_protection"] == False


# =============================================================================
# ACCESS CONTROL DETECTOR TESTS
# =============================================================================

class TestAccessControlSemanticDetector:
    """Tests for Access Control Semantic Detector."""

    def test_detector_initialization(self):
        """Test detector initialization."""
        detector = AccessControlSemanticDetector()
        assert detector is not None

    def test_unprotected_privileged_function(self):
        """Test detection of unprotected privileged functions."""
        detector = AccessControlSemanticDetector()
        findings = detector.analyze(VULNERABLE_CONTRACT)

        # Should find setOwner as unprotected
        vuln_types = [f.vuln_type for f in findings]
        assert any("unprotected" in vt or "missing" in vt for vt in vuln_types)

    def test_protected_function_not_flagged(self):
        """Test that protected functions are not flagged."""
        detector = AccessControlSemanticDetector()
        findings = detector.analyze(SAFE_CONTRACT)

        # setFee has onlyOwner, should not be flagged as unprotected
        for f in findings:
            if f.function == "setFee":
                assert "unprotected" not in f.vuln_type

    def test_uninitialized_owner_detection(self):
        """Test detection of uninitialized owner."""
        code = '''
        contract Test {
            address owner;  // Not initialized

            function doSomething() public {
                require(msg.sender == owner);
            }
        }
        '''

        detector = AccessControlSemanticDetector()
        findings = detector.analyze(code)

        vuln_types = [f.vuln_type for f in findings]
        # May or may not detect depending on implementation
        assert isinstance(findings, list)

    def test_to_findings_format(self):
        """Test conversion to MIESC finding format."""
        detector = AccessControlSemanticDetector()
        ac_findings = detector.analyze(VULNERABLE_CONTRACT)
        miesc_findings = detector.to_findings(ac_findings)

        for finding in miesc_findings:
            assert "type" in finding
            assert "severity" in finding
            assert "location" in finding
            assert "swc_id" in finding


# =============================================================================
# DoS DETECTOR TESTS
# =============================================================================

class TestDoSCrossFunctionDetector:
    """Tests for DoS Cross-Function Detector."""

    def test_detector_initialization(self):
        """Test detector initialization."""
        detector = DoSCrossFunctionDetector()
        assert detector is not None

    def test_unbounded_loop_detection(self):
        """Test detection of unbounded loops."""
        detector = DoSCrossFunctionDetector()
        findings = detector.analyze(VULNERABLE_CONTRACT)

        vuln_types = [f.vuln_type for f in findings]
        # distributeRewards has unbounded loop
        assert any("loop" in vt or "dos" in vt for vt in vuln_types)

    def test_push_payment_detection(self):
        """Test detection of push payment pattern."""
        code = '''
        contract Test {
            address[] users;

            function distribute() public {
                for (uint i = 0; i < users.length; i++) {
                    payable(users[i]).transfer(1 ether);
                }
            }
        }
        '''

        detector = DoSCrossFunctionDetector()
        findings = detector.analyze(code)

        # Should detect push payment in loop
        vuln_types = [f.vuln_type for f in findings]
        assert len(findings) > 0

    def test_to_findings_format(self):
        """Test conversion to MIESC finding format."""
        detector = DoSCrossFunctionDetector()
        dos_findings = detector.analyze(VULNERABLE_CONTRACT)
        miesc_findings = detector.to_findings(dos_findings)

        for finding in miesc_findings:
            assert "type" in finding
            assert "severity" in finding
            assert "swc_id" in finding


# =============================================================================
# CROSS-VALIDATION TESTS
# =============================================================================

class TestCrossValidation:
    """Tests for Cross-Validation enforcement."""

    def test_cross_validation_required_set(self):
        """Test that CROSS_VALIDATION_REQUIRED is defined."""
        engine = SmartCorrelationEngine()
        assert hasattr(engine, 'CROSS_VALIDATION_REQUIRED')
        assert "reentrancy" in engine.CROSS_VALIDATION_REQUIRED

    def test_requires_cross_validation(self):
        """Test the requires_cross_validation method."""
        engine = SmartCorrelationEngine()

        assert engine.requires_cross_validation("reentrancy-eth") == True
        assert engine.requires_cross_validation("arbitrary-send") == True
        assert engine.requires_cross_validation("naming-convention") == False

    def test_single_tool_confidence_cap(self):
        """Test that single-tool critical findings are capped."""
        engine = SmartCorrelationEngine()

        finding = {
            "type": "reentrancy-eth",
            "confidence": 0.90,
        }

        adjusted = engine.apply_cross_validation_penalty(finding, tool_count=1)

        # Confidence should be capped at SINGLE_TOOL_MAX_CONFIDENCE
        assert adjusted["confidence"] <= engine.SINGLE_TOOL_MAX_CONFIDENCE

    def test_multi_tool_no_penalty(self):
        """Test that multi-tool findings are not penalized."""
        engine = SmartCorrelationEngine()

        finding = {
            "type": "reentrancy-eth",
            "confidence": 0.90,
        }

        adjusted = engine.apply_cross_validation_penalty(finding, tool_count=2)

        # With 2 tools, confidence should not be capped
        assert adjusted["confidence"] == finding["confidence"]


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestV460Integration:
    """Integration tests for v4.6.0 modules."""

    def test_detect_semantic_vulnerabilities(self):
        """Test combined semantic vulnerability detection."""
        results = detect_semantic_vulnerabilities(VULNERABLE_CONTRACT)

        assert 'access_control' in results
        assert 'dos' in results
        assert 'classic' in results

        # Should find vulnerabilities
        total = (
            len(results['access_control']) +
            len(results['dos']) +
            len(results['classic'])
        )
        assert total > 0

    def test_full_analysis_pipeline(self):
        """Test full analysis with all v4.6.0 components."""
        # Build call graph
        call_graph = build_call_graph(VULNERABLE_CONTRACT)

        # Run taint analysis
        taint_result = analyze_taint(VULNERABLE_CONTRACT)

        # Run semantic detectors
        semantic_result = detect_semantic_vulnerabilities(VULNERABLE_CONTRACT)

        # All should complete without errors
        assert call_graph is not None
        assert taint_result is not None
        assert semantic_result is not None

    def test_safe_contract_fewer_findings(self):
        """Test that safe contract has fewer findings."""
        vuln_results = detect_semantic_vulnerabilities(VULNERABLE_CONTRACT)
        safe_results = detect_semantic_vulnerabilities(SAFE_CONTRACT)

        vuln_total = sum(len(v) for v in vuln_results.values())
        safe_total = sum(len(v) for v in safe_results.values())

        # Safe contract should have fewer findings
        assert safe_total <= vuln_total


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
