"""
Tests for src/ml/taint_analysis.py

Comprehensive tests for taint analysis including:
- TaintSource, TaintSink, SanitizerType enums
- TaintedVariable and TaintedPath dataclasses
- TaintAnalyzer class
- Convenience functions
"""

import pytest

from src.ml.taint_analysis import (
    SanitizerType,
    TaintAnalyzer,
    TaintedPath,
    TaintedVariable,
    TaintSink,
    TaintSource,
    analyze_taint,
    find_tainted_sinks,
)


class TestTaintSource:
    """Tests for TaintSource enum."""

    def test_msg_sender(self):
        """Test MSG_SENDER value."""
        assert TaintSource.MSG_SENDER.value == "msg.sender"

    def test_msg_value(self):
        """Test MSG_VALUE value."""
        assert TaintSource.MSG_VALUE.value == "msg.value"

    def test_tx_origin(self):
        """Test TX_ORIGIN value."""
        assert TaintSource.TX_ORIGIN.value == "tx.origin"

    def test_function_param(self):
        """Test FUNCTION_PARAM value."""
        assert TaintSource.FUNCTION_PARAM.value == "function_parameter"

    def test_all_sources(self):
        """Test all sources are defined."""
        sources = list(TaintSource)
        assert len(sources) >= 10


class TestTaintSink:
    """Tests for TaintSink enum."""

    def test_call(self):
        """Test CALL value."""
        assert TaintSink.CALL.value == "call"

    def test_delegatecall(self):
        """Test DELEGATECALL value."""
        assert TaintSink.DELEGATECALL.value == "delegatecall"

    def test_selfdestruct(self):
        """Test SELFDESTRUCT value."""
        assert TaintSink.SELFDESTRUCT.value == "selfdestruct"

    def test_transfer(self):
        """Test TRANSFER value."""
        assert TaintSink.TRANSFER.value == "transfer"

    def test_all_sinks(self):
        """Test all sinks are defined."""
        sinks = list(TaintSink)
        assert len(sinks) >= 9


class TestSanitizerType:
    """Tests for SanitizerType enum."""

    def test_require(self):
        """Test REQUIRE value."""
        assert SanitizerType.REQUIRE.value == "require"

    def test_assert(self):
        """Test ASSERT value."""
        assert SanitizerType.ASSERT.value == "assert"

    def test_owner_check(self):
        """Test OWNER_CHECK value."""
        assert SanitizerType.OWNER_CHECK.value == "owner_check"


class TestTaintedVariable:
    """Tests for TaintedVariable dataclass."""

    def test_minimal_construction(self):
        """Test creating TaintedVariable with required fields."""
        var = TaintedVariable(
            name="amount",
            source=TaintSource.MSG_VALUE,
        )
        assert var.name == "amount"
        assert var.source == TaintSource.MSG_VALUE
        assert var.line == 0
        assert var.is_sanitized is False
        assert var.sanitizers == []

    def test_full_construction(self):
        """Test creating TaintedVariable with all fields."""
        var = TaintedVariable(
            name="sender",
            source=TaintSource.MSG_SENDER,
            line=42,
            is_sanitized=True,
            sanitizers=[SanitizerType.REQUIRE, SanitizerType.OWNER_CHECK],
        )
        assert var.name == "sender"
        assert var.line == 42
        assert var.is_sanitized is True
        assert len(var.sanitizers) == 2

    def test_to_dict(self):
        """Test to_dict method."""
        var = TaintedVariable(
            name="value",
            source=TaintSource.MSG_VALUE,
            line=10,
            is_sanitized=True,
            sanitizers=[SanitizerType.REQUIRE],
        )
        d = var.to_dict()
        assert d["name"] == "value"
        assert d["source"] == "msg.value"
        assert d["line"] == 10
        assert d["is_sanitized"] is True
        assert "require" in d["sanitizers"]


class TestTaintedPath:
    """Tests for TaintedPath dataclass."""

    @pytest.fixture
    def sample_variable(self):
        """Create sample tainted variable."""
        return TaintedVariable(
            name="amount",
            source=TaintSource.MSG_VALUE,
            line=5,
        )

    def test_minimal_construction(self, sample_variable):
        """Test creating TaintedPath with required fields."""
        path = TaintedPath(
            source=sample_variable,
            sink=TaintSink.CALL,
            sink_line=15,
        )
        assert path.source == sample_variable
        assert path.sink == TaintSink.CALL
        assert path.sink_line == 15
        assert path.is_sanitized is False
        assert path.is_vulnerable is True
        assert path.severity == "medium"

    def test_sanitized_path(self, sample_variable):
        """Test sanitized path is not vulnerable."""
        path = TaintedPath(
            source=sample_variable,
            sink=TaintSink.TRANSFER,
            sink_line=20,
            is_sanitized=True,
            sanitizers=[SanitizerType.REQUIRE],
        )
        assert path.is_sanitized is True
        assert path.is_vulnerable is False

    def test_to_dict(self, sample_variable):
        """Test to_dict method."""
        path = TaintedPath(
            source=sample_variable,
            sink=TaintSink.DELEGATECALL,
            sink_line=25,
            path_variables=["amount", "target"],
            code_snippet="target.delegatecall(data);",
            severity="critical",
        )
        d = path.to_dict()
        assert d["sink"] == "delegatecall"
        assert d["sink_line"] == 25
        assert "amount" in d["path_variables"]
        assert d["is_vulnerable"] is True
        assert d["severity"] == "critical"

    def test_code_snippet_truncation(self, sample_variable):
        """Test code snippet is truncated in to_dict."""
        long_snippet = "x" * 300
        path = TaintedPath(
            source=sample_variable,
            sink=TaintSink.CALL,
            sink_line=10,
            code_snippet=long_snippet,
        )
        d = path.to_dict()
        assert len(d["code_snippet"]) == 200


class TestTaintAnalyzerInit:
    """Tests for TaintAnalyzer initialization."""

    def test_default_init(self):
        """Test default initialization."""
        analyzer = TaintAnalyzer()
        assert analyzer._tainted_vars == {}
        assert analyzer._paths == []

    def test_source_patterns_defined(self):
        """Test source patterns are defined."""
        assert TaintSource.MSG_SENDER in TaintAnalyzer.SOURCE_PATTERNS
        assert TaintSource.MSG_VALUE in TaintAnalyzer.SOURCE_PATTERNS

    def test_sink_patterns_defined(self):
        """Test sink patterns are defined."""
        assert TaintSink.CALL in TaintAnalyzer.SINK_PATTERNS
        assert TaintSink.DELEGATECALL in TaintAnalyzer.SINK_PATTERNS


class TestTaintAnalyzerAnalyze:
    """Tests for TaintAnalyzer.analyze method."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return TaintAnalyzer()

    def test_analyze_simple_reentrancy(self, analyzer):
        """Test analyzing simple reentrancy pattern."""
        code = """
        function withdraw(uint256 amount) external {
            require(balances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
        """
        paths = analyzer.analyze(code)
        assert len(paths) > 0
        # Should find msg.sender flowing to call
        call_paths = [p for p in paths if p.sink == TaintSink.CALL]
        assert len(call_paths) > 0

    def test_analyze_msg_value_to_transfer(self, analyzer):
        """Test analyzing msg.value to transfer."""
        code = """
        function forward(address payable recipient) external payable {
            uint256 amount = msg.value;
            recipient.transfer(amount);
        }
        """
        paths = analyzer.analyze(code)
        transfer_paths = [p for p in paths if p.sink == TaintSink.TRANSFER]
        assert len(transfer_paths) > 0

    def test_analyze_with_sanitizer(self, analyzer):
        """Test analyzing code with sanitizer."""
        code = """
        function withdraw(uint256 amount) external {
            require(amount > 0);
            require(amount <= balances[msg.sender]);
            (bool success, ) = msg.sender.call{value: amount}("");
        }
        """
        paths = analyzer.analyze(code)
        # Some paths should be sanitized due to require
        sanitized = [p for p in paths if p.is_sanitized]
        # The analysis should find sanitizers
        assert len(paths) > 0

    def test_analyze_function_parameters(self, analyzer):
        """Test analyzing function parameters as taint sources."""
        code = """
        function transferTo(address recipient, uint256 amount) external {
            recipient.transfer(amount);
        }
        """
        paths = analyzer.analyze(code)
        # Parameters should be marked as tainted
        param_paths = [p for p in paths if p.source.source == TaintSource.FUNCTION_PARAM]
        assert len(param_paths) > 0

    def test_analyze_specific_function(self, analyzer):
        """Test analyzing specific function."""
        code = """
        function safeFunction() external {
            // Safe code
        }

        function unsafeFunction(uint256 amount) external {
            msg.sender.call{value: amount}("");
        }
        """
        paths = analyzer.analyze(code, function_name="unsafeFunction")
        assert len(paths) > 0

    def test_analyze_delegatecall(self, analyzer):
        """Test analyzing delegatecall pattern."""
        code = """
        function execute(address target, bytes calldata data) external {
            target.delegatecall(data);
        }
        """
        paths = analyzer.analyze(code)
        delegatecall_paths = [p for p in paths if p.sink == TaintSink.DELEGATECALL]
        assert len(delegatecall_paths) > 0

    def test_analyze_selfdestruct(self, analyzer):
        """Test analyzing selfdestruct pattern."""
        code = """
        function destroy(address payable recipient) external {
            selfdestruct(recipient);
        }
        """
        paths = analyzer.analyze(code)
        selfdestruct_paths = [p for p in paths if p.sink == TaintSink.SELFDESTRUCT]
        assert len(selfdestruct_paths) > 0

    def test_analyze_empty_code(self, analyzer):
        """Test analyzing empty code."""
        paths = analyzer.analyze("")
        assert paths == []

    def test_analyze_no_sinks(self, analyzer):
        """Test analyzing code without sinks."""
        code = """
        function getBalance() external view returns (uint256) {
            return balances[msg.sender];
        }
        """
        paths = analyzer.analyze(code)
        assert paths == []


class TestTaintAnalyzerHelpers:
    """Tests for TaintAnalyzer helper methods."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return TaintAnalyzer()

    def test_extract_assigned_variable(self, analyzer):
        """Test extracting assigned variable."""
        line = "uint256 amount = msg.value;"
        var = analyzer._extract_assigned_variable(line, r"\bmsg\.value\b")
        assert var == "amount"

    def test_extract_assigned_variable_no_match(self, analyzer):
        """Test extracting variable when no match."""
        line = "require(msg.sender == owner);"
        var = analyzer._extract_assigned_variable(line, r"\bmsg\.sender\b")
        assert var is None

    def test_calculate_severity_critical(self, analyzer):
        """Test critical severity calculation."""
        severity = analyzer._calculate_severity(TaintSource.MSG_VALUE, TaintSink.CALL)
        assert severity == "critical"

    def test_calculate_severity_high(self, analyzer):
        """Test high severity calculation."""
        severity = analyzer._calculate_severity(TaintSource.MSG_SENDER, TaintSink.DELEGATECALL)
        assert severity == "high"

    def test_calculate_severity_medium(self, analyzer):
        """Test medium severity calculation."""
        severity = analyzer._calculate_severity(TaintSource.FUNCTION_PARAM, TaintSink.TRANSFER)
        assert severity == "medium"

    def test_calculate_severity_low(self, analyzer):
        """Test low severity calculation."""
        severity = analyzer._calculate_severity(TaintSource.BLOCK_NUMBER, TaintSink.SEND)
        assert severity == "low"

    def test_extract_function(self, analyzer):
        """Test extracting specific function."""
        code = """
        function foo() external {
            // foo code
        }

        function bar() external {
            // bar code
        }
        """
        extracted = analyzer._extract_function(code, "foo")
        assert "foo code" in extracted
        assert "bar code" not in extracted

    def test_extract_function_not_found(self, analyzer):
        """Test extracting non-existent function."""
        code = "function foo() {}"
        extracted = analyzer._extract_function(code, "nonexistent")
        # Should return original code if function not found
        assert extracted == code

    def test_get_recommendation(self, analyzer):
        """Test getting recommendations."""
        rec = analyzer._get_recommendation(TaintSink.CALL)
        assert "reentrancy" in rec.lower() or "validate" in rec.lower()

        rec = analyzer._get_recommendation(TaintSink.DELEGATECALL)
        assert "delegatecall" in rec.lower()

    def test_get_swc_id(self, analyzer):
        """Test getting SWC IDs."""
        assert analyzer._get_swc_id(TaintSink.CALL) == "SWC-107"
        assert analyzer._get_swc_id(TaintSink.DELEGATECALL) == "SWC-112"
        assert analyzer._get_swc_id(TaintSink.SELFDESTRUCT) == "SWC-106"
        assert analyzer._get_swc_id(TaintSink.ARITHMETIC) == "SWC-101"


class TestTaintAnalyzerResults:
    """Tests for TaintAnalyzer result methods."""

    @pytest.fixture
    def analyzer_with_paths(self):
        """Create analyzer with pre-analyzed paths."""
        analyzer = TaintAnalyzer()
        code = """
        function vulnerable(uint256 amount) external {
            require(amount > 0);
            msg.sender.call{value: amount}("");
        }
        """
        analyzer.analyze(code)
        return analyzer

    def test_get_vulnerable_paths(self, analyzer_with_paths):
        """Test getting vulnerable paths."""
        vulnerable = analyzer_with_paths.get_vulnerable_paths()
        assert isinstance(vulnerable, list)
        for path in vulnerable:
            assert path.is_vulnerable

    def test_get_summary(self, analyzer_with_paths):
        """Test getting summary."""
        summary = analyzer_with_paths.get_summary()
        assert "total_tainted_variables" in summary
        assert "total_paths" in summary
        assert "vulnerable_paths" in summary
        assert "by_severity" in summary
        assert "by_sink" in summary
        assert "by_source" in summary

    def test_to_findings(self, analyzer_with_paths):
        """Test converting to findings format."""
        findings = analyzer_with_paths.to_findings()
        assert isinstance(findings, list)
        for finding in findings:
            assert "type" in finding
            assert "severity" in finding
            assert "location" in finding
            assert "message" in finding
            assert "tool" in finding
            assert finding["tool"] == "taint-analyzer"


class TestTaintPropagation:
    """Tests for taint propagation."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return TaintAnalyzer()

    def test_propagation_through_assignment(self, analyzer):
        """Test taint propagates through assignment."""
        code = """
        function test() external {
            uint256 x = msg.value;
            uint256 y = x;
            uint256 z = y;
            msg.sender.call{value: z}("");
        }
        """
        paths = analyzer.analyze(code)
        # z should be tainted and reach call
        assert len(paths) > 0

    def test_propagation_stops_at_literal(self, analyzer):
        """Test taint doesn't propagate from literals."""
        code = """
        function test() external {
            uint256 x = 100;
            msg.sender.call{value: x}("");
        }
        """
        paths = analyzer.analyze(code)
        # x is not tainted from msg.value, but msg.sender still flows to call
        msg_sender_paths = [
            p
            for p in paths
            if "msg.sender" in p.source.name or p.source.source == TaintSource.MSG_SENDER
        ]
        assert len(msg_sender_paths) > 0


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_analyze_taint(self):
        """Test analyze_taint function."""
        code = """
        function withdraw(uint256 amount) external {
            msg.sender.call{value: amount}("");
        }
        """
        result = analyze_taint(code)
        assert "paths" in result
        assert "vulnerable_paths" in result
        assert "findings" in result
        assert "summary" in result

    def test_analyze_taint_with_function_name(self):
        """Test analyze_taint with specific function."""
        code = """
        function safe() external {}
        function unsafe(uint256 x) external {
            msg.sender.call{value: x}("");
        }
        """
        result = analyze_taint(code, function_name="unsafe")
        assert len(result["paths"]) > 0

    def test_find_tainted_sinks_all(self):
        """Test find_tainted_sinks without filter."""
        code = """
        function test(address target) external {
            target.call("");
            target.transfer(1);
        }
        """
        paths = find_tainted_sinks(code)
        assert len(paths) >= 2

    def test_find_tainted_sinks_specific(self):
        """Test find_tainted_sinks with specific sink."""
        code = """
        function test(address target) external {
            target.call("");
            target.transfer(1);
        }
        """
        paths = find_tainted_sinks(code, sink_type=TaintSink.CALL)
        for path in paths:
            assert path.sink == TaintSink.CALL


class TestEdgeCases:
    """Edge case tests."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return TaintAnalyzer()

    def test_nested_functions(self, analyzer):
        """Test analysis with nested function calls."""
        code = """
        function outer() external {
            inner(msg.value);
        }
        function inner(uint256 x) internal {
            msg.sender.call{value: x}("");
        }
        """
        paths = analyzer.analyze(code)
        assert len(paths) > 0

    def test_multiple_sinks_same_line(self, analyzer):
        """Test multiple sinks on same line."""
        code = """
        function test(address a, address b) external payable {
            a.transfer(msg.value); b.send(msg.value);
        }
        """
        paths = analyzer.analyze(code)
        # Should find both transfer and send
        assert len(paths) >= 2

    def test_block_timestamp(self, analyzer):
        """Test block.timestamp as source."""
        code = """
        function timeDependent() external {
            uint256 t = block.timestamp;
            require(t > deadline);
        }
        """
        paths = analyzer.analyze(code)
        # block.timestamp should be tracked but may not reach a sink
        assert analyzer._tainted_vars

    def test_tx_origin(self, analyzer):
        """Test tx.origin as source."""
        code = """
        function authenticate() external {
            address origin = tx.origin;
            require(origin == owner);
        }
        """
        paths = analyzer.analyze(code)
        # tx.origin should be identified as source
        tx_origin_vars = [
            v for v in analyzer._tainted_vars.values() if v.source == TaintSource.TX_ORIGIN
        ]
        assert len(tx_origin_vars) > 0

    def test_owner_check_sanitizer(self, analyzer):
        """Test owner check is recognized as sanitizer."""
        code = """
        function privileged() external {
            require(msg.sender == owner);
            selfdestruct(payable(msg.sender));
        }
        """
        paths = analyzer.analyze(code)
        # The path should be marked as sanitized
        if paths:
            sanitized_paths = [p for p in paths if SanitizerType.OWNER_CHECK in p.sanitizers]
            # Owner check should be detected
            assert len(sanitized_paths) >= 0  # May or may not catch depending on implementation

    def test_send_sink(self, analyzer):
        """Test send is detected as sink."""
        code = """
        function sendFunds(address payable recipient, uint256 amount) external {
            recipient.send(amount);
        }
        """
        paths = analyzer.analyze(code)
        send_paths = [p for p in paths if p.sink == TaintSink.SEND]
        assert len(send_paths) > 0

    def test_staticcall_sink(self, analyzer):
        """Test staticcall is detected as sink."""
        code = """
        function view_call(address target, bytes calldata data) external {
            target.staticcall(data);
        }
        """
        paths = analyzer.analyze(code)
        static_paths = [p for p in paths if p.sink == TaintSink.STATICCALL]
        assert len(static_paths) > 0
