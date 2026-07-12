"""Tests for PeculiarAdapter code-graph and pattern-analysis logic (no GNN model).

Exercises the pattern-based fallback analyzer and the graph extraction helpers,
which are pure and run without the optional GNN weights.
"""

from __future__ import annotations

from miesc.adapters.peculiar_adapter import PeculiarAdapter

VULN_SRC = """contract Vuln {
    address owner;
    uint balance;
    function auth() public { require(tx.origin == owner); }
    function exec(address t, bytes data) public { t.delegatecall(data); }
    function timeLock() public { if (block.timestamp > 100) { balance = 0; } }
    function withdraw() public { msg.sender.call.value(balance)(""); balance = 0; }
}"""


def _adapter():
    return PeculiarAdapter()


class TestClassifyStatement:
    def test_classifications(self):
        a = _adapter()
        assert a._classify_statement("if (x) {") == "conditional"
        assert a._classify_statement("for (uint i;;) {") == "loop"
        assert a._classify_statement("require(x > 0);") == "guard"
        assert a._classify_statement("emit Sent(x);") == "event_emit"
        assert a._classify_statement("return x;") == "return"
        assert a._classify_statement("t.call(d);") == "external_call"
        assert a._classify_statement("t.delegatecall(d);") == "delegatecall"
        assert a._classify_statement("x = 1;") == "assignment"
        assert a._classify_statement("foo(bar);") == "expression"


class TestGraphExtraction:
    def test_extract_functions(self):
        a = _adapter()
        funcs = a._build_code_graph(VULN_SRC, "Vuln.sol").get("functions", [])
        names = {f.get("name") for f in funcs}
        assert {"auth", "exec", "timeLock", "withdraw"} <= names

    def test_extract_state_variables(self):
        a = _adapter()
        names = {v.get("name") for v in a._extract_state_variables(VULN_SRC)}
        assert {"owner", "balance"} <= names

    def test_split_statements(self):
        a = _adapter()
        stmts = a._split_statements("a = 1; b = 2; require(a > 0);")
        assert len([s for s in stmts if s.strip()]) >= 3


class TestPatternAnalysis:
    def test_run_pattern_analysis_finds_known_vulns(self):
        a = _adapter()
        graph = a._build_code_graph(VULN_SRC, "Vuln.sol")
        preds = a._run_pattern_analysis(graph, VULN_SRC)
        types = {p.get("type") for p in preds}
        assert "tx_origin" in types
        assert "delegatecall_injection" in types
        assert "timestamp_dependence" in types

    def test_clean_contract_no_false_alarms_for_txorigin(self):
        a = _adapter()
        src = "contract C { uint x; function set(uint v) public { x = v; } }"
        graph = a._build_code_graph(src, "C.sol")
        preds = a._run_pattern_analysis(graph, src)
        assert "tx_origin" not in {p.get("type") for p in preds}

    def test_tx_origin_pattern_direct(self):
        a = _adapter()
        graph = a._build_code_graph(VULN_SRC, "Vuln.sol")
        findings = a._pattern_tx_origin(graph, VULN_SRC)
        assert any(f.get("type") == "tx_origin" for f in findings)
