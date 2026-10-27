"""Shapes that were scored as vulnerabilities on SmartBugs-curated contracts labelled
with other categories, next to the shapes that must keep firing."""

import time

from miesc.adapters.fouranalyzer_adapter import FourAnalyzerAdapter
from miesc.adapters.peculiar_adapter import PeculiarAdapter
from miesc.adapters.threat_model_adapter import ThreatModelAdapter
from miesc.cli.commands.evaluate import _normalize_category
from miesc.core.intelligence import detect_zero_recall_categories
from miesc.detectors.smartbugs_detectors import AccessControlDetector

TX_ORIGIN = """
pragma solidity ^0.4.24;
contract Bank {
    address owner;
    mapping(address => uint) balances;
    function Bank() { balances[tx.origin] = 10000; }
    function play() public { require(msg.sender == tx.origin); }
    function sweep(address to) public { require(tx.origin == owner); to.transfer(this.balance); }
}
"""

LOOPS = """
pragma solidity ^0.4.24;
contract Airdrop {
    address[] players;
    function batch(address[] _tos, uint v) public {
        for (uint i = 0; i < _tos.length; i++) { _tos[i].transfer(v); }
    }
    function payAll() public {
        for (uint i = 0; i < players.length; i++) { players[i].transfer(1); }
    }
}
"""


def _types(findings):
    return [f["type"] for f in findings]


def test_informational_and_remediation_rules_have_no_benchmark_category():
    assert _normalize_category("low-level-calls", description="Low level call in f()") is None
    assert (
        _normalize_category(
            "use_of_transfer_instead_of_call",
            description="Use of .transfer() or .send() with fixed gas stipend (2300)",
        )
        is None
    )
    assert (
        _normalize_category(
            "unsafe-erc20-operation",
            description="ERC20 functions may not behave as expected. For example: return values "
            "are not always meaningful.",
        )
        is None
    )
    assert _normalize_category("unchecked-lowlevel") == "unchecked_low_level_calls"


def test_fouranalyzer_erc20_rule_skips_eth_transfer(tmp_path):
    src = tmp_path / "C.sol"
    src.write_text(
        "contract C {\n"
        "  function a() { msg.sender.transfer(this.balance); }\n"
        "  function b(address t, address to) { Token(t).transfer(to, 5); }\n"
        "}\n"
    )
    result = FourAnalyzerAdapter()._run_pattern_analysis(str(src), time.time())
    lines = [
        f["location"]["line"] for f in result["findings"] if f["type"] == "unsafe_erc20_transfer"
    ]
    assert lines == [3]


def test_tx_origin_counts_only_when_it_authorizes():
    lines = [f.line for f in AccessControlDetector().detect(TX_ORIGIN) if "tx.origin" in f.title]
    assert lines == [8]

    adapter = PeculiarAdapter()
    graph = adapter._build_code_graph(TX_ORIGIN, "Bank.sol")
    assert len(adapter._pattern_tx_origin(graph, TX_ORIGIN)) == 1

    eoa_only = TX_ORIGIN.replace("require(tx.origin == owner);", "")
    assert "tx_origin_auth" in _types(detect_zero_recall_categories(TX_ORIGIN))
    assert "tx_origin_auth" not in _types(detect_zero_recall_categories(eoa_only))


def test_guarded_selfdestruct_is_not_unprotected():
    guarded = "contract C { address o; function k() { if (msg.sender != o) throw; suicide(o); } }"
    open_kill = "contract C { address o; function k() { suicide(o); } }"
    assert "unprotected_selfdestruct" not in _types(detect_zero_recall_categories(guarded))
    assert "unprotected_selfdestruct" in _types(detect_zero_recall_categories(open_kill))


def test_loop_over_caller_array_is_not_gas_limit_dos():
    only_param = LOOPS.split("    function payAll")[0] + "}\n"
    assert not {"dos_gas_limit", "dos_unbounded_loop"} & set(
        _types(detect_zero_recall_categories(only_param))
    )
    assert "dos_gas_limit" in _types(detect_zero_recall_categories(LOOPS))

    threats = ThreatModelAdapter()._analyze_stride_threats(LOOPS, "Airdrop.sol")
    loop_lines = [t["location"]["line"] for t in threats if "Unbounded loop" in t["description"]]
    assert loop_lines == [9]
