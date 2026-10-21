"""End-to-end: the emitters and the scorer honour the minimal chain-attribute data flow.

Measured on SmartBugs-curated (2026-10-21, LLM-free profile): the presence-only
rules below produced 46 bad_randomness and 43 time_manipulation false positives;
with the flow requirement recall stays 143/143 and the two drop to 14 and 30.
"""

from pathlib import Path

import pytest

from miesc.adapters.fouranalyzer_adapter import FourAnalyzerAdapter
from miesc.adapters.smartbugs_ml_adapter import SmartBugsMLAdapter
from miesc.cli.commands.evaluate import _normalize_category
from miesc.core.intelligence import detect_zero_recall_categories

STORE_ONLY = """pragma solidity ^0.4.24;
contract Vault {
    mapping(address => uint) public lastDeposit;
    event Deposited(address who, uint when);
    function deposit() public payable {
        lastDeposit[msg.sender] = now;
        emit Deposited(msg.sender, block.timestamp);
    }
    function known() public pure returns (bool) { return true; }
}
"""

GATED_PAYOUT = """pragma solidity ^0.4.24;
contract Survey {
    uint public lastInvestment;
    function invest() public payable {
        lastInvestment = block.timestamp;
    }
    function claim() public {
        if (lastInvestment + 1 minutes < block.timestamp) {
            msg.sender.transfer(address(this).balance);
        }
    }
}
"""

LOTTERY = """pragma solidity ^0.4.24;
contract Lottery {
    address[] public players;
    function draw() public {
        uint winner = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty))) % players.length;
        players[winner].transfer(address(this).balance);
    }
}
"""


def _write(tmp_path: Path, name: str, code: str) -> str:
    path = tmp_path / name
    path.write_text(code)
    return str(path)


def _types(result):
    return [f.get("type") for f in result.get("findings", [])]


class TestFourAnalyzerTimestampRule:
    def test_store_and_log_only_is_silent(self, tmp_path):
        result = FourAnalyzerAdapter().analyze(_write(tmp_path, "vault.sol", STORE_ONLY))
        assert "use_of_block_timestamp" not in _types(result)

    def test_timestamp_gating_a_payout_is_reported_at_the_comparison(self, tmp_path):
        result = FourAnalyzerAdapter().analyze(_write(tmp_path, "survey.sol", GATED_PAYOUT))
        hits = [f for f in result["findings"] if f.get("type") == "use_of_block_timestamp"]
        lines = {(f.get("location") or {}).get("line") or f.get("line") for f in hits}
        assert lines == {8}, "only the comparison line, not the store on line 5"


class TestMLFallbackRandomnessRule:
    def test_now_as_a_word_only(self):
        features = SmartBugsMLAdapter()._extract_features("contract C { function known() {} }")
        assert features["uses_timestamp"] == 0.0

    def test_presence_of_timestamp_is_not_randomness(self):
        adapter = SmartBugsMLAdapter()
        features = adapter._extract_features(STORE_ONLY)
        assert features["uses_timestamp"] == 1.0
        assert "bad_randomness" not in [
            f["type"] for f in adapter._run_ml_inference(features, STORE_ONLY)
        ]

    def test_entropy_flow_is_randomness(self):
        adapter = SmartBugsMLAdapter()
        features = adapter._extract_features(LOTTERY)
        assert "bad_randomness" in [f["type"] for f in adapter._run_ml_inference(features, LOTTERY)]


class TestIntelligenceTimestampFilter:
    def test_store_only_is_not_time_manipulation(self):
        types = [f["type"] for f in detect_zero_recall_categories(STORE_ONLY)]
        assert "time_manipulation" not in types

    def test_timestamp_comparison_is_time_manipulation(self):
        types = [f["type"] for f in detect_zero_recall_categories(GATED_PAYOUT)]
        assert "time_manipulation" in types


class TestScorerMappings:
    def test_slither_timestamp_detector_is_time_manipulation(self):
        desc = "Dangerous comparisons: require(bool)(block.timestamp > deadline)"
        assert _normalize_category("timestamp", "", desc) == "time_manipulation"

    def test_adapter_category_is_honoured_before_keywords(self):
        desc = "Using block.number in conditional logic at line 7. Block number is predictable."
        assert (
            _normalize_category("", "Timestamp Dependency", desc, "time_manipulation")
            == "time_manipulation"
        )

    @pytest.mark.parametrize("category", ["unknown", "other", "security"])
    def test_non_taxonomy_categories_fall_through(self, category):
        assert _normalize_category("", "Something", "nothing relevant", category) is None

    def test_deprecation_notices_are_not_findings(self):
        desc = "Deprecated standard detected [x = uint8(sha3()(now, block.blockhash(block.number - 1))) % 20]"
        assert _normalize_category("deprecated-standards", "", desc) is None
        assert (
            _normalize_category("constant-functions-assembly", "", "may lead to vulnerabilities")
            is None
        )

    def test_corpus_paths_in_descriptions_do_not_leak_the_label(self):
        desc = "[Lottery](benchmarks/datasets/smartbugs-curated/dataset/bad_randomness/lottery.sol#L11) sets array length"
        assert _normalize_category("controlled-array-length", "", desc) is None
        desc = (
            "[Bank.withdraw()](dataset/reentrancy/simple_dao.sol#L20-L30) shadows a builtin symbol"
        )
        assert _normalize_category("shadowing-builtin", "", desc) is None
        # a genuine keyword still maps once the path is gone
        desc = "[Bank.withdraw()](dataset/other/x.sol#L2) ignores the return value of .call("
        assert _normalize_category("unused-return", "", desc) == "unchecked_low_level_calls"
