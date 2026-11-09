"""Every finding carries a real file path and, when derivable, a function name.

Wave C1 "Trust the findings": the intelligence engine used to hard-code
``location.file == ""`` and ``function == "unknown"`` on its own pattern hits,
and tool findings that only carry a line (Aderyn, Solhint) were reported with
``function == "unknown"`` even though the source is at hand.
"""

from pathlib import Path

import pytest

from miesc.core.intelligence import (
    complete_location,
    detect_zero_recall_categories,
    enhance_findings,
    function_at_line,
)

SMARTBUGS = Path(__file__).resolve().parent.parent / "benchmarks/datasets/smartbugs-curated/dataset"

SOURCE = """pragma solidity ^0.8.0;

contract Bank {
    mapping(address => uint256) public balances;

    constructor() {
        balances[msg.sender] = 1;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }

    receive() external payable {}
}

interface IBank {
    function ping() external;
}
"""


class TestFunctionAtLine:
    def test_body_line_maps_to_enclosing_function(self):
        assert function_at_line(SOURCE, 16) == "withdraw"
        assert function_at_line(SOURCE, 11) == "deposit"

    def test_declaration_line_counts(self):
        assert function_at_line(SOURCE, 14) == "withdraw"

    def test_constructor_and_receive(self):
        assert function_at_line(SOURCE, 7) == "constructor"
        assert function_at_line(SOURCE, 21) == "receive"

    def test_outside_any_function_is_none(self):
        assert function_at_line(SOURCE, 1) is None  # pragma
        assert function_at_line(SOURCE, 4) is None  # state variable

    def test_bodyless_declaration_covers_only_its_line(self):
        assert function_at_line(SOURCE, 25) == "ping"
        assert function_at_line(SOURCE, 26) is None

    def test_garbage_input(self):
        assert function_at_line("", 3) is None
        assert function_at_line(SOURCE, 0) is None
        assert function_at_line(SOURCE, 10_000) is None


class TestCompleteLocation:
    def test_fills_file_and_function(self):
        f = {"type": "x", "location": {"file": "", "line": 16, "function": "unknown"}}
        complete_location(f, SOURCE, "Bank.sol")
        assert f["location"] == {"file": "Bank.sol", "line": 16, "function": "withdraw"}

    def test_keeps_tool_supplied_values(self):
        f = {"type": "x", "location": {"file": "a/Bank.sol", "line": 16, "function": "w"}}
        complete_location(f, SOURCE, "Bank.sol")
        assert f["location"] == {"file": "a/Bank.sol", "line": 16, "function": "w"}

    def test_non_dict_location_is_replaced(self):
        f = {"type": "x", "location": "Bank.sol:16"}
        complete_location(f, SOURCE, "Bank.sol")
        assert f["location"]["file"] == "Bank.sol"

    def test_unknown_stays_unknown_outside_functions(self):
        f = {"type": "x", "location": {"file": "", "line": 1, "function": "unknown"}}
        complete_location(f, SOURCE, "Bank.sol")
        assert f["location"]["function"] == "unknown"


# A value-bearing `.call` alone no longer counts as reentrancy (tools cover the
# CEI violation); the gap-filler keeps the callback-into-caller shape.
CALLBACK_SOURCE = """pragma solidity ^0.8.0;

interface IBank {
    function onWithdraw() external;
}

contract Bank {
    mapping(address => uint256) public balances;

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        IBank(msg.sender).onWithdraw();
        balances[msg.sender] = 0;
    }
}
"""


class TestIntelligenceFindingsCarryLocation:
    def test_pattern_findings_have_file_and_function(self):
        findings = detect_zero_recall_categories(CALLBACK_SOURCE, "Bank.sol")
        assert findings, "expected at least the cross-function reentrancy pattern"
        for f in findings:
            assert f["location"]["file"] == "Bank.sol"
        by_type = {f["type"]: f for f in findings}
        assert by_type["reentrancy_crossfunction"]["location"]["function"] == "withdraw"

    def test_enhance_findings_derives_function_for_tool_findings(self):
        aderyn_like = {
            "type": "send-ether-no-checks",
            "severity": "High",
            "tool": "aderyn",
            "location": {"file": "Bank.sol", "line": 14, "function": "unknown"},
        }
        out = enhance_findings([aderyn_like], source_code=SOURCE, file_path="Bank.sol")
        hit = next(f for f in out if f["type"] == "send-ether-no-checks")
        assert hit["location"]["function"] == "withdraw"


@pytest.mark.skipif(not SMARTBUGS.is_dir(), reason="SmartBugs-curated dataset not checked out")
def test_no_finding_without_file_on_smartbugs_curated():
    """Acceptance (plan B.1): no finding with an empty ``location.file`` on the corpus."""
    contracts = sorted(SMARTBUGS.rglob("*.sol"))
    assert len(contracts) >= 143
    empty: list[str] = []
    for path in contracts:
        source = path.read_text(encoding="utf-8", errors="ignore")
        seed = [
            {
                "type": "unchecked-send",
                "severity": "Medium",
                "tool": "aderyn",
                "location": {"file": "", "line": 1, "function": "unknown"},
            }
        ]
        for f in enhance_findings(seed, source_code=source, file_path=str(path)):
            if not f.get("location", {}).get("file"):
                empty.append(f"{path.name}:{f.get('type')}")
    assert not empty, empty[:10]
