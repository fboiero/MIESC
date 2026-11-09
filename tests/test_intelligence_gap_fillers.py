"""Scope of the intelligence engine's zero-recall gap-fillers on SmartBugs shapes.

Each rule below is exercised with a contract that MUST fire and one that MUST
NOT. The negative cases are the shapes that produced false positives on the
SmartBugs-curated profile (2026-10-20) without a single true positive that a
tool had not already found.
"""

from miesc.core.intelligence import ZERO_RECALL_PATTERNS, detect_zero_recall_categories


def _types(code: str) -> set:
    return {f["type"] for f in detect_zero_recall_categories(code)}


class TestDosPushUnboundedRemoved:
    def test_rule_is_gone(self):
        assert "dos_push_unbounded" not in ZERO_RECALL_PATTERNS

    def test_plain_array_push_is_not_a_dos(self):
        # 19 of the 25 FP contracts: an audit-log push in a reentrancy sample.
        code = """
        pragma solidity ^0.4.19;
        contract Bank {
            struct Message { address sender; uint value; uint time; }
            Message[] public History;
            Message LastMsg;
            function deposit() public payable {
                LastMsg.sender = msg.sender;
                LastMsg.value = msg.value;
                LastMsg.time = now;
                History.push(LastMsg);
            }
        }
        """
        assert not {t for t in _types(code) if t.startswith("dos_")}

    def test_loop_over_dynamic_array_still_fires(self):
        code = """
        pragma solidity ^0.4.24;
        contract Refund {
            address[] public refundAddresses;
            mapping(address => uint) public refunds;
            function refundAll() public {
                for (uint x = 0; x < refundAddresses.length; x++) {
                    refundAddresses[x].transfer(refunds[refundAddresses[x]]);
                }
            }
        }
        """
        assert {t for t in _types(code) if t.startswith("dos_")}


class TestReentrancyCrossfunctionScope:
    def test_bare_value_call_is_not_flagged(self):
        # 20 FP contracts: forwarder `adr.call.value(msg.value)(data)` with no
        # shared state; Slither flags the real CEI violations.
        code = """
        pragma solidity ^0.4.24;
        contract Forwarder {
            function execute(address adr, bytes data) public payable {
                adr.call.value(msg.value)(data);
            }
        }
        """
        assert "reentrancy_crossfunction" not in _types(code)

    def test_call_with_value_syntax_is_not_flagged(self):
        code = """
        pragma solidity ^0.8.0;
        contract Pay {
            function pay(address payable to) public payable {
                (bool ok, ) = to.call{value: msg.value}("");
                require(ok);
            }
        }
        """
        assert "reentrancy_crossfunction" not in _types(code)

    def test_callback_into_caller_controlled_contract_fires(self):
        # SmartBugs reentrancy/modifier_reentrancy.sol shape.
        code = """
        pragma solidity ^0.5.0;
        contract Bank {
            function supportsToken() external returns (bytes32);
        }
        contract Attack {
            mapping(address => uint) public balances;
            modifier supportsToken() {
                require(keccak256("Nu Token") == Bank(msg.sender).supportsToken());
                _;
            }
            function withdraw() public supportsToken {
                balances[msg.sender] = 0;
            }
        }
        """
        assert "reentrancy_crossfunction" in _types(code)
