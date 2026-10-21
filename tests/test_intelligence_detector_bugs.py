"""Three gap-filler bugs found by attributing SmartBugs-curated false positives
to the rule that produced them (2026-10-20). Each has a positive (must fire) and
a negative (must not fire) contract.
"""

from miesc.core.intelligence import detect_zero_recall_categories


def _types(code: str) -> set:
    return {f["type"] for f in detect_zero_recall_categories(code)}


class TestIncorrectConstructorNameChecksEnclosingContract:
    """SWC-118: a function named exactly like its contract IS the pre-0.4.22 constructor."""

    def test_typo_in_constructor_name_fires(self):
        # SmartBugs access_control/incorrect_constructor_name1.sol
        code = """
        pragma solidity ^0.4.24;
        contract Missing {
            address private owner;
            function IamMissing() public {
                owner = msg.sender;
            }
        }
        """
        assert "incorrect_constructor_name" in _types(code)

    def test_real_constructor_does_not_fire(self):
        # SmartBugs front_running/eth_tx_order_dependence_minimal.sol
        code = """
        pragma solidity ^0.4.22;
        contract EthTxOrderDependenceMinimal {
            address public owner;
            function EthTxOrderDependenceMinimal() public {
                owner = msg.sender;
            }
        }
        """
        assert "incorrect_constructor_name" not in _types(code)

    def test_name_of_another_contract_in_the_file_still_fires(self):
        # Matching a *different* contract's name is the classic copy-paste bug.
        code = """
        pragma solidity ^0.4.24;
        contract Token {
            uint public supply;
        }
        contract TokenBank {
            address public owner;
            function Token() public {
                owner = msg.sender;
            }
        }
        """
        assert "incorrect_constructor_name" in _types(code)

    def test_multiline_signature_real_constructor_does_not_fire(self):
        code = """
        pragma solidity ^0.4.21;
        contract Wallet {
            address public owner;
            function Wallet(address _o)
                public
            {
                owner = msg.sender;
            }
        }
        """
        assert "incorrect_constructor_name" not in _types(code)


class TestUncheckedCallPatternRespectsCapturedReturn:
    """SWC-104: the return value is only unchecked when nothing receives it."""

    def test_bare_call_statement_fires(self):
        code = """
        pragma solidity ^0.4.24;
        contract Pay {
            function pay(address to, uint amount) public {
                to.call.value(amount)();
            }
        }
        """
        assert "unchecked_call_pattern" in _types(code)

    def test_bare_call_with_data_fires(self):
        code = """
        pragma solidity ^0.4.24;
        contract Fwd {
            function f(address to, bytes data) public {
                to.call(data);
            }
        }
        """
        assert "unchecked_call_pattern" in _types(code)

    def test_captured_and_required_return_does_not_fire(self):
        # SmartBugs reentrancy/reentrancy_bonus.sol
        code = """
        pragma solidity ^0.5.0;
        contract Bonus {
            mapping(address => uint) private rewards;
            function withdrawReward(address recipient) public {
                uint amountToWithdraw = rewards[recipient];
                rewards[recipient] = 0;
                (bool success, ) = recipient.call.value(amountToWithdraw)("");
                require(success);
            }
        }
        """
        assert "unchecked_call_pattern" not in _types(code)

    def test_call_inside_require_does_not_fire(self):
        code = """
        pragma solidity ^0.4.24;
        contract Pay {
            function pay(address to, uint amount) public {
                require(to.call.value(amount)());
            }
        }
        """
        assert "unchecked_call_pattern" not in _types(code)


class TestFrontRunningApproveNeedsABody:
    """SWC-114: an interface declaration of approve() is not an approve race."""

    def test_implemented_approve_fires(self):
        # SmartBugs front_running/ERC20.sol shape (no increaseAllowance).
        code = """
        pragma solidity ^0.4.24;
        contract Token {
            mapping(address => mapping(address => uint)) allowed;
            function approve(address spender, uint value) public returns (bool) {
                allowed[msg.sender][spender] = value;
                return true;
            }
        }
        """
        assert "front_running" in _types(code)

    def test_implemented_approve_with_brace_on_next_line_fires(self):
        code = """
        pragma solidity ^0.4.24;
        contract Token {
            mapping(address => mapping(address => uint)) allowed;
            function approve(address spender, uint value) public returns (bool)
            {
                allowed[msg.sender][spender] = value;
                return true;
            }
        }
        """
        assert "front_running" in _types(code)

    def test_interface_declaration_does_not_fire(self):
        # SmartBugs unchecked_low_level_calls/0x663e...sol: abstract ERC20 declaration.
        code = """
        pragma solidity ^0.4.11;
        contract ERC20 {
            function totalSupply() constant returns (uint supply);
            function balanceOf( address who ) constant returns (uint value);
            function approve( address spender, uint value ) returns (bool ok);
            event Approval( address indexed owner, address indexed spender, uint value);
        }
        """
        assert "front_running" not in _types(code)
