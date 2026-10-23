"""Caller guards and self-service withdrawals (miesc.detectors.access_guards).

Shapes are the ones measured on SmartBugs-curated (2026-10-23): the negatives come from
contracts labelled reentrancy / unchecked calls / arithmetic / randomness, the positives
from the labelled access_control contracts.
"""

from miesc.detectors.access_guards import (
    OWNER_LIKE_RE,
    function_text_at,
    has_caller_guard,
    is_self_service_withdrawal,
    moves_value,
)


class TestCallerGuard:
    def test_only_modifier_any_spelling(self):
        assert has_caller_guard("function f() onlyOwner", "{}")
        assert has_caller_guard("function f() onlywizard", "{}")
        assert has_caller_guard("function f() public onlyBy(owner)", "{}")
        assert not has_caller_guard("function f() public", "{}")

    def test_msg_sender_comparison_in_if_or_require(self):
        assert has_caller_guard(
            "function destroy()", "{ if (msg.sender != organizer) { throw; } suicide(organizer); }"
        )
        assert has_caller_guard(
            "function kill() public",
            "{ if (msg.sender == ownerAddr && now > lastPlayed + 1 days) { suicide(msg.sender); } }",
        )
        assert has_caller_guard("function f() public", "{ require(owner == msg.sender, 'no'); }")

    def test_role_mapping_as_boolean_is_a_guard(self):
        assert has_caller_guard("function f() public", "{ require(isOwner[msg.sender]); }")
        assert has_caller_guard("function f() public", "{ if (!admins[msg.sender]) revert(); }")

    def test_balance_mapping_comparison_is_not_a_guard(self):
        assert not has_caller_guard(
            "function withdraw() public",
            "{ require(balances[msg.sender] > 0); require(now > lockTime[msg.sender]); }",
        )

    def test_msg_sender_outside_a_condition_is_not_a_guard(self):
        assert not has_caller_guard("function f() public", "{ owner = msg.sender; }")


class TestSelfServiceWithdrawal:
    def test_user_withdraws_own_balance(self):
        body = (
            "{ uint v = balances[msg.sender]; balances[msg.sender] = 0; msg.sender.transfer(v); }"
        )
        assert is_self_service_withdrawal(body)

    def test_recipient_bound_payout(self):
        body = '{ uint a = rewardsForA[recipient]; rewardsForA[recipient] = 0; (bool ok, ) = recipient.call.value(a)(""); }'
        assert is_self_service_withdrawal(body)

    def test_refund_of_msg_value(self):
        assert is_self_service_withdrawal(
            "{ if (paused) { msg.sender.transfer(msg.value); return; } }"
        )

    def test_computed_amount_without_balance_entry_is_not_self_service(self):
        body = "{ withdrawalCounter += 1; require(lib.delegatecall(sig, withdrawalCounter)); msg.sender.transfer(calculatedFibNumber * 1 ether); }"
        assert not is_self_service_withdrawal(body)

    def test_contract_balance_is_never_self_service(self):
        assert not is_self_service_withdrawal("{ msg.sender.transfer(this.balance); }")
        assert not is_self_service_withdrawal(
            "{ payable(msg.sender).transfer(address(this).balance); }"
        )
        assert not is_self_service_withdrawal(
            "{ require(balances[msg.sender] > 0); owner.transfer(address(this).balance); }"
        )

    def test_no_value_sink(self):
        assert not is_self_service_withdrawal(
            "{ rewardsForA[recipient] += 100; withdrawReward(recipient); }"
        )
        assert not moves_value("{ rewardsForA[recipient] += 100; }")
        assert moves_value("{ to.send(amount); }")


class TestHelpers:
    def test_owner_like_names(self):
        for name in (
            "owner",
            "_owner",
            "admin",
            "creator",
            "root",
            "contractOwner",
            "ownerAddress",
            "owner_",
        ):
            assert OWNER_LIKE_RE.match(name), name
        for name in ("ticketOwner", "lastOwner", "ownerCount", "balances", "msg"):
            assert not OWNER_LIKE_RE.match(name), name

    def test_function_text_at(self):
        src = "contract C {\n  function f(uint a) public onlyOwner {\n    if (a > 1) { x = a; }\n  }\n  function g() external;\n}\n"
        header, body = function_text_at(src, src.index("function f"))
        assert header.strip() == "function f(uint a) public onlyOwner"
        assert body.strip().startswith("{") and body.strip().endswith("}") and "x = a" in body
        header, body = function_text_at(src, src.index("function g"))
        assert header.strip() == "function g() external" and body == ""
        assert function_text_at(src, len(src)) == ("", "")
