"""Minimal data flow for chain attributes (miesc.detectors.chain_attribute_flow).

The shapes below are the ones measured on SmartBugs-curated (2026-10-21): every
labelled time_manipulation / bad_randomness contract has a flow, store-only and
log-only uses never do.
"""

from miesc.detectors.chain_attribute_flow import (
    has_time_dependence,
    has_weak_randomness,
    time_dependence,
    time_dependent_lines,
    weak_randomness,
    weak_randomness_lines,
)

STORE_ONLY = """pragma solidity ^0.4.24;
contract Vault {
    mapping(address => uint) public lastDeposit;
    uint public createdAt = block.timestamp;
    event Deposited(address who, uint when);
    function deposit() public payable {
        lastDeposit[msg.sender] = now;
        emit Deposited(msg.sender, block.timestamp);
        uint age = block.timestamp - createdAt;
        lastDeposit[msg.sender] += age;
    }
}
"""

ROULETTE = """pragma solidity ^0.4.24;
contract Roulette {
    function play() public payable {
        if (now % 15 == 0) {
            msg.sender.transfer(address(this).balance);
        }
    }
}
"""

# time_manipulation/ether_lotto.sol shape: the timestamp only feeds the entropy.
ETHER_LOTTO = """pragma solidity ^0.4.0;
contract EtherLotto {
    function play() payable {
        uint random = uint(sha3(block.timestamp)) % 2;
        if (random == 0) {
            msg.sender.transfer(1 ether);
        }
    }
}
"""

# bad_randomness/old_blockhash.sol shape: blockhash into a local, compared later.
OLD_BLOCKHASH = """pragma solidity ^0.4.24;
contract PredictTheBlockHashChallenge {
    mapping(address => bytes32) guesses;
    function settle() public {
        require(block.number > settlementBlock);
        bytes32 answer = blockhash(settlementBlock);
        if (guesses[msg.sender] == answer) {
            msg.sender.transfer(2 ether);
        }
    }
}
"""


class TestTimeDependence:
    def test_store_and_log_only_is_not_time_dependent(self):
        assert not has_time_dependence(STORE_ONLY)
        assert time_dependent_lines(STORE_ONLY) == set()

    def test_comparison_in_condition(self):
        code = "function f() public { require(block.timestamp > deadline); }"
        hits = time_dependence(code)
        assert [(h.attribute, h.sink) for h in hits] == [("block.timestamp", "condition")]

    def test_comparison_in_return(self):
        code = "function isOver() public view returns (bool) { return now >= end; }"
        assert [h.sink for h in time_dependence(code)] == ["return"]

    def test_ternary_counts_as_condition(self):
        code = "function f() public { uint fee = block.timestamp < start ? 1 : 2; }"
        assert [h.sink for h in time_dependence(code)] == ["condition"]

    def test_block_number_proxy_for_time(self):
        code = "function f() public { if (block.number > unlockBlock) { pay(); } }"
        assert has_time_dependence(code)

    def test_local_derived_from_timestamp_reaching_a_condition(self):
        code = """function f() public {
            uint elapsed = block.timestamp - startTime;
            uint window = elapsed * 2;
            if (window > limit) { payout(); }
        }"""
        hits = time_dependence(code)
        assert hits and hits[0].line == 2 and hits[0].sink == "condition" and hits[0].sink_line == 4

    def test_timestamp_as_entropy_is_time_dependent(self):
        assert has_time_dependence(ETHER_LOTTO)
        assert {"hash", "modulo"} <= {h.sink for h in time_dependence(ETHER_LOTTO)}

    def test_modulo_on_now(self):
        assert has_time_dependence(ROULETTE)
        assert time_dependent_lines(ROULETTE) == {4}

    def test_lines_are_the_attribute_reads_not_the_sinks(self):
        code = "function f() public {\n  uint t = now;\n  uint u = t + 1;\n  require(u > end);\n}"
        assert time_dependent_lines(code) == {2}

    def test_comments_and_strings_are_ignored(self):
        code = """function f() public {
            // require(block.timestamp > deadline);
            /* if (now > x) { } */
            emit Log("block.timestamp > deadline");
        }"""
        assert not has_time_dependence(code)

    def test_interface_declarations_are_skipped(self):
        code = "interface I { function f(uint now) external; }\ncontract C { uint t = block.timestamp; }"
        assert not has_time_dependence(code)

    def test_bare_snippet_without_function_is_analysed(self):
        assert has_time_dependence("require(block.timestamp > lockEnd);")
        assert not has_time_dependence("uint seed = block.timestamp;")


class TestWeakRandomness:
    def test_timestamp_store_is_not_randomness(self):
        assert not has_weak_randomness(STORE_ONLY)

    def test_timestamp_comparison_is_not_randomness(self):
        code = "function f() public { require(block.timestamp > deadline); }"
        assert not has_weak_randomness(code)

    def test_hash_of_block_attribute(self):
        code = "function r() public view returns (uint) { return uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))); }"
        assert [h.sink for h in weak_randomness(code)] == ["hash"]

    def test_modulo_on_block_attribute(self):
        assert {h.sink for h in weak_randomness(ROULETTE)} == {"modulo"}

    def test_strong_sources_count_on_any_use(self):
        assert has_weak_randomness(OLD_BLOCKHASH)
        assert {h.attribute for h in weak_randomness(OLD_BLOCKHASH)} == {"blockhash"}
        assert has_weak_randomness("function f() public { uint d = block.difficulty; }")
        assert has_weak_randomness("function f() public { emit Miner(block.coinbase); }")

    def test_local_derived_from_block_number_reaching_a_hash(self):
        code = """function draw() public {
            uint b = block.number - 1;
            bytes32 h = keccak256(abi.encodePacked(b));
            winner = uint(h) % players.length;
        }"""
        assert weak_randomness_lines(code) == {2}

    def test_ether_lotto_is_randomness_too(self):
        assert has_weak_randomness(ETHER_LOTTO)
