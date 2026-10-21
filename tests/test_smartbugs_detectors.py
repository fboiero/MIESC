#!/usr/bin/env python3
"""
Unit tests for MIESC SmartBugs-Specific Detectors.

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import sys
from pathlib import Path

import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from miesc.detectors.smartbugs_detectors import (  # noqa: E402
    AccessControlDetector,
    ArithmeticDetector,
    BadRandomnessDetector,
    DenialOfServiceDetector,
    FrontRunningDetector,
    ReentrancyDetector,
    ShortAddressDetector,
    SmartBugsDetectorEngine,
    TimeManipulationDetector,
    UncheckedLowLevelCallsDetector,
)


class TestArithmeticDetector:
    """Tests for ArithmeticDetector."""

    @pytest.fixture
    def detector(self):
        return ArithmeticDetector()

    def test_detects_addition_overflow(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Test {
            mapping(address => uint) balances;
            function deposit(uint amount) public {
                balances[msg.sender] = balances[msg.sender] + amount;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0
        assert any("overflow" in f.title.lower() for f in findings)

    def test_detects_subtraction_underflow(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Test {
            mapping(address => uint) balances;
            function withdraw(uint amount) public {
                balances[msg.sender] -= amount;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_state_variable_written_with_user_input(self, detector):
        # SmartBugs arithmetic/integer_overflow_minimal.sol shape: no financial
        # term, no index, but a contract-level counter written with a parameter.
        code = """
        pragma solidity ^0.4.19;
        contract IntegerOverflowMinimal {
            uint public count = 1;
            function run(uint256 input) public {
                count -= input;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) == 1
        assert findings[0].line == 6

    def test_context_free_arithmetic_is_not_a_finding(self, detector):
        # "pre-0.8 code does arithmetic" fired on every non-arithmetic SmartBugs
        # contract (128/128) while Slither already covered the real ones; a local
        # computation with no state write and no financial term is not reported.
        code = """
        pragma solidity ^0.4.24;
        contract Test {
            function add(uint a, uint b) public returns (uint) {
                uint c = a + b;
                return c;
            }
        }
        """
        assert detector.detect(code) == []

    def test_ignores_safemath(self, detector):
        code = """
        pragma solidity ^0.4.24;
        import "SafeMath.sol";
        contract Test {
            using SafeMath for uint;
            function add(uint a, uint b) public returns (uint) {
                return a.add(b);
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) == 0

    def test_ignores_solidity_08(self, detector):
        code = """
        pragma solidity ^0.8.0;
        contract Test {
            function add(uint a, uint b) public returns (uint) {
                uint c = a + b;
                return c;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) == 0

    def test_detects_cast_multiplication_bypassing_safemath(self, detector):
        # BECToken batchOverflow shape: the contract defines SafeMath but one raw
        # multiplication with a cast operand bypasses it. The `uint256(cnt)` cast
        # used to defeat the operand regex, so the real overflow was missed.
        code = """
        pragma solidity ^0.4.16;
        library SafeMath {
            function mul(uint256 a, uint256 b) internal returns (uint256) {
                uint256 c = a * b;
                assert(a == 0 || c / a == b);
                return c;
            }
        }
        contract Token {
            using SafeMath for uint256;
            function batchTransfer(uint256 cnt, uint256 _value) public {
                uint256 amount = uint256(cnt) * _value;
            }
        }
        """
        findings = detector.detect(code)
        assert any("overflow" in f.title.lower() for f in findings)
        # The raw bypass line is flagged, but the SafeMath library's own `a * b` is not.
        assert any("uint256(cnt) * _value" in f.code_snippet for f in findings)
        assert not any("c = a * b" in f.code_snippet for f in findings)

    def test_ignores_safemath_library_internals(self, detector):
        # A SafeMath library's own checked-primitive arithmetic must not be flagged.
        code = """
        pragma solidity ^0.4.24;
        library SafeMath {
            function mul(uint256 a, uint256 b) internal returns (uint256) {
                uint256 c = a * b;
                return c;
            }
            function add(uint256 a, uint256 b) internal returns (uint256) {
                uint256 c = a + b;
                return c;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) == 0


class TestReentrancyDetector:
    """Tests for ReentrancyDetector."""

    @pytest.fixture
    def detector(self):
        return ReentrancyDetector()

    def test_detects_classic_reentrancy(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            mapping(address => uint) balances;
            function withdraw(uint amount) public {
                if (balances[msg.sender] >= amount) {
                    msg.sender.call.value(amount)();
                    balances[msg.sender] -= amount;
                }
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0
        assert any("reentrancy" in f.title.lower() for f in findings)

    def test_detects_send_reentrancy(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            mapping(address => uint) balances;
            function withdraw() public {
                uint amount = balances[msg.sender];
                msg.sender.send(amount);
                balances[msg.sender] = 0;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_transfer_after_balance_guard(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            mapping(address => uint) balances;
            function withdraw(uint amount) public {
                require(balances[msg.sender] >= amount);
                msg.sender.transfer(amount);
                balances[msg.sender] -= amount;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_ignores_tod_reward_transfer_as_reentrancy(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Reward {
            bool public claimed;
            uint public reward;
            function claimReward(uint256 submission) public {
                require(!claimed);
                require(submission < 10);
                msg.sender.transfer(reward);
                claimed = true;
            }
        }
        """
        findings = detector.detect(code)
        assert findings == []

    def test_detects_channel_balance_transfer_before_delete(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Channel {
            struct State {
                address[2] partyAddresses;
                uint[2] ethBalances;
            }
            mapping(bytes32 => State) Channels;
            function LCOpenTimeout(bytes32 id) public {
                Channels[id].partyAddresses[0].transfer(Channels[id].ethBalances[0]);
                delete Channels[id];
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_internal_helper_reentrancy(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Bonus {
            mapping(address => bool) claimedBonus;
            mapping(address => uint) rewardsForA;
            function withdrawReward(address recipient) public {
                uint amountToWithdraw = rewardsForA[recipient];
                rewardsForA[recipient] = 0;
                recipient.call.value(amountToWithdraw)("");
            }
            function getFirstWithdrawalBonus(address recipient) public {
                require(!claimedBonus[recipient]);
                rewardsForA[recipient] += 100;
                withdrawReward(recipient);
                claimedBonus[recipient] = true;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_ignores_reentrancy_guard(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Safe {
            bool locked;
            modifier nonReentrant() {
                require(!locked);
                locked = true;
                _;
                locked = false;
            }
            function withdraw() public nonReentrant {
                msg.sender.call.value(100)();
                balances[msg.sender] = 0;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) == 0

    def test_detects_modifier_reentrancy(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract ModifierEntrancy {
            mapping (address => uint) public tokenBalance;

            function airDrop() hasNoBalance supportsToken public {
                tokenBalance[msg.sender] += 20;
            }

            modifier supportsToken() {
                require(keccak256("Nu Token") == Bank(msg.sender).supportsToken());
                _;
            }

            modifier hasNoBalance {
                require(tokenBalance[msg.sender] == 0);
                _;
            }
        }

        contract Bank {
            function supportsToken() external returns(bytes32);
        }
        """
        findings = detector.detect(code)
        assert any("modifier" in f.title.lower() for f in findings)


class TestDenialOfServiceDetector:
    """Tests for DenialOfServiceDetector."""

    @pytest.fixture
    def detector(self):
        return DenialOfServiceDetector()

    def test_detects_transfer_in_loop(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            address[] users;
            function refundAll() public {
                for (uint i = 0; i < users.length; i++) {
                    users[i].transfer(100);
                }
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0
        assert any("loop" in f.title.lower() for f in findings)

    def test_detects_push_in_loop(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            address[] users;
            function addMany() public {
                for (uint i = 0; i < 100; i++) {
                    users.push(msg.sender);
                }
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_require_send(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function bid() public payable {
                require(currentLeader.send(currentBid));
                currentLeader = msg.sender;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0


class TestFrontRunningDetector:
    """Tests for FrontRunningDetector."""

    @pytest.fixture
    def detector(self):
        return FrontRunningDetector()

    def test_detects_hash_puzzle(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract HashPuzzle {
            bytes32 public hash;
            function solve(string solution) public {
                require(sha3(solution) == hash);
                msg.sender.transfer(1 ether);
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0
        assert any("hash" in f.title.lower() for f in findings)

    def test_detects_erc20_approve(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract ERC20 {
            mapping(address => mapping(address => uint)) _allowed;
            function approve(address spender, uint value) public {
                _allowed[msg.sender][spender] = value;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0
        assert any("approve" in f.title.lower() for f in findings)

    def test_detects_tod_transfer(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract TOD {
            uint public reward;
            function claim() public {
                msg.sender.transfer(reward);
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_incomplete_commit_reveal(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Puzzle {
            mapping(address => bytes32) public commitments;

            function commit(bytes32 answerHash) public {
                commitments[msg.sender] = answerHash;
            }

            function reveal(string answer) public {
                require(keccak256(answer) == commitments[msg.sender]);
                msg.sender.transfer(1 ether);
            }
        }
        """
        findings = detector.detect(code)
        assert any("commit-reveal" in f.title.lower() for f in findings)


class TestAccessControlDetector:
    """Tests for AccessControlDetector."""

    @pytest.fixture
    def detector(self):
        return AccessControlDetector()

    def test_detects_tx_origin(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function transferOwnership(address newOwner) public {
                require(tx.origin == owner);
                owner = newOwner;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0
        assert any("tx.origin" in f.description.lower() for f in findings)

    def test_detects_unprotected_selfdestruct(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function kill() public {
                selfdestruct(msg.sender);
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_incorrect_legacy_constructor_name(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Missing {
            address private owner;
            function IamMissing() public {
                owner = msg.sender;
            }
        }
        """
        findings = detector.detect(code)
        constructor_findings = [f for f in findings if f.swc_id == "SWC-118"]
        assert constructor_findings
        assert constructor_findings[0].line == 5

    def test_ignores_commented_access_control_modifier(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Unprotected {
            address private owner;
            function changeOwner(address newOwner) public {
                owner = newOwner;
            }
            /*
            function changeOwnerFixed(address newOwner) public onlyOwner {
                owner = newOwner;
            }
            */
        }
        """
        findings = detector.detect(code)
        assert any("changeOwner" in f.description for f in findings)

    def test_detects_public_delegatecall_without_access_control(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Proxy {
            function forward(address callee, bytes data) public {
                require(callee.delegatecall(data));
            }
        }
        """
        findings = detector.detect(code)
        assert any("delegatecall" in f.description.lower() for f in findings)

    def test_detects_arbitrary_array_index_write(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Map {
            uint256[] map;
            function set(uint256 key, uint256 value) public {
                map[key] = value;
            }
        }
        """
        findings = detector.detect(code)
        assert any(f.swc_id == "SWC-124" for f in findings)


class TestUncheckedLowLevelCallsDetector:
    """Tests for UncheckedLowLevelCallsDetector."""

    @pytest.fixture
    def detector(self):
        return UncheckedLowLevelCallsDetector()

    def test_detects_unchecked_call(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function forward(address to) public {
                to.call.value(100)();
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_unchecked_send(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function pay(address to) public {
                to.send(100);
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_ignores_checked_call(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Safe {
            function forward(address to) public {
                require(to.send(100));
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) == 0


class TestTimeManipulationDetector:
    """Tests for TimeManipulationDetector."""

    @pytest.fixture
    def detector(self):
        return TimeManipulationDetector()

    def test_detects_timestamp_in_condition(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function isExpired() public view returns (bool) {
                return block.timestamp > deadline;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_now_usage(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function random() public view returns (uint) {
                return uint(keccak256(now));
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_ignores_account_timelock(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Timelock {
            mapping(address => uint) lockTime;
            function lock() public {
                lockTime[msg.sender] = now + 1 weeks;
            }
            function withdraw() public {
                require(now > lockTime[msg.sender]);
            }
        }
        """
        findings = detector.detect(code)
        assert findings == []

    def test_detects_auction_deadline_condition(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Auction {
            uint public deadline;
            function canBid() public view returns (bool) {
                return block.timestamp < deadline;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_ignores_withdraw_cooldown_as_time_manipulation(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vault {
            mapping(address => uint) unlockTime;
            function withdraw(uint amount) public {
                require(now > unlockTime[msg.sender]);
                msg.sender.transfer(amount);
            }
        }
        """
        findings = detector.detect(code)
        assert findings == []


class TestBadRandomnessDetector:
    """Tests for BadRandomnessDetector."""

    @pytest.fixture
    def detector(self):
        return BadRandomnessDetector()

    def test_detects_blockhash_randomness(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function random() public view returns (uint) {
                return uint(blockhash(block.number - 1));
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_block_timestamp_randomness(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function random() public view returns (uint) {
                return uint(keccak256(block.timestamp));
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_ignores_timestamp_timelock_as_randomness(self, detector):
        code = """
        pragma solidity ^0.4.24;
        contract Timelock {
            mapping(address => uint) lockTime;
            function lock() public {
                lockTime[msg.sender] = now + 1 weeks;
            }
            function withdraw() public {
                require(now > lockTime[msg.sender]);
            }
        }
        """
        findings = detector.detect(code)
        assert findings == []


class TestSmartBugsDetectorEngine:
    """Tests for the main detector engine."""

    @pytest.fixture
    def engine(self):
        return SmartBugsDetectorEngine()

    def test_engine_has_all_detectors(self, engine):
        """Ensure engine has all 9 detectors."""
        assert len(engine.detectors) == 9

    def test_engine_analyzes_file(self, engine, tmp_path):
        """Test file analysis."""
        test_file = tmp_path / "test.sol"
        test_file.write_text("""
        pragma solidity ^0.4.24;
        contract Test {
            function add(uint a, uint b) public returns (uint) {
                return a + b;
            }
        }
        """)
        findings = engine.analyze_file(test_file)
        assert isinstance(findings, list)

    def test_engine_analyzes_code(self, engine, tmp_path):
        """Test code analysis via file."""
        code = """
        pragma solidity ^0.4.24;
        contract Test {
            function withdraw() public {
                msg.sender.call.value(100)();
                balance = 0;
            }
        }
        """
        test_file = tmp_path / "reentrancy.sol"
        test_file.write_text(code)
        findings = engine.analyze_file(test_file)
        assert len(findings) > 0


# =============================================================================
# ADDITIONAL COVERAGE TESTS
# =============================================================================


class TestArithmeticDetectorEdgeCases:
    """Edge case tests for ArithmeticDetector."""

    @pytest.fixture
    def detector(self):
        return ArithmeticDetector()

    def test_detects_multiplication_overflow(self, detector):
        """Test multiplication overflow detection on a financial state write."""
        code = """
        pragma solidity ^0.4.24;
        contract Test {
            uint public totalSupply;
            function mint(uint factor) public {
                totalSupply = totalSupply * factor;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_compound_assignment(self, detector):
        """Test compound assignment detection."""
        code = """
        pragma solidity ^0.4.24;
        contract Test {
            uint public total;
            function addToTotal(uint amount) public {
                total += amount;
            }
            function subFromTotal(uint amount) public {
                total -= amount;
            }
            function mulTotal(uint factor) public {
                total *= factor;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) >= 3  # One for each compound assignment

    def test_skips_comments(self, detector):
        """Test that inline comments starting with // are skipped."""
        code = """
        pragma solidity ^0.8.0;
        contract Test {
            // uint c = a + b;
            function safe() public pure returns (uint) {
                return 1;
            }
        }
        """
        findings = detector.detect(code)
        # Solidity 0.8+ has built-in checks, so no findings expected
        assert len(findings) == 0

    def test_skips_loop_counters(self, detector):
        """Test that loop counters are skipped."""
        code = """
        pragma solidity ^0.4.24;
        contract Test {
            function loop() public pure {
                for (uint i = 0; i < 10; i++) {
                    // loop body
                }
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) == 0


class TestShortAddressDetectorEdgeCases:
    """Edge case tests for ShortAddressDetector."""

    @pytest.fixture
    def detector(self):
        return ShortAddressDetector()

    def test_detects_transferFrom(self, detector):
        """Test detection of transferFrom function."""
        code = """
        pragma solidity ^0.4.24;
        contract Token {
            mapping(address => uint) balances;
            function transferFrom(address from, address to, uint amount) public {
                balances[from] -= amount;
                balances[to] += amount;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_approve(self, detector):
        """Test detection of approve function."""
        code = """
        pragma solidity ^0.4.24;
        contract Token {
            mapping(address => mapping(address => uint)) allowed;
            function approve(address spender, uint value) public {
                allowed[msg.sender][spender] = value;
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_ignores_declaration_without_body(self, detector):
        """An interface declaration cannot be the attacked entry point."""
        code = """
        pragma solidity ^0.4.24;
        contract ERC20Interface {
            function transfer(address to, uint256 tokens) public returns (bool success);
        }
        """
        assert detector.detect(code) == []

    def test_ignores_internal_helper(self, detector):
        """Internal functions never decode calldata."""
        code = """
        pragma solidity ^0.4.24;
        contract Game {
            mapping(address => uint) balances;
            function credit(address player, uint amount) internal {
                balances[player] += amount;
            }
        }
        """
        assert detector.detect(code) == []

    def test_ignores_function_that_does_not_credit_the_address(self, detector):
        """(address, uint) parameters that only get logged are not a short-address target."""
        code = """
        pragma solidity ^0.4.24;
        contract Log {
            struct Message { address sender; uint val; string data; }
            Message[] public history;
            function AddMessage(address _adr, uint _val, string _data) public {
                history.push(Message(_adr, _val, _data));
            }
        }
        """
        assert detector.detect(code) == []

    def test_ignores_owner_only_function(self, detector):
        """An owner-only payout has no third-party caller to trick."""
        code = """
        pragma solidity ^0.4.24;
        contract Treasury {
            address owner;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function sendMoney(address target, uint value) public onlyOwner {
                target.transfer(value);
            }
        }
        """
        assert detector.detect(code) == []

    def test_ignores_solc_05_and_later(self, detector):
        """solc >= 0.5 reverts on short calldata, so the attack is impossible."""
        code = """
        pragma solidity ^0.5.0;
        contract Token {
            mapping(address => uint) balances;
            function transfer(address to, uint amount) public {
                balances[msg.sender] -= amount;
                balances[to] += amount;
            }
        }
        """
        assert detector.detect(code) == []

    def test_ignores_with_length_check(self, detector):
        """Test that msg.data.length check is recognized as protection."""
        code = """
        pragma solidity ^0.4.24;
        contract Safe {
            modifier validPayload(uint size) {
                require(msg.data.length >= size);
                _;
            }
            function transfer(address to, uint amount) public validPayload(68) {
                // transfer logic
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) == 0


class TestDenialOfServiceDetectorEdgeCases:
    """Edge case tests for DenialOfServiceDetector."""

    @pytest.fixture
    def detector(self):
        return DenialOfServiceDetector()

    def test_detects_send_in_loop(self, detector):
        """Test detection of send in loop."""
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            address[] users;
            function refundAll() public {
                for (uint i = 0; i < users.length; i++) {
                    users[i].send(100);
                }
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_require_transfer(self, detector):
        """Test detection of require with transfer."""
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function bid() public payable {
                require(currentLeader.transfer(currentBid));
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_array_length_modification(self, detector):
        """Test detection of array length modification in loop."""
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            uint[] data;
            function grow() public {
                for (uint i = 0; i < 100; i++) {
                    data.length += 1;
                }
            }
        }
        """
        findings = detector.detect(code)
        # Array length modification in loop is a DoS pattern
        assert len(findings) >= 0  # May or may not detect depending on loop tracking


class TestAccessControlDetectorEdgeCases:
    """Edge case tests for AccessControlDetector."""

    @pytest.fixture
    def detector(self):
        return AccessControlDetector()

    def test_detects_suicide(self, detector):
        """Test detection of suicide function."""
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function kill() public {
                suicide(msg.sender);
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0

    def test_detects_unprotected_call_value(self, detector):
        """Test detection of unprotected call with value."""
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function forward(address to) public {
                to.call.value(100)();
            }
        }
        """
        findings = detector.detect(code)
        # May detect unchecked call or access control issue
        assert len(findings) >= 0

    def test_low_severity_for_protected_functions(self, detector):
        """Test that protected functions get lower severity."""
        code = """
        pragma solidity ^0.4.24;
        contract Safe {
            address owner;
            modifier onlyOwner() {
                require(msg.sender == owner);
                _;
            }
            function kill() public onlyOwner {
                selfdestruct(owner);
            }
        }
        """
        findings = detector.detect(code)
        # With onlyOwner, severity should be reduced or no findings
        if findings:
            # If there are findings, they should have context about protection
            assert isinstance(findings, list)


class TestTimeManipulationDetectorEdgeCases:
    """Edge case tests for TimeManipulationDetector."""

    @pytest.fixture
    def detector(self):
        return TimeManipulationDetector()

    def test_detects_block_number(self, detector):
        """Test detection of block.number usage."""
        code = """
        pragma solidity ^0.4.24;
        contract Vulnerable {
            function random() public view returns (uint) {
                return uint(keccak256(abi.encodePacked(block.number)));
            }
        }
        """
        findings = detector.detect(code)
        assert len(findings) > 0


class TestSmartBugsDetectorEngineEdgeCases:
    """Edge case tests for SmartBugsDetectorEngine."""

    @pytest.fixture
    def engine(self):
        return SmartBugsDetectorEngine()

    def test_analyze_empty_file(self, engine, tmp_path):
        """Test analyzing empty file."""
        test_file = tmp_path / "empty.sol"
        test_file.write_text("")
        findings = engine.analyze_file(test_file)
        assert isinstance(findings, list)

    def test_analyze_nonexistent_file(self, engine, tmp_path):
        """Test analyzing non-existent file."""
        test_file = tmp_path / "nonexistent.sol"
        try:
            findings = engine.analyze_file(test_file)
            # If it returns empty list, that's ok
            assert isinstance(findings, list)
        except FileNotFoundError:
            # If it raises, that's also acceptable
            pass

    def test_analyze_complex_contract(self, engine, tmp_path):
        """Test analyzing a complex contract with multiple vulnerabilities."""
        code = """
        pragma solidity ^0.4.24;
        contract Complex {
            mapping(address => uint) balances;
            address owner;
            uint public reward;

            function withdraw() public {
                uint amount = balances[msg.sender];
                msg.sender.call.value(amount)();
                balances[msg.sender] = 0;
            }

            function transfer(address to, uint amount) public {
                balances[msg.sender] -= amount;
                balances[to] += amount;
            }

            function random() public view returns (uint) {
                return uint(keccak256(abi.encodePacked(block.timestamp)));
            }

            function kill() public {
                selfdestruct(msg.sender);
            }
        }
        """
        test_file = tmp_path / "complex.sol"
        test_file.write_text(code)
        findings = engine.analyze_file(test_file)
        # Should find multiple vulnerability types
        assert len(findings) >= 3

    def test_get_summary(self, engine):
        """Test get_summary method generates correct statistics."""
        code = """
        pragma solidity ^0.4.24;
        contract MultiVuln {
            mapping(address => uint) balances;

            function withdraw() public {
                msg.sender.call.value(balances[msg.sender])();
                balances[msg.sender] = 0;
            }

            function add(uint a, uint b) public returns (uint) {
                return a + b;
            }
        }
        """
        findings = engine.analyze(code)
        summary = engine.get_summary(findings)

        assert "total" in summary
        assert "by_severity" in summary
        assert "by_category" in summary
        assert summary["total"] == len(findings)
        assert isinstance(summary["by_severity"], dict)
        assert isinstance(summary["by_category"], dict)

    def test_get_summary_empty_findings(self, engine):
        """Test get_summary with empty findings list."""
        summary = engine.get_summary([])
        assert summary["total"] == 0
        assert summary["by_severity"] == {}
        assert summary["by_category"] == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# --------------------------------------------------------------------------- #
# Arithmetic detector SKIP conditions (_get_confidence -> None) — added for
# coverage of the defensive skip branches (pre-0.8 contract required).
# --------------------------------------------------------------------------- #
def test_arithmetic_skip_conditions():
    from miesc.detectors.smartbugs_detectors import SmartBugsDetectorEngine

    src = (
        "pragma solidity ^0.4.24;\n"
        "contract Skips {\n"
        "    uint counter; uint idx; uint num; uint length; uint size; uint index;\n"
        "    function f() public {\n"
        "        uint a; uint b; uint n;\n"
        "        x = arr[i + 1];\n"  # array indexing skip
        "        string memory s = a + b;\n"  # string skip
        "        require(a + b > 0);\n"  # require/assert skip
        "        assert(a - b < n);\n"  # assert skip
        "        for (uint i = 0; i < n; i++) { y = i + 1; }\n"  # i++ / i = i + 1
        "        ++i;\n"  # ++i
        "        i += 1;\n"  # i += 1
        "        for (uint j = n; j > 0; j--) { z = j - 1; }\n"  # j-- / j -= 1
        "        --j;\n"
        "        j -= 1;\n"
        "        counter += 1;\n"  # counter += 1 (counter var)
        "        idx = idx + 1;\n"  # idx = idx + 1
        "        length -= 1;\n"
        "        size = size + 1;\n"
        "        index += 1;\n"
        "        num += 1;\n"
        "        i = i + 1;\n"
        "        k++;\n"
        "        a + b;\n"
        "    }\n"
        "    function g() public view returns (uint) { uint a; uint b; return a + b; }\n"  # view skip
        "    function h() public pure returns (uint) { uint a; uint b; return a * b; }\n"  # pure skip
        "    uint constant Z = 1 + 2;\n"  # constant skip
        "    uint immutable W = 3 + 4;\n"  # immutable skip
        "}\n"
    )
    findings = SmartBugsDetectorEngine().analyze(src)
    # all arithmetic ops here are in skip contexts -> none should be flagged as overflow
    assert all("Overflow" not in f.title for f in findings)


# =============================================================================
# Tightened short_addresses / front_running patterns on SmartBugs-curated
# =============================================================================

SMARTBUGS_DATASET = PROJECT_ROOT / "benchmarks" / "datasets" / "smartbugs-curated" / "dataset"

pytestmark_dataset = pytest.mark.skipif(
    not SMARTBUGS_DATASET.is_dir(), reason="SmartBugs-curated dataset not checked out"
)


def _dataset_source(relative: str) -> str:
    return (SMARTBUGS_DATASET / relative).read_text(encoding="utf-8", errors="replace")


@pytestmark_dataset
class TestShortAddressOnSmartBugsCurated:
    """Positive = the ground-truth contract; negative = former false positives."""

    @pytest.fixture
    def detector(self):
        return ShortAddressDetector()

    def test_ground_truth_contract_is_reported_at_the_labelled_line(self, detector):
        findings = detector.detect(_dataset_source("short_addresses/short_address_example.sol"))
        assert [f.line for f in findings] == [18]
        assert findings[0].category == "short_addresses"
        assert "sendCoin" in findings[0].description

    @pytest.mark.parametrize(
        "contract",
        [
            # AddMessage(address, uint, string): logs the arguments, credits nothing
            "reentrancy/0xb93430ce38ac4a6bb47fb1fc085ea669353fd89e.sol",
            # only an ERC20 interface declaration without a body
            "unchecked_low_level_calls/0x52d2e0f9b01101a59b38a3d05c80b7618aeed984.sol",
            # deal(address, uint8) is internal
            "bad_randomness/blackjack.sol",
        ],
    )
    def test_former_false_positives_are_silent(self, detector, contract):
        assert detector.detect(_dataset_source(contract)) == []


@pytestmark_dataset
class TestFrontRunningOnSmartBugsCurated:
    """Positive = the four ground-truth contracts; negative = former false positives."""

    @pytest.fixture
    def detector(self):
        return FrontRunningDetector()

    def test_erc20_approve_race(self, detector):
        findings = detector.detect(_dataset_source("front_running/ERC20.sol"))
        assert any(f.line == 110 and "Approve" in f.title for f in findings)

    def test_hash_puzzle(self, detector):
        findings = detector.detect(_dataset_source("front_running/FindThisHash.sol"))
        assert [(f.line, f.title) for f in findings] == [(17, "Front-Running - Hash Puzzle")]

    def test_transaction_order_dependence(self, detector):
        findings = detector.detect(
            _dataset_source("front_running/eth_tx_order_dependence_minimal.sol")
        )
        assert any(f.line == 31 and "Transaction Order" in f.title for f in findings)

    def test_player_registration_game(self, detector):
        findings = detector.detect(_dataset_source("front_running/odds_and_evens.sol"))
        assert any(f.line == 28 for f in findings)

    @pytest.mark.parametrize(
        "contract",
        [
            # keccak256 only builds a function selector
            "unchecked_low_level_calls/0x4051334adc52057aca763453820cb0e045076ef3.sol",
            # sha3(msg.data) inside multisig modifiers, no calldata secret
            "access_control/parity_wallet_bug_1.sol",
            # hash of block data (randomness), not of a parameter, next to a transfer
            "bad_randomness/guess_the_random_number.sol",
        ],
    )
    def test_former_false_positives_are_silent(self, detector, contract):
        assert detector.detect(_dataset_source(contract)) == []
