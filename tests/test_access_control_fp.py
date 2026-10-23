"""Access-control rules only fire on unguarded privileged operations (SmartBugs wave, 2026-10-23).

Measured on SmartBugs-curated, LLM-free paper profile: access_control false positives
66 -> 42 with recall 143/143; the positives below are the labelled shapes, the negatives
the contracts labelled with other categories that used to be flagged.
"""

from miesc.adapters.peculiar_adapter import PeculiarAdapter
from miesc.cli.commands.evaluate import _normalize_category
from miesc.core.intelligence import detect_zero_recall_categories
from miesc.detectors.smartbugs_detectors import AccessControlDetector

TIMELOCK = """pragma solidity ^0.4.24;
contract TimeLock {
    mapping(address => uint) public balances;
    mapping(address => uint) public lockTime;
    function deposit() public payable { balances[msg.sender] += msg.value; lockTime[msg.sender] = now + 1 weeks; }
    function withdraw() public {
        require(balances[msg.sender] > 0);
        require(now > lockTime[msg.sender]);
        uint transferValue = balances[msg.sender];
        balances[msg.sender] = 0;
        msg.sender.transfer(transferValue);
    }
}
"""

LOTTERY_DESTROY = """pragma solidity ^0.4.0;
contract Lottery {
    address organizer;
    function destroy() {
        if(msg.sender != organizer) { throw; }
        suicide(organizer);
    }
    function kill() public {
        if (msg.sender == ownerAddr && now > lastPlayed + 1 days) { suicide(msg.sender); }
    }
}
"""

FIBONACCI = """pragma solidity ^0.4.22;
contract FibonacciBalance {
    address public fibonacciLibrary;
    uint public calculatedFibNumber;
    uint public withdrawalCounter;
    bytes4 constant fibSig = bytes4(keccak256("setFibonacci(uint256)"));
    function withdraw() {
        withdrawalCounter += 1;
        require(fibonacciLibrary.delegatecall(fibSig, withdrawalCounter));
        msg.sender.transfer(calculatedFibNumber * 1 ether);
    }
}
"""

ARBITRARY_WRITE = """pragma solidity ^0.4.25;
contract Wallet {
    uint[] private bonusCodes;
    address private owner;
    function PopBonusCode() public { require(0 <= bonusCodes.length); bonusCodes.length--; }
    function UpdateBonusCodeAt(uint idx, uint c) public { require(idx < bonusCodes.length); bonusCodes[idx] = c; }
}
"""

GROWS_ARRAY = """pragma solidity ^0.4.24;
contract Billions {
    uint[] public hashes;
    uint public hashesSize = 16384;
    function addHashes(uint _sadd) public returns (uint) {
        uint n = hashes.length;
        if (n + _sadd > hashesSize) { hashes.length = hashesSize; } else { hashes.length += _sadd; }
        return n;
    }
}
"""

TYPO_CONSTRUCTOR = """pragma solidity ^0.4.24;
contract Missing {
    address private owner;
    modifier onlyowner { require(msg.sender == owner); _; }
    function IamMissing() public { owner = msg.sender; }
    function () payable {}
    function withdraw() public onlyowner { owner.transfer(this.balance); }
}
"""

REAL_CONSTRUCTOR_PLUS_SETTER = """pragma solidity ^0.4.18;
contract SafeMath { function add(uint a, uint b) internal pure returns (uint) { return a + b; } }
contract Ownable {
    address public owner;
    function Ownable() public { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
}
"""


class TestLayer6AccessControl:
    def setup_method(self):
        self.detector = AccessControlDetector()

    def titles(self, code):
        return [f.description.split(".")[0] for f in self.detector.detect(code)]

    def test_user_withdrawal_is_not_missing_access_control(self):
        assert self.titles(TIMELOCK) == []

    def test_inline_owner_checks_count_as_guards(self):
        assert self.titles(LOTTERY_DESTROY) == []

    def test_payout_not_bound_to_caller_balance_is_flagged(self):
        assert "Unprotected withdrawal function" in self.titles(FIBONACCI)

    def test_array_shrink_and_param_index_write_are_flagged(self):
        assert self.titles(ARBITRARY_WRITE).count("Unprotected arbitrary storage write") == 2

    def test_array_growth_is_not_an_arbitrary_write(self):
        assert self.titles(GROWS_ARRAY) == []

    def test_legacy_constructor_typo_is_flagged(self):
        assert any(
            t.startswith("Incorrect legacy constructor name") for t in self.titles(TYPO_CONSTRUCTOR)
        )

    def test_real_legacy_constructor_is_not_a_typo(self):
        assert self.titles(REAL_CONSTRUCTOR_PLUS_SETTER) == []


class TestPeculiarAccessControl:
    def _ac(self, tmp_path, code):
        path = tmp_path / "c.sol"
        path.write_text(code)
        result = PeculiarAdapter().analyze(str(path), timeout=60)
        return [f for f in result.get("findings", []) if f.get("type") == "access_control"]

    def test_user_withdrawal_is_not_privileged(self, tmp_path):
        assert self._ac(tmp_path, TIMELOCK) == []

    def test_custom_only_modifier_is_a_guard(self, tmp_path):
        code = "pragma solidity ^0.4.0;\ncontract T { address w; modifier onlywizard { if (msg.sender != w) throw; _; }\n  function transferOwnership(address n) onlywizard { w = n; } }\n"
        assert self._ac(tmp_path, code) == []

    def test_reading_paused_is_not_pause(self, tmp_path):
        code = "pragma solidity ^0.4.0;\ncontract R { bool paused; function buy() payable public { if (paused) { msg.sender.transfer(msg.value); return; } } }\n"
        assert self._ac(tmp_path, code) == []

    def test_bookkeeping_named_withdraw_without_value_is_not_flagged(self, tmp_path):
        code = "pragma solidity ^0.4.0;\ncontract B { mapping(address=>uint) r; function getFirstWithdrawalBonus(address a) public { r[a] += 100; } }\n"
        assert self._ac(tmp_path, code) == []

    def test_unguarded_drain_is_flagged(self, tmp_path):
        code = "pragma solidity ^0.4.0;\ncontract D { function withdrawAll() public { msg.sender.transfer(this.balance); } }\n"
        assert len(self._ac(tmp_path, code)) == 1


class TestIntelligenceAccessControlFilters:
    def types(self, code):
        return sorted({f["type"] for f in detect_zero_recall_categories(code)})

    def test_constructor_regex_does_not_cross_contracts(self):
        assert "constructor_mismatch" not in self.types(REAL_CONSTRUCTOR_PLUS_SETTER)
        assert "incorrect_constructor_name" not in self.types(REAL_CONSTRUCTOR_PLUS_SETTER)

    def test_typo_constructor_still_reported(self):
        assert "incorrect_constructor_name" in self.types(TYPO_CONSTRUCTOR)

    def test_init_setting_a_flag_is_not_an_ownership_takeover(self):
        code = "contract A { uint initialized; mapping(uint=>uint) map; function init() public { initialized = 1; } function init2(uint k, uint v) public { map[k] -= v; } }"
        assert "access_control_initwallet" not in self.types(code)

    def test_init_that_sets_owner_or_delegates_to_init_is_reported(self):
        assert "access_control_initwallet" in self.types(
            "contract W { address owner; function initWallet(address o) public { owner = o; } }"
        )
        assert "access_control_initwallet" in self.types(
            "contract W { function initWallet(address[] o, uint r) public { initMultiowned(o, r); } }"
        )

    def test_guarded_owner_reassignment_is_not_reported(self):
        code = "contract O { address owner; function setOwner(address n) public { require(msg.sender == owner); owner = n; } }"
        assert "access_control_owner_reassign" not in self.types(code)
        assert "access_control_newowner_public" not in self.types(code)


def test_ownership_not_renounced_is_a_note_not_a_category():
    desc = "Contract has onlyOwner functions but ownership is not renounced. Owner retains control."
    assert _normalize_category("", "Ownership Not Renounced", desc, "rug_pull") is None
    assert _normalize_category("Ownership Not Renounced", "Ownership Not Renounced", desc) is None
