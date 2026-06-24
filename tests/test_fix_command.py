"""
Tests for the `miesc fix` CLI command.

Covers:
  - Reentrancy fix → nonReentrant modifier added
  - Access control fix → onlyOwner modifier added
  - Unchecked call fix → require(success) wrapping added
  - Arithmetic fix → SafeMath insertion on pre-0.8 pragma
  - Generic/unknown type → comment block with fix_code inserted
  - No findings with fix_code → exits 0 with "nothing to fix" message
  - Output file is written to --output path when specified
  - Default output path (<stem>.fixed.sol) when -o is omitted
  - Multiple findings on the same contract are all applied
  - Dry-run flag shows summary without writing a file
  - Results JSON with only per-tool results (not top-level findings)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from miesc.cli.commands.fix import (
    _add_modifier_to_function,
    _collect_fixable_findings,
    _insert_using_safemath,
    apply_fix,
    fix,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SIMPLE_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Victim {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    function restricted() public {
        balances[msg.sender] = 0;
    }
}
"""

LEGACY_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract Token {
    uint256 public total;

    function mint(uint256 amount) public {
        total += amount;
    }
}
"""

LEGACY_UNCHECKED_CALL_CONTRACT = """\
pragma solidity 0.4.25;

contract ReturnValue {
  function callnotchecked(address callee) public {
    callee.call();
  }
}
"""

LEGACY_UNCHECKED_SEND_CONTRACT = """\
pragma solidity ^0.4.0;

contract SendBack {
    mapping (address => uint) userBalances;
    function withdrawBalance() public {
        uint amountToWithdraw = userBalances[msg.sender];
        userBalances[msg.sender] = 0;
        msg.sender.send(amountToWithdraw);
    }
}
"""


@pytest.fixture
def contract_file(tmp_path):
    p = tmp_path / "Victim.sol"
    p.write_text(SIMPLE_CONTRACT)
    return p


@pytest.fixture
def legacy_contract_file(tmp_path):
    p = tmp_path / "Token.sol"
    p.write_text(LEGACY_CONTRACT)
    return p


def _make_results(findings: list, tmp_path: Path) -> Path:
    """Write a minimal MIESC results JSON to a temp file and return the path."""
    data = {
        "contract": "Victim.sol",
        "findings": findings,
    }
    p = tmp_path / "results.json"
    p.write_text(json.dumps(data))
    return p


def _make_results_tool_format(findings: list, tmp_path: Path) -> Path:
    """Write results using the per-tool `results` array format."""
    data = {
        "contract": "Victim.sol",
        "results": [{"tool": "slither", "status": "success", "findings": findings}],
    }
    p = tmp_path / "results.json"
    p.write_text(json.dumps(data))
    return p


# ---------------------------------------------------------------------------
# Unit tests — patching helpers
# ---------------------------------------------------------------------------


class TestAddModifierToFunction:
    def test_adds_modifier_to_existing_function(self):
        source, changed = _add_modifier_to_function(SIMPLE_CONTRACT, "withdraw", "nonReentrant")
        assert changed
        assert "nonReentrant" in source
        # Must appear inside the function signature
        assert "function withdraw" in source

    def test_does_not_duplicate_existing_modifier(self):
        source_with_modifier = SIMPLE_CONTRACT.replace(
            "function withdraw(uint256 amount) public",
            "function withdraw(uint256 amount) public nonReentrant",
        )
        source, changed = _add_modifier_to_function(
            source_with_modifier, "withdraw", "nonReentrant"
        )
        assert not changed

    def test_returns_unchanged_when_function_not_found(self):
        source, changed = _add_modifier_to_function(
            SIMPLE_CONTRACT, "nonExistentFunction", "nonReentrant"
        )
        assert not changed
        assert source == SIMPLE_CONTRACT


class TestInsertUsingSafeMath:
    def test_inserts_after_contract_opening_brace(self):
        source, changed = _insert_using_safemath(LEGACY_CONTRACT)
        assert changed
        assert "using SafeMath for uint256;" in source

    def test_does_not_change_source_without_contract(self):
        source, changed = _insert_using_safemath("// just a comment\n")
        assert not changed


class TestCollectFixableFindings:
    def test_finds_top_level_findings_with_fix_code(self):
        data = {
            "findings": [
                {"type": "reentrancy", "fix_code": "add nonReentrant"},
                {"type": "access_control"},  # no fix_code → skipped
            ]
        }
        result = _collect_fixable_findings(data)
        assert len(result) == 1
        assert result[0]["type"] == "reentrancy"

    def test_finds_per_tool_findings_with_fix_code(self):
        data = {
            "results": [
                {
                    "tool": "slither",
                    "findings": [
                        {"type": "reentrancy", "fix_code": "add nonReentrant"},
                    ],
                }
            ]
        }
        result = _collect_fixable_findings(data)
        assert len(result) == 1

    def test_returns_empty_when_no_fix_code(self):
        data = {"findings": [{"type": "reentrancy"}]}
        result = _collect_fixable_findings(data)
        assert result == []

    def test_synthesizes_dos_array_fix_codes(self):
        data = {
            "findings": [
                {
                    "type": "controlled-array-length",
                    "severity": "High",
                    "location": {"line": 24, "function": "DosGas"},
                },
                {
                    "type": "dynamic-array-length-assignment",
                    "severity": "High",
                    "location": {"line": 20, "function": "unknown"},
                },
            ]
        }

        result = _collect_fixable_findings(data)

        assert len(result) == 2
        assert "unbounded dynamic array growth" in result[0]["fix_code"]
        assert "array.length" in result[1]["fix_code"]

    def test_synthesizes_static_fallback_fix_codes(self):
        data = {
            "findings": [
                {
                    "type": "arbitrary-send-eth",
                    "severity": "High",
                    "location": {"line": 6, "function": "pay"},
                },
                {
                    "type": "incorrect_constructor_name",
                    "severity": "Critical",
                    "location": {"line": 17, "function": "unknown"},
                },
                {
                    "type": "tautology-or-contradiction",
                    "severity": "High",
                    "location": {"line": 20, "function": "unknown"},
                },
            ]
        }

        result = _collect_fixable_findings(data)

        assert len(result) == 3
        assert "ETH-transfer functions" in result[0]["fix_code"]
        assert "constructor()" in result[1]["fix_code"]
        assert "tautological or contradictory comparisons" in result[2]["fix_code"]

    def test_combines_top_level_and_per_tool(self):
        data = {
            "findings": [{"type": "reentrancy", "fix_code": "x"}],
            "results": [
                {
                    "tool": "aderyn",
                    "findings": [{"type": "access_control", "fix_code": "y"}],
                }
            ],
        }
        result = _collect_fixable_findings(data)
        assert len(result) == 2


class TestApplyFix:
    def test_reentrancy_adds_nonreentrant(self):
        finding = {
            "type": "reentrancy",
            "function": "withdraw",
            "fix_code": "add nonReentrant",
        }
        patched, changed = apply_fix(SIMPLE_CONTRACT, finding)
        assert changed
        assert "nonReentrant" in patched

    def test_reentrancy_legacy_call_value_moves_balance_effect_before_call(self):
        source = """\
pragma solidity ^0.4.19;

contract Bank {
    mapping(address => uint256) public balances;

    function Collect(uint256 _am) public {
        if (balances[msg.sender] >= _am) {
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender]-=_am;
                emit Collected(msg.sender, _am);
            }
        }
    }

    event Collected(address who, uint256 amount);
}
"""
        finding = {
            "type": "reentrancy",
            "function": "Collect",
            "line": 7,
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "MIESC: checks-effects-interactions for legacy call.value" in patched
        assert (
            "balances[msg.sender] -= _am;\n            if(msg.sender.call.value(_am)())" in patched
        )
        assert "else\n            {\n                balances[msg.sender] += _am;" in patched
        assert patched.index("balances[msg.sender] -= _am;") < patched.index(
            "if(msg.sender.call.value(_am)())"
        )

    def test_reentrancy_legacy_call_value_keeps_mismatched_effect_in_place(self):
        source = """\
pragma solidity ^0.4.19;

contract Bank {
    mapping(address => uint256) public balances;

    function Collect(uint256 _am, uint256 fee) public {
        if(msg.sender.call.value(_am)())
        {
            balances[msg.sender]-=fee;
        }
    }
}
"""
        finding = {
            "type": "reentrancy",
            "function": "Collect",
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "MIESC: checks-effects-interactions" not in patched
        assert "balances[msg.sender]-=fee;" in patched

    def test_reentrancy_legacy_call_value_moves_storage_alias_effect_before_call(self):
        source = """\
pragma solidity ^0.4.25;

contract Bank {
    struct Account {
        uint256 balance;
    }
    mapping(address => Account) public Acc;

    function Collect(uint256 _am) public {
        var acc = Acc[msg.sender];
        if (acc.balance >= _am) {
            if(msg.sender.call.value(_am)())
            {
                acc.balance -= _am;
                emit Collected(msg.sender, _am);
            }
        }
    }

    event Collected(address who, uint256 amount);
}
"""
        finding = {
            "type": "reentrancy",
            "function": "Collect",
            "line": 9,
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "MIESC: checks-effects-interactions for legacy call.value" in patched
        assert "acc.balance -= _am;\n            if(msg.sender.call.value(_am)())" in patched
        assert "else\n            {\n                acc.balance += _am;" in patched
        assert patched.index("acc.balance -= _am;") < patched.index(
            "if(msg.sender.call.value(_am)())"
        )

    def test_reentrancy_legacy_require_call_value_moves_following_effects_before_call(self):
        source = """\
pragma solidity ^0.4.10;

contract EtherStore {
    uint256 public withdrawalLimit = 1 ether;
    mapping(address => uint256) public lastWithdrawTime;
    mapping(address => uint256) public balances;

    function withdrawFunds (uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        require(_weiToWithdraw <= withdrawalLimit);
        require(now >= lastWithdrawTime[msg.sender] + 1 weeks);
        require(msg.sender.call.value(_weiToWithdraw)());
        balances[msg.sender] -= _weiToWithdraw;
        lastWithdrawTime[msg.sender] = now;
    }
}
"""
        finding = {
            "type": "reentrancy",
            "function": "withdrawFunds",
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "MIESC: checks-effects-interactions for legacy call.value" in patched
        assert patched.index("balances[msg.sender] -= _weiToWithdraw;") < patched.index(
            "require(msg.sender.call.value(_weiToWithdraw)());"
        )
        assert patched.index("lastWithdrawTime[msg.sender] = now;") < patched.index(
            "require(msg.sender.call.value(_weiToWithdraw)());"
        )

    def test_reentrancy_legacy_inverted_throw_call_value_moves_zeroing_before_call(self):
        source = """\
pragma solidity ^0.4.0;

contract EtherBank{
    mapping (address => uint) userBalances;

    function withdrawBalance() {
        uint amountToWithdraw = userBalances[msg.sender];
        if (!(msg.sender.call.value(amountToWithdraw)())) { throw; }
        userBalances[msg.sender] = 0;
    }
}
"""
        finding = {
            "type": "reentrancy",
            "function": "withdrawBalance",
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "MIESC: checks-effects-interactions for legacy call.value" in patched
        assert patched.index("userBalances[msg.sender] = 0;") < patched.index(
            "if (!(msg.sender.call.value(amountToWithdraw)()))"
        )

    def test_reentrancy_legacy_bool_call_value_moves_decrement_and_requires_success(self):
        source = """\
pragma solidity ^0.4.2;

contract SimpleDAO {
  mapping (address => uint) public credit;

  function withdraw(uint amount) {
    if (credit[msg.sender] >= amount) {
      bool res = msg.sender.call.value(amount)();
      credit[msg.sender] -= amount;
    }
  }
}
"""
        finding = {
            "type": "reentrancy",
            "function": "withdraw",
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "MIESC: checks-effects-interactions for legacy call.value" in patched
        assert patched.index("credit[msg.sender] -= amount;") < patched.index(
            "bool res = msg.sender.call.value(amount)();"
        )
        assert "require(res);" in patched

    def test_reentrancy_normalizes_legacy_call_value_tuple_assignment(self):
        source = """\
pragma solidity ^0.4.24;

contract Bonus {
    function withdraw(address recipient, uint256 amount) public {
        (bool success, ) = recipient.call.value(amount)("");
        require(success);
    }
}
"""
        finding = {
            "type": "reentrancy",
            "function": "withdraw",
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "(bool success, )" not in patched
        assert 'bool success = recipient.call.value(amount)("");' in patched
        assert "require(success);" in patched

    def test_reentrancy_ignores_openzeppelin_import_inside_fix_comment(self):
        source = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/*
MIESC FIX: reentrancy
Suggested patch:
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract SafeVault is ReentrancyGuard {
    function withdraw() external nonReentrant {}
}
*/

contract Victim {
    function withdraw() public {
        (bool ok, ) = msg.sender.call("");
        require(ok);
    }
}
"""
        finding = {
            "type": "reentrancy",
            "function": "withdraw",
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "contract MiescReentrancyGuard" in patched
        assert "contract Victim is MiescReentrancyGuard" in patched
        assert "contract Victim is ReentrancyGuard" not in patched

    def test_reentrancy_guard_is_added_to_contract_containing_target_function(self):
        source = """\
pragma solidity ^0.8.0;

contract First {
    function noop() public {}
}

contract Second {
    function withdraw() public {
        (bool ok, ) = msg.sender.call("");
        require(ok);
    }
}
"""
        finding = {
            "type": "reentrancy",
            "function": "withdraw",
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "contract First is MiescReentrancyGuard" not in patched
        assert "contract Second is MiescReentrancyGuard" in patched
        assert "function withdraw() nonReentrant public" in patched

    def test_reentrancy_guard_uses_line_hint_for_duplicate_function_names(self):
        source = """\
pragma solidity ^0.8.0;

contract First {
    function create() internal {
    }
}

contract Second {
    function create() internal {
    }
}
"""
        finding = {
            "type": "reentrancy",
            "function": "create",
            "line": 8,
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "contract First is MiescReentrancyGuard" not in patched
        assert "contract Second is MiescReentrancyGuard" in patched
        assert "function create() nonReentrant internal" in patched

    def test_reentrancy_adds_inheritance_when_guard_definition_already_exists(self):
        source = """\
pragma solidity ^0.8.0;

contract MiescReentrancyGuard {
    modifier nonReentrant() { _; }
}

contract First is MiescReentrancyGuard {
    function one() nonReentrant public {}
}

contract Second {
    function two() public {}
}
"""
        finding = {
            "type": "reentrancy",
            "function": "two",
            "line": 11,
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert patched.count("contract MiescReentrancyGuard") == 1
        assert "contract Second is MiescReentrancyGuard" in patched
        assert "function two() nonReentrant public" in patched

    def test_reentrancy_does_not_duplicate_transitive_guard_inheritance(self):
        source = """\
pragma solidity ^0.8.0;

contract MiescReentrancyGuard {
    modifier nonReentrant() { _; }
}

contract Base is MiescReentrancyGuard {
}

contract Child is Base {
    function guarded() public {}
}
"""
        finding = {
            "type": "reentrancy",
            "function": "guarded",
            "line": 11,
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "contract Child is Base, MiescReentrancyGuard" not in patched
        assert "contract Child is Base" in patched
        assert "function guarded() nonReentrant public" in patched

    def test_reentrancy_removes_redundant_direct_guard_from_descendant(self):
        source = """\
pragma solidity ^0.8.0;

contract MiescReentrancyGuard {
    modifier nonReentrant() { _; }
}

contract Base {
    function baseGuarded() public {}
}

contract Child is Base, MiescReentrancyGuard {
    function childGuarded() nonReentrant public {}
}
"""
        finding = {
            "type": "reentrancy",
            "function": "baseGuarded",
            "line": 8,
            "fix_code": "add nonReentrant",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "contract Base is MiescReentrancyGuard" in patched
        assert "contract Child is Base, MiescReentrancyGuard" not in patched
        assert "contract Child is Base" in patched

    def test_access_control_adds_only_owner(self):
        finding = {
            "type": "access_control",
            "function": "restricted",
            "fix_code": "add onlyOwner",
        }
        patched, changed = apply_fix(SIMPLE_CONTRACT, finding)
        assert changed
        assert "onlyOwner" in patched
        assert "address public owner = msg.sender;" in patched

    def test_access_control_reuses_existing_private_owner_state(self):
        source = """\
pragma solidity ^0.8.0;

contract Wallet {
    address private owner;

    constructor() {
        owner = msg.sender;
    }

    function destroy() public {
        selfdestruct(payable(msg.sender));
    }
}
"""
        finding = {
            "type": "access_control",
            "function": "destroy",
            "fix_code": "add onlyOwner",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "address private owner;" in patched
        assert "address public owner = msg.sender;" not in patched
        assert "function destroy() onlyOwner public" in patched

    def test_access_control_modifier_is_added_to_contract_containing_target_function(self):
        source = """\
pragma solidity ^0.8.0;

contract Abi {
    function kill() external;
}

contract Wallet {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
"""
        finding = {
            "type": "access_control",
            "function": "kill",
            "fix_code": "add onlyOwner",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "contract Abi {\n    // MIESC: Inline onlyOwner modifier" not in patched
        assert "contract Wallet {" in patched
        assert "MIESC: Inline onlyOwner modifier" in patched
        assert "function kill() onlyOwner public" in patched

    def test_arbitrary_send_eth_adds_only_owner(self):
        source = """\
pragma solidity ^0.8.20;

contract Treasury {
    function pay(address payable recipient) public {
        recipient.transfer(address(this).balance);
    }
}
"""
        finding = {
            "type": "arbitrary-send-eth",
            "function": "pay",
            "fix_code": "restrict arbitrary recipient transfers",
        }

        patched, changed = apply_fix(source, finding)

        assert changed
        assert "MIESC: Inline onlyOwner modifier" in patched
        assert "address public owner = msg.sender;" in patched
        assert "function pay(address payable recipient) onlyOwner public" in patched

    def test_arithmetic_inserts_safemath_on_legacy(self):
        finding = {
            "type": "arithmetic",
            "function": "mint",
            "fix_code": "use SafeMath",
        }
        patched, changed = apply_fix(LEGACY_CONTRACT, finding)
        assert changed
        assert "using SafeMath for uint256;" in patched

    def test_unchecked_legacy_call_uses_single_bool_return(self):
        finding = {
            "type": "unchecked-call",
            "function": "callnotchecked",
            "fix_code": "check call return",
        }
        patched, changed = apply_fix(LEGACY_UNCHECKED_CALL_CONTRACT, finding)

        assert changed
        assert "bool miescCallSuccess = callee.call();" in patched
        assert 'require(miescCallSuccess, "Call failed");' in patched
        assert "(bool miescCallSuccess, ) = callee.call();" not in patched

    def test_unchecked_send_gets_require_check(self):
        finding = {
            "type": "unchecked-call",
            "function": "withdrawBalance",
            "fix_code": "check send return",
        }
        patched, changed = apply_fix(LEGACY_UNCHECKED_SEND_CONTRACT, finding)

        assert changed
        assert "bool miescCallSuccess = msg.sender.send(amountToWithdraw);" in patched
        assert 'require(miescCallSuccess, "Call failed");' in patched

    def test_unchecked_existing_tuple_assignment_gets_require_check(self):
        finding = {
            "type": "unchecked-call",
            "function": "withdraw",
            "fix_code": "check call return",
        }
        patched, changed = apply_fix(SIMPLE_CONTRACT, finding)

        assert changed
        assert '(bool ok, ) = msg.sender.call{value: amount}("");' in patched
        assert 'require(ok, "Call failed");' in patched

    def test_reentrancy_line_inference_uses_original_source_after_safemath_insert(self, tmp_path):
        source = """\
pragma solidity ^0.6.12;

contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""
        contract = tmp_path / "Vault.sol"
        contract.write_text(source)
        results = _make_results(
            [
                {"type": "arithmetic", "line": 9, "fix_code": "use SafeMath"},
                {"type": "reentrancy", "line": 6, "fix_code": "add nonReentrant"},
            ],
            tmp_path,
        )
        out = tmp_path / "patched.sol"

        runner = CliRunner()
        result = runner.invoke(
            fix,
            [str(results), "--contract", str(contract), "--output", str(out), "--quiet"],
        )

        assert result.exit_code == 0
        patched = out.read_text()
        assert "function withdraw(uint256 amount) nonReentrant public" in patched
        assert "function add(uint256 a, uint256 b) nonReentrant" not in patched
        assert "function sub(uint256 a, uint256 b) nonReentrant" not in patched

    def test_generic_type_inserts_comment_block(self):
        finding = {
            "type": "timestamp_dependence",
            "function": "deposit",
            "fix_code": "Avoid block.timestamp for randomness.",
        }
        patched, changed = apply_fix(SIMPLE_CONTRACT, finding)
        assert changed
        assert "MIESC FIX: timestamp_dependence" in patched
        assert "Avoid block.timestamp for randomness." in patched

    def test_generic_type_without_function_inserts_file_comment_block(self):
        finding = {
            "type": "time_manipulation",
            "location": {"line": 1, "function": "unknown"},
            "fix_code": "Avoid block.timestamp for ordering-sensitive logic.",
        }

        patched, changed = apply_fix(SIMPLE_CONTRACT, finding)

        assert changed
        assert "MIESC FIX: time_manipulation" in patched
        assert "Avoid block.timestamp for ordering-sensitive logic." in patched
        assert patched.index("MIESC FIX: time_manipulation") < patched.index("contract Victim")

    def test_generic_type_with_non_function_location_falls_back_to_file_comment(self):
        finding = {
            "type": "uninitialized-storage",
            "location": {"line": 12, "function": "newRecord"},
            "fix_code": "Initialize storage references explicitly.",
        }

        patched, changed = apply_fix(SIMPLE_CONTRACT, finding)

        assert changed
        assert "MIESC FIX: uninitialized_storage" in patched
        assert "Initialize storage references explicitly." in patched
        assert "function newRecord" not in patched

    def test_no_change_when_function_not_found(self):
        finding = {
            "type": "reentrancy",
            "function": "ghostFunction",
            "fix_code": "add nonReentrant",
        }
        patched, changed = apply_fix(SIMPLE_CONTRACT, finding)
        assert not changed
        assert patched == SIMPLE_CONTRACT


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


class TestFixCommand:
    def test_help_shows_expected_options(self):
        runner = CliRunner()
        result = runner.invoke(fix, ["--help"])
        assert result.exit_code == 0
        assert "--contract" in result.output
        assert "--output" in result.output
        assert "--dry-run" in result.output

    def test_no_findings_with_fix_code_exits_zero(self, contract_file, tmp_path):
        results_file = _make_results(
            [{"type": "reentrancy"}],  # no fix_code
            tmp_path,
        )
        runner = CliRunner()
        result = runner.invoke(
            fix, [str(results_file), "--contract", str(contract_file), "--quiet"]
        )
        assert result.exit_code == 0
        assert "nothing to fix" in result.output.lower()

    def test_reentrancy_fix_written_to_output(self, contract_file, tmp_path):
        results_file = _make_results(
            [{"type": "reentrancy", "function": "withdraw", "fix_code": "add nonReentrant"}],
            tmp_path,
        )
        out = tmp_path / "patched.sol"
        runner = CliRunner()
        result = runner.invoke(
            fix,
            [str(results_file), "--contract", str(contract_file), "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.exists()
        content = out.read_text()
        assert "nonReentrant" in content

    def test_access_control_fix_written_to_output(self, contract_file, tmp_path):
        results_file = _make_results(
            [{"type": "access_control", "function": "restricted", "fix_code": "add onlyOwner"}],
            tmp_path,
        )
        out = tmp_path / "patched.sol"
        runner = CliRunner()
        result = runner.invoke(
            fix,
            [str(results_file), "--contract", str(contract_file), "--output", str(out)],
        )
        assert result.exit_code == 0
        content = out.read_text()
        assert "onlyOwner" in content

    def test_default_output_path_is_stem_fixed_sol(self, contract_file, tmp_path):
        """When -o is omitted, the output should be <stem>.fixed.sol next to the contract."""
        results_file = _make_results(
            [{"type": "reentrancy", "function": "withdraw", "fix_code": "x"}],
            tmp_path,
        )
        runner = CliRunner()
        result = runner.invoke(fix, [str(results_file), "--contract", str(contract_file)])
        assert result.exit_code == 0
        expected_out = contract_file.parent / "Victim.fixed.sol"
        assert expected_out.exists()

    def test_multiple_findings_all_applied(self, contract_file, tmp_path):
        findings = [
            {"type": "reentrancy", "function": "withdraw", "fix_code": "add nonReentrant"},
            {"type": "access_control", "function": "restricted", "fix_code": "add onlyOwner"},
        ]
        results_file = _make_results(findings, tmp_path)
        out = tmp_path / "patched.sol"
        runner = CliRunner()
        result = runner.invoke(
            fix,
            [str(results_file), "--contract", str(contract_file), "--output", str(out)],
        )
        assert result.exit_code == 0
        content = out.read_text()
        assert "nonReentrant" in content
        assert "onlyOwner" in content

    def test_dry_run_does_not_write_file(self, contract_file, tmp_path):
        results_file = _make_results(
            [{"type": "reentrancy", "function": "withdraw", "fix_code": "add nonReentrant"}],
            tmp_path,
        )
        out = tmp_path / "patched.sol"
        runner = CliRunner()
        result = runner.invoke(
            fix,
            [
                str(results_file),
                "--contract",
                str(contract_file),
                "--output",
                str(out),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0
        assert not out.exists()
        assert "dry-run" in result.output.lower()

    def test_per_tool_results_format_is_processed(self, contract_file, tmp_path):
        """Results JSON with `results[].findings` (not top-level) must be processed."""
        results_file = _make_results_tool_format(
            [{"type": "reentrancy", "function": "withdraw", "fix_code": "add nonReentrant"}],
            tmp_path,
        )
        out = tmp_path / "patched.sol"
        runner = CliRunner()
        result = runner.invoke(
            fix,
            [str(results_file), "--contract", str(contract_file), "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.exists()
        assert "nonReentrant" in out.read_text()

    def test_invalid_results_file_exits_nonzero(self, contract_file, tmp_path):
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("not valid json {{")
        runner = CliRunner()
        result = runner.invoke(fix, [str(bad_json), "--contract", str(contract_file), "--quiet"])
        assert result.exit_code != 0
