"""`context_aware_fp_check` Rules 1 and 4a look up the finding's function by its
name; that search is scoped to the finding's OWN contract, not the whole file.

A `.sol` file routinely defines the same function name in several contracts
(ERC20 `transfer`/`approve`, a sibling's `withdraw`). The old code took the
FIRST `function <name>` in the file, so it read a neighbour's modifiers:

- recall bug: a guarded `A.withdraw` suppressed a genuine finding on an
  unguarded `B.withdraw`;
- precision bug: an unguarded `A.withdraw` kept a finding that `B.withdraw`'s own
  `onlyOwner` should have cleared.

Scoping to the enclosing contract fixes BOTH directions. This is therefore a
bidirectional change (it can add and remove suppressions), unlike the purely
narrowing #318/#319/#321. Each new suppression is a real claim that the function,
in its own contract, carries the modifier.

Known limitations, unchanged here (own follow-ups): the 500-char context window
can still read a neighbouring function WITHIN the same contract, and overloads of
the same name in one contract are not disambiguated (first match wins).
"""

from __future__ import annotations

from miesc.core.intelligence import context_aware_fp_check


def _line_of(src: str, needle: str, nth: int = 1) -> int:
    seen = 0
    for i, ln in enumerate(src.split("\n"), 1):
        if needle in ln:
            seen += 1
            if seen == nth:
                return i
    raise AssertionError(f"needle not found (nth={nth}): {needle!r}")


def _finding(ftype: str, func: str, line: int) -> dict:
    return {
        "type": ftype,
        "title": ftype,
        "location": {"file": "P.sol", "function": func, "line": line},
    }


# A.withdraw is guarded, B.withdraw is not.
AC_GUARD_IN_A = """pragma solidity ^0.8.0;
contract A {
    function withdraw() external onlyOwner { payable(msg.sender).transfer(1); }
}
contract B {
    function withdraw() external { payable(msg.sender).transfer(address(this).balance); }
}
"""

# A.withdraw is not guarded, B.withdraw is.
AC_GUARD_IN_B = """pragma solidity ^0.8.0;
contract A {
    function withdraw() external { payable(msg.sender).transfer(1); }
}
contract B {
    function withdraw() external onlyOwner { payable(msg.sender).transfer(1); }
}
"""


def test_rule1_recall_sibling_guard_does_not_suppress():
    """Recall: a guard on A.withdraw must not suppress a finding on B.withdraw."""
    b_line = _line_of(AC_GUARD_IN_A, "function withdraw", nth=2)
    is_fp, _ = context_aware_fp_check(
        _finding("arbitrary-send-eth", "withdraw", b_line), AC_GUARD_IN_A, "P.sol"
    )
    assert is_fp is False


def test_rule1_recall_old_whole_file_behaviour_on_no_line():
    """No line → whole-file first match (prior behaviour): A.withdraw's guard is
    found and the finding is suppressed. Documents what the fix changes."""
    is_fp, reason = context_aware_fp_check(
        _finding("arbitrary-send-eth", "withdraw", 0), AC_GUARD_IN_A, "P.sol"
    )
    assert is_fp is True
    assert "admin modifier" in (reason or "")


def test_rule1_precision_own_guard_suppresses():
    """Precision: B.withdraw's own onlyOwner suppresses its access-control finding,
    even though the first `withdraw` in the file (A) is unguarded. NEW suppression,
    and it is correct — B.withdraw really carries the modifier."""
    b_line = _line_of(AC_GUARD_IN_B, "function withdraw", nth=2)
    is_fp, reason = context_aware_fp_check(
        _finding("arbitrary-send-eth", "withdraw", b_line), AC_GUARD_IN_B, "P.sol"
    )
    assert is_fp is True
    assert "admin modifier" in (reason or "")


REENT_GUARD_IN_A = """pragma solidity ^0.8.0;
contract A {
    function claim() external nonReentrant { (bool ok, ) = msg.sender.call{value: 1}(""); }
}
contract B {
    function claim() external { (bool ok, ) = msg.sender.call{value: 1}(""); }
}
"""


def test_rule4a_recall_sibling_nonreentrant_does_not_suppress():
    b_line = _line_of(REENT_GUARD_IN_A, "function claim", nth=2)
    is_fp, _ = context_aware_fp_check(
        _finding("reentrancy-eth", "claim", b_line), REENT_GUARD_IN_A, "P.sol"
    )
    assert is_fp is False


def test_rule4a_precision_own_nonreentrant_suppresses():
    swapped = """pragma solidity ^0.8.0;
contract A {
    function claim() external { (bool ok, ) = msg.sender.call{value: 1}(""); }
}
contract B {
    function claim() external nonReentrant { (bool ok, ) = msg.sender.call{value: 1}(""); }
}
"""
    b_line = _line_of(swapped, "function claim", nth=2)
    is_fp, reason = context_aware_fp_check(
        _finding("reentrancy-eth", "claim", b_line), swapped, "P.sol"
    )
    assert is_fp is True
    assert "nonReentrant" in (reason or "")


INHERIT_DEF = """pragma solidity ^0.8.0;
contract Base {
    function f() external onlyOwner { selfdestruct(payable(msg.sender)); }
}
contract Derived is Base {
    uint256 x;
}
"""


def test_inherited_function_reported_at_definition_is_scoped_to_base():
    """When a tool reports the finding at the definition site (in Base), the
    span is Base — which has the modifier — so it is suppressed."""
    ln = _line_of(INHERIT_DEF, "function f")
    is_fp, reason = context_aware_fp_check(
        _finding("arbitrary-send-eth", "f", ln), INHERIT_DEF, "P.sol"
    )
    assert is_fp is True
    assert "admin modifier" in (reason or "")


OVERLOAD = """pragma solidity ^0.8.0;
contract C {
    function transfer(address to) external onlyOwner { payable(to).transfer(1); }
    function transfer(address to, uint256 amt) external { payable(to).transfer(amt); }
}
"""


def test_overload_disambiguation_is_not_handled():
    """KNOWN LIMITATION (follow-up): two overloads of `transfer` in one contract,
    the FIRST guarded and the second not. A finding on the unguarded second
    overload is wrongly suppressed because the name-only search hits the first
    (guarded) overload. Pinned so the limitation is explicit, not a surprise —
    scoping fixes cross-contract collisions, not same-contract overloads."""
    second = _line_of(OVERLOAD, "function transfer", nth=2)
    is_fp, _ = context_aware_fp_check(
        _finding("arbitrary-send-eth", "transfer", second), OVERLOAD, "P.sol"
    )
    assert is_fp is True  # first (guarded) overload's modifier wrongly clears the second


# The Parity library bug: initWallet is unprotected; the adjacent kill() carries
# the owner check. The guard check must read ONLY initWallet's own text.
PARITY = """pragma solidity ^0.8.0;
contract ParityWalletLibrary {
    address public owner;
    bool public initialized;
    function initWallet(address _owner) public {
        require(!initialized);
        owner = _owner;
        initialized = true;
    }
    function kill(address _to) public {
        require(msg.sender == owner);
        selfdestruct(payable(_to));
    }
}
"""


def test_parity_initwallet_not_suppressed_by_adjacent_kill_guard():
    """Regression: the bounded window must not read kill()'s owner check when
    judging the unprotected initWallet a few lines above."""
    ln = _line_of(PARITY, "function initWallet")
    is_fp, _ = context_aware_fp_check(
        _finding("arbitrary-send-eth", "initWallet", ln), PARITY, "P.sol"
    )
    assert is_fp is False


IFACE = """pragma solidity ^0.8.0;
interface IVault {
    function withdraw() external;
}
contract Vault {
    function withdraw() external onlyOwner {}
}
"""


def test_interface_signature_without_body_does_not_crash():
    """A finding resolved to an interface declaration (no body, ends in `;`) must
    be handled without error; it has no modifier, so it is not suppressed."""
    ln = _line_of(IFACE, "function withdraw")  # the interface decl (first)
    is_fp, _ = context_aware_fp_check(
        _finding("arbitrary-send-eth", "withdraw", ln), IFACE, "P.sol"
    )
    assert is_fp is False


def test_long_body_beyond_500_chars_still_suppressed():
    """The bound is the function's own closing brace, not a 500-char cap: a
    guarded function with a long body is still recognised as guarded."""
    filler = "\n".join(f"        uint256 v{i} = {i};" for i in range(60))  # > 500 chars
    src = (
        "pragma solidity ^0.8.0;\n"
        "contract C {\n"
        "    function admin() external onlyOwner {\n"
        f"{filler}\n"
        "    }\n"
        "}\n"
    )
    ln = _line_of(src, "function admin")
    is_fp, reason = context_aware_fp_check(
        _finding("arbitrary-send-eth", "admin", ln), src, "P.sol"
    )
    assert is_fp is True
    assert "admin modifier" in (reason or "")
