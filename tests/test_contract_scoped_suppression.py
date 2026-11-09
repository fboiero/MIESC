"""Contract-level guard checks (`context_aware_fp_check` Rules 4b / 5 / 6) run
against the finding's OWN contract, not the whole file.

A `.sol` file routinely holds several contracts (interfaces, base + derived,
libraries). The presence checks — ``"ReentrancyGuard" in src``, OZ upgrade
infra, ``SafeERC20`` usage — used to scan the entire file, so a guard/import in
contract A silently suppressed a genuine finding in contract B. These now scope
to the contract that contains the finding's line (declaration header through the
closing brace, so an inherited ``is ReentrancyGuard`` guard is still seen). When
the finding has no line that lands in a contract, the check falls back to the
whole file (prior behaviour).

Function-match scoping (Rules 1 and 4a) is intentionally NOT changed here — that
is bidirectional (it can add suppressions) and belongs in its own PR.
"""

from __future__ import annotations

from miesc.core.intelligence import _enclosing_contract_text, context_aware_fp_check


def _line_of(src: str, needle: str) -> int:
    for i, ln in enumerate(src.split("\n"), 1):
        if needle in ln:
            return i
    raise AssertionError(f"needle not found: {needle!r}")


def _finding(ftype: str, line: int, func: str = "unknown") -> dict:
    return {
        "type": ftype,
        "title": ftype,
        "location": {"file": "P.sol", "function": func, "line": line},
    }


TWO_CONTRACTS = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Vault is ReentrancyGuard {
    function safeWithdraw() external nonReentrant {}
}
contract Bank {
    mapping(address => uint) bal;
    function withdraw() external {
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}("");
        bal[msg.sender] = 0;
    }
}
"""


def test_rule4_guard_in_sibling_contract_does_not_suppress():
    """Vault's `ReentrancyGuard` must not protect Bank's genuine reentrancy."""
    ln = _line_of(TWO_CONTRACTS, "function withdraw")
    is_fp, _ = context_aware_fp_check(_finding("reentrancy-eth", ln), TWO_CONTRACTS, "P.sol")
    assert is_fp is False


def test_rule4_fallback_to_whole_file_when_no_line():
    """No usable line → fall back to whole-file presence (prior behaviour)."""
    is_fp, reason = context_aware_fp_check(_finding("reentrancy-eth", 0), TWO_CONTRACTS, "P.sol")
    assert is_fp is True
    assert "ReentrancyGuard" in (reason or "")


INHERITED_GUARD = """pragma solidity ^0.8.0;
contract Bank is ReentrancyGuard {
    function withdraw() external {
        (bool ok, ) = msg.sender.call{value: 1}("");
    }
}
"""


def test_rule4_inherited_guard_in_header_suppresses():
    """Guard present only via the `is ReentrancyGuard` header (no `nonReentrant`
    on the function) must still suppress — proves the span includes the header."""
    ln = _line_of(INHERITED_GUARD, "function withdraw")
    is_fp, reason = context_aware_fp_check(_finding("reentrancy-eth", ln), INHERITED_GUARD, "P.sol")
    assert is_fp is True
    assert "ReentrancyGuard" in (reason or "")


PROXY = """pragma solidity ^0.8.0;
contract Upgradeable is UUPSUpgradeable {
    function _authorizeUpgrade(address) internal {}
}
contract Plain {
    function upgrade(address impl) external {}
}
"""


def test_rule5_proxy_infra_in_sibling_does_not_suppress():
    ln = _line_of(PROXY, "function upgrade")
    is_fp, _ = context_aware_fp_check(_finding("proxy_upgrade", ln), PROXY, "P.sol")
    assert is_fp is False


def test_rule5_own_contract_proxy_infra_suppresses():
    ln = _line_of(PROXY, "_authorizeUpgrade")
    is_fp, _ = context_aware_fp_check(_finding("proxy_upgrade", ln), PROXY, "P.sol")
    assert is_fp is True


SAFE_ERC20 = """pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
contract A {
    using SafeERC20 for IERC20;
    function a(IERC20 t) external { t.safeTransfer(msg.sender, 1); }
}
contract B {
    function b(IERC20 t) external { t.transfer(msg.sender, 1); }
}
"""


def test_rule6_safeerc20_in_sibling_does_not_suppress():
    """Import is file-level, but B does not `using SafeERC20` — its raw transfer
    finding must stay even though sibling A uses it."""
    ln = _line_of(SAFE_ERC20, "t.transfer(")
    is_fp, _ = context_aware_fp_check(_finding("unchecked-transfer", ln), SAFE_ERC20, "P.sol")
    assert is_fp is False


def test_rule6_own_contract_safeerc20_suppresses():
    ln = _line_of(SAFE_ERC20, "t.safeTransfer(")
    is_fp, _ = context_aware_fp_check(_finding("unchecked-transfer", ln), SAFE_ERC20, "P.sol")
    assert is_fp is True


SINGLE = """pragma solidity ^0.8.0;
contract Bank is ReentrancyGuard {
    function withdraw() external { (bool ok, ) = msg.sender.call{value: 1}(""); }
}
"""


def test_single_contract_behaviour_preserved():
    """One contract → scope == whole file → existing suppression still fires."""
    ln = _line_of(SINGLE, "function withdraw")
    is_fp, _ = context_aware_fp_check(_finding("reentrancy-eth", ln), SINGLE, "P.sol")
    assert is_fp is True


def test_enclosing_contract_text_returns_own_contract_with_header():
    ln = _line_of(TWO_CONTRACTS, "function withdraw")
    text = _enclosing_contract_text(TWO_CONTRACTS, ln)
    assert text is not None
    assert text.lstrip().startswith("contract Bank")
    assert "function withdraw" in text
    assert "ReentrancyGuard" not in text  # Vault's header/guard is out of scope


def test_enclosing_contract_text_none_outside_any_contract():
    # line 2 (pragma) is outside any contract body
    assert _enclosing_contract_text(TWO_CONTRACTS, 2) is None
    assert _enclosing_contract_text(TWO_CONTRACTS, 0) is None
    assert _enclosing_contract_text("", 1) is None


BODY_GUARD = """pragma solidity ^0.8.0;
contract Safe {
    modifier MiescReentrancyGuard() { _; }
    function pull() external MiescReentrancyGuard {}
}
contract Bank {
    function withdraw() external { (bool ok, ) = msg.sender.call{value: 1}(""); }
}
"""


def test_rule4_body_only_guard_suppresses_own_not_sibling():
    """The MIESC inline guard lives in the contract BODY (a modifier), not the
    `is` header — pins that the span covers the body too."""
    safe_ln = _line_of(BODY_GUARD, "function pull")
    is_fp, _ = context_aware_fp_check(_finding("reentrancy-eth", safe_ln), BODY_GUARD, "P.sol")
    assert is_fp is True  # guard is in Safe's own body

    bank_ln = _line_of(BODY_GUARD, "function withdraw")
    is_fp, _ = context_aware_fp_check(_finding("reentrancy-eth", bank_ln), BODY_GUARD, "P.sol")
    assert is_fp is False  # Safe's body guard must not reach Bank


DECLS = """pragma solidity ^0.8.0;
interface IToken { function transfer(address, uint) external returns (bool); }
library Math { function add(uint a, uint b) internal pure returns (uint) { return a + b; } }
abstract contract Base is ReentrancyGuard { function f() external virtual; }
contract Impl { function withdraw() external { (bool ok, ) = msg.sender.call{value: 1}(""); } }
"""


def test_span_resolves_for_interface_library_abstract_and_contract():
    for needle, kind in [
        ("interface IToken", "interface IToken"),
        ("library Math", "library Math"),
        ("abstract contract Base", "contract Base"),
        ("contract Impl", "contract Impl"),
    ]:
        text = _enclosing_contract_text(DECLS, _line_of(DECLS, needle))
        assert text is not None and kind.split()[-1] in text


def test_abstract_sibling_guard_does_not_reach_plain_contract():
    """`Base is ReentrancyGuard` is a different declaration from `Impl`, which
    does not inherit it — Impl's reentrancy finding must stay."""
    ln = _line_of(DECLS, "function withdraw")
    is_fp, _ = context_aware_fp_check(_finding("reentrancy-eth", ln), DECLS, "P.sol")
    assert is_fp is False


def test_crlf_line_endings_resolve_the_right_contract():
    """Offsets must be correct with Windows `\\r\\n` endings."""
    src = TWO_CONTRACTS.replace("\n", "\r\n")
    ln = _line_of(src, "function withdraw")
    is_fp, _ = context_aware_fp_check(_finding("reentrancy-eth", ln), src, "P.sol")
    assert is_fp is False  # Bank resolved correctly; Vault's guard out of scope
