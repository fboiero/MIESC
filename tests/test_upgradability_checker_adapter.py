"""
Tests for UpgradabilityCheckerAdapter (src/adapters/upgradability_checker_adapter.py).

Pure-logic module (no subprocess, no external CLI / z3): static analysis of EVM proxy
upgradability gaps (uninitialized proxy, missing storage gap, selfdestruct,
unsafe delegatecall, UUPS upgrade guard, EIP-1967 slots, constructor-in-proxy).
Every helper takes strings and returns dicts -> no mocking needed.
"""

from miesc.adapters.upgradability_checker_adapter import UpgradabilityCheckerAdapter
from miesc.core.tool_protocol import ToolStatus


def _a():
    return UpgradabilityCheckerAdapter()


def _lines(src):
    return src.split("\n")


# --------------------------------------------------------------------------- #
# metadata / availability
# --------------------------------------------------------------------------- #
def test_metadata_and_availability():
    a = _a()
    assert a.get_metadata().name == "upgradability_checker"
    assert a.is_available() == ToolStatus.AVAILABLE


# --------------------------------------------------------------------------- #
# _detect_proxy_type / _is_upgradeable
# --------------------------------------------------------------------------- #
def test_detect_proxy_type():
    a = _a()
    assert a._detect_proxy_type("contract C is UUPSUpgradeable {}") == "uups_proxy"
    assert a._detect_proxy_type("import 'ERC1967Proxy.sol';") == "transparent_proxy"
    assert a._detect_proxy_type("using Clones for address;") == "minimal_proxy"
    assert a._detect_proxy_type("contract Plain {}") is None


def test_is_upgradeable():
    a = _a()
    # Initializable + initialize( -> 2 indicators
    assert a._is_upgradeable("contract C is Initializable { function initialize() {} }") is True
    assert a._is_upgradeable("contract Token { function transfer() public {} }") is False


# --------------------------------------------------------------------------- #
# _check_initialization
# --------------------------------------------------------------------------- #
def test_initialization_flags_missing_initializer_modifier():
    a = _a()
    src = "function initialize() public { owner = msg.sender; }"
    out = a._check_initialization(src, _lines(src), "C.sol")
    assert any(f["type"] == "uninitialized_proxy" for f in out)


def test_initialization_flags_constructor_without_disable():
    a = _a()
    src = "constructor() {}\nfunction initialize() public initializer {}"
    out = a._check_initialization(src, _lines(src), "C.sol")
    assert any(f["type"] == "uninitialized_proxy" for f in out)


def test_initialization_clean_with_modifier_and_no_constructor():
    a = _a()
    src = "function initialize() public initializer { owner = msg.sender; }"
    out = a._check_initialization(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_storage_gap
# --------------------------------------------------------------------------- #
def test_storage_gap_flags_inheritance_without_gap():
    a = _a()
    src = "contract Token is ERC20Upgradeable {\n  uint x;\n}"
    out = a._check_storage_gap(src, _lines(src), "C.sol")
    assert any(f["type"] == "missing_storage_gap" for f in out)


def test_storage_gap_clean_with_gap():
    a = _a()
    src = "contract Token is ERC20Upgradeable {\n  uint256[50] private __gap;\n}"
    out = a._check_storage_gap(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_selfdestruct
# --------------------------------------------------------------------------- #
def test_selfdestruct_flagged():
    a = _a()
    src = "function kill() external { selfdestruct(payable(owner)); }"
    out = a._check_selfdestruct(src, _lines(src), "C.sol")
    assert any(f["type"] == "selfdestruct_in_implementation" for f in out)


def test_selfdestruct_clean():
    a = _a()
    src = "function f() external { x = 1; }"
    assert a._check_selfdestruct(src, _lines(src), "C.sol") == []


# --------------------------------------------------------------------------- #
# _check_delegatecall
# --------------------------------------------------------------------------- #
def test_delegatecall_flags_unvalidated_target():
    a = _a()
    src = "function fwd(address t, bytes d) external { t.delegatecall(d); }"
    out = a._check_delegatecall(src, _lines(src), "C.sol")
    assert any(f["type"] == "unsafe_delegatecall_target" for f in out)


def test_delegatecall_clean_with_validation():
    a = _a()
    src = "require(target == implementation);\n" "(bool ok,) = target.delegatecall(d);"
    out = a._check_delegatecall(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_uups_guard
# --------------------------------------------------------------------------- #
def test_uups_guard_flags_missing_authorize():
    a = _a()
    src = "contract C is UUPSUpgradeable {\n  function f() external {}\n}"
    out = a._check_uups_guard(src, _lines(src), "C.sol")
    assert any(f["type"] == "missing_upgrade_guard" for f in out)


def test_uups_guard_flags_authorize_without_access_control():
    a = _a()
    src = "function _authorizeUpgrade(address newImpl) internal override {}"
    out = a._check_uups_guard(src, _lines(src), "C.sol")
    assert any(f["type"] == "missing_upgrade_guard" for f in out)


def test_uups_guard_clean_with_access_control():
    a = _a()
    src = (
        "function _authorizeUpgrade(address newImpl) internal override "
        "{ require(msg.sender == owner); }"
    )
    out = a._check_uups_guard(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_eip1967
# --------------------------------------------------------------------------- #
def test_eip1967_flags_noncompliant_proxy():
    a = _a()
    src = "contract C is UUPSUpgradeable {\n  function f() { t.delegatecall(d); }\n}"
    out = a._check_eip1967(src, _lines(src), "C.sol")
    assert any(f["type"] == "eip1967_noncompliance" for f in out)


def test_eip1967_clean_with_standard_slot():
    a = _a()
    src = (
        "contract C is UUPSUpgradeable {\n"
        "  bytes32 constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;\n"
        "  function f() { t.delegatecall(d); }\n}"
    )
    out = a._check_eip1967(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_constructor
# --------------------------------------------------------------------------- #
def test_constructor_flags_state_setting():
    a = _a()
    src = "constructor() { owner = msg.sender; }"
    out = a._check_constructor(src, _lines(src), "C.sol")
    assert any(f["type"] == "missing_initializer" for f in out)


def test_constructor_clean_with_only_disable_initializers():
    a = _a()
    src = "constructor() { _disableInitializers(); }"
    out = a._check_constructor(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# analyze — end to end
# --------------------------------------------------------------------------- #
def test_analyze_non_upgradeable_returns_empty(tmp_path):
    a = _a()
    sol = tmp_path / "plain.sol"
    sol.write_text("contract Token { function transfer() public {} }")
    out = a.analyze(str(sol))
    assert out["status"] == "success"
    assert out["metadata"]["is_upgradeable"] is False


def test_analyze_upgradeable_produces_findings(tmp_path):
    a = _a()
    sol = tmp_path / "proxy.sol"
    sol.write_text(
        "pragma solidity ^0.8.0;\n"
        "contract MyProxy is UUPSUpgradeable {\n"
        "  uint public x;\n"
        "  function initialize() public { x = 1; }\n"
        "  function fwd(address t, bytes d) external { t.delegatecall(d); }\n"
        "}\n"
    )
    out = a.analyze(str(sol))
    assert out["status"] == "success"
    assert out["metadata"]["is_upgradeable"] is True
    assert out["metadata"]["proxy_type"] == "uups_proxy"
    assert out["findings"]
    keys = [(f["type"], f["location"]["line"]) for f in out["findings"]]
    assert len(keys) == len(set(keys))  # deduped


def test_analyze_missing_file_returns_error():
    a = _a()
    out = a.analyze("/nonexistent/proxy.sol")
    assert out["status"] == "error"
    assert out["error"]


# --------------------------------------------------------------------------- #
# normalize_findings
# --------------------------------------------------------------------------- #
def test_normalize_findings_maps_known_key_and_skips_non_dict():
    a = _a()
    raw = [
        {
            "type": "selfdestruct_in_implementation",
            "vuln_key": "selfdestruct_in_implementation",
            "line": 7,
            "file": "C.sol",
            "code": "selfdestruct(o);",
        },
        12345,  # non-dict skipped
    ]
    out = a.normalize_findings(raw)
    assert len(out) == 1
    assert out[0]["severity"] == "Critical"
    assert out[0]["id"].startswith("UPG-")
    assert out[0]["tool"] == "upgradability_checker"


def test_normalize_findings_empty():
    assert _a().normalize_findings([]) == []
    assert _a().normalize_findings(None) == []
