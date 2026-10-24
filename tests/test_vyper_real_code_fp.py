"""Vyper analyzer on shapes taken from audited production code (Curve, snekmate,
Yearn, stableswap-ng): the public API of a token or pool is not missing access
control, a constructor cannot be re-entered, and an access check written as `if`
or through a snekmate module still counts as a guard."""

import pytest

from miesc.adapters.vyper_adapter import VyperAnalyzer, VyperPatternDetector


def _types(source, tmp_path):
    vy_file = tmp_path / "C.vy"
    vy_file.write_text(source)
    return [f["type"] for f in VyperAnalyzer().analyze(str(vy_file))["findings"]]


def test_token_and_pool_public_api_is_not_missing_access_control(tmp_path):
    source = """\
# @version 0.3.7

balanceOf: public(HashMap[address, uint256])
admin_balances: public(uint256[2])

@external
def transfer(_to: address, _value: uint256) -> bool:
    self.balanceOf[msg.sender] -= _value
    self.balanceOf[_to] += _value
    return True

@external
def exchange(i: int128, j: int128, dx: uint256) -> uint256:
    self.admin_balances[0] += dx / 100
    return dx
"""
    assert "missing_access_control" not in _types(source, tmp_path)


@pytest.mark.parametrize(
    "guard",
    [
        "    if msg.sender != self.owner:\n        raise",
        "    ownable._check_owner()",
        "    assert self.is_admin[msg.sender], 'not admin'",
    ],
)
def test_guard_shapes_are_recognized(guard, tmp_path):
    source = f"""\
# @version 0.3.7

owner: address
fee: uint256
is_admin: HashMap[address, bool]

@external
def set_fee(new_fee: uint256):
{guard}
    self.fee = new_fee
"""
    assert "missing_access_control" not in _types(source, tmp_path)


def test_balance_check_is_not_a_guard(tmp_path):
    source = """\
# @version 0.3.7

fee: uint256
balances: HashMap[address, uint256]

@external
def set_fee(new_fee: uint256):
    assert self.balances[msg.sender] >= 1
    self.fee = new_fee
"""
    assert "missing_access_control" in _types(source, tmp_path)


def test_constructor_is_not_a_reentrancy_target(tmp_path):
    source = """\
# @version 0.3.7

token: address

@external
def __init__(_token: address):
    self.token = _token
    ERC20(_token).approve(msg.sender, max_value(uint256))
"""
    assert "missing_reentrancy_guard" not in _types(source, tmp_path)


def test_nonreentrancy_pragma_guards_the_module(tmp_path):
    source = """\
# pragma version 0.4.1
# pragma nonreentrancy on

balances: HashMap[address, uint256]

@external
def withdraw():
    raw_call(msg.sender, b"", value=self.balances[msg.sender])
    self.balances[msg.sender] = 0
"""
    assert "missing_reentrancy_guard" not in _types(source, tmp_path)


def test_raw_revert_is_not_an_external_call(tmp_path):
    source = """\
# @version 0.3.7

count: uint256

@external
def bump(data: Bytes[64]):
    self.count += 1
    if self.count > 10:
        raw_revert(data)
"""
    assert "missing_reentrancy_guard" not in _types(source, tmp_path)


def test_tx_origin_assignment_is_not_authorization():
    detector = VyperPatternDetector()
    assert detector.detect_simple_patterns("    self.manager = tx.origin", "t.vy") == []


def test_unsafe_math_is_low_severity():
    detector = VyperPatternDetector()
    (match,) = detector.detect_simple_patterns("x: uint256 = unsafe_add(a, b)", "t.vy")
    assert match["severity"] == "Low"


def test_parses_defaults_with_calls_and_multiline_returns():
    source = """\
@external
def claim_rewards(_addr: address = msg.sender, _receiver: address = empty(address)):
    pass

@internal
@view
def _calc(
    _amount: uint256,
    i: int128,
) -> (
    uint256,
    uint256,
):
    return 0, 0
"""
    names = [f.name for f in VyperPatternDetector().extract_functions(source, "t.vy")]
    assert names == ["claim_rewards", "_calc"]
