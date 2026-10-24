"""Vyper analyzer on shapes taken from audited production code (Curve, snekmate,
Yearn, stableswap-ng): the public API of a token or pool is not missing access
control, a constructor cannot be re-entered, and an access check written as `if`
or through a snekmate module still counts as a guard."""

import pytest

from miesc.adapters.vyper_adapter import VyperAnalyzer, VyperPatternDetector, VyperVulnerability


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


def _findings(source, tmp_path):
    vy_file = tmp_path / "C.vy"
    vy_file.write_text(source)
    return VyperAnalyzer().analyze(str(vy_file))["findings"]


def test_multiline_signature_body_is_parsed():
    source = """\
@external
def withdraw(
    amount: uint256,
):
    raw_call(msg.sender, b"", value=amount)
    self.balance_of[msg.sender] -= amount
"""
    (fn,) = VyperPatternDetector().extract_functions(source, "t.vy")
    assert "raw_call" in fn.body
    assert "self.balance_of" in fn.body


def test_column_zero_comment_does_not_end_the_body():
    source = """\
@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
# keep the accounting after the call on purpose
    self.balance_of[msg.sender] -= amount
"""
    (fn,) = VyperPatternDetector().extract_functions(source, "t.vy")
    assert "self.balance_of" in fn.body


def test_patterns_in_comments_and_docstrings_are_ignored():
    source = '''\
# never call selfdestruct( here, and never check tx.origin == owner
@external
def f():
    """Unlike older code we do not use selfdestruct(self) or tx.origin == x."""
    pass
'''
    assert VyperPatternDetector().detect_simple_patterns(source, "t.vy") == []


LOCKED = """\
# @version {spec}

@external
@nonreentrant("lock")
def withdraw():
    pass
"""


@pytest.mark.parametrize("spec", ["^0.3.0", "~0.3.0", ">=0.3.0 <0.4.0"])
def test_version_range_is_low_confidence_not_critical(spec, tmp_path):
    (lock,) = [
        f
        for f in _findings(LOCKED.format(spec=spec), tmp_path)
        if f["type"] == "broken_reentrancy_lock_compiler"
    ]
    assert lock["severity"].lower() == "low"
    assert lock["location"]["line"] == 1


def test_exact_broken_version_is_critical_on_the_pragma_line(tmp_path):
    source = "\n" + LOCKED.format(spec="0.3.0")
    (lock,) = [
        f for f in _findings(source, tmp_path) if f["type"] == "broken_reentrancy_lock_compiler"
    ]
    assert lock["severity"].lower() == "critical"
    assert lock["location"]["line"] == 2


def test_fixed_version_has_no_lock_finding(tmp_path):
    types = [f["type"] for f in _findings(LOCKED.format(spec="0.3.1"), tmp_path)]
    assert "broken_reentrancy_lock_compiler" not in types


def test_checks_effects_interactions_is_not_missing_guard(tmp_path):
    source = """\
# @version 0.3.7

balances: HashMap[address, uint256]

@external
def withdraw():
    amount: uint256 = self.balances[msg.sender]
    self.balances[msg.sender] = 0
    raw_call(msg.sender, b"", value=amount)
"""
    assert "missing_reentrancy_guard" not in _types(source, tmp_path)


@pytest.mark.parametrize(
    "deploy, flagged",
    [
        ("    pool: address = create_from_blueprint(self.blueprint, x)", False),
        (
            "    pool: address = create_minimal_proxy_to(self.impl)\n"
            "    Pool(pool).initialize(msg.sender)",
            False,
        ),
        ("    pool: address = create_minimal_proxy_to(self.impl)", True),
    ],
)
def test_proxy_flagged_only_without_init(deploy, flagged):
    source = f"@external\ndef deploy(x: uint256):\n{deploy}\n"
    types = [m["vuln_type"] for m in VyperPatternDetector().detect_simple_patterns(source, "t.vy")]
    assert (VyperVulnerability.UNSAFE_PROXY_CREATION in types) is flagged


@pytest.mark.parametrize(
    "call, flagged",
    [
        ("raw_call(self, data, is_delegate_call=True)", False),
        ("raw_call(target, _abi_encode(x, method_id=m), is_delegate_call=True)", True),
        ("raw_call(target, data)", False),
    ],
)
def test_delegatecall_flags_only_foreign_targets(call, flagged):
    source = f"@external\ndef f(target: address, data: Bytes[100]):\n    {call}\n"
    types = [m["vuln_type"] for m in VyperPatternDetector().detect_simple_patterns(source, "t.vy")]
    assert (VyperVulnerability.DANGEROUS_DELEGATECALL in types) is flagged


def test_eoa_check_with_msg_sender_is_not_tx_origin_auth():
    source = "    assert msg.sender == tx.origin, 'no contracts'\n"
    assert VyperPatternDetector().detect_simple_patterns(source, "t.vy") == []


REENTRY = """\
# @version 0.3.7

interface Token:
    def decimals() -> uint8: view
    def pull(owner: address, amount: uint256): nonpayable

owner: address
count: uint256

@external
def f(t: address, amount: uint256):
{body}
"""


@pytest.mark.parametrize(
    "body, flagged",
    [
        ("    x: uint8 = Token(t).decimals()\n    self.count += 1", False),
        (
            "    assert msg.sender == self.owner\n    Token(t).pull(msg.sender, amount)\n"
            "    self.count += 1",
            False,
        ),
        ("    Token(t).pull(msg.sender, amount)\n    self.count += 1", True),
    ],
)
def test_reentrancy_needs_a_state_changing_call_open_to_anyone(body, flagged, tmp_path):
    types = _types(REENTRY.format(body=body), tmp_path)
    assert ("missing_reentrancy_guard" in types) is flagged


@pytest.mark.parametrize(
    "name, guard, flagged",
    [
        ("initialize", "    assert self.activation == 0\n", False),
        ("initialize", "", True),
        ("set_owner", "    assert self.activation == 0\n", True),
    ],
)
def test_one_shot_initializer_counts_as_a_guard(name, guard, flagged, tmp_path):
    source = (
        f"# @version 0.3.7\n\nowner: address\nactivation: uint256\n\n"
        f"@external\ndef {name}(o: address):\n{guard}    self.owner = o\n"
    )
    assert ("missing_access_control" in _types(source, tmp_path)) is flagged
