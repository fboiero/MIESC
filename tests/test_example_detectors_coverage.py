"""Coverage for the example custom detectors.

These are pure regex detectors (no network, no LLM). A vulnerable kitchen-sink
contract trips most of them (exercising the finding-construction branches); a
hardened contract exercises the mitigation / skip branches.
"""

import inspect

import pytest

import miesc.detectors.examples as ex
from miesc.detectors import BaseDetector, Finding, Severity

DETECTORS = [
    obj
    for _, obj in inspect.getmembers(ex, inspect.isclass)
    if issubclass(obj, BaseDetector) and obj is not BaseDetector and obj.__module__ == ex.__name__
]

VULNERABLE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract KitchenSink {
    address owner;
    uint256 balance;
    mapping(address => uint256) balances;
    address hardcoded = 0x000000000000000000000000000000000000dEaD;

    function withdraw(uint256 amt) public {
        (bool ok, ) = msg.sender.call{value: amt}("");
        balances[msg.sender] = balances[msg.sender] - amt;
    }
    function setConfig(uint256 x) public { balance = x; }
    function mint(address to, uint256 a) public { _mint(to, a); }
    function auth() public { require(tx.origin == owner); }
    function run(bytes memory d) public { target.delegatecall(d); }
    function boom() public { selfdestruct(payable(msg.sender)); }
    function price() public { uint256 p = oracle.getPrice(); balance = p; }
    function swapNow(uint256 a) public { router.swap(a, 0); }
    function disableTrading() public {}
    function blacklist(address u) public {}
    function timed() public view returns (bool) { return block.timestamp > 100; }
    function appr(address s) public { token.approve(s, 100); }
    function loop(uint256[] memory arr) public {
        for (uint256 i = 0; i < arr.length; i++) { balance += arr[i]; }
    }
    function liquidate(address u) public {}
    function rand() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
    }
    function unsafeSend(address payable r) public { r.send(1 ether); }
}
"""

HARDENED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Safe is ReentrancyGuard {
    address owner;
    uint256 balance;

    modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

    function withdraw(uint256 amt) public onlyOwner nonReentrant {
        balance = balance - amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "fail");
    }
    function price() public view returns (uint256) {
        return oracle.consult();  // TWAP
    }
    function swapNow(uint256 a, uint256 amountOutMin, uint256 deadline) public {
        router.swap(a, amountOutMin, deadline);
    }
    function timed(uint256 deadline) public view returns (bool) {
        require(block.timestamp < deadline, "expired");
        return true;
    }
    function rand() public view returns (uint256) {
        return VRF.requestRandomness();
    }
}
"""


@pytest.mark.parametrize("det_cls", DETECTORS, ids=[d.__name__ for d in DETECTORS])
class TestEveryDetector:
    def test_runs_on_vulnerable_without_error(self, det_cls):
        findings = det_cls().analyze(VULNERABLE, file_path="KitchenSink.sol")
        assert isinstance(findings, list)
        for f in findings:
            assert isinstance(f, Finding)
            assert f.title
            assert f.location.line >= 1

    def test_runs_on_hardened_without_error(self, det_cls):
        findings = det_cls().analyze(HARDENED, file_path="Safe.sol")
        assert isinstance(findings, list)

    def test_runs_on_empty_source(self, det_cls):
        assert det_cls().analyze("", file_path="E.sol") == []


def test_at_least_one_detector_registered():
    assert len(DETECTORS) >= 10


def test_vulnerable_contract_triggers_many_detectors():
    total = 0
    fired = 0
    for det_cls in DETECTORS:
        n = len(det_cls().analyze(VULNERABLE, file_path="KitchenSink.sol"))
        total += n
        fired += 1 if n else 0
    # The kitchen-sink is designed to trip a broad set of detectors.
    assert total >= 10
    assert fired >= 8


def test_high_confidence_detectors_fire():
    by_name = {d.__name__: d for d in DETECTORS}

    def findings_of(name):
        cls = by_name.get(name)
        if cls is None:
            pytest.skip(f"{name} not present")
        return cls().analyze(VULNERABLE, file_path="C.sol")

    # Detectors whose trigger the kitchen-sink definitely contains.
    for name in (
        "ReentrancyPatternDetector",
        "TxOriginDetector",
        "SelfdestructDetector",
        "DelegateCallDetector",
        "TimestampDependenceDetector",
        "WeakRandomnessDetector",
    ):
        assert len(findings_of(name)) >= 1, f"{name} should fire on the kitchen-sink"


def test_hardened_contract_quiets_some_detectors():
    by_name = {d.__name__: d for d in DETECTORS}
    # The hardened contract removes the triggers / adds the mitigations these
    # detectors look for, so they should stay silent.
    quiet_candidates = ["TxOriginDetector", "SelfdestructDetector"]
    silenced = 0
    for name in quiet_candidates:
        cls = by_name.get(name)
        if cls is None:
            continue
        if len(cls().analyze(HARDENED, file_path="Safe.sol")) == 0:
            silenced += 1
    assert silenced >= 1


def test_hardcoded_address_branches():
    by_name = {d.__name__: d for d in DETECTORS}
    cls = by_name.get("HardcodedAddressDetector")
    if cls is None:
        pytest.skip("HardcodedAddressDetector not present")
    src = """// SPDX-License-Identifier: MIT
contract Addrs {
    // commented 0x1111111111111111111111111111111111111111 should be skipped
    address constant ROUTER = 0x2222222222222222222222222222222222222222;
    address plain = 0x3333333333333333333333333333333333333333;
}
"""
    findings = cls().analyze(src, file_path="Addrs.sol")
    titles = [f.title for f in findings]
    # The commented address is skipped; the constant and the plain address are
    # both reported (the constant one at INFO severity).
    assert titles.count("Hardcoded Address") >= 2
    severities = {f.severity for f in findings}
    assert Severity.INFO in severities
