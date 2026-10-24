"""Tests for the access-control gap executor (hypothesis -> counterexample, force-run)."""

from __future__ import annotations

import shutil

import pytest

from miesc.llm import revert_invariant_executor as ex
from miesc.llm.revert_invariant_executor import execute_access_control_gaps
from miesc.llm.revert_invariant_mining import mine_revert_invariants

_AC_POSITIVE = """pragma solidity ^0.8.20;
contract Vault {
  address owner; address treasury; uint256 fee;
  constructor() { owner = msg.sender; }
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  function setFee(uint256 x) external onlyOwner { fee = x; }
  function setTreasury(address a) external { treasury = a; }
}
"""
# Unguarded-by-access, but reverts for an unrelated reason (zero arg) -> must NOT be a counterexample.
_AC_VACUOUS_REVERT = """pragma solidity ^0.8.20;
contract Vault {
  address owner; address treasury;
  constructor() { owner = msg.sender; }
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  function setFee(uint256 x) external onlyOwner { treasury = address(0); }
  function setTreasury(address a) external { require(a != address(0), "zero"); treasury = a; }
}
"""
_CTOR_ARGS = """pragma solidity ^0.8.20;
contract Vault {
  address owner; address treasury;
  constructor(address o) { owner = o; }
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  function setFee(uint256 x) external onlyOwner {}
  function setTreasury(address a) external { treasury = a; }
}
"""
_NON_ELEMENTARY = """pragma solidity ^0.8.20;
contract Vault {
  address owner; string note;
  constructor() { owner = msg.sender; }
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  function setNoteAdmin(string calldata s) external onlyOwner { note = s; }
  function setNote(string calldata s) external { note = s; }
}
"""
_PAUSE_ONLY = """pragma solidity ^0.8.20;
contract C {
  bool paused;
  modifier whenNotPaused() { require(!paused); _; }
  function deposit() external whenNotPaused { }
  function withdraw() external { }
}
"""


def _gaps(src):
    return [
        (g.category, g.affected_functions)
        for p in mine_revert_invariants(src)
        for g in p.gap_hypotheses
    ]


class TestEligibilityWithoutRunning:
    """These short-circuit before any forge invocation."""

    def test_forge_absent_is_not_executed(self, monkeypatch):
        monkeypatch.setattr(ex.shutil, "which", lambda _: None)
        res = execute_access_control_gaps(mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE)
        assert len(res) == 1
        assert res[0]["promotion_state"] == "hypothesis"
        assert "forge not available" in res[0]["reason"]

    def test_constructor_args_make_it_ineligible(self, monkeypatch):
        monkeypatch.setattr(ex.shutil, "which", lambda _: "/usr/bin/forge")  # pretend present
        assert ("access_control", ["setTreasury"]) in _gaps(_CTOR_ARGS)
        res = execute_access_control_gaps(mine_revert_invariants(_CTOR_ARGS), _CTOR_ARGS)
        assert res[0]["promotion_state"] == "hypothesis"
        assert "constructor arguments" in res[0]["reason"]

    def test_non_elementary_args_are_ineligible(self, monkeypatch):
        monkeypatch.setattr(ex.shutil, "which", lambda _: "/usr/bin/forge")
        res = execute_access_control_gaps(mine_revert_invariants(_NON_ELEMENTARY), _NON_ELEMENTARY)
        assert res[0]["promotion_state"] == "hypothesis"
        assert "elementary" in res[0]["reason"]

    def test_non_access_control_gaps_are_ignored(self):
        # pause gaps are never routed to the executor.
        assert any(c == "pause_toggle" for c, _ in _gaps(_PAUSE_ONLY))
        assert execute_access_control_gaps(mine_revert_invariants(_PAUSE_ONLY), _PAUSE_ONLY) == []

    def test_empty_plans(self):
        assert execute_access_control_gaps([], "") == []


# Real end-to-end runs: need forge on PATH. Skipped in CI (no forge), exercised locally.
_HAS_FORGE = shutil.which("forge") is not None


@pytest.mark.skipif(not _HAS_FORGE, reason="forge not installed")
class TestRealExecution:
    def test_unguarded_setter_is_a_counterexample(self):
        res = execute_access_control_gaps(
            mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE, timeout=180
        )
        assert len(res) == 1
        assert res[0]["promotion_state"] == "counterexample"
        assert res[0]["counterexamples"] == ["setTreasury"]
        assert res[0]["evidence"]

    def test_unrelated_revert_stays_hypothesis_not_rejected(self):
        res = execute_access_control_gaps(
            mine_revert_invariants(_AC_VACUOUS_REVERT), _AC_VACUOUS_REVERT, timeout=180
        )
        assert len(res) == 1
        # It reverted, but for the wrong reason: never promoted, never downgraded to rejected.
        assert res[0]["promotion_state"] == "hypothesis"
        assert "counterexamples" not in res[0]
