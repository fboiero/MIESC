"""Tests for the pause/freshness reasoning executor (hypothesis -> counterexample, control-gated).

The load-bearing test is ``TestCentralFalsePositive``: a WRONG pauser (named ``pause`` but it does
not set the paused flag) must produce ZERO counterexamples and ZERO findings, because the control
probe never confirms the rejectable state. A wrong fact fails CLOSED.
"""

from __future__ import annotations

import shutil

import pytest

from miesc.core.finding_taxonomy import CanonicalCategory, normalize_finding_type
from miesc.llm import revert_invariant_reasoning as rr
from miesc.llm.revert_invariant_findings import counterexample_findings
from miesc.llm.revert_invariant_mining import mine_revert_invariants
from miesc.llm.revert_invariant_reasoning import execute_reasoning_gaps

# --- fixtures ---------------------------------------------------------------------------------

# Correct pause gap: deposit is whenNotPaused (guarded), withdraw is not (unguarded), pause() sets
# the flag. withdraw writes storage -> it is a real counterexample once paused.
_PAUSE_OK = """pragma solidity ^0.8.20;
contract Pausable {
  bool public paused;
  uint256 public counter;
  modifier whenNotPaused() { require(!paused, "paused"); _; }
  function pause() external { paused = true; }
  function deposit() external whenNotPaused { counter += 1; }
  function withdraw() external { counter += 1; }
}
"""

# Central FP: the "pauser" is literally named pause() but does NOT set the paused flag. The control
# probe pauses, calls the guarded sibling, and it does NOT revert -> state unconfirmed -> no promote.
_PAUSE_WRONG = """pragma solidity ^0.8.20;
contract Pausable {
  bool public paused;
  uint256 public counter;
  modifier whenNotPaused() { require(!paused, "paused"); _; }
  function pause() external { counter += 1; }
  function deposit() external whenNotPaused { counter += 1; }
  function withdraw() external { counter += 1; }
}
"""

# Vacuous-revert FP: wrong pauser AND the guarded sibling reverts on zero args for an unrelated
# reason (require(a > 0)). The control baseline (sibling must succeed BEFORE pausing) catches it.
_PAUSE_VACUOUS = """pragma solidity ^0.8.20;
contract Pausable {
  bool public paused;
  uint256 public counter;
  modifier whenNotPaused() { require(!paused, "paused"); _; }
  function pause() external { counter += 1; }
  function deposit(uint256 a) external whenNotPaused { require(a > 0, "amt"); counter += 1; }
  function withdraw() external { counter += 1; }
}
"""

# Correct freshness gap: commit checks its deadline (guarded), settle ignores it (unguarded).
_FRESH_OK = """pragma solidity ^0.8.20;
contract Orders {
  uint256 public counter;
  function commit(uint256 deadline) external { require(block.timestamp <= deadline, "expired"); counter += 1; }
  function settle(uint256 deadline) external { counter += 1; }
}
"""

# No gap: both user functions are pause-gated -> consistent family -> nothing to execute.
_NO_GAP = """pragma solidity ^0.8.20;
contract Pausable {
  bool public paused;
  uint256 public counter;
  modifier whenNotPaused() { require(!paused, "paused"); _; }
  function pause() external { paused = true; }
  function deposit() external whenNotPaused { counter += 1; }
  function withdraw() external whenNotPaused { counter += 1; }
}
"""

# Provider-absent: a pause gap whose toggler is named halt() -> the local literal-case extractor
# cannot identify a pauser -> gap unchanged, no forge run, no isolation key.
_PROVIDER_ABSENT = """pragma solidity ^0.8.20;
contract Pausable {
  bool public paused;
  uint256 public counter;
  modifier whenNotPaused() { require(!paused, "paused"); _; }
  function halt() external { paused = true; }
  function deposit() external whenNotPaused { counter += 1; }
  function withdraw() external { counter += 1; }
}
"""

_HAS_FORGE = shutil.which("forge") is not None


# --- degradation ladder (no forge run) --------------------------------------------------------
class TestDegradationWithoutForge:
    def test_forge_absent_is_not_executed(self, monkeypatch):
        monkeypatch.setattr(rr.shutil, "which", lambda _: None)
        res = execute_reasoning_gaps(mine_revert_invariants(_PAUSE_OK), _PAUSE_OK)
        assert len(res) == 1
        assert res[0]["promotion_state"] == "hypothesis"
        assert "forge not available" in res[0]["reason"]
        assert "isolation" not in res[0]

    def test_provider_absent_local_facts_unextractable(self, monkeypatch):
        # forge present, but the toggler is named halt(): no literal pauser -> gap unchanged.
        monkeypatch.setattr(rr.shutil, "which", lambda _: "/usr/bin/forge")
        res = execute_reasoning_gaps(mine_revert_invariants(_PROVIDER_ABSENT), _PROVIDER_ABSENT)
        assert len(res) == 1
        assert res[0]["promotion_state"] == "hypothesis"
        assert "could not extract probe facts" in res[0]["reason"]
        assert "isolation" not in res[0]  # never reached a forge run

    def test_no_gap_yields_nothing(self):
        assert execute_reasoning_gaps(mine_revert_invariants(_NO_GAP), _NO_GAP) == []

    def test_empty_plans(self):
        assert execute_reasoning_gaps([], "") == []

    def test_access_control_gaps_are_ignored(self):
        # Access-control gaps belong to the executor, not here.
        src = """pragma solidity ^0.8.20;
contract Vault {
  address owner;
  constructor() { owner = msg.sender; }
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  function setFee(uint256 x) external onlyOwner {}
  function setTreasury(address a) external { owner = a; }
}
"""
        assert execute_reasoning_gaps(mine_revert_invariants(src), src) == []


# --- the central precision test (CI-safe only with forge; skipped otherwise) ------------------
@pytest.mark.skipif(not _HAS_FORGE, reason="forge not installed")
class TestCentralFalsePositive:
    def test_wrong_pauser_yields_zero_counterexamples_and_zero_findings(self):
        res = execute_reasoning_gaps(
            mine_revert_invariants(_PAUSE_WRONG), _PAUSE_WRONG, timeout=180
        )
        assert len(res) == 1
        assert res[0]["promotion_state"] == "hypothesis"
        assert "counterexamples" not in res[0]
        assert "control probe did not confirm" in res[0]["reason"]
        # And nothing crosses into the finding set.
        assert counterexample_findings(res, _PAUSE_WRONG, "C.sol") == []

    def test_vacuous_revert_sibling_is_not_a_counterexample(self):
        # The guarded sibling reverts on zero args for an unrelated reason; the control baseline
        # (sibling must succeed before the state is reached) prevents a false counterexample.
        res = execute_reasoning_gaps(
            mine_revert_invariants(_PAUSE_VACUOUS), _PAUSE_VACUOUS, timeout=180
        )
        assert res[0]["promotion_state"] == "hypothesis"
        assert "counterexamples" not in res[0]
        assert counterexample_findings(res, _PAUSE_VACUOUS, "C.sol") == []


@pytest.mark.skipif(not _HAS_FORGE, reason="forge not installed")
class TestCorrectCounterexamples:
    def test_correct_pause_gap_is_a_counterexample(self):
        res = execute_reasoning_gaps(mine_revert_invariants(_PAUSE_OK), _PAUSE_OK, timeout=180)
        assert len(res) == 1
        assert res[0]["promotion_state"] == "counterexample"
        assert res[0]["counterexamples"] == ["withdraw"]
        assert res[0]["evidence"]
        iso = res[0]["isolation"]
        assert iso["ffi"] is False and iso["fs_permissions"] == [] and iso["env"] == "scrubbed"

    def test_correct_pause_gap_emits_a_dos_finding(self):
        res = execute_reasoning_gaps(mine_revert_invariants(_PAUSE_OK), _PAUSE_OK, timeout=180)
        out = counterexample_findings(res, _PAUSE_OK, "C.sol")
        assert len(out) == 1
        f = out[0]
        assert f["type"] == "dos"
        assert normalize_finding_type(f) is CanonicalCategory.DENIAL_OF_SERVICE
        assert f["source"] == "revert_invariant_reasoning"
        assert "withdraw" in f["title"]
        assert f["location"]["line"] == 8  # `function withdraw(` declaration

    def test_correct_freshness_gap_is_a_counterexample(self):
        res = execute_reasoning_gaps(mine_revert_invariants(_FRESH_OK), _FRESH_OK, timeout=180)
        assert len(res) == 1
        assert res[0]["promotion_state"] == "counterexample"
        assert res[0]["counterexamples"] == ["settle"]

    def test_correct_freshness_gap_emits_a_timestamp_finding(self):
        res = execute_reasoning_gaps(mine_revert_invariants(_FRESH_OK), _FRESH_OK, timeout=180)
        out = counterexample_findings(res, _FRESH_OK, "C.sol")
        assert len(out) == 1
        f = out[0]
        assert f["type"] == "timestamp"
        assert normalize_finding_type(f) is CanonicalCategory.TIME_MANIPULATION
        assert f["source"] == "revert_invariant_reasoning"
        assert "settle" in f["title"]
        assert f["location"]["line"] == 5  # `function settle(` declaration


# --- config wiring ----------------------------------------------------------------------------
class TestConfigWiring:
    def test_gap_reasoning_flag_defaults_off(self):
        from miesc.agents.deep_audit_agent import DeepAuditConfig

        assert DeepAuditConfig().enable_gap_reasoning is False

    def test_reuses_remote_gate_no_new_flag(self):
        from miesc.agents.deep_audit_agent import DeepAuditConfig

        # Remote is gated by the existing agentic_invariants_allow_remote; there is no parallel one.
        assert not hasattr(DeepAuditConfig(), "gap_reasoning_allow_remote")
        assert DeepAuditConfig().agentic_invariants_allow_remote is False


@pytest.mark.skipif(not _HAS_FORGE, reason="forge not installed")
class TestSynthesisWiring:
    """The findings must reach the report through the SAME FP filter as every other finding."""

    def test_reasoning_findings_survive_the_fp_filter_when_enabled(self):
        from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig

        agent = DeepAuditAgent(
            DeepAuditConfig(enable_gap_execution=True, enable_gap_reasoning=True, enable_llm=False)
        )
        pause = agent._counterexample_findings(_PAUSE_OK, "C.sol")
        fresh = agent._counterexample_findings(_FRESH_OK, "C.sol")
        assert any(f["type"] == "dos" and "withdraw" in f["title"] for f in pause)
        assert any(f["type"] == "timestamp" and "settle" in f["title"] for f in fresh)

    def test_reasoning_off_adds_no_pause_or_freshness_findings(self):
        from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig

        agent = DeepAuditAgent(
            DeepAuditConfig(enable_gap_execution=True, enable_gap_reasoning=False, enable_llm=False)
        )
        emitted = agent._counterexample_findings(_PAUSE_OK, "C.sol")
        assert all(f.get("source") != "revert_invariant_reasoning" for f in emitted)
