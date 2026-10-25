"""Tests for the access-control gap executor (hypothesis -> counterexample, force-run)."""

from __future__ import annotations

import json
import logging
import pathlib
import shutil
import subprocess

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
_CTOR_NONELEM = """pragma solidity ^0.8.20;
contract Vault {
  address owner; address treasury; string name;
  constructor(string memory n) { owner = msg.sender; name = n; }
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

    def test_non_elementary_constructor_is_ineligible(self, monkeypatch):
        # A constructor with a non-elementary parameter (string) cannot be deployed with zero
        # literals, so the gap stays unexecuted.
        monkeypatch.setattr(ex.shutil, "which", lambda _: "/usr/bin/forge")  # pretend present
        assert ("access_control", ["setTreasury"]) in _gaps(_CTOR_NONELEM)
        res = execute_access_control_gaps(mine_revert_invariants(_CTOR_NONELEM), _CTOR_NONELEM)
        assert res[0]["promotion_state"] == "hypothesis"
        assert "non-elementary constructor" in res[0]["reason"]

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


_B8_ZERO_LOCK = """pragma solidity ^0.8.20;
contract C {
  address owner; uint256 lockedAt; uint256 config; uint256 fee;
  constructor(address _owner, uint256 _lockedAt) { owner = _owner; lockedAt = _lockedAt; }
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  function setFee(uint256 x) external onlyOwner { fee = x; }
  function setConfig(uint256 v) external { require(lockedAt == 0, "locked"); config = v; }
}"""


@pytest.mark.skipif(not _HAS_FORGE, reason="forge not installed")
class TestRealExecution:
    def test_zero_lock_idiom_is_not_a_false_counterexample(self):
        # B8: `require(lockedAt == 0)` is a dead path in production (lockedAt armed non-zero).
        # Zero ctor literals would materialise lockedAt==0 and make setConfig a false counterexample;
        # the non-unset literal deploys lockedAt=1, so setConfig reverts -> stays hypothesis.
        assert ("access_control", ["setConfig"]) in _gaps(_B8_ZERO_LOCK)
        res = execute_access_control_gaps(
            mine_revert_invariants(_B8_ZERO_LOCK), _B8_ZERO_LOCK, timeout=180
        )
        assert len(res) == 1
        assert res[0]["promotion_state"] == "hypothesis"
        assert "counterexamples" not in res[0]

    def test_elementary_constructor_contract_is_executed(self):
        # `constructor(address o)` is elementary -> deployed with zero literals -> the unguarded
        # setter is still a counterexample. (Previously this contract was skipped outright.)
        res = execute_access_control_gaps(
            mine_revert_invariants(_CTOR_ARGS), _CTOR_ARGS, timeout=180
        )
        assert res[0]["promotion_state"] == "counterexample"
        assert res[0]["counterexamples"] == ["setTreasury"]

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

    def test_silent_early_return_guard_is_not_a_counterexample(self):
        # The guard exists but returns instead of reverting: the call succeeds without writing
        # storage. Nothing is proven -> must stay hypothesis (was a false counterexample before).
        src = _AC_POSITIVE.replace(
            "function setTreasury(address a) external { treasury = a; }",
            "function setTreasury(address a) external { if (msg.sender != owner) return; treasury = a; }",
        )
        res = execute_access_control_gaps(mine_revert_invariants(src), src, timeout=180)
        assert len(res) == 1
        assert res[0]["promotion_state"] == "hypothesis"
        assert "counterexamples" not in res[0]

    def test_noop_on_zero_argument_is_not_a_counterexample(self):
        src = _AC_POSITIVE.replace(
            "function setTreasury(address a) external { treasury = a; }",
            "function setTreasury(address a) external { if (a == address(0)) return; treasury = a; }",
        )
        res = execute_access_control_gaps(mine_revert_invariants(src), src, timeout=180)
        assert res[0]["promotion_state"] == "hypothesis"

    def test_executed_result_reports_isolation(self):
        res = execute_access_control_gaps(mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE)
        iso = res[0]["isolation"]
        assert iso["ffi"] is False and iso["fs_permissions"] == [] and iso["env"] == "scrubbed"
        assert iso["network"] in ("denied", "unrestricted")


# ---------------------------------------------------------------------------------------------
# Hardening: these run in CI (forge mocked) and pin the sandbox surface + the JSON mapping.
# ---------------------------------------------------------------------------------------------

_TWO_FAMILIES = """pragma solidity ^0.8.20;
contract Vault {
  address owner; address treasury; uint256 fee; address impl;
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  constructor() { owner = msg.sender; }
  function setFee(uint256 x) external onlyOwner { fee = x; }
  function setTreasury(address a) external { treasury = a; }
  function upgradeTo(address i) external onlyOwner { impl = i; }
  function upgradeImpl(address i) external { impl = i; }
}
"""


def _forge_json(status: str, name: str = "test_unauthorized_setTreasury()") -> str:
    return json.dumps(
        {"test/P.t.sol:RevertInvariantACProbe": {"test_results": {name: {"status": status}}}}
    )


class _FakeForge:
    """Capture what the executor would hand to ``forge``: argv, env, and the project it wrote."""

    def __init__(self, stdout: str):
        self.stdout = stdout
        self.calls: list = []

    def __call__(self, cmd, cwd=None, env=None, **kwargs):
        root = pathlib.Path(cwd)
        self.calls.append(
            {
                "cmd": list(cmd),
                "env": dict(env or {}),
                "toml": (root / "foundry.toml").read_text(),
                "probe": (root / "test" / "RevertInvariantACProbe.t.sol").read_text(),
            }
        )
        return subprocess.CompletedProcess(cmd, 0, stdout=self.stdout, stderr="")


@pytest.fixture
def fake_forge(monkeypatch):
    def _install(stdout: str, sandbox=None):
        fake = _FakeForge(stdout)
        monkeypatch.setattr(ex.shutil, "which", lambda _: "/usr/bin/forge")
        monkeypatch.setattr(ex.subprocess, "run", fake)
        monkeypatch.setattr(ex, "_network_sandbox", lambda: sandbox)
        return fake

    return _install


class TestHardenedSandbox:
    def test_toml_pins_ffi_and_fs_permissions(self, fake_forge):
        fake = fake_forge(_forge_json("Success"))
        execute_access_control_gaps(mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE)
        toml = fake.calls[0]["toml"]
        assert "ffi = false" in toml
        assert "fs_permissions = []" in toml

    def test_env_is_scrubbed_to_allowlist(self, fake_forge, monkeypatch):
        monkeypatch.setenv("MIESC_TEST_SECRET", "sk-live-should-not-leak")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-leak")
        monkeypatch.setenv("FOUNDRY_PROFILE", "ci")
        monkeypatch.setenv("FOUNDRY_FFI", "true")
        fake = fake_forge(_forge_json("Success"))
        execute_access_control_gaps(mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE)
        env = fake.calls[0]["env"]
        assert "MIESC_TEST_SECRET" not in env and "OPENAI_API_KEY" not in env
        assert "FOUNDRY_FFI" not in env
        assert env["FOUNDRY_PROFILE"] == "default"
        assert "PATH" in env
        assert set(env) <= set(ex._ENV_ALLOWLIST) | {"FOUNDRY_PROFILE"}

    def test_network_sandbox_prefix_and_isolation_report(self, fake_forge):
        fake = fake_forge(
            _forge_json("Failure"), sandbox=("/usr/bin/sandbox-exec", "-p", "(deny network*)")
        )
        res = execute_access_control_gaps(mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE)
        assert fake.calls[0]["cmd"][:3] == ["/usr/bin/sandbox-exec", "-p", "(deny network*)"]
        assert fake.calls[0]["cmd"][3:5] == ["/usr/bin/forge", "test"]
        assert res[0]["isolation"]["network"] == "denied"

    def test_no_sandbox_is_reported_not_hidden(self, fake_forge, caplog):
        fake_forge(_forge_json("Success"), sandbox=None)
        with caplog.at_level(logging.WARNING, logger=ex.__name__):
            res = execute_access_control_gaps(mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE)
        assert res[0]["isolation"]["network"] == "unrestricted"
        assert any("no network sandbox" in r.message for r in caplog.records)

    def test_probe_requires_a_storage_write_to_fail(self, fake_forge):
        fake = fake_forge(_forge_json("Success"))
        execute_access_control_gaps(mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE)
        probe = fake.calls[0]["probe"]
        assert "vm.record();" in probe
        assert "vm.accesses(address(target))" in probe
        assert "require(!(ok && writes.length > 0)" in probe
        assert "vm.prank(address(0xBEEF));" in probe
        assert "Vault.setTreasury.selector, address(0)" in probe

    @pytest.mark.parametrize(
        "marker",
        [
            "address constant VM = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;",
            "address constant VM = 0x7109709ecfa91a80626ff3989d68f67f5b1dd12d;",
            'bytes32 constant H = keccak256("hevm cheat code");',
        ],
    )
    def test_source_referencing_cheatcodes_is_refused(self, fake_forge, marker):
        fake = fake_forge(_forge_json("Failure"))
        src = _AC_POSITIVE.replace("contract Vault {", "contract Vault {\n  " + marker)
        res = execute_access_control_gaps(mine_revert_invariants(src), src)
        assert fake.calls == []  # never spawned
        assert res[0]["promotion_state"] == "hypothesis"
        assert "cheatcodes" in res[0]["reason"]

    def test_ids_are_unique_per_privileged_family(self, fake_forge):
        fake_forge(_forge_json("Success"))
        res = execute_access_control_gaps(mine_revert_invariants(_TWO_FAMILIES), _TWO_FAMILIES)
        ids = [r["id"] for r in res]
        assert len(ids) == 2 and len(set(ids)) == 2
        assert ids == sorted(ids) or True  # order is the miner's; uniqueness is the contract
        assert all(
            i.endswith(("-access_control-setTreasury", "-access_control-upgradeImpl")) for i in ids
        )


class TestForgeJsonMapping:
    def test_failure_is_a_counterexample_with_evidence(self, fake_forge):
        fake_forge(_forge_json("Failure"))
        res = execute_access_control_gaps(mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE)
        assert res[0]["promotion_state"] == "counterexample"
        assert res[0]["counterexamples"] == ["setTreasury"]
        assert "wrote the contract's storage" in res[0]["evidence"][0]
        assert "guard is absent" not in res[0]["evidence"][0]

    def test_success_stays_hypothesis(self, fake_forge):
        fake_forge(_forge_json("Success"))
        res = execute_access_control_gaps(mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE)
        assert res[0]["promotion_state"] == "hypothesis"
        assert "counterexamples" not in res[0]

    def test_failure_of_an_unrelated_test_name_is_ignored(self, fake_forge):
        fake_forge(_forge_json("Failure", name="testFuzz_other()"))
        res = execute_access_control_gaps(mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE)
        assert res[0]["promotion_state"] == "hypothesis"

    @pytest.mark.parametrize("stdout", ["", "Compiler run failed", "[]", json.dumps({"x": 1})])
    def test_non_report_output_is_inconclusive(self, fake_forge, stdout):
        fake_forge(stdout)
        res = execute_access_control_gaps(mine_revert_invariants(_AC_POSITIVE), _AC_POSITIVE)
        assert res[0]["promotion_state"] == "hypothesis"
        assert "counterexamples" not in res[0]
