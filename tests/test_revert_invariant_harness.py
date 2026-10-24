"""Tests for the revert-guard probe harness generator (the test_generated rung)."""

from __future__ import annotations

from miesc.llm.revert_invariant_harness import generate_revert_guard_harnesses
from miesc.llm.revert_invariant_mining import mine_revert_invariants

_ACCESS_CONTROL = (
    "contract C {\n"
    "  address owner;\n"
    "  modifier onlyOwner() { require(msg.sender == owner); _; }\n"
    "  function setFee(uint x) external onlyOwner { fee = x; }\n"
    "  function setTreasury(address a) external { treasury = a; }\n"
    "}\n"
)
_PAUSE = (
    "contract C {\n"
    "  bool paused;\n"
    "  modifier whenNotPaused() { require(!paused); _; }\n"
    "  function deposit() external whenNotPaused { bal += 1; }\n"
    "  function withdraw() external { bal -= 1; }\n"
    "}\n"
)
_FRESHNESS = (
    "contract C {\n"
    "  function a(uint256 deadline, uint256 x) external {\n"
    '    require(block.timestamp <= deadline, "expired"); _do(x);\n'
    "  }\n"
    "  function b(uint256 deadline, uint256 y) external { _do(y); }\n"
    "}\n"
)


def _harnesses(src: str):
    return generate_revert_guard_harnesses(mine_revert_invariants(src))


class TestHarnessShape:
    def test_access_control_harness_is_test_generated(self):
        h = _harnesses(_ACCESS_CONTROL)
        assert len(h) >= 1
        art = h[0]
        assert art["promotion_state"] == "test_generated"
        assert art["blockers"]  # never an empty-evidence test_generated
        assert "vm.expectRevert()" in art["foundry_harness"]

    def test_access_control_generates_unauthorized_prank(self):
        art = _harnesses(_ACCESS_CONTROL)[0]
        assert "vm.prank(address(0xBEEF))" in art["foundry_harness"]
        assert "test_revertGuard_setTreasury" in art["foundry_harness"]

    def test_freshness_generates_warp_past_deadline(self):
        art = _harnesses(_FRESHNESS)[0]
        assert "vm.warp(" in art["foundry_harness"]
        assert art["category"] == "freshness_check"


class TestHarnessDoesNotManufacture:
    """The hard, un-fakeable setup must stay a TODO, never a guessed call."""

    def test_pause_harness_does_not_invent_a_pauser_call(self):
        art = _harnesses(_PAUSE)[0]
        src = art["foundry_harness"]
        assert art["category"] == "pause_toggle"
        # No fabricated pause call of any shape.
        for invented in ("target.pause(", "pause()", "setPaused(", "target._pause("):
            assert invented not in src
        # The paused state is an explicit, recorded blocker instead.
        assert any("paused state" in b for b in art["blockers"])

    def test_constructor_and_args_are_blockers_not_guesses(self):
        art = _harnesses(_ACCESS_CONTROL)[0]
        blockers = " ".join(art["blockers"])
        assert "constructor arguments" in blockers
        assert "arguments for `setTreasury`" in blockers
        # setUp does not fabricate constructor args.
        assert "new Contract(" not in art["foundry_harness"].replace(
            "// target = new Contract(", ""
        )


class TestHarnessNotAutoRun:
    def test_harness_is_an_artifact_not_a_runnable_foundry_test(self):
        # The artifact exposes `foundry_harness`, never a `foundry_test` the validator gate runs.
        art = _harnesses(_ACCESS_CONTROL)[0]
        assert "foundry_harness" in art
        assert "foundry_test" not in art

    def test_module_does_not_touch_the_validator(self):
        # The docstring references the validator to explain the scope boundary, but the module
        # must neither import it nor execute anything.
        import miesc.llm.revert_invariant_harness as mod

        text = open(mod.__file__).read()
        assert "import InvariantValidator" not in text
        assert "InvariantValidator(" not in text
        assert ".validate(" not in text


class TestHarnessSilence:
    def test_no_gaps_yields_no_harnesses(self):
        src = (
            "contract C {\n"
            "  address owner;\n"
            "  modifier onlyOwner() { require(msg.sender == owner); _; }\n"
            "  function setFee(uint x) external onlyOwner { fee = x; }\n"
            "}\n"
        )
        assert _harnesses(src) == []

    def test_empty_input(self):
        assert generate_revert_guard_harnesses([]) == []
        assert _harnesses("") == []
