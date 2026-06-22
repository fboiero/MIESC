"""
Tests for the recall-safe benign-context verifier (src/ml/benign_context_verifier.py).

The cardinal invariant under test: the verifier drops a finding ONLY when the contract
clearly mitigates it (benign context); it must NEVER drop a real, unmitigated finding.
These tests lock that property so a future refactor cannot silently start losing
vulnerabilities. All rule-only (model=None) -> deterministic, no network.
"""

from src.ml.benign_context_verifier import (
    BenignContextVerifier,
    apply_to_results,
    match_benign,
)

V = BenignContextVerifier(model=None)  # rule-only, deterministic


def _f(vtype, function="", line=None):
    loc = {"function": function or "unknown"}
    if line is not None:
        loc["line"] = line
    return {"type": vtype, "location": loc, "severity": "high"}


# --------------------------------------------------------------------------- #
# CARDINAL: mitigated -> dropped, unmitigated -> KEPT (per category)
# --------------------------------------------------------------------------- #
class TestRecallSafePairs:
    def test_reentrancy_guarded_is_flagged_not_dropped(self):
        # guard PRESENCE is contextual, not proof of benignity -> flag, never drop
        code = ("pragma solidity ^0.8.0; contract C { mapping(address=>uint) b; bool l;"
                " modifier nonReentrant(){require(!l);l=true;_;l=false;}"
                " function withdraw(uint a) external nonReentrant {"
                ' (bool ok,)=msg.sender.call{value:a}(""); require(ok); b[msg.sender]-=a; } }')
        assert V.verify(_f("reentrancy", "withdraw"), code) == "needs_review"

    def test_reentrancy_unguarded_is_kept(self):
        code = ("pragma solidity ^0.8.0; contract C { mapping(address=>uint) b;"
                " function withdraw(uint a) external {"
                ' (bool ok,)=msg.sender.call{value:a}(""); require(ok); b[msg.sender]-=a; } }')
        assert V.verify(_f("reentrancy", "withdraw"), code) == "confirmed"

    def test_reentrancy_cei_is_flagged_not_dropped(self):
        # CEI ordering is contextual (subtle reentrancy can remain) -> flag, never drop
        code = ("pragma solidity ^0.8.0; contract C { mapping(address=>uint) balances;"
                " function withdraw(uint a) external { require(balances[msg.sender]>=a);"
                ' balances[msg.sender]-=a; (bool ok,)=msg.sender.call{value:a}(""); require(ok); } }')
        assert V.verify(_f("reentrancy", "withdraw"), code) == "needs_review"

    def test_access_onlyowner_is_flagged_not_dropped(self):
        # onlyOwner presence is contextual (owner-rug) -> flag, never drop
        code = ("pragma solidity ^0.8.0; contract C { address owner;"
                " modifier onlyOwner(){require(msg.sender==owner);_;}"
                " function setOwner(address n) external onlyOwner { owner=n; } }")
        assert V.verify(_f("access_control", "setOwner"), code) == "needs_review"

    def test_access_unprotected_is_kept(self):
        code = ("pragma solidity ^0.8.0; contract C { address owner;"
                " function setOwner(address n) external { owner=n; } }")
        assert V.verify(_f("access_control", "setOwner"), code) == "confirmed"

    def test_arithmetic_solidity08_is_dropped(self):
        code = ("pragma solidity ^0.8.0; contract C { mapping(address=>uint) b;"
                " function add(uint a) public { b[msg.sender]+=a; } }")
        assert V.verify(_f("arithmetic", "add"), code) == "false_positive"

    def test_arithmetic_solidity04_is_kept(self):
        code = ("pragma solidity ^0.4.24; contract C { mapping(address=>uint) b;"
                " function add(uint a) public { b[msg.sender]+=a; } }")
        assert V.verify(_f("arithmetic", "add"), code) == "confirmed"

    def test_rounding_on_solidity08_is_kept(self):
        # 0.8 guards overflow/underflow but NOT precision/rounding -> must NOT drop
        code = ("pragma solidity ^0.8.0; contract C { uint s;"
                " function f(uint a, uint b, uint c) public { s = a * b / c; } }")
        finding = {"type": "arithmetic", "title": "rounding_error_division",
                   "location": {"function": "f"}, "severity": "medium"}
        assert V.verify(finding, code) != "false_positive"

    def test_unchecked_call_discarded_is_kept(self):
        code = ("pragma solidity ^0.8.0; contract C {"
                ' function pay(address a) external { a.call{value:1}(""); } }')
        assert V.verify(_f("unchecked_low_level_calls", "pay"), code) == "confirmed"

    def test_unchecked_call_checked_is_dropped(self):
        code = ("pragma solidity ^0.8.0; contract C {"
                ' function pay(address a) external { (bool ok,)=a.call{value:1}(""); require(ok); } }')
        assert V.verify(_f("unchecked_low_level_calls", "pay"), code) == "false_positive"

    def test_timestamp_timelock_is_flagged_not_dropped(self):
        # timestamp gate is contextual (miner skew can still matter) -> flag, never drop
        code = ("pragma solidity ^0.8.0; contract C { uint t;"
                ' function unlock() external { require(block.timestamp>=t,"locked"); } }')
        assert V.verify(_f("time_manipulation", "unlock"), code) == "needs_review"

    def test_timestamp_entropy_is_kept(self):
        code = ("pragma solidity ^0.8.0; contract C {"
                " function pick(uint n) public view returns(uint){ return block.timestamp % n; } }")
        assert V.verify(_f("time_manipulation", "pick"), code) == "confirmed"

    def test_informational_lint_is_dropped(self):
        code = "pragma solidity ^0.8.0; contract C { function f() public {} }"
        assert V.verify(_f("useless-public-function", "f"), code) == "false_positive"


# --------------------------------------------------------------------------- #
# Line-scoping when the detector reports function='unknown'
# --------------------------------------------------------------------------- #
class TestLineScoping:
    CODE = (
        "pragma solidity ^0.8.0;\n"
        "contract C {\n"
        "  mapping(address=>uint) b;\n"
        "  bool l;\n"
        "  modifier nonReentrant(){require(!l);l=true;_;l=false;}\n"
        "  function guarded(uint a) external nonReentrant {\n"
        '    (bool ok,)=msg.sender.call{value:a}(""); require(ok); b[msg.sender]-=a;\n'
        "  }\n"
        "  function open(uint a) external {\n"
        '    (bool ok,)=msg.sender.call{value:a}(""); require(ok); b[msg.sender]-=a;\n'
        "  }\n"
        "}\n"
    )

    def test_line_inside_guarded_function_is_flagged(self):
        # line 7 = the call inside guarded() -> guard detected via line scope -> FLAG (contextual)
        assert V.verify(_f("reentrancy", "unknown", line=7), self.CODE) == "needs_review"

    def test_line_inside_open_function_is_kept(self):
        # line 10 = the call inside open() (no guard) -> must be KEPT (recall-safe)
        assert V.verify(_f("reentrancy", "unknown", line=10), self.CODE) == "confirmed"


# --------------------------------------------------------------------------- #
# Weak-signal handling: never drop on absent/ambiguous grounding
# --------------------------------------------------------------------------- #
class TestNeverDropOnWeakSignal:
    def test_cited_function_absent_is_flagged_not_dropped(self):
        code = "pragma solidity ^0.8.0; contract C { function withdraw() external {} }"
        # finding cites a function that does not exist -> needs_review, NOT dropped
        assert V.verify(_f("reentrancy", "doesNotExist"), code) == "needs_review"

    def test_unknown_function_no_line_does_not_falsely_drop_real(self):
        code = ("pragma solidity ^0.8.0; contract C { mapping(address=>uint) b;"
                ' function open(uint a) external { (bool ok,)=msg.sender.call{value:a}(""); b[msg.sender]-=a; } }')
        # no scope info + no benign signal -> must not be dropped
        assert V.verify(_f("reentrancy", "unknown"), code) != "false_positive"


# --------------------------------------------------------------------------- #
# apply_to_results: in-place, recall-safe, returns (dropped, flagged)
# --------------------------------------------------------------------------- #
class TestApplyToResults:
    def test_drops_deterministic_benign_keeps_real(self, tmp_path):
        checked = tmp_path / "G.sol"  # checked return -> deterministic benign -> DROPPED
        checked.write_text(
            "pragma solidity ^0.8.0; contract C {"
            ' function pay(address a) external { (bool ok,)=a.call{value:1}(""); require(ok); } }'
        )
        openf = tmp_path / "O.sol"  # unguarded reentrancy -> real -> KEPT
        openf.write_text(
            "pragma solidity ^0.8.0; contract C { mapping(address=>uint) b;"
            " function withdraw(uint a) external {"
            ' (bool ok,)=msg.sender.call{value:a}(""); require(ok); b[msg.sender]-=a; } }'
        )
        results = [
            {"tool": "t", "findings": [
                {"type": "unchecked_low_level_calls", "location": {"function": "pay"}, "file": str(checked)},
                {"type": "reentrancy", "location": {"function": "withdraw"}, "file": str(openf)},
            ]},
        ]
        dropped, flagged = apply_to_results(results)
        kept = results[0]["findings"]
        assert dropped == 1  # the checked call (deterministic benign)
        assert len(kept) == 1 and kept[0]["file"] == str(openf)  # real finding survives

    def test_guarded_finding_is_flagged_not_dropped(self, tmp_path):
        guarded = tmp_path / "G.sol"
        guarded.write_text(
            "pragma solidity ^0.8.0; contract C { bool l;"
            " modifier nonReentrant(){require(!l);l=true;_;l=false;}"
            ' function withdraw() external nonReentrant { msg.sender.call{value:1}(""); } }'
        )
        results = [{"tool": "t", "findings": [
            {"type": "reentrancy", "location": {"function": "withdraw"}, "file": str(guarded)}]}]
        dropped, flagged = apply_to_results(results)
        assert dropped == 0 and flagged == 1  # guard PRESENCE -> flagged, never dropped
        assert len(results[0]["findings"]) == 1  # finding retained

    def test_match_benign_returns_pattern_for_guarded(self):
        code = ("pragma solidity ^0.8.0; contract C { bool l;"
                " modifier nonReentrant(){require(!l);l=true;_;l=false;}"
                ' function w() external nonReentrant { msg.sender.call{value:1}(""); } }')
        p = match_benign({"type": "reentrancy", "location": {"function": "w"}}, code, V.patterns)
        assert p is not None and "REENTRANCY" in p["id"]

    def test_rule_only_makes_no_network_call(self):
        # model=None must never attempt an LLM query
        assert V.model is None
        v = BenignContextVerifier()
        assert v._llm_false_positive({"type": "reentrancy", "function": "x"}, "contract C {}") is False


# --------------------------------------------------------------------------- #
# LLM is ADVISORY: it may flag (needs_review) but must NEVER drop a finding.
# Locks the fix from the wild real-data eval, where LLM drops lost 3/21 real vulns.
# --------------------------------------------------------------------------- #
class TestLLMNeverDrops:
    def test_llm_false_positive_only_flags_never_drops(self):
        v = BenignContextVerifier(model="dummy")
        v._llm_false_positive = lambda finding, code: True  # force max-aggressive LLM
        # real unchecked send (the exact pattern the LLM wrongly dropped) with NO benign rule
        code = ("pragma solidity ^0.4.24; contract C { address owner;"
                " function flush() public { owner.send(this.balance); } }")
        assert v.verify(_f("unchecked_low_level_calls", "flush"), code) == "needs_review"

    def test_llm_cannot_drop_real_timestamp_vuln(self):
        v = BenignContextVerifier(model="dummy")
        v._llm_false_positive = lambda finding, code: True
        code = ("pragma solidity ^0.4.24; contract C { uint start;"
                " function buy() public { if (now < start) throw; } }")
        assert v.verify(_f("time_manipulation", "buy"), code) != "false_positive"

    def test_rule_benign_still_drops_even_with_llm_off(self):
        # the deterministic rule path is the ONLY drop path and must still work
        v = BenignContextVerifier(model="dummy")
        v._llm_false_positive = lambda finding, code: False
        code = ("pragma solidity ^0.8.0; contract C { mapping(address=>uint) b;"
                " function add(uint a) public { b[msg.sender]+=a; } }")
        assert v.verify(_f("arithmetic", "add"), code) == "false_positive"


# --------------------------------------------------------------------------- #
# Type-deterministic corpus additions (mined from wild FPs; 0 real across sources)
# --------------------------------------------------------------------------- #
class TestDeterministicAdditions:
    def _f(self, vtype, title, line=1):
        return {"type": vtype, "title": title, "location": {"function": "unknown", "line": line}}

    def test_missing_event_emission_is_dropped(self):
        # missing event is informational (not in DASP/SWC exploit taxonomy) -> drop
        code = "pragma solidity ^0.8.0; contract C { uint v; function set(uint x) public { v = x; } }"
        assert V.verify(self._f("missing_event_emission", "missing_event_emission"), code) == "false_positive"

    def test_constructor_mismatch_modern_is_dropped(self):
        # SWC-118 impossible on >=0.5 -> compiler-guaranteed benign
        code = "pragma solidity ^0.8.0; contract C { address owner; constructor() { owner = msg.sender; } }"
        assert V.verify(self._f("access_control", "constructor_mismatch"), code) == "false_positive"

    def test_constructor_mismatch_legacy_is_kept(self):
        # on <0.5 the wrong-constructor-name vuln is REAL -> must NOT drop
        code = ("pragma solidity ^0.4.24; contract C { address owner;"
                " function C() public { owner = msg.sender; } }")
        assert V.verify(self._f("access_control", "constructor_mismatch"), code) != "false_positive"


# --------------------------------------------------------------------------- #
# Unchecked-call benign patterns must scope to the FLAGGED line, not the function.
# Locks the wild-at-scale fix where a .transfer() elsewhere over-dropped real .call()/.send().
# --------------------------------------------------------------------------- #
class TestUncheckedCallLineScoping:
    CODE = (
        "pragma solidity ^0.8.0;\n"      # 1
        "contract C {\n"                  # 2
        "  function f(address t) external {\n"          # 3
        '    t.call{value:1}("");\n'                     # 4  <- unchecked call (REAL)
        "    payable(msg.sender).transfer(1);\n"        # 5  <- a .transfer elsewhere
        "  }\n"                            # 6
        "}\n"                             # 7
    )

    def _f(self, title, line):
        return {"type": "unchecked_low_level_calls", "title": title,
                "location": {"function": "unknown", "line": line}}

    def test_unchecked_call_not_dropped_when_transfer_elsewhere(self):
        # the .call() on line 4 is real; a .transfer() on line 5 must NOT make it benign
        assert V.verify(self._f("unchecked_call_pattern", 4), self.CODE) != "false_positive"

    def test_finding_on_transfer_line_is_dropped(self):
        # an unchecked-return finding ON a .transfer() line IS benign (transfer reverts)
        assert V.verify(self._f("erc20_return_check", 5), self.CODE) == "false_positive"
