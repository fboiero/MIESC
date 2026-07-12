"""
Tests for the LSP-aligned CodeAction output of ``miesc fix``.

Covers:
  - compute_text_edits: pure insertion → precise zero-width range
  - compute_text_edits: full-line replacement → line-spanning range
  - compute_text_edits: identical sources → no edits
  - compute_text_edits: multi-hunk edits are ordered and non-overlapping
  - to_code_actions: shape, key set, drops no-op fixes
  - build_code_actions: range + newText correctness per deterministic fix type
    (reentrancy, access_control, unchecked_call, arithmetic)
  - JSON serialization is stable/deterministic
  - CLI: `fix -f code-actions` emits valid JSON (populated + empty cases)
  - finding_id is stable and unique
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from miesc.cli.commands.fix import (
    _action_title,
    _finding_id,
    _fix_category,
    build_code_actions,
    fix,
)
from miesc.core.code_actions import (
    CODE_ACTION_KIND_QUICKFIX,
    FixEdit,
    compute_text_edits,
    to_code_actions,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

REENTRANCY_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Victim {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
"""

ACCESS_CONTROL_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    address public owner = msg.sender;

    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
"""

UNCHECKED_CALL_CONTRACT = """\
pragma solidity 0.4.25;

contract ReturnValue {
  function callnotchecked(address callee) public {
    callee.call();
  }
}
"""

ARITHMETIC_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract Token {
    uint256 public total;

    function mint(uint256 amount) public {
        total += amount;
    }
}
"""


def _assert_valid_range(rng: dict) -> None:
    """Every LSP range is 0-based and start <= end (lexicographic)."""
    start, end = rng["start"], rng["end"]
    for pos in (start, end):
        assert pos["line"] >= 0
        assert pos["character"] >= 0
    assert (start["line"], start["character"]) <= (end["line"], end["character"])


def _make_results(findings: list, tmp_path: Path) -> Path:
    p = tmp_path / "results.json"
    p.write_text(json.dumps({"contract": "C.sol", "findings": findings}))
    return p


# ---------------------------------------------------------------------------
# compute_text_edits
# ---------------------------------------------------------------------------


class TestComputeTextEdits:
    def test_identical_sources_produce_no_edits(self):
        assert compute_text_edits("abc\n", "abc\n") == []

    def test_pure_insertion_is_zero_width_with_precise_newtext(self):
        original = "function withdraw() public {\n"
        patched = "function withdraw() public nonReentrant {\n"
        edits = compute_text_edits(original, patched)
        assert len(edits) == 1
        edit = edits[0]
        _assert_valid_range(edit["range"])
        # Zero-width insertion right before the opening brace.
        assert edit["range"]["start"] == edit["range"]["end"]
        assert edit["range"]["start"]["line"] == 0
        assert edit["range"]["start"]["character"] == len("function withdraw() public ")
        assert edit["newText"] == "nonReentrant "

    def test_full_line_replacement_spans_the_line(self):
        original = "line one\nOLD LINE\nline three\n"
        patched = "line one\nNEW REPLACEMENT LINE\nline three\n"
        edits = compute_text_edits(original, patched)
        assert len(edits) == 1
        rng = edits[0]["range"]
        _assert_valid_range(rng)
        # Change is confined to line index 1 (0-based).
        assert rng["start"]["line"] == 1
        assert rng["end"]["line"] == 1
        # Common prefix/suffix trimmed: only the differing middle is replaced.
        assert edits[0]["newText"].startswith("NEW REPLACEMENT")

    def test_multi_line_insertion_range_and_newtext(self):
        original = "a\nb\n"
        patched = "a\nINSERTED1\nINSERTED2\nb\n"
        edits = compute_text_edits(original, patched)
        assert len(edits) == 1
        assert "INSERTED1\nINSERTED2\n" in edits[0]["newText"]

    def test_multiple_hunks_are_ordered_and_non_overlapping(self):
        original = "one\ntwo\nthree\nfour\n"
        patched = "ONE\ntwo\nthree\nFOUR\n"
        edits = compute_text_edits(original, patched)
        assert len(edits) == 2
        for edit in edits:
            _assert_valid_range(edit["range"])
        # Ordered top-to-bottom and non-overlapping.
        first_end = (edits[0]["range"]["end"]["line"], edits[0]["range"]["end"]["character"])
        second_start = (
            edits[1]["range"]["start"]["line"],
            edits[1]["range"]["start"]["character"],
        )
        assert first_end <= second_start


# ---------------------------------------------------------------------------
# to_code_actions
# ---------------------------------------------------------------------------


class TestToCodeActions:
    def test_shape_and_keys(self):
        fx = FixEdit(
            finding_id="abc:7",
            title="Add nonReentrant guard in withdraw",
            file="Victim.sol",
            original="x\n",
            patched="x2\n",
        )
        actions = to_code_actions([fx])
        assert len(actions) == 1
        action = actions[0]
        assert set(action.keys()) == {"finding_id", "title", "kind", "file", "edits"}
        assert action["finding_id"] == "abc:7"
        assert action["title"] == "Add nonReentrant guard in withdraw"
        assert action["kind"] == CODE_ACTION_KIND_QUICKFIX
        assert action["file"] == "Victim.sol"
        assert isinstance(action["edits"], list) and action["edits"]

    def test_drops_no_op_fixes(self):
        fx = FixEdit("id", "title", "f.sol", "same\n", "same\n")
        assert to_code_actions([fx]) == []

    def test_json_serializable_and_stable(self):
        fx = FixEdit("id:1", "t", "f.sol", "a\n", "b\n")
        actions = to_code_actions([fx])
        first = json.dumps(actions, sort_keys=True)
        second = json.dumps(to_code_actions([fx]), sort_keys=True)
        assert first == second


# ---------------------------------------------------------------------------
# build_code_actions — per deterministic fix type
# ---------------------------------------------------------------------------


class TestBuildCodeActionsPerType:
    def _single_action(self, source: str, finding: dict) -> dict:
        actions = build_code_actions(source, [finding], "C.sol")
        assert len(actions) == 1, f"expected exactly one action, got {actions}"
        action = actions[0]
        assert action["file"] == "C.sol"
        assert action["edits"]
        for edit in action["edits"]:
            _assert_valid_range(edit["range"])
        return action

    def test_reentrancy_range_and_newtext(self):
        action = self._single_action(
            REENTRANCY_CONTRACT,
            {"type": "reentrancy", "function": "withdraw", "line": 7, "fix_code": "x"},
        )
        assert action["title"] == "Add nonReentrant guard in withdraw"
        joined = "".join(e["newText"] for e in action["edits"])
        assert "nonReentrant" in joined
        # The precise modifier insertion is a zero-width edit.
        assert any(
            e["range"]["start"] == e["range"]["end"] and e["newText"] == "nonReentrant "
            for e in action["edits"]
        )

    def test_access_control_range_and_newtext(self):
        action = self._single_action(
            ACCESS_CONTROL_CONTRACT,
            {"type": "suicidal", "function": "kill", "line": 7, "fix_code": "x"},
        )
        assert "onlyOwner" in action["title"]
        joined = "".join(e["newText"] for e in action["edits"])
        assert "onlyOwner" in joined

    def test_unchecked_call_range_and_newtext(self):
        action = self._single_action(
            UNCHECKED_CALL_CONTRACT,
            {"type": "unchecked_call", "function": "callnotchecked", "line": 5, "fix_code": "x"},
        )
        joined = "".join(e["newText"] for e in action["edits"])
        assert "require(" in joined

    def test_arithmetic_range_and_newtext(self):
        action = self._single_action(
            ARITHMETIC_CONTRACT,
            {"type": "arithmetic", "function": "mint", "line": 7, "fix_code": "x"},
        )
        joined = "".join(e["newText"] for e in action["edits"])
        assert "SafeMath" in joined

    def test_unfixable_finding_yields_no_action(self):
        actions = build_code_actions(
            REENTRANCY_CONTRACT,
            [{"type": "reentrancy", "function": "doesNotExist", "line": 99, "fix_code": "x"}],
            "C.sol",
        )
        assert actions == []


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------


class TestMetadataHelpers:
    def test_fix_category_mapping(self):
        assert _fix_category("reentrancy-eth") == "reentrancy"
        assert _fix_category("suicidal") == "access_control"
        assert _fix_category("unchecked-low-level-call") == "unchecked_call"
        assert _fix_category("integer_overflow") == "arithmetic"
        assert _fix_category("mystery") == "mystery"

    def test_action_title_with_and_without_function(self):
        assert _action_title("reentrancy", "withdraw") == "Add nonReentrant guard in withdraw"
        assert _action_title("reentrancy", "") == "Add nonReentrant guard"
        assert _action_title("weird-type", "f") == "Apply MIESC fix: weird-type in f"

    def test_finding_id_prefers_explicit_id(self):
        assert _finding_id({"id": "CUSTOM-1"}, 3) == "CUSTOM-1"

    def test_finding_id_is_stable_for_same_finding(self):
        finding = {"type": "reentrancy", "file": "C.sol", "line": 7, "message": "bad"}
        assert _finding_id(finding, 0) == _finding_id(finding, 0)

    def test_finding_id_unique_across_lines(self):
        base = {"type": "reentrancy", "file": "C.sol", "message": "bad"}
        id_a = _finding_id({**base, "line": 7}, 0)
        id_b = _finding_id({**base, "line": 20}, 1)
        assert id_a != id_b


# ---------------------------------------------------------------------------
# CLI smoke tests
# ---------------------------------------------------------------------------


class TestCliCodeActionsFormat:
    def test_emits_valid_json_to_stdout(self, tmp_path):
        contract = tmp_path / "Victim.sol"
        contract.write_text(REENTRANCY_CONTRACT)
        results = _make_results(
            [{"type": "reentrancy", "function": "withdraw", "line": 7, "fix_code": "x"}],
            tmp_path,
        )
        result = CliRunner().invoke(
            fix, [str(results), "-c", str(contract), "-f", "code-actions"]
        )
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert isinstance(payload, list) and len(payload) == 1
        assert payload[0]["kind"] == "quickfix"
        assert payload[0]["edits"]

    def test_writes_json_to_output_file(self, tmp_path):
        contract = tmp_path / "Victim.sol"
        contract.write_text(REENTRANCY_CONTRACT)
        results = _make_results(
            [{"type": "reentrancy", "function": "withdraw", "line": 7, "fix_code": "x"}],
            tmp_path,
        )
        out = tmp_path / "actions.json"
        result = CliRunner().invoke(
            fix,
            [str(results), "-c", str(contract), "-f", "code-actions", "-o", str(out)],
        )
        assert result.exit_code == 0
        payload = json.loads(out.read_text())
        assert isinstance(payload, list) and len(payload) == 1

    def test_no_fixable_findings_emits_empty_array(self, tmp_path):
        contract = tmp_path / "Victim.sol"
        contract.write_text(REENTRANCY_CONTRACT)
        results = _make_results([{"type": "reentrancy", "function": "withdraw"}], tmp_path)
        result = CliRunner().invoke(
            fix, [str(results), "-c", str(contract), "-f", "code-actions"]
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == []
