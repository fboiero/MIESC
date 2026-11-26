"""The shared brace matcher is the single implementation (scorecard F16)."""

from miesc.agents import repo_call_graph
from miesc.llm import _solidity_text, yul_assembly_memory_safety


def test_balanced():
    assert _solidity_text._match_brace("a{b{c}d}e", 1) == 7


def test_unbalanced_defaults_to_len():
    src = "a{b"
    assert _solidity_text._match_brace(src, 1) == len(src)


def test_unbalanced_missing_sentinel():
    assert _solidity_text._match_brace("a{b", 1, missing=-1) == -1


def test_no_local_duplicates():
    assert yul_assembly_memory_safety._match_brace is _solidity_text._match_brace
    assert repo_call_graph._match_brace is _solidity_text._match_brace
