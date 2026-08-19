"""Regression tests: grep_repo must not hang on a ReDoS pattern.

The agentic auditor exposes grep_repo to the LLM, whose pattern argument is
attacker-influenceable via prompt injection. The old code compiled that pattern
with the stdlib ``re`` engine (which cannot be interrupted mid-match) and ran it
against attacker-controlled contract source — a classic catastrophic-backtracking
denial of service. The fix routes untrusted regexes through the ``regex`` module's
per-search ``timeout`` (or falls back to substring search), so a pathological
pattern can never hang the single-threaded audit worker.
"""

import time
from pathlib import Path

import pytest

from miesc.agents.repo_call_graph import (
    RepoCallGraph,
    _ContractInfo,
    _timeout_regex,
)
from miesc.ml.call_graph import CallGraph


def _repo_with_evil_line():
    """A contract whose body carries a long repetitive line = ReDoS haystack.

    Built directly (not via ``RepoCallGraph.build`` on a temp dir) because the
    pytest ``tmp_path`` fixture's directory name contains "test", which the
    build-time ``_SKIP_PATH`` filter would (correctly) skip.
    """
    evil = "a" * 5000 + "!"  # long run of 'a' ending in a non-matching char
    source = "contract Evil {\n" f"    // {evil}\n" "    function withdraw() public {}\n" "}"
    info = _ContractInfo(name="Evil", source=source, file=Path("Evil.sol"), graph=CallGraph())
    return RepoCallGraph(contracts={"Evil": info})


@pytest.mark.timeout(10)
def test_grep_repo_redos_pattern_returns_promptly():
    """A catastrophic-backtracking pattern must return fast, not hang.

    Under the old stdlib-``re`` code this call never returns and pytest-timeout
    kills the test; under the fix it returns in well under a second.
    """
    graph = _repo_with_evil_line()
    start = time.time()
    result = graph.grep_repo(r"(a+)+$")
    elapsed = time.time() - start
    assert elapsed < 3.0, f"grep_repo took {elapsed:.1f}s — ReDoS not mitigated"
    assert isinstance(result, str)


def test_grep_repo_substring_still_works():
    """A plain substring pattern must still locate code (no regression)."""
    graph = _repo_with_evil_line()
    result = graph.grep_repo("withdraw")
    assert "withdraw" in result
    assert "Evil:" in result


@pytest.mark.skipif(_timeout_regex is None, reason="regex module not installed")
def test_grep_repo_regex_still_works():
    """A benign regex must still match when the regex module is available."""
    graph = _repo_with_evil_line()
    result = graph.grep_repo(r"function\s+\w+")
    assert "withdraw" in result


def test_grep_repo_overlong_pattern_is_capped():
    """An absurdly long pattern must not blow up (length cap)."""
    graph = _repo_with_evil_line()
    result = graph.grep_repo("z" * 100_000)  # no match, but must return a string
    assert isinstance(result, str)
