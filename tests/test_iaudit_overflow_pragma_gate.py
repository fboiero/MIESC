"""
iAudit's pattern-fallback must not emit a false SWC-101 "integer overflow" finding
on a Solidity >= 0.8 contract — the compiler reverts on overflow from 0.8.0 on, so
the finding is demonstrably wrong there (observed on a real solc 0.8.30 target when
the LLM detector timed out and fell back to pattern analysis).

The gate is recall-safe: it suppresses the finding only when EVERY pragma in the
file guarantees a >= 0.8 floor; an unknown, lower, or exclusive-`>` pragma keeps it.
"""

from __future__ import annotations

import pytest

from miesc.adapters.iaudit_adapter import (
    IAuditAdapter,
    _pragma_guarantees_checked_arithmetic,
)


@pytest.fixture
def adapter():
    return IAuditAdapter()


def _contract(pragma: str) -> str:
    return (
        f"// SPDX-License-Identifier: MIT\n{pragma}\n"
        "contract C {\n"
        "    uint256 public total;\n"
        "    function add(uint256 x) external { total = total + 1; uint256 y = x * 2; }\n"
        "}\n"
    )


# ---------------------------------------------------------------------------
# _pragma_guarantees_checked_arithmetic — lower-bound semantics, recall-safe
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pragma,expected",
    [
        ("pragma solidity =0.8.30;", True),  # the actual bug
        ("pragma solidity ^0.8.0;", True),
        ("pragma solidity 0.8.30;", True),
        ("pragma solidity ~0.8.1;", True),
        ("pragma solidity 0.8;", True),
        ("pragma solidity >=0.8.0 <0.9.0;", True),
        ("pragma solidity ^0.7.6;", False),
        ("pragma solidity >=0.7.0;", False),
        ("pragma solidity >0.7.6;", False),  # exclusive -> conservative
        ("pragma solidity >=0.5.0;", False),
        ("pragma solidity ^0.4.24;", False),
        ("pragma solidity <0.9.0;", False),  # upper-bound only
    ],
)
def test_pragma_floor_detection(pragma, expected):
    assert _pragma_guarantees_checked_arithmetic(pragma) is expected


def test_no_pragma_is_not_guaranteed():
    assert _pragma_guarantees_checked_arithmetic("contract C {}") is False


def test_mixed_pragmas_take_the_minimum_floor():
    # A flattened file: one contract <0.8 means the file is not guaranteed.
    code = "pragma solidity ^0.8.0;\n// ...\npragma solidity ^0.7.0;\n"
    assert _pragma_guarantees_checked_arithmetic(code) is False


# ---------------------------------------------------------------------------
# End-to-end through the pattern fallback (the real reproduction, no Ollama)
# ---------------------------------------------------------------------------


def _types(result) -> set:
    return {f["type"] for f in result["findings"]}


def test_overflow_suppressed_on_0_8_contract(adapter, tmp_path):
    path = tmp_path / "C08.sol"
    path.write_text(_contract("pragma solidity =0.8.30;"), encoding="utf-8")

    result = adapter.analyze(str(path), fallback_only=True)

    assert result["status"] == "success"
    assert "integer_overflow" not in _types(
        result
    ), "0.8.x has checked arithmetic — the overflow finding is false there"


def test_overflow_still_emitted_below_0_8(adapter, tmp_path):
    # The pattern is *allowed* to fire on a genuinely pre-0.8 contract.
    path = tmp_path / "C07.sol"
    path.write_text(_contract("pragma solidity ^0.7.0;"), encoding="utf-8")

    result = adapter.analyze(str(path), fallback_only=True)

    assert "integer_overflow" in _types(result)
