"""`_is_test_or_mock_path` matches test/mock files by PATH COMPONENT, not a raw
substring of the absolute path.

The old `_TEST_FILE` regex (`test[_/]|mock[_/]|\\.t\\.sol$|Test\\.sol$`) was
searched against the finding's absolute `file_path`, so a production contract
under a directory like ``~/test_projects/`` or ``~/mock_data/`` was silently
suppressed as a test file (recall-unsafe). It also matched ``Contest.sol`` via
``Test\\.sol$`` + IGNORECASE.

The helper keeps EXACTLY the set the old regex suppressed — a ``test``/``mock``
directory segment, a ``test_``/``mock_`` prefix, ``*.t.sol``, and ``*Test.sol``
(now boundary-anchored) — just computed on path components, minus the substring
false positives. It deliberately does NOT add ``tests``/``mocks`` segments:
MIESC documents scanning ``tests/fixtures/*.sol`` as its smoke/demo target, so
those must stay reportable.
"""

from __future__ import annotations

import pytest

from miesc.core.intelligence import _is_test_or_mock_path

# (path, expected) — expected True == treated as a test/mock file (suppressible)
CASES = [
    # --- the bug: production code under a test-ish directory NAME ---
    ("/Users/x/test_projects/src/Bank.sol", False),
    ("/Users/x/mock_data/src/Bank.sol", False),
    ("/home/dev/contest_2026/contracts/Vault.sol", False),
    # --- genuine test/mock directory segments (singular, as the old regex) ---
    ("/Users/x/proj/test/Bank.t.sol", True),
    ("/Users/x/proj/src/mock/Token.sol", True),
    ("/Users/x/Test/src/Bank.sol", True),  # case-insensitive segment
    # --- plural dirs are NOT suppressors: MIESC's documented demo lives here ---
    ("/Users/x/proj/tests/Bank.sol", False),
    ("/Users/x/proj/src/mocks/Token.sol", False),
    ("tests/fixtures/reentrancy.sol", False),
    # --- genuine test/mock basenames (what the old regex caught) ---
    ("/Users/x/proj/src/FooTest.sol", True),
    ("/Users/x/proj/src/Foo.t.sol", True),
    ("/Users/x/proj/src/Foo.test.sol", True),
    ("/Users/x/proj/src/test_Foo.sol", True),
    ("/Users/x/proj/src/mock_Token.sol", True),
    # --- mock camelCase was NOT matched by the old regex; stays faithful ---
    ("/Users/x/proj/src/MockToken.sol", False),
    ("/Users/x/proj/src/TokenMock.sol", False),
    # --- production basenames that merely CONTAIN test/mock ---
    ("/Users/x/proj/src/Contest.sol", False),
    ("/Users/x/proj/src/Testament.sol", False),
    ("/Users/x/proj/src/mockingbird.sol", False),
    ("/Users/x/proj/src/Bank.sol", False),
    # --- windows backslash normalization ---
    (r"C:\proj\test\Bank.sol", True),
    (r"C:\proj\src\Bank.sol", False),
    # --- non-.sol basename / directory paths / empty ---
    ("/Users/x/proj", False),
    ("/Users/x/proj/src", False),
    ("", False),
]


@pytest.mark.parametrize("path,expected", CASES)
def test_is_test_or_mock_path(path, expected):
    assert _is_test_or_mock_path(path) is expected


def test_production_under_test_named_dir_is_not_suppressed():
    """The headline regression: a real contract under `test_projects/` stays."""
    assert _is_test_or_mock_path("/x/test_projects/src/RealVault.sol") is False


def test_contest_is_not_a_test_file():
    """`Contest.sol` (…con+test, no word boundary) is production, not a test —
    the old `Test\\.sol$` + IGNORECASE regex wrongly suppressed it."""
    assert _is_test_or_mock_path("/x/proj/src/Contest.sol") is False
    assert _is_test_or_mock_path("/x/proj/src/FooTest.sol") is True


def test_documented_fixture_demo_path_stays_reportable():
    """`examples/README.md`, `docs/evidence/*` and the DPG-compliance docs tell
    users to run `miesc scan tests/fixtures/reentrancy.sol`. `scan` runs the
    intelligence suppression path, so that file must NOT be treated as test/mock
    or the documented demo would return an empty result."""
    assert _is_test_or_mock_path("tests/fixtures/reentrancy.sol") is False
    assert _is_test_or_mock_path("tests/fixtures/access_control.sol") is False
