"""Offline unit tests for RepoCallGraph (whole-repo call graph wrapper).

No network, no API. Exercises repo_map, function_body, and cross-contract
callers/callees on small inline Solidity fixtures.
"""

import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from src.agents.repo_call_graph import RepoCallGraph

TOKEN_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) public returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }
}
"""

BANK_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Token.sol";

contract Bank {
    Token public token;
    mapping(address => uint256) public deposits;

    function deposit(uint256 amount) public {
        deposits[msg.sender] += amount;
        _record(amount);
    }

    function withdraw(uint256 amount) external {
        deposits[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    function _record(uint256 amount) internal {
        deposits[address(this)] += amount;
    }
}
"""


@pytest.fixture()
def repo() -> Iterator[RepoCallGraph]:
    # NOTE: a neutral temp dir is required — pytest's tmp_path contains the test
    # name ("test_..."), which the _SKIP_PATH "/test" rule would skip entirely.
    root = Path(tempfile.mkdtemp(prefix="miesc_rcg_"))
    try:
        src = root / "src"
        src.mkdir()
        (src / "Token.sol").write_text(TOKEN_SOL)
        (src / "Bank.sol").write_text(BANK_SOL)
        # A test file that MUST be skipped by the scope/skip rules.
        tests = root / "tests"
        tests.mkdir()
        (tests / "BankTest.sol").write_text(
            "contract BankTest { function noop() public {} }"
        )
        yield RepoCallGraph.build(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_repo_map_lists_every_public_external_fn(repo: RepoCallGraph) -> None:
    rmap = repo.repo_map()
    # Every public/external function is present...
    for fn in ("transfer", "mint", "deposit", "withdraw"):
        assert fn in rmap, f"repo_map missing {fn}\n{rmap}"
    # ...internal helpers are NOT listed as entry points.
    assert "_record" not in rmap
    # Skipped test file must not appear.
    assert "BankTest" not in rmap
    # Both contracts appear.
    assert "contract Token" in rmap
    assert "contract Bank" in rmap


def test_function_body_returns_exact_source(repo: RepoCallGraph) -> None:
    body = repo.function_body("Bank", "withdraw")
    assert body is not None
    assert body.startswith("function withdraw(uint256 amount) external")
    assert "token.transfer(msg.sender, amount);" in body
    assert body.rstrip().endswith("}")
    # Substring of the original source (exact extraction, no reconstruction).
    assert body in BANK_SOL

    assert repo.function_body("Bank", "doesNotExist") is None
    assert repo.function_body("NoSuchContract", "withdraw") is None


def test_cross_contract_callers_and_callees(repo: RepoCallGraph) -> None:
    # Bank.withdraw calls Token.transfer (cross-contract).
    assert "Token.transfer" in repo.callees_of("Bank", "withdraw")
    assert "Bank.withdraw" in repo.callers_of("Token", "transfer")

    # Same-contract internal call resolves too.
    assert "Bank._record" in repo.callees_of("Bank", "deposit")

    # No spurious edge from a global receiver like msg.sender.
    assert "Bank.sender" not in repo.callees_of("Bank", "deposit")


def test_paths_to_reaches_sink_from_entry_point(repo: RepoCallGraph) -> None:
    paths = repo.paths_to("Token", "transfer")
    assert all(p[-1] == "Token.transfer" for p in paths)
    # The cross-contract path Bank.withdraw -> Token.transfer must appear.
    assert ["Bank.withdraw", "Token.transfer"] in paths


def test_contract_source_returns_full_block(repo: RepoCallGraph) -> None:
    source = repo.contract_source("Bank")
    assert source is not None
    assert "contract Bank" in source
    # The full body is present, not just the header.
    assert "token.transfer(msg.sender, amount);" in source
    assert source in BANK_SOL

    # Unknown contract → None.
    assert repo.contract_source("NoSuchContract") is None


def test_contract_file_returns_existing_sol_path(repo: RepoCallGraph) -> None:
    path = repo.contract_file("Token")
    assert path is not None
    assert path.exists()
    assert path.suffix == ".sol"
    assert path.name == "Token.sol"

    # Unknown contract → None.
    assert repo.contract_file("NoSuchContract") is None


def test_repo_dir_is_built_root() -> None:
    root = Path(tempfile.mkdtemp(prefix="miesc_rcg_"))
    try:
        src = root / "src"
        src.mkdir()
        (src / "Token.sol").write_text(TOKEN_SOL)
        graph = RepoCallGraph.build(root)
        assert graph.repo_dir() == root
    finally:
        shutil.rmtree(root, ignore_errors=True)
