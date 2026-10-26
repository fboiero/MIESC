"""Peculiar's function extraction does not backtrack catastrophically.

The old pattern backtracked exponentially on a modifier with nested parentheses and on
declarations ending in `;`, and it holds the GIL while it does, so no thread-based
timeout can interrupt it: OZ's AccountERC7579 ran for over 15 minutes. The check runs
in a subprocess so a regression fails on the timeout instead of hanging the suite.
"""

import json
import subprocess
import sys
from pathlib import Path

# From OpenZeppelin's draft-AccountERC7579.sol, plus an interface declaration.
SOURCE = """
interface IExec {
    function executeFromExecutor(bytes32 mode, bytes calldata data) external payable virtual returns (bytes[] memory);
}
contract Account {
    function executeFromExecutor(
        bytes32 mode,
        bytes calldata executionCalldata
    )
        public
        payable
        virtual
        onlyModule(MODULE_TYPE_EXECUTOR, Calldata.emptyBytes())
        returns (bytes[] memory returnData)
    {
        return _execute(Mode.wrap(mode), executionCalldata);
    }

    function grantRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    function owner() public view returns (address) { return _owner; }
}
"""


def _extract(source: str) -> dict:
    script = (
        "import json, sys, time; from miesc.adapters.peculiar_adapter import PeculiarAdapter;"
        "t = time.perf_counter(); fs = PeculiarAdapter()._extract_functions(sys.stdin.read());"
        "print(json.dumps({'seconds': time.perf_counter() - t, 'functions': {f['name']: f for f in fs}}))"
    )
    run = subprocess.run(
        [sys.executable, "-c", script],
        input=source,
        text=True,
        timeout=30,
        capture_output=True,
        cwd=Path(__file__).parents[1],
    )
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


def test_signature_without_body_does_not_backtrack():
    # The match fails on `;`; the old pattern took over 60 s on 16 qualifiers.
    source = "interface I {\n    function f(uint a) external " + " ".join(["view"] * 40) + ";\n}\n"

    assert _extract(source)["seconds"] < 1


def test_nested_parentheses_and_interfaces_are_extracted():
    functions = _extract(SOURCE)["functions"]

    assert set(functions) == {"executeFromExecutor", "grantRole", "owner"}
    execute = functions["executeFromExecutor"]
    assert execute["visibility"] == "public" and execute["is_payable"]
    assert "onlyModule" in execute["modifiers"]
    assert "returnData" not in execute["modifiers"]  # the returns clause is not a modifier
    assert execute["body"].strip().startswith("return _execute")
    assert "onlyRole" in functions["grantRole"]["modifiers"]
    assert functions["owner"]["modifiers"] == []
