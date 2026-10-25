"""audit deep on a directory: every .sol file runs the single-file pipeline, the reports
are merged without the findings each importing file repeats, and the report lists what
each contract inherits and which function of another contract it calls."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig
from miesc.ml import MLPipeline
from miesc.ml.protocol_graph import build_protocol_graph, cross_contract_calls

BASE = """pragma solidity ^0.8.20;

contract Base {
    address public owner;

    function sweep() external {}
}
"""

VAULT = """pragma solidity ^0.8.20;

import "./Base.sol";

contract Vault is Base {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"""

CONTROLLER = """pragma solidity ^0.8.20;

import "./Vault.sol";

// contract Fake { } in a comment is not a contract
contract Controller {
    function pull(address v, uint256 amount) external {
        Vault vault = Vault(v);
        vault.withdraw(amount);
        Vault(v).withdraw(amount);
        Vault(v).sweep();
    }
}
"""

HIGH = {"id": "v1", "type": "reentrancy", "severity": "High"}


def _protocol(tmp_path):
    (tmp_path / "Base.sol").write_text(BASE)
    (tmp_path / "Vault.sol").write_text(VAULT)
    (tmp_path / "Controller.sol").write_text(CONTROLLER)
    return tmp_path


def _graph(root, *names):
    return build_protocol_graph([str(root / name) for name in names])


def test_graph_records_which_functions_each_contract_calls(tmp_path):
    graph = _graph(_protocol(tmp_path), "Base.sol", "Vault.sol", "Controller.sol")

    assert set(graph.contracts) == {"Base", "Vault", "Controller"}  # not the commented one
    assert graph.contracts["Vault"]["bases"] == ["Base"]
    assert cross_contract_calls(graph) == [
        {"caller": "Controller", "callee": "Vault", "functions": ["sweep", "withdraw"]}
    ]


def test_interface_call_resolves_to_the_concrete_contract(tmp_path):
    (tmp_path / "Vault.sol").write_text(VAULT)
    (tmp_path / "Router.sol").write_text(
        "contract Router { function f(address v) external { IVault(v).withdraw(1); } }"
    )
    graph = _graph(tmp_path, "Vault.sol", "Router.sol")
    assert graph.calls == {("Router", "Vault"): {"withdraw"}}


def test_state_variables_and_parameters_typed_as_a_contract_count(tmp_path):
    (tmp_path / "Vault.sol").write_text(VAULT)
    (tmp_path / "Router.sol").write_text("""contract Router {
    IVault public immutable vault;
    uint256 total;
    function f(Vault other, uint256 x) external {
        vault.withdraw(x);
        other.deposit();
        total.max(x);
    }
}""")
    graph = _graph(tmp_path, "Vault.sol", "Router.sol")
    assert graph.calls == {("Router", "Vault"): {"withdraw", "deposit"}}


def _fake_files(reports):
    """Patch the single-file pipeline; the directory path still runs for real."""
    real = DeepAuditAgent.analyze

    def analyze(self, contract_path, **kwargs):
        if Path(contract_path).is_dir():
            return real(self, contract_path, **kwargs)
        return reports(contract_path)

    return patch.object(DeepAuditAgent, "analyze", analyze)


def test_directory_merges_the_file_reports(tmp_path):
    root = _protocol(tmp_path)

    def reports(path):
        if path.endswith("Vault.sol"):
            # No summary: a file that times out before synthesis still counts.
            return {"findings": [HIGH]}
        return {"findings": [], "summary": {"tools_used": ["slither"]}}

    with _fake_files(reports):
        result = DeepAuditAgent(DeepAuditConfig(timeout_seconds=60)).analyze(str(root))

    assert result["metadata"]["files_analyzed"] == 3
    assert result["findings"] == [HIGH]
    assert result["summary"]["HIGH"] == 1 and result["summary"]["total"] == 1
    assert result["summary"]["tools_used"] == ["slither"]
    assert result["protocol"]["calls"][0]["callee"] == "Vault"
    assert result["protocol"]["contracts"]["Vault"]["bases"] == ["Base"]


def test_a_finding_reported_by_every_file_that_imports_it_counts_once(tmp_path):
    root = _protocol(tmp_path)
    in_base = {
        "tool": "slither",
        "type": "missing-zero-check",
        "severity": "Low",
        "location": {"file": "Base.sol", "line": 4},
    }
    other_line = {**in_base, "location": {"file": "Base.sol", "line": 6}}

    chain = {"id": "CHAIN-1", "vulnerabilities": ["a", "b"]}

    def reports(path):
        return {"findings": [dict(in_base), dict(other_line)], "exploit_chains": [dict(chain)]}

    with _fake_files(reports):
        result = DeepAuditAgent(DeepAuditConfig(timeout_seconds=60)).analyze(str(root))

    assert result["findings"] == [in_base, other_line]
    assert result["summary"]["total"] == 2
    assert result["exploit_chains"] == [chain] and result["summary"]["exploit_chains"] == 1


def test_pattern_findings_name_the_analyzed_file():
    source = "contract C {\n  function f() public { selfdestruct(payable(msg.sender)); }\n}"
    findings = MLPipeline()._detect_classic_patterns(source, "src/C.sol")
    assert findings and {f["location"]["file"] for f in findings} == {"src/C.sol"}


def test_dependencies_tests_and_build_output_are_skipped(tmp_path):
    root = _protocol(tmp_path)
    for sub in ("lib/forge-std/src", "node_modules/@oz", "test", "script", "out"):
        (root / sub).mkdir(parents=True)
        (root / sub / "Extra.sol").write_text("contract Extra {}")
    (root / "build" / "Vault.sol").mkdir(parents=True)  # a directory named like a source
    seen = []

    with _fake_files(lambda p: seen.append(Path(p).name) or {"findings": []}):
        DeepAuditAgent(DeepAuditConfig(timeout_seconds=60)).analyze(str(root))

    assert sorted(seen) == ["Base.sol", "Controller.sol", "Vault.sol"]


def test_timeout_is_the_budget_for_the_whole_directory(tmp_path):
    root = _protocol(tmp_path)
    with _fake_files(lambda p: {"findings": []}):
        result = DeepAuditAgent(DeepAuditConfig(timeout_seconds=0)).analyze(str(root))

    assert result["metadata"]["files_analyzed"] == 0
    assert result["metadata"]["timed_out"] is True


@patch("miesc.agents.deep_audit_agent.DeepAuditAgent._get_ml_orchestrator")
def test_directory_runs_the_real_single_file_pipeline(mock_orch, tmp_path):
    root = _protocol(tmp_path)
    mock_orch.return_value.analyze.return_value = MagicMock(
        raw_findings=[], ml_filtered_findings=[], tools_success=["slither"]
    )
    config = DeepAuditConfig(timeout_seconds=60, enable_llm=False, enable_rag=False)

    result = DeepAuditAgent(config).analyze(str(root))

    assert [Path(r["contract"]).name for r in result["files"]] == [
        "Base.sol",
        "Controller.sol",
        "Vault.sol",
    ]
    assert all("phases" in r for r in result["files"])


def test_cli_prints_the_protocol_line(tmp_path):
    from miesc.cli.commands.audit import audit

    root = _protocol(tmp_path)
    with _fake_files(lambda p: {"findings": []}):
        out = CliRunner().invoke(audit, ["deep", str(root), "--no-llm"]).output

    assert "Protocol: 3/3 files, 3 contracts, 1 cross-contract calls" in out
    assert "Controller -> Vault: sweep, withdraw" in out


def test_location_less_findings_from_different_files_are_not_collapsed(tmp_path):
    """A finding with no resolvable location (enriched/LLM-normalized to location {}) must not
    collapse to one row per (tool, type) across every file — that is a recall loss, not dedupe."""
    (tmp_path / "A.sol").write_text("pragma solidity ^0.8.20;\ncontract A {}")
    (tmp_path / "B.sol").write_text("pragma solidity ^0.8.20;\ncontract B {}")

    def reports(path):
        name = Path(path).stem
        # same tool+type, empty location, distinct ids: two real findings, one per file.
        return {
            "findings": [
                {"id": f"{name}-1", "tool": "llm", "type": "reentrancy", "severity": "High"}
            ]
        }

    with _fake_files(reports):
        result = DeepAuditAgent(DeepAuditConfig(timeout_seconds=60)).analyze(str(tmp_path))

    assert len(result["findings"]) == 2
    assert result["summary"]["HIGH"] == 2


def test_location_less_findings_without_id_are_kept_each(tmp_path):
    (tmp_path / "A.sol").write_text("pragma solidity ^0.8.20;\ncontract A {}")
    (tmp_path / "B.sol").write_text("pragma solidity ^0.8.20;\ncontract B {}")

    def reports(path):
        return {"findings": [{"tool": "llm", "type": "reentrancy", "severity": "Low"}]}

    with _fake_files(reports):
        result = DeepAuditAgent(DeepAuditConfig(timeout_seconds=60)).analyze(str(tmp_path))
    assert len(result["findings"]) == 2  # no id, no location -> never silently merged


def test_one_failing_file_does_not_abort_the_whole_directory(tmp_path):
    """A file that raises during analyze is recorded and skipped; the other reports survive and
    the failure is counted in metadata."""
    for n in ("A", "B", "C"):
        (tmp_path / f"{n}.sol").write_text(f"pragma solidity ^0.8.20;\ncontract {n} {{}}")

    def reports(path):
        if Path(path).stem == "B":
            raise UnicodeDecodeError("utf-8", b"", 0, 1, "boom")
        return {
            "findings": [
                {
                    "id": Path(path).stem,
                    "tool": "slither",
                    "type": "x",
                    "severity": "Low",
                    "location": {"file": Path(path).name, "line": 1},
                }
            ]
        }

    with _fake_files(reports):
        result = DeepAuditAgent(DeepAuditConfig(timeout_seconds=60)).analyze(str(tmp_path))

    assert result["metadata"]["files_analyzed"] == 3
    assert result["metadata"]["files_failed"] == 1
    assert len(result["findings"]) == 2  # A and C survived
    errored = [r for r in result["files"] if r.get("error")]
    assert len(errored) == 1 and errored[0]["contract"].endswith("B.sol")
