"""
Tests for MEJORAS.md item #5: contract-segmented call graphs and the
cross-file protocol graph (inheritance, cross-contract calls, storage-risk
heuristic).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

from pathlib import Path

import pytest

from miesc.agents.xray_agent import run_xray
from miesc.ml.call_graph import CallGraphBuilder
from miesc.ml.protocol_graph import (
    build_protocol_graph,
    find_cross_contract_chains,
    resolve_finding_contract,
)

TWO_CONTRACTS_SAME_FUNCTION_NAME = """
pragma solidity ^0.8.0;
contract A {
    function _transfer() internal {}
    function foo() external {}
}
contract B is A {
    function _transfer() internal {}
    function bar() external {}
}
"""

BASE_UPGRADEABLE_NO_GAP = """
pragma solidity ^0.8.0;
contract Base is Initializable {
    uint256 public x;
    function initialize() public {}
}
"""

BASE_UPGRADEABLE_WITH_GAP = """
pragma solidity ^0.8.0;
contract SafeBase is Initializable {
    uint256 public x;
    uint256[50] private __gap;
    function initialize() public {}
}
"""

DERIVED = """
pragma solidity ^0.8.0;
import "./Base.sol";
contract Derived is Base {
    function foo() external {}
}
"""

ROUTER = """
pragma solidity ^0.8.0;
import "./Derived.sol";
interface IDerived {
    function foo() external;
}
contract Router {
    function callDerived(address x) external {
        IDerived(x).foo();
    }
}
"""


class TestContractSegmentation:
    def test_same_named_functions_in_different_contracts_dont_collide(self):
        graph = CallGraphBuilder().build_from_source(TWO_CONTRACTS_SAME_FUNCTION_NAME)

        assert set(graph.contracts) == {"A", "B"}
        assert graph.inheritance == {"A": [], "B": ["A"]}
        assert set(graph.nodes_by_contract["A"].keys()) == {"_transfer", "foo"}
        assert set(graph.nodes_by_contract["B"].keys()) == {"_transfer", "bar"}
        assert graph.nodes_by_contract["A"]["_transfer"].contract == "A"
        assert graph.nodes_by_contract["B"]["_transfer"].contract == "B"

    def test_flat_nodes_and_entry_points_unchanged_for_existing_callers(self):
        # Regression guard: existing single-contract-per-file callers (deep_audit_agent,
        # xray_agent) must see identical behavior to before this change.
        graph = CallGraphBuilder().build_from_source(
            "pragma solidity ^0.8.0;\ncontract C { function pub() external {} }"
        )
        assert list(graph.nodes.keys()) == ["pub"]
        assert [f.name for f in graph.get_entry_points()] == ["pub"]


def _write_fixture(tmp_path: Path) -> list[str]:
    (tmp_path / "Base.sol").write_text(BASE_UPGRADEABLE_NO_GAP)
    (tmp_path / "Derived.sol").write_text(DERIVED)
    (tmp_path / "Router.sol").write_text(ROUTER)
    return sorted(str(p) for p in tmp_path.glob("*.sol"))


class TestBuildProtocolGraph:
    def test_cross_file_inheritance_and_call_edges(self, tmp_path):
        paths = _write_fixture(tmp_path)
        graph = build_protocol_graph(paths)

        assert set(graph.contracts.keys()) == {"Base", "Derived", "Router"}
        assert ("Derived", "Base") in graph.inheritance_edges
        assert ("Router", "Derived") in graph.call_edges

    # MEJORAS2.md backlog (Cross-Contract Reasoning vs. real protocols):
    # found while testing against a real audit (Y2K Finance) — the synthetic
    # fixture above only ever exercised the "I"-prefixed inline-call form.
    def test_concrete_type_inline_call_no_i_prefix(self, tmp_path):
        (tmp_path / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Vault { function foo() external {} }\n"
        )
        (tmp_path / "Controller.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Controller {\n"
            "    function bar(address a) external { Vault(a).foo(); }\n"
            "}\n"
        )
        graph = build_protocol_graph(
            [str(tmp_path / "Vault.sol"), str(tmp_path / "Controller.sol")]
        )
        assert ("Controller", "Vault") in graph.call_edges

    def test_typed_local_variable_cast_then_call(self, tmp_path):
        # `Vault vault = Vault(vaultAddress); ... vault.foo();` — cast to a
        # local variable, called on a later line. Real pattern confirmed on
        # Y2K Finance's Controller.sol (6 real audit findings involve
        # exactly this Controller->Vault relationship).
        (tmp_path / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Vault { function foo() external {} }\n"
        )
        (tmp_path / "Controller.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Controller {\n"
            "    function bar(address a) external {\n"
            "        Vault vault = Vault(a);\n"
            "        vault.foo();\n"
            "    }\n"
            "}\n"
        )
        graph = build_protocol_graph(
            [str(tmp_path / "Vault.sol"), str(tmp_path / "Controller.sol")]
        )
        assert ("Controller", "Vault") in graph.call_edges

    def test_typed_local_call_does_not_confuse_unrelated_variable_calls(self, tmp_path):
        # A call on a variable never assigned via a typed cast must not
        # produce a spurious edge just because some OTHER known contract
        # name exists in the file set.
        (tmp_path / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Vault { function foo() external {} }\n"
        )
        (tmp_path / "Controller.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Controller {\n"
            "    function bar(SomeToken token) external { token.transfer(msg.sender, 1); }\n"
            "}\n"
        )
        graph = build_protocol_graph(
            [str(tmp_path / "Vault.sol"), str(tmp_path / "Controller.sol")]
        )
        assert graph.call_edges == []

    def test_unresolved_package_import_does_not_crash(self, tmp_path):
        (tmp_path / "Token.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            'import "@openzeppelin/contracts/token/ERC20/ERC20.sol";\n'
            "contract Token {}\n"
        )
        graph = build_protocol_graph([str(tmp_path / "Token.sol")])
        assert "@openzeppelin/contracts/token/ERC20/ERC20.sol" in graph.unresolved_imports

    def test_storage_risk_flagged_when_base_upgradeable_without_gap(self, tmp_path):
        paths = _write_fixture(tmp_path)
        graph = build_protocol_graph(paths)

        assert len(graph.storage_risk) == 1
        assert graph.storage_risk[0]["derived"] == "Derived"
        assert graph.storage_risk[0]["base"] == "Base"

    def test_no_storage_risk_when_base_has_gap(self, tmp_path):
        (tmp_path / "SafeBase.sol").write_text(BASE_UPGRADEABLE_WITH_GAP)
        (tmp_path / "SafeDerived.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            'import "./SafeBase.sol";\n'
            "contract SafeDerived is SafeBase {}\n"
        )
        graph = build_protocol_graph(
            [str(tmp_path / "SafeBase.sol"), str(tmp_path / "SafeDerived.sol")]
        )
        assert graph.storage_risk == []


class TestRunXrayProtocolIntegration:
    def test_single_file_omits_protocol_key(self, tmp_path):
        (tmp_path / "Solo.sol").write_text(BASE_UPGRADEABLE_NO_GAP)
        report = run_xray([str(tmp_path / "Solo.sol")])
        assert "protocol" not in report

    def test_multi_file_includes_protocol_key_without_source_leakage(self, tmp_path):
        paths = _write_fixture(tmp_path)
        report = run_xray(paths)

        assert "protocol" in report
        protocol = report["protocol"]
        assert ("Derived", "Base") in [tuple(e) for e in protocol["inheritance_edges"]]
        assert protocol["storage_risk"]
        for info in protocol["contracts"].values():
            assert "source" not in info


class TestResolveFindingContract:
    def test_resolves_finding_to_correct_contract(self, tmp_path):
        paths = _write_fixture(tmp_path)
        graph = build_protocol_graph(paths)
        finding = {
            "id": "f1",
            "location": {"file": str(tmp_path / "Derived.sol"), "line": 4},
        }
        assert resolve_finding_contract(finding, graph) == "Derived"

    def test_file_not_in_protocol_returns_none(self, tmp_path):
        paths = _write_fixture(tmp_path)
        graph = build_protocol_graph(paths)
        finding = {"id": "f1", "location": {"file": "/nowhere/Other.sol", "line": 5}}
        assert resolve_finding_contract(finding, graph) is None

    def test_missing_location_returns_none_not_a_crash(self, tmp_path):
        paths = _write_fixture(tmp_path)
        graph = build_protocol_graph(paths)
        assert resolve_finding_contract({"id": "f1"}, graph) is None
        assert resolve_finding_contract({"id": "f2", "location": {}}, graph) is None


class TestFindCrossContractChains:
    def test_risky_finding_in_callee_produces_chain(self, tmp_path):
        paths = _write_fixture(tmp_path)
        graph = build_protocol_graph(paths)
        finding = {
            "id": "f1",
            "type": "access_control",
            "message": "missing access control on foo",
            "location": {"file": str(tmp_path / "Derived.sol"), "line": 4},
        }
        chains = find_cross_contract_chains({"Derived": [finding]}, graph)
        assert len(chains) == 1
        assert chains[0]["contracts"] == ["Router", "Derived"]
        assert chains[0]["callee_finding_id"] == "f1"

    def test_finding_without_risk_keyword_produces_no_chain(self, tmp_path):
        paths = _write_fixture(tmp_path)
        graph = build_protocol_graph(paths)
        finding = {"id": "f1", "type": "style", "message": "naming convention violation"}
        chains = find_cross_contract_chains({"Derived": [finding]}, graph)
        assert chains == []

    # MEJORAS2.md backlog follow-up (PR #32's own "found, not fixed" list):
    # the old 6-keyword text scan missed denial_of_service/bad_randomness/
    # time_manipulation entirely despite them being real CanonicalCategory
    # values — confirmed on Y2K Finance's real findings. Now goes through
    # finding_taxonomy's shared vocabulary instead of a 4th ad-hoc list.
    @pytest.mark.parametrize(
        "finding_type",
        ["dos", "weak-randomness", "timestamp", "unchecked-lowlevel"],
    )
    def test_previously_uncovered_canonical_categories_now_produce_chains(
        self, tmp_path, finding_type
    ):
        paths = _write_fixture(tmp_path)
        graph = build_protocol_graph(paths)
        finding = {"id": "f1", "type": finding_type}
        chains = find_cross_contract_chains({"Derived": [finding]}, graph)
        assert len(chains) == 1

    def test_modern_category_not_in_canonical_taxonomy_still_matches_via_fallback(self, tmp_path):
        # business_logic/rounding/fee_on_transfer/erc4626 (evaluate.py's
        # MODERN_CATEGORIES) have no CanonicalCategory equivalent at all —
        # kept covered via a small explicit text fallback instead of
        # silently dropping them again.
        paths = _write_fixture(tmp_path)
        graph = build_protocol_graph(paths)
        finding = {
            "id": "f1",
            "type": "unknown",
            "title": "Users lose all deposits due to a business logic flaw",
        }
        chains = find_cross_contract_chains({"Derived": [finding]}, graph)
        assert len(chains) == 1
        assert chains[0]["category"] == "business_logic"

    def test_no_call_edge_produces_no_chain(self, tmp_path):
        graph = build_protocol_graph(_write_fixture(tmp_path))
        finding = {
            "id": "f1",
            "type": "reentrancy",
            "location": {"file": str(tmp_path / "Base.sol"), "line": 3},
        }
        # Base has no caller in this fixture's call_edges (only Router -> Derived).
        chains = find_cross_contract_chains({"Base": [finding]}, graph)
        assert chains == []
