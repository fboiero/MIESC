"""
Tests for the PolkaVM / pallet-revive difference-with-EVM support (F5).

Covers:
- PolkaVMDiffAdapter metadata / availability / can_analyze
- each class-(B) check firing on its fixture, and the clean contract firing none
- the comment/string-aware engine NOT false-positiving on comment mentions
- gas-cap and literal-size suppression (true-negative guards)
- honest error contract (missing file -> status "error", never success-with-0)
- ground-truth consistency with expected_findings.json
- adapter registration (ADAPTER_MAP / POLKAVM_TOOLS) and AdapterLoader resolution
- CLI routing: --target polkavm routes to polkavm_diff and skips EVM-bytecode
  tools; without the flag the EVM path does not pull in polkavm_diff
- PolkaVM findings export to valid SARIF 2.1.0

No external binary (resolc) is needed: the fixtures are committed and the adapter
is a built-in source-level analyzer.
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from miesc.adapters.polkavm_diff_adapter import (
    PolkaVMDiffAdapter,
    blank_comments_and_strings,
)
from miesc.core.tool_protocol import ToolStatus

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "examples" / "contracts" / "polkadot" / "polkavm_poc"


def _adapter() -> PolkaVMDiffAdapter:
    return PolkaVMDiffAdapter()


def _types(result: dict) -> list:
    return [f["type"] for f in result["findings"]]


# --------------------------------------------------------------------------- #
# metadata / availability
# --------------------------------------------------------------------------- #
def test_is_available():
    assert _adapter().is_available() == ToolStatus.AVAILABLE


def test_metadata():
    meta = _adapter().get_metadata()
    assert meta.name == "polkavm_diff"
    assert meta.license == "AGPL-3.0"
    assert "solidity" in meta.capabilities[0].supported_languages
    # seven class-(B) checks
    assert len(meta.capabilities[0].detection_types) == 7


def test_can_analyze():
    a = _adapter()
    assert a.can_analyze("Foo.sol") is True
    assert a.can_analyze("foo.rs") is False
    assert a.can_analyze("foo.cairo") is False


# --------------------------------------------------------------------------- #
# each fixture fires its expected check; clean fires none
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "fixture,expected_check",
    [
        ("vulnerable/UnlimitedGasCall.sol", "polkavm-unlimited-gas-call"),
        ("vulnerable/UnboundedMemory.sol", "polkavm-unbounded-memory"),
        ("vulnerable/Create2Address.sol", "polkavm-create2-address-assumption"),
        ("vulnerable/PredictableRandomness.sol", "polkavm-predictable-prevrandao"),
        ("vulnerable/ConstructorOrder.sol", "polkavm-constructor-init-order"),
        ("vulnerable/SelfDestructUse.sol", "polkavm-selfdestruct-semantics"),
        ("vulnerable/AsmManualDeploy.sol", "polkavm-asm-manual-deploy"),
    ],
)
def test_fixture_fires_expected_check(fixture, expected_check):
    result = _adapter().analyze(str(FIXTURES / fixture))
    assert result["status"] == "success"
    assert expected_check in _types(result)


def test_clean_contract_has_no_findings():
    result = _adapter().analyze(str(FIXTURES / "clean" / "Counter.sol"))
    assert result["status"] == "success"
    assert result["findings"] == []


# --------------------------------------------------------------------------- #
# comment/string guard — the explanatory comments must not false-positive
# --------------------------------------------------------------------------- #
def test_comment_mention_does_not_fire():
    src = (
        "pragma solidity ^0.8.0;\n"
        "contract C {\n"
        "  // selfdestruct(owner) and block.prevrandao are risky; .call(data) too\n"
        '  string note = "selfdestruct block.prevrandao .call";\n'
        "  function f() external {}\n"
        "}\n"
    )
    assert _adapter().normalize_findings(src) == []


def test_blank_preserves_line_count():
    src = "a\n// comment\n/* block\nspanning */\nb\n"
    blanked = blank_comments_and_strings(src)
    assert blanked.count("\n") == src.count("\n")
    assert "comment" not in blanked and "spanning" not in blanked


# --------------------------------------------------------------------------- #
# true-negative guards
# --------------------------------------------------------------------------- #
def test_gas_capped_call_not_flagged():
    src = (
        "pragma solidity ^0.8.0;\n"
        "contract C {\n"
        "  function f(address t, bytes calldata d) external {\n"
        "    (bool ok, ) = t.call{gas: 5000}(d); ok;\n"
        "  }\n"
        "}\n"
    )
    assert "polkavm-unlimited-gas-call" not in [
        f["type"] for f in _adapter().normalize_findings(src)
    ]


def test_asm_manual_deploy_fires_only_inside_assembly():
    # A function NAMED create and a Solidity-level call to it (outside any
    # assembly block) must NOT fire polkavm-asm-manual-deploy; only the Yul
    # create/create2 builtin inside an assembly block does.
    src = (
        "pragma solidity ^0.8.0;\n"
        "contract Factory {\n"
        "  function create(uint256 n) public returns (uint256) { return n; }\n"
        "  function run() external returns (uint256) { return create(1); }\n"
        "}\n"
    )
    assert "polkavm-asm-manual-deploy" not in [
        f["type"] for f in _adapter().normalize_findings(src)
    ]


def test_asm_manual_deploy_memory_safe_form_fires():
    # OZ v5 Clones uses `assembly ("memory-safe") { ... }`; the blanker blanks the
    # quoted flag, so the opener regex must still match.
    src = (
        "pragma solidity ^0.8.0;\n"
        "contract C {\n"
        "  function clone(address impl) external returns (address inst) {\n"
        '    assembly ("memory-safe") {\n'
        "      let ptr := mload(0x40)\n"
        "      inst := create(0, ptr, 0x37)\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    assert "polkavm-asm-manual-deploy" in [f["type"] for f in _adapter().normalize_findings(src)]


def test_asm_manual_deploy_skips_creationcode_form():
    # The UniswapV2 / OZ Create2.deploy idiom feeds type(T).creationCode into an
    # assembly create2. That is the Solidity-level form already reported by
    # polkavm-create2-address-assumption, so asm-manual-deploy must NOT also fire
    # (no double-report), and the "hand-built initcode" message does not apply.
    src = (
        "pragma solidity ^0.8.0;\n"
        "contract Factory {\n"
        "  function deploy(bytes32 salt) external returns (address pair) {\n"
        "    bytes memory bytecode = type(Factory).creationCode;\n"
        "    assembly { pair := create2(0, add(bytecode, 32), mload(bytecode), salt) }\n"
        "  }\n"
        "}\n"
    )
    types = [f["type"] for f in _adapter().normalize_findings(src)]
    assert "polkavm-asm-manual-deploy" not in types
    assert "polkavm-create2-address-assumption" in types


def test_asm_manual_deploy_fires_on_assembly_create():
    src = (
        "pragma solidity ^0.8.0;\n"
        "contract C {\n"
        "  function clone(address impl) external returns (address inst) {\n"
        "    assembly {\n"
        "      let ptr := mload(0x40)\n"
        "      inst := create2(0, ptr, 0x37, 0)\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    types = [f["type"] for f in _adapter().normalize_findings(src)]
    assert "polkavm-asm-manual-deploy" in types


def test_literal_sized_memory_not_flagged():
    src = (
        "pragma solidity ^0.8.0;\n"
        "contract C {\n"
        "  function f() external pure returns (bytes memory b) { b = new bytes(32); }\n"
        "}\n"
    )
    assert "polkavm-unbounded-memory" not in [f["type"] for f in _adapter().normalize_findings(src)]


# --------------------------------------------------------------------------- #
# honest error contract
# --------------------------------------------------------------------------- #
def test_missing_file_is_error_not_empty_success():
    result = _adapter().analyze(str(FIXTURES / "does_not_exist.sol"))
    assert result["status"] == "error"
    assert result["error"]
    assert result["findings"] == []


# --------------------------------------------------------------------------- #
# ground-truth consistency
# --------------------------------------------------------------------------- #
def test_matches_expected_findings_json():
    data = json.loads((FIXTURES / "expected_findings.json").read_text())
    adapter = _adapter()
    for entry in data["contracts"]:
        result = adapter.analyze(str(FIXTURES / entry["file"]))
        assert result["status"] == "success"
        produced = sorted(_types(result))
        expected = sorted(e["check"] for e in entry["expected"])
        assert produced == expected, f"{entry['file']}: {produced} != {expected}"


# --------------------------------------------------------------------------- #
# registration
# --------------------------------------------------------------------------- #
def test_registered_in_adapter_map_and_tools():
    from miesc.cli.constants import ADAPTER_MAP, POLKAVM_TOOLS

    assert ADAPTER_MAP.get("polkavm_diff") == "PolkaVMDiffAdapter"
    assert "polkavm_diff" in POLKAVM_TOOLS
    # EVM bytecode/symbolic/fuzzing tools are NOT in the PolkaVM set
    for evm_only in ("mythril", "manticore", "echidna", "medusa"):
        assert evm_only not in POLKAVM_TOOLS


def test_adapter_loader_resolves():
    from miesc.cli.utils import AdapterLoader

    adapter = AdapterLoader.get_adapter("polkavm_diff")
    assert type(adapter).__name__ == "PolkaVMDiffAdapter"


# --------------------------------------------------------------------------- #
# CLI routing (end-to-end, built-in tool only — robust without slither/aderyn)
# --------------------------------------------------------------------------- #
def test_cli_target_polkavm_routes_and_skips_evm(tmp_path):
    from miesc.cli.commands.scan import scan

    out = tmp_path / "pvm.json"
    res = CliRunner().invoke(
        scan,
        [
            str(FIXTURES / "vulnerable" / "UnlimitedGasCall.sol"),
            "--target",
            "polkavm",
            "-o",
            str(out),
            "--quiet",
        ],
    )
    assert res.exit_code == 0, res.output
    data = json.loads(out.read_text())
    assert "polkavm_diff" in data["tools"]
    # the PolkaVM layer fired its check
    assert any(f["type"] == "polkavm-unlimited-gas-call" for f in data["findings"])
    # no EVM bytecode/symbolic tool was routed
    for evm_only in ("mythril", "manticore", "echidna"):
        assert evm_only not in data["tools"]


def test_cli_without_target_does_not_route_polkavm(tmp_path):
    from miesc.cli.commands.scan import scan

    out = tmp_path / "evm.json"
    res = CliRunner().invoke(
        scan,
        [str(FIXTURES / "clean" / "Counter.sol"), "-o", str(out), "--quiet"],
    )
    assert res.exit_code == 0, res.output
    data = json.loads(out.read_text())
    # default EVM path must not pull in the PolkaVM adapter
    assert "polkavm_diff" not in data["tools"]


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 export of PolkaVM findings
# --------------------------------------------------------------------------- #
def test_polkavm_findings_export_valid_sarif():
    from miesc.core.exporters import Finding, SARIFExporter

    result = _adapter().analyze(str(FIXTURES / "vulnerable" / "PredictableRandomness.sol"))
    findings = [
        Finding(
            id=f["id"],
            type=f["type"],
            severity=f["severity"],
            title=f["type"],
            description=f["description"],
            file_path=f["location"]["file"],
            line_start=f["location"]["line"],
            tool=f.get("tool", "polkavm_diff"),
            confidence=f["confidence"],
            cwe=f.get("cwe_id"),
            remediation=f.get("recommendation"),
        )
        for f in result["findings"]
    ]
    sarif = json.loads(SARIFExporter(tool_name="MIESC").export(findings))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(sarif["runs"]) == 1
    results = sarif["runs"][0]["results"]
    assert len(results) == len(findings) and findings  # every finding exported
    rule_ids = {r["ruleId"] for r in results}
    assert any("PREVRANDAO" in rid.upper() for rid in rule_ids)
