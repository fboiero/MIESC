"""
Tests for the PolkaVM / pallet-revive ``resolc`` compile-compatibility adapter.

The adapter shells out to ``resolc`` (the Parity revive compiler) and reports
class (A) compile-time rejections (unsupported opcodes) for the PolkaVM target.
CI has no ``resolc``, so the behavioural tests **mock ``run_subprocess``** with
stderr captured verbatim from a real resolc 1.5.0 run; a handful of live tests
run resolc for real and are skipped when it cannot be resolved on PATH.

Covers:
- metadata / can_analyze / PATH-only availability (never executes resolc)
- exit 0 -> clean (zero findings), even when no artifact is produced (interface)
- class (A) rejection -> one HIGH finding, source-anchored, compiler offset kept
  in metadata, no CWE; ambiguous anchor -> line 0
- any other non-zero exit (solc ParserError, missing solc) -> honest error,
  never a finding and never a false "clean"
- missing file / unavailable tool / timeout -> honest error
- registration (ADAPTER_MAP / POLKAVM_TOOLS) and AdapterLoader resolution
- SARIF 2.1.0 export
- live (skip without resolc): the committed fixtures behave as measured
"""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from miesc.adapters import polkavm_resolc_adapter as mod
from miesc.adapters.polkavm_resolc_adapter import PolkaVMResolcAdapter
from miesc.core.tool_protocol import ToolStatus

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "examples" / "contracts" / "polkadot" / "polkavm_poc"
_EXTCODECOPY_FIXTURE = FIXTURES / "error_cases" / "ExtCodeCopyRejected.sol"


def _opcode_line(path: Path, opcode: str) -> int:
    """1-based line of the (single) non-comment opcode token in a fixture.

    Derived from the file so the test does not hardcode a line that a header edit
    would shift. Uses a word boundary (like the adapter) so the contract name
    ``ExtCodeCopyRejected`` does not count as an ``extcodecopy`` occurrence.
    """
    token_re = re.compile(r"\b" + re.escape(opcode) + r"\b", re.IGNORECASE)
    hits = [
        i
        for i, ln in enumerate(path.read_text().splitlines(), 1)
        if token_re.search(ln) and not ln.lstrip().startswith("//")
    ]
    assert len(hits) == 1, f"expected exactly one {opcode} in {path.name}, got {hits}"
    return hits[0]


# Verbatim resolc 1.5.0 stderr for a class (A) rejection (EXTCODECOPY). The
# `29:25` is a Yul/compiler-internal offset, NOT a Solidity source line.
CLASS_A_STDERR = (
    "Error: LLVM IR generator: 29:25 The `EXTCODECOPY` instruction is not supported\n"
    "--> ExtCodeCopyRejected.sol\n"
)
# Verbatim resolc stderr for a plain solc parse error (NOT a class-A rejection).
PARSE_ERROR_STDERR = (
    "Error: Error: ParserError: Expected type name\n"
    " --> Broken.sol:3:31:\n  |\n3 | contract Broken { function x( external {  }\n"
)


def _adapter() -> PolkaVMResolcAdapter:
    return PolkaVMResolcAdapter()


def _force_available(monkeypatch, adapter) -> None:
    """Pretend a real ``resolc`` is on PATH so analyze() runs its body."""
    monkeypatch.setattr(adapter, "_resolc_base_cmd", lambda: ["resolc"])


def _mock_run(monkeypatch, adapter, rc, stdout="", stderr=""):
    def fake_run(cmd, timeout=180, env=None, cwd=None):
        return (rc, stdout, stderr)

    monkeypatch.setattr(adapter, "run_subprocess", fake_run)


# --------------------------------------------------------------------------- #
# metadata / can_analyze
# --------------------------------------------------------------------------- #
def test_metadata():
    meta = _adapter().get_metadata()
    assert meta.name == "polkavm_resolc"
    assert meta.license == "AGPL-3.0"
    assert "solidity" in meta.capabilities[0].supported_languages
    assert meta.capabilities[0].detection_types == ["polkavm-unsupported-opcode"]
    assert meta.is_optional is True


def test_can_analyze():
    a = _adapter()
    assert a.can_analyze("Foo.sol") is True
    assert a.can_analyze("foo.rs") is False
    assert a.can_analyze("foo.cairo") is False


# --------------------------------------------------------------------------- #
# availability is PATH-only and never executes resolc
# --------------------------------------------------------------------------- #
@pytest.mark.resolc_logic
def test_available_when_resolc_on_path(monkeypatch):
    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/resolc")
    assert _adapter().is_available() == ToolStatus.AVAILABLE


@pytest.mark.resolc_logic
def test_available_on_demand_via_npx(monkeypatch):
    present = {"npx", "node", "solc"}
    monkeypatch.setattr(
        mod.shutil, "which", lambda name: f"/bin/{name}" if name in present else None
    )
    a = _adapter()
    assert a.is_available() == ToolStatus.AVAILABLE
    cmd = a._resolc_base_cmd()
    assert cmd is not None
    assert cmd[:2] == ["npx", "--yes"]


@pytest.mark.resolc_logic
def test_not_installed_without_toolchain(monkeypatch):
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    assert _adapter().is_available() == ToolStatus.NOT_INSTALLED


@pytest.mark.resolc_logic
def test_is_available_does_not_execute(monkeypatch):
    # Probing availability must never shell out (npx would hit the network).
    a = _adapter()

    def boom(*args, **kwargs):  # pragma: no cover - must not be called
        raise AssertionError("is_available executed a subprocess")

    monkeypatch.setattr(a, "run_subprocess", boom)
    monkeypatch.setattr(mod.shutil, "which", lambda name: "/bin/x")
    a.is_available()  # no raise


# --------------------------------------------------------------------------- #
# exit 0 -> clean
# --------------------------------------------------------------------------- #
def test_exit_zero_is_clean(monkeypatch, tmp_path):
    f = tmp_path / "C.sol"
    f.write_text("pragma solidity ^0.8.0; contract C {}")
    a = _adapter()
    _force_available(monkeypatch, a)
    _mock_run(monkeypatch, a, rc=0)
    result = a.analyze(str(f))
    assert result["status"] == "success"
    assert result["findings"] == []
    assert result["metadata"]["resolc_exit_code"] == 0


def test_interface_only_clean_even_without_artifact(monkeypatch, tmp_path):
    # exit 0 with no .polkavm artifact (an interface) is still clean, not an error.
    f = tmp_path / "I.sol"
    f.write_text("pragma solidity ^0.8.0; interface I { function f() external; }")
    a = _adapter()
    _force_available(monkeypatch, a)
    _mock_run(monkeypatch, a, rc=0)
    result = a.analyze(str(f))
    assert result["status"] == "success"
    assert result["findings"] == []


# --------------------------------------------------------------------------- #
# class (A) rejection -> finding
# --------------------------------------------------------------------------- #
def test_class_a_rejection_emits_finding(monkeypatch):
    a = _adapter()
    _force_available(monkeypatch, a)
    _mock_run(monkeypatch, a, rc=1, stderr=CLASS_A_STDERR)
    result = a.analyze(str(FIXTURES / "error_cases" / "ExtCodeCopyRejected.sol"))

    assert result["status"] == "success"
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["type"] == "polkavm-unsupported-opcode"
    assert f["severity"].lower() == "high"
    assert f["confidence"] == 0.99
    assert f["cwe_id"] is None
    assert "EXTCODECOPY" in f["message"]
    # anchored to the real source line of the opcode, NOT the Yul offset 29
    assert f["location"]["line"] == _opcode_line(_EXTCODECOPY_FIXTURE, "extcodecopy")
    assert f["location"]["function"] == "copy"
    # compiler offset kept in metadata, labelled as not-a-source-line
    assert f["compiler_position"] == "29:25"
    assert "not a source line" in f["compiler_position_note"]
    assert f["canonical_category"] == "polkavm-unsupported-opcode"
    assert f["tool"] == "polkavm_resolc"


def test_ambiguous_opcode_anchor_is_line_zero(monkeypatch, tmp_path):
    f = tmp_path / "Two.sol"
    f.write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Two {\n"
        "  function a(address x) external view { assembly { extcodecopy(x,0,0,32) } }\n"
        "  function b(address y) external view { assembly { extcodecopy(y,0,0,32) } }\n"
        "}\n"
    )
    a = _adapter()
    _force_available(monkeypatch, a)
    _mock_run(monkeypatch, a, rc=1, stderr=CLASS_A_STDERR)
    result = a.analyze(str(f))
    assert result["status"] == "success"
    assert len(result["findings"]) == 1
    # two occurrences -> cannot uniquely anchor -> line 0, stated honestly
    assert result["findings"][0]["location"]["line"] == 0
    assert "could not be uniquely located" in result["findings"][0]["message"]


# --------------------------------------------------------------------------- #
# honest error: any other non-zero exit is NOT a finding and NOT clean
# --------------------------------------------------------------------------- #
def test_parse_error_is_honest_error(monkeypatch, tmp_path):
    f = tmp_path / "Broken.sol"
    f.write_text("pragma solidity ^0.8.0; contract B {")
    a = _adapter()
    _force_available(monkeypatch, a)
    _mock_run(monkeypatch, a, rc=1, stderr=PARSE_ERROR_STDERR)
    result = a.analyze(str(f))
    assert result["status"] == "error"
    assert result["findings"] == []
    assert "exit 1" in result["error"]


def test_missing_file_is_error(monkeypatch):
    a = _adapter()
    _force_available(monkeypatch, a)
    result = a.analyze(str(FIXTURES / "nope.sol"))
    assert result["status"] == "error"
    assert result["findings"] == []


def test_unavailable_is_error_not_clean(monkeypatch, tmp_path):
    f = tmp_path / "C.sol"
    f.write_text("pragma solidity ^0.8.0; contract C {}")
    a = _adapter()
    monkeypatch.setattr(a, "_resolc_base_cmd", lambda: None)
    result = a.analyze(str(f))
    assert result["status"] == "error"
    assert result["findings"] == []
    assert "not available" in result["error"]


def test_timeout_is_error(monkeypatch, tmp_path):
    f = tmp_path / "C.sol"
    f.write_text("pragma solidity ^0.8.0; contract C {}")
    a = _adapter()
    _force_available(monkeypatch, a)

    def timeout_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="resolc", timeout=1)

    monkeypatch.setattr(a, "run_subprocess", timeout_run)
    result = a.analyze(str(f))
    assert result["status"] == "error"
    assert "timed out" in result["error"]


# --------------------------------------------------------------------------- #
# normalize_findings tuple path (build findings from captured output)
# --------------------------------------------------------------------------- #
def test_normalize_findings_tuple():
    a = _adapter()
    source = _EXTCODECOPY_FIXTURE.read_text()
    findings = a.normalize_findings((CLASS_A_STDERR, source, "ExtCodeCopyRejected.sol"))
    assert len(findings) == 1
    assert findings[0]["location"]["line"] == _opcode_line(_EXTCODECOPY_FIXTURE, "extcodecopy")
    assert a.normalize_findings("not a tuple") == []


# --------------------------------------------------------------------------- #
# registration
# --------------------------------------------------------------------------- #
def test_registered_in_adapter_map_and_tools():
    from miesc.cli.constants import ADAPTER_MAP, POLKAVM_TOOLS

    assert ADAPTER_MAP.get("polkavm_resolc") == "PolkaVMResolcAdapter"
    assert "polkavm_resolc" in POLKAVM_TOOLS
    for evm_only in ("mythril", "manticore", "echidna", "medusa"):
        assert evm_only not in POLKAVM_TOOLS


def test_adapter_loader_resolves():
    from miesc.cli.utils import AdapterLoader

    adapter = AdapterLoader.get_adapter("polkavm_resolc")
    assert type(adapter).__name__ == "PolkaVMResolcAdapter"


def test_not_in_layers_so_evm_path_never_routes_it():
    # polkavm_resolc must be reachable only via --target polkavm (or audit single),
    # never pulled into an implicit EVM scan/audit path (which builds from LAYERS).
    from miesc.cli.constants import LAYERS

    for layer in LAYERS.values():
        assert "polkavm_resolc" not in layer.get("tools", [])


def test_cli_without_target_does_not_route_polkavm_resolc(tmp_path):
    from click.testing import CliRunner

    from miesc.cli.commands.scan import scan

    out = tmp_path / "evm.json"
    res = CliRunner().invoke(
        scan,
        [str(FIXTURES / "clean" / "Counter.sol"), "-o", str(out), "--quiet"],
    )
    assert res.exit_code == 0, res.output
    data = json.loads(out.read_text())
    # the default EVM path must not pull in the compile-level PolkaVM adapter
    assert "polkavm_resolc" not in data["tools"]


# --------------------------------------------------------------------------- #
# multi-file limitation: a rejected import is an honest error, not a false clean
# --------------------------------------------------------------------------- #
def test_import_rejection_is_honest_error(monkeypatch, tmp_path):
    # The npx resolcjs wrapper rejects relative imports; that must surface as an
    # error, never a finding and never a clean result.
    f = tmp_path / "Main.sol"
    f.write_text('pragma solidity ^0.8.0;\nimport "./Lib.sol";\ncontract Main {}')
    a = _adapter()
    _force_available(monkeypatch, a)
    _mock_run(monkeypatch, a, rc=1, stderr="Error: Error: Invalid import path format.")
    result = a.analyze(str(f))
    assert result["status"] == "error"
    assert result["findings"] == []


# --------------------------------------------------------------------------- #
# SARIF export of a class (A) finding
# --------------------------------------------------------------------------- #
def test_finding_exports_valid_sarif(monkeypatch):
    from miesc.core.exporters import Finding, SARIFExporter

    a = _adapter()
    _force_available(monkeypatch, a)
    _mock_run(monkeypatch, a, rc=1, stderr=CLASS_A_STDERR)
    result = a.analyze(str(FIXTURES / "error_cases" / "ExtCodeCopyRejected.sol"))
    findings = [
        Finding(
            id=f["id"],
            type=f["type"],
            severity=f["severity"],
            title=f["type"],
            description=f["description"],
            file_path=f["location"]["file"],
            line_start=f["location"]["line"],
            tool=f.get("tool", "polkavm_resolc"),
            confidence=f["confidence"],
            cwe=f.get("cwe_id"),
            remediation=f.get("recommendation"),
        )
        for f in result["findings"]
    ]
    sarif = json.loads(SARIFExporter(tool_name="MIESC").export(findings))
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert any("UNSUPPORTED-OPCODE" in r["ruleId"].upper() for r in results)


# --------------------------------------------------------------------------- #
# live tests — opt-in via MIESC_RESOLC_LIVE=1, and skipped when resolc is
# unresolvable. They are off by default so CI never shells out to npm; the
# _neutralize_resolc_unless_live conftest fixture also honours the same env var.
# --------------------------------------------------------------------------- #
_RESOLC = _adapter()._resolc_base_cmd()
_requires_resolc = pytest.mark.skipif(
    not os.environ.get("MIESC_RESOLC_LIVE") or _RESOLC is None,
    reason="set MIESC_RESOLC_LIVE=1 with resolc resolvable (resolc, or node+npx+solc) to run",
)


@_requires_resolc
def test_live_clean_contract_has_no_findings():
    result = _adapter().analyze(str(FIXTURES / "clean" / "Counter.sol"), timeout=180)
    assert result["status"] == "success"
    assert result["findings"] == []


@_requires_resolc
def test_live_class_a_fixture_fires_one_finding():
    result = _adapter().analyze(str(_EXTCODECOPY_FIXTURE), timeout=180)
    assert result["status"] == "success"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "polkavm-unsupported-opcode"
    assert result["findings"][0]["location"]["line"] == _opcode_line(
        _EXTCODECOPY_FIXTURE, "extcodecopy"
    )
