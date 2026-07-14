"""
Coverage-focused unit tests for low-covered non-CLI MIESC modules.

Targets real code paths (no live tools / network / LLM required) in:
  - miesc.core.quick_scanner       (QuickScanner static-tool orchestration)
  - miesc.poc.foundry_scaffold     (temp Foundry workspace helper)
  - miesc.detectors.__init__       (custom detector registry API)
  - miesc.adapters.iaudit_adapter  (multi-agent iAudit adapter + fallback)
  - miesc.api.rest                 (Django REST Framework views + helpers)

All external effects (subprocess, urllib, filesystem tools, LLM) are mocked so
the suite is deterministic and passes with no local tools installed.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import subprocess
import urllib.error
from unittest.mock import MagicMock, Mock, patch

import pytest

# ===========================================================================
# miesc.core.quick_scanner
# ===========================================================================
from miesc.core import quick_scanner as qs_mod
from miesc.core.quick_scanner import QuickScanner


def _make_scanner(available):
    """Build a QuickScanner with a controlled availability map (no subprocess)."""
    with patch.object(QuickScanner, "_check_tools", return_value=dict(available)):
        return QuickScanner()


class TestQuickScannerCheckTools:
    def test_check_tools_all_available(self):
        proc = Mock(returncode=0)
        with patch.object(qs_mod.subprocess, "run", return_value=proc):
            scanner = QuickScanner()
        assert scanner.available_tools == {
            "slither": True,
            "aderyn": True,
            "solhint": True,
        }

    def test_check_tools_handles_exceptions(self):
        with patch.object(qs_mod.subprocess, "run", side_effect=FileNotFoundError()):
            scanner = QuickScanner()
        assert scanner.available_tools == {
            "slither": False,
            "aderyn": False,
            "solhint": False,
        }

    def test_check_tools_nonzero_returncode(self):
        with patch.object(qs_mod.subprocess, "run", return_value=Mock(returncode=1)):
            scanner = QuickScanner()
        assert all(v is False for v in scanner.available_tools.values())


class TestQuickScannerScan:
    def test_scan_missing_file_raises(self, tmp_path):
        scanner = _make_scanner({"slither": False, "aderyn": False, "solhint": False})
        with pytest.raises(FileNotFoundError):
            scanner.scan(str(tmp_path / "does_not_exist.sol"))

    def test_scan_no_tools_available(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        scanner = _make_scanner({"slither": False, "aderyn": False, "solhint": False})
        result = scanner.scan(str(contract), verbose=True)

        assert result["scan_type"] == "quick"
        assert result["tools_run"] == []
        assert result["findings"] == []
        assert result["summary"]["total_findings"] == 0
        assert "execution_time" in result

    def test_scan_runs_available_tool_and_aggregates(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        scanner = _make_scanner({"slither": True, "aderyn": False, "solhint": False})

        fake_findings = [
            {"tool": "slither", "type": "reentrancy", "severity": "high"},
            {"tool": "slither", "type": "reentrancy", "severity": "high"},
            {"tool": "slither", "type": "locked-ether", "severity": "medium"},
        ]
        with patch.object(scanner, "_run_slither", return_value=fake_findings):
            result = scanner.scan(str(contract), verbose=True)

        assert result["tools_run"] == ["slither"]
        assert len(result["findings"]) == 3
        summ = result["summary"]
        assert summ["total_findings"] == 3
        assert summ["by_severity"]["high"] == 2
        assert summ["by_severity"]["medium"] == 1
        assert summ["issue_types"] == 2
        assert "slither" in summ["tools_used"]

    def test_scan_tool_exception_is_swallowed(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        scanner = _make_scanner({"slither": True, "aderyn": False, "solhint": False})
        with patch.object(scanner, "_run_slither", side_effect=RuntimeError("boom")):
            result = scanner.scan(str(contract))
        # Exception logged, tool not added to tools_run, no crash.
        assert result["tools_run"] == []
        assert result["findings"] == []


class TestQuickScannerRunTool:
    def test_run_tool_dispatch_unknown_returns_empty(self):
        scanner = _make_scanner({})
        assert scanner._run_tool("unknown", "/x.sol") == []

    def test_run_slither_parses_json(self):
        scanner = _make_scanner({})
        slither_json = json.dumps(
            {
                "results": {
                    "detectors": [
                        {
                            "check": "reentrancy-eth",
                            "impact": "High",
                            "confidence": "High",
                            "description": "reentrancy found",
                            "first_markdown_element": "C.f()",
                        }
                    ]
                }
            }
        )
        proc = Mock(stdout=slither_json)
        with patch.object(qs_mod.subprocess, "run", return_value=proc):
            findings = scanner._run_slither("/tmp/C.sol")
        assert len(findings) == 1
        f = findings[0]
        assert f["tool"] == "slither"
        assert f["type"] == "reentrancy-eth"
        assert f["severity"] == "high"
        assert f["confidence"] == "high"

    def test_run_slither_bad_json(self):
        scanner = _make_scanner({})
        with patch.object(qs_mod.subprocess, "run", return_value=Mock(stdout="not json")):
            assert scanner._run_slither("/tmp/C.sol") == []

    def test_run_slither_timeout(self):
        scanner = _make_scanner({})
        with patch.object(
            qs_mod.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="slither", timeout=60),
        ):
            assert scanner._run_slither("/tmp/C.sol") == []

    def test_run_slither_not_installed(self):
        scanner = _make_scanner({})
        with patch.object(qs_mod.subprocess, "run", side_effect=FileNotFoundError()):
            assert scanner._run_slither("/tmp/C.sol") == []

    def test_run_aderyn_parses_json(self):
        scanner = _make_scanner({})
        aderyn_json = json.dumps(
            {"issues": [{"title": "unused-var", "severity": "low", "description": "x"}]}
        )
        with patch.object(qs_mod.subprocess, "run", return_value=Mock(stdout=aderyn_json)):
            findings = scanner._run_aderyn("/tmp/C.sol")
        assert findings[0]["tool"] == "aderyn"
        assert findings[0]["type"] == "unused-var"
        assert findings[0]["severity"] == "low"

    def test_run_aderyn_timeout(self):
        scanner = _make_scanner({})
        with patch.object(
            qs_mod.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="aderyn", timeout=60),
        ):
            assert scanner._run_aderyn("/tmp/C.sol") == []

    def test_run_solhint_parses_json(self):
        scanner = _make_scanner({})
        solhint_json = json.dumps(
            [
                {
                    "messages": [
                        {
                            "ruleId": "no-inline-assembly",
                            "severity": 2,
                            "message": "avoid assembly",
                            "line": 12,
                            "column": 3,
                        },
                        {
                            "ruleId": "max-line-length",
                            "severity": 1,
                            "message": "line too long",
                            "line": 5,
                            "column": 1,
                        },
                    ]
                }
            ]
        )
        with patch.object(qs_mod.subprocess, "run", return_value=Mock(stdout=solhint_json)):
            findings = scanner._run_solhint("/tmp/C.sol")
        assert len(findings) == 2
        # severity 2 -> error -> high ; severity 1 -> warning -> medium
        assert findings[0]["severity"] == "high"
        assert findings[1]["severity"] == "medium"

    def test_run_solhint_not_installed(self):
        scanner = _make_scanner({})
        with patch.object(qs_mod.subprocess, "run", side_effect=FileNotFoundError()):
            assert scanner._run_solhint("/tmp/C.sol") == []


class TestQuickScannerHelpers:
    def test_normalize_severity_mapping(self):
        scanner = _make_scanner({})
        assert scanner._normalize_severity("High") == "high"
        assert scanner._normalize_severity("Informational") == "info"
        assert scanner._normalize_severity("warning") == "medium"
        assert scanner._normalize_severity("error") == "high"
        assert scanner._normalize_severity("optimization") == "info"
        assert scanner._normalize_severity("") == "info"
        assert scanner._normalize_severity("nonsense") == "info"

    def test_calculate_summary_counts(self):
        scanner = _make_scanner({})
        findings = [
            {"tool": "a", "severity": "critical", "type": "t1"},
            {"tool": "a", "severity": "unknownsev", "type": "t1"},
            {"tool": "b", "severity": "low", "type": None},
        ]
        summ = scanner._calculate_summary(findings)
        assert summ["total_findings"] == 3
        assert summ["by_severity"]["critical"] == 1
        assert summ["by_severity"]["low"] == 1
        assert set(summ["tools_used"]) == {"a", "b"}
        assert summ["issue_types"] == 1  # only "t1" (None ignored)


# ===========================================================================
# miesc.poc.foundry_scaffold
# ===========================================================================
import shutil as _shutil  # noqa: E402

from miesc.poc import foundry_scaffold as fs  # noqa: E402


class TestFoundryScaffoldHelpers:
    def test_detect_solc_from_pragma(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.19;\ncontract C {}")
        assert fs._detect_solc_version(contract, tmp_path) == "0.8.19"

    def test_detect_solc_from_foundry_toml(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")  # no pragma
        (tmp_path / "foundry.toml").write_text('[profile.default]\nsolc = "0.8.17"\n')
        assert fs._detect_solc_version(contract, tmp_path) == "0.8.17"

    def test_detect_solc_default(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        assert fs._detect_solc_version(contract, tmp_path) == fs.DEFAULT_SOLC

    def test_detect_imports_variants(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text(
            'import "./Local.sol";\n'
            'import "@openzeppelin/contracts/token/ERC20.sol";\n'
            'import "@openzeppelin/contracts-upgradeable/proxy/Init.sol";\n'
            'import "@chainlink/contracts/src/Feed.sol";\n'
            'import "forge-std/Test.sol";\n'
            'import "solmate/tokens/ERC20.sol";\n'
            'import "solady/utils/SafeTransferLib.sol";\n'
            'import {Foo} from "mypkg/Foo.sol";\n'
        )
        imports = fs._detect_imports(contract)
        assert "@openzeppelin/contracts" in imports
        assert "@openzeppelin/contracts-upgradeable" in imports
        assert "@chainlink/contracts" in imports
        assert "forge-std" in imports
        assert "solmate" in imports
        assert "solady" in imports
        assert "mypkg" in imports
        # relative import excluded
        assert not any(i.startswith(".") for i in imports)

    def test_read_repo_remappings_txt_and_toml(self, tmp_path):
        (tmp_path / "remappings.txt").write_text(
            "# a comment\nforge-std/=lib/forge-std/src/\nsolmate/=lib/solmate/src\n"
        )
        (tmp_path / "foundry.toml").write_text(
            '[profile.default]\nremappings = [\n    "@oz/=lib/oz/",\n]\n'
        )
        remaps = fs._read_repo_remappings(tmp_path)
        # relative RHS rebased to absolute, deduped by prefix, trailing slash added
        joined = "\n".join(remaps)
        assert "forge-std/=" in joined
        assert str(tmp_path) in joined
        assert all(r.endswith("/") for r in remaps)
        prefixes = [r.split("=", 1)[0] for r in remaps]
        assert len(prefixes) == len(set(prefixes))

    def test_repo_vendors(self, tmp_path):
        assert fs._repo_vendors(tmp_path, "forge-std") is False  # no lib/
        (tmp_path / "lib" / "forge-std").mkdir(parents=True)
        assert fs._repo_vendors(tmp_path, "forge-std") is True
        assert fs._repo_vendors(tmp_path, "not-a-known-dep") is False

    def test_write_foundry_toml(self, tmp_path):
        fs._write_foundry_toml(tmp_path, "0.8.20", ["@repo/=/abs/repo/"])
        text = (tmp_path / "foundry.toml").read_text()
        assert 'solc = "0.8.20"' in text
        assert "auto_detect_solc = false" in text
        assert "@repo/=/abs/repo/" in text
        assert "remappings = [" in text

    def test_write_foundry_toml_no_remappings(self, tmp_path):
        fs._write_foundry_toml(tmp_path, "0.8.20", [])
        text = (tmp_path / "foundry.toml").read_text()
        assert "remappings" not in text


class TestScaffoldFoundryProject:
    def test_returns_none_when_forge_absent(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        with patch.object(fs.shutil, "which", return_value=None):
            assert fs.scaffold_foundry_project(tmp_path, contract) is None

    def test_scaffold_creates_workspace(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        contract = repo / "Vault.sol"
        contract.write_text(
            "pragma solidity 0.8.20;\n"
            'import "@openzeppelin/contracts/token/ERC20.sol";\n'
            "contract Vault {}"
        )
        workspace = None
        try:
            with (
                patch.object(fs.shutil, "which", return_value="/usr/bin/forge"),
                patch.object(
                    fs.subprocess, "run", return_value=Mock(returncode=0, stderr="")
                ) as mrun,
            ):
                workspace = fs.scaffold_foundry_project(repo, contract)

            assert workspace is not None
            assert (workspace / "foundry.toml").is_file()
            assert (workspace / "src").is_dir()
            assert (workspace / "test").is_dir()
            toml_text = (workspace / "foundry.toml").read_text()
            assert fs.REPO_REMAP_PREFIX in toml_text
            assert 'solc = "0.8.20"' in toml_text
            # git init + at least one forge install invoked
            assert mrun.call_count >= 2
        finally:
            if workspace is not None:
                _shutil.rmtree(workspace, ignore_errors=True)

    def test_scaffold_survives_failed_install(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        contract = repo / "C.sol"
        contract.write_text("pragma solidity 0.8.20;\ncontract C {}")
        workspace = None
        try:
            with (
                patch.object(fs.shutil, "which", return_value="/usr/bin/forge"),
                patch.object(
                    fs.subprocess,
                    "run",
                    return_value=Mock(returncode=1, stderr="offline"),
                ),
            ):
                workspace = fs.scaffold_foundry_project(repo, contract)
            # A failed forge install is non-fatal: workspace still returned.
            assert workspace is not None
            assert (workspace / "foundry.toml").is_file()
        finally:
            if workspace is not None:
                _shutil.rmtree(workspace, ignore_errors=True)


# ===========================================================================
# miesc.detectors.__init__ (custom detector registry API)
# ===========================================================================
from miesc import detectors as det  # noqa: E402
from miesc.detectors import (  # noqa: E402
    BaseDetector,
    Confidence,
    Finding,
    Location,
    Severity,
)


class _SampleDetector(BaseDetector):
    name = "sample-detector"
    description = "Sample for tests"
    category = "custom"
    severity_default = Severity.HIGH

    def analyze(self, source_code, file_path=None):
        findings = []
        if "danger" in source_code:
            findings.append(
                self.create_finding(
                    title="Danger found",
                    description="dangerous",
                    line=3,
                    file_path=file_path or "x.sol",
                    contract="C",
                    function="f",
                    extra="meta",
                )
            )
        return findings


class _OtherCategoryDetector(BaseDetector):
    name = "other-detector"
    description = "Other category"
    category = "defi"

    def analyze(self, source_code, file_path=None):
        return [self.create_finding("t", "d", 1)]


class _BrokenDetector(BaseDetector):
    name = "broken-detector"
    description = "Raises"
    category = "custom"

    def analyze(self, source_code, file_path=None):
        raise RuntimeError("kaboom")


@pytest.fixture
def clean_registry():
    """Isolate the module-level detector registry per test."""
    saved = dict(det._detector_registry)
    det._detector_registry.clear()
    yield
    det._detector_registry.clear()
    det._detector_registry.update(saved)


class TestDetectorDataModels:
    def test_finding_to_dict(self):
        f = Finding(
            detector="d",
            title="t",
            description="desc",
            severity=Severity.CRITICAL,
            location=Location(file="a.sol", line=7, function="f", contract="C"),
            confidence=Confidence.HIGH,
            recommendation="fix it",
            swc_id="SWC-107",
            cwe_id="CWE-841",
        )
        d = f.to_dict()
        assert d["severity"] == "Critical"
        assert d["confidence"] == "high"
        assert d["location"]["line"] == 7
        assert d["swc_id"] == "SWC-107"
        assert d["detector"] == "d"

    def test_base_detector_enable_disable(self):
        d = _SampleDetector()
        assert d.is_enabled() is True
        d.disable()
        assert d.is_enabled() is False
        d.enable()
        assert d.is_enabled() is True

    def test_get_metadata(self):
        meta = _SampleDetector().get_metadata()
        assert meta["name"] == "sample-detector"
        assert meta["category"] == "custom"
        assert meta["severity"] == "High"

    def test_create_finding_defaults(self):
        f = _SampleDetector().create_finding(title="t", description="d", line=10, file_path="C.sol")
        assert f.detector == "sample-detector"
        assert f.severity == Severity.HIGH  # severity_default
        assert f.location.line == 10


class TestDetectorRegistry:
    def test_register_and_get(self, clean_registry):
        ret = det.register_detector(_SampleDetector)
        assert ret is _SampleDetector  # usable as decorator
        assert det.get_detector("sample-detector") is _SampleDetector
        assert "sample-detector" in det.get_all_detectors()

    def test_register_duplicate_warns_and_overwrites(self, clean_registry):
        det.register_detector(_SampleDetector)
        det.register_detector(_SampleDetector)  # duplicate path
        assert det.get_detector("sample-detector") is _SampleDetector

    def test_register_non_subclass_raises(self, clean_registry):
        class NotADetector:
            name = "x"

        with pytest.raises(TypeError):
            det.register_detector(NotADetector)

    def test_unregister(self, clean_registry):
        det.register_detector(_SampleDetector)
        assert det.unregister_detector("sample-detector") is True
        assert det.unregister_detector("sample-detector") is False
        assert det.get_detector("sample-detector") is None

    def test_list_detectors(self, clean_registry):
        det.register_detector(_SampleDetector)
        listed = det.list_detectors()
        assert any(m["name"] == "sample-detector" for m in listed)


class TestDetectorExecution:
    def test_run_detector_success(self, clean_registry):
        det.register_detector(_SampleDetector)
        findings = det.run_detector("sample-detector", "danger here", "C.sol")
        assert len(findings) == 1
        assert findings[0].title == "Danger found"

    def test_run_detector_not_found(self, clean_registry):
        with pytest.raises(ValueError):
            det.run_detector("missing", "code")

    def test_run_detector_disabled_returns_empty(self, clean_registry):
        det.register_detector(_SampleDetector)

        # Patch is_enabled so the constructed instance is disabled.
        with patch.object(_SampleDetector, "is_enabled", return_value=False):
            assert det.run_detector("sample-detector", "danger") == []

    def test_run_all_detectors(self, clean_registry):
        det.register_detector(_SampleDetector)
        det.register_detector(_OtherCategoryDetector)
        all_findings = det.run_all_detectors("danger present")
        assert len(all_findings) == 2  # sample (danger) + other (always)

    def test_run_all_detectors_category_filter(self, clean_registry):
        det.register_detector(_SampleDetector)
        det.register_detector(_OtherCategoryDetector)
        only_defi = det.run_all_detectors("danger present", categories=["defi"])
        assert len(only_defi) == 1

    def test_run_all_detectors_swallows_errors(self, clean_registry):
        det.register_detector(_BrokenDetector)
        det.register_detector(_OtherCategoryDetector)
        # Broken detector raises but is swallowed; other still runs.
        results = det.run_all_detectors("code")
        assert len(results) == 1

    def test_run_all_detectors_skips_disabled(self, clean_registry):
        det.register_detector(_OtherCategoryDetector)
        with patch.object(_OtherCategoryDetector, "is_enabled", return_value=False):
            assert det.run_all_detectors("code") == []


class TestDetectorLoading:
    def test_load_detectors_from_bad_package(self):
        assert det.load_detectors_from_package("nonexistent.package.xyz") == 0

    def test_load_detectors_from_package_success(self, clean_registry):
        import types

        pkg = types.ModuleType("fakepkg")
        pkg.__path__ = []  # type: ignore[attr-defined]
        submodule = types.ModuleType("fakepkg.mod")
        submodule.SomeDetector = _SampleDetector  # discovered via real dir()

        with (
            patch.object(det.importlib, "import_module") as imp,
            patch.object(det.pkgutil, "iter_modules", return_value=[(None, "mod", False)]),
        ):
            imp.side_effect = [pkg, submodule]
            loaded = det.load_detectors_from_package("fakepkg")
        assert loaded == 1
        assert det.get_detector("sample-detector") is _SampleDetector

    def test_load_local_plugins_import_error(self):
        with patch.dict("sys.modules", {"miesc.plugins": None}):
            # Importing miesc.plugins raises ImportError -> returns 0
            assert det.load_local_plugins() == 0

    def test_load_local_plugins_with_detectors(self, clean_registry):
        fake_manager = MagicMock()
        fake_manager.get_local_plugin_detectors.return_value = [
            ("sample-detector", _SampleDetector)
        ]
        fake_pm_module = MagicMock()
        fake_pm_module.PluginManager.return_value = fake_manager
        with patch.dict("sys.modules", {"miesc.plugins": fake_pm_module}):
            loaded = det.load_local_plugins()
        assert loaded == 1


# ===========================================================================
# miesc.adapters.iaudit_adapter
# ===========================================================================
from miesc.adapters.iaudit_adapter import IAuditAdapter  # noqa: E402
from miesc.core.tool_protocol import ToolStatus  # noqa: E402

REENTRANT_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity 0.7.0;
contract Vulnerable {
    mapping(address => uint256) public balances;
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""


@pytest.fixture
def iaudit(monkeypatch):
    monkeypatch.setenv("MIESC_DISABLE_LLM_CACHE", "1")
    return IAuditAdapter(ollama_url="http://localhost:11434")


class TestIAuditBasics:
    def test_metadata(self, iaudit):
        meta = iaudit.get_metadata()
        assert meta.name == "iaudit"
        assert meta.requires_api_key is False
        assert meta.is_optional is True

    def test_can_analyze(self, iaudit):
        assert iaudit.can_analyze("/x/C.sol") is True
        assert iaudit.can_analyze("/x/C.txt") is False

    def test_default_config(self, iaudit):
        cfg = iaudit.get_default_config()
        assert cfg["model"] == "qwen2.5-coder:7b"
        assert cfg["fallback_only"] is False

    def test_normalize_severity(self, iaudit):
        assert iaudit._normalize_severity("critical") == "Critical"
        assert iaudit._normalize_severity("warning") == "Medium"
        assert iaudit._normalize_severity("error") == "High"
        assert iaudit._normalize_severity("bogus") == "Medium"

    def test_valid_taxonomy_id(self, iaudit):
        assert iaudit._valid_taxonomy_id(None) == ""
        assert iaudit._valid_taxonomy_id("SWC-XXX") == ""
        assert iaudit._valid_taxonomy_id("n/a") == ""
        assert iaudit._valid_taxonomy_id("SWC-107") == "SWC-107"

    def test_error_result(self, iaudit):
        r = iaudit._error_result(0.0, "bad")
        assert r["status"] == "error"
        assert r["error"] == "bad"
        assert r["findings"] == []

    def test_get_cache_key_deterministic(self, iaudit):
        k1 = iaudit._get_cache_key("contract A")
        k2 = iaudit._get_cache_key("contract A")
        k3 = iaudit._get_cache_key("contract B")
        assert k1 == k2 != k3

    def test_truncate_code(self, iaudit):
        short = "x" * 10
        assert iaudit._truncate_code(short) == short
        long = "y" * (iaudit.MAX_CONTRACT_CHARS + 50)
        out = iaudit._truncate_code(long)
        assert len(out) < len(long) + 60
        assert "truncated" in out


class TestIAuditReadContract:
    def test_read_existing(self, iaudit, tmp_path):
        c = tmp_path / "C.sol"
        c.write_text("contract C {}")
        assert iaudit._read_contract(str(c)) == "contract C {}"

    def test_read_missing(self, iaudit, tmp_path):
        assert iaudit._read_contract(str(tmp_path / "nope.sol")) is None

    def test_read_non_sol_still_reads(self, iaudit, tmp_path):
        c = tmp_path / "C.txt"
        c.write_text("data")
        assert iaudit._read_contract(str(c)) == "data"


class TestIAuditNormalizeFindings:
    def test_from_result_dict(self, iaudit):
        raw = {
            "findings": [
                {
                    "id": "f1",
                    "type": "reentrancy",
                    "severity": "Critical",
                    "confidence": 0.9,
                    "title": "Reentrancy",
                    "location": {"file": "C.sol", "line": 5, "function": "withdraw"},
                    "swc_id": "SWC-107",
                    "cwe_id": "XXX",
                }
            ]
        }
        out = iaudit.normalize_findings(raw)
        assert len(out) == 1
        assert out[0]["severity"] == "Critical"
        assert out[0]["swc_id"] == "SWC-107"
        assert out[0]["cwe_id"] is None  # placeholder stripped

    def test_from_list_with_string_location(self, iaudit):
        out = iaudit.normalize_findings([{"title": "x", "location": "in fn foo"}])
        assert out[0]["location"]["function"] == "in fn foo"

    def test_junk_input(self, iaudit):
        assert iaudit.normalize_findings("nope") == []
        assert iaudit.normalize_findings([123, "bad"]) == []


class TestIAuditPatternFallback:
    def test_pattern_fallback_detects_reentrancy(self, iaudit):
        result = iaudit._run_pattern_fallback(REENTRANT_CONTRACT, "/x/Vuln.sol", 0.0)
        assert result["status"] == "success"
        assert result["metadata"]["backend"] == "pattern-fallback"
        types = {f["type"] for f in result["findings"]}
        assert "reentrancy" in types

    def test_search_patterns(self, iaudit):
        lines = ["a.call(x);", "b += 1;"]
        matched = iaudit._search_patterns("\n".join(lines), lines, [r"\.call\("])
        assert matched and matched[0][0] == 0

    def test_search_patterns_invalid_regex(self, iaudit):
        lines = ["whatever"]
        assert iaudit._search_patterns("whatever", lines, ["(unclosed"]) == []

    def test_has_negative_patterns(self, iaudit):
        assert iaudit._has_negative_patterns("using SafeMath for uint;", [r"SafeMath"]) is True
        assert iaudit._has_negative_patterns("plain", [r"SafeMath"]) is False

    def test_check_reentrancy_pattern(self, iaudit):
        assert iaudit._check_reentrancy_pattern(REENTRANT_CONTRACT) is True
        safe = "function f() public { balances[msg.sender] -= 1; msg.sender.call{value: 1}(''); }"
        assert iaudit._check_reentrancy_pattern(safe) is False

    def test_find_enclosing_function(self, iaudit):
        lines = REENTRANT_CONTRACT.split("\n")
        # locate a line inside withdraw()
        idx = next(i for i, l in enumerate(lines) if "call{value" in l)
        assert iaudit._find_enclosing_function(lines, idx) == "withdraw"

    def test_downgrade_severity(self, iaudit):
        assert iaudit._downgrade_severity("Critical") == "High"
        assert iaudit._downgrade_severity("Info") == "Info"
        assert iaudit._downgrade_severity("weird") == "weird"


class TestIAuditJSONExtraction:
    def test_extract_json_block(self, iaudit):
        text = 'noise ```json\n{"findings": []}\n``` more'
        assert iaudit._extract_json_robust(text) == {"findings": []}

    def test_extract_findings_key(self, iaudit):
        text = 'prefix {"findings": [{"id": "a"}]} suffix'
        parsed = iaudit._extract_json_robust(text)
        assert parsed["findings"][0]["id"] == "a"

    def test_extract_first_to_last(self, iaudit):
        text = 'x {"a": 1} y'
        assert iaudit._extract_json_robust(text) == {"a": 1}

    def test_extract_repair_trailing_comma(self, iaudit):
        text = '{"findings": [{"id": "a"},]}'
        parsed = iaudit._extract_json_robust(text)
        assert parsed is not None
        assert parsed["findings"][0]["id"] == "a"

    def test_extract_empty_returns_none(self, iaudit):
        assert iaudit._extract_json_robust("") is None
        assert iaudit._extract_json_robust("no json here") is None

    def test_extract_balanced_json(self, iaudit):
        text = 'aa {"x": {"y": 1}} bb'
        start = text.find("{")
        assert iaudit._extract_balanced_json(text, start) == {"x": {"y": 1}}

    def test_repair_json_trailing(self, iaudit):
        repaired = iaudit._repair_json('{"a": 1,}')
        assert json.loads(repaired) == {"a": 1}


class TestIAuditParseDetector:
    def test_parse_detector_output(self, iaudit):
        raw = json.dumps(
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "critical",
                        "title": "Reentrancy",
                        "location": {"function": "withdraw"},
                        "confidence": 0.8,
                    }
                ]
            }
        )
        findings = iaudit._parse_detector_output(raw, "/x/C.sol")
        assert len(findings) == 1
        assert findings[0]["severity"] == "Critical"
        assert findings[0]["location"]["file"] == "/x/C.sol"

    def test_parse_detector_string_location(self, iaudit):
        raw = json.dumps({"findings": [{"type": "x", "location": "withdraw()"}]})
        findings = iaudit._parse_detector_output(raw, "/x/C.sol")
        assert findings[0]["location"]["function"] == "withdraw()"

    def test_parse_detector_unparseable(self, iaudit):
        assert iaudit._parse_detector_output("garbage no json", "/x/C.sol") == []


class TestIAuditReviewer:
    def _det_findings(self):
        return [
            {
                "id": "iaudit-1",
                "type": "reentrancy",
                "severity": "Critical",
                "title": "R",
                "confidence": 0.8,
            },
            {
                "id": "iaudit-2",
                "type": "dos",
                "severity": "Medium",
                "title": "D",
                "confidence": 0.7,
            },
            {"id": "iaudit-3", "type": "ts", "severity": "Low", "title": "T", "confidence": 0.7},
        ]

    def test_confirmed_and_downgraded(self, iaudit):
        review = json.dumps(
            {
                "reviewed_findings": [
                    {
                        "original_id": "iaudit-1",
                        "verdict": "confirmed",
                        "adjusted_confidence": 0.95,
                    },
                    {
                        "original_id": "iaudit-2",
                        "verdict": "downgraded",
                        "adjusted_severity": "Low",
                    },
                ]
            }
        )
        out = iaudit._apply_reviewer_verdicts(self._det_findings(), review)
        by_id = {f["id"]: f for f in out}
        assert by_id["iaudit-1"]["confidence"] == 0.95
        assert by_id["iaudit-2"]["severity"] == "Low"
        # iaudit-3 had no verdict -> kept with lowered confidence
        assert by_id["iaudit-3"]["reviewed"] is False

    def test_false_positive_removed_and_critical_kept(self, iaudit):
        review = json.dumps(
            {
                "reviewed_findings": [
                    {"original_id": "iaudit-1", "verdict": "false_positive"},
                    {"original_id": "iaudit-2", "verdict": "false_positive"},
                ]
            }
        )
        out = iaudit._apply_reviewer_verdicts(self._det_findings(), review)
        ids = {f["id"] for f in out}
        # Critical FP kept (overridden); medium FP removed; iaudit-3 kept (no verdict)
        assert "iaudit-1" in ids
        assert "iaudit-2" not in ids

    def test_needs_context(self, iaudit):
        review = json.dumps(
            {"reviewed_findings": [{"original_id": "iaudit-1", "verdict": "needs_context"}]}
        )
        out = iaudit._apply_reviewer_verdicts(self._det_findings(), review)
        first = next(f for f in out if f["id"] == "iaudit-1")
        assert first.get("needs_context") is True

    def test_no_reviewed_findings_returns_original(self, iaudit):
        review = json.dumps({"reviewed_findings": []})
        out = iaudit._apply_reviewer_verdicts(self._det_findings(), review)
        assert len(out) == 3

    def test_unparseable_review_uses_text_fallback(self, iaudit):
        out = iaudit._apply_reviewer_verdicts(self._det_findings(), "plain text no json")
        # text fallback keeps everything (no FP markers)
        assert len(out) == 3

    def test_text_fallback_marks_fp(self, iaudit):
        text = "The finding 'd' is a false_positive and should be dropped."
        findings = [
            {"id": "iaudit-2", "type": "dos", "severity": "Medium", "title": "D", "confidence": 0.7}
        ]
        out = iaudit._apply_reviewer_text_fallback(findings, text)
        assert out == []  # medium FP removed


class TestIAuditAvailability:
    def test_is_available_with_suitable_model(self, iaudit):
        payload = json.dumps({"models": [{"name": "qwen2.5-coder:7b"}]}).encode()
        cm = MagicMock()
        cm.__enter__.return_value.read.return_value = payload
        with patch("miesc.adapters.iaudit_adapter.urllib.request.urlopen", return_value=cm):
            assert iaudit.is_available() == ToolStatus.AVAILABLE

    def test_is_available_no_suitable_model(self, iaudit):
        payload = json.dumps({"models": [{"name": "tinyllama:latest"}]}).encode()
        cm = MagicMock()
        cm.__enter__.return_value.read.return_value = payload
        with patch("miesc.adapters.iaudit_adapter.urllib.request.urlopen", return_value=cm):
            assert iaudit.is_available() == ToolStatus.CONFIGURATION_ERROR

    def test_is_available_urlerror_falls_to_cli(self, iaudit):
        with (
            patch(
                "miesc.adapters.iaudit_adapter.urllib.request.urlopen",
                side_effect=urllib.error.URLError("down"),
            ),
            patch.object(iaudit, "_check_ollama_cli", return_value=ToolStatus.NOT_INSTALLED) as cli,
        ):
            assert iaudit.is_available() == ToolStatus.NOT_INSTALLED
            cli.assert_called_once()

    def test_check_ollama_cli_available(self, iaudit):
        proc = Mock(returncode=0, stdout="qwen2.5-coder:7b   123 MB")
        with patch.object(iaudit_subprocess(), "run", return_value=proc):
            assert iaudit._check_ollama_cli() == ToolStatus.AVAILABLE

    def test_check_ollama_cli_not_installed(self, iaudit):
        with patch.object(iaudit_subprocess(), "run", side_effect=FileNotFoundError()):
            assert iaudit._check_ollama_cli() == ToolStatus.NOT_INSTALLED

    def test_check_ollama_cli_no_model(self, iaudit):
        proc = Mock(returncode=0, stdout="tinyllama:latest")
        with patch.object(iaudit_subprocess(), "run", return_value=proc):
            assert iaudit._check_ollama_cli() == ToolStatus.CONFIGURATION_ERROR


def iaudit_subprocess():
    """Return the subprocess module object referenced inside iaudit_adapter."""
    from miesc.adapters import iaudit_adapter

    return iaudit_adapter.subprocess


class TestIAuditModelDetection:
    def test_env_override_wins(self, iaudit, monkeypatch):
        monkeypatch.setenv("MIESC_LLM_MODEL", "custom-model:99b")
        assert iaudit._detect_best_model() == "custom-model:99b"

    def test_detect_from_api(self, iaudit, monkeypatch):
        monkeypatch.delenv("MIESC_LLM_MODEL", raising=False)
        payload = json.dumps({"models": [{"name": "codellama:7b"}]}).encode()
        cm = MagicMock()
        cm.__enter__.return_value.read.return_value = payload
        with patch("miesc.adapters.iaudit_adapter.urllib.request.urlopen", return_value=cm):
            assert iaudit._detect_best_model() == "codellama:7b"


class TestIAuditAnalyze:
    def test_analyze_missing_file(self, iaudit, tmp_path):
        r = iaudit.analyze(str(tmp_path / "nope.sol"))
        assert r["status"] == "error"

    def test_analyze_fallback_only(self, iaudit, tmp_path):
        c = tmp_path / "Vuln.sol"
        c.write_text(REENTRANT_CONTRACT)
        r = iaudit.analyze(str(c), fallback_only=True)
        assert r["status"] == "success"
        assert r["metadata"]["backend"] == "pattern-fallback"

    def test_analyze_multi_agent_pipeline(self, iaudit, tmp_path):
        c = tmp_path / "Vuln.sol"
        c.write_text(REENTRANT_CONTRACT)

        planner = '{"scope": "withdraw"}'
        detector = json.dumps(
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "critical",
                        "title": "Reentrancy in withdraw",
                        "location": {"function": "withdraw"},
                        "confidence": 0.85,
                    }
                ]
            }
        )
        reviewer = json.dumps(
            {"reviewed_findings": [{"original_id": "iaudit-1", "verdict": "confirmed"}]}
        )

        with (
            patch.object(iaudit, "is_available", return_value=ToolStatus.AVAILABLE),
            patch.object(iaudit, "_detect_best_model", return_value="codellama:7b"),
            patch.object(iaudit, "_call_ollama_api", side_effect=[planner, detector, reviewer]),
        ):
            r = iaudit.analyze(str(c))

        assert r["status"] == "success"
        assert r["metadata"]["backend"] == "ollama"
        assert len(r["findings"]) == 1
        assert r["findings"][0]["reviewed"] is True

    def test_analyze_pipeline_planner_fails_falls_back(self, iaudit, tmp_path):
        c = tmp_path / "Vuln.sol"
        c.write_text(REENTRANT_CONTRACT)
        with (
            patch.object(iaudit, "is_available", return_value=ToolStatus.AVAILABLE),
            patch.object(iaudit, "_detect_best_model", return_value="codellama:7b"),
            patch.object(iaudit, "_call_ollama_api", return_value=None),
        ):
            r = iaudit.analyze(str(c))
        # Planner returns None -> pattern fallback
        assert r["metadata"]["backend"] == "pattern-fallback"


# ===========================================================================
# miesc.api.rest (Django REST Framework)
# ===========================================================================
django = pytest.importorskip("django")
pytest.importorskip("rest_framework")

# Importing the rest module configures Django settings (settings.configure +
# django.setup at import time). Only after that can rest_framework.test be imported,
# so APIRequestFactory is imported lazily inside the fixture below.
from miesc.api import rest  # noqa: E402


@pytest.fixture
def factory():
    from rest_framework.test import APIRequestFactory

    return APIRequestFactory()


class TestRestPureFunctions:
    def test_run_tool_no_adapter(self):
        with patch.object(rest.AdapterLoader, "get_adapter", return_value=None):
            r = rest.run_tool("ghost", "/x/C.sol")
        assert r["status"] == "no_adapter"
        assert r["findings"] == []

    def test_run_tool_not_available(self):
        adapter = Mock()
        adapter.is_available.return_value = ToolStatus.NOT_INSTALLED
        with patch.object(rest.AdapterLoader, "get_adapter", return_value=adapter):
            r = rest.run_tool("slither", "/x/C.sol")
        assert r["status"] == "not_available"
        assert "not available" in r["error"]

    def test_run_tool_success(self):
        adapter = Mock()
        adapter.is_available.return_value = ToolStatus.AVAILABLE
        adapter.analyze.return_value = {
            "status": "success",
            "findings": [{"severity": "HIGH"}],
            "execution_time": 0.1,
            "metadata": {"x": 1},
        }
        with patch.object(rest.AdapterLoader, "get_adapter", return_value=adapter):
            r = rest.run_tool("slither", "/x/C.sol", timeout=10)
        assert r["status"] == "success"
        assert r["findings"] == [{"severity": "HIGH"}]
        assert r["metadata"] == {"x": 1}

    def test_run_tool_exception(self):
        adapter = Mock()
        adapter.is_available.return_value = ToolStatus.AVAILABLE
        adapter.analyze.side_effect = RuntimeError("boom")
        with patch.object(rest.AdapterLoader, "get_adapter", return_value=adapter):
            r = rest.run_tool("slither", "/x/C.sol")
        assert r["status"] == "error"
        assert "boom" in r["error"]

    def test_run_layer_invalid(self):
        assert rest.run_layer(99, "/x/C.sol") == []

    def test_run_layer_valid(self):
        with patch.object(rest, "run_tool", return_value={"tool": "t", "findings": []}):
            results = rest.run_layer(1, "/x/C.sol")
        assert len(results) == len(rest.LAYERS[1]["tools"])

    def test_run_full_audit(self):
        with patch.object(rest, "run_tool", return_value={"tool": "t", "findings": []}):
            r = rest.run_full_audit("/x/C.sol", layers=[1])
        assert "audit_id" in r and r["layers"] == [1]

    def test_summarize_findings(self):
        results = [{"findings": [{"severity": "CRIT"}, {"severity": "HI"}, {"severity": "x"}]}]
        s = rest.summarize_findings(results)
        assert s["CRITICAL"] == 1 and s["HIGH"] == 1 and s["INFO"] == 1

    def test_to_sarif(self):
        results = [
            {
                "tool": "slither",
                "contract": "C.sol",
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "HIGH",
                        "location": {"file": "C.sol", "line": 3},
                    }
                ],
            }
        ]
        sarif = rest.to_sarif(results)
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_check_tool_status_with_adapter(self):
        adapter = Mock()
        adapter.is_available.return_value = ToolStatus.AVAILABLE
        with patch.object(rest.AdapterLoader, "get_adapter", return_value=adapter):
            status = rest.AdapterLoader.check_tool_status("slither")
        assert status["available"] is True
        assert status["status"] == "available"

    def test_check_tool_status_error(self):
        adapter = Mock()
        adapter.is_available.side_effect = RuntimeError("x")
        with patch.object(rest.AdapterLoader, "get_adapter", return_value=adapter):
            status = rest.AdapterLoader.check_tool_status("slither")
        assert status["available"] is False
        assert status["status"] == "error"


@pytest.mark.skipif(not rest.DRF_AVAILABLE, reason="DRF not available")
class TestRestViews:
    def test_api_root(self, factory):
        resp = rest.api_root(factory.get("/"))
        assert resp.status_code == 200
        assert resp.data["service"] == "MIESC REST API"

    def test_analyze_quick_missing_body(self, factory):
        resp = rest.analyze_quick(factory.post("/", {}, format="json"))
        assert resp.status_code == 400

    def test_analyze_quick_with_code(self, factory):
        canned = {"tool": "slither", "findings": [{"severity": "HIGH"}], "status": "success"}
        with patch.object(rest, "run_tool", return_value=canned):
            resp = rest.analyze_quick(
                factory.post("/", {"contract_code": "contract C {}"}, format="json")
            )
        assert resp.status_code == 200
        assert resp.data["audit_type"] == "quick"
        assert resp.data["total_findings"] >= 1

    def test_analyze_quick_sarif(self, factory):
        canned = {"tool": "slither", "findings": [{"type": "r", "severity": "HIGH"}]}
        with patch.object(rest, "run_tool", return_value=canned):
            resp = rest.analyze_quick(
                factory.post(
                    "/", {"contract_code": "contract C {}", "format": "sarif"}, format="json"
                )
            )
        assert resp.status_code == 200
        assert resp.data["version"] == "2.1.0"

    def test_analyze_full_missing_body(self, factory):
        resp = rest.analyze_full(factory.post("/", {}, format="json"))
        assert resp.status_code == 400

    def test_analyze_full_invalid_layers(self, factory):
        resp = rest.analyze_full(
            factory.post("/", {"contract_code": "x", "layers": [99]}, format="json")
        )
        assert resp.status_code == 400

    def test_analyze_full_valid(self, factory):
        with patch.object(rest, "run_tool", return_value={"tool": "t", "findings": []}):
            resp = rest.analyze_full(
                factory.post("/", {"contract_code": "contract C {}", "layers": [1]}, format="json")
            )
        assert resp.status_code == 200
        assert "audit_id" in resp.data

    def test_analyze_layer_invalid(self, factory):
        resp = rest.analyze_layer(factory.post("/", {"contract_code": "x"}, format="json"), 99)
        assert resp.status_code == 400

    def test_analyze_layer_missing_body(self, factory):
        resp = rest.analyze_layer(factory.post("/", {}, format="json"), 1)
        assert resp.status_code == 400

    def test_analyze_layer_valid(self, factory):
        with patch.object(rest, "run_tool", return_value={"tool": "t", "findings": []}):
            resp = rest.analyze_layer(
                factory.post("/", {"contract_code": "contract C {}"}, format="json"), 1
            )
        assert resp.status_code == 200
        assert resp.data["layer"] == 1

    def test_analyze_tool_unknown(self, factory):
        resp = rest.analyze_tool(factory.post("/", {"contract_code": "x"}, format="json"), "ghost")
        assert resp.status_code == 400

    def test_analyze_tool_missing_body(self, factory):
        resp = rest.analyze_tool(factory.post("/", {}, format="json"), "slither")
        assert resp.status_code == 400

    def test_analyze_tool_valid(self, factory):
        canned = {"tool": "slither", "findings": [], "status": "success"}
        with patch.object(rest, "run_tool", return_value=canned):
            resp = rest.analyze_tool(
                factory.post("/", {"contract_code": "contract C {}"}, format="json"), "slither"
            )
        assert resp.status_code == 200
        assert resp.data["tool"] == "slither"

    def test_tools_list(self, factory):
        with patch.object(
            rest.AdapterLoader,
            "check_tool_status",
            return_value={"status": "available", "available": True},
        ):
            resp = rest.tools_list(factory.get("/"))
        assert resp.status_code == 200
        assert resp.data["total_tools"] > 0
        assert resp.data["available_tools"] == resp.data["total_tools"]

    def test_tools_info_unknown(self, factory):
        resp = rest.tools_info(factory.get("/"), "ghost")
        assert resp.status_code == 404

    def test_tools_info_no_adapter(self, factory):
        with patch.object(rest.AdapterLoader, "get_adapter", return_value=None):
            resp = rest.tools_info(factory.get("/"), "slither")
        assert resp.status_code == 200
        assert resp.data["status"] == "no_adapter"

    def test_tools_info_with_adapter(self, factory):
        adapter = Mock()
        meta = Mock()
        meta.name = "slither"
        meta.version = "1.0"
        meta.category = Mock(value="static_analysis")
        meta.author = "x"
        meta.license = "AGPL"
        meta.homepage = "h"
        meta.repository = "r"
        meta.documentation = "d"
        meta.installation_cmd = "pip"
        meta.capabilities = []
        adapter.get_metadata.return_value = meta
        adapter.is_available.return_value = ToolStatus.AVAILABLE
        with patch.object(rest.AdapterLoader, "get_adapter", return_value=adapter):
            resp = rest.tools_info(factory.get("/"), "slither")
        assert resp.status_code == 200
        assert resp.data["name"] == "slither"
        assert resp.data["available"] is True

    def test_layers_list(self, factory):
        with patch.object(
            rest.AdapterLoader,
            "check_tool_status",
            return_value={"status": "available", "available": True},
        ):
            resp = rest.layers_list(factory.get("/"))
        assert resp.status_code == 200
        assert resp.data["total_layers"] == len(rest.LAYERS)

    def test_health_check(self, factory):
        with (
            patch.object(
                rest.AdapterLoader,
                "check_tool_status",
                return_value={"status": "available", "available": True},
            ),
            patch("subprocess.run", return_value=Mock(returncode=0, stdout="v1.0\n")),
        ):
            resp = rest.health_check(factory.get("/"))
        assert resp.status_code == 200
        assert resp.data["status"] == "healthy"

    def test_reports_list_get(self, factory):
        resp = rest.reports_list(factory.get("/"))
        assert resp.status_code == 200

    def test_reports_list_post(self, factory):
        resp = rest.reports_list(factory.post("/", {"k": "v"}, format="json"))
        assert resp.status_code == 201
        assert "report_id" in resp.data

    def test_remediate_missing_results(self, factory):
        resp = rest.remediate_contract_view(
            factory.post("/", {"contract_code": "x"}, format="json")
        )
        assert resp.status_code == 400

    def test_remediate_success(self, factory):
        evidence = Mock()
        evidence.status = "ok"
        evidence.to_dict.return_value = {"status": "ok"}
        with patch("miesc.security.remediation_pipeline.remediate_contract", return_value=evidence):
            resp = rest.remediate_contract_view(
                factory.post(
                    "/",
                    {"results": {"findings": []}, "contract_code": "contract C {}"},
                    format="json",
                )
            )
        assert resp.status_code == 200
        assert resp.data["status"] == "ok"


class TestRestExceptionHandler:
    def test_custom_exception_handler_fallback(self):
        # With no DRF context match, returns a Response with error payload.
        resp = rest.custom_exception_handler(ValueError("bad"), {})
        assert resp.status_code in (400, 500)


class TestRestAppFactory:
    def test_create_app(self):
        assert rest.create_app() is True
