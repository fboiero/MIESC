"""
Tests for the bundled reference example plugins and the marketplace index.

These prove the plugin ecosystem end-to-end:

- every example plugin under ``examples/plugins/`` passes the versioned Plugin
  API conformance suite (as a community developer would run it via
  ``miesc plugins conformance <path>``);
- each plugin declares ``API_VERSION == PLUGIN_API_VERSION`` explicitly;
- each plugin's real detection / reporting logic works on a sample (a true
  finding on a vulnerable snippet, none on a clean one);
- the marketplace index still validates against ``schema.json`` and lists the
  seeded example plugins.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from miesc.plugins import (
    PLUGIN_API_VERSION,
    PluginConformanceChecker,
    PluginContext,
    PluginLoader,
    PluginType,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "examples" / "plugins"
MARKETPLACE_DIR = REPO_ROOT / "data" / "marketplace"

# (relative plugin file, expected plugin class name, expected plugin type)
EXAMPLE_PLUGINS = [
    ("reentrancy_detector/detector.py", "ReentrancyDetectorPlugin", PluginType.DETECTOR),
    ("txorigin_detector/detector.py", "TxOriginAuthDetectorPlugin", PluginType.DETECTOR),
    ("csv_reporter/reporter.py", "CSVReporterPlugin", PluginType.REPORTER),
]

# Slugs seeded into the marketplace index for the example plugins.
SEEDED_SLUGS = {"reentrancy-detector", "txorigin-auth-detector", "csv-reporter"}


def _plugin_path(rel: str) -> Path:
    return EXAMPLES_DIR / rel


def _context() -> PluginContext:
    return PluginContext(
        miesc_version="6.0.0",
        config={},
        data_dir=Path("/tmp"),
        cache_dir=Path("/tmp"),
    )


def _load_instance(rel: str):
    """Load an example plugin file and return an initialized instance."""
    loaded = PluginLoader().load_plugin_file(_plugin_path(rel))
    assert loaded, f"No plugin classes found in {rel}"
    instance = loaded[0].plugin_class()
    instance.initialize(_context())
    return instance


# ---------------------------------------------------------------------------
# Conformance + API version
# ---------------------------------------------------------------------------
class TestExamplePluginConformance:
    @pytest.mark.parametrize("rel,cls_name,ptype", EXAMPLE_PLUGINS)
    def test_passes_conformance(self, rel, cls_name, ptype):
        reports = PluginConformanceChecker().check_file(_plugin_path(rel))
        assert len(reports) == 1
        report = reports[0]
        assert report.plugin == cls_name
        assert report.passed, [f.message for f in report.failures]
        assert report.failures == []

    @pytest.mark.parametrize("rel,cls_name,ptype", EXAMPLE_PLUGINS)
    def test_declares_host_api_version(self, rel, cls_name, ptype):
        instance = _load_instance(rel)
        assert instance.api_version == PLUGIN_API_VERSION
        # Declared explicitly on the class, not merely inherited by default.
        assert "API_VERSION" in vars(type(instance))
        assert type(instance).API_VERSION == PLUGIN_API_VERSION

    @pytest.mark.parametrize("rel,cls_name,ptype", EXAMPLE_PLUGINS)
    def test_reports_expected_type(self, rel, cls_name, ptype):
        instance = _load_instance(rel)
        assert instance.plugin_type == ptype

    @pytest.mark.parametrize("rel,cls_name,ptype", EXAMPLE_PLUGINS)
    def test_metadata_carries_api_version(self, rel, cls_name, ptype):
        instance = _load_instance(rel)
        meta = instance.get_metadata()
        assert meta.api_version == PLUGIN_API_VERSION


# ---------------------------------------------------------------------------
# Reentrancy detector logic
# ---------------------------------------------------------------------------
class TestReentrancyDetectorLogic:
    VULNERABLE = """
    contract Bank {
        mapping(address => uint256) public balances;
        function withdraw() public {
            uint256 bal = balances[msg.sender];
            (bool ok, ) = msg.sender.call{value: bal}("");
            require(ok);
            balances[msg.sender] = 0;
        }
    }
    """

    CLEAN = """
    contract Bank {
        mapping(address => uint256) public balances;
        function withdraw() public {
            uint256 bal = balances[msg.sender];
            balances[msg.sender] = 0;
            payable(msg.sender).transfer(bal);
        }
    }
    """

    def test_flags_cei_violation(self):
        plugin = _load_instance("reentrancy_detector/detector.py")
        findings = plugin.detect(self.VULNERABLE, "Bank.sol")
        assert findings, "expected a reentrancy finding on vulnerable code"
        assert any(f["severity"] == "High" for f in findings)
        assert all(f["swc_id"] == "SWC-107" for f in findings)

    def test_clean_code_has_no_external_call_finding(self):
        plugin = _load_instance("reentrancy_detector/detector.py")
        findings = plugin.detect(self.CLEAN, "Bank.sol")
        assert findings == []


# ---------------------------------------------------------------------------
# tx.origin detector logic
# ---------------------------------------------------------------------------
class TestTxOriginDetectorLogic:
    VULNERABLE = """
    contract Wallet {
        address owner;
        function withdraw() public {
            require(tx.origin == owner, "not owner");
        }
    }
    """

    CLEAN = """
    contract Wallet {
        address owner;
        function withdraw() public {
            require(msg.sender == owner, "not owner");
        }
    }
    """

    def test_flags_tx_origin_auth(self):
        plugin = _load_instance("txorigin_detector/detector.py")
        findings = plugin.detect(self.VULNERABLE, "Wallet.sol")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["severity"] == "High"
        assert finding["swc_id"] == "SWC-115"
        assert finding["type"] == "tx-origin-authentication"

    def test_clean_code_has_no_finding(self):
        plugin = _load_instance("txorigin_detector/detector.py")
        findings = plugin.detect(self.CLEAN, "Wallet.sol")
        assert findings == []

    def test_execute_wraps_detect(self):
        plugin = _load_instance("txorigin_detector/detector.py")
        result = plugin.execute(code=self.VULNERABLE, filename="Wallet.sol")
        assert result.success
        assert result.metadata["finding_count"] == 1


# ---------------------------------------------------------------------------
# CSV reporter logic
# ---------------------------------------------------------------------------
class TestCSVReporterLogic:
    FINDINGS = [
        {
            "id": "F-1",
            "tool": "example",
            "severity": "High",
            "type": "reentrancy",
            "swc_id": "SWC-107",
            "message": "external call before state update",
            "location": {"file": "Bank.sol", "line": 6, "column": 0},
        },
        {
            "id": "F-2",
            "tool": "example",
            "severity": "Low",
            "type": "tx-origin-authentication",
            "swc_id": "SWC-115",
            "message": "tx.origin usage",
            "location": {"file": "Wallet.sol", "line": 5, "column": 0},
        },
    ]

    def test_generates_csv_file(self, tmp_path):
        plugin = _load_instance("csv_reporter/reporter.py")
        out = tmp_path / "report.csv"
        result = plugin.generate(self.FINDINGS, {"title": "Test"}, out)
        assert result == out
        assert out.exists()
        text = out.read_text(encoding="utf-8")
        rows = [r for r in text.splitlines() if r.strip()]
        # header + one row per finding
        assert len(rows) == 1 + len(self.FINDINGS)
        assert "severity" in rows[0]
        assert "SWC-107" in text
        assert "Bank.sol" in text

    def test_empty_findings_writes_header_only(self, tmp_path):
        plugin = _load_instance("csv_reporter/reporter.py")
        out = tmp_path / "empty.csv"
        plugin.generate([], {}, out)
        rows = [r for r in out.read_text(encoding="utf-8").splitlines() if r.strip()]
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Marketplace index
# ---------------------------------------------------------------------------
class TestMarketplaceIndex:
    def _load_index(self) -> dict:
        with (MARKETPLACE_DIR / "marketplace-index.json").open() as fh:
            return json.load(fh)

    def test_index_validates_against_schema(self):
        jsonschema = pytest.importorskip("jsonschema")
        with (MARKETPLACE_DIR / "schema.json").open() as fh:
            schema = json.load(fh)
        jsonschema.validate(self._load_index(), schema)

    def test_slugs_are_unique(self):
        slugs = [p["slug"] for p in self._load_index()["plugins"]]
        assert len(slugs) == len(set(slugs))

    def test_example_plugins_are_seeded(self):
        slugs = {p["slug"] for p in self._load_index()["plugins"]}
        assert SEEDED_SLUGS.issubset(slugs)

    def test_seeded_entries_reference_valid_types(self):
        valid = {t.value for t in PluginType}
        for plugin in self._load_index()["plugins"]:
            assert plugin["plugin_type"] in valid
            assert plugin["pypi_package"].startswith(("miesc-", "miesc_"))
