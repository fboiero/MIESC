"""
Tests for `miesc analyze` CLI routing (MEJORAS.md item #6).

Covers:
- `.vy` files now route to the Vyper analyzer instead of `ethereum`/scan
  (which rejects non-.sol files and used to crash with an uncaught
  crytic-compile exception).
- Regression test for `_normalize_finding()`: it used to flatten every
  AbstractChainAnalyzer finding dict into a single unstructured "raw"
  string (plain dicts have neither `.to_dict()` nor `__dict__`), silently
  discarding severity/type/location for the move/solana/vyper chains.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from miesc.cli.commands.analyze import _normalize_finding, analyze, detect_chain

VULNERABLE_VYPER = """# @version 0.3.7

owner: public(address)

@external
def __init__():
    self.owner = msg.sender

@external
def kill():
    selfdestruct(self.owner)
"""


class TestNormalizeFindingRegression:
    def test_dict_finding_is_not_flattened_to_raw(self):
        """A finding dict from AbstractChainAnalyzer.normalize_finding() must pass
        through with its fields intact, not collapse into {"raw": str(dict)}."""
        finding = {
            "id": "vyper-selfdestruct_usage-9",
            "type": "selfdestruct_usage",
            "severity": "High",
            "location": {"file": "t.vy", "line": 9},
        }

        result = _normalize_finding(finding, "vyper")

        assert result["type"] == "selfdestruct_usage"
        assert result["severity"] == "High"
        assert result["location"] == {"file": "t.vy", "line": 9}
        assert result["chain"] == "vyper"
        assert "raw" not in result

    def test_non_dict_finding_still_falls_back_to_raw(self):
        result = _normalize_finding(object(), "vyper")
        assert result["chain"] == "vyper"
        assert "raw" in result


class TestVyperChainDetection:
    def test_detect_chain_from_extension(self):
        assert detect_chain("Vault.vy") == "vyper"
        assert detect_chain("Vault.sol") == "ethereum"

    def test_analyze_vy_file_end_to_end(self, tmp_path: Path):
        contract = tmp_path / "Vault.vy"
        contract.write_text(VULNERABLE_VYPER)
        out_file = tmp_path / "out.json"

        runner = CliRunner()
        result = runner.invoke(analyze, [str(contract), "-o", str(out_file), "-q"])

        assert result.exit_code == 0, result.output
        report = json.loads(out_file.read_text())
        assert report["chain"] == "vyper"
        assert any(f["type"] == "selfdestruct_usage" for f in report["findings"])
