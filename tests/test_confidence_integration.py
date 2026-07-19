"""Integration tests for calibrated finding confidence.

These exercise confidence end-to-end rather than the calibrator in isolation:

- the ML orchestrator's default ``analyze`` path annotates each surviving finding
  with a calibrated ``confidence``/``confidence_level`` (cross-tool agreement raises
  it, a benign single-tool finding stays low);
- the ``--min-confidence`` CLI gate drops low-confidence findings before the report
  is written, while keeping high-confidence ones;
- the SARIF ``rank`` reflects the calibrated confidence.
"""

import json
import unittest
from unittest import mock

from click.testing import CliRunner

from miesc.cli.commands.scan import scan
from miesc.core.exporters import Finding, SARIFExporter
from miesc.core.ml_orchestrator import MLOrchestrator

# Modern contract: the reentrancy is real, the solc-version pragma is benign.
MODERN_CODE = """
pragma solidity ^0.8.0;
contract Bank {
    mapping(address => uint) balances;
    function withdraw() external {
        uint amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""


def _tool_result(finding_template: dict):
    """Build a per-tool ``_run_tool`` side effect returning a FRESH copy of the
    finding for each call, so the orchestrator can tag each with its own tool and
    then collapse the exact duplicates (merging the ``tools`` provenance list)."""

    def _side_effect(tool_name, contract_path, timeout=120):
        return {
            "tool": tool_name,
            "status": "success",
            "findings": [dict(finding_template)],
        }

    return _side_effect


class TestOrchestratorConfidenceAnnotation(unittest.TestCase):
    """The default analyze() path attaches a calibrated confidence to findings."""

    def _analyze(self, tools, finding_template):
        orch = MLOrchestrator(ml_enabled=False)
        with (
            mock.patch.object(orch, "_read_contract_source", return_value=MODERN_CODE),
            mock.patch.object(orch, "_determine_tools", return_value=tools),
            mock.patch.object(orch, "_run_tool", side_effect=_tool_result(finding_template)),
        ):
            return orch.analyze("Bank.sol")

    def test_multi_tool_reentrancy_is_high_confidence(self):
        # Three distinct tools report the same reentrancy at the same location: the
        # exact duplicates collapse into one survivor whose provenance lists all
        # three tools, and cross-tool agreement pushes confidence to "high".
        finding = {
            "type": "reentrancy-eth",
            "check": "reentrancy-eth",
            "swc": "SWC-107",
            "title": "Reentrancy",
            "severity": "high",
            "location": {"file": "Bank.sol", "line": 6},
        }
        result = self._analyze(["slither", "mythril", "aderyn"], finding)

        self.assertEqual(len(result.ml_filtered_findings), 1, "exact duplicates must collapse")
        survivor = result.ml_filtered_findings[0]
        self.assertEqual(set(survivor["tools"]), {"slither", "mythril", "aderyn"})
        self.assertEqual(survivor["confidence_level"], "high")
        self.assertGreaterEqual(survivor["confidence"], 0.70)

    def test_benign_single_tool_finding_is_low_confidence(self):
        # A single tool reporting solc-version on a modern contract is the canonical
        # benign finding: one tool + a high FP signal keeps confidence "low".
        finding = {
            "type": "solc-version",
            "check": "solc-version",
            "swc": "SWC-103",
            "title": "solc-version",
            "severity": "informational",
            "location": {"file": "Bank.sol", "line": 2},
        }
        result = self._analyze(["slither"], finding)

        self.assertEqual(len(result.ml_filtered_findings), 1)
        survivor = result.ml_filtered_findings[0]
        self.assertEqual(survivor["confidence_level"], "low")


class TestScanMinConfidenceGate(unittest.TestCase):
    """`miesc scan --min-confidence` drops low-confidence findings before output."""

    @staticmethod
    def _fake_annotate(findings, contract_source="", contract_path=""):
        # Deterministic stand-in for the real calibrator: high for reentrancy, low
        # for solc-version, so the min-confidence gate has a clear boundary to cut on.
        for f in findings:
            if f.get("type") == "reentrancy":
                f["confidence"], f["confidence_level"] = 0.90, "high"
            else:
                f["confidence"], f["confidence_level"] = 0.20, "low"

    @staticmethod
    def _fake_run_tool(tool, contract, timeout=300, **kwargs):
        return {
            "tool": tool,
            "status": "success",
            "findings": [
                {
                    "type": "reentrancy",
                    "title": "Reentrancy",
                    "severity": "high",
                    "location": {"file": "C.sol", "line": 5},
                },
                {
                    "type": "solc-version",
                    "title": "solc-version",
                    "severity": "informational",
                    "location": {"file": "C.sol", "line": 1},
                },
            ],
        }

    def test_min_confidence_drops_low_keeps_high(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("C.sol", "w", encoding="utf-8") as fh:
                fh.write("pragma solidity ^0.8.0; contract C {}\n")

            with (
                mock.patch("miesc.cli.commands.scan.run_tool", self._fake_run_tool),
                mock.patch(
                    "miesc.core.intelligence.enhance_findings",
                    side_effect=lambda findings, **kw: findings,
                ),
                mock.patch("miesc.core.confidence.annotate_confidence", self._fake_annotate),
            ):
                res = runner.invoke(
                    scan,
                    [
                        "C.sol",
                        "--fp-strictness",
                        "off",
                        "--min-confidence",
                        "0.5",
                        "-o",
                        "out.json",
                        "-q",
                    ],
                )

            self.assertEqual(res.exit_code, 0, res.output)
            with open("out.json", encoding="utf-8") as fh:
                data = json.load(fh)

            types = {f.get("type") for f in data["findings"]}
            self.assertIn("reentrancy", types, "high-confidence finding must be kept")
            self.assertNotIn("solc-version", types, "low-confidence finding must be dropped")
            self.assertTrue(all(f["confidence"] >= 0.5 for f in data["findings"]))


class TestSarifRankReflectsConfidence(unittest.TestCase):
    """SARIF ``rank`` (0-100) mirrors the calibrated confidence."""

    def test_confidence_0_9_yields_rank_90(self):
        finding_dict = {"confidence": 0.9}
        finding = Finding(
            id="1",
            type="reentrancy",
            severity="high",
            title="Reentrancy",
            description="reentrancy in withdraw",
            file_path="C.sol",
            line_start=5,
            confidence=finding_dict.get("confidence", 0.8),
        )
        sarif = json.loads(SARIFExporter().export([finding]))
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["rank"], 90.0)
        self.assertEqual(result["properties"]["confidence"], 0.9)


if __name__ == "__main__":
    unittest.main()
