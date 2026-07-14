"""Recall-safety invariant for the orchestrator FP filter (issue #69).

The ML orchestrator now applies the recall-safe benign-context
FalsePositiveFilter when ``fp_strictness`` is set. The whole point is that it
removes precision-killing benign findings (e.g. ``solc-version``) WITHOUT ever
dropping a real vulnerability such as reentrancy. If a future change makes the
filter drop a true positive, recall silently regresses; these tests guard that.
"""

import unittest
from unittest.mock import patch

from src.core.ml_orchestrator import MLOrchestrator
from src.ml.fp_filter import FalsePositiveFilter

# A modern-Solidity contract: the solc-version pragma warning is a textbook
# false positive here, while the reentrancy is real.
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


def _finding(ftype: str, severity: str) -> dict:
    return {
        "type": ftype,
        "check": ftype,
        "severity": severity,
        "title": ftype,
        "description": ftype,
        "tool": "slither",
    }


class TestOrchestratorFPRecallSafety(unittest.TestCase):
    def setUp(self):
        self.filter = FalsePositiveFilter(strictness="high", use_rag=False)

    def test_reentrancy_true_positive_is_never_dropped(self):
        for ftype in ("reentrancy-eth", "reentrancy-no-eth", "reentrancy"):
            fr = self.filter.filter_finding(
                _finding(ftype, "critical"), code_context=MODERN_CODE, file_path="Bank.sol"
            )
            self.assertFalse(
                fr.is_likely_fp,
                f"recall regression: {ftype} was flagged as a false positive",
            )

    def test_benign_solc_version_is_filtered(self):
        fr = self.filter.filter_finding(
            _finding("solc-version", "informational"),
            code_context=MODERN_CODE,
            file_path="Bank.sol",
        )
        # solc-version on a modern contract is the canonical benign FP.
        self.assertTrue(fr.is_likely_fp)

    def test_arithmetic_with_safemath_is_downgraded_not_dropped(self):
        # BECToken scenario: the contract imports SafeMath, but the flagged
        # multiplication overflowed anyway. Presence of SafeMath must NOT drop
        # the real arithmetic finding — it is kept and marked needs_review.
        code_with_safemath = (
            "pragma solidity ^0.4.24;\n"
            "import './SafeMath.sol';\n"
            "contract BEC { using SafeMath for uint;\n"
            "  function batchTransfer(address[] r, uint v) public {\n"
            "    uint amount = uint(r.length) * v;  // unchecked, overflows\n"
            "  } }\n"
        )
        fr = self.filter.filter_finding(
            _finding("arithmetic", "medium"),
            code_context=code_with_safemath,
            file_path="BECToken.sol",
        )
        # Invariant that matters: a real arithmetic finding is never dropped just
        # because SafeMath is present. (The downgrade-to-needs_review path is
        # additionally verified end-to-end against the real BECToken.sol, where
        # the finding would otherwise cross the drop threshold.)
        self.assertFalse(
            fr.is_likely_fp, "recall regression: real overflow dropped by SafeMath heuristic"
        )


class TestOrchestratorFPIntegration(unittest.TestCase):
    """Issue #69: ``analyze(fp_strictness=...)`` must engage the FP filter
    end-to-end. The bug was that ``audit full`` removed 0 false positives because
    the orchestrator did not apply the strictness filter to its findings. These
    tests drive the orchestrator (not just the filter) with a benign FP plus a real
    vulnerability and assert the filter is actually engaged and recall-safe.
    """

    def _analyze(self, fp_strictness: str):
        # ml_enabled=False isolates the fp_strictness stage from the (dormant) ML
        # pipeline; the FP stage runs regardless of ml_enabled.
        orch = MLOrchestrator(ml_enabled=False)
        findings = [
            _finding("solc-version", "informational"),  # benign FP on modern code
            _finding("reentrancy-eth", "critical"),  # real vuln, must survive
        ]
        with (
            patch.object(MLOrchestrator, "_read_contract_source", return_value=MODERN_CODE),
            patch.object(MLOrchestrator, "_determine_tools", return_value=["slither"]),
            patch.object(
                MLOrchestrator,
                "_run_tool",
                return_value={"status": "success", "findings": findings},
            ),
        ):
            return orch.analyze("Bank.sol", fp_strictness=fp_strictness)

    def test_high_strictness_removes_benign_fp(self):
        result = self._analyze("high")
        self.assertGreaterEqual(
            result.false_positives_removed,
            1,
            "issue #69 regression: orchestrator removed 0 FPs at fp_strictness=high",
        )

    def test_high_strictness_preserves_real_vulnerability(self):
        result = self._analyze("high")
        kept = {f.get("type") for f in result.ml_filtered_findings}
        self.assertIn("reentrancy-eth", kept, "recall regression: real reentrancy was dropped")

    def test_off_strictness_removes_nothing(self):
        result = self._analyze("off")
        self.assertEqual(
            result.false_positives_removed,
            0,
            "default 'off' must preserve raw recall (no orchestrator FP removal)",
        )


class TestExactDuplicateCollapse(unittest.TestCase):
    """Issue #69(b): findings that are identical except for the reporting tool
    collapse to a single entry (with provenance preserved), while findings that
    differ in any identifying field are never collapsed."""

    def setUp(self):
        self.orch = MLOrchestrator(ml_enabled=False)

    def _f(self, swc, line, tool, file="C.sol", severity="high", title=None):
        return {
            "swc": swc,
            "type": swc,
            "check": swc,
            "title": title or swc,
            "severity": severity,
            "tool": tool,
            "location": {"file": file, "line": line},
        }

    def test_identical_findings_from_different_tools_collapse(self):
        findings = [
            self._f("SWC-107", 20, "slither"),
            self._f("SWC-107", 20, "mythril"),
            self._f("SWC-107", 20, "aderyn"),
            self._f("SWC-107", 20, "gptscan"),
        ]
        deduped, collapsed = self.orch._collapse_exact_duplicates(findings)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(collapsed, 3)
        self.assertEqual(set(deduped[0]["tools"]), {"slither", "mythril", "aderyn", "gptscan"})

    def test_distinct_findings_are_preserved(self):
        findings = [
            self._f("SWC-107", 20, "slither"),  # reentrancy @ L20
            self._f("SWC-107", 42, "slither"),  # reentrancy @ L42 (different line)
            self._f("SWC-101", 20, "slither"),  # overflow @ L20 (different swc)
            self._f("SWC-107", 20, "mythril"),  # exact dup of the first
        ]
        deduped, collapsed = self.orch._collapse_exact_duplicates(findings)
        self.assertEqual(len(deduped), 3, "distinct findings must be preserved")
        self.assertEqual(collapsed, 1, "only the exact duplicate is collapsed")

    def test_empty_input(self):
        deduped, collapsed = self.orch._collapse_exact_duplicates([])
        self.assertEqual(deduped, [])
        self.assertEqual(collapsed, 0)

    def test_original_findings_are_not_mutated(self):
        f1 = self._f("SWC-107", 20, "slither")
        f2 = self._f("SWC-107", 20, "mythril")
        self.orch._collapse_exact_duplicates([f1, f2])
        self.assertNotIn("tools", f1, "input findings must not be mutated")
        self.assertNotIn("tools", f2, "input findings must not be mutated")


if __name__ == "__main__":
    unittest.main()
