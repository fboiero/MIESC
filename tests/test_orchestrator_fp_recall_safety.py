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
        with patch.object(
            MLOrchestrator, "_read_contract_source", return_value=MODERN_CODE
        ), patch.object(
            MLOrchestrator, "_determine_tools", return_value=["slither"]
        ), patch.object(
            MLOrchestrator,
            "_run_tool",
            return_value={"status": "success", "findings": findings},
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
        self.assertIn(
            "reentrancy-eth", kept, "recall regression: real reentrancy was dropped"
        )

    def test_off_strictness_removes_nothing(self):
        result = self._analyze("off")
        self.assertEqual(
            result.false_positives_removed,
            0,
            "default 'off' must preserve raw recall (no orchestrator FP removal)",
        )


if __name__ == "__main__":
    unittest.main()
