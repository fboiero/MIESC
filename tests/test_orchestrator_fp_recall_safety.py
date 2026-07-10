"""Recall-safety invariant for the orchestrator FP filter (issue #69).

The ML orchestrator now applies the recall-safe benign-context
FalsePositiveFilter when ``fp_strictness`` is set. The whole point is that it
removes precision-killing benign findings (e.g. ``solc-version``) WITHOUT ever
dropping a real vulnerability such as reentrancy. If a future change makes the
filter drop a true positive, recall silently regresses; these tests guard that.
"""

import unittest

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


if __name__ == "__main__":
    unittest.main()
