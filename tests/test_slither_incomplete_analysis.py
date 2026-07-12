"""Unit tests for Slither incomplete-analysis detection.

Slither can crash on SlithIR generation for a function (common on legacy
Solidity 0.4.x) yet still emit a partial JSON report. When that happens the
detectors silently skip the crashed function, so a real vulnerability there is
a silent miss. `incomplete_functions_from_stderr` surfaces the condition from
Slither's stderr so downstream can fall back to the pattern layer or flag the
contract for manual review.
"""

import unittest

from miesc.adapters.slither_adapter import incomplete_functions_from_stderr


class TestIncompleteAnalysisDetection(unittest.TestCase):
    def test_none_stderr_is_complete(self):
        self.assertEqual(incomplete_functions_from_stderr(None), [])

    def test_empty_stderr_is_complete(self):
        self.assertEqual(incomplete_functions_from_stderr(""), [])

    def test_clean_run_is_complete(self):
        stderr = "Compilation warnings/errors on X.sol:\nWarning: unused variable\n"
        self.assertEqual(incomplete_functions_from_stderr(stderr), [])

    def test_single_ir_failure_detected(self):
        stderr = (
            "Compilation warnings/errors on reentrancy_bonus.sol:\n"
            "Failed to generate IR for Reentrancy_bonus.withdrawReward. "
            "Please open an issue https://github.com/crytic/slither/issues.\n"
            "Reentrancy_bonus.withdrawReward (reentrancy_bonus.sol#16-21):\n"
        )
        result = incomplete_functions_from_stderr(stderr)
        self.assertEqual(len(result), 1)
        self.assertIn("withdrawReward", result[0])

    def test_multiple_ir_failures_all_reported(self):
        stderr = (
            "Failed to generate IR for A.f1.\n"
            "some traceback noise\n"
            "Failed to generate IR for B.f2.\n"
        )
        self.assertEqual(len(incomplete_functions_from_stderr(stderr)), 2)


if __name__ == "__main__":
    unittest.main()
