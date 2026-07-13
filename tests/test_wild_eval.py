"""
Tests for the wild benign-context eval harness pure logic
(scripts/wild_benign_context_eval.py): ground-truth anchoring, MIESC category
normalization, and vulnerabilities.json loading. No solc / no network.
"""

import importlib.util
import json
import os
import sys

_SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, _SCRIPTS)
_SPEC = importlib.util.spec_from_file_location(
    "wild_benign_context_eval", os.path.join(_SCRIPTS, "wild_benign_context_eval.py")
)
w = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(w)


# --------------------------------------------------------------------------- #
# anchored_real: a finding is REAL iff category + line match an annotated vuln
# --------------------------------------------------------------------------- #
class TestAnchoredReal:
    VULNS = [
        {"category": "reentrancy", "lines": [10, 11]},
        {"category": "access_control", "lines": []},
    ]

    def test_exact_line_match(self):
        assert w.anchored_real({"type": "reentrancy", "line": 10}, self.VULNS) is True

    def test_wrong_category(self):
        assert w.anchored_real({"type": "arithmetic", "line": 10}, self.VULNS) is False

    def test_far_line_no_anchor_exact(self):
        assert w.anchored_real({"type": "reentrancy", "line": 40}, self.VULNS) is False

    def test_window_tolerates_offset(self):
        assert w.anchored_real({"type": "reentrancy", "line": 12}, self.VULNS, window=2) is True

    def test_category_without_lines_is_conservative_true(self):
        # access_control annotated with no lines -> conservatively real (never inflates)
        assert w.anchored_real({"type": "access_control", "line": 5}, self.VULNS) is True


# --------------------------------------------------------------------------- #
# _norm_miesc: internal detector categories -> the anchor vocabulary
# --------------------------------------------------------------------------- #
class TestNormMiesc:
    def test_prefix_families(self):
        assert w._norm_miesc("reentrancy_crossfunction") == "reentrancy"
        assert w._norm_miesc("bad_randomness_blockhash") == "bad_randomness"
        assert w._norm_miesc("dos_push_unbounded") == "denial_of_service"
        assert w._norm_miesc("access_control_initwallet") == "access_control"

    def test_explicit_map(self):
        assert w._norm_miesc("unchecked_call_pattern") == "unchecked_low_level_calls"
        assert w._norm_miesc("rounding_error_division") == "arithmetic"

    def test_passthrough(self):
        assert w._norm_miesc("time_manipulation") == "time_manipulation"
        assert w._norm_miesc("front_running") == "front_running"


# --------------------------------------------------------------------------- #
# load_ground_truth: vulnerabilities.json -> (vuln_idx, clean_set)
# --------------------------------------------------------------------------- #
def test_load_ground_truth_splits_vuln_and_clean(tmp_path):
    gt = tmp_path / "vulnerabilities.json"
    gt.write_text(
        json.dumps(
            [
                {
                    "path": "dir/Vuln.sol",
                    "vulnerabilities": [{"category": "reentrancy", "lines": [5]}],
                },
                {"path": "dir/Clean.sol", "vulnerabilities": [], "clean": True},
            ]
        )
    )
    vuln_idx, clean = w.load_ground_truth(str(gt))
    assert "Vuln.sol" in vuln_idx
    assert vuln_idx["Vuln.sol"][0]["category"] == "reentrancy"
    assert "Clean.sol" in clean
    assert "Vuln.sol" not in clean
