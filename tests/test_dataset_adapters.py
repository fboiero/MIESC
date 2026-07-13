"""
Tests for the ground-truth dataset adapters (scripts/dataset_adapters.py).

Locks the pure parsers (SWC->category, DAppSCAN lineNumber) and the SolidiFI adapter's
category/line-range mapping — the bits a wild-eval ground-truth run depends on.
"""

import importlib.util
import json
import os

_SPEC = importlib.util.spec_from_file_location(
    "dataset_adapters",
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts",
        "dataset_adapters.py",
    ),
)
da = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(da)


# --------------------------------------------------------------------------- #
# SWC -> our-category mapping
# --------------------------------------------------------------------------- #
class TestSwcCategory:
    def test_mapped_swcs(self):
        assert da._swc_category("SWC-107-Reentrancy") == "reentrancy"
        assert da._swc_category("SWC-101-Integer Overflow") == "arithmetic"
        assert da._swc_category("SWC-104-Unchecked Call") == "unchecked_low_level_calls"
        assert da._swc_category("SWC-116-Timestamp") == "time_manipulation"

    def test_unmapped_swc_kept_inert(self):
        # an unmapped SWC must be kept as swc-<n> so it never falsely anchors
        assert da._swc_category("SWC-135-Code With No Effects") == "swc-135"

    def test_no_swc_falls_back_to_raw(self):
        assert da._swc_category("some-other-thing") == "some-other-thing"


# --------------------------------------------------------------------------- #
# DAppSCAN lineNumber parsing: 'L74' | 'L45-47' | 74
# --------------------------------------------------------------------------- #
class TestParseLineNumber:
    def test_single(self):
        assert da._parse_linenumber("L74") == [74]

    def test_range_expands(self):
        assert da._parse_linenumber("L45-47") == [45, 46, 47]

    def test_plain_int_string(self):
        assert da._parse_linenumber("3") == [3]

    def test_garbage_is_empty(self):
        assert da._parse_linenumber("Lx") == []
        assert da._parse_linenumber("") == []


# --------------------------------------------------------------------------- #
# SolidiFI adapter: BugLog loc/length -> line range, label from folder
# --------------------------------------------------------------------------- #
class _Args:
    pass


def test_solidifi_adapter_maps_category_and_line_range(tmp_path):
    rdir = tmp_path / "buggy_contracts" / "Re-entrancy"
    rdir.mkdir(parents=True)
    (rdir / "buggy_1.sol").write_text("pragma solidity ^0.5.0; contract C {}\n")
    # CSV bug-type value is UTF-7-mangled for Re-entrancy -> adapter must use the FOLDER
    (rdir / "BugLog_1.csv").write_text(
        "loc,length,bug type,approach\n10,8,Re+AC0-erntrancy,code snippet injection\n"
    )
    a = _Args()
    a.repo = str(tmp_path)
    a.out_corpus = str(tmp_path / "corpus")
    a.out_gt = str(tmp_path / "gt.json")
    assert da.adapt_solidifi(a) == 0

    gt = json.load(open(a.out_gt))
    assert len(gt) == 1
    entry = gt[0]
    assert entry["path"] == "Re-entrancy__buggy_1.sol"
    vuln = entry["vulnerabilities"][0]
    assert vuln["category"] == "reentrancy"  # from folder, not the mangled CSV value
    assert vuln["lines"] == list(range(10, 18))  # loc=10, length=8 -> [10..17]
    assert os.path.exists(os.path.join(a.out_corpus, "Re-entrancy__buggy_1.sol"))
