"""
Tests for the Code4rena + Sherlock findings-scraper pure parsers
(scripts/code4rena_scraper.py, scripts/sherlock_scraper.py).

Locks the parsing the audit-grade ground-truth depends on — permalink extraction (SHA and
branch refs), severity classification, free-text title -> category, and the Sherlock
severity-folder regex — without any network access.
"""

import importlib.util
import os
import sys

_SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, _SCRIPTS)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_SCRIPTS, f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


c4 = _load("code4rena_scraper")
sh = _load("sherlock_scraper")


# --------------------------------------------------------------------------- #
# Code4rena permalink parsing (commit SHA AND branch ref)
# --------------------------------------------------------------------------- #
class TestParseLocations:
    def test_sha_range(self):
        locs = c4.parse_locations(
            "github.com/code-423n4/2023-05-ajna/blob/a4f9f6c/contracts/Pool.sol#L393-L406")
        assert locs == [{"org": "code-423n4", "repo": "2023-05-ajna", "sha": "a4f9f6c",
                         "path": "contracts/Pool.sol", "lstart": 393, "lend": 406}]

    def test_single_line(self):
        locs = c4.parse_locations("https://github.com/foo/bar/blob/abc1234/src/V.sol#L135")
        assert locs[0]["lstart"] == 135 and locs[0]["lend"] == 135

    def test_branch_ref_and_columns(self):
        # Sherlock pins to a branch (main), and permalinks may carry column suffixes
        locs = c4.parse_locations(
            "github.com/sherlock-audit/x/blob/main/src/T.sol#L10C5-L20C30")
        assert locs[0]["sha"] == "main" and locs[0]["lstart"] == 10 and locs[0]["lend"] == 20

    def test_no_permalink(self):
        assert c4.parse_locations("no link here") == []


# --------------------------------------------------------------------------- #
# Severity classification (labels + title prefix)
# --------------------------------------------------------------------------- #
class TestSeverity:
    def test_from_labels(self):
        assert c4.severity_from([{"name": "3 (High Risk)"}], "x") == "high"
        assert c4.severity_from([{"name": "2 (Med Risk)"}], "x") == "medium"

    def test_qa_gas_are_none(self):
        assert c4.severity_from([{"name": "QA (Quality Assurance)"}], "x") is None
        assert c4.severity_from([], "Gas optimization") is None

    def test_from_title_prefix(self):
        assert c4.severity_from([], "H-01: reentrancy") == "high"
        assert c4.severity_from([], "M-03 something") == "medium"


# --------------------------------------------------------------------------- #
# Free-text title -> our category (noisy; unmapped -> 'other')
# --------------------------------------------------------------------------- #
class TestTitleCategory:
    def test_keyword_map(self):
        assert c4.title_category("Reentrancy in withdraw()") == "reentrancy"
        assert c4.title_category("Integer overflow in mint") == "arithmetic"
        assert c4.title_category("Missing access control on setOwner") == "access_control"
        assert c4.title_category("Unchecked return value of transfer") == "unchecked_low_level_calls"
        assert c4.title_category("Sandwich attack on swap") == "front_running"

    def test_unmapped_is_other(self):
        assert c4.title_category("Weird business logic bug") == "other"


# --------------------------------------------------------------------------- #
# Sherlock severity-folder regex + first-heading title
# --------------------------------------------------------------------------- #
class TestSherlock:
    def test_folder_regex(self):
        assert sh.FOLDER_RE.match("003-H/136-best.md").groups() == ("003", "H", "136-best.md")
        assert sh.FOLDER_RE.match("001-M/168.md").groups() == ("001", "M", "168.md")
        assert sh.FOLDER_RE.match("003.md") is None        # root summary -> skipped
        assert sh.FOLDER_RE.match("005-Low/x.md") is None  # Low -> not [HM]

    def test_first_heading_skips_handle_and_severity(self):
        body = "IllIllI\n\nhigh\n\n# Collateral cannot be claimed\n## Summary"
        assert sh._first_heading(body) == "Collateral cannot be claimed"
