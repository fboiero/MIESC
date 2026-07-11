"""
Regression tests for the LLM output location-coercion fix.

Bug: Before v5.1.7, `VulnerabilityFinding.location` was strictly typed as
Optional[CodeLocation]. LLMs in the wild return location as:
  - "function:line" strings
  - bare integers
  - plain function names
  - empty strings

Pydantic rejected all of these, causing SmartLLM / GPTScan to silently
drop every LLM finding ("findings.0.location: Input should be a valid
dictionary or instance of CodeLocation"). This broke the LLM path on the
Rekt benchmark (0 LLM findings returned).

Fix: added a @field_validator(mode='before') that coerces common LLM
shapes into CodeLocation dicts.
"""

from __future__ import annotations

import pytest

from miesc.security.llm_output_validator import CodeLocation, VulnerabilityFinding

BASE = {"type": "reentrancy-eth", "severity": "High", "title": "Reentrancy in withdraw"}


class TestLocationCoercion:
    def test_function_colon_line_string(self):
        f = VulnerabilityFinding(**BASE, location="withdraw:42")
        assert f.location is not None
        assert f.location.function == "withdraw"
        assert f.location.line == 42

    def test_line_prefix_string(self):
        for s in ("L42", "line 42", "line42"):
            f = VulnerabilityFinding(**BASE, location=s)
            assert f.location is not None
            assert f.location.line == 42

    def test_bare_integer(self):
        f = VulnerabilityFinding(**BASE, location=42)
        assert f.location is not None
        assert f.location.line == 42

    def test_plain_function_name(self):
        f = VulnerabilityFinding(**BASE, location="withdraw")
        assert f.location is not None
        assert f.location.function == "withdraw"
        assert f.location.line is None

    def test_well_formed_dict_unchanged(self):
        f = VulnerabilityFinding(**BASE, location={"file": "x.sol", "line": 10})
        assert f.location is not None
        assert f.location.file == "x.sol"
        assert f.location.line == 10

    def test_code_location_instance_passes_through(self):
        loc = CodeLocation(function="withdraw", line=10)
        f = VulnerabilityFinding(**BASE, location=loc)
        assert f.location is not None
        assert f.location.function == "withdraw"

    def test_none_stays_none(self):
        f = VulnerabilityFinding(**BASE, location=None)
        assert f.location is None

    def test_empty_string_becomes_none(self):
        f = VulnerabilityFinding(**BASE, location="")
        assert f.location is None

    def test_integer_out_of_range_stripped(self):
        # Line numbers above 1M are suspicious; CodeLocation's le=1_000_000
        # rejects them. The coercer should not smuggle them in.
        f = VulnerabilityFinding(**BASE, location=2_000_000)
        # Either the coercer dropped the line or pydantic rejected it
        if f.location is not None:
            assert f.location.line is None or f.location.line <= 1_000_000

    def test_unexpected_type_degrades_gracefully(self):
        """A list or nested structure should NOT crash — coerce to None."""
        f = VulnerabilityFinding(**BASE, location=[1, 2, 3])
        assert f.location is None


class TestRegressionBehavior:
    """End-to-end: the same shapes that used to produce 0 findings now
    produce valid VulnerabilityFinding objects."""

    @pytest.mark.parametrize(
        "location",
        [
            "withdraw:15",
            "L22",
            42,
            "myFunction",
            {"function": "myFunction", "line": 42},
            "",
            None,
        ],
    )
    def test_all_shapes_accepted_in_lenient_mode(self, location):
        """All these used to reject. Now they all parse into a valid finding."""
        data = {**BASE, "location": location}
        f = VulnerabilityFinding(**data)
        # Got a finding back (no exception) is the contract
        assert f.type == "reentrancy-eth"
        assert f.severity.lower() == "high"  # validator normalizes case

    def test_list_of_findings_with_mixed_locations(self):
        """Typical LLM output: a list where different findings have
        different location shapes. All should parse."""
        findings_data = [
            {**BASE, "type": "reentrancy-eth", "location": "withdraw:15"},
            {**BASE, "type": "access-control", "location": {"function": "setOwner", "line": 8}},
            {**BASE, "type": "overflow", "location": None},
            {**BASE, "type": "weak-randomness", "location": "lottery:99"},
        ]
        parsed = [VulnerabilityFinding(**d) for d in findings_data]
        assert len(parsed) == 4
        assert parsed[0].location.line == 15
        assert parsed[1].location.function == "setOwner"
        assert parsed[2].location is None
        assert parsed[3].location.line == 99
