"""Tests for structured counterexample parsing (formal verification, phase 1).

Counterexamples arrive from provers as free text; this turns the `name = value`
witnesses into structured bindings a PoC generator can consume, while never
losing the raw text. Sample strings mirror the real formats already asserted in
tests/test_spec_runner.py.
"""

import unittest

from miesc.formal.unified_report import Counterexample, parse_assignments


class TestParseAssignments(unittest.TestCase):
    def test_single_assignment(self):
        self.assertEqual(parse_assignments("amount = 3"), [{"name": "amount", "value": "3"}])

    def test_no_spaces(self):
        self.assertEqual(parse_assignments("x=1"), [{"name": "x", "value": "1"}])

    def test_comma_separated(self):
        out = parse_assignments("x = 0, to = 0xdeadbeef")
        self.assertEqual(out, [{"name": "x", "value": "0"}, {"name": "to", "value": "0xdeadbeef"}])

    def test_multiline(self):
        text = "\n    balance = 100\n    owner = 0x1\n"
        out = parse_assignments(text)
        self.assertEqual([a["name"] for a in out], ["balance", "owner"])

    def test_big_expression_value_preserved(self):
        out = parse_assignments("amount = 2**256 - 1")
        self.assertEqual(out, [{"name": "amount", "value": "2**256 - 1"}])

    def test_huge_decimal(self):
        val = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        self.assertEqual(parse_assignments(f"amount = {val}"), [{"name": "amount", "value": val}])

    def test_no_assignment_returns_empty(self):
        self.assertEqual(parse_assignments("property violated somewhere"), [])

    def test_empty_text(self):
        self.assertEqual(parse_assignments(""), [])


class TestCounterexampleStructured(unittest.TestCase):
    def test_auto_populates_assignments_from_text(self):
        cx = Counterexample(prover="halmos", text="x = 0, amount = 42")
        self.assertEqual(
            cx.assignments, [{"name": "x", "value": "0"}, {"name": "amount", "value": "42"}]
        )

    def test_to_dict_includes_assignments(self):
        cx = Counterexample(prover="halmos", text="v = 1")
        d = cx.to_dict()
        self.assertIn("assignments", d)
        self.assertEqual(d["assignments"], [{"name": "v", "value": "1"}])
        self.assertEqual(d["text"], "v = 1")  # raw text preserved

    def test_explicit_assignments_not_overwritten(self):
        given = [{"name": "custom", "value": "9"}]
        cx = Counterexample(prover="kontrol", text="x = 1", assignments=given)
        self.assertEqual(cx.assignments, given)

    def test_unparseable_text_leaves_empty_assignments(self):
        cx = Counterexample(prover="smtchecker", text="assertion may fail")
        self.assertEqual(cx.assignments, [])
        self.assertEqual(cx.text, "assertion may fail")


if __name__ == "__main__":
    unittest.main()
