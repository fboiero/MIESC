"""Tests for AlgorandAdapter TEAL/PyTeal parsing and vulnerability detection.

Pure logic — parses temp TEAL/PyTeal files and runs the pattern detectors;
no Algorand node or external tools required.
"""

from __future__ import annotations

from miesc.adapters.algorand_adapter import (
    AlgorandPatternDetector,
    PyTealParser,
    TealParser,
)

TEAL = "#pragma version 6\nint 1\nreturn\n"
PYTEAL = "from pyteal import *\ndef approval():\n    return Approve()\n"


def _teal_program(tmp_path):
    f = tmp_path / "c.teal"
    f.write_text(TEAL, encoding="utf-8")
    return TealParser().parse(str(f))


def _pyteal_contract(tmp_path):
    f = tmp_path / "c.py"
    f.write_text(PYTEAL, encoding="utf-8")
    return PyTealParser().parse(str(f))


class TestTealParsing:
    def test_parse_yields_instructions(self, tmp_path):
        prog = _teal_program(tmp_path)
        assert len(prog.instructions) >= 1

    def test_detect_teal_vulnerabilities(self, tmp_path):
        prog = _teal_program(tmp_path)
        vulns = AlgorandPatternDetector().detect_teal_vulnerabilities(prog, TEAL)
        types = {v.get("type") for v in vulns}
        # A bare approval program lacks rekey/txn-type guards
        assert "missing_sender_check" in types or "unchecked_txn_type" in types


class TestPyTealParsing:
    def test_parse_yields_functions(self, tmp_path):
        contract = _pyteal_contract(tmp_path)
        assert len(contract.functions) >= 1

    def test_detect_pyteal_vulnerabilities(self, tmp_path):
        contract = _pyteal_contract(tmp_path)
        vulns = AlgorandPatternDetector().detect_pyteal_vulnerabilities(contract, PYTEAL)
        types = {v.get("type") for v in vulns}
        assert "rekey_attack" in types or "close_to_attack" in types


class TestPyTealParserHelpers:
    def test_parse_params(self):
        p = PyTealParser()
        params = p._parse_params("amount: int, receiver: str")
        assert len(params) == 2

    def test_parse_imports(self):
        p = PyTealParser()
        imports = p._parse_imports("from pyteal import *\nimport os\n")
        assert isinstance(imports, list)
