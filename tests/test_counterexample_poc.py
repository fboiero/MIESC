"""Tests for the counterexample→Foundry PoC scaffold (phase 2).

Pins that the scaffold plugs in the counterexample's exact values with correctly
inferred Solidity types, always produces a well-formed test contract, names the
violated property, and degrades gracefully when no structured inputs are present.
"""

import unittest

from miesc.formal.counterexample_poc import (
    _format_value,
    _infer_type_and_name,
    counterexample_to_foundry_test,
)
from miesc.formal.unified_report import Counterexample


class TestTypeInference(unittest.TestCase):
    def test_halmos_param_naming(self):
        self.assertEqual(_infer_type_and_name("p_amount_uint256"), ("uint256", "amount"))

    def test_halmos_symbolic_with_id(self):
        self.assertEqual(_infer_type_and_name("halmos_to_address_01"), ("address", "to"))

    def test_bool_type(self):
        self.assertEqual(_infer_type_and_name("p_flag_bool"), ("bool", "flag"))

    def test_bytes32(self):
        self.assertEqual(_infer_type_and_name("p_hash_bytes32"), ("bytes32", "hash"))

    def test_bare_uint_defaults_to_256(self):
        self.assertEqual(_infer_type_and_name("p_x_uint"), ("uint256", "x"))

    def test_unknown_name_defaults(self):
        sol_type, name = _infer_type_and_name("amount")
        self.assertEqual(sol_type, "uint256")
        self.assertEqual(name, "amount")


class TestValueFormatting(unittest.TestCase):
    def test_bool(self):
        self.assertEqual(_format_value("0", "bool"), "false")
        self.assertEqual(_format_value("1", "bool"), "true")

    def test_address_hex(self):
        self.assertEqual(_format_value("0xdeadbeef", "address"), "address(0xdeadbeef)")

    def test_address_decimal(self):
        self.assertEqual(_format_value("0", "address"), "address(uint160(0))")

    def test_numeric_passthrough(self):
        self.assertEqual(_format_value("42", "uint256"), "42")


class TestScaffoldGeneration(unittest.TestCase):
    def test_scaffold_has_typed_inputs_with_values(self):
        cx = Counterexample(
            prover="halmos",
            text="p_amount_uint256 = 42, p_to_address = 0x1",
            property="balance never underflows",
        )
        out = counterexample_to_foundry_test(cx, contract_name="Vault")
        # structure
        self.assertIn('import "forge-std/Test.sol";', out)
        self.assertIn("contract VaultCounterexamplePoC is Test", out)
        self.assertIn("balance never underflows", out)
        # typed inputs with the counterexample's exact values
        self.assertIn("uint256 amount = 42;", out)
        self.assertIn("address to = address(0x1);", out)

    def test_scaffold_names_the_test_function(self):
        cx = Counterexample(prover="kontrol", text="x = 1")
        out = counterexample_to_foundry_test(cx, test_name="test_myprop")
        self.assertIn("function test_myprop() public", out)

    def test_no_assignments_falls_back_to_witness_comment(self):
        cx = Counterexample(prover="smtchecker", text="assertion may fail at line 12")
        self.assertEqual(cx.assignments, [])  # unparseable -> empty (phase 1)
        out = counterexample_to_foundry_test(cx)
        self.assertIn("// witness: assertion may fail at line 12", out)
        self.assertIn("is Test", out)  # still a valid contract shell

    def test_duplicate_names_disambiguated(self):
        cx = Counterexample(prover="halmos", text="p_x_uint256 = 1, x = 2")
        out = counterexample_to_foundry_test(cx)
        # both bindings appear; identifiers must not collide
        self.assertIn("uint256 x = 1;", out)
        self.assertIn("x_1 = 2;", out)

    def test_output_is_balanced_braces(self):
        cx = Counterexample(prover="halmos", text="p_a_uint256 = 5")
        out = counterexample_to_foundry_test(cx)
        self.assertEqual(out.count("{"), out.count("}"))


class TestCounterexampleMethod(unittest.TestCase):
    def test_to_foundry_scaffold_method(self):
        cx = Counterexample(prover="halmos", text="p_amount_uint256 = 7", property="no overflow")
        out = cx.to_foundry_scaffold(contract_name="Bank")
        self.assertIn("contract BankCounterexamplePoC is Test", out)
        self.assertIn("uint256 amount = 7;", out)


if __name__ == "__main__":
    unittest.main()
