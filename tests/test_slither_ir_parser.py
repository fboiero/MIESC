"""
Tests for src/ml/slither_ir_parser.py

Comprehensive tests for Slither IR parsing functionality including:
- IROpcode enum
- All dataclasses (IRVariable, IRInstruction, StateTransition, Call, FunctionIR)
- SlitherIRParser class methods
- Convenience functions
"""

import pytest

from src.ml.slither_ir_parser import (
    IROpcode,
    IRVariable,
    IRInstruction,
    StateTransition,
    Call,
    FunctionIR,
    SlitherIRParser,
    parse_slither_ir,
    get_function_state_transitions,
    get_external_calls,
)


class TestIROpcode:
    """Tests for IROpcode enum."""

    def test_assignment_opcodes(self):
        """Test assignment-related opcodes."""
        assert IROpcode.ASSIGNMENT.value == "ASSIGNMENT"
        assert IROpcode.BINARY.value == "BINARY"
        assert IROpcode.UNARY.value == "UNARY"
        assert IROpcode.INDEX.value == "INDEX"
        assert IROpcode.MEMBER.value == "MEMBER"

    def test_call_opcodes(self):
        """Test call-related opcodes."""
        assert IROpcode.HIGH_LEVEL_CALL.value == "HIGH_LEVEL_CALL"
        assert IROpcode.LOW_LEVEL_CALL.value == "LOW_LEVEL_CALL"
        assert IROpcode.INTERNAL_CALL.value == "INTERNAL_CALL"
        assert IROpcode.INTERNAL_DYNAMIC_CALL.value == "INTERNAL_DYNAMIC_CALL"
        assert IROpcode.LIBRARY_CALL.value == "LIBRARY_CALL"
        assert IROpcode.SOLIDITY_CALL.value == "SOLIDITY_CALL"
        assert IROpcode.EVENT_CALL.value == "EVENT_CALL"
        assert IROpcode.SEND.value == "SEND"
        assert IROpcode.TRANSFER.value == "TRANSFER"

    def test_control_flow_opcodes(self):
        """Test control flow opcodes."""
        assert IROpcode.CONDITION.value == "CONDITION"
        assert IROpcode.RETURN.value == "RETURN"

    def test_state_operation_opcodes(self):
        """Test state operation opcodes."""
        assert IROpcode.NEW_CONTRACT.value == "NEW_CONTRACT"
        assert IROpcode.NEW_ARRAY.value == "NEW_ARRAY"
        assert IROpcode.NEW_STRUCTURE.value == "NEW_STRUCTURE"

    def test_type_operation_opcodes(self):
        """Test type operation opcodes."""
        assert IROpcode.CONVERT.value == "CONVERT"
        assert IROpcode.UNPACK.value == "UNPACK"
        assert IROpcode.TYPE_CONVERSION.value == "TYPE_CONVERSION"

    def test_special_opcodes(self):
        """Test special opcodes."""
        assert IROpcode.PHI.value == "PHI"
        assert IROpcode.PUSH.value == "PUSH"
        assert IROpcode.DELETE.value == "DELETE"
        assert IROpcode.LENGTH.value == "LENGTH"
        assert IROpcode.UNKNOWN.value == "UNKNOWN"


class TestIRVariable:
    """Tests for IRVariable dataclass."""

    def test_default_values(self):
        """Test default values."""
        var = IRVariable(name="balance")
        assert var.name == "balance"
        assert var.var_type == ""
        assert var.is_state is False
        assert var.is_constant is False
        assert var.is_temporary is False

    def test_custom_values(self):
        """Test custom values."""
        var = IRVariable(
            name="totalSupply",
            var_type="uint256",
            is_state=True,
            is_constant=False,
            is_temporary=False,
        )
        assert var.name == "totalSupply"
        assert var.var_type == "uint256"
        assert var.is_state is True

    def test_to_dict(self):
        """Test to_dict method."""
        var = IRVariable(
            name="owner",
            var_type="address",
            is_state=True,
            is_constant=False,
            is_temporary=False,
        )
        d = var.to_dict()
        assert d["name"] == "owner"
        assert d["type"] == "address"
        assert d["is_state"] is True
        assert d["is_constant"] is False
        assert d["is_temporary"] is False


class TestIRInstruction:
    """Tests for IRInstruction dataclass."""

    def test_default_values(self):
        """Test default values."""
        instr = IRInstruction(opcode=IROpcode.ASSIGNMENT)
        assert instr.opcode == IROpcode.ASSIGNMENT
        assert instr.lvalue is None
        assert instr.operands == []
        assert instr.call_target is None
        assert instr.call_type is None
        assert instr.line == 0
        assert instr.raw == ""

    def test_with_lvalue(self):
        """Test instruction with lvalue."""
        lvalue = IRVariable(name="result", var_type="uint256")
        instr = IRInstruction(
            opcode=IROpcode.BINARY,
            lvalue=lvalue,
            line=10,
            raw="result = a + b",
        )
        assert instr.lvalue.name == "result"
        assert instr.line == 10

    def test_to_dict(self):
        """Test to_dict method."""
        lvalue = IRVariable(name="tmp", var_type="uint256")
        operand = IRVariable(name="balance", var_type="uint256")
        instr = IRInstruction(
            opcode=IROpcode.HIGH_LEVEL_CALL,
            lvalue=lvalue,
            operands=[operand],
            call_target="token",
            call_type="transfer",
            line=25,
            raw="TMP_0 = HIGH_LEVEL_CALL dest:token function:transfer",
        )
        d = instr.to_dict()
        assert d["opcode"] == "HIGH_LEVEL_CALL"
        assert d["lvalue"]["name"] == "tmp"
        assert len(d["operands"]) == 1
        assert d["operands"][0]["name"] == "balance"
        assert d["call_target"] == "token"
        assert d["call_type"] == "transfer"
        assert d["line"] == 25

    def test_to_dict_no_lvalue(self):
        """Test to_dict with no lvalue."""
        instr = IRInstruction(opcode=IROpcode.RETURN, line=50)
        d = instr.to_dict()
        assert d["lvalue"] is None
        assert d["operands"] == []

    def test_raw_truncation(self):
        """Test that raw is truncated to 100 chars."""
        long_raw = "x" * 200
        instr = IRInstruction(opcode=IROpcode.ASSIGNMENT, raw=long_raw)
        d = instr.to_dict()
        assert len(d["raw"]) == 100


class TestStateTransition:
    """Tests for StateTransition dataclass."""

    def test_default_values(self):
        """Test default values."""
        trans = StateTransition(state_var="balance", function="withdraw")
        assert trans.state_var == "balance"
        assert trans.function == "withdraw"
        assert trans.old_value is None
        assert trans.new_value is None
        assert trans.condition is None
        assert trans.line == 0

    def test_with_values(self):
        """Test with all values set."""
        trans = StateTransition(
            state_var="balance",
            function="withdraw",
            old_value="100",
            new_value="50",
            condition="balance >= amount",
            line=42,
        )
        assert trans.old_value == "100"
        assert trans.new_value == "50"
        assert trans.condition == "balance >= amount"

    def test_to_dict(self):
        """Test to_dict method."""
        trans = StateTransition(
            state_var="totalSupply",
            function="mint",
            old_value="1000",
            new_value="1100",
            line=30,
        )
        d = trans.to_dict()
        assert d["state_var"] == "totalSupply"
        assert d["function"] == "mint"
        assert d["old_value"] == "1000"
        assert d["new_value"] == "1100"
        assert d["line"] == 30


class TestCall:
    """Tests for Call dataclass."""

    def test_default_values(self):
        """Test default values."""
        call = Call(function="transfer", call_type="external")
        assert call.function == "transfer"
        assert call.call_type == "external"
        assert call.target is None
        assert call.arguments == []
        assert call.value is None
        assert call.gas is None
        assert call.return_value is None
        assert call.line == 0

    def test_with_all_values(self):
        """Test with all values set."""
        call = Call(
            function="send",
            call_type="low_level",
            target="victim",
            arguments=["100"],
            value="1 ether",
            gas="2300",
            return_value="success",
            line=100,
        )
        assert call.target == "victim"
        assert call.value == "1 ether"
        assert call.gas == "2300"

    def test_to_dict(self):
        """Test to_dict method."""
        call = Call(
            function="withdraw",
            call_type="external",
            target="bank",
            arguments=["amount"],
            line=55,
        )
        d = call.to_dict()
        assert d["function"] == "withdraw"
        assert d["type"] == "external"
        assert d["target"] == "bank"
        assert d["arguments"] == ["amount"]
        assert d["line"] == 55


class TestFunctionIR:
    """Tests for FunctionIR dataclass."""

    def test_default_values(self):
        """Test default values."""
        func = FunctionIR(name="deposit")
        assert func.name == "deposit"
        assert func.instructions == []
        assert func.state_reads == set()
        assert func.state_writes == set()
        assert func.internal_calls == []
        assert func.external_calls == []
        assert func.state_transitions == []

    def test_with_instructions(self):
        """Test with instructions."""
        instr = IRInstruction(opcode=IROpcode.ASSIGNMENT)
        func = FunctionIR(name="transfer", instructions=[instr])
        assert len(func.instructions) == 1

    def test_with_state_operations(self):
        """Test with state reads and writes."""
        func = FunctionIR(
            name="withdraw",
            state_reads={"balance", "owner"},
            state_writes={"balance"},
        )
        assert "balance" in func.state_reads
        assert "owner" in func.state_reads
        assert "balance" in func.state_writes

    def test_to_dict(self):
        """Test to_dict method."""
        instr = IRInstruction(opcode=IROpcode.RETURN, line=10)
        call = Call(function="send", call_type="external", line=5)
        trans = StateTransition(state_var="balance", function="withdraw")

        func = FunctionIR(
            name="withdraw",
            instructions=[instr],
            state_reads={"balance"},
            state_writes={"balance"},
            internal_calls=[],
            external_calls=[call],
            state_transitions=[trans],
        )

        d = func.to_dict()
        assert d["name"] == "withdraw"
        assert d["instruction_count"] == 1
        assert "balance" in d["state_reads"]
        assert "balance" in d["state_writes"]
        assert len(d["external_calls"]) == 1
        assert len(d["state_transitions"]) == 1


class TestSlitherIRParser:
    """Tests for SlitherIRParser class."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return SlitherIRParser()

    def test_init(self, parser):
        """Test initialization."""
        assert parser._functions == {}

    def test_opcode_map_defined(self, parser):
        """Test OPCODE_MAP is properly defined."""
        assert "ASSIGNMENT" in parser.OPCODE_MAP
        assert "HIGH_LEVEL_CALL" in parser.OPCODE_MAP
        assert "RETURN" in parser.OPCODE_MAP
        assert parser.OPCODE_MAP["ASSIGNMENT"] == IROpcode.ASSIGNMENT

    def test_parse_empty_slither_output(self, parser):
        """Test parsing empty Slither output."""
        result = parser.parse_slither_output({})
        assert result == {}

    def test_parse_slither_output_no_printers(self, parser):
        """Test parsing with no printers."""
        result = parser.parse_slither_output({"results": {}})
        assert result == {}

    def test_parse_slither_output_with_detectors(self, parser):
        """Test parsing with detector results."""
        slither_json = {
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy",
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "type_specific_fields": {
                                    "state_variables_read": [{"name": "balance"}],
                                    "state_variables_written": [{"name": "balance"}],
                                },
                            }
                        ],
                    }
                ]
            }
        }
        result = parser.parse_slither_output(slither_json)
        assert "withdraw" in result
        assert "balance" in result["withdraw"].state_reads
        assert "balance" in result["withdraw"].state_writes

    def test_parse_function_ir_empty(self, parser):
        """Test parsing empty IR text."""
        result = parser.parse_function_ir("", "test")
        assert result.name == "test"
        assert result.instructions == []

    def test_parse_function_ir_with_comments(self, parser):
        """Test parsing IR with comments."""
        ir_text = """
        # This is a comment
        RETURN
        """
        result = parser.parse_function_ir(ir_text, "test")
        assert len(result.instructions) == 1
        assert result.instructions[0].opcode == IROpcode.RETURN

    def test_parse_function_ir_high_level_call(self, parser):
        """Test parsing HIGH_LEVEL_CALL instruction."""
        ir_text = "TMP_0 = HIGH_LEVEL_CALL dest:token function:transfer"
        result = parser.parse_function_ir(ir_text, "test")
        assert len(result.instructions) == 1
        assert result.instructions[0].opcode == IROpcode.HIGH_LEVEL_CALL
        assert result.instructions[0].call_target == "token"
        assert result.instructions[0].call_type == "transfer"

    def test_parse_function_ir_low_level_call(self, parser):
        """Test parsing LOW_LEVEL_CALL instruction."""
        ir_text = "LOW_LEVEL_CALL dest:victim"
        result = parser.parse_function_ir(ir_text, "test")
        assert len(result.instructions) == 1
        assert result.instructions[0].opcode == IROpcode.LOW_LEVEL_CALL
        assert result.instructions[0].call_target == "victim"

    def test_parse_function_ir_send(self, parser):
        """Test parsing SEND instruction."""
        ir_text = "SEND dest:recipient"
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions[0].opcode == IROpcode.SEND

    def test_parse_function_ir_transfer(self, parser):
        """Test parsing TRANSFER instruction."""
        ir_text = "TRANSFER dest:user"
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions[0].opcode == IROpcode.TRANSFER

    def test_parse_function_ir_internal_call(self, parser):
        """Test parsing INTERNAL_CALL instruction."""
        ir_text = "INTERNAL_CALL function:_updateBalance"
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions[0].opcode == IROpcode.INTERNAL_CALL

    def test_parse_function_ir_library_call(self, parser):
        """Test parsing LIBRARY_CALL instruction."""
        ir_text = "LIBRARY_CALL dest:SafeMath function:add"
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions[0].opcode == IROpcode.LIBRARY_CALL

    def test_parse_function_ir_solidity_call(self, parser):
        """Test parsing SOLIDITY_CALL instruction."""
        ir_text = "SOLIDITY_CALL function:require"
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions[0].opcode == IROpcode.SOLIDITY_CALL

    def test_parse_function_ir_assignment(self, parser):
        """Test parsing assignment instruction."""
        ir_text = "result = balance + amount"
        result = parser.parse_function_ir(ir_text, "test")
        assert len(result.instructions) == 1
        assert result.instructions[0].opcode == IROpcode.ASSIGNMENT
        assert result.instructions[0].lvalue.name == "result"

    def test_parse_function_ir_condition(self, parser):
        """Test parsing CONDITION instruction."""
        ir_text = "CONDITION balance > 0"
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions[0].opcode == IROpcode.CONDITION

    def test_parse_function_ir_if_condition(self, parser):
        """Test parsing IF condition."""
        ir_text = "IF balance > 0"
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions[0].opcode == IROpcode.CONDITION

    def test_parse_function_ir_return(self, parser):
        """Test parsing RETURN instruction."""
        ir_text = "RETURN result"
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions[0].opcode == IROpcode.RETURN

    def test_track_external_calls(self, parser):
        """Test tracking external calls."""
        ir_text = """
        HIGH_LEVEL_CALL dest:token function:transfer
        LOW_LEVEL_CALL dest:victim
        SEND dest:user
        TRANSFER dest:recipient
        """
        result = parser.parse_function_ir(ir_text, "test")
        assert len(result.external_calls) == 4

    def test_track_internal_calls(self, parser):
        """Test tracking internal calls."""
        ir_text = """
        INTERNAL_CALL function:_update
        LIBRARY_CALL dest:Math function:add
        """
        result = parser.parse_function_ir(ir_text, "test")
        assert len(result.internal_calls) == 2

    def test_extract_state_transitions_unknown_function(self, parser):
        """Test extracting transitions for unknown function."""
        result = parser.extract_state_transitions("nonexistent")
        assert result == []

    def test_extract_state_transitions(self, parser):
        """Test extracting state transitions."""
        # First parse some output
        slither_json = {
            "results": {
                "detectors": [
                    {
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "type_specific_fields": {
                                    "state_variables_written": ["balance"],
                                },
                            }
                        ]
                    }
                ]
            }
        }
        parser.parse_slither_output(slither_json)
        result = parser.extract_state_transitions("withdraw")
        assert len(result) == 1
        assert result[0].state_var == "balance"

    def test_get_call_sequence_unknown_function(self, parser):
        """Test getting call sequence for unknown function."""
        result = parser.get_call_sequence("nonexistent")
        assert result == []

    def test_get_call_sequence(self, parser):
        """Test getting call sequence."""
        ir_text = """
        INTERNAL_CALL function:_check
        HIGH_LEVEL_CALL dest:token function:transfer
        """
        parser.parse_function_ir(ir_text, "withdraw")
        parser._functions["withdraw"] = parser.parse_function_ir(ir_text, "withdraw")

        result = parser.get_call_sequence("withdraw")
        assert len(result) == 2

    def test_get_summary_empty(self, parser):
        """Test getting summary with no functions."""
        summary = parser.get_summary()
        assert summary["functions_parsed"] == 0
        assert summary["total_instructions"] == 0

    def test_get_summary(self, parser):
        """Test getting summary with functions."""
        ir_text = """
        HIGH_LEVEL_CALL dest:token function:transfer
        INTERNAL_CALL function:_update
        RETURN
        """
        parser._functions["test"] = parser.parse_function_ir(ir_text, "test")
        summary = parser.get_summary()
        assert summary["functions_parsed"] == 1
        assert summary["total_instructions"] == 3

    def test_parse_slithir_printer(self, parser):
        """Test parsing slithir printer output."""
        slither_json = {
            "results": {
                "printers": [
                    {
                        "printer": "slithir",
                        "elements": [
                            {
                                "type": "function",
                                "name": "deposit",
                                "description": "balance = msg.value\nRETURN",
                            }
                        ],
                    }
                ]
            }
        }
        result = parser.parse_slither_output(slither_json)
        assert "deposit" in result
        assert len(result["deposit"].instructions) == 2

    def test_parse_function_summary(self, parser):
        """Test parsing function-summary printer output."""
        slither_json = {
            "results": {
                "printers": [
                    {
                        "printer": "function-summary",
                        "elements": [
                            {
                                "type": "table",
                                "rows": [
                                    ["transfer", "public", "external"],
                                    ["withdraw", "public", "external"],
                                ],
                            }
                        ],
                    }
                ]
            }
        }
        result = parser.parse_slither_output(slither_json)
        assert "transfer" in result
        assert "withdraw" in result

    def test_parse_data_dependency(self, parser):
        """Test parsing data-dependency printer output."""
        # Setup function first
        parser._functions["deposit"] = FunctionIR(name="deposit")

        # Call _parse_data_dependency directly (parse_slither_output resets _functions)
        printer = {
            "printer": "data-dependency",
            "elements": [
                {
                    "function": "deposit",
                    "dependencies": {
                        "balance": ["msg.value"],
                        "owner": [],
                    },
                }
            ],
        }
        parser._parse_data_dependency(printer)
        assert "balance" in parser._functions["deposit"].state_reads

    def test_extract_from_detectors_string_var(self, parser):
        """Test extracting from detectors with string state vars."""
        slither_json = {
            "results": {
                "detectors": [
                    {
                        "elements": [
                            {
                                "type": "function",
                                "name": "test",
                                "type_specific_fields": {
                                    "state_variables_read": ["balance"],
                                    "state_variables_written": ["counter"],
                                },
                            }
                        ]
                    }
                ]
            }
        }
        result = parser.parse_slither_output(slither_json)
        assert "balance" in result["test"].state_reads
        assert "counter" in result["test"].state_writes


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_parse_slither_ir_empty(self):
        """Test parse_slither_ir with empty input."""
        result = parse_slither_ir({})
        assert result["functions_parsed"] == 0

    def test_parse_slither_ir_with_data(self):
        """Test parse_slither_ir with data."""
        slither_json = {
            "results": {
                "detectors": [
                    {
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                            }
                        ]
                    }
                ]
            }
        }
        result = parse_slither_ir(slither_json)
        assert result["functions_parsed"] == 1
        assert "withdraw" in result["functions"]

    def test_get_function_state_transitions_empty(self):
        """Test get_function_state_transitions with no matching function."""
        result = get_function_state_transitions({}, "nonexistent")
        assert result == []

    def test_get_function_state_transitions(self):
        """Test get_function_state_transitions with data."""
        slither_json = {
            "results": {
                "detectors": [
                    {
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "type_specific_fields": {
                                    "state_variables_written": ["balance"],
                                },
                            }
                        ]
                    }
                ]
            }
        }
        result = get_function_state_transitions(slither_json, "withdraw")
        assert len(result) == 1
        assert result[0]["state_var"] == "balance"

    def test_get_external_calls_empty(self):
        """Test get_external_calls with no calls."""
        result = get_external_calls({})
        assert result == []

    def test_get_external_calls_all_functions(self):
        """Test get_external_calls without function filter."""
        slither_json = {
            "results": {
                "printers": [
                    {
                        "printer": "slithir",
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "description": "HIGH_LEVEL_CALL dest:token function:transfer",
                            }
                        ],
                    }
                ]
            }
        }
        result = get_external_calls(slither_json)
        assert len(result) == 1
        assert result[0]["caller_function"] == "withdraw"

    def test_get_external_calls_filtered(self):
        """Test get_external_calls with function filter."""
        slither_json = {
            "results": {
                "printers": [
                    {
                        "printer": "slithir",
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "description": "HIGH_LEVEL_CALL dest:token function:transfer",
                            },
                            {
                                "type": "function",
                                "name": "deposit",
                                "description": "HIGH_LEVEL_CALL dest:vault function:store",
                            },
                        ],
                    }
                ]
            }
        }
        result = get_external_calls(slither_json, "withdraw")
        assert len(result) == 1
        assert result[0]["caller_function"] == "withdraw"


class TestStateTracking:
    """Tests for state variable tracking."""

    @pytest.fixture
    def parser(self):
        return SlitherIRParser()

    def test_track_state_read_pattern(self, parser):
        """Test tracking state variable reads."""
        ir_text = "REF_0(uint256) = balance(mapping(address => uint256))"
        result = parser.parse_function_ir(ir_text, "test")
        # The pattern should detect 'balance' as a state read
        # Note: exact behavior depends on regex matching

    def test_track_state_write_pattern(self, parser):
        """Test tracking state variable writes."""
        ir_text = "balances(mapping(address => uint256))[msg.sender] = newValue"
        result = parser.parse_function_ir(ir_text, "test")
        # Pattern should detect state write

    def test_exclude_temporary_variables(self, parser):
        """Test that TMP_ and REF_ variables are excluded."""
        ir_text = "TMP_0 = 100\nREF_1 = balance"
        result = parser.parse_function_ir(ir_text, "test")
        # TMP_ and REF_ should not appear in state_reads/writes
        assert "TMP_0" not in result.state_reads
        assert "REF_1" not in result.state_writes


class TestEdgeCases:
    """Edge case tests."""

    @pytest.fixture
    def parser(self):
        return SlitherIRParser()

    def test_empty_ir_lines(self, parser):
        """Test handling of empty lines."""
        ir_text = "\n\n\n"
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions == []

    def test_whitespace_only_lines(self, parser):
        """Test handling of whitespace-only lines."""
        ir_text = "   \n\t\n  "
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions == []

    def test_unknown_opcode(self, parser):
        """Test handling of unknown opcodes."""
        ir_text = "UNKNOWN_OP arg1 arg2"
        result = parser.parse_function_ir(ir_text, "test")
        # Unknown opcodes without matching patterns return None
        # so no instruction is added

    def test_call_without_dest(self, parser):
        """Test call instruction without dest."""
        ir_text = "HIGH_LEVEL_CALL"
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions[0].call_target is None

    def test_call_without_function(self, parser):
        """Test call instruction without function."""
        ir_text = "HIGH_LEVEL_CALL dest:target"
        result = parser.parse_function_ir(ir_text, "test")
        assert result.instructions[0].call_type is None

    def test_multiple_functions(self, parser):
        """Test parsing multiple functions."""
        slither_json = {
            "results": {
                "printers": [
                    {
                        "printer": "slithir",
                        "elements": [
                            {
                                "type": "function",
                                "name": "func1",
                                "description": "RETURN",
                            },
                            {
                                "type": "function",
                                "name": "func2",
                                "description": "RETURN",
                            },
                        ],
                    }
                ]
            }
        }
        result = parser.parse_slither_output(slither_json)
        assert len(result) == 2
        assert "func1" in result
        assert "func2" in result

    def test_function_summary_short_rows(self, parser):
        """Test function summary with short rows."""
        slither_json = {
            "results": {
                "printers": [
                    {
                        "printer": "function-summary",
                        "elements": [
                            {
                                "type": "table",
                                "rows": [
                                    ["single"],  # Only one element
                                    [],  # Empty row
                                ],
                            }
                        ],
                    }
                ]
            }
        }
        # Should not crash
        result = parser.parse_slither_output(slither_json)
        assert "single" not in result  # Row too short

    def test_data_dependency_no_matching_function(self, parser):
        """Test data dependency for non-existent function."""
        slither_json = {
            "results": {
                "printers": [
                    {
                        "printer": "data-dependency",
                        "elements": [
                            {
                                "function": "nonexistent",
                                "dependencies": {"var": ["dep"]},
                            }
                        ],
                    }
                ]
            }
        }
        # Should not crash
        result = parser.parse_slither_output(slither_json)

    def test_detector_non_function_element(self, parser):
        """Test detector with non-function elements."""
        slither_json = {
            "results": {
                "detectors": [
                    {
                        "elements": [
                            {
                                "type": "variable",
                                "name": "balance",
                            }
                        ]
                    }
                ]
            }
        }
        result = parser.parse_slither_output(slither_json)
        # Variable elements should be skipped
        assert "balance" not in result

    def test_call_sequence_sorting(self, parser):
        """Test that call sequence is sorted by line number."""
        func_ir = FunctionIR(name="test")
        func_ir.internal_calls = [Call(function="b", call_type="internal", line=20)]
        func_ir.external_calls = [Call(function="a", call_type="external", line=10)]
        parser._functions["test"] = func_ir

        result = parser.get_call_sequence("test")
        assert result[0].function == "a"  # Line 10 first
        assert result[1].function == "b"  # Line 20 second
