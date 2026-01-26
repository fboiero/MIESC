"""
MIESC Slither IR Parser v4.6.0
==============================

Parses Slither's Intermediate Representation (SlithIR) for advanced analysis.
Enables detailed understanding of contract behavior beyond regex patterns.

Features:
- SlithIR instruction parsing
- State transition extraction
- Call sequence analysis
- Control flow understanding
- Data dependency tracking

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
License: AGPL-3.0
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class IROpcode(Enum):
    """SlithIR opcodes."""
    # Assignments
    ASSIGNMENT = "ASSIGNMENT"
    BINARY = "BINARY"
    UNARY = "UNARY"
    INDEX = "INDEX"
    MEMBER = "MEMBER"

    # Calls
    HIGH_LEVEL_CALL = "HIGH_LEVEL_CALL"
    LOW_LEVEL_CALL = "LOW_LEVEL_CALL"
    INTERNAL_CALL = "INTERNAL_CALL"
    INTERNAL_DYNAMIC_CALL = "INTERNAL_DYNAMIC_CALL"
    LIBRARY_CALL = "LIBRARY_CALL"
    SOLIDITY_CALL = "SOLIDITY_CALL"
    EVENT_CALL = "EVENT_CALL"
    SEND = "SEND"
    TRANSFER = "TRANSFER"

    # Control flow
    CONDITION = "CONDITION"
    RETURN = "RETURN"

    # State operations
    NEW_CONTRACT = "NEW_CONTRACT"
    NEW_ARRAY = "NEW_ARRAY"
    NEW_STRUCTURE = "NEW_STRUCTURE"

    # Type operations
    CONVERT = "CONVERT"
    UNPACK = "UNPACK"
    TYPE_CONVERSION = "TYPE_CONVERSION"

    # Special
    PHI = "PHI"
    PUSH = "PUSH"
    DELETE = "DELETE"
    LENGTH = "LENGTH"

    # Unknown
    UNKNOWN = "UNKNOWN"


@dataclass
class IRVariable:
    """Represents a variable in SlithIR."""
    name: str
    var_type: str = ""
    is_state: bool = False
    is_constant: bool = False
    is_temporary: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'type': self.var_type,
            'is_state': self.is_state,
            'is_constant': self.is_constant,
            'is_temporary': self.is_temporary,
        }


@dataclass
class IRInstruction:
    """
    Represents a single SlithIR instruction.

    Example IR instructions:
    - "REF_0(uint256) = balance(mapping(address => uint256)) (msg.sender)"
    - "TMP_0(bool) = LOW_LEVEL_CALL, dest:victim, ..."
    """
    opcode: IROpcode
    lvalue: Optional[IRVariable] = None
    operands: List[IRVariable] = field(default_factory=list)
    call_target: Optional[str] = None
    call_type: Optional[str] = None
    line: int = 0
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'opcode': self.opcode.value,
            'lvalue': self.lvalue.to_dict() if self.lvalue else None,
            'operands': [o.to_dict() for o in self.operands],
            'call_target': self.call_target,
            'call_type': self.call_type,
            'line': self.line,
            'raw': self.raw[:100] if self.raw else "",
        }


@dataclass
class StateTransition:
    """
    Represents a state variable modification.

    Tracks which state variables are modified, by which function,
    and under what conditions.
    """
    state_var: str
    function: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    condition: Optional[str] = None
    line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'state_var': self.state_var,
            'function': self.function,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'condition': self.condition,
            'line': self.line,
        }


@dataclass
class Call:
    """Represents a function call (internal or external)."""
    function: str
    call_type: str  # "internal", "external", "library", "high_level", "low_level"
    target: Optional[str] = None
    arguments: List[str] = field(default_factory=list)
    value: Optional[str] = None  # ETH value sent
    gas: Optional[str] = None
    return_value: Optional[str] = None
    line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function': self.function,
            'type': self.call_type,
            'target': self.target,
            'arguments': self.arguments,
            'value': self.value,
            'gas': self.gas,
            'return_value': self.return_value,
            'line': self.line,
        }


@dataclass
class FunctionIR:
    """SlithIR representation of a function."""
    name: str
    instructions: List[IRInstruction] = field(default_factory=list)
    state_reads: Set[str] = field(default_factory=set)
    state_writes: Set[str] = field(default_factory=set)
    internal_calls: List[Call] = field(default_factory=list)
    external_calls: List[Call] = field(default_factory=list)
    state_transitions: List[StateTransition] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'instruction_count': len(self.instructions),
            'state_reads': list(self.state_reads),
            'state_writes': list(self.state_writes),
            'internal_calls': [c.to_dict() for c in self.internal_calls],
            'external_calls': [c.to_dict() for c in self.external_calls],
            'state_transitions': [t.to_dict() for t in self.state_transitions],
        }


class SlitherIRParser:
    """
    Parses Slither's intermediate representation output.

    Slither can output IR information using various printers:
    - human-summary: High-level overview
    - function-summary: Per-function details
    - call-graph: Call relationships
    - data-dependency: Data flow information
    - slithir: Raw IR instructions

    This parser extracts structured information from these outputs.
    """

    # Pattern to match SlithIR instructions
    IR_INSTRUCTION_PATTERN = re.compile(
        r'(?:(\w+)\s*[=]\s*)?'  # Optional lvalue assignment
        r'(\w+)'                # Opcode
        r'(?:\s*,\s*(.*))?'     # Optional arguments
    )

    # Pattern to match function IR sections
    FUNCTION_IR_PATTERN = re.compile(
        r'Function\s+(\w+)[^:]*:?\s*\n((?:\s+.*\n)*)',
        re.MULTILINE
    )

    # Opcode mapping from string to enum
    OPCODE_MAP = {
        'ASSIGNMENT': IROpcode.ASSIGNMENT,
        'BINARY': IROpcode.BINARY,
        'UNARY': IROpcode.UNARY,
        'INDEX': IROpcode.INDEX,
        'MEMBER': IROpcode.MEMBER,
        'HIGH_LEVEL_CALL': IROpcode.HIGH_LEVEL_CALL,
        'LOW_LEVEL_CALL': IROpcode.LOW_LEVEL_CALL,
        'INTERNAL_CALL': IROpcode.INTERNAL_CALL,
        'INTERNAL_DYNAMIC_CALL': IROpcode.INTERNAL_DYNAMIC_CALL,
        'LIBRARY_CALL': IROpcode.LIBRARY_CALL,
        'SOLIDITY_CALL': IROpcode.SOLIDITY_CALL,
        'EVENT_CALL': IROpcode.EVENT_CALL,
        'SEND': IROpcode.SEND,
        'TRANSFER': IROpcode.TRANSFER,
        'CONDITION': IROpcode.CONDITION,
        'RETURN': IROpcode.RETURN,
        'NEW_CONTRACT': IROpcode.NEW_CONTRACT,
        'NEW_ARRAY': IROpcode.NEW_ARRAY,
        'NEW_STRUCTURE': IROpcode.NEW_STRUCTURE,
        'CONVERT': IROpcode.CONVERT,
        'UNPACK': IROpcode.UNPACK,
        'TYPE_CONVERSION': IROpcode.TYPE_CONVERSION,
        'PHI': IROpcode.PHI,
        'PUSH': IROpcode.PUSH,
        'DELETE': IROpcode.DELETE,
        'LENGTH': IROpcode.LENGTH,
    }

    def __init__(self):
        """Initialize the IR parser."""
        self._functions: Dict[str, FunctionIR] = {}

    def parse_slither_output(
        self,
        slither_json: Dict[str, Any],
    ) -> Dict[str, FunctionIR]:
        """
        Parse Slither JSON output to extract IR information.

        Args:
            slither_json: Parsed Slither JSON output

        Returns:
            Dictionary mapping function names to FunctionIR objects
        """
        self._functions = {}

        # Extract from printers
        results = slither_json.get('results', {})
        printers = results.get('printers', [])

        for printer in printers:
            printer_name = printer.get('printer', '')

            if printer_name == 'slithir':
                self._parse_slithir_printer(printer)
            elif printer_name == 'function-summary':
                self._parse_function_summary(printer)
            elif printer_name == 'data-dependency':
                self._parse_data_dependency(printer)

        # Also extract from detectors
        self._extract_from_detectors(slither_json)

        return self._functions

    def parse_function_ir(
        self,
        ir_text: str,
        function_name: str,
    ) -> FunctionIR:
        """
        Parse raw SlithIR text for a single function.

        Args:
            ir_text: Raw SlithIR text
            function_name: Name of the function

        Returns:
            FunctionIR object
        """
        func_ir = FunctionIR(name=function_name)

        lines = ir_text.strip().split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            instruction = self._parse_instruction(line, line_num)
            if instruction:
                func_ir.instructions.append(instruction)

                # Track state operations
                self._track_state_operations(instruction, func_ir)

                # Track calls
                self._track_calls(instruction, func_ir)

        return func_ir

    def _parse_instruction(
        self,
        line: str,
        line_num: int,
    ) -> Optional[IRInstruction]:
        """Parse a single IR instruction line."""
        # Try to match common patterns
        instruction = IRInstruction(
            opcode=IROpcode.UNKNOWN,
            line=line_num,
            raw=line,
        )

        # Check for call patterns
        call_patterns = [
            (r'HIGH_LEVEL_CALL', IROpcode.HIGH_LEVEL_CALL),
            (r'LOW_LEVEL_CALL', IROpcode.LOW_LEVEL_CALL),
            (r'INTERNAL_CALL', IROpcode.INTERNAL_CALL),
            (r'LIBRARY_CALL', IROpcode.LIBRARY_CALL),
            (r'SOLIDITY_CALL', IROpcode.SOLIDITY_CALL),
            (r'SEND', IROpcode.SEND),
            (r'TRANSFER', IROpcode.TRANSFER),
        ]

        for pattern, opcode in call_patterns:
            if pattern in line:
                instruction.opcode = opcode

                # Extract call target
                dest_match = re.search(r'dest:(\w+)', line)
                if dest_match:
                    instruction.call_target = dest_match.group(1)

                # Extract function name
                func_match = re.search(r'function:(\w+)', line)
                if func_match:
                    instruction.call_type = func_match.group(1)

                return instruction

        # Check for assignment patterns
        if '=' in line and 'CALL' not in line:
            instruction.opcode = IROpcode.ASSIGNMENT

            # Extract lvalue
            lvalue_match = re.match(r'(\w+)\s*[=]', line)
            if lvalue_match:
                instruction.lvalue = IRVariable(name=lvalue_match.group(1))

            return instruction

        # Check for return
        if line.startswith('RETURN'):
            instruction.opcode = IROpcode.RETURN
            return instruction

        # Check for condition
        if 'CONDITION' in line or line.startswith('IF'):
            instruction.opcode = IROpcode.CONDITION
            return instruction

        return instruction if instruction.opcode != IROpcode.UNKNOWN else None

    def _track_state_operations(
        self,
        instruction: IRInstruction,
        func_ir: FunctionIR,
    ) -> None:
        """Track state variable reads and writes from instruction."""
        # Check for state variable patterns in the raw instruction
        raw = instruction.raw

        # Pattern for state variable read: varName(type)
        state_read_pattern = r'\b(\w+)\s*\([^)]+\)\s*\[|REF_\d+\([^)]+\)\s*=\s*(\w+)'
        for match in re.finditer(state_read_pattern, raw):
            var_name = match.group(1) or match.group(2)
            if var_name and not var_name.startswith(('TMP_', 'REF_')):
                func_ir.state_reads.add(var_name)

        # Pattern for state variable write
        state_write_pattern = r'(\w+)\s*\([^)]+\)\s*\[.*\]\s*='
        for match in re.finditer(state_write_pattern, raw):
            var_name = match.group(1)
            if var_name and not var_name.startswith(('TMP_', 'REF_')):
                func_ir.state_writes.add(var_name)

    def _track_calls(
        self,
        instruction: IRInstruction,
        func_ir: FunctionIR,
    ) -> None:
        """Track function calls from instruction."""
        if instruction.opcode in [
            IROpcode.HIGH_LEVEL_CALL,
            IROpcode.LOW_LEVEL_CALL,
            IROpcode.SEND,
            IROpcode.TRANSFER,
        ]:
            call = Call(
                function=instruction.call_type or 'unknown',
                call_type='external',
                target=instruction.call_target,
                line=instruction.line,
            )
            func_ir.external_calls.append(call)

        elif instruction.opcode in [
            IROpcode.INTERNAL_CALL,
            IROpcode.LIBRARY_CALL,
        ]:
            call = Call(
                function=instruction.call_type or 'unknown',
                call_type='internal',
                target=instruction.call_target,
                line=instruction.line,
            )
            func_ir.internal_calls.append(call)

    def _parse_slithir_printer(
        self,
        printer: Dict[str, Any],
    ) -> None:
        """Parse slithir printer output."""
        elements = printer.get('elements', [])

        for element in elements:
            if element.get('type') == 'function':
                func_name = element.get('name', 'unknown')
                ir_text = element.get('description', '')

                if ir_text:
                    func_ir = self.parse_function_ir(ir_text, func_name)
                    self._functions[func_name] = func_ir

    def _parse_function_summary(
        self,
        printer: Dict[str, Any],
    ) -> None:
        """Parse function-summary printer output."""
        elements = printer.get('elements', [])

        for element in elements:
            if element.get('type') == 'table':
                # Extract function info from table rows
                rows = element.get('rows', [])
                for row in rows:
                    if len(row) >= 2:
                        func_name = row[0]
                        if func_name and func_name not in self._functions:
                            self._functions[func_name] = FunctionIR(name=func_name)

    def _parse_data_dependency(
        self,
        printer: Dict[str, Any],
    ) -> None:
        """Parse data-dependency printer output."""
        elements = printer.get('elements', [])

        for element in elements:
            func_name = element.get('function', '')
            dependencies = element.get('dependencies', {})

            if func_name in self._functions:
                func_ir = self._functions[func_name]

                for var_name, deps in dependencies.items():
                    if deps:
                        func_ir.state_reads.add(var_name)

    def _extract_from_detectors(
        self,
        slither_json: Dict[str, Any],
    ) -> None:
        """Extract IR-relevant information from detector results."""
        detectors = slither_json.get('results', {}).get('detectors', [])

        for detector in detectors:
            elements = detector.get('elements', [])

            for element in elements:
                if element.get('type') == 'function':
                    func_name = element.get('name', '')

                    if func_name and func_name not in self._functions:
                        self._functions[func_name] = FunctionIR(name=func_name)

                    # Extract type-specific fields
                    type_fields = element.get('type_specific_fields', {})

                    if func_name in self._functions:
                        func_ir = self._functions[func_name]

                        # Extract state variables if available
                        state_vars = type_fields.get('state_variables_read', [])
                        for var in state_vars:
                            if isinstance(var, dict):
                                func_ir.state_reads.add(var.get('name', ''))
                            else:
                                func_ir.state_reads.add(str(var))

                        state_writes = type_fields.get('state_variables_written', [])
                        for var in state_writes:
                            if isinstance(var, dict):
                                func_ir.state_writes.add(var.get('name', ''))
                            else:
                                func_ir.state_writes.add(str(var))

    def extract_state_transitions(
        self,
        function_name: str,
    ) -> List[StateTransition]:
        """
        Extract state transitions for a function.

        Args:
            function_name: Name of the function

        Returns:
            List of StateTransition objects
        """
        if function_name not in self._functions:
            return []

        func_ir = self._functions[function_name]
        transitions = []

        for var_name in func_ir.state_writes:
            transition = StateTransition(
                state_var=var_name,
                function=function_name,
            )
            transitions.append(transition)

        return transitions

    def get_call_sequence(
        self,
        function_name: str,
    ) -> List[Call]:
        """
        Get the sequence of calls in a function.

        Args:
            function_name: Name of the function

        Returns:
            List of Call objects in order
        """
        if function_name not in self._functions:
            return []

        func_ir = self._functions[function_name]

        # Combine internal and external calls, sorted by line number
        all_calls = func_ir.internal_calls + func_ir.external_calls
        all_calls.sort(key=lambda c: c.line)

        return all_calls

    def get_summary(self) -> Dict[str, Any]:
        """Generate summary of parsed IR."""
        total_instructions = sum(
            len(f.instructions) for f in self._functions.values()
        )
        total_external_calls = sum(
            len(f.external_calls) for f in self._functions.values()
        )
        total_internal_calls = sum(
            len(f.internal_calls) for f in self._functions.values()
        )
        total_state_reads = sum(
            len(f.state_reads) for f in self._functions.values()
        )
        total_state_writes = sum(
            len(f.state_writes) for f in self._functions.values()
        )

        return {
            'functions_parsed': len(self._functions),
            'total_instructions': total_instructions,
            'total_external_calls': total_external_calls,
            'total_internal_calls': total_internal_calls,
            'total_state_reads': total_state_reads,
            'total_state_writes': total_state_writes,
            'functions': {
                name: func.to_dict()
                for name, func in self._functions.items()
            },
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def parse_slither_ir(
    slither_json: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Convenience function to parse Slither IR output.

    Args:
        slither_json: Parsed Slither JSON output

    Returns:
        Parsed IR information with summary
    """
    parser = SlitherIRParser()
    parser.parse_slither_output(slither_json)

    return parser.get_summary()


def get_function_state_transitions(
    slither_json: Dict[str, Any],
    function_name: str,
) -> List[Dict[str, Any]]:
    """
    Get state transitions for a specific function.

    Args:
        slither_json: Parsed Slither JSON output
        function_name: Name of the function

    Returns:
        List of state transitions as dictionaries
    """
    parser = SlitherIRParser()
    parser.parse_slither_output(slither_json)

    transitions = parser.extract_state_transitions(function_name)
    return [t.to_dict() for t in transitions]


def get_external_calls(
    slither_json: Dict[str, Any],
    function_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Get all external calls, optionally filtered by function.

    Args:
        slither_json: Parsed Slither JSON output
        function_name: Optional function name filter

    Returns:
        List of external calls as dictionaries
    """
    parser = SlitherIRParser()
    functions = parser.parse_slither_output(slither_json)

    calls = []
    for name, func_ir in functions.items():
        if function_name is None or name == function_name:
            for call in func_ir.external_calls:
                call_dict = call.to_dict()
                call_dict['caller_function'] = name
                calls.append(call_dict)

    return calls


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "IROpcode",
    "IRVariable",
    "IRInstruction",
    "StateTransition",
    "Call",
    "FunctionIR",
    "SlitherIRParser",
    "parse_slither_ir",
    "get_function_state_transitions",
    "get_external_calls",
]
