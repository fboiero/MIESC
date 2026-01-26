"""
Algorand Adapter
================

Adapter for analyzing Algorand smart contracts written in TEAL and PyTeal.

Features:
- Parse TEAL assembly code
- Parse PyTeal Python source
- Detect Algorand-specific vulnerabilities:
  - Missing sender/creator checks
  - Rekeying attacks
  - Close-to attacks
  - Asset clawback issues
  - Inner transaction safety
  - Group transaction validation
  - Logic signature security

References:
- https://developer.algorand.org/
- https://pyteal.readthedocs.io/
- https://github.com/algorand/pyteal

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from src.core.chain_abstraction import (
    AbstractChainAnalyzer,
    AbstractContract,
    AbstractEvent,
    AbstractFunction,
    AbstractVariable,
    ChainType,
    ContractLanguage,
    Location,
    Mutability,
    Parameter,
    SecurityProperty,
    TypeInfo,
    Visibility,
    register_chain_analyzer,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Algorand-Specific Types
# ============================================================================


class AlgorandVulnerability(Enum):
    """Algorand-specific vulnerability types."""

    MISSING_SENDER_CHECK = "missing_sender_check"
    MISSING_CREATOR_CHECK = "missing_creator_check"
    REKEY_ATTACK = "rekey_attack"
    CLOSE_TO_ATTACK = "close_to_attack"
    ASSET_CLOSE_TO = "asset_close_to"
    CLAWBACK_ABUSE = "clawback_abuse"
    INNER_TXN_UNSAFE = "inner_txn_unsafe"
    GROUP_TXN_VALIDATION = "group_txn_validation"
    LOGIC_SIG_STATELESS = "logic_sig_stateless"
    UNCHECKED_TXN_TYPE = "unchecked_txn_type"
    TIMESTAMP_DEPENDENCE = "timestamp_dependence"
    OVERFLOW_UNDERFLOW = "overflow_underflow"
    UNRESTRICTED_UPDATE = "unrestricted_update"
    UNRESTRICTED_DELETE = "unrestricted_delete"
    FEE_MANIPULATION = "fee_manipulation"
    FIRST_VALID_CHECK = "first_valid_check"
    ASSET_TRANSFER_UNCHECKED = "asset_transfer_unchecked"
    GLOBAL_STATE_OVERFLOW = "global_state_overflow"
    LOCAL_STATE_OVERFLOW = "local_state_overflow"
    BOX_STORAGE_UNSAFE = "box_storage_unsafe"


class TealOpcode(Enum):
    """Important TEAL opcodes for security analysis."""

    # Transaction field access
    TXN = "txn"
    GTXN = "gtxn"
    ITXN = "itxn"
    ITXN_FIELD = "itxn_field"
    ITXN_SUBMIT = "itxn_submit"
    ITXN_BEGIN = "itxn_begin"
    ITXN_NEXT = "itxn_next"

    # Global/Local state
    APP_GLOBAL_GET = "app_global_get"
    APP_GLOBAL_PUT = "app_global_put"
    APP_LOCAL_GET = "app_local_get"
    APP_LOCAL_PUT = "app_local_put"
    APP_GLOBAL_DEL = "app_global_del"
    APP_LOCAL_DEL = "app_local_del"

    # Box storage
    BOX_CREATE = "box_create"
    BOX_DEL = "box_del"
    BOX_GET = "box_get"
    BOX_PUT = "box_put"
    BOX_LEN = "box_len"

    # Control flow
    RETURN = "return"
    ASSERT = "assert"
    ERR = "err"
    BNZ = "bnz"
    BZ = "bz"
    B = "b"

    # Crypto
    ED25519VERIFY = "ed25519verify"
    ECDSA_VERIFY = "ecdsa_verify"
    KECCAK256 = "keccak256"
    SHA256 = "sha256"
    SHA512_256 = "sha512_256"

    # Arithmetic
    ADD = "+"
    SUB = "-"
    MUL = "*"
    DIV = "/"
    MOD = "%"


@dataclass
class TealInstruction:
    """Represents a TEAL instruction."""

    opcode: str
    args: List[str] = field(default_factory=list)
    line_number: int = 0
    comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "opcode": self.opcode,
            "args": self.args,
            "line": self.line_number,
            "comment": self.comment,
        }


@dataclass
class TealProgram:
    """Parsed TEAL program structure."""

    version: int = 8
    mode: str = "Application"  # Application, LogicSig
    instructions: List[TealInstruction] = field(default_factory=list)
    labels: Dict[str, int] = field(default_factory=dict)  # label -> line number
    subroutines: Dict[str, int] = field(default_factory=dict)  # name -> line number
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PyTealFunction:
    """Represents a PyTeal function/method."""

    name: str
    decorators: List[str] = field(default_factory=list)
    parameters: List[Tuple[str, str]] = field(default_factory=list)
    return_type: Optional[str] = None
    body: str = ""
    is_subroutine: bool = False
    is_bare_call: bool = False
    on_complete: Optional[str] = None
    location: Optional[Location] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "decorators": self.decorators,
            "is_subroutine": self.is_subroutine,
            "is_bare_call": self.is_bare_call,
            "on_complete": self.on_complete,
        }


@dataclass
class AlgorandContract:
    """Parsed Algorand contract information."""

    name: str
    language: str  # "teal" or "pyteal"
    version: int = 8
    functions: List[PyTealFunction] = field(default_factory=list)
    global_schema: Dict[str, int] = field(default_factory=dict)  # bytes, uints
    local_schema: Dict[str, int] = field(default_factory=dict)
    teal_program: Optional[TealProgram] = None
    imports: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# TEAL Parser
# ============================================================================


class TealParser:
    """Parser for TEAL assembly code."""

    # TEAL version pattern
    VERSION_PATTERN = r"^#pragma\s+version\s+(\d+)"

    # Label pattern
    LABEL_PATTERN = r"^(\w+):\s*$"

    # Comment pattern
    COMMENT_PATTERN = r"//.*$"

    def parse(self, source_path: Union[str, Path]) -> TealProgram:
        """Parse TEAL source file."""
        path = Path(source_path)
        content = path.read_text()
        lines = content.split("\n")

        program = TealProgram()

        for line_no, line in enumerate(lines, 1):
            # Remove comments but keep for documentation
            comment = ""
            if "//" in line:
                comment_match = re.search(self.COMMENT_PATTERN, line)
                if comment_match:
                    comment = comment_match.group().strip("// ")
                line = re.sub(self.COMMENT_PATTERN, "", line)

            line = line.strip()
            if not line:
                continue

            # Check for version pragma
            version_match = re.match(self.VERSION_PATTERN, line)
            if version_match:
                program.version = int(version_match.group(1))
                continue

            # Check for label
            label_match = re.match(self.LABEL_PATTERN, line)
            if label_match:
                program.labels[label_match.group(1)] = line_no
                continue

            # Parse instruction
            parts = line.split()
            if parts:
                opcode = parts[0]
                args = parts[1:] if len(parts) > 1 else []

                instruction = TealInstruction(
                    opcode=opcode,
                    args=args,
                    line_number=line_no,
                    comment=comment,
                )
                program.instructions.append(instruction)

                # Track subroutines
                if opcode == "proto":
                    # Previous label is subroutine name
                    for label, label_line in program.labels.items():
                        if label_line == line_no - 1:
                            program.subroutines[label] = label_line

        return program


# ============================================================================
# PyTeal Parser
# ============================================================================


class PyTealParser:
    """Parser for PyTeal Python source code."""

    # Import patterns
    IMPORT_PATTERN = r"^(?:from\s+pyteal|import\s+pyteal)"

    # Router/BareCall patterns
    ROUTER_PATTERN = r"Router\s*\("
    BAREAPP_PATTERN = r"BareCallActions\s*\("

    # Subroutine decorator
    SUBROUTINE_PATTERN = r"@Subroutine\s*\(.*\)"
    ABIMethod_PATTERN = r"@\w+\.method\s*\("

    # Function definition
    FN_PATTERN = r"def\s+(\w+)\s*\(([^)]*)\)(?:\s*->\s*([^:]+))?:"

    # OnComplete types
    ON_COMPLETE_TYPES = [
        "NoOp", "OptIn", "CloseOut", "UpdateApplication",
        "DeleteApplication", "ClearState"
    ]

    def parse(self, source_path: Union[str, Path]) -> AlgorandContract:
        """Parse PyTeal source file."""
        path = Path(source_path)
        content = path.read_text()
        lines = content.split("\n")

        contract = AlgorandContract(
            name=path.stem,
            language="pyteal",
        )

        # Parse imports
        contract.imports = self._parse_imports(content)

        # Parse functions
        contract.functions = self._parse_functions(content, lines)

        # Parse schema
        contract.global_schema, contract.local_schema = self._parse_schema(content)

        return contract

    def _parse_imports(self, content: str) -> List[str]:
        """Parse PyTeal imports."""
        imports = []
        for line in content.split("\n"):
            if re.match(self.IMPORT_PATTERN, line.strip()):
                imports.append(line.strip())
        return imports

    def _parse_functions(
        self, content: str, lines: List[str]
    ) -> List[PyTealFunction]:
        """Parse PyTeal functions."""
        functions = []

        for i, line in enumerate(lines):
            # Check for function definition
            fn_match = re.search(self.FN_PATTERN, line)
            if fn_match:
                name = fn_match.group(1)
                params_str = fn_match.group(2)
                return_type = fn_match.group(3)

                # Check decorators (look back up to 5 lines)
                decorators = []
                is_subroutine = False
                is_bare_call = False
                on_complete = None

                for j in range(max(0, i - 5), i):
                    dec_line = lines[j].strip()
                    if dec_line.startswith("@"):
                        decorators.append(dec_line)
                        if "Subroutine" in dec_line:
                            is_subroutine = True
                        if "bare_call" in dec_line.lower():
                            is_bare_call = True
                        for oc in self.ON_COMPLETE_TYPES:
                            if oc.lower() in dec_line.lower():
                                on_complete = oc
                                break

                # Extract body
                body = self._extract_body(lines, i)

                # Parse parameters
                params = self._parse_params(params_str)

                func = PyTealFunction(
                    name=name,
                    decorators=decorators,
                    parameters=params,
                    return_type=return_type.strip() if return_type else None,
                    body=body,
                    is_subroutine=is_subroutine,
                    is_bare_call=is_bare_call,
                    on_complete=on_complete,
                    location=Location(file=str(Path().absolute()), line=i + 1),
                )
                functions.append(func)

        return functions

    def _parse_params(self, params_str: str) -> List[Tuple[str, str]]:
        """Parse function parameters."""
        params = []
        if not params_str.strip():
            return params

        for part in params_str.split(","):
            part = part.strip()
            if ":" in part:
                name, type_str = part.split(":", 1)
                params.append((name.strip(), type_str.strip()))
            elif part and part not in ("self", "*"):
                params.append((part, "Any"))

        return params

    def _extract_body(self, lines: List[str], start_line: int) -> str:
        """Extract function body."""
        body_lines = []
        if start_line >= len(lines):
            return ""

        # Get indentation of function def
        base_indent = len(lines[start_line]) - len(lines[start_line].lstrip())

        for i in range(start_line + 1, len(lines)):
            line = lines[i]
            if not line.strip():
                body_lines.append("")
                continue

            current_indent = len(line) - len(line.lstrip())
            if current_indent <= base_indent and line.strip():
                break

            body_lines.append(line)

        return "\n".join(body_lines)

    def _parse_schema(self, content: str) -> Tuple[Dict[str, int], Dict[str, int]]:
        """Parse global and local state schema."""
        global_schema = {"bytes": 0, "uints": 0}
        local_schema = {"bytes": 0, "uints": 0}

        # Look for schema definitions
        global_match = re.search(
            r"GlobalStateSchema\s*\(\s*num_uints\s*=\s*(\d+)\s*,\s*num_byte_slices\s*=\s*(\d+)",
            content
        )
        if global_match:
            global_schema["uints"] = int(global_match.group(1))
            global_schema["bytes"] = int(global_match.group(2))

        local_match = re.search(
            r"LocalStateSchema\s*\(\s*num_uints\s*=\s*(\d+)\s*,\s*num_byte_slices\s*=\s*(\d+)",
            content
        )
        if local_match:
            local_schema["uints"] = int(local_match.group(1))
            local_schema["bytes"] = int(local_match.group(2))

        return global_schema, local_schema


# ============================================================================
# Algorand Pattern Detector
# ============================================================================


class AlgorandPatternDetector:
    """Pattern-based vulnerability detector for Algorand contracts."""

    # TEAL patterns for security checks
    TEAL_SECURITY_PATTERNS = {
        # Sender/Creator checks
        "sender_check": r"txn\s+Sender|Txn\.sender",
        "creator_check": r"global\s+CreatorAddress|Global\.creator_address",
        "app_id_check": r"txn\s+ApplicationID|Txn\.application_id",

        # Dangerous operations
        "rekey_to": r"txn\s+RekeyTo|Txn\.rekey_to",
        "close_remainder_to": r"txn\s+CloseRemainderTo|Txn\.close_remainder_to",
        "asset_close_to": r"txn\s+AssetCloseTo|Txn\.asset_close_to",

        # Inner transactions
        "itxn_begin": r"itxn_begin|InnerTxnBuilder\.Begin",
        "itxn_submit": r"itxn_submit|InnerTxnBuilder\.Submit",

        # Group transactions
        "group_size": r"global\s+GroupSize|Global\.group_size",
        "gtxn": r"gtxn\s+\d+|Gtxn\[",

        # Update/Delete
        "on_complete": r"txn\s+OnCompletion|Txn\.on_completion",
        "update_app": r"UpdateApplication|OnComplete\.UpdateApplication",
        "delete_app": r"DeleteApplication|OnComplete\.DeleteApplication",
    }

    # PyTeal dangerous patterns
    PYTEAL_DANGEROUS_PATTERNS = {
        "assert_none": r"Assert\s*\(\s*\)",
        "return_1": r"Return\s*\(\s*Int\s*\(\s*1\s*\)\s*\)",
        "approve_all": r"Approve\s*\(\s*\)",
        "unchecked_inner": r"InnerTxnBuilder.*Submit.*(?!Assert)",
    }

    # Arithmetic patterns
    ARITHMETIC_PATTERNS = {
        "teal_add": r"^\s*\+\s*$",
        "teal_sub": r"^\s*-\s*$",
        "teal_mul": r"^\s*\*\s*$",
        "teal_div": r"^\s*/\s*$",
        "pyteal_add": r"\.add\s*\(|Add\s*\(",
        "pyteal_sub": r"\.sub\s*\(|Minus\s*\(",
        "pyteal_mul": r"\.mul\s*\(|Mul\s*\(",
        "pyteal_div": r"\.div\s*\(|Div\s*\(",
    }

    @classmethod
    def detect_teal_vulnerabilities(
        cls, program: TealProgram, content: str
    ) -> List[Dict[str, Any]]:
        """Detect vulnerabilities in TEAL code."""
        findings = []

        # Check for missing sender validation
        has_sender_check = any(
            "Sender" in instr.opcode or "Sender" in " ".join(instr.args)
            for instr in program.instructions
        )

        if not has_sender_check:
            findings.append({
                "type": AlgorandVulnerability.MISSING_SENDER_CHECK.value,
                "line": 1,
                "message": "No transaction sender validation found",
                "severity": "High",
                "recommendation": "Add sender validation using 'txn Sender' comparison",
            })

        # Check for rekey vulnerability
        has_rekey_check = False
        for instr in program.instructions:
            if "RekeyTo" in instr.opcode or "RekeyTo" in " ".join(instr.args):
                # Check if there's a zero address comparison
                has_rekey_check = True
                break

        if not has_rekey_check and any(
            instr.opcode in ("txn", "gtxn") for instr in program.instructions
        ):
            findings.append({
                "type": AlgorandVulnerability.REKEY_ATTACK.value,
                "line": 1,
                "message": "No RekeyTo validation - potential rekey attack",
                "severity": "Critical",
                "recommendation": "Verify RekeyTo is ZeroAddress: txn RekeyTo; global ZeroAddress; ==",
            })

        # Check for CloseRemainderTo vulnerability
        has_close_check = any(
            "CloseRemainderTo" in instr.opcode or "CloseRemainderTo" in " ".join(instr.args)
            for instr in program.instructions
        )

        if not has_close_check and any(
            instr.opcode == "txn" for instr in program.instructions
        ):
            findings.append({
                "type": AlgorandVulnerability.CLOSE_TO_ATTACK.value,
                "line": 1,
                "message": "No CloseRemainderTo validation - potential close-to attack",
                "severity": "High",
                "recommendation": "Verify CloseRemainderTo is ZeroAddress",
            })

        # Check inner transaction safety
        itxn_begin_count = sum(
            1 for instr in program.instructions if instr.opcode == "itxn_begin"
        )
        itxn_submit_count = sum(
            1 for instr in program.instructions if instr.opcode == "itxn_submit"
        )

        if itxn_begin_count > 0:
            # Check if there's proper validation before submit
            findings.append({
                "type": AlgorandVulnerability.INNER_TXN_UNSAFE.value,
                "line": 1,
                "message": f"Inner transactions detected ({itxn_begin_count} begin, {itxn_submit_count} submit) - verify authorization",
                "severity": "Medium",
                "recommendation": "Ensure proper authorization before inner transaction submission",
            })

        # Check for unchecked OnCompletion
        on_completion_checks = [
            instr for instr in program.instructions
            if "OnCompletion" in " ".join(instr.args) or instr.opcode == "txn" and "OnCompletion" in " ".join(instr.args)
        ]

        if not on_completion_checks:
            findings.append({
                "type": AlgorandVulnerability.UNCHECKED_TXN_TYPE.value,
                "line": 1,
                "message": "No OnCompletion check - contract may accept unexpected calls",
                "severity": "Medium",
                "recommendation": "Check txn OnCompletion for expected values",
            })

        return findings

    @classmethod
    def detect_pyteal_vulnerabilities(
        cls, contract: AlgorandContract, content: str
    ) -> List[Dict[str, Any]]:
        """Detect vulnerabilities in PyTeal code."""
        findings = []
        lines = content.split("\n")

        # Check for sender validation in functions
        for func in contract.functions:
            if func.is_bare_call or func.on_complete:
                has_sender_check = bool(
                    re.search(r"Txn\.sender|sender\(\)", func.body, re.IGNORECASE)
                )

                if not has_sender_check and func.on_complete in (
                    "UpdateApplication", "DeleteApplication"
                ):
                    findings.append({
                        "type": AlgorandVulnerability.UNRESTRICTED_UPDATE.value
                        if func.on_complete == "UpdateApplication"
                        else AlgorandVulnerability.UNRESTRICTED_DELETE.value,
                        "function": func.name,
                        "line": func.location.line if func.location else 0,
                        "message": f"Function '{func.name}' handles {func.on_complete} without sender check",
                        "severity": "Critical",
                        "recommendation": "Add Txn.sender() == Global.creator_address() check",
                    })

        # Check for approve-all patterns
        for i, line in enumerate(lines, 1):
            if re.search(r"Return\s*\(\s*Int\s*\(\s*1\s*\)\s*\)", line):
                # Check context - is this in a security check?
                context_start = max(0, i - 10)
                context = "\n".join(lines[context_start:i])
                if not re.search(r"Txn\.sender|Assert|Cond|If", context):
                    findings.append({
                        "type": AlgorandVulnerability.MISSING_SENDER_CHECK.value,
                        "line": i,
                        "message": "Return Int(1) without visible authorization check",
                        "severity": "High",
                        "recommendation": "Add authorization check before approval",
                    })

        # Check for RekeyTo validation
        if not re.search(r"Txn\.rekey_to.*ZeroAddress|RekeyTo.*==.*ZeroAddress", content, re.IGNORECASE):
            findings.append({
                "type": AlgorandVulnerability.REKEY_ATTACK.value,
                "line": 1,
                "message": "No RekeyTo validation found",
                "severity": "Critical",
                "recommendation": "Add Assert(Txn.rekey_to() == Global.zero_address())",
            })

        # Check for CloseRemainderTo validation
        if not re.search(r"close_remainder_to.*ZeroAddress|CloseRemainderTo.*==.*ZeroAddress", content, re.IGNORECASE):
            findings.append({
                "type": AlgorandVulnerability.CLOSE_TO_ATTACK.value,
                "line": 1,
                "message": "No CloseRemainderTo validation found",
                "severity": "High",
                "recommendation": "Add Assert(Txn.close_remainder_to() == Global.zero_address())",
            })

        # Check for inner transaction safety
        inner_txn_matches = list(re.finditer(r"InnerTxnBuilder", content))
        for match in inner_txn_matches:
            line_no = content[:match.start()].count("\n") + 1
            # Check for authorization before inner txn
            context_start = max(0, match.start() - 500)
            context = content[context_start:match.start()]
            if not re.search(r"Assert|sender|creator", context, re.IGNORECASE):
                findings.append({
                    "type": AlgorandVulnerability.INNER_TXN_UNSAFE.value,
                    "line": line_no,
                    "message": "Inner transaction without visible authorization",
                    "severity": "High",
                    "recommendation": "Add authorization check before InnerTxnBuilder",
                })

        # Check for group transaction validation
        if re.search(r"Gtxn\[|gtxn", content, re.IGNORECASE):
            if not re.search(r"Global\.group_size|GroupSize", content, re.IGNORECASE):
                findings.append({
                    "type": AlgorandVulnerability.GROUP_TXN_VALIDATION.value,
                    "line": 1,
                    "message": "Group transaction access without group size validation",
                    "severity": "Medium",
                    "recommendation": "Validate Global.group_size() before accessing Gtxn",
                })

        return findings


# ============================================================================
# Algorand Analyzer
# ============================================================================


class AlgorandAnalyzer(AbstractChainAnalyzer):
    """
    Analyzer for Algorand smart contracts (TEAL/PyTeal).

    Integrates with MIESC chain abstraction layer for unified analysis.
    """

    def __init__(self):
        super().__init__(ChainType.ALGORAND, ContractLanguage.TEAL)
        self.teal_parser = TealParser()
        self.pyteal_parser = PyTealParser()

    @property
    def name(self) -> str:
        return "AlgorandAnalyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return [".teal", ".py"]

    def _is_pyteal_file(self, path: Path) -> bool:
        """Check if a Python file is a PyTeal contract."""
        if path.suffix != ".py":
            return False

        content = path.read_text()
        return bool(re.search(r"from\s+pyteal|import\s+pyteal", content))

    def parse(self, source_path: Union[str, Path]) -> AbstractContract:
        """Parse Algorand source into AbstractContract."""
        path = Path(source_path)
        content = path.read_text()

        if path.suffix == ".teal":
            return self._parse_teal(path, content)
        elif self._is_pyteal_file(path):
            return self._parse_pyteal(path, content)
        else:
            raise ValueError(f"Unsupported file type: {path.suffix}")

    def _parse_teal(self, path: Path, content: str) -> AbstractContract:
        """Parse TEAL source file."""
        program = self.teal_parser.parse(path)

        # Convert subroutines to functions
        functions = []
        for name, line_no in program.subroutines.items():
            func = AbstractFunction(
                name=name,
                visibility=Visibility.PUBLIC,
                mutability=Mutability.MUTABLE,
                location=Location(file=str(path), line=line_no),
                chain_metadata={"is_subroutine": True},
            )
            functions.append(func)

        # Add main entry point
        functions.append(AbstractFunction(
            name="main",
            visibility=Visibility.PUBLIC,
            mutability=Mutability.MUTABLE,
            location=Location(file=str(path), line=1),
            chain_metadata={"is_entry_point": True, "teal_version": program.version},
        ))

        return AbstractContract(
            name=path.stem,
            chain_type=ChainType.ALGORAND,
            language=ContractLanguage.TEAL,
            source_path=str(path),
            source_code=content,
            functions=functions,
        )

    def _parse_pyteal(self, path: Path, content: str) -> AbstractContract:
        """Parse PyTeal source file."""
        contract = self.pyteal_parser.parse(path)

        # Convert to AbstractContract
        functions = []
        for func in contract.functions:
            visibility = Visibility.PUBLIC if not func.name.startswith("_") else Visibility.PRIVATE

            parameters = [
                Parameter(
                    name=name,
                    type_info=TypeInfo(name=type_str),
                )
                for name, type_str in func.parameters
            ]

            abstract_func = AbstractFunction(
                name=func.name,
                visibility=visibility,
                mutability=Mutability.MUTABLE,
                parameters=parameters,
                return_types=[TypeInfo(name=func.return_type)] if func.return_type else [],
                modifiers=func.decorators,
                location=func.location,
                body_source=func.body,
                chain_metadata={
                    "is_subroutine": func.is_subroutine,
                    "is_bare_call": func.is_bare_call,
                    "on_complete": func.on_complete,
                },
            )
            functions.append(abstract_func)

        return AbstractContract(
            name=contract.name,
            chain_type=ChainType.ALGORAND,
            language=ContractLanguage.PYTEAL,
            source_path=str(path),
            source_code=content,
            functions=functions,
            imports=contract.imports,
        )

    def detect_vulnerabilities(
        self,
        contract: AbstractContract,
        properties: Optional[List[SecurityProperty]] = None,
    ) -> List[Dict[str, Any]]:
        """Detect vulnerabilities in Algorand contract."""
        findings = []
        content = contract.source_code

        # Default to all properties
        if properties is None:
            properties = list(SecurityProperty)

        if contract.language == ContractLanguage.TEAL:
            program = self.teal_parser.parse(contract.source_path)
            teal_findings = AlgorandPatternDetector.detect_teal_vulnerabilities(
                program, content
            )
            for f in teal_findings:
                findings.append(self.normalize_finding(
                    vuln_type=f["type"],
                    severity=f["severity"],
                    message=f["message"],
                    location=Location(
                        file=contract.source_path,
                        line=f.get("line", 0),
                    ),
                    recommendation=f.get("recommendation"),
                ))

        elif contract.language == ContractLanguage.PYTEAL:
            pyteal_contract = self.pyteal_parser.parse(contract.source_path)
            pyteal_findings = AlgorandPatternDetector.detect_pyteal_vulnerabilities(
                pyteal_contract, content
            )
            for f in pyteal_findings:
                findings.append(self.normalize_finding(
                    vuln_type=f["type"],
                    severity=f["severity"],
                    message=f["message"],
                    location=Location(
                        file=contract.source_path,
                        line=f.get("line", 0),
                    ),
                    function=f.get("function"),
                    recommendation=f.get("recommendation"),
                ))

        return findings


# ============================================================================
# Registration
# ============================================================================


# Register analyzer
try:
    register_chain_analyzer(AlgorandAnalyzer())
except Exception as e:
    logger.warning(f"Failed to register AlgorandAnalyzer: {e}")


# Export for external use
__all__ = [
    "AlgorandAnalyzer",
    "AlgorandVulnerability",
    "AlgorandPatternDetector",
    "TealParser",
    "PyTealParser",
    "TealProgram",
    "TealInstruction",
    "PyTealFunction",
    "AlgorandContract",
]
