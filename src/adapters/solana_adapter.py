"""
Solana/Anchor Adapter
=====================

Adapter for analyzing Solana programs written with the Anchor framework.

Features:
- Parse Anchor IDL files
- Parse Rust source code for Anchor programs
- Detect Solana-specific vulnerabilities:
  - Missing signer checks
  - Missing account validation
  - PDA verification issues
  - Account data validation
  - Type confusion attacks
  - Cross-program invocation (CPI) issues
  - Arithmetic overflow

References:
- https://www.anchor-lang.com/
- https://github.com/coral-xyz/sealevel-attacks
- https://solana.com/developers/guides/security

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

import json
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
# Solana-Specific Types
# ============================================================================


class SolanaVulnerability(Enum):
    """Solana-specific vulnerability types."""

    MISSING_SIGNER_CHECK = "missing_signer_check"
    MISSING_OWNER_CHECK = "missing_owner_check"
    ACCOUNT_DATA_MATCHING = "account_data_matching"
    TYPE_COSPLAY = "type_cosplay"
    SYSVAR_ADDRESS_CHECK = "sysvar_address_check"
    ARBITRARY_CPI = "arbitrary_cpi"
    DUPLICATE_MUTABLE_ACCOUNTS = "duplicate_mutable_accounts"
    CLOSING_ACCOUNTS = "closing_accounts"
    PDA_SHARING = "pda_sharing"
    BUMP_SEED_CANONICALIZATION = "bump_seed_canonicalization"
    INITIALIZATION_ATTACK = "initialization_attack"
    REINITIALIZATION = "reinitialization"
    MISSING_RENT_EXEMPTION = "missing_rent_exemption"
    ARITHMETIC_OVERFLOW = "arithmetic_overflow"
    ORACLE_MANIPULATION = "oracle_manipulation"


@dataclass
class AnchorAccount:
    """Represents an Anchor account."""

    name: str
    account_type: str
    is_mut: bool = False
    is_signer: bool = False
    is_init: bool = False
    is_init_if_needed: bool = False
    is_close: bool = False
    has_constraint: bool = False
    constraint_expr: Optional[str] = None
    pda_seeds: List[str] = field(default_factory=list)
    space: Optional[int] = None
    location: Optional[Location] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "account_type": self.account_type,
            "is_mut": self.is_mut,
            "is_signer": self.is_signer,
            "is_init": self.is_init,
            "has_constraint": self.has_constraint,
            "pda_seeds": self.pda_seeds,
        }


@dataclass
class AnchorInstruction:
    """Represents an Anchor instruction."""

    name: str
    accounts: List[AnchorAccount] = field(default_factory=list)
    args: List[Parameter] = field(default_factory=list)
    handler_function: Optional[str] = None
    location: Optional[Location] = None
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "accounts": [a.to_dict() for a in self.accounts],
            "args": [{"name": a.name, "type": str(a.type_info)} for a in self.args],
            "handler": self.handler_function,
        }


@dataclass
class AnchorIDL:
    """Parsed Anchor IDL."""

    version: str
    name: str
    instructions: List[AnchorInstruction] = field(default_factory=list)
    accounts: List[Dict[str, Any]] = field(default_factory=list)
    types: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Solana Pattern Detectors
# ============================================================================


class SolanaPatternDetector:
    """Detects vulnerability patterns in Solana/Anchor code."""

    # Missing signer check patterns
    SIGNER_PATTERNS = [
        (r"#\[account\((?!.*signer).*mut.*\)\]", "mutable_without_signer"),
        (r"\.key\(\)\s*==\s*\w+\.key\(\)", "key_comparison_without_signer"),
        (r"ctx\.accounts\.\w+\s*(?!.*\.is_signer)", "account_without_signer_check"),
    ]

    # Missing owner check patterns
    OWNER_PATTERNS = [
        (r"#\[account\((?!.*owner).*\)\]", "missing_owner_constraint"),
        (r"\.owner\s*!=\s*\w+", "incorrect_owner_check"),
        (r"Account<'info,\s*\w+>(?!.*owner)", "unvalidated_account_owner"),
    ]

    # PDA patterns
    PDA_PATTERNS = [
        (r"Pubkey::find_program_address\s*\(", "find_pda"),
        (r"#\[account\(.*seeds\s*=.*\)\]", "pda_seeds"),
        (r"\.bump\s*=", "bump_assignment"),
        (r"create_program_address\s*\((?!.*canonical)", "non_canonical_bump"),
    ]

    # Initialization patterns
    INIT_PATTERNS = [
        (r"#\[account\(init(?!_if_needed)", "init_account"),
        (r"#\[account\(init_if_needed", "init_if_needed"),
        (r"is_initialized\s*:\s*bool", "initialization_flag"),
        (r"\.is_initialized\s*==\s*false", "initialization_check"),
    ]

    # CPI patterns
    CPI_PATTERNS = [
        (r"invoke\s*\(", "raw_invoke"),
        (r"invoke_signed\s*\(", "invoke_signed"),
        (r"CpiContext::new\s*\(", "cpi_context"),
        (r"\.invoke\s*\(", "anchor_invoke"),
    ]

    # Arithmetic patterns
    ARITHMETIC_PATTERNS = [
        (r"\.checked_add\s*\(", "checked_add"),
        (r"\.checked_sub\s*\(", "checked_sub"),
        (r"\.checked_mul\s*\(", "checked_mul"),
        (r"\.checked_div\s*\(", "checked_div"),
        (r"\s+\+\s+(?!.*checked)", "unchecked_add"),
        (r"\s+-\s+(?!.*checked)", "unchecked_sub"),
        (r"\s+\*\s+(?!.*checked)", "unchecked_mul"),
        (r"as\s+u64", "unsafe_cast"),
    ]

    # Account close patterns
    CLOSE_PATTERNS = [
        (r"#\[account\(.*close\s*=", "close_account"),
        (r"\.lamports\s*=\s*0", "zero_lamports"),
        (r"close\s*\(\s*ctx\.accounts", "anchor_close"),
    ]

    def detect_patterns(
        self,
        source_code: str,
        file_path: str,
    ) -> List[Dict[str, Any]]:
        """
        Detect vulnerability patterns in source code.

        Args:
            source_code: Rust/Anchor source code
            file_path: Path for reporting

        Returns:
            List of pattern matches
        """
        findings = []
        lines = source_code.split("\n")

        # Check all pattern categories
        all_patterns = [
            (self.SIGNER_PATTERNS, "access_control", "High"),
            (self.OWNER_PATTERNS, "access_control", "High"),
            (self.PDA_PATTERNS, "input_validation", "Medium"),
            (self.INIT_PATTERNS, "state_handling", "Medium"),
            (self.CPI_PATTERNS, "external_calls", "Medium"),
            (self.ARITHMETIC_PATTERNS, "arithmetic", "High"),
            (self.CLOSE_PATTERNS, "state_handling", "Medium"),
        ]

        for patterns, category, severity in all_patterns:
            for pattern, pattern_name in patterns:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        findings.append({
                            "pattern": pattern_name,
                            "category": category,
                            "severity": severity,
                            "line": i,
                            "file": file_path,
                            "code": line.strip(),
                        })

        return findings


# ============================================================================
# Solana Analyzer
# ============================================================================


class SolanaAnalyzer(AbstractChainAnalyzer):
    """
    Analyzer for Solana programs (Anchor framework).

    Provides parsing and vulnerability detection for Rust-based
    Solana programs using the Anchor framework.
    """

    def __init__(self):
        super().__init__(ChainType.SOLANA, ContractLanguage.RUST)
        self.pattern_detector = SolanaPatternDetector()
        self._idl_cache: Dict[str, AnchorIDL] = {}

    @property
    def name(self) -> str:
        return "solana-analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return [".rs", ".json"]  # .json for IDL files

    def parse(self, source_path: Union[str, Path]) -> AbstractContract:
        """
        Parse Solana program source.

        Args:
            source_path: Path to .rs or .json (IDL) file

        Returns:
            AbstractContract representation
        """
        path = Path(source_path)

        if path.suffix == ".json":
            return self._parse_idl(path)
        else:
            return self._parse_rust(path)

    def _parse_idl(self, idl_path: Path) -> AbstractContract:
        """Parse Anchor IDL file."""
        with open(idl_path) as f:
            idl_data = json.load(f)

        idl = AnchorIDL(
            version=idl_data.get("version", "0.0.0"),
            name=idl_data.get("name", idl_path.stem),
            metadata=idl_data.get("metadata", {}),
        )

        # Parse instructions
        for ix in idl_data.get("instructions", []):
            instruction = AnchorInstruction(
                name=ix.get("name", ""),
                handler_function=ix.get("name", ""),
            )

            # Parse accounts
            for acc in ix.get("accounts", []):
                account = AnchorAccount(
                    name=acc.get("name", ""),
                    account_type=acc.get("type", {}).get("kind", "account"),
                    is_mut=acc.get("isMut", False),
                    is_signer=acc.get("isSigner", False),
                )
                instruction.accounts.append(account)

            # Parse args
            for arg in ix.get("args", []):
                param = Parameter(
                    name=arg.get("name", ""),
                    type_info=TypeInfo(name=self._idl_type_to_str(arg.get("type", {}))),
                )
                instruction.args.append(param)

            idl.instructions.append(instruction)

        # Convert to AbstractContract
        functions = []
        for ix in idl.instructions:
            func = AbstractFunction(
                name=ix.name,
                visibility=Visibility.PUBLIC,
                mutability=Mutability.MUTABLE,
                parameters=ix.args,
                chain_metadata={
                    "accounts": [a.to_dict() for a in ix.accounts],
                    "instruction_type": "anchor",
                },
            )
            functions.append(func)

        return AbstractContract(
            name=idl.name,
            chain_type=ChainType.SOLANA,
            language=ContractLanguage.RUST,
            source_path=str(idl_path),
            functions=functions,
            compiler_version=idl.version,
        )

    def _parse_rust(self, rust_path: Path) -> AbstractContract:
        """Parse Rust/Anchor source file."""
        source_code = rust_path.read_text()

        contract = AbstractContract(
            name=rust_path.stem,
            chain_type=ChainType.SOLANA,
            language=ContractLanguage.RUST,
            source_path=str(rust_path),
            source_code=source_code,
        )

        # Extract program ID
        program_id_match = re.search(r'declare_id!\s*\(\s*"([^"]+)"\s*\)', source_code)
        if program_id_match:
            contract.compiler_version = program_id_match.group(1)[:8] + "..."

        # Extract functions (instruction handlers)
        function_pattern = r'pub\s+fn\s+(\w+)\s*\(([^)]*)\)[^{]*\{'
        for match in re.finditer(function_pattern, source_code):
            func_name = match.group(1)
            params_str = match.group(2)
            line_num = source_code[:match.start()].count("\n") + 1

            # Parse parameters
            parameters = []
            if params_str.strip():
                for param_match in re.finditer(r'(\w+)\s*:\s*([^,]+)', params_str):
                    param_name = param_match.group(1)
                    param_type = param_match.group(2).strip()
                    parameters.append(Parameter(
                        name=param_name,
                        type_info=TypeInfo(name=param_type),
                    ))

            func = AbstractFunction(
                name=func_name,
                visibility=Visibility.PUBLIC,
                mutability=Mutability.MUTABLE,
                parameters=parameters,
                location=Location(file=str(rust_path), line=line_num),
            )

            # Check for context parameter (Anchor pattern)
            if "Context<" in params_str:
                func.chain_metadata["has_context"] = True

            contract.functions.append(func)

        # Extract account structs
        account_pattern = r'#\[account\(([^)]*)\)\]\s*pub\s+struct\s+(\w+)'
        for match in re.finditer(account_pattern, source_code):
            attrs = match.group(1)
            struct_name = match.group(2)
            line_num = source_code[:match.start()].count("\n") + 1

            var = AbstractVariable(
                name=struct_name,
                type_info=TypeInfo(name="Account"),
                visibility=Visibility.PUBLIC,
                location=Location(file=str(rust_path), line=line_num),
                metadata={
                    "is_anchor_account": True,
                    "attributes": attrs,
                },
            )
            contract.variables.append(var)

        # Extract events
        event_pattern = r'#\[event\]\s*pub\s+struct\s+(\w+)'
        for match in re.finditer(event_pattern, source_code):
            event_name = match.group(1)
            line_num = source_code[:match.start()].count("\n") + 1

            event = AbstractEvent(
                name=event_name,
                location=Location(file=str(rust_path), line=line_num),
            )
            contract.events.append(event)

        return contract

    def _idl_type_to_str(self, idl_type: Any) -> str:
        """Convert IDL type to string representation."""
        if isinstance(idl_type, str):
            return idl_type
        if isinstance(idl_type, dict):
            if "vec" in idl_type:
                return f"Vec<{self._idl_type_to_str(idl_type['vec'])}>"
            if "option" in idl_type:
                return f"Option<{self._idl_type_to_str(idl_type['option'])}>"
            if "defined" in idl_type:
                return idl_type["defined"]
            if "array" in idl_type:
                inner, size = idl_type["array"]
                return f"[{self._idl_type_to_str(inner)}; {size}]"
        return str(idl_type)

    def detect_vulnerabilities(
        self,
        contract: AbstractContract,
        properties: Optional[List[SecurityProperty]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Detect Solana-specific vulnerabilities.

        Args:
            contract: Parsed contract
            properties: Security properties to check

        Returns:
            List of findings
        """
        findings = []
        source_code = contract.source_code

        if not source_code:
            return findings

        properties = properties or list(SecurityProperty)

        # Run pattern detector
        pattern_matches = self.pattern_detector.detect_patterns(
            source_code, contract.source_path
        )

        # Convert pattern matches to findings
        for match in pattern_matches:
            finding = self._pattern_to_finding(match, contract)
            if finding:
                findings.append(finding)

        # Additional semantic checks
        if SecurityProperty.ACCESS_CONTROL in properties:
            findings.extend(self._check_signer_validation(contract))

        if SecurityProperty.INPUT_VALIDATION in properties:
            findings.extend(self._check_account_validation(contract))

        if SecurityProperty.ARITHMETIC in properties:
            findings.extend(self._check_arithmetic_safety(contract))

        if SecurityProperty.REENTRANCY in properties:
            findings.extend(self._check_cpi_reentrancy(contract))

        return findings

    def _pattern_to_finding(
        self,
        match: Dict[str, Any],
        contract: AbstractContract,
    ) -> Optional[Dict[str, Any]]:
        """Convert pattern match to finding."""
        pattern = match["pattern"]
        category = match["category"]

        # Define finding messages
        messages = {
            "mutable_without_signer": (
                "Mutable account without signer check",
                "Add `signer` constraint to the account attribute",
            ),
            "missing_owner_constraint": (
                "Account missing owner constraint",
                "Add owner validation using `#[account(owner = ...)]` or explicit check",
            ),
            "non_canonical_bump": (
                "PDA created without canonical bump",
                "Use `Pubkey::find_program_address` to ensure canonical bump",
            ),
            "unchecked_add": (
                "Unchecked arithmetic addition",
                "Use `.checked_add()` or `#[checked]` attribute",
            ),
            "unchecked_sub": (
                "Unchecked arithmetic subtraction",
                "Use `.checked_sub()` or handle underflow explicitly",
            ),
            "unsafe_cast": (
                "Potentially unsafe type cast",
                "Validate value range before casting",
            ),
            "raw_invoke": (
                "Raw CPI invoke detected",
                "Consider using Anchor's CPI wrappers for type safety",
            ),
        }

        if pattern not in messages:
            return None

        message, recommendation = messages[pattern]

        return self.normalize_finding(
            vuln_type=pattern,
            severity=match["severity"],
            message=message,
            location=Location(
                file=match["file"],
                line=match["line"],
            ),
            description=f"Pattern: {pattern}\nCode: {match.get('code', '')}",
            recommendation=recommendation,
            confidence=0.75,
        )

    def _check_signer_validation(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for missing signer validation."""
        findings = []
        source = contract.source_code

        # Look for instruction handlers without signer checks
        handler_pattern = r'pub\s+fn\s+(\w+)\s*\(\s*ctx\s*:\s*Context<(\w+)>'
        for match in re.finditer(handler_pattern, source):
            func_name = match.group(1)
            ctx_type = match.group(2)
            line = source[:match.start()].count("\n") + 1

            # Find the accounts struct
            ctx_pattern = rf'#\[derive\(Accounts\)\]\s*pub\s+struct\s+{ctx_type}'
            ctx_match = re.search(ctx_pattern, source)

            if ctx_match:
                # Check if any mutable account lacks signer
                ctx_start = ctx_match.end()
                ctx_end = source.find("}", ctx_start)
                ctx_body = source[ctx_start:ctx_end]

                if "#[account(mut" in ctx_body and "signer" not in ctx_body:
                    # Check if there's at least one signer
                    if "is_signer" not in ctx_body and "#[account(signer" not in ctx_body:
                        findings.append(self.normalize_finding(
                            vuln_type=SolanaVulnerability.MISSING_SIGNER_CHECK.value,
                            severity="High",
                            message=f"Instruction '{func_name}' may lack proper signer validation",
                            location=Location(file=contract.source_path, line=line),
                            description=(
                                f"The instruction handler '{func_name}' has mutable accounts "
                                "but may not properly validate signers."
                            ),
                            recommendation=(
                                "Ensure at least one account has `signer` constraint and "
                                "represents the authorized party for this operation."
                            ),
                        ))

        return findings

    def _check_account_validation(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for missing account validation."""
        findings = []
        source = contract.source_code

        # Check for AccountInfo without validation
        if "AccountInfo<'info>" in source:
            # Find usages without validation
            info_pattern = r'(\w+)\s*:\s*AccountInfo<\'info>'
            for match in re.finditer(info_pattern, source):
                account_name = match.group(1)
                line = source[:match.start()].count("\n") + 1

                # Check if there's a constraint for this account
                context_line = source[:match.end()].rfind("#[account(")
                has_constraint = context_line > source[:match.start()].rfind("\n")

                if not has_constraint:
                    findings.append(self.normalize_finding(
                        vuln_type=SolanaVulnerability.ACCOUNT_DATA_MATCHING.value,
                        severity="Medium",
                        message=f"AccountInfo '{account_name}' without explicit validation",
                        location=Location(file=contract.source_path, line=line),
                        description=(
                            f"The account '{account_name}' is declared as AccountInfo "
                            "without explicit validation constraints."
                        ),
                        recommendation=(
                            "Consider using typed accounts or adding explicit validation "
                            "with constraints like `#[account(constraint = ...)]`."
                        ),
                    ))

        return findings

    def _check_arithmetic_safety(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for unsafe arithmetic."""
        findings = []
        source = contract.source_code

        # Dangerous patterns
        dangerous_ops = [
            (r'(\w+)\s*\+=\s*(\w+)', "compound_add"),
            (r'(\w+)\s*-=\s*(\w+)', "compound_sub"),
            (r'(\w+)\s*\*=\s*(\w+)', "compound_mul"),
        ]

        for pattern, op_type in dangerous_ops:
            for match in re.finditer(pattern, source):
                line = source[:match.start()].count("\n") + 1

                # Check if it's in an unchecked block or using checked math
                context_start = max(0, match.start() - 100)
                context = source[context_start:match.start()]

                if "checked_" not in context and ".unwrap()" not in source[match.end():match.end() + 50]:
                    findings.append(self.normalize_finding(
                        vuln_type=SolanaVulnerability.ARITHMETIC_OVERFLOW.value,
                        severity="High",
                        message=f"Potentially unsafe {op_type} operation",
                        location=Location(file=contract.source_path, line=line),
                        recommendation="Use checked arithmetic methods or require-* error handling.",
                    ))

        return findings

    def _check_cpi_reentrancy(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for CPI reentrancy risks."""
        findings = []
        source = contract.source_code

        # Find invoke calls
        invoke_pattern = r'(invoke|invoke_signed)\s*\('
        for match in re.finditer(invoke_pattern, source):
            line = source[:match.start()].count("\n") + 1

            # Check if there's state modification after invoke
            invoke_end = source.find(";", match.end())
            if invoke_end != -1:
                after_invoke = source[invoke_end:invoke_end + 200]

                # Look for state modifications
                if any(pattern in after_invoke for pattern in [".borrow_mut()", "= ", "+= ", "-= "]):
                    findings.append(self.normalize_finding(
                        vuln_type="cpi_reentrancy",
                        severity="High",
                        message="Potential CPI reentrancy vulnerability",
                        location=Location(file=contract.source_path, line=line),
                        description=(
                            "State is modified after a CPI call, which could lead to "
                            "reentrancy-like attacks if the called program makes a callback."
                        ),
                        recommendation=(
                            "Follow checks-effects-interactions pattern: validate inputs, "
                            "update state, then make external calls."
                        ),
                    ))

        return findings


# ============================================================================
# Registration
# ============================================================================


def register_solana_analyzer() -> SolanaAnalyzer:
    """Create and register the Solana analyzer."""
    analyzer = SolanaAnalyzer()
    register_chain_analyzer(analyzer)
    return analyzer


# ============================================================================
# Convenience Functions
# ============================================================================


def analyze_solana_program(
    source_path: Union[str, Path],
    properties: Optional[List[SecurityProperty]] = None,
) -> Dict[str, Any]:
    """
    Analyze a Solana program.

    Args:
        source_path: Path to .rs or IDL .json file
        properties: Security properties to check

    Returns:
        Analysis result
    """
    analyzer = SolanaAnalyzer()
    return analyzer.analyze(source_path, properties)


def parse_anchor_idl(idl_path: Union[str, Path]) -> AbstractContract:
    """
    Parse an Anchor IDL file.

    Args:
        idl_path: Path to IDL JSON file

    Returns:
        AbstractContract representation
    """
    analyzer = SolanaAnalyzer()
    return analyzer.parse(idl_path)


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "SolanaAnalyzer",
    "SolanaVulnerability",
    "SolanaPatternDetector",
    "AnchorAccount",
    "AnchorInstruction",
    "AnchorIDL",
    "register_solana_analyzer",
    "analyze_solana_program",
    "parse_anchor_idl",
]
