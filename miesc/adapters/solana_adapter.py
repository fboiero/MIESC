"""
Solana/Anchor Adapter
=====================

⚠️  EXPERIMENTAL / ROADMAP — NOT production-validated.
This non-EVM adapter uses pattern-based (regex/heuristic) detection only and is
NOT registered in the active tool. EVM analysis is the production-ready surface.
Non-EVM chains are future work (in test/development). See docs/MULTICHAIN.md.

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
from typing import Any, Dict, List, Optional, Union, cast

from miesc.core.chain_abstraction import (
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
    # v5.1.9: 2024-2025 Anchor patterns from real exploits
    ACCOUNT_CLOSURE_REENTRANCY = "account_closure_reentrancy"
    MISSING_DISCRIMINATOR = "missing_discriminator"
    TOKEN_AUTHORITY_MISMATCH = "token_authority_mismatch"
    PROGRAM_UPGRADE_EXPOSURE = "program_upgrade_exposure"
    UNCHECKED_CPI_RETURN = "unchecked_cpi_return"
    FREEZE_AUTHORITY_MISSING = "freeze_authority_missing"
    REMAINING_ACCOUNTS_UNVALIDATED = "remaining_accounts_unvalidated"


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


def _blank_rust(source: str) -> str:
    """Blank comment and string *contents* (newlines preserved) so regex rules
    match real code, not words in comments/strings.

    Rust-aware, unlike a Solidity blanker: ``'`` is NEVER treated as a string
    delimiter, so lifetimes such as ``<'info>`` are left intact (the old
    Solidity-style blanker opened a "string" at the lifetime tick and blanked the
    rest of the struct). Handles ``//`` line comments, ``/* */`` nestable block
    comments, and ``"..."`` strings with ``\\`` escapes. Raw strings
    (``r"..."``/``r#"..."#``) are a documented limitation.
    """
    out: List[str] = []
    i, n = 0, len(source)
    state = "code"  # code | line | block | string
    depth = 0
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out.append("  ")
                i += 2
                state = "line"
            elif ch == "/" and nxt == "*":
                out.append("  ")
                i += 2
                depth = 1
                state = "block"
            elif ch == '"':
                out.append(" ")
                i += 1
                state = "string"
            else:
                out.append(ch)
                i += 1
        elif state == "line":
            if ch == "\n":
                out.append("\n")
                state = "code"
            else:
                out.append(" ")
            i += 1
        elif state == "block":
            if ch == "/" and nxt == "*":
                out.append("  ")
                i += 2
                depth += 1
            elif ch == "*" and nxt == "/":
                out.append("  ")
                i += 2
                depth -= 1
                if depth == 0:
                    state = "code"
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
        elif state == "string":
            if ch == "\\" and nxt:
                out.append("  ")
                i += 2
            elif ch == '"':
                out.append(" ")
                i += 1
                state = "code"
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
    return "".join(out)


class SolanaPatternDetector:
    """Detects *genuine* Solana/Anchor vulnerabilities (hardened 2026-11-12).

    The previous version emitted SAFE constructs (``checked_add``,
    ``find_program_address``, ``CpiContext::new``, ``#[account(init)]`` ...) as
    "findings" and used line-local negative-lookahead regexes that could not see
    the ``#[derive(Accounts)]`` struct where Anchor's validation lives — measured
    firing 13 findings (10 High) on a clean 41-line Anchor program. This version:

    * blanks comments/strings first, **Rust-aware** (lifetimes like ``<'info>``
      are never read as string literals);
    * emits only genuine vulnerability patterns;
    * uses the disproving control (safe math on the line, a program-id check, an
      ``owner``/``has_one``/``address``/``constraint`` in the nearby attribute) as
      a **suppressor** — it stays silent when the control is visible.

    Pattern-level only (no full Anchor parse), so it is conservative: it favors
    precision and will miss validations split across many lines, macro-generated
    code, or cross-file flows. Experimental — no recall/precision validated.
    """

    _FINANCIAL = (
        r"(?:balance|amount|lamports|total|supply|stake|deposit|debt|reserve|shares|collateral)"
    )
    _SAFE_MATH = re.compile(r"\b(?:checked_|saturating_|wrapping_)(?:add|sub|mul|div)\b")
    _UNCHECKED_ASSIGN = re.compile(r"\b\w*" + _FINANCIAL + r"\w*\s*(?:\+=|-=|\*=)", re.IGNORECASE)
    _UNCHECKED_EXPR = re.compile(
        r"\b\w*" + _FINANCIAL + r"\w*\s*=\s*[^;]*[+\-*][^;]+", re.IGNORECASE
    )
    _RAW_LAMPORT_MUT = re.compile(
        r"(?:try_borrow_mut_lamports\s*\(\s*\)\s*\??|lamports\s*\(\s*\)\s*\.\s*borrow_mut\s*\(\s*\))"
        r"\s*[-+*]?="
    )
    _INVOKE = re.compile(r"\binvoke(?:_signed)?\s*\(")
    # Treat a typed Program<'info,...> account or an explicit key equality as
    # evidence the program validates its CPI target. Conservative (may suppress a
    # real arbitrary CPI); passing an account's .key as an argument does NOT count.
    _ID_CHECK = re.compile(r"require_keys_eq!|\.key\(\)\s*==|\bProgram\s*<\s*'")
    _CREATE_PDA = re.compile(r"\bcreate_program_address\s*\(")
    _UNCHECKED_ACCT = re.compile(r"\b(?:UncheckedAccount|AccountInfo)\s*<")
    _ACCT_CONSTRAINT = re.compile(
        r"owner\s*=|address\s*=|has_one|constraint\s*=|seeds\s*=|\baddress\b"
    )

    def detect_patterns(self, source_code: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect genuine vulnerability patterns. Output shape is unchanged:
        ``{pattern, category, severity, line, file, code}`` per finding."""
        findings: List[Dict[str, Any]] = []
        blank = _blank_rust(source_code)
        blines = blank.splitlines()
        raws = source_code.splitlines()
        while len(raws) < len(blines):
            raws.append("")

        file_has_id_check = bool(self._ID_CHECK.search(blank))

        def add(idx: int, name: str, category: str, severity: str) -> None:
            findings.append(
                {
                    "pattern": name,
                    "category": category,
                    "severity": severity,
                    "line": idx + 1,
                    "file": file_path,
                    "code": raws[idx].strip(),
                }
            )

        for i, bl in enumerate(blines):
            # 1. Unchecked arithmetic on a financial value (no safe math on the line)
            if (
                self._UNCHECKED_ASSIGN.search(bl) or self._UNCHECKED_EXPR.search(bl)
            ) and not self._SAFE_MATH.search(bl):
                add(i, "unchecked_arithmetic", "arithmetic", "Medium")
            # 2. Manual lamport mutation — verify a signer/owner check authorizes it
            if self._RAW_LAMPORT_MUT.search(bl):
                add(i, "raw_lamport_mutation", "access_control", "High")
            # 3. Arbitrary CPI: invoke with no program-id validation anywhere in file
            if self._INVOKE.search(bl) and not file_has_id_check:
                add(i, "arbitrary_cpi", "external_calls", "Medium")
            # 4. Non-canonical PDA derivation (use find_program_address + stored bump)
            if self._CREATE_PDA.search(bl):
                add(i, "non_canonical_pda", "input_validation", "Medium")
            # 5. Unchecked account with no validating constraint in the attribute block
            if self._UNCHECKED_ACCT.search(bl):
                window = " ".join(blines[max(0, i - 3) : i + 1])
                if not self._ACCT_CONSTRAINT.search(window):
                    add(i, "unchecked_account_no_constraint", "access_control", "Medium")

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

    def __init__(self) -> None:
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
        function_pattern = r"pub\s+fn\s+(\w+)\s*\(([^)]*)\)[^{]*\{"
        for match in re.finditer(function_pattern, source_code):
            func_name = match.group(1)
            params_str = match.group(2)
            line_num = source_code[: match.start()].count("\n") + 1

            # Parse parameters
            parameters = []
            if params_str.strip():
                for param_match in re.finditer(r"(\w+)\s*:\s*([^,]+)", params_str):
                    param_name = param_match.group(1)
                    param_type = param_match.group(2).strip()
                    parameters.append(
                        Parameter(
                            name=param_name,
                            type_info=TypeInfo(name=param_type),
                        )
                    )

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
        account_pattern = r"#\[account\(([^)]*)\)\]\s*pub\s+struct\s+(\w+)"
        for match in re.finditer(account_pattern, source_code):
            attrs = match.group(1)
            struct_name = match.group(2)
            line_num = source_code[: match.start()].count("\n") + 1

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
        event_pattern = r"#\[event\]\s*pub\s+struct\s+(\w+)"
        for match in re.finditer(event_pattern, source_code):
            event_name = match.group(1)
            line_num = source_code[: match.start()].count("\n") + 1

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
                return cast(str, idl_type["defined"])
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
        findings: List[Dict[str, Any]] = []
        source_code = contract.source_code

        if not source_code:
            return findings

        properties = properties or list(SecurityProperty)

        # Run pattern detector
        pattern_matches = self.pattern_detector.detect_patterns(source_code, contract.source_path)

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
        match["category"]

        # Finding message + recommendation per hardened pattern name.
        messages = {
            "unchecked_arithmetic": (
                "Unchecked arithmetic on a financial value",
                "Use checked_add/checked_sub/checked_mul (or ensure overflow-checks "
                "is on for the release profile).",
            ),
            "raw_lamport_mutation": (
                "Manual lamport mutation without a visible authorization check",
                "Verify a Signer/owner constraint authorizes this transfer; prefer a "
                "CPI transfer or `#[account(close = ...)]` over hand-editing lamports.",
            ),
            "arbitrary_cpi": (
                "CPI invoke with no visible program-id validation",
                "Type the target as `Program<'info, T>` or check its key with "
                "`require_keys_eq!` before invoking.",
            ),
            "non_canonical_pda": (
                "Non-canonical PDA derivation via create_program_address",
                "Use `find_program_address` and store/verify the canonical bump.",
            ),
            "unchecked_account_no_constraint": (
                "UncheckedAccount/AccountInfo with no validating constraint",
                "Add `owner`/`address`/`has_one`/`seeds`, or use a typed "
                "`Account<'info, T>` so Anchor validates the account.",
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
        findings: List[Dict[str, Any]] = []
        source = contract.source_code

        # Look for instruction handlers without signer checks
        handler_pattern = r"pub\s+fn\s+(\w+)\s*\(\s*ctx\s*:\s*Context<(\w+)>"
        for match in re.finditer(handler_pattern, source):
            func_name = match.group(1)
            ctx_type = match.group(2)
            line = source[: match.start()].count("\n") + 1

            # Find the accounts struct
            ctx_pattern = rf"#\[derive\(Accounts\)\]\s*pub\s+struct\s+{ctx_type}"
            ctx_match = re.search(ctx_pattern, source)

            if ctx_match:
                # Check if any mutable account lacks signer
                ctx_start = ctx_match.end()
                ctx_end = source.find("}", ctx_start)
                ctx_body = source[ctx_start:ctx_end]

                # A field typed `Signer<'info>` (or an explicit is_signer /
                # #[account(signer)] / has_one) is Anchor's signer validation.
                # The old check tested lowercase "signer", which never matches the
                # `Signer` type and so flagged every struct that used it — the main
                # source of false positives on clean Anchor code.
                has_signer = (
                    "Signer<" in ctx_body
                    or "is_signer" in ctx_body
                    or "#[account(signer" in ctx_body
                    or "has_one" in ctx_body
                )
                if "#[account(mut" in ctx_body:
                    if not has_signer:
                        findings.append(
                            self.normalize_finding(
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
                            )
                        )

        return findings

    def _check_account_validation(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for missing account validation."""
        findings: List[Dict[str, Any]] = []
        source = contract.source_code

        # Check for AccountInfo without validation
        if "AccountInfo<'info>" in source:
            # Find usages without validation
            info_pattern = r"(\w+)\s*:\s*AccountInfo<\'info>"
            for match in re.finditer(info_pattern, source):
                account_name = match.group(1)
                line = source[: match.start()].count("\n") + 1

                # Check if there's a constraint for this account
                context_line = source[: match.end()].rfind("#[account(")
                has_constraint = context_line > source[: match.start()].rfind("\n")

                if not has_constraint:
                    findings.append(
                        self.normalize_finding(
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
                        )
                    )

        return findings

    def _check_arithmetic_safety(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for unsafe arithmetic."""
        findings: List[Dict[str, Any]] = []
        source = contract.source_code

        # Dangerous patterns
        dangerous_ops = [
            (r"(\w+)\s*\+=\s*(\w+)", "compound_add"),
            (r"(\w+)\s*-=\s*(\w+)", "compound_sub"),
            (r"(\w+)\s*\*=\s*(\w+)", "compound_mul"),
        ]

        for pattern, op_type in dangerous_ops:
            for match in re.finditer(pattern, source):
                line = source[: match.start()].count("\n") + 1

                # Check if it's in an unchecked block or using checked math
                context_start = max(0, match.start() - 100)
                context = source[context_start : match.start()]

                if (
                    "checked_" not in context
                    and ".unwrap()" not in source[match.end() : match.end() + 50]
                ):
                    findings.append(
                        self.normalize_finding(
                            vuln_type=SolanaVulnerability.ARITHMETIC_OVERFLOW.value,
                            severity="High",
                            message=f"Potentially unsafe {op_type} operation",
                            location=Location(file=contract.source_path, line=line),
                            recommendation="Use checked arithmetic methods or require-* error handling.",
                        )
                    )

        return findings

    def _check_cpi_reentrancy(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for CPI reentrancy risks."""
        findings: List[Dict[str, Any]] = []
        source = contract.source_code

        # Find invoke calls
        invoke_pattern = r"(invoke|invoke_signed)\s*\("
        for match in re.finditer(invoke_pattern, source):
            line = source[: match.start()].count("\n") + 1

            # Check if there's state modification after invoke
            invoke_end = source.find(";", match.end())
            if invoke_end != -1:
                after_invoke = source[invoke_end : invoke_end + 200]

                # Look for state modifications
                if any(
                    pattern in after_invoke for pattern in [".borrow_mut()", "= ", "+= ", "-= "]
                ):
                    findings.append(
                        self.normalize_finding(
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
                        )
                    )

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
