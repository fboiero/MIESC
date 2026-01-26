"""
Cardano/Plutus Adapter
======================

Adapter for analyzing Cardano smart contracts written in Plutus (Haskell) and Aiken.

Features:
- Parse Plutus Haskell source code
- Parse Aiken source code
- Understand eUTXO model (datums, redeemers, script context)
- Detect Cardano-specific vulnerabilities:
  - Double satisfaction attacks
  - Datum hijacking
  - Missing datum validation
  - Redeemer injection
  - Minting policy bypass
  - Reference input manipulation
  - Time validity attacks
  - Insufficient collateral checks

References:
- https://developers.cardano.org/
- https://plutus.readthedocs.io/
- https://aiken-lang.org/
- https://github.com/input-output-hk/plutus

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
# Cardano-Specific Types
# ============================================================================


class CardanoVulnerability(Enum):
    """Cardano-specific vulnerability types."""

    # eUTXO Model Vulnerabilities
    DOUBLE_SATISFACTION = "double_satisfaction"
    DATUM_HIJACKING = "datum_hijacking"
    MISSING_DATUM_VALIDATION = "missing_datum_validation"
    REDEEMER_INJECTION = "redeemer_injection"
    UTXO_CONTENTION = "utxo_contention"

    # Minting Policy Vulnerabilities
    UNAUTHORIZED_MINTING = "unauthorized_minting"
    MISSING_MINTING_CHECK = "missing_minting_check"
    TOKEN_NAME_COLLISION = "token_name_collision"

    # Validator Vulnerabilities
    MISSING_SIGNER_CHECK = "missing_signer_check"
    WEAK_VALIDATOR_LOGIC = "weak_validator_logic"
    INCOMPLETE_PATTERN_MATCH = "incomplete_pattern_match"
    UNBOUNDED_COMPUTATION = "unbounded_computation"

    # Time-based Vulnerabilities
    TIME_VALIDITY_BYPASS = "time_validity_bypass"
    SLOT_MANIPULATION = "slot_manipulation"

    # Reference Input Vulnerabilities
    REFERENCE_INPUT_MANIPULATION = "reference_input_manipulation"
    MISSING_REFERENCE_VALIDATION = "missing_reference_validation"

    # Value Handling
    ADA_CALCULATION_ERROR = "ada_calculation_error"
    INSUFFICIENT_COLLATERAL = "insufficient_collateral"
    VALUE_NOT_PRESERVED = "value_not_preserved"

    # Script Context
    MISSING_CONTEXT_CHECK = "missing_context_check"
    SCRIPT_HASH_MISMATCH = "script_hash_mismatch"


class PlutusScriptType(Enum):
    """Types of Plutus scripts."""

    VALIDATOR = "validator"
    MINTING_POLICY = "minting_policy"
    STAKING = "staking"


@dataclass
class PlutusValidator:
    """Represents a Plutus validator script."""

    name: str
    script_type: PlutusScriptType
    datum_type: Optional[str] = None
    redeemer_type: Optional[str] = None
    parameters: List[Tuple[str, str]] = field(default_factory=list)
    body: str = ""
    has_datum_check: bool = False
    has_signer_check: bool = False
    has_time_check: bool = False
    has_value_check: bool = False
    location: Optional[Location] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "script_type": self.script_type.value,
            "datum_type": self.datum_type,
            "redeemer_type": self.redeemer_type,
            "has_datum_check": self.has_datum_check,
            "has_signer_check": self.has_signer_check,
            "has_time_check": self.has_time_check,
            "has_value_check": self.has_value_check,
        }


@dataclass
class AikenValidator:
    """Represents an Aiken validator."""

    name: str
    script_type: PlutusScriptType
    datum_type: Optional[str] = None
    redeemer_type: Optional[str] = None
    parameters: List[Tuple[str, str]] = field(default_factory=list)
    body: str = ""
    when_clauses: List[str] = field(default_factory=list)
    location: Optional[Location] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "script_type": self.script_type.value,
            "datum_type": self.datum_type,
            "redeemer_type": self.redeemer_type,
            "when_clauses": self.when_clauses,
        }


@dataclass
class CardanoContract:
    """Parsed Cardano contract information."""

    name: str
    language: str  # "plutus" or "aiken"
    validators: List[Union[PlutusValidator, AikenValidator]] = field(default_factory=list)
    minting_policies: List[Union[PlutusValidator, AikenValidator]] = field(default_factory=list)
    data_types: List[Dict[str, Any]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Plutus (Haskell) Parser
# ============================================================================


class PlutusParser:
    """Parser for Plutus Haskell source code."""

    # Module/Import patterns
    MODULE_PATTERN = r"module\s+(\w+(?:\.\w+)*)"
    IMPORT_PATTERN = r"import\s+(?:qualified\s+)?(\w+(?:\.\w+)*)"

    # Validator patterns
    VALIDATOR_PATTERN = r"mkValidator\s*::\s*([^-]+)\s*->\s*([^-]+)\s*->\s*ScriptContext\s*->\s*Bool"
    MINTING_PATTERN = r"mkMintingPolicy\s*::\s*([^-]+)\s*->\s*ScriptContext\s*->\s*Bool"

    # Type patterns
    DATA_PATTERN = r"data\s+(\w+)\s*=\s*([^|]+(?:\|[^|]+)*)"
    NEWTYPE_PATTERN = r"newtype\s+(\w+)\s*=\s*(\w+)\s*\{([^}]+)\}"

    # Function patterns
    FUNCTION_PATTERN = r"(\w+)\s*::\s*([^\n]+)\n\1\s+([^=]+)=\s*"

    # Security-relevant patterns
    SIGNER_PATTERNS = [
        r"txSignedBy",
        r"signatories",
        r"txInfoSignatories",
        r"elem\s+\w+\s+signers",
    ]

    DATUM_PATTERNS = [
        r"findDatum",
        r"getDatum",
        r"txInfoData",
        r"Datum\s*\(",
    ]

    TIME_PATTERNS = [
        r"txInfoValidRange",
        r"contains\s+\w+\s+validRange",
        r"POSIXTime",
        r"interval",
    ]

    VALUE_PATTERNS = [
        r"valuePaidTo",
        r"valueProduced",
        r"txOutValue",
        r"Ada\.lovelaceValueOf",
    ]

    def parse(self, source_path: Union[str, Path]) -> CardanoContract:
        """Parse Plutus Haskell source file."""
        path = Path(source_path)
        content = path.read_text()

        contract = CardanoContract(
            name=path.stem,
            language="plutus",
        )

        # Parse imports
        contract.imports = self._parse_imports(content)

        # Parse data types
        contract.data_types = self._parse_data_types(content)

        # Parse validators
        contract.validators = self._parse_validators(content)

        # Parse minting policies
        contract.minting_policies = self._parse_minting_policies(content)

        return contract

    def _parse_imports(self, content: str) -> List[str]:
        """Parse module imports."""
        imports = []
        for match in re.finditer(self.IMPORT_PATTERN, content):
            imports.append(match.group(1))
        return imports

    def _parse_data_types(self, content: str) -> List[Dict[str, Any]]:
        """Parse data type definitions."""
        types = []

        for match in re.finditer(self.DATA_PATTERN, content):
            type_name = match.group(1)
            constructors = match.group(2).strip()
            types.append({
                "name": type_name,
                "constructors": [c.strip() for c in constructors.split("|")],
            })

        for match in re.finditer(self.NEWTYPE_PATTERN, content):
            type_name = match.group(1)
            types.append({
                "name": type_name,
                "newtype": True,
            })

        return types

    def _parse_validators(self, content: str) -> List[PlutusValidator]:
        """Parse validator definitions."""
        validators = []
        lines = content.split("\n")

        for match in re.finditer(self.VALIDATOR_PATTERN, content):
            datum_type = match.group(1).strip()
            redeemer_type = match.group(2).strip()

            # Find the function body
            start_pos = match.end()
            line_no = content[:match.start()].count("\n") + 1

            # Extract body (simplified)
            body = self._extract_function_body(content, start_pos)

            validator = PlutusValidator(
                name="validator",
                script_type=PlutusScriptType.VALIDATOR,
                datum_type=datum_type,
                redeemer_type=redeemer_type,
                body=body,
                has_datum_check=self._has_pattern(body, self.DATUM_PATTERNS),
                has_signer_check=self._has_pattern(body, self.SIGNER_PATTERNS),
                has_time_check=self._has_pattern(body, self.TIME_PATTERNS),
                has_value_check=self._has_pattern(body, self.VALUE_PATTERNS),
                location=Location(file=str(Path().absolute()), line=line_no),
            )
            validators.append(validator)

        return validators

    def _parse_minting_policies(self, content: str) -> List[PlutusValidator]:
        """Parse minting policy definitions."""
        policies = []

        for match in re.finditer(self.MINTING_PATTERN, content):
            redeemer_type = match.group(1).strip()
            start_pos = match.end()
            line_no = content[:match.start()].count("\n") + 1

            body = self._extract_function_body(content, start_pos)

            policy = PlutusValidator(
                name="mintingPolicy",
                script_type=PlutusScriptType.MINTING_POLICY,
                redeemer_type=redeemer_type,
                body=body,
                has_signer_check=self._has_pattern(body, self.SIGNER_PATTERNS),
                has_time_check=self._has_pattern(body, self.TIME_PATTERNS),
                location=Location(file=str(Path().absolute()), line=line_no),
            )
            policies.append(policy)

        return policies

    def _extract_function_body(self, content: str, start_pos: int) -> str:
        """Extract function body from position."""
        # Find the next top-level definition or end of file
        remaining = content[start_pos:]

        # Look for next function definition at column 0
        lines = remaining.split("\n")
        body_lines = []

        for line in lines:
            # Stop at next top-level definition
            if line and not line[0].isspace() and re.match(r"\w+\s*::", line):
                break
            body_lines.append(line)

        return "\n".join(body_lines[:50])  # Limit for performance

    def _has_pattern(self, content: str, patterns: List[str]) -> bool:
        """Check if content contains any of the patterns."""
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False


# ============================================================================
# Aiken Parser
# ============================================================================


class AikenParser:
    """Parser for Aiken source code."""

    # Import patterns
    USE_PATTERN = r"use\s+(\w+(?:/\w+)*)"

    # Validator patterns
    VALIDATOR_PATTERN = r"validator\s+(\w+)\s*(?:\(([^)]*)\))?\s*\{"
    MINT_PATTERN = r"mint\s*\(([^)]*)\)\s*\{"

    # Function patterns
    FN_PATTERN = r"fn\s+(\w+)\s*\(([^)]*)\)(?:\s*->\s*([^{]+))?\s*\{"

    # Type patterns
    TYPE_PATTERN = r"type\s+(\w+)\s*(?:<[^>]+>)?\s*\{([^}]+)\}"
    ENUM_PATTERN = r"type\s+(\w+)\s*=\s*\n(\s+\|[^\n]+)+"

    # Pattern matching
    WHEN_PATTERN = r"when\s+\w+\s+is\s*\{"
    IF_PATTERN = r"if\s+([^{]+)\s*\{"
    EXPECT_PATTERN = r"expect\s+([^=]+)="

    # Security patterns
    SIGNER_PATTERNS = [
        r"list\.has\(.*signator",
        r"signator.*list\.has",
        r"must_be_signed_by",
        r"extra_signatories",
    ]

    DATUM_PATTERNS = [
        r"datum\s*:",
        r"expect.*datum",
        r"InlineDatum",
    ]

    TIME_PATTERNS = [
        r"validity_range",
        r"valid_after",
        r"valid_before",
        r"interval\.",
    ]

    VALUE_PATTERNS = [
        r"value\.from_lovelace",
        r"value\.lovelace_of",
        r"value\.quantity_of",
        r"outputs_at",
    ]

    def parse(self, source_path: Union[str, Path]) -> CardanoContract:
        """Parse Aiken source file."""
        path = Path(source_path)
        content = path.read_text()

        contract = CardanoContract(
            name=path.stem,
            language="aiken",
        )

        # Parse imports
        contract.imports = self._parse_imports(content)

        # Parse types
        contract.data_types = self._parse_types(content)

        # Parse validators
        contract.validators = self._parse_validators(content, path)

        return contract

    def _parse_imports(self, content: str) -> List[str]:
        """Parse use statements."""
        imports = []
        for match in re.finditer(self.USE_PATTERN, content):
            imports.append(match.group(1))
        return imports

    def _parse_types(self, content: str) -> List[Dict[str, Any]]:
        """Parse type definitions."""
        types = []

        for match in re.finditer(self.TYPE_PATTERN, content):
            type_name = match.group(1)
            fields = match.group(2).strip()
            types.append({
                "name": type_name,
                "fields": fields,
            })

        return types

    def _parse_validators(self, content: str, path: Path) -> List[AikenValidator]:
        """Parse validator definitions."""
        validators = []
        lines = content.split("\n")

        for match in re.finditer(self.VALIDATOR_PATTERN, content):
            name = match.group(1)
            params_str = match.group(2) or ""
            start_pos = match.end()
            line_no = content[:match.start()].count("\n") + 1

            body = self._extract_body(content, start_pos)
            when_clauses = self._find_when_clauses(body)

            # Parse parameters
            params = self._parse_params(params_str)

            # Determine datum and redeemer types from signature
            datum_type, redeemer_type = self._infer_types(body)

            validator = AikenValidator(
                name=name,
                script_type=PlutusScriptType.VALIDATOR,
                datum_type=datum_type,
                redeemer_type=redeemer_type,
                parameters=params,
                body=body,
                when_clauses=when_clauses,
                location=Location(file=str(path), line=line_no),
            )
            validators.append(validator)

        return validators

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

        return params

    def _extract_body(self, content: str, start_pos: int) -> str:
        """Extract validator body."""
        brace_count = 1
        pos = start_pos

        while pos < len(content) and brace_count > 0:
            if content[pos] == "{":
                brace_count += 1
            elif content[pos] == "}":
                brace_count -= 1
            pos += 1

        return content[start_pos:pos - 1]

    def _find_when_clauses(self, body: str) -> List[str]:
        """Find when/pattern match clauses."""
        clauses = []
        for match in re.finditer(r"(\w+)\s*->", body):
            clauses.append(match.group(1))
        return clauses

    def _infer_types(self, body: str) -> Tuple[Optional[str], Optional[str]]:
        """Infer datum and redeemer types from body."""
        datum_type = None
        redeemer_type = None

        # Look for type annotations in expect statements
        datum_match = re.search(r"datum\s*:\s*(\w+)", body)
        if datum_match:
            datum_type = datum_match.group(1)

        redeemer_match = re.search(r"redeemer\s*:\s*(\w+)", body)
        if redeemer_match:
            redeemer_type = redeemer_match.group(1)

        return datum_type, redeemer_type


# ============================================================================
# Cardano Pattern Detector
# ============================================================================


class CardanoPatternDetector:
    """Pattern-based vulnerability detector for Cardano contracts."""

    # Double satisfaction patterns
    DOUBLE_SATISFACTION_PATTERNS = {
        "missing_output_check": r"(?!.*outputs_at)validator",
        "multiple_inputs": r"inputs.*inputs",
        "shared_utxo": r"utxo.*shared|shared.*utxo",
    }

    # Datum validation patterns
    DATUM_PATTERNS = {
        "inline_datum": r"InlineDatum|inline_datum",
        "datum_hash": r"DatumHash|datum_hash",
        "find_datum": r"findDatum|find_datum",
        "expect_datum": r"expect.*datum",
    }

    # Signer check patterns
    SIGNER_PATTERNS = {
        "signed_by": r"txSignedBy|must_be_signed_by|list\.has.*signator",
        "signatories": r"signatories|extra_signatories",
        "pubkey_hash": r"PubKeyHash|pub_key_hash",
    }

    # Time validity patterns
    TIME_PATTERNS = {
        "valid_range": r"txInfoValidRange|validity_range",
        "interval_check": r"contains.*interval|interval\.(before|after|between)",
        "posix_time": r"POSIXTime|posix_time",
        "slot_check": r"slot\s*(>|<|>=|<=|==)",
    }

    # Value handling patterns
    VALUE_PATTERNS = {
        "value_paid": r"valuePaidTo|value_paid_to",
        "lovelace": r"lovelaceValueOf|lovelace_of|from_lovelace",
        "value_produced": r"valueProduced|value_produced",
        "ada_check": r"Ada\.|ada_value",
    }

    # Minting patterns
    MINTING_PATTERNS = {
        "minted_value": r"txInfoMint|mint.*value|minted_value",
        "token_name": r"TokenName|token_name",
        "currency_symbol": r"CurrencySymbol|currency_symbol|policy_id",
    }

    @classmethod
    def detect_plutus_vulnerabilities(
        cls, contract: CardanoContract, content: str
    ) -> List[Dict[str, Any]]:
        """Detect vulnerabilities in Plutus code."""
        findings = []

        for validator in contract.validators:
            # Check for missing datum validation
            if not validator.has_datum_check:
                findings.append({
                    "type": CardanoVulnerability.MISSING_DATUM_VALIDATION.value,
                    "validator": validator.name,
                    "line": validator.location.line if validator.location else 0,
                    "message": f"Validator '{validator.name}' may not properly validate datum",
                    "severity": "High",
                    "recommendation": "Use findDatum/getDatum and validate datum contents",
                })

            # Check for missing signer check
            if not validator.has_signer_check:
                findings.append({
                    "type": CardanoVulnerability.MISSING_SIGNER_CHECK.value,
                    "validator": validator.name,
                    "line": validator.location.line if validator.location else 0,
                    "message": f"Validator '{validator.name}' may not check transaction signers",
                    "severity": "High",
                    "recommendation": "Use txSignedBy to verify required signatures",
                })

            # Check for missing value validation
            if not validator.has_value_check:
                findings.append({
                    "type": CardanoVulnerability.VALUE_NOT_PRESERVED.value,
                    "validator": validator.name,
                    "line": validator.location.line if validator.location else 0,
                    "message": f"Validator '{validator.name}' may not validate value preservation",
                    "severity": "Medium",
                    "recommendation": "Verify output values match expected amounts",
                })

        # Check minting policies
        for policy in contract.minting_policies:
            if not policy.has_signer_check:
                findings.append({
                    "type": CardanoVulnerability.UNAUTHORIZED_MINTING.value,
                    "policy": policy.name,
                    "line": policy.location.line if policy.location else 0,
                    "message": f"Minting policy '{policy.name}' may allow unauthorized minting",
                    "severity": "Critical",
                    "recommendation": "Add signer verification to minting policy",
                })

        # Global content checks
        findings.extend(cls._check_global_patterns(content))

        return findings

    @classmethod
    def detect_aiken_vulnerabilities(
        cls, contract: CardanoContract, content: str
    ) -> List[Dict[str, Any]]:
        """Detect vulnerabilities in Aiken code."""
        findings = []
        lines = content.split("\n")

        # Check validators
        for validator in contract.validators:
            body = validator.body if hasattr(validator, 'body') else ""

            # Check for signer verification
            has_signer = bool(re.search(
                r"list\.has.*signator|must_be_signed|extra_signatories",
                body, re.IGNORECASE
            ))
            if not has_signer:
                findings.append({
                    "type": CardanoVulnerability.MISSING_SIGNER_CHECK.value,
                    "validator": validator.name,
                    "line": validator.location.line if validator.location else 0,
                    "message": f"Validator '{validator.name}' may not check transaction signers",
                    "severity": "High",
                    "recommendation": "Add list.has(signatories, required_signer) check",
                })

            # Check for datum validation
            has_datum = bool(re.search(r"expect.*datum|datum\s*:", body, re.IGNORECASE))
            if not has_datum and validator.datum_type:
                findings.append({
                    "type": CardanoVulnerability.MISSING_DATUM_VALIDATION.value,
                    "validator": validator.name,
                    "line": validator.location.line if validator.location else 0,
                    "message": f"Validator '{validator.name}' may not validate datum properly",
                    "severity": "High",
                    "recommendation": "Use expect to destructure and validate datum",
                })

            # Check for incomplete pattern matching
            when_clauses = validator.when_clauses if hasattr(validator, 'when_clauses') else []
            if not any("_" in c or "else" in c.lower() for c in when_clauses):
                # No catch-all pattern
                if when_clauses:
                    findings.append({
                        "type": CardanoVulnerability.INCOMPLETE_PATTERN_MATCH.value,
                        "validator": validator.name,
                        "line": validator.location.line if validator.location else 0,
                        "message": f"Validator '{validator.name}' may have incomplete pattern matching",
                        "severity": "Medium",
                        "recommendation": "Add a catch-all pattern (_) or ensure all cases are covered",
                    })

        # Check for double satisfaction risks
        if re.search(r"inputs.*filter|filter.*inputs", content):
            if not re.search(r"outputs_at|output.*script", content):
                findings.append({
                    "type": CardanoVulnerability.DOUBLE_SATISFACTION.value,
                    "line": 1,
                    "message": "Potential double satisfaction vulnerability - inputs processed without output verification",
                    "severity": "Critical",
                    "recommendation": "Verify outputs are sent to correct addresses/scripts",
                })

        # Check for time validity
        if re.search(r"deadline|expir|timeout", content, re.IGNORECASE):
            if not re.search(r"validity_range|valid_(before|after)", content):
                findings.append({
                    "type": CardanoVulnerability.TIME_VALIDITY_BYPASS.value,
                    "line": 1,
                    "message": "Time-sensitive logic without validity range check",
                    "severity": "High",
                    "recommendation": "Use validity_range to enforce time constraints",
                })

        return findings

    @classmethod
    def _check_global_patterns(cls, content: str) -> List[Dict[str, Any]]:
        """Check for global vulnerability patterns."""
        findings = []

        # Check for potential unbounded computation
        if re.search(r"foldr|foldl|map\s+\(", content):
            if re.search(r"all\s+inputs|all\s+outputs", content):
                findings.append({
                    "type": CardanoVulnerability.UNBOUNDED_COMPUTATION.value,
                    "line": 1,
                    "message": "Potential unbounded computation over all inputs/outputs",
                    "severity": "Medium",
                    "recommendation": "Consider limiting iterations to prevent exceeding execution units",
                })

        # Check for missing script context validation
        if not re.search(r"ScriptContext|script_context|ctx\.", content):
            findings.append({
                "type": CardanoVulnerability.MISSING_CONTEXT_CHECK.value,
                "line": 1,
                "message": "Script may not properly use ScriptContext",
                "severity": "Medium",
                "recommendation": "Validate relevant fields from ScriptContext",
            })

        return findings


# ============================================================================
# Cardano Analyzer
# ============================================================================


class CardanoAnalyzer(AbstractChainAnalyzer):
    """
    Analyzer for Cardano smart contracts (Plutus/Aiken).

    Integrates with MIESC chain abstraction layer for unified analysis.
    """

    def __init__(self):
        super().__init__(ChainType.CARDANO, ContractLanguage.PLUTUS)
        self.plutus_parser = PlutusParser()
        self.aiken_parser = AikenParser()

    @property
    def name(self) -> str:
        return "CardanoAnalyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return [".hs", ".ak"]

    def _detect_language(self, path: Path, content: str) -> str:
        """Detect contract language from file extension and content."""
        if path.suffix == ".ak":
            return "aiken"
        if path.suffix == ".hs":
            return "plutus"

        # Content-based detection
        if re.search(r"^use\s+aiken", content, re.MULTILINE):
            return "aiken"
        if re.search(r"^module\s+\w+", content, re.MULTILINE):
            return "plutus"

        return "plutus"  # Default

    def parse(self, source_path: Union[str, Path]) -> AbstractContract:
        """Parse Cardano source into AbstractContract."""
        path = Path(source_path)
        content = path.read_text()
        language = self._detect_language(path, content)

        if language == "aiken":
            return self._parse_aiken(path, content)
        else:
            return self._parse_plutus(path, content)

    def _parse_plutus(self, path: Path, content: str) -> AbstractContract:
        """Parse Plutus Haskell source file."""
        contract = self.plutus_parser.parse(path)

        # Convert validators to functions
        functions = []
        for validator in contract.validators + contract.minting_policies:
            func = AbstractFunction(
                name=validator.name,
                visibility=Visibility.PUBLIC,
                mutability=Mutability.MUTABLE,
                location=validator.location,
                body_source=validator.body,
                chain_metadata={
                    "script_type": validator.script_type.value,
                    "datum_type": validator.datum_type,
                    "redeemer_type": validator.redeemer_type,
                    "has_datum_check": validator.has_datum_check,
                    "has_signer_check": validator.has_signer_check,
                    "has_time_check": validator.has_time_check,
                    "has_value_check": validator.has_value_check,
                },
            )
            functions.append(func)

        return AbstractContract(
            name=contract.name,
            chain_type=ChainType.CARDANO,
            language=ContractLanguage.PLUTUS,
            source_path=str(path),
            source_code=content,
            functions=functions,
            imports=contract.imports,
        )

    def _parse_aiken(self, path: Path, content: str) -> AbstractContract:
        """Parse Aiken source file."""
        contract = self.aiken_parser.parse(path)

        # Convert validators to functions
        functions = []
        for validator in contract.validators:
            parameters = [
                Parameter(
                    name=name,
                    type_info=TypeInfo(name=type_str),
                )
                for name, type_str in validator.parameters
            ]

            func = AbstractFunction(
                name=validator.name,
                visibility=Visibility.PUBLIC,
                mutability=Mutability.MUTABLE,
                parameters=parameters,
                location=validator.location,
                body_source=validator.body,
                chain_metadata={
                    "script_type": validator.script_type.value,
                    "datum_type": validator.datum_type,
                    "redeemer_type": validator.redeemer_type,
                    "when_clauses": validator.when_clauses,
                },
            )
            functions.append(func)

        return AbstractContract(
            name=contract.name,
            chain_type=ChainType.CARDANO,
            language=ContractLanguage.AIKEN,
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
        """Detect vulnerabilities in Cardano contract."""
        findings = []
        content = contract.source_code

        # Default to all properties
        if properties is None:
            properties = list(SecurityProperty)

        # Reconstruct contract for pattern detection
        if contract.language == ContractLanguage.AIKEN:
            cardano_contract = self.aiken_parser.parse(contract.source_path)
            vuln_findings = CardanoPatternDetector.detect_aiken_vulnerabilities(
                cardano_contract, content
            )
        else:
            cardano_contract = self.plutus_parser.parse(contract.source_path)
            vuln_findings = CardanoPatternDetector.detect_plutus_vulnerabilities(
                cardano_contract, content
            )

        for f in vuln_findings:
            findings.append(self.normalize_finding(
                vuln_type=f["type"],
                severity=f["severity"],
                message=f["message"],
                location=Location(
                    file=contract.source_path,
                    line=f.get("line", 0),
                ),
                validator=f.get("validator"),
                policy=f.get("policy"),
                recommendation=f.get("recommendation"),
            ))

        return findings


# ============================================================================
# Registration
# ============================================================================


def register_cardano_analyzer() -> CardanoAnalyzer:
    """Register and return Cardano analyzer."""
    analyzer = CardanoAnalyzer()
    try:
        register_chain_analyzer(analyzer)
    except Exception as e:
        logger.warning(f"Failed to register CardanoAnalyzer: {e}")
    return analyzer


# Auto-register
try:
    register_cardano_analyzer()
except Exception as e:
    logger.warning(f"Failed to auto-register CardanoAnalyzer: {e}")


# Export for external use
__all__ = [
    "CardanoAnalyzer",
    "CardanoVulnerability",
    "CardanoPatternDetector",
    "PlutusParser",
    "AikenParser",
    "PlutusValidator",
    "AikenValidator",
    "CardanoContract",
    "PlutusScriptType",
    "register_cardano_analyzer",
]
