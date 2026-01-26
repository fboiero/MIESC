"""
Stellar/Soroban Adapter
=======================

Adapter for analyzing Stellar smart contracts written for the Soroban platform.

Features:
- Parse Soroban SDK Rust source code
- Detect Stellar-specific vulnerabilities:
  - Missing authorization checks
  - Storage access issues
  - Panic handling in production
  - Cross-contract invocation safety
  - Time-bound operations
  - Token handling issues
  - Resource exhaustion

References:
- https://soroban.stellar.org/
- https://stellar.org/developers/soroban
- https://github.com/stellar/soroban-examples

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
# Stellar-Specific Types
# ============================================================================


class StellarVulnerability(Enum):
    """Stellar/Soroban-specific vulnerability types."""

    MISSING_AUTH_CHECK = "missing_auth_check"
    MISSING_REQUIRE_AUTH = "missing_require_auth"
    UNPROTECTED_STORAGE = "unprotected_storage"
    PANIC_IN_CONTRACT = "panic_in_contract"
    UNWRAP_WITHOUT_CHECK = "unwrap_without_check"
    CROSS_CONTRACT_UNSAFE = "cross_contract_unsafe"
    TIME_BOUND_MISSING = "time_bound_missing"
    TOKEN_TRANSFER_UNCHECKED = "token_transfer_unchecked"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    STORAGE_COLLISION = "storage_collision"
    REENTRANCY_RISK = "reentrancy_risk"
    ARITHMETIC_OVERFLOW = "arithmetic_overflow"
    EVENT_EMISSION_MISSING = "event_emission_missing"
    TTL_NOT_EXTENDED = "ttl_not_extended"
    ADMIN_UNPROTECTED = "admin_unprotected"


@dataclass
class SorobanFunction:
    """Represents a Soroban contract function."""

    name: str
    visibility: str  # pub, pub(crate), etc.
    is_init: bool = False
    is_upgrade: bool = False
    has_auth: bool = False
    parameters: List[Tuple[str, str]] = field(default_factory=list)  # (name, type)
    return_type: Optional[str] = None
    decorators: List[str] = field(default_factory=list)  # #[contractimpl], etc.
    body: str = ""
    location: Optional[Location] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "visibility": self.visibility,
            "is_init": self.is_init,
            "has_auth": self.has_auth,
            "parameters": [{"name": n, "type": t} for n, t in self.parameters],
            "return_type": self.return_type,
            "decorators": self.decorators,
        }


@dataclass
class SorobanStorage:
    """Represents Soroban storage access."""

    key_type: str
    value_type: str
    storage_type: str  # Instance, Persistent, Temporary
    access_pattern: str  # get, set, has, remove
    location: Optional[Location] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_type": self.key_type,
            "value_type": self.value_type,
            "storage_type": self.storage_type,
            "access_pattern": self.access_pattern,
        }


@dataclass
class SorobanContract:
    """Parsed Soroban contract information."""

    name: str
    functions: List[SorobanFunction] = field(default_factory=list)
    storage_accesses: List[SorobanStorage] = field(default_factory=list)
    events: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    traits_impl: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Stellar Pattern Detectors
# ============================================================================


class StellarPatternDetector:
    """Pattern-based vulnerability detector for Stellar/Soroban contracts."""

    # Authorization patterns
    AUTH_PATTERNS = {
        "require_auth": r"\.require_auth\s*\(\s*\)",
        "require_auth_for_args": r"\.require_auth_for_args\s*\(",
        "address_require_auth": r"address\.require_auth\s*\(",
        "admin_check": r"admin\.require_auth|check_admin|is_admin",
    }

    # Dangerous patterns
    DANGEROUS_PATTERNS = {
        "unwrap": r"\.unwrap\s*\(\s*\)",
        "expect": r"\.expect\s*\(",
        "panic": r"panic!\s*\(",
        "unreachable": r"unreachable!\s*\(",
        "todo": r"todo!\s*\(",
        "unimplemented": r"unimplemented!\s*\(",
    }

    # Storage patterns
    STORAGE_PATTERNS = {
        "instance_get": r"env\.storage\(\)\.instance\(\)\.get\s*[:<]",
        "instance_set": r"env\.storage\(\)\.instance\(\)\.set\s*\(",
        "persistent_get": r"env\.storage\(\)\.persistent\(\)\.get\s*[:<]",
        "persistent_set": r"env\.storage\(\)\.persistent\(\)\.set\s*\(",
        "temporary_get": r"env\.storage\(\)\.temporary\(\)\.get\s*[:<]",
        "temporary_set": r"env\.storage\(\)\.temporary\(\)\.set\s*\(",
        "has_key": r"env\.storage\(\)\.\w+\(\)\.has\s*\(",
        "remove_key": r"env\.storage\(\)\.\w+\(\)\.remove\s*\(",
    }

    # Cross-contract patterns
    CROSS_CONTRACT_PATTERNS = {
        "invoke_contract": r"env\.invoke_contract\s*[:<]",
        "call_contract": r"\.call\s*\(",
        "register_contract": r"env\.register_contract\s*\(",
        "current_contract": r"env\.current_contract_address\s*\(",
    }

    # Token patterns
    TOKEN_PATTERNS = {
        "transfer": r"token\.transfer\s*\(|TokenClient.*transfer",
        "mint": r"token\.mint\s*\(|\.mint\s*\(",
        "burn": r"token\.burn\s*\(|\.burn\s*\(",
        "approve": r"token\.approve\s*\(|\.approve\s*\(",
        "balance": r"token\.balance\s*\(|\.balance\s*\(",
    }

    # TTL/Lifecycle patterns
    TTL_PATTERNS = {
        "extend_ttl": r"\.extend_ttl\s*\(",
        "bump": r"\.bump\s*\(",
        "ttl_get": r"\.get_ttl\s*\(",
        "max_ttl": r"MAX_TTL|LIFETIME_THRESHOLD",
    }

    # Arithmetic patterns
    ARITHMETIC_PATTERNS = {
        "checked_add": r"\.checked_add\s*\(",
        "checked_sub": r"\.checked_sub\s*\(",
        "checked_mul": r"\.checked_mul\s*\(",
        "checked_div": r"\.checked_div\s*\(",
        "saturating_add": r"\.saturating_add\s*\(",
        "saturating_sub": r"\.saturating_sub\s*\(",
        "wrapping_add": r"\.wrapping_add\s*\(",
        "unchecked_ops": r"\+\s*=|\-\s*=|\*\s*=",
    }

    @classmethod
    def find_patterns(cls, content: str, patterns: Dict[str, str]) -> List[Tuple[str, int, str]]:
        """Find all pattern matches in content.

        Returns:
            List of (pattern_name, line_number, matched_text)
        """
        matches = []
        lines = content.split("\n")

        for pattern_name, pattern in patterns.items():
            for line_no, line in enumerate(lines, 1):
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    matches.append((pattern_name, line_no, match.group()))

        return matches

    @classmethod
    def detect_missing_auth(
        cls, content: str, functions: List[SorobanFunction]
    ) -> List[Dict[str, Any]]:
        """Detect functions missing authorization checks."""
        findings = []
        lines = content.split("\n")

        # Find functions that modify state but don't have auth
        state_modifying_patterns = [
            r"env\.storage\(\).*\.set\s*\(",
            r"\.transfer\s*\(",
            r"\.mint\s*\(",
            r"\.burn\s*\(",
        ]

        for func in functions:
            if func.visibility != "pub":
                continue

            if func.has_auth:
                continue

            # Check if function modifies state
            func_body = func.body
            modifies_state = any(
                re.search(pattern, func_body) for pattern in state_modifying_patterns
            )

            if modifies_state:
                findings.append({
                    "type": StellarVulnerability.MISSING_AUTH_CHECK.value,
                    "function": func.name,
                    "line": func.location.line if func.location else 0,
                    "message": f"Public function '{func.name}' modifies state without authorization check",
                    "severity": "High",
                    "recommendation": "Add `address.require_auth()` or `env.require_auth_for_args()` before state modifications",
                })

        return findings

    @classmethod
    def detect_panic_in_contract(cls, content: str) -> List[Dict[str, Any]]:
        """Detect panic and unwrap usage that could cause contract failure."""
        findings = []
        matches = cls.find_patterns(content, cls.DANGEROUS_PATTERNS)

        for pattern_name, line_no, matched_text in matches:
            severity = "High" if pattern_name in ("panic", "unwrap") else "Medium"
            findings.append({
                "type": StellarVulnerability.PANIC_IN_CONTRACT.value
                if pattern_name == "panic"
                else StellarVulnerability.UNWRAP_WITHOUT_CHECK.value,
                "pattern": pattern_name,
                "line": line_no,
                "matched": matched_text,
                "message": f"Dangerous pattern '{pattern_name}' could cause contract to fail unexpectedly",
                "severity": severity,
                "recommendation": f"Replace {pattern_name} with proper error handling using Result/Option",
            })

        return findings

    @classmethod
    def detect_storage_issues(cls, content: str) -> List[Dict[str, Any]]:
        """Detect storage access issues."""
        findings = []

        # Check for storage access without TTL extension
        storage_writes = cls.find_patterns(content, {
            "set": r"env\.storage\(\)\.\w+\(\)\.set\s*\(",
        })

        ttl_extensions = cls.find_patterns(content, cls.TTL_PATTERNS)

        if storage_writes and not ttl_extensions:
            for _, line_no, matched in storage_writes:
                findings.append({
                    "type": StellarVulnerability.TTL_NOT_EXTENDED.value,
                    "line": line_no,
                    "message": "Storage write without TTL extension may cause data loss",
                    "severity": "Medium",
                    "recommendation": "Call extend_ttl() after storage writes to persistent data",
                })

        return findings

    @classmethod
    def detect_cross_contract_risks(cls, content: str) -> List[Dict[str, Any]]:
        """Detect cross-contract invocation risks."""
        findings = []
        matches = cls.find_patterns(content, cls.CROSS_CONTRACT_PATTERNS)

        # Check for invoke_contract without proper validation
        for pattern_name, line_no, matched_text in matches:
            if pattern_name == "invoke_contract":
                # Check if there's address validation nearby
                lines = content.split("\n")
                context_start = max(0, line_no - 5)
                context_end = min(len(lines), line_no + 5)
                context = "\n".join(lines[context_start:context_end])

                if not re.search(r"require_auth|verify|check", context, re.IGNORECASE):
                    findings.append({
                        "type": StellarVulnerability.CROSS_CONTRACT_UNSAFE.value,
                        "line": line_no,
                        "message": "Cross-contract call without visible authorization check",
                        "severity": "High",
                        "recommendation": "Verify caller authorization before cross-contract invocations",
                    })

        return findings

    @classmethod
    def detect_arithmetic_issues(cls, content: str) -> List[Dict[str, Any]]:
        """Detect potential arithmetic overflow/underflow."""
        findings = []

        # Find unchecked arithmetic operations
        unchecked_ops = cls.find_patterns(content, {
            "add": r"[^a-z_](\+)[^=]",
            "sub": r"[^a-z_](\-)[^=\>]",
            "mul": r"[^a-z_](\*)[^=]",
        })

        # Find checked operations
        checked_ops = cls.find_patterns(content, {
            k: v for k, v in cls.ARITHMETIC_PATTERNS.items()
            if k.startswith("checked_") or k.startswith("saturating_")
        })

        # If there are unchecked ops but no checked ops, it's suspicious
        if unchecked_ops and not checked_ops:
            for op_name, line_no, _ in unchecked_ops[:5]:  # Limit to first 5
                findings.append({
                    "type": StellarVulnerability.ARITHMETIC_OVERFLOW.value,
                    "line": line_no,
                    "operation": op_name,
                    "message": "Arithmetic operation without overflow check",
                    "severity": "Medium",
                    "recommendation": "Use checked_* or saturating_* methods for safe arithmetic",
                })

        return findings

    @classmethod
    def detect_token_issues(cls, content: str) -> List[Dict[str, Any]]:
        """Detect token handling issues."""
        findings = []
        token_ops = cls.find_patterns(content, cls.TOKEN_PATTERNS)

        for pattern_name, line_no, matched_text in token_ops:
            if pattern_name in ("transfer", "mint", "burn"):
                # Check for auth before token operation
                lines = content.split("\n")
                context_start = max(0, line_no - 10)
                context = "\n".join(lines[context_start:line_no])

                if not re.search(r"require_auth", context):
                    findings.append({
                        "type": StellarVulnerability.TOKEN_TRANSFER_UNCHECKED.value,
                        "line": line_no,
                        "operation": pattern_name,
                        "message": f"Token {pattern_name} without visible authorization",
                        "severity": "Critical",
                        "recommendation": f"Ensure proper authorization before token {pattern_name}",
                    })

        return findings


# ============================================================================
# Soroban Parser
# ============================================================================


class SorobanParser:
    """Parser for Soroban Rust source code."""

    # Contract attribute patterns
    CONTRACT_ATTR = r"#\[contract\]"
    CONTRACTIMPL_ATTR = r"#\[contractimpl\]"
    CONTRACTTYPE_ATTR = r"#\[contracttype\]"

    # Function patterns
    FN_PATTERN = r"(?P<visibility>pub(?:\s*\([^)]*\))?\s+)?fn\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)(?:\s*->\s*(?P<return>[^{]+))?\s*\{"

    # Import patterns
    USE_PATTERN = r"use\s+(?:soroban_sdk|crate|super|self)(?:::[^;]+)?;"

    def __init__(self):
        self.contracts: List[SorobanContract] = []

    def parse(self, source_path: Union[str, Path]) -> SorobanContract:
        """Parse a Soroban Rust source file."""
        path = Path(source_path)
        content = path.read_text()

        contract = SorobanContract(name=path.stem)

        # Parse imports
        contract.imports = self._parse_imports(content)

        # Parse functions
        contract.functions = self._parse_functions(content)

        # Parse storage accesses
        contract.storage_accesses = self._parse_storage(content)

        # Parse events
        contract.events = self._parse_events(content)

        # Parse errors
        contract.errors = self._parse_errors(content)

        # Check for contract traits
        contract.traits_impl = self._parse_traits(content)

        return contract

    def _parse_imports(self, content: str) -> List[str]:
        """Parse Soroban SDK imports."""
        imports = []
        for match in re.finditer(self.USE_PATTERN, content):
            imports.append(match.group())
        return imports

    def _parse_functions(self, content: str) -> List[SorobanFunction]:
        """Parse contract functions."""
        functions = []
        lines = content.split("\n")

        # Find #[contractimpl] blocks
        in_impl_block = False
        brace_count = 0
        impl_start = 0

        for i, line in enumerate(lines):
            if re.search(self.CONTRACTIMPL_ATTR, line):
                in_impl_block = True
                impl_start = i
                continue

            if in_impl_block:
                brace_count += line.count("{") - line.count("}")
                if brace_count <= 0 and i > impl_start:
                    in_impl_block = False
                    brace_count = 0

        # Parse individual functions
        for match in re.finditer(self.FN_PATTERN, content):
            visibility = match.group("visibility") or ""
            name = match.group("name")
            params_str = match.group("params")
            return_type = match.group("return")

            # Parse parameters
            parameters = self._parse_params(params_str)

            # Get function body
            start_pos = match.end() - 1  # Position of opening brace
            body = self._extract_body(content, start_pos)

            # Check for auth patterns
            has_auth = bool(re.search(r"require_auth", body))

            # Calculate line number
            line_no = content[:match.start()].count("\n") + 1

            # Check for decorators
            decorators = []
            pre_fn_content = content[max(0, match.start() - 100):match.start()]
            if "#[init]" in pre_fn_content or name == "__constructor":
                decorators.append("init")
            if "#[upgrade]" in pre_fn_content or name == "upgrade":
                decorators.append("upgrade")

            func = SorobanFunction(
                name=name,
                visibility=visibility.strip() if visibility else "private",
                is_init="init" in decorators or name == "__constructor",
                is_upgrade="upgrade" in decorators,
                has_auth=has_auth,
                parameters=parameters,
                return_type=return_type.strip() if return_type else None,
                decorators=decorators,
                body=body,
                location=Location(file=str(Path().absolute()), line=line_no),
            )
            functions.append(func)

        return functions

    def _parse_params(self, params_str: str) -> List[Tuple[str, str]]:
        """Parse function parameters."""
        params = []
        if not params_str.strip():
            return params

        # Split by comma, handling generics
        parts = []
        current = ""
        angle_count = 0

        for char in params_str:
            if char == "<":
                angle_count += 1
            elif char == ">":
                angle_count -= 1
            elif char == "," and angle_count == 0:
                parts.append(current.strip())
                current = ""
                continue
            current += char

        if current.strip():
            parts.append(current.strip())

        # Parse each parameter
        for part in parts:
            if ":" in part:
                name, type_str = part.split(":", 1)
                name = name.strip()
                type_str = type_str.strip()

                # Skip self parameter
                if name in ("self", "&self", "&mut self"):
                    continue

                params.append((name, type_str))

        return params

    def _extract_body(self, content: str, start_pos: int) -> str:
        """Extract function body from opening brace."""
        brace_count = 1
        pos = start_pos + 1
        body_start = pos

        while pos < len(content) and brace_count > 0:
            if content[pos] == "{":
                brace_count += 1
            elif content[pos] == "}":
                brace_count -= 1
            pos += 1

        return content[body_start:pos - 1]

    def _parse_storage(self, content: str) -> List[SorobanStorage]:
        """Parse storage access patterns."""
        storage_accesses = []

        patterns = {
            "instance": r"env\.storage\(\)\.instance\(\)\.(get|set|has|remove)",
            "persistent": r"env\.storage\(\)\.persistent\(\)\.(get|set|has|remove)",
            "temporary": r"env\.storage\(\)\.temporary\(\)\.(get|set|has|remove)",
        }

        for storage_type, pattern in patterns.items():
            for match in re.finditer(pattern, content):
                access_pattern = match.group(1)
                line_no = content[:match.start()].count("\n") + 1

                storage_accesses.append(SorobanStorage(
                    key_type="unknown",
                    value_type="unknown",
                    storage_type=storage_type,
                    access_pattern=access_pattern,
                    location=Location(file="", line=line_no),
                ))

        return storage_accesses

    def _parse_events(self, content: str) -> List[str]:
        """Parse event emissions."""
        events = []
        pattern = r"env\.events\(\)\.publish\s*\("
        for match in re.finditer(pattern, content):
            events.append("event_publish")
        return events

    def _parse_errors(self, content: str) -> List[str]:
        """Parse custom error types."""
        errors = []
        pattern = r"#\[contracterror\][\s\S]*?enum\s+(\w+)"
        for match in re.finditer(pattern, content):
            errors.append(match.group(1))
        return errors

    def _parse_traits(self, content: str) -> List[str]:
        """Parse implemented traits."""
        traits = []
        pattern = r"impl\s+(\w+)\s+for"
        for match in re.finditer(pattern, content):
            traits.append(match.group(1))
        return traits


# ============================================================================
# Stellar Analyzer
# ============================================================================


class StellarAnalyzer(AbstractChainAnalyzer):
    """
    Analyzer for Stellar/Soroban smart contracts.

    Integrates with MIESC chain abstraction layer for unified analysis.
    """

    def __init__(self):
        super().__init__(ChainType.STELLAR, ContractLanguage.RUST)
        self.parser = SorobanParser()

    @property
    def name(self) -> str:
        return "StellarAnalyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return [".rs"]

    def parse(self, source_path: Union[str, Path]) -> AbstractContract:
        """Parse Soroban Rust source into AbstractContract."""
        path = Path(source_path)
        content = path.read_text()

        # Parse with Soroban parser
        soroban_contract = self.parser.parse(source_path)

        # Convert to AbstractContract
        functions = []
        for func in soroban_contract.functions:
            visibility = Visibility.PUBLIC if "pub" in func.visibility else Visibility.PRIVATE

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
                calls_external="invoke_contract" in func.body,
                reads_state="storage" in func.body and "get" in func.body,
                writes_state="storage" in func.body and "set" in func.body,
                chain_metadata={
                    "has_auth": func.has_auth,
                    "is_init": func.is_init,
                    "is_upgrade": func.is_upgrade,
                },
            )
            functions.append(abstract_func)

        # Create variables from storage accesses
        variables = []
        for i, storage in enumerate(soroban_contract.storage_accesses):
            variables.append(AbstractVariable(
                name=f"storage_{storage.storage_type}_{i}",
                type_info=TypeInfo(name=storage.value_type),
                visibility=Visibility.INTERNAL,
                location=storage.location,
                metadata={"storage_type": storage.storage_type},
            ))

        return AbstractContract(
            name=soroban_contract.name,
            chain_type=ChainType.STELLAR,
            language=ContractLanguage.RUST,
            source_path=str(path),
            source_code=content,
            functions=functions,
            variables=variables,
            events=[
                AbstractEvent(name=e)
                for e in soroban_contract.events
            ],
            imports=soroban_contract.imports,
        )

    def detect_vulnerabilities(
        self,
        contract: AbstractContract,
        properties: Optional[List[SecurityProperty]] = None,
    ) -> List[Dict[str, Any]]:
        """Detect vulnerabilities in Soroban contract."""
        findings = []
        content = contract.source_code

        # Get Soroban functions
        soroban_functions = [
            SorobanFunction(
                name=f.name,
                visibility="pub" if f.visibility == Visibility.PUBLIC else "private",
                has_auth=f.chain_metadata.get("has_auth", False),
                body=f.body_source or "",
                location=f.location,
            )
            for f in contract.functions
        ]

        # Default to all properties
        if properties is None:
            properties = list(SecurityProperty)

        # Access Control checks
        if SecurityProperty.ACCESS_CONTROL in properties:
            auth_findings = StellarPatternDetector.detect_missing_auth(
                content, soroban_functions
            )
            for f in auth_findings:
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

        # State handling checks (panic/unwrap)
        if SecurityProperty.STATE_HANDLING in properties:
            panic_findings = StellarPatternDetector.detect_panic_in_contract(content)
            for f in panic_findings:
                findings.append(self.normalize_finding(
                    vuln_type=f["type"],
                    severity=f["severity"],
                    message=f["message"],
                    location=Location(
                        file=contract.source_path,
                        line=f.get("line", 0),
                    ),
                    pattern=f.get("pattern"),
                    recommendation=f.get("recommendation"),
                ))

        # External calls (cross-contract)
        if SecurityProperty.EXTERNAL_CALLS in properties:
            cc_findings = StellarPatternDetector.detect_cross_contract_risks(content)
            for f in cc_findings:
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

        # Arithmetic checks
        if SecurityProperty.ARITHMETIC in properties:
            arith_findings = StellarPatternDetector.detect_arithmetic_issues(content)
            for f in arith_findings:
                findings.append(self.normalize_finding(
                    vuln_type=f["type"],
                    severity=f["severity"],
                    message=f["message"],
                    location=Location(
                        file=contract.source_path,
                        line=f.get("line", 0),
                    ),
                    operation=f.get("operation"),
                    recommendation=f.get("recommendation"),
                ))

        # Storage/TTL checks
        storage_findings = StellarPatternDetector.detect_storage_issues(content)
        for f in storage_findings:
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

        # Token handling
        token_findings = StellarPatternDetector.detect_token_issues(content)
        for f in token_findings:
            findings.append(self.normalize_finding(
                vuln_type=f["type"],
                severity=f["severity"],
                message=f["message"],
                location=Location(
                    file=contract.source_path,
                    line=f.get("line", 0),
                ),
                operation=f.get("operation"),
                recommendation=f.get("recommendation"),
            ))

        return findings


# ============================================================================
# Registration
# ============================================================================


# Add STELLAR to ChainType if not present
if not hasattr(ChainType, "STELLAR"):
    # Dynamically add STELLAR
    ChainType.STELLAR = "stellar"


# Register analyzer
try:
    register_chain_analyzer(StellarAnalyzer())
except Exception as e:
    logger.warning(f"Failed to register StellarAnalyzer: {e}")


# Export for external use
__all__ = [
    "StellarAnalyzer",
    "StellarVulnerability",
    "StellarPatternDetector",
    "SorobanParser",
    "SorobanFunction",
    "SorobanStorage",
    "SorobanContract",
]
