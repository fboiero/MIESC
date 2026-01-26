"""
Move Language Adapter (Sui/Aptos)
=================================

Adapter for analyzing Move smart contracts on Sui and Aptos.

Features:
- Parse Move module source code
- Detect Move-specific vulnerabilities:
  - Capability leaks
  - Object ownership issues
  - Unchecked aborts
  - Resource handling errors
  - Access control bypasses
  - Flash loan vulnerabilities

References:
- https://move-language.github.io/move/
- https://docs.sui.io/concepts/sui-move-concepts
- https://aptos.dev/move/move-on-aptos

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
# Move-Specific Types
# ============================================================================


class MoveVulnerability(Enum):
    """Move-specific vulnerability types."""

    CAPABILITY_LEAK = "capability_leak"
    OBJECT_OWNERSHIP = "object_ownership"
    UNCHECKED_ABORT = "unchecked_abort"
    RESOURCE_LEAK = "resource_leak"
    MISSING_ACCESS_CONTROL = "missing_access_control"
    FLASH_LOAN_ATTACK = "flash_loan_attack"
    TYPE_CONFUSION = "type_confusion"
    REENTRANCY = "reentrancy"
    ORACLE_MANIPULATION = "oracle_manipulation"
    ARITHMETIC_OVERFLOW = "arithmetic_overflow"
    WITNESS_PATTERN_BYPASS = "witness_pattern_bypass"
    HOT_POTATO_ABUSE = "hot_potato_abuse"


class MoveChainVariant(Enum):
    """Move chain variants."""

    SUI = "sui"
    APTOS = "aptos"
    MOVEMENT = "movement"


@dataclass
class MoveModule:
    """Represents a Move module."""

    name: str
    address: Optional[str] = None
    variant: MoveChainVariant = MoveChainVariant.SUI
    structs: List["MoveStruct"] = field(default_factory=list)
    functions: List["MoveFunction"] = field(default_factory=list)
    constants: List[Dict[str, Any]] = field(default_factory=list)
    uses: List[str] = field(default_factory=list)
    friends: List[str] = field(default_factory=list)
    location: Optional[Location] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "address": self.address,
            "variant": self.variant.value,
            "structs": [s.to_dict() for s in self.structs],
            "functions": [f.to_dict() for f in self.functions],
        }


@dataclass
class MoveStruct:
    """Represents a Move struct/resource."""

    name: str
    has_key: bool = False
    has_store: bool = False
    has_drop: bool = False
    has_copy: bool = False
    fields: List[Dict[str, str]] = field(default_factory=list)
    type_params: List[str] = field(default_factory=list)
    location: Optional[Location] = None

    @property
    def is_resource(self) -> bool:
        """Check if struct is a resource (no copy/drop)."""
        return self.has_key and not (self.has_copy and self.has_drop)

    @property
    def is_capability(self) -> bool:
        """Check if struct looks like a capability."""
        name_lower = self.name.lower()
        return any(cap in name_lower for cap in ["cap", "admin", "owner", "authority"])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "abilities": {
                "key": self.has_key,
                "store": self.has_store,
                "drop": self.has_drop,
                "copy": self.has_copy,
            },
            "is_resource": self.is_resource,
            "is_capability": self.is_capability,
            "fields": self.fields,
        }


@dataclass
class MoveFunction:
    """Represents a Move function."""

    name: str
    visibility: str = "private"  # public, public(friend), entry, private
    is_entry: bool = False
    parameters: List[Parameter] = field(default_factory=list)
    return_types: List[str] = field(default_factory=list)
    type_params: List[str] = field(default_factory=list)
    acquires: List[str] = field(default_factory=list)
    location: Optional[Location] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "visibility": self.visibility,
            "is_entry": self.is_entry,
            "parameters": [{"name": p.name, "type": str(p.type_info)} for p in self.parameters],
            "return_types": self.return_types,
            "acquires": self.acquires,
        }


# ============================================================================
# Move Pattern Detector
# ============================================================================


class MovePatternDetector:
    """Detects vulnerability patterns in Move code."""

    # Capability/Access patterns
    CAPABILITY_PATTERNS = [
        (r"struct\s+\w*[Cc]ap\w*\s+has", "capability_struct"),
        (r"struct\s+\w*[Aa]dmin\w*\s+has", "admin_struct"),
        (r"struct\s+\w*[Oo]wner\w*\s+has", "owner_struct"),
        (r"&mut\s+\w*[Cc]ap", "mutable_cap_ref"),
        (r"public\s+fun\s+\w+\s*\([^)]*\w*[Cc]ap", "public_cap_param"),
    ]

    # Object/Resource patterns (Sui specific)
    OBJECT_PATTERNS = [
        (r"transfer::\w+\s*\(", "object_transfer"),
        (r"object::new\s*\(", "object_creation"),
        (r"object::delete\s*\(", "object_deletion"),
        (r"dynamic_field::", "dynamic_field"),
        (r"dynamic_object_field::", "dynamic_object_field"),
        (r"&mut\s+UID", "mutable_uid"),
    ]

    # Entry function patterns
    ENTRY_PATTERNS = [
        (r"public\s+entry\s+fun", "public_entry"),
        (r"entry\s+fun", "entry_function"),
        (r"public\s+fun\s+\w+\s*<", "public_generic"),
    ]

    # Dangerous patterns
    DANGEROUS_PATTERNS = [
        (r"abort\s+\d+", "abort_code"),
        (r"assert!\s*\(", "assert_macro"),
        (r"borrow_global_mut\s*<", "borrow_global_mut"),
        (r"move_to\s*<", "move_to"),
        (r"move_from\s*<", "move_from"),
    ]

    # Arithmetic patterns
    ARITHMETIC_PATTERNS = [
        (r"\+\s*(?!.*checked)", "unchecked_add"),
        (r"-\s*(?!.*checked)", "unchecked_sub"),
        (r"\*\s*(?!.*checked)", "unchecked_mul"),
        (r"as\s+u\d+", "type_cast"),
    ]

    # Witness pattern (one-time type for authorization)
    WITNESS_PATTERNS = [
        (r"struct\s+\w+\s+has\s+drop", "witness_candidate"),
        (r"fun\s+init\s*\(witness:", "init_with_witness"),
    ]

    # Flash loan patterns
    FLASH_LOAN_PATTERNS = [
        (r"flash_\w+", "flash_function"),
        (r"hot_potato", "hot_potato"),
        (r"struct\s+\w+\s*\{[^}]*\}\s*//.*no\s+drop", "no_drop_struct"),
    ]

    def detect_patterns(
        self,
        source_code: str,
        file_path: str,
    ) -> List[Dict[str, Any]]:
        """
        Detect vulnerability patterns in source code.

        Args:
            source_code: Move source code
            file_path: Path for reporting

        Returns:
            List of pattern matches
        """
        findings = []
        lines = source_code.split("\n")

        all_patterns = [
            (self.CAPABILITY_PATTERNS, "access_control", "Medium"),
            (self.OBJECT_PATTERNS, "state_handling", "info"),
            (self.ENTRY_PATTERNS, "access_control", "info"),
            (self.DANGEROUS_PATTERNS, "error_handling", "Medium"),
            (self.ARITHMETIC_PATTERNS, "arithmetic", "Medium"),
            (self.WITNESS_PATTERNS, "access_control", "info"),
            (self.FLASH_LOAN_PATTERNS, "flash_loan", "High"),
        ]

        for patterns, category, severity in all_patterns:
            for pattern, pattern_name in patterns:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
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
# Move Analyzer
# ============================================================================


class MoveAnalyzer(AbstractChainAnalyzer):
    """
    Analyzer for Move smart contracts (Sui/Aptos).

    Provides parsing and vulnerability detection for Move modules.
    """

    def __init__(self, variant: MoveChainVariant = MoveChainVariant.SUI):
        chain = ChainType.SUI if variant == MoveChainVariant.SUI else ChainType.APTOS
        super().__init__(chain, ContractLanguage.MOVE)
        self.variant = variant
        self.pattern_detector = MovePatternDetector()

    @property
    def name(self) -> str:
        return f"move-analyzer-{self.variant.value}"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return [".move"]

    def parse(self, source_path: Union[str, Path]) -> AbstractContract:
        """
        Parse Move module source.

        Args:
            source_path: Path to .move file

        Returns:
            AbstractContract representation
        """
        path = Path(source_path)
        source_code = path.read_text()

        # Detect chain variant from imports
        if "sui::" in source_code or "sui_framework" in source_code:
            self.variant = MoveChainVariant.SUI
            self.chain_type = ChainType.SUI
        elif "aptos_" in source_code or "aptos::" in source_code:
            self.variant = MoveChainVariant.APTOS
            self.chain_type = ChainType.APTOS

        contract = AbstractContract(
            name=path.stem,
            chain_type=self.chain_type,
            language=ContractLanguage.MOVE,
            source_path=str(path),
            source_code=source_code,
        )

        # Extract module info
        module_match = re.search(r'module\s+(\w+)::(\w+)\s*\{', source_code)
        if module_match:
            contract.name = module_match.group(2)
            contract.compiler_version = module_match.group(1)  # Using address as version

        # Extract uses/imports
        use_pattern = r'use\s+([\w:]+)'
        contract.imports = re.findall(use_pattern, source_code)

        # Extract friend declarations
        friend_pattern = r'friend\s+([\w:]+)'
        friends = re.findall(friend_pattern, source_code)
        if friends:
            contract.inherits_from = friends  # Using inherits_from for friends

        # Extract structs
        contract.variables = self._extract_structs(source_code, str(path))

        # Extract functions
        contract.functions = self._extract_functions(source_code, str(path))

        # Extract events (Sui events)
        contract.events = self._extract_events(source_code, str(path))

        return contract

    def _extract_structs(self, source_code: str, file_path: str) -> List[AbstractVariable]:
        """Extract Move structs."""
        variables = []

        # Pattern for struct extraction
        struct_pattern = r'''
            struct\s+(\w+)                    # Struct name
            (?:<([^>]+)>)?                    # Optional type params
            \s+has\s+([^{]+)                  # Abilities
            \s*\{([^}]*)\}                    # Fields
        '''

        for match in re.finditer(struct_pattern, source_code, re.VERBOSE):
            name = match.group(1)
            type_params = match.group(2) or ""
            abilities_str = match.group(3)
            fields_str = match.group(4)
            line = source_code[:match.start()].count("\n") + 1

            # Parse abilities
            abilities = abilities_str.lower().split(",")
            abilities = [a.strip() for a in abilities]

            # Create metadata
            metadata = {
                "has_key": "key" in abilities,
                "has_store": "store" in abilities,
                "has_drop": "drop" in abilities,
                "has_copy": "copy" in abilities,
                "type_params": type_params.split(",") if type_params else [],
                "is_resource": "key" in abilities and "drop" not in abilities,
                "is_capability": any(cap in name.lower() for cap in ["cap", "admin", "owner"]),
            }

            # Parse fields
            fields = []
            for field_match in re.finditer(r'(\w+)\s*:\s*([^,\n}]+)', fields_str):
                fields.append({
                    "name": field_match.group(1),
                    "type": field_match.group(2).strip(),
                })
            metadata["fields"] = fields

            var = AbstractVariable(
                name=name,
                type_info=TypeInfo(name="struct"),
                visibility=Visibility.PUBLIC,
                location=Location(file=file_path, line=line),
                metadata=metadata,
            )
            variables.append(var)

        return variables

    def _extract_functions(self, source_code: str, file_path: str) -> List[AbstractFunction]:
        """Extract Move functions."""
        functions = []

        # Pattern for function extraction
        func_pattern = r'''
            (?P<vis>public(?:\s*\(\s*friend\s*\))?\s+)?  # Visibility
            (?P<entry>entry\s+)?                         # Entry modifier
            fun\s+(?P<name>\w+)                          # Function name
            (?:<(?P<tparams>[^>]+)>)?                    # Type params
            \s*\((?P<params>[^)]*)\)                     # Parameters
            (?:\s*:\s*(?P<ret>[^{]+))?                   # Return type
            (?:\s+acquires\s+(?P<acq>[^{]+))?           # Acquires
            \s*\{                                        # Body start
        '''

        for match in re.finditer(func_pattern, source_code, re.VERBOSE):
            vis = match.group("vis") or ""
            is_entry = match.group("entry") is not None
            name = match.group("name")
            params_str = match.group("params") or ""
            ret_type = match.group("ret")
            acquires = match.group("acq")
            line = source_code[:match.start()].count("\n") + 1

            # Determine visibility
            if "public(friend)" in vis:
                visibility = Visibility.INTERNAL
            elif "public" in vis:
                visibility = Visibility.PUBLIC
            else:
                visibility = Visibility.PRIVATE

            # Parse parameters
            parameters = []
            for param_match in re.finditer(r'(\w+)\s*:\s*([^,]+)', params_str):
                param_name = param_match.group(1)
                param_type = param_match.group(2).strip()
                parameters.append(Parameter(
                    name=param_name,
                    type_info=TypeInfo(name=param_type),
                ))

            func = AbstractFunction(
                name=name,
                visibility=visibility,
                mutability=Mutability.MUTABLE,
                parameters=parameters,
                return_types=[TypeInfo(name=ret_type.strip())] if ret_type else [],
                modifiers=["entry"] if is_entry else [],
                location=Location(file=file_path, line=line),
                chain_metadata={
                    "is_entry": is_entry,
                    "acquires": acquires.split(",") if acquires else [],
                    "variant": self.variant.value,
                },
            )

            functions.append(func)

        return functions

    def _extract_events(self, source_code: str, file_path: str) -> List[AbstractEvent]:
        """Extract Move events."""
        events = []

        # Sui events use emit
        event_pattern = r'event::emit\s*\(\s*(\w+)\s*\{'
        for match in re.finditer(event_pattern, source_code):
            event_name = match.group(1)
            line = source_code[:match.start()].count("\n") + 1

            events.append(AbstractEvent(
                name=event_name,
                location=Location(file=file_path, line=line),
            ))

        return events

    def detect_vulnerabilities(
        self,
        contract: AbstractContract,
        properties: Optional[List[SecurityProperty]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Detect Move-specific vulnerabilities.

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

        # Convert patterns to findings
        for match in pattern_matches:
            finding = self._pattern_to_finding(match, contract)
            if finding:
                findings.append(finding)

        # Semantic checks
        if SecurityProperty.ACCESS_CONTROL in properties:
            findings.extend(self._check_capability_handling(contract))

        if SecurityProperty.STATE_HANDLING in properties:
            findings.extend(self._check_object_safety(contract))

        return findings

    def _pattern_to_finding(
        self,
        match: Dict[str, Any],
        contract: AbstractContract,
    ) -> Optional[Dict[str, Any]]:
        """Convert pattern match to finding."""
        pattern = match["pattern"]
        severity = match["severity"]

        if severity == "info":
            return None

        messages = {
            "public_cap_param": (
                "Capability passed to public function",
                "Consider using friend functions or capability guards",
            ),
            "mutable_cap_ref": (
                "Mutable reference to capability",
                "Capabilities should typically be immutable references",
            ),
            "abort_code": (
                "Explicit abort in code",
                "Ensure abort conditions are well documented",
            ),
            "flash_function": (
                "Flash loan pattern detected",
                "Ensure proper validation before and after flash operations",
            ),
            "hot_potato": (
                "Hot potato pattern detected",
                "Verify the struct cannot be stored to prevent abuse",
            ),
            "unchecked_add": (
                "Potentially unchecked arithmetic",
                "Use checked arithmetic or verify bounds",
            ),
        }

        if pattern not in messages:
            return None

        message, recommendation = messages[pattern]

        return self.normalize_finding(
            vuln_type=pattern,
            severity=severity,
            message=message,
            location=Location(file=match["file"], line=match["line"]),
            description=f"Pattern: {pattern}\nCode: {match.get('code', '')}",
            recommendation=recommendation,
            confidence=0.7,
        )

    def _check_capability_handling(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for capability handling issues."""
        findings = []

        # Find capability structs
        cap_structs = []
        for var in contract.variables:
            metadata = var.metadata or {}
            if metadata.get("is_capability"):
                cap_structs.append(var.name)

        if not cap_structs:
            return findings

        # Check if capabilities are properly protected
        source = contract.source_code

        for func in contract.functions:
            if func.visibility != Visibility.PUBLIC:
                continue

            # Check if function takes capability as parameter
            for param in func.parameters:
                param_type = str(param.type_info)
                for cap in cap_structs:
                    if cap in param_type and "&mut" in param_type:
                        findings.append(self.normalize_finding(
                            vuln_type=MoveVulnerability.CAPABILITY_LEAK.value,
                            severity="High",
                            message=f"Public function '{func.name}' takes mutable capability reference",
                            location=func.location,
                            description=(
                                f"The function '{func.name}' accepts a mutable reference to "
                                f"capability '{cap}', which could allow unauthorized modifications."
                            ),
                            recommendation=(
                                "Use immutable references for capabilities or restrict "
                                "function visibility with friend declarations."
                            ),
                        ))

        return findings

    def _check_object_safety(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for object safety issues (Sui specific)."""
        findings = []

        if self.variant != MoveChainVariant.SUI:
            return findings

        source = contract.source_code

        # Check for shared object mutations without proper checks
        for func in contract.functions:
            metadata = func.chain_metadata or {}
            if not metadata.get("is_entry"):
                continue

            if func.location:
                func_start = source.find(f"fun {func.name}")
                if func_start != -1:
                    # Find function body
                    brace_start = source.find("{", func_start)
                    if brace_start != -1:
                        # Simple body extraction
                        depth = 1
                        end = brace_start + 1
                        while depth > 0 and end < len(source):
                            if source[end] == "{":
                                depth += 1
                            elif source[end] == "}":
                                depth -= 1
                            end += 1

                        func_body = source[brace_start:end]

                        # Check for shared object access
                        if "&mut" in func_body and "shared" in source[func_start:brace_start].lower():
                            findings.append(self.normalize_finding(
                                vuln_type=MoveVulnerability.OBJECT_OWNERSHIP.value,
                                severity="Medium",
                                message=f"Entry function '{func.name}' mutates shared object",
                                location=func.location,
                                description=(
                                    "Entry functions that mutate shared objects need careful "
                                    "consideration for concurrent access."
                                ),
                                recommendation=(
                                    "Ensure proper access control and consider using "
                                    "owned objects where possible."
                                ),
                            ))

        return findings


# ============================================================================
# Registration
# ============================================================================


def register_move_analyzer(variant: MoveChainVariant = MoveChainVariant.SUI) -> MoveAnalyzer:
    """Create and register the Move analyzer."""
    analyzer = MoveAnalyzer(variant)
    register_chain_analyzer(analyzer)
    return analyzer


# ============================================================================
# Convenience Functions
# ============================================================================


def analyze_move_module(
    source_path: Union[str, Path],
    variant: MoveChainVariant = MoveChainVariant.SUI,
    properties: Optional[List[SecurityProperty]] = None,
) -> Dict[str, Any]:
    """
    Analyze a Move module.

    Args:
        source_path: Path to .move file
        variant: Chain variant (Sui/Aptos)
        properties: Security properties to check

    Returns:
        Analysis result
    """
    analyzer = MoveAnalyzer(variant)
    return analyzer.analyze(source_path, properties)


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "MoveAnalyzer",
    "MoveVulnerability",
    "MoveChainVariant",
    "MovePatternDetector",
    "MoveModule",
    "MoveStruct",
    "MoveFunction",
    "register_move_analyzer",
    "analyze_move_module",
]
