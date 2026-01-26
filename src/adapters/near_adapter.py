"""
NEAR Protocol Adapter
=====================

Adapter for analyzing NEAR smart contracts written in Rust.

Features:
- Parse NEAR/Rust contract source code
- Detect NEAR-specific vulnerabilities:
  - Missing predecessor checks (access control)
  - Cross-contract call issues
  - Promise handling vulnerabilities
  - Storage access control
  - Callback reentrancy
  - Panic in view functions
  - Unbounded iterations

References:
- https://docs.near.org/develop/contracts/security
- https://github.com/nicholasrq/near-security-checklist
- https://near-sdk.io/

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
# NEAR-Specific Types
# ============================================================================


class NearVulnerability(Enum):
    """NEAR-specific vulnerability types."""

    MISSING_PREDECESSOR_CHECK = "missing_predecessor_check"
    MISSING_SIGNER_CHECK = "missing_signer_check"
    UNPROTECTED_CALLBACK = "unprotected_callback"
    PROMISE_RESULT_UNHANDLED = "promise_result_unhandled"
    CROSS_CONTRACT_REENTRANCY = "cross_contract_reentrancy"
    STORAGE_KEY_COLLISION = "storage_key_collision"
    UNBOUNDED_ITERATION = "unbounded_iteration"
    PANIC_IN_VIEW = "panic_in_view"
    INSECURE_RANDOMNESS = "insecure_randomness"
    INSUFFICIENT_GAS = "insufficient_gas"
    UPGRADE_VULNERABILITY = "upgrade_vulnerability"
    DENIAL_OF_SERVICE = "denial_of_service"


@dataclass
class NearMethod:
    """Represents a NEAR contract method."""

    name: str
    is_init: bool = False
    is_payable: bool = False
    is_private: bool = False
    is_view: bool = False
    has_callback: bool = False
    parameters: List[Parameter] = field(default_factory=list)
    return_type: Optional[str] = None
    location: Optional[Location] = None
    decorators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "is_init": self.is_init,
            "is_payable": self.is_payable,
            "is_private": self.is_private,
            "is_view": self.is_view,
            "has_callback": self.has_callback,
            "decorators": self.decorators,
        }


@dataclass
class NearStorage:
    """Represents NEAR contract storage."""

    name: str
    storage_type: str
    key_prefix: Optional[str] = None
    location: Optional[Location] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "storage_type": self.storage_type,
            "key_prefix": self.key_prefix,
        }


# ============================================================================
# NEAR Pattern Detector
# ============================================================================


class NearPatternDetector:
    """Detects vulnerability patterns in NEAR contracts."""

    # Access control patterns
    ACCESS_PATTERNS = [
        (r"env::predecessor_account_id\(\)", "predecessor_check"),
        (r"env::signer_account_id\(\)", "signer_check"),
        (r"#\[private\]", "private_decorator"),
        (r"require!\s*\(\s*env::predecessor", "predecessor_require"),
        (r"assert!\s*\(\s*env::predecessor", "predecessor_assert"),
    ]

    # Missing checks patterns (potential vulnerabilities)
    MISSING_CHECK_PATTERNS = [
        (r"pub\s+fn\s+\w+\s*\([^)]*\)[^{]*\{(?![^}]*predecessor_account_id)", "missing_predecessor"),
        (r"#\[payable\]\s*pub\s+fn", "payable_function"),
    ]

    # Cross-contract call patterns
    CROSS_CONTRACT_PATTERNS = [
        (r"Promise::new\s*\(", "promise_new"),
        (r"\.function_call\s*\(", "function_call"),
        (r"\.then\s*\(", "promise_then"),
        (r"ext_\w+::", "external_contract_call"),
        (r"#\[ext_contract", "ext_contract_trait"),
    ]

    # Callback patterns
    CALLBACK_PATTERNS = [
        (r"#\[private\]\s*pub\s+fn\s+\w*callback", "private_callback"),
        (r"pub\s+fn\s+\w*callback(?![^}]*#\[private\])", "public_callback"),
        (r"env::promise_result\s*\(", "promise_result"),
        (r"PromiseResult::", "promise_result_enum"),
    ]

    # Storage patterns
    STORAGE_PATTERNS = [
        (r"LookupMap::<", "lookup_map"),
        (r"UnorderedMap::<", "unordered_map"),
        (r"TreeMap::<", "tree_map"),
        (r"LookupSet::<", "lookup_set"),
        (r"UnorderedSet::<", "unordered_set"),
        (r"Vector::<", "vector"),
        (r"LazyOption::<", "lazy_option"),
        (r"env::storage_write\s*\(", "raw_storage_write"),
        (r"env::storage_read\s*\(", "raw_storage_read"),
    ]

    # Dangerous patterns
    DANGEROUS_PATTERNS = [
        (r"\.unwrap\(\)", "unwrap_usage"),
        (r"\.expect\(", "expect_usage"),
        (r"panic!\s*\(", "panic_macro"),
        (r"unreachable!\s*\(", "unreachable_macro"),
        (r"env::random_seed\s*\(", "random_seed"),
        (r"for\s+\w+\s+in\s+\w+\.iter\(\)", "unbounded_loop"),
        (r"while\s+", "while_loop"),
    ]

    # Gas patterns
    GAS_PATTERNS = [
        (r"Gas\s*\(\s*\d+", "gas_specification"),
        (r"prepaid_gas\s*\(\)", "prepaid_gas_check"),
        (r"used_gas\s*\(\)", "used_gas_check"),
    ]

    def detect_patterns(
        self,
        source_code: str,
        file_path: str,
    ) -> List[Dict[str, Any]]:
        """
        Detect vulnerability patterns in source code.

        Args:
            source_code: Rust/NEAR source code
            file_path: Path for reporting

        Returns:
            List of pattern matches
        """
        findings = []
        lines = source_code.split("\n")

        all_patterns = [
            (self.ACCESS_PATTERNS, "access_control", "info"),
            (self.MISSING_CHECK_PATTERNS, "access_control", "High"),
            (self.CROSS_CONTRACT_PATTERNS, "external_calls", "Medium"),
            (self.CALLBACK_PATTERNS, "reentrancy", "Medium"),
            (self.STORAGE_PATTERNS, "state_handling", "info"),
            (self.DANGEROUS_PATTERNS, "error_handling", "Medium"),
            (self.GAS_PATTERNS, "gas", "info"),
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
# NEAR Analyzer
# ============================================================================


class NearAnalyzer(AbstractChainAnalyzer):
    """
    Analyzer for NEAR Protocol smart contracts.

    Provides parsing and vulnerability detection for Rust-based
    NEAR contracts using near-sdk.
    """

    def __init__(self):
        super().__init__(ChainType.NEAR, ContractLanguage.RUST)
        self.pattern_detector = NearPatternDetector()

    @property
    def name(self) -> str:
        return "near-analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return [".rs"]

    def parse(self, source_path: Union[str, Path]) -> AbstractContract:
        """
        Parse NEAR contract source.

        Args:
            source_path: Path to .rs file

        Returns:
            AbstractContract representation
        """
        path = Path(source_path)
        source_code = path.read_text()

        contract = AbstractContract(
            name=path.stem,
            chain_type=ChainType.NEAR,
            language=ContractLanguage.RUST,
            source_path=str(path),
            source_code=source_code,
        )

        # Detect if it's a NEAR contract
        if "near_sdk" not in source_code and "near_bindgen" not in source_code:
            logger.warning(f"{path} may not be a NEAR contract")

        # Extract contract struct
        struct_match = re.search(
            r'#\[near_bindgen\]\s*(?:#\[derive[^\]]+\]\s*)*pub\s+struct\s+(\w+)',
            source_code
        )
        if struct_match:
            contract.name = struct_match.group(1)

        # Extract methods
        contract.functions = self._extract_methods(source_code, str(path))

        # Extract storage types
        contract.variables = self._extract_storage(source_code, str(path))

        # Extract events
        contract.events = self._extract_events(source_code, str(path))

        return contract

    def _extract_methods(self, source_code: str, file_path: str) -> List[AbstractFunction]:
        """Extract NEAR methods from source."""
        methods = []

        # Pattern for method extraction
        method_pattern = r'''
            (?P<decorators>(?:\#\[\w+(?:\([^\]]*\))?\]\s*)*)  # Decorators
            pub\s+fn\s+(?P<name>\w+)\s*                       # Function name
            (?:<[^>]+>)?\s*                                   # Optional generics
            \((?P<params>[^)]*)\)\s*                          # Parameters
            (?:->\s*(?P<return>[^{]+))?\s*                   # Optional return type
            \{                                                # Function body start
        '''

        for match in re.finditer(method_pattern, source_code, re.VERBOSE):
            decorators_str = match.group("decorators") or ""
            name = match.group("name")
            params_str = match.group("params")
            return_type = match.group("return")

            line = source_code[:match.start()].count("\n") + 1

            # Parse decorators
            decorators = re.findall(r'#\[(\w+)', decorators_str)

            # Determine method properties
            is_init = "init" in decorators
            is_payable = "payable" in decorators
            is_private = "private" in decorators
            is_view = return_type and "self" not in params_str.split(",")[0] if params_str else False

            # Parse parameters
            parameters = []
            if params_str.strip():
                for param_match in re.finditer(r'(\w+)\s*:\s*([^,]+)', params_str):
                    param_name = param_match.group(1)
                    param_type = param_match.group(2).strip()
                    if param_name not in ("self", "&self", "&mut self"):
                        parameters.append(Parameter(
                            name=param_name,
                            type_info=TypeInfo(name=param_type),
                        ))

            # Determine visibility and mutability
            visibility = Visibility.PRIVATE if is_private else Visibility.PUBLIC
            mutability = Mutability.VIEW if is_view else Mutability.MUTABLE

            func = AbstractFunction(
                name=name,
                visibility=visibility,
                mutability=mutability,
                parameters=parameters,
                return_types=[TypeInfo(name=return_type.strip())] if return_type else [],
                modifiers=decorators,
                location=Location(file=file_path, line=line),
                chain_metadata={
                    "is_init": is_init,
                    "is_payable": is_payable,
                    "is_private": is_private,
                    "is_view": is_view,
                    "decorators": decorators,
                },
            )

            # Check for cross-contract calls
            method_end = source_code.find("}", match.end())
            method_body = source_code[match.end():method_end] if method_end != -1 else ""
            func.calls_external = bool(re.search(r'Promise::new|\.function_call|ext_\w+::', method_body))

            methods.append(func)

        return methods

    def _extract_storage(self, source_code: str, file_path: str) -> List[AbstractVariable]:
        """Extract storage variables."""
        variables = []

        # Find the main contract struct
        struct_pattern = r'#\[near_bindgen\]\s*(?:#\[derive[^\]]+\]\s*)*pub\s+struct\s+\w+\s*\{([^}]+)\}'
        struct_match = re.search(struct_pattern, source_code)

        if struct_match:
            struct_body = struct_match.group(1)
            line_offset = source_code[:struct_match.start()].count("\n")

            # Parse fields
            field_pattern = r'(?:pub\s+)?(\w+)\s*:\s*([^,\n]+)'
            for i, match in enumerate(re.finditer(field_pattern, struct_body)):
                field_name = match.group(1)
                field_type = match.group(2).strip()

                # Detect storage type
                storage_type = "primitive"
                if "LookupMap" in field_type:
                    storage_type = "LookupMap"
                elif "UnorderedMap" in field_type:
                    storage_type = "UnorderedMap"
                elif "Vector" in field_type:
                    storage_type = "Vector"
                elif "LookupSet" in field_type:
                    storage_type = "LookupSet"

                var = AbstractVariable(
                    name=field_name,
                    type_info=TypeInfo(name=field_type),
                    visibility=Visibility.PUBLIC,
                    location=Location(file=file_path, line=line_offset + i + 2),
                    metadata={"storage_type": storage_type},
                )
                variables.append(var)

        return variables

    def _extract_events(self, source_code: str, file_path: str) -> List[AbstractEvent]:
        """Extract NEAR events."""
        events = []

        # NEAR events are typically logged with env::log or log!
        event_pattern = r'#\[derive\([^)]*Event[^)]*\)\]\s*(?:pub\s+)?struct\s+(\w+)'
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
        Detect NEAR-specific vulnerabilities.

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

        # Convert relevant patterns to findings
        for match in pattern_matches:
            finding = self._pattern_to_finding(match, contract)
            if finding:
                findings.append(finding)

        # Semantic checks
        if SecurityProperty.ACCESS_CONTROL in properties:
            findings.extend(self._check_access_control(contract))

        if SecurityProperty.REENTRANCY in properties:
            findings.extend(self._check_callback_safety(contract))

        if SecurityProperty.INPUT_VALIDATION in properties:
            findings.extend(self._check_view_safety(contract))

        return findings

    def _pattern_to_finding(
        self,
        match: Dict[str, Any],
        contract: AbstractContract,
    ) -> Optional[Dict[str, Any]]:
        """Convert pattern match to finding."""
        pattern = match["pattern"]
        severity = match["severity"]

        # Skip info-level patterns
        if severity == "info":
            return None

        messages = {
            "missing_predecessor": (
                "Public function without predecessor check",
                "Add env::predecessor_account_id() validation for access control",
            ),
            "public_callback": (
                "Callback function without #[private] decorator",
                "Add #[private] decorator to prevent external calls to callback",
            ),
            "unwrap_usage": (
                "Use of unwrap() can cause panic",
                "Use proper error handling with Result/Option matching",
            ),
            "panic_macro": (
                "Explicit panic in contract code",
                "Use require! or return Result::Err for graceful error handling",
            ),
            "unbounded_loop": (
                "Potentially unbounded iteration",
                "Add pagination or limit to prevent gas exhaustion",
            ),
            "random_seed": (
                "Predictable randomness source",
                "env::random_seed is predictable; use external VRF for security",
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
            confidence=0.75,
        )

    def _check_access_control(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for access control issues."""
        findings = []
        source = contract.source_code

        for func in contract.functions:
            if func.visibility != Visibility.PUBLIC:
                continue

            # Skip init and view functions
            metadata = func.chain_metadata or {}
            if metadata.get("is_init") or metadata.get("is_view"):
                continue

            # Check if function modifies state
            if func.location:
                func_start = self._find_function_body(source, func.name)
                if func_start:
                    func_body = self._extract_function_body(source, func_start)

                    # Look for state modifications without access check
                    modifies_state = any(pattern in func_body for pattern in [
                        ".insert(", ".remove(", ".replace(", "= ", "+= ", "-= ",
                    ])

                    has_access_check = any(pattern in func_body for pattern in [
                        "predecessor_account_id", "signer_account_id", "require!",
                    ])

                    if modifies_state and not has_access_check and not metadata.get("is_private"):
                        findings.append(self.normalize_finding(
                            vuln_type=NearVulnerability.MISSING_PREDECESSOR_CHECK.value,
                            severity="High",
                            message=f"Function '{func.name}' modifies state without access control",
                            location=func.location,
                            description=(
                                f"The function '{func.name}' appears to modify contract state "
                                "but doesn't verify the caller's identity."
                            ),
                            recommendation=(
                                "Add access control using env::predecessor_account_id() check "
                                "or use #[private] decorator if it should only be called internally."
                            ),
                        ))

        return findings

    def _check_callback_safety(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for callback safety issues."""
        findings = []
        source = contract.source_code

        for func in contract.functions:
            if "callback" not in func.name.lower():
                continue

            metadata = func.chain_metadata or {}
            decorators = metadata.get("decorators", [])

            if "private" not in decorators and func.visibility == Visibility.PUBLIC:
                findings.append(self.normalize_finding(
                    vuln_type=NearVulnerability.UNPROTECTED_CALLBACK.value,
                    severity="High",
                    message=f"Callback '{func.name}' is not marked as private",
                    location=func.location,
                    description=(
                        f"The callback function '{func.name}' can be called by anyone, "
                        "not just the contract itself after a cross-contract call."
                    ),
                    recommendation="Add #[private] decorator to ensure only the contract can call this callback.",
                ))

        return findings

    def _check_view_safety(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Check for view function safety."""
        findings = []
        source = contract.source_code

        for func in contract.functions:
            metadata = func.chain_metadata or {}
            if not metadata.get("is_view"):
                continue

            if func.location:
                func_start = self._find_function_body(source, func.name)
                if func_start:
                    func_body = self._extract_function_body(source, func_start)

                    # Check for panic in view function
                    if any(pattern in func_body for pattern in ["panic!", "unwrap()", ".expect("]):
                        findings.append(self.normalize_finding(
                            vuln_type=NearVulnerability.PANIC_IN_VIEW.value,
                            severity="Medium",
                            message=f"View function '{func.name}' may panic",
                            location=func.location,
                            description=(
                                f"View function '{func.name}' contains panic-inducing code "
                                "which can make the contract appear broken."
                            ),
                            recommendation="Use Option/Result return types instead of panicking in view functions.",
                        ))

        return findings

    def _find_function_body(self, source: str, func_name: str) -> Optional[int]:
        """Find the start of a function body."""
        pattern = rf'fn\s+{func_name}\s*[^{{]*\{{'
        match = re.search(pattern, source)
        return match.end() if match else None

    def _extract_function_body(self, source: str, start: int, max_length: int = 2000) -> str:
        """Extract function body with brace matching."""
        depth = 1
        end = start

        while depth > 0 and end < len(source) and end - start < max_length:
            if source[end] == '{':
                depth += 1
            elif source[end] == '}':
                depth -= 1
            end += 1

        return source[start:end]


# ============================================================================
# Registration
# ============================================================================


def register_near_analyzer() -> NearAnalyzer:
    """Create and register the NEAR analyzer."""
    analyzer = NearAnalyzer()
    register_chain_analyzer(analyzer)
    return analyzer


# ============================================================================
# Convenience Functions
# ============================================================================


def analyze_near_contract(
    source_path: Union[str, Path],
    properties: Optional[List[SecurityProperty]] = None,
) -> Dict[str, Any]:
    """
    Analyze a NEAR contract.

    Args:
        source_path: Path to .rs file
        properties: Security properties to check

    Returns:
        Analysis result
    """
    analyzer = NearAnalyzer()
    return analyzer.analyze(source_path, properties)


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "NearAnalyzer",
    "NearVulnerability",
    "NearPatternDetector",
    "NearMethod",
    "NearStorage",
    "register_near_analyzer",
    "analyze_near_contract",
]
