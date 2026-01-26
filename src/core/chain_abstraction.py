"""
Chain Abstraction Layer
========================

Abstract interfaces for multi-chain smart contract analysis.

Provides a unified abstraction layer for analyzing contracts across different
blockchain platforms (Ethereum/Solidity, Solana/Anchor, NEAR/Rust, Move).

Features:
- Chain-agnostic contract representation
- Unified vulnerability detection interfaces
- Cross-chain finding normalization
- Chain-specific pattern mapping

Architecture:
    AbstractContract
        ├── SolidityContract (EVM)
        ├── AnchorProgram (Solana)
        ├── NearContract (NEAR)
        └── MoveModule (Sui/Aptos)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


# ============================================================================
# Chain Types and Enums
# ============================================================================


class ChainType(Enum):
    """Supported blockchain types."""

    # EVM-compatible chains
    ETHEREUM = "ethereum"
    POLYGON = "polygon"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    BSC = "bsc"
    AVALANCHE = "avalanche"

    # Non-EVM chains
    SOLANA = "solana"
    NEAR = "near"
    SUI = "sui"
    APTOS = "aptos"
    STELLAR = "stellar"
    ALGORAND = "algorand"
    CARDANO = "cardano"

    # Language-based grouping
    @classmethod
    def evm_chains(cls) -> List["ChainType"]:
        """Get all EVM-compatible chains."""
        return [cls.ETHEREUM, cls.POLYGON, cls.ARBITRUM, cls.OPTIMISM, cls.BSC, cls.AVALANCHE]

    @classmethod
    def move_chains(cls) -> List["ChainType"]:
        """Get all Move-based chains."""
        return [cls.SUI, cls.APTOS]


class ContractLanguage(Enum):
    """Smart contract programming languages."""

    SOLIDITY = "solidity"
    VYPER = "vyper"
    RUST = "rust"  # Solana/NEAR/Stellar
    MOVE = "move"  # Sui/Aptos
    CAIRO = "cairo"  # StarkNet
    TEAL = "teal"  # Algorand
    PYTEAL = "pyteal"  # Algorand Python SDK
    PLUTUS = "plutus"  # Cardano (Haskell-based)
    AIKEN = "aiken"  # Cardano (modern language)


class Visibility(Enum):
    """Function/variable visibility."""

    PUBLIC = "public"
    EXTERNAL = "external"
    INTERNAL = "internal"
    PRIVATE = "private"


class Mutability(Enum):
    """Function mutability."""

    PURE = "pure"
    VIEW = "view"
    PAYABLE = "payable"
    NONPAYABLE = "nonpayable"
    MUTABLE = "mutable"  # For non-EVM chains


class SecurityProperty(Enum):
    """Security properties that can be analyzed."""

    ACCESS_CONTROL = "access_control"
    REENTRANCY = "reentrancy"
    ARITHMETIC = "arithmetic"
    INPUT_VALIDATION = "input_validation"
    STATE_HANDLING = "state_handling"
    EXTERNAL_CALLS = "external_calls"
    RANDOMNESS = "randomness"
    TIMESTAMP = "timestamp"
    SIGNATURE = "signature"
    UPGRADE = "upgrade"
    FLASH_LOAN = "flash_loan"
    ORACLE = "oracle"
    MEV = "mev"


# ============================================================================
# Abstract Data Types
# ============================================================================


@dataclass
class TypeInfo:
    """Type information for variables and parameters."""

    name: str
    is_primitive: bool = True
    is_array: bool = False
    is_mapping: bool = False
    key_type: Optional["TypeInfo"] = None
    value_type: Optional["TypeInfo"] = None
    size: Optional[int] = None  # For fixed-size types

    def __str__(self) -> str:
        if self.is_mapping and self.key_type and self.value_type:
            return f"mapping({self.key_type} => {self.value_type})"
        if self.is_array:
            return f"{self.name}[]"
        return self.name


@dataclass
class Parameter:
    """Function parameter."""

    name: str
    type_info: TypeInfo
    is_indexed: bool = False  # For events
    is_storage: bool = False
    default_value: Optional[str] = None


@dataclass
class Location:
    """Source code location."""

    file: str
    line: int
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }


# ============================================================================
# Abstract Contract Elements
# ============================================================================


@dataclass
class AbstractVariable:
    """Abstract representation of a state variable."""

    name: str
    type_info: TypeInfo
    visibility: Visibility = Visibility.INTERNAL
    is_constant: bool = False
    is_immutable: bool = False
    initial_value: Optional[str] = None
    location: Optional[Location] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": str(self.type_info),
            "visibility": self.visibility.value,
            "is_constant": self.is_constant,
            "is_immutable": self.is_immutable,
            "initial_value": self.initial_value,
            "location": self.location.to_dict() if self.location else None,
        }


@dataclass
class AbstractModifier:
    """Abstract representation of a modifier/attribute."""

    name: str
    parameters: List[Parameter] = field(default_factory=list)
    location: Optional[Location] = None
    body_source: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "parameters": [{"name": p.name, "type": str(p.type_info)} for p in self.parameters],
        }


@dataclass
class AbstractFunction:
    """Abstract representation of a function across chains."""

    name: str
    visibility: Visibility = Visibility.PUBLIC
    mutability: Mutability = Mutability.NONPAYABLE
    parameters: List[Parameter] = field(default_factory=list)
    return_types: List[TypeInfo] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    location: Optional[Location] = None
    body_source: Optional[str] = None

    # Analysis metadata
    calls_external: bool = False
    reads_state: bool = False
    writes_state: bool = False
    uses_assembly: bool = False
    has_reentrancy_guard: bool = False

    # Chain-specific
    chain_metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def signature(self) -> str:
        """Get function signature."""
        params = ", ".join(str(p.type_info) for p in self.parameters)
        return f"{self.name}({params})"

    @property
    def is_constructor(self) -> bool:
        """Check if this is a constructor."""
        return self.name in ("constructor", "__init__", "initialize", "init")

    @property
    def is_fallback(self) -> bool:
        """Check if this is a fallback function."""
        return self.name in ("fallback", "receive", "__fallback__")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "signature": self.signature,
            "visibility": self.visibility.value,
            "mutability": self.mutability.value,
            "parameters": [{"name": p.name, "type": str(p.type_info)} for p in self.parameters],
            "return_types": [str(t) for t in self.return_types],
            "modifiers": self.modifiers,
            "calls_external": self.calls_external,
            "reads_state": self.reads_state,
            "writes_state": self.writes_state,
            "uses_assembly": self.uses_assembly,
            "has_reentrancy_guard": self.has_reentrancy_guard,
            "location": self.location.to_dict() if self.location else None,
        }


@dataclass
class AbstractEvent:
    """Abstract representation of an event/log."""

    name: str
    parameters: List[Parameter] = field(default_factory=list)
    location: Optional[Location] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "parameters": [
                {"name": p.name, "type": str(p.type_info), "indexed": p.is_indexed}
                for p in self.parameters
            ],
        }


# ============================================================================
# Abstract Contract
# ============================================================================


@dataclass
class AbstractContract:
    """
    Abstract representation of a smart contract.

    Provides a chain-agnostic view of contract structure that can be
    used for cross-chain vulnerability analysis.
    """

    name: str
    chain_type: ChainType
    language: ContractLanguage
    source_path: str
    source_code: str = ""

    # Contract structure
    functions: List[AbstractFunction] = field(default_factory=list)
    variables: List[AbstractVariable] = field(default_factory=list)
    events: List[AbstractEvent] = field(default_factory=list)
    modifiers: List[AbstractModifier] = field(default_factory=list)

    # Inheritance/imports
    inherits_from: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)

    # Metadata
    compiler_version: Optional[str] = None
    is_abstract: bool = False
    is_interface: bool = False
    is_library: bool = False

    # Analysis cache
    _hash: Optional[str] = field(default=None, repr=False)

    @property
    def content_hash(self) -> str:
        """Get content hash for caching."""
        if not self._hash:
            self._hash = hashlib.sha256(self.source_code.encode()).hexdigest()[:16]
        return self._hash

    def get_function(self, name: str) -> Optional[AbstractFunction]:
        """Get function by name."""
        for func in self.functions:
            if func.name == name:
                return func
        return None

    def get_public_functions(self) -> List[AbstractFunction]:
        """Get all public/external functions."""
        return [
            f for f in self.functions
            if f.visibility in (Visibility.PUBLIC, Visibility.EXTERNAL)
        ]

    def get_state_variables(self) -> List[AbstractVariable]:
        """Get all non-constant state variables."""
        return [v for v in self.variables if not v.is_constant and not v.is_immutable]

    def get_external_calls(self) -> List[AbstractFunction]:
        """Get functions that make external calls."""
        return [f for f in self.functions if f.calls_external]

    def has_modifier(self, name: str) -> bool:
        """Check if contract has a modifier."""
        return any(m.name == name for m in self.modifiers)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "chain_type": self.chain_type.value,
            "language": self.language.value,
            "source_path": self.source_path,
            "content_hash": self.content_hash,
            "functions": [f.to_dict() for f in self.functions],
            "variables": [v.to_dict() for v in self.variables],
            "events": [e.to_dict() for e in self.events],
            "modifiers": [m.to_dict() for m in self.modifiers],
            "inherits_from": self.inherits_from,
            "imports": self.imports,
            "compiler_version": self.compiler_version,
            "is_abstract": self.is_abstract,
            "is_interface": self.is_interface,
            "is_library": self.is_library,
        }


# ============================================================================
# Chain-Specific Vulnerability Mappings
# ============================================================================


@dataclass
class VulnerabilityMapping:
    """Maps vulnerability types across chains."""

    canonical_name: str
    description: str
    severity_default: str
    security_property: SecurityProperty

    # Chain-specific names
    solidity_names: List[str] = field(default_factory=list)
    solana_names: List[str] = field(default_factory=list)
    near_names: List[str] = field(default_factory=list)
    move_names: List[str] = field(default_factory=list)
    stellar_names: List[str] = field(default_factory=list)
    algorand_names: List[str] = field(default_factory=list)
    cardano_names: List[str] = field(default_factory=list)

    # Standard identifiers
    swc_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)


# Cross-chain vulnerability mappings
VULNERABILITY_MAPPINGS: Dict[str, VulnerabilityMapping] = {
    "access_control": VulnerabilityMapping(
        canonical_name="access_control",
        description="Missing or improper access control checks",
        severity_default="High",
        security_property=SecurityProperty.ACCESS_CONTROL,
        solidity_names=["unprotected-function", "missing-onlyowner", "arbitrary-send"],
        solana_names=["missing-signer-check", "missing-owner-check", "account-validation"],
        near_names=["missing-predecessor-check", "access-control"],
        move_names=["missing-capability", "unauthorized-access"],
        stellar_names=["missing-auth-check", "missing-require-auth", "admin-unprotected"],
        algorand_names=["missing-sender-check", "unprotected-update", "missing-app-creator-check"],
        cardano_names=["missing-signer-check", "unauthorized-minting", "missing-datum-check"],
        swc_ids=["SWC-105"],
        cwe_ids=["CWE-284", "CWE-285"],
    ),
    "reentrancy": VulnerabilityMapping(
        canonical_name="reentrancy",
        description="Reentrancy vulnerability allowing recursive calls",
        severity_default="Critical",
        security_property=SecurityProperty.REENTRANCY,
        solidity_names=["reentrancy", "reentrancy-eth", "reentrancy-no-eth", "cross-function-reentrancy"],
        solana_names=["cpi-reentrancy", "cross-program-reentrancy"],
        near_names=["cross-contract-reentrancy"],
        move_names=["reentrancy"],  # Move prevents most reentrancy by design
        stellar_names=["reentrancy-risk", "cross-contract-unsafe"],
        algorand_names=["inner-txn-reentrancy"],  # Algorand has atomic groups
        cardano_names=["double-satisfaction"],  # eUTXO prevents traditional reentrancy
        swc_ids=["SWC-107"],
        cwe_ids=["CWE-841"],
    ),
    "arithmetic": VulnerabilityMapping(
        canonical_name="arithmetic",
        description="Integer overflow/underflow or precision loss",
        severity_default="High",
        security_property=SecurityProperty.ARITHMETIC,
        solidity_names=["integer-overflow", "integer-underflow", "unchecked-math"],
        solana_names=["arithmetic-overflow", "checked-math"],
        near_names=["overflow", "underflow"],
        move_names=["abort-on-overflow"],  # Move has built-in overflow checks
        stellar_names=["arithmetic-overflow", "unchecked-ops"],
        algorand_names=["overflow", "underflow", "division-by-zero"],
        cardano_names=["integer-overflow", "ada-calculation-error"],
        swc_ids=["SWC-101"],
        cwe_ids=["CWE-190", "CWE-191"],
    ),
    "input_validation": VulnerabilityMapping(
        canonical_name="input_validation",
        description="Missing or improper input validation",
        severity_default="Medium",
        security_property=SecurityProperty.INPUT_VALIDATION,
        solidity_names=["unvalidated-input", "missing-zero-check", "assert-violation"],
        solana_names=["account-data-validation", "type-confusion", "missing-account-check"],
        near_names=["input-validation", "deserialization"],
        move_names=["type-safety", "borrow-check"],
        stellar_names=["unwrap-without-check", "panic-in-contract"],
        algorand_names=["unchecked-txn-type", "missing-asset-check", "gtxn-validation"],
        cardano_names=["datum-validation", "redeemer-injection", "missing-utxo-check"],
        swc_ids=["SWC-123"],
        cwe_ids=["CWE-20"],
    ),
    "signature": VulnerabilityMapping(
        canonical_name="signature",
        description="Signature verification issues",
        severity_default="Critical",
        security_property=SecurityProperty.SIGNATURE,
        solidity_names=["signature-malleability", "ecrecover", "signature-replay"],
        solana_names=["signature-verification", "ed25519-validation"],
        near_names=["signature-check"],
        move_names=["signature-verification"],
        stellar_names=["signature-check"],
        algorand_names=["ed25519-verify", "lsig-security"],
        cardano_names=["ed25519-verify", "multisig-validation"],
        swc_ids=["SWC-117", "SWC-121", "SWC-122"],
        cwe_ids=["CWE-347"],
    ),
}


def get_vulnerability_mapping(vuln_type: str) -> Optional[VulnerabilityMapping]:
    """Get vulnerability mapping by canonical name or chain-specific name."""
    # Direct lookup
    if vuln_type in VULNERABILITY_MAPPINGS:
        return VULNERABILITY_MAPPINGS[vuln_type]

    # Search in chain-specific names
    vuln_lower = vuln_type.lower().replace("-", "_").replace(" ", "_")
    for mapping in VULNERABILITY_MAPPINGS.values():
        all_names = (
            mapping.solidity_names +
            mapping.solana_names +
            mapping.near_names +
            mapping.move_names +
            mapping.stellar_names +
            mapping.algorand_names +
            mapping.cardano_names
        )
        for name in all_names:
            if name.lower().replace("-", "_") == vuln_lower:
                return mapping

    return None


def normalize_vulnerability_type(vuln_type: str, source_chain: ChainType) -> str:
    """Normalize chain-specific vulnerability type to canonical name."""
    mapping = get_vulnerability_mapping(vuln_type)
    if mapping:
        return mapping.canonical_name
    return vuln_type


# ============================================================================
# Abstract Analyzer Interface
# ============================================================================


class AbstractChainAnalyzer(ABC):
    """
    Abstract base class for chain-specific analyzers.

    Provides a unified interface for parsing and analyzing contracts
    across different blockchain platforms.
    """

    def __init__(self, chain_type: ChainType, language: ContractLanguage):
        """
        Initialize analyzer.

        Args:
            chain_type: Target blockchain type
            language: Contract language
        """
        self.chain_type = chain_type
        self.language = language
        self._parsed_contracts: Dict[str, AbstractContract] = {}

    @property
    @abstractmethod
    def name(self) -> str:
        """Analyzer name."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Analyzer version."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """Supported file extensions."""
        pass

    @abstractmethod
    def parse(self, source_path: Union[str, Path]) -> AbstractContract:
        """
        Parse source file into AbstractContract.

        Args:
            source_path: Path to source file

        Returns:
            AbstractContract representation
        """
        pass

    @abstractmethod
    def detect_vulnerabilities(
        self,
        contract: AbstractContract,
        properties: Optional[List[SecurityProperty]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities in contract.

        Args:
            contract: Parsed contract
            properties: Security properties to check (None = all)

        Returns:
            List of findings in MIESC normalized format
        """
        pass

    def can_analyze(self, source_path: Union[str, Path]) -> bool:
        """Check if this analyzer can handle the file."""
        path = Path(source_path)
        return path.suffix.lower() in self.supported_extensions

    def analyze(
        self,
        source_path: Union[str, Path],
        properties: Optional[List[SecurityProperty]] = None,
    ) -> Dict[str, Any]:
        """
        Full analysis: parse + detect vulnerabilities.

        Args:
            source_path: Path to source file
            properties: Security properties to check

        Returns:
            Analysis result with contract info and findings
        """
        import time
        start_time = time.time()

        try:
            # Parse contract
            contract = self.parse(source_path)
            self._parsed_contracts[contract.content_hash] = contract

            # Detect vulnerabilities
            findings = self.detect_vulnerabilities(contract, properties)

            execution_time = time.time() - start_time

            return {
                "status": "success",
                "analyzer": self.name,
                "version": self.version,
                "chain_type": self.chain_type.value,
                "language": self.language.value,
                "contract": contract.to_dict(),
                "findings": findings,
                "execution_time": execution_time,
                "properties_checked": [p.value for p in (properties or list(SecurityProperty))],
            }

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {
                "status": "error",
                "analyzer": self.name,
                "chain_type": self.chain_type.value,
                "error": str(e),
                "execution_time": time.time() - start_time,
            }

    def normalize_finding(
        self,
        vuln_type: str,
        severity: str,
        message: str,
        location: Location,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Create a normalized finding.

        Args:
            vuln_type: Vulnerability type (will be normalized)
            severity: Severity level
            message: Finding message
            location: Source location
            **kwargs: Additional finding fields

        Returns:
            Normalized finding dictionary
        """
        # Normalize vulnerability type
        canonical_type = normalize_vulnerability_type(vuln_type, self.chain_type)
        mapping = get_vulnerability_mapping(canonical_type)

        finding = {
            "id": f"{self.chain_type.value}-{canonical_type}-{location.line}",
            "type": canonical_type,
            "original_type": vuln_type,
            "severity": severity,
            "confidence": kwargs.get("confidence", 0.8),
            "location": location.to_dict(),
            "message": message,
            "description": kwargs.get("description", message),
            "recommendation": kwargs.get("recommendation", ""),
            "chain_type": self.chain_type.value,
            "language": self.language.value,
        }

        # Add mapping info if available
        if mapping:
            finding["swc_id"] = mapping.swc_ids[0] if mapping.swc_ids else None
            finding["cwe_id"] = mapping.cwe_ids[0] if mapping.cwe_ids else None
            finding["security_property"] = mapping.security_property.value

        # Add any extra fields
        for key, value in kwargs.items():
            if key not in finding:
                finding[key] = value

        return finding


# ============================================================================
# Chain Registry
# ============================================================================


class ChainRegistry:
    """
    Registry for chain-specific analyzers.

    Manages analyzer instances and provides discovery functionality.
    """

    _instance: Optional["ChainRegistry"] = None
    _analyzers: Dict[ChainType, AbstractChainAnalyzer] = {}

    def __new__(cls) -> "ChainRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._analyzers = {}
        return cls._instance

    def register(self, analyzer: AbstractChainAnalyzer) -> None:
        """Register an analyzer."""
        self._analyzers[analyzer.chain_type] = analyzer
        logger.info(f"Registered {analyzer.name} for {analyzer.chain_type.value}")

    def get(self, chain_type: ChainType) -> Optional[AbstractChainAnalyzer]:
        """Get analyzer for chain type."""
        return self._analyzers.get(chain_type)

    def get_for_file(self, file_path: Union[str, Path]) -> Optional[AbstractChainAnalyzer]:
        """Get analyzer that can handle a file."""
        for analyzer in self._analyzers.values():
            if analyzer.can_analyze(file_path):
                return analyzer
        return None

    def list_chains(self) -> List[ChainType]:
        """List registered chain types."""
        return list(self._analyzers.keys())

    def get_status(self) -> Dict[str, Any]:
        """Get registry status."""
        return {
            "registered_chains": [c.value for c in self._analyzers.keys()],
            "analyzers": [
                {
                    "name": a.name,
                    "version": a.version,
                    "chain": a.chain_type.value,
                    "language": a.language.value,
                    "extensions": a.supported_extensions,
                }
                for a in self._analyzers.values()
            ],
        }


# Global registry instance
_chain_registry: Optional[ChainRegistry] = None


def get_chain_registry() -> ChainRegistry:
    """Get the global chain registry."""
    global _chain_registry
    if _chain_registry is None:
        _chain_registry = ChainRegistry()
    return _chain_registry


def register_chain_analyzer(analyzer: AbstractChainAnalyzer) -> None:
    """Register a chain analyzer."""
    get_chain_registry().register(analyzer)


def get_analyzer_for_chain(chain_type: ChainType) -> Optional[AbstractChainAnalyzer]:
    """Get analyzer for a specific chain."""
    return get_chain_registry().get(chain_type)


def get_analyzer_for_file(file_path: Union[str, Path]) -> Optional[AbstractChainAnalyzer]:
    """Get analyzer that can handle a file."""
    return get_chain_registry().get_for_file(file_path)


# ============================================================================
# Export
# ============================================================================

__all__ = [
    # Enums
    "ChainType",
    "ContractLanguage",
    "Visibility",
    "Mutability",
    "SecurityProperty",
    # Data types
    "TypeInfo",
    "Parameter",
    "Location",
    # Contract elements
    "AbstractVariable",
    "AbstractModifier",
    "AbstractFunction",
    "AbstractEvent",
    "AbstractContract",
    # Vulnerability mappings
    "VulnerabilityMapping",
    "VULNERABILITY_MAPPINGS",
    "get_vulnerability_mapping",
    "normalize_vulnerability_type",
    # Abstract analyzer
    "AbstractChainAnalyzer",
    # Registry
    "ChainRegistry",
    "get_chain_registry",
    "register_chain_analyzer",
    "get_analyzer_for_chain",
    "get_analyzer_for_file",
]
