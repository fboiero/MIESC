"""
Vyper Adapter
=============

WARNING: EXPERIMENTAL / ROADMAP - NOT production-validated.
This adapter uses pattern-based (regex/heuristic) detection only, same tier
as the other non-Solidity adapters (near, stellar, algorand, cardano,
solana, move, cairo). EVM/Solidity analysis (Slither/Aderyn/Mythril/etc.)
is the production-ready surface. See docs/MULTICHAIN.md.

Adapter for analyzing Vyper (.vy) smart contracts.

Detects Vyper-specific patterns:
- Known-broken @nonreentrant lock in specific compiler versions (root
  cause of the Curve Finance ~$70M incident, 2023-07-30 - Vyper compiler
  versions 0.2.15, 0.2.16 and 0.3.0 shipped a broken reentrancy lock;
  see the official advisory for the authoritative version list before
  relying on this check alone)
- Reentrancy: external value transfer without @nonreentrant guard
- selfdestruct usage (deprecated since Vyper 0.3.10, still dangerous
  where available)
- raw_call(..., is_delegate_call=True) - delegatecall to a
  caller-influenced target
- create_forwarder_to / create_minimal_proxy_to / create_from_blueprint
  without a visible init guard in the same function (proxy front-running)
- tx.origin used for authorization
- Missing access control on state-changing @external functions
- unsafe_add/unsafe_sub/unsafe_mul/unsafe_div (explicit unchecked math)

References:
- https://docs.vyperlang.org/en/stable/
- https://github.com/vyperlang/vyper/security/advisories/GHSA-ph9x-4vc9-m2gg
- https://hacken.io/discover/curve-finance-hack/ (Curve Finance incident writeup)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: August 2026
Version: 1.0.0
"""

import logging
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from miesc.core.chain_abstraction import (
    AbstractChainAnalyzer,
    AbstractContract,
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
from miesc.core.tool_protocol import (
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

logger = logging.getLogger(__name__)

# Vyper compiler versions with a documented broken @nonreentrant lock.
# Root cause of the Curve Finance incident (2023-07-30, ~$70M across
# multiple pools). Consult the official advisory for the authoritative,
# up-to-date list — this set is a starting point, not exhaustive.
BROKEN_REENTRANCY_LOCK_VERSIONS = {"0.2.15", "0.2.16", "0.3.0"}


# ============================================================================
# Vyper-Specific Types
# ============================================================================


class VyperVulnerability(Enum):
    """Vyper-specific vulnerability types."""

    BROKEN_REENTRANCY_LOCK_COMPILER = "broken_reentrancy_lock_compiler"
    MISSING_REENTRANCY_GUARD = "missing_reentrancy_guard"
    SELFDESTRUCT_USAGE = "selfdestruct_usage"
    DANGEROUS_DELEGATECALL = "dangerous_delegatecall"
    UNSAFE_PROXY_CREATION = "unsafe_proxy_creation"
    TX_ORIGIN_AUTH = "tx_origin_auth"
    MISSING_ACCESS_CONTROL = "missing_access_control"
    UNSAFE_ARITHMETIC = "unsafe_arithmetic"


@dataclass
class VyperFunction:
    """Represents a Vyper contract function."""

    name: str
    decorators: List[str] = field(default_factory=list)
    params: str = ""
    body: str = ""
    line: int = 0

    @property
    def is_external(self) -> bool:
        return "external" in self.decorators

    @property
    def is_payable(self) -> bool:
        return "payable" in self.decorators

    @property
    def has_reentrancy_guard(self) -> bool:
        return any(d.startswith("nonreentrant") for d in self.decorators)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "decorators": self.decorators,
            "is_external": self.is_external,
            "is_payable": self.is_payable,
            "has_reentrancy_guard": self.has_reentrancy_guard,
        }


# ============================================================================
# Vyper Pattern Detector
# ============================================================================


class VyperPatternDetector:
    """Detects vulnerability patterns in Vyper source code."""

    VERSION_RE = re.compile(r"#\s*(?:@version|pragma\s+version)\s+([^\s\n]+)")
    FUNCTION_RE = re.compile(
        r"(?P<decorators>(?:^@\w+(?:\([^)\n]*\))?[ \t]*\n)*)"
        r"^def[ \t]+(?P<name>\w+)[ \t]*\((?P<params>[^)]*)\)[ \t]*"
        r"(?:->[ \t]*[^:\n]+)?:",
        re.MULTILINE,
    )
    DECORATOR_RE = re.compile(r"@(\w+)")

    # Simple, single-occurrence patterns: (regex, VyperVulnerability, severity)
    SIMPLE_PATTERNS = [
        (re.compile(r"\bselfdestruct\s*\("), VyperVulnerability.SELFDESTRUCT_USAGE, "High"),
        (re.compile(r"\btx\.origin\b"), VyperVulnerability.TX_ORIGIN_AUTH, "Medium"),
        (
            re.compile(r"\bunsafe_(add|sub|mul|div)\s*\("),
            VyperVulnerability.UNSAFE_ARITHMETIC,
            "Medium",
        ),
        (
            re.compile(r"raw_call\s*\([^)]{0,300}?is_delegate_call\s*=\s*True", re.DOTALL),
            VyperVulnerability.DANGEROUS_DELEGATECALL,
            "High",
        ),
        (
            re.compile(
                r"\b(create_forwarder_to|create_minimal_proxy_to|create_from_blueprint)\s*\("
            ),
            VyperVulnerability.UNSAFE_PROXY_CREATION,
            "Medium",
        ),
    ]

    EXTERNAL_CALL_RE = re.compile(
        r"\braw_call\s*\(|\bsend\s*\(|\bextcall\b|\braw_revert\s*\(|"
        r"\b\w+\s*\(\s*\w+\s*\)\.\w+\s*\("
    )
    STATE_WRITE_RE = re.compile(r"\bself\.\w+\s*(\[[^\]]*\])?\s*(\+=|-=|\*=|/=|=[^=])")
    ACCESS_CHECK_RE = re.compile(r"assert\s+[^\n]*msg\.sender|owner\s*\(\s*\)")

    def detect_simple_patterns(self, source_code: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect single-regex vulnerability patterns anywhere in the source."""
        findings: List[Dict[str, Any]] = []
        for pattern, vuln_type, severity in self.SIMPLE_PATTERNS:
            for match in pattern.finditer(source_code):
                line = source_code[: match.start()].count("\n") + 1
                findings.append(
                    {
                        "vuln_type": vuln_type,
                        "severity": severity,
                        "line": line,
                        "file": file_path,
                        "code": (
                            source_code.splitlines()[line - 1].strip()
                            if line <= len(source_code.splitlines())
                            else ""
                        ),
                    }
                )
        return findings

    def extract_version(self, source_code: str) -> Optional[str]:
        match = self.VERSION_RE.search(source_code)
        if not match:
            return None
        return match.group(1).lstrip("=^~<>! ")

    def extract_functions(self, source_code: str, file_path: str) -> List[VyperFunction]:
        """Extract top-level (0-indent) function definitions with their decorators."""
        functions: List[VyperFunction] = []
        lines = source_code.split("\n")

        for match in self.FUNCTION_RE.finditer(source_code):
            name = match.group("name")
            decorators = self.DECORATOR_RE.findall(match.group("decorators") or "")
            # Line the `def` keyword itself is on (i.e. after the decorator lines).
            def_offset = match.start(0) + len(match.group("decorators") or "")
            def_line = source_code[:def_offset].count("\n") + 1

            body = self._extract_body(lines, def_line)

            functions.append(
                VyperFunction(
                    name=name,
                    decorators=decorators,
                    params=match.group("params"),
                    body=body,
                    line=def_line,
                )
            )
        return functions

    def _extract_body(self, lines: List[str], def_line: int) -> str:
        """Collect lines indented deeper than the `def` line (Python-style blocks)."""
        if def_line < 1 or def_line > len(lines):
            return ""
        def_indent = len(lines[def_line - 1]) - len(lines[def_line - 1].lstrip())
        body_lines: List[str] = []
        for line in lines[def_line:]:
            if not line.strip():
                body_lines.append(line)
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= def_indent:
                break
            body_lines.append(line)
        return "\n".join(body_lines)


# ============================================================================
# Vyper Analyzer
# ============================================================================


class VyperAnalyzer(AbstractChainAnalyzer):
    """
    Analyzer for Vyper smart contracts.

    Pattern-based parsing and vulnerability detection — no dependency on
    the `vyper` compiler being installed. If `vyper` is available on PATH,
    `compiler_available` is recorded on the result as a bonus signal, but
    detection never depends on it (a contract's `@version` pragma very
    often won't match whatever compiler happens to be installed, so relying
    on a real compile would produce noisy false "can't analyze" failures).
    """

    def __init__(self) -> None:
        super().__init__(ChainType.ETHEREUM, ContractLanguage.VYPER)
        self.pattern_detector = VyperPatternDetector()

    @property
    def name(self) -> str:
        return "vyper-analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def supported_extensions(self) -> List[str]:
        return [".vy"]

    def parse(self, source_path: Union[str, Path]) -> AbstractContract:
        path = Path(source_path)
        source_code = path.read_text()

        contract = AbstractContract(
            name=path.stem,
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.VYPER,
            source_path=str(path),
            source_code=source_code,
            compiler_version=self.pattern_detector.extract_version(source_code),
        )

        for vyper_fn in self.pattern_detector.extract_functions(source_code, str(path)):
            visibility = Visibility.EXTERNAL if vyper_fn.is_external else Visibility.INTERNAL
            mutability = Mutability.PAYABLE if vyper_fn.is_payable else Mutability.NONPAYABLE

            params = []
            for p in vyper_fn.params.split(","):
                p = p.strip()
                if not p:
                    continue
                name_part = p.split(":")[0].strip()
                type_part = p.split(":", 1)[1].strip() if ":" in p else "unknown"
                params.append(Parameter(name=name_part, type_info=TypeInfo(name=type_part)))

            contract.functions.append(
                AbstractFunction(
                    name=vyper_fn.name,
                    visibility=visibility,
                    mutability=mutability,
                    parameters=params,
                    modifiers=vyper_fn.decorators,
                    location=Location(file=str(path), line=vyper_fn.line),
                    body_source=vyper_fn.body,
                    calls_external=bool(
                        self.pattern_detector.EXTERNAL_CALL_RE.search(vyper_fn.body)
                    ),
                    writes_state=bool(self.pattern_detector.STATE_WRITE_RE.search(vyper_fn.body)),
                    has_reentrancy_guard=vyper_fn.has_reentrancy_guard,
                    chain_metadata={"decorators": vyper_fn.decorators},
                )
            )

        contract.variables = self._extract_state_variables(source_code, str(path))
        return contract

    def _extract_state_variables(self, source_code: str, file_path: str) -> List[AbstractVariable]:
        """Extract module-level state variable declarations (`name: type`)."""
        variables: List[AbstractVariable] = []
        var_re = re.compile(
            r"^(\w+)\s*:\s*(public\s*\(\s*)?([^=\n]+?)\)?\s*(?:=.*)?$", re.MULTILINE
        )
        for match in var_re.finditer(source_code):
            name = match.group(1)
            if name in ("def", "event", "struct", "interface", "implements"):
                continue
            line = source_code[: match.start()].count("\n") + 1
            # Only module-level (0-indent) declarations, not inside a function/struct body.
            line_text = source_code.splitlines()[line - 1]
            if line_text != line_text.lstrip():
                continue
            is_public = match.group(2) is not None
            variables.append(
                AbstractVariable(
                    name=name,
                    type_info=TypeInfo(name=match.group(3).strip()),
                    visibility=Visibility.PUBLIC if is_public else Visibility.INTERNAL,
                    location=Location(file=file_path, line=line),
                )
            )
        return variables

    def detect_vulnerabilities(
        self,
        contract: AbstractContract,
        properties: Optional[List[SecurityProperty]] = None,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        source_code = contract.source_code
        if not source_code:
            return findings

        properties = properties or list(SecurityProperty)

        if SecurityProperty.REENTRANCY in properties:
            findings.extend(self._check_broken_reentrancy_lock(contract))
            findings.extend(self._check_missing_reentrancy_guard(contract))

        for match in self.pattern_detector.detect_simple_patterns(
            source_code, contract.source_path
        ):
            vuln_type = match["vuln_type"]
            if vuln_type == VyperVulnerability.DANGEROUS_DELEGATECALL and (
                SecurityProperty.EXTERNAL_CALLS not in properties
            ):
                continue
            if (
                vuln_type
                in (
                    VyperVulnerability.SELFDESTRUCT_USAGE,
                    VyperVulnerability.TX_ORIGIN_AUTH,
                    VyperVulnerability.MISSING_ACCESS_CONTROL,
                )
                and SecurityProperty.ACCESS_CONTROL not in properties
            ):
                continue
            if vuln_type == VyperVulnerability.UNSAFE_ARITHMETIC and (
                SecurityProperty.ARITHMETIC not in properties
            ):
                continue
            if vuln_type == VyperVulnerability.UNSAFE_PROXY_CREATION and (
                SecurityProperty.UPGRADE not in properties
            ):
                continue
            findings.append(self._simple_match_to_finding(match))

        if SecurityProperty.ACCESS_CONTROL in properties:
            findings.extend(self._check_missing_access_control(contract))

        return [f for f in findings if f is not None]

    def _simple_match_to_finding(self, match: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        vuln_type: VyperVulnerability = match["vuln_type"]
        messages = {
            VyperVulnerability.SELFDESTRUCT_USAGE: (
                "Use of selfdestruct()",
                "selfdestruct is deprecated since Vyper 0.3.10 and destroys the contract "
                "irrecoverably; avoid it, and if kept, gate it behind strict access control.",
            ),
            VyperVulnerability.TX_ORIGIN_AUTH: (
                "tx.origin referenced in source",
                "Never use tx.origin for authorization — a malicious contract can relay a "
                "call through a legitimate user. Use msg.sender instead.",
            ),
            VyperVulnerability.UNSAFE_ARITHMETIC: (
                "Explicit unsafe_* arithmetic operation",
                "unsafe_add/sub/mul/div skip Vyper's built-in overflow checks — confirm the "
                "operands can never realistically over/underflow before relying on this.",
            ),
            VyperVulnerability.DANGEROUS_DELEGATECALL: (
                "raw_call with is_delegate_call=True",
                "Delegatecall executes target code in this contract's storage context — if "
                "the target address is caller-influenced, this is a full storage-takeover "
                "primitive. Restrict the target to a trusted, immutable address.",
            ),
            VyperVulnerability.UNSAFE_PROXY_CREATION: (
                "Proxy/clone creation without a visible init guard",
                "create_forwarder_to/create_minimal_proxy_to/create_from_blueprint deploy an "
                "uninitialized clone — if initialization isn't atomic with deployment, an "
                "attacker can front-run it and take ownership of the clone.",
            ),
        }
        if vuln_type not in messages:
            return None
        message, recommendation = messages[vuln_type]
        return self.normalize_finding(
            vuln_type=vuln_type.value,
            severity=match["severity"],
            message=message,
            location=Location(file=match["file"], line=match["line"]),
            description=f"{message}\nCode: {match.get('code', '')}",
            recommendation=recommendation,
            confidence=0.7,
        )

    def _check_broken_reentrancy_lock(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        """Flag @nonreentrant used under a compiler version with a known-broken lock.

        Root cause of the Curve Finance incident (2023-07-30, ~$70M). Confirm
        against the official Vyper security advisory before treating this as
        conclusive — BROKEN_REENTRANCY_LOCK_VERSIONS is a starting point.
        """
        if not contract.compiler_version:
            return []
        if contract.compiler_version not in BROKEN_REENTRANCY_LOCK_VERSIONS:
            return []
        if "@nonreentrant" not in contract.source_code:
            return []

        return [
            self.normalize_finding(
                vuln_type=VyperVulnerability.BROKEN_REENTRANCY_LOCK_COMPILER.value,
                severity="Critical",
                message=(
                    f"@nonreentrant used under Vyper {contract.compiler_version}, a compiler "
                    "version with a documented broken reentrancy lock"
                ),
                location=Location(file=contract.source_path, line=1),
                description=(
                    "Vyper compiler versions 0.2.15, 0.2.16 and 0.3.0 shipped a broken "
                    "@nonreentrant lock implementation — the root cause of the Curve Finance "
                    "incident (2023-07-30, ~$70M across multiple pools). Contracts compiled "
                    "with one of these versions have a reentrancy guard that does not "
                    "actually block reentrancy."
                ),
                recommendation=(
                    "Recompile with a patched Vyper version and redeploy, or verify against "
                    "the official advisory (GHSA-ph9x-4vc9-m2gg) whether this exact version "
                    "and pattern combination is affected."
                ),
                confidence=0.6,
            )
        ]

    def _check_missing_reentrancy_guard(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for func in contract.functions:
            if func.visibility != Visibility.EXTERNAL:
                continue
            if not func.calls_external or not func.writes_state:
                continue
            if func.has_reentrancy_guard:
                continue
            findings.append(
                self.normalize_finding(
                    vuln_type=VyperVulnerability.MISSING_REENTRANCY_GUARD.value,
                    severity="High",
                    message=f"'{func.name}' writes state and makes an external call "
                    "without @nonreentrant",
                    location=func.location,
                    description=f"Function: {func.name}\nDecorators: {func.modifiers}",
                    recommendation="Add the @nonreentrant decorator, or apply "
                    "checks-effects-interactions (update state before the external call).",
                    confidence=0.65,
                )
            )
        return findings

    def _check_missing_access_control(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        # Vyper has no modifiers, so `self._check_admin()`-style internal helpers are the
        # idiomatic way to share an access check across functions — look one call deep
        # before flagging, or every such contract is 100% false positives.
        bodies_by_name = {f.name: f.body_source or "" for f in contract.functions}
        internal_call_re = re.compile(r"self\.(\w+)\s*\(")
        for func in contract.functions:
            if func.visibility != Visibility.EXTERNAL:
                continue
            if not func.writes_state:
                continue
            if func.name in ("__init__",):
                continue
            body = func.body_source or ""
            if self.pattern_detector.ACCESS_CHECK_RE.search(body):
                continue
            if any(
                self.pattern_detector.ACCESS_CHECK_RE.search(bodies_by_name.get(callee, ""))
                for callee in internal_call_re.findall(body)
            ):
                continue
            findings.append(
                self.normalize_finding(
                    vuln_type=VyperVulnerability.MISSING_ACCESS_CONTROL.value,
                    severity="Medium",
                    message=f"'{func.name}' is external, writes state, and has no visible "
                    "msg.sender / owner() check",
                    location=func.location,
                    description=f"Function: {func.name}",
                    recommendation="Add an explicit assert msg.sender == <authorized address> "
                    "(or equivalent) if this function should be access-restricted; ignore if "
                    "it's intentionally open (e.g., deposit()).",
                    confidence=0.4,
                )
            )
        return findings


# ============================================================================
# ToolAdapter wrapper — lets run_layer()/run_tool() (miesc/cli/utils.py) drive
# VyperAnalyzer the same way as any Solidity tool (MEJORAS3.md item 7: before
# this, `.vy` files had no route into the evaluate/scan tool-execution path;
# `miesc analyze` invoked VyperAnalyzer directly instead).
# ============================================================================


class VyperAdapter:
    """ToolAdapter-shaped wrapper around VyperAnalyzer (duck-typed, same

    pattern as DeFiAdapter/SmartBugsDetectorAdapter — no external binary, no
    ToolAdapter subclassing needed for run_layer to drive it).
    """

    name = "vyper"

    def __init__(self) -> None:
        self._analyzer = VyperAnalyzer()

    def is_available(self) -> ToolStatus:
        # Pure Python pattern matching — no external compiler/binary required.
        return ToolStatus.AVAILABLE

    def can_analyze(self, contract_path: str) -> bool:
        return self._analyzer.can_analyze(contract_path)

    def analyze(self, contract_path: str, timeout: int = 0, **kwargs: Any) -> Dict[str, Any]:
        # Regex/AST-free pattern matching over source text — effectively
        # instant, so `timeout` (used by subprocess-based adapters) doesn't
        # apply here.
        return self._analyzer.analyze(contract_path)

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.name,
            version=self._analyzer.version,
            category=ToolCategory.STATIC_ANALYSIS,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://fboiero.github.io/MIESC/docs/MULTICHAIN.html",
            installation_cmd="",  # bundled — no separate install step
            capabilities=[
                ToolCapability(
                    name="vyper_pattern_detection",
                    description="Pattern-based vulnerability detection for Vyper (.vy) contracts",
                    supported_languages=["vyper"],
                    detection_types=[v.value for v in VyperVulnerability],
                )
            ],
            is_optional=True,
        )


# ============================================================================
# Optional compiler probe (bonus signal only — never required for detection)
# ============================================================================


def probe_vyper_compiler() -> Optional[str]:
    """Return the installed `vyper` compiler version string, or None if unavailable."""
    try:
        result = subprocess.run(["vyper", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.debug(f"vyper compiler not available: {e}")
    return None


# ============================================================================
# Registration
# ============================================================================


def register_vyper_analyzer() -> VyperAnalyzer:
    """Create and register the Vyper analyzer."""
    analyzer = VyperAnalyzer()
    register_chain_analyzer(analyzer)
    return analyzer


# ============================================================================
# Convenience Functions
# ============================================================================


def analyze_vyper_contract(
    source_path: Union[str, Path],
    properties: Optional[List[SecurityProperty]] = None,
) -> Dict[str, Any]:
    """Analyze a Vyper contract (parse + detect_vulnerabilities)."""
    analyzer = VyperAnalyzer()
    return analyzer.analyze(source_path, properties)


__all__ = [
    "VyperAnalyzer",
    "VyperVulnerability",
    "VyperPatternDetector",
    "VyperFunction",
    "BROKEN_REENTRANCY_LOCK_VERSIONS",
    "register_vyper_analyzer",
    "analyze_vyper_contract",
    "probe_vyper_compiler",
]
