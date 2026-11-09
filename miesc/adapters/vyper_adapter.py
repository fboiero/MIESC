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
- create_forwarder_to / create_minimal_proxy_to without an init call after it
  in the same function (proxy front-running; create_from_blueprint runs the
  blueprint's constructor atomically and is not flagged)
- tx.origin used for authorization
- Missing access control on state-changing @external functions
- unsafe_add/unsafe_sub/unsafe_mul/unsafe_div (explicit unchecked math)

Known limit: a .vy file only reaches this analyzer. SlitherAdapter.can_analyze
accepts .sol only, so Slither's own Vyper support (which needs the vyper
compiler on PATH) is not used.

References:
- https://docs.vyperlang.org/en/stable/
- https://github.com/vyperlang/vyper/security/advisories/GHSA-5824-cm3x-3c38
- https://hacken.io/discover/curve-finance-hack/ (Curve Finance incident writeup)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: August 2026
Version: 1.0.0
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import AbstractSet, Any, Dict, List, Optional, Union

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

# Comments and docstrings, blanked before any pattern runs (newlines kept, so line
# numbers survive): a `selfdestruct(` or `tx.origin` in prose is not code. Plain string
# literals are matched too, so a `#` inside one is not taken for a comment, and kept.
_COMMENT_OR_STRING_RE = re.compile(
    r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|#[^\n]*'
)


def strip_comments(source: str) -> str:
    """Blank comments and docstrings, keeping every newline."""

    def blank(match: "re.Match[str]") -> str:
        text = match.group()
        if text.startswith(("#", '"""', "'''")):
            return re.sub(r"[^\n]", " ", text)
        return text

    return _COMMENT_OR_STRING_RE.sub(blank, source)


_SPEC_TERM_RE = re.compile(r"(\^|~=?|[<>]=?|==?)?\s*v?(\d+)\.(\d+)\.(\d+)")


def version_spec_terms(spec: str) -> List[tuple]:
    return [(op, (int(a), int(b), int(c))) for op, a, b, c in _SPEC_TERM_RE.findall(spec)]


def version_spec_admits(spec: str, version: str) -> bool:
    """Whether a `# @version` / `# pragma version` spec admits ``version``.

    ``^0.3.0`` and ``~0.3.0``/``~=0.3.0`` admit up to the next minor (``<0.4.0``);
    comparators (``>=0.3.0 <0.4.0``) are ANDed; a bare version is an exact pin.
    """
    terms = version_spec_terms(spec)
    if not terms:
        return False
    v = tuple(int(x) for x in version.split("."))
    for op, b in terms:
        if op in ("^", "~", "~="):
            upper = (b[0] + 1, 0, 0) if op == "^" and b[0] > 0 else (b[0], b[1] + 1, 0)
            ok = b <= v < upper
        elif op == ">=":
            ok = v >= b
        elif op == ">":
            ok = v > b
        elif op == "<=":
            ok = v <= b
        elif op == "<":
            ok = v < b
        else:
            ok = v == b
        if not ok:
            return False
    return True


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

    VERSION_RE = re.compile(r"#\s*(?:@version|pragma\s+version)\s+([^\n]+)")
    FUNCTION_RE = re.compile(
        r"(?P<decorators>(?:^@\w+(?:\([^)\n]*\))?[ \t]*\n)*)"
        r"^def[ \t]+(?P<name>\w+)[ \t]*\((?P<params>(?:[^()]|\([^()]*\))*)\)[ \t]*"
        r"(?:->(?:[^:()]|\([^()]*\))+)?:",
        re.MULTILINE,
    )
    DECORATOR_RE = re.compile(r"@(\w+)")

    # Simple, single-occurrence patterns: (regex, VyperVulnerability, severity)
    SIMPLE_PATTERNS = [
        (re.compile(r"\bselfdestruct\s*\("), VyperVulnerability.SELFDESTRUCT_USAGE, "High"),
        (
            re.compile(r"\btx\.origin\s*[!=]=|[!=]=\s*tx\.origin\b|\bassert\b[^\n]*\btx\.origin\b"),
            VyperVulnerability.TX_ORIGIN_AUTH,
            "Medium",
        ),
        (
            re.compile(r"\bunsafe_(add|sub|mul|div)\s*\("),
            VyperVulnerability.UNSAFE_ARITHMETIC,
            "Low",
        ),
    ]
    RAW_CALL_RE = re.compile(r"\braw_call\s*\(")
    CLONE_RE = re.compile(r"\b(?:create_forwarder_to|create_minimal_proxy_to)\s*\(")
    CLONE_INIT_RE = re.compile(r"\.\s*(?:init|initialize)\w*\s*\(")
    TOP_LEVEL_RE = re.compile(r"^(?:@|def\b)", re.MULTILINE)

    EXTERNAL_CALL_RE = re.compile(
        r"\braw_call\s*\(|\bsend\s*\(|\bextcall\b|" r"\b\w+\s*\(\s*\w+\s*\)\.\w+\s*\("
    )
    # `Iface(addr).method(` - the method name is what tells a STATICCALL from a call.
    INTERFACE_CALL_RE = re.compile(r"\b\w+\s*\(\s*\w+\s*\)\.(\w+)\s*\(")
    # Interface methods declared view/pure (`constant` before 0.2) compile to STATICCALL,
    # which cannot change state, so they are no reentry point. Plus the ERC20 views of the
    # built-in `vyper.interfaces.ERC20` / `ERC20Detailed`, which are imported, not declared.
    VIEW_METHOD_RE = re.compile(
        r"^[ \t]+def[ \t]+(\w+)[ \t]*\((?:[^()]|\([^()]*\))*\)[^:\n]*:[ \t]*(?:view|pure|constant)\b",
        re.MULTILINE,
    )
    ERC20_VIEWS = frozenset({"balanceOf", "allowance", "totalSupply", "name", "symbol", "decimals"})
    # One-shot initializer: `assert self.activation == 0`, `assert not self.initialized`.
    # Same role as Solidity's `require(!initialized)` / `initializer` modifier.
    ONE_TIME_INIT_RE = re.compile(
        r"^\s*assert\s+(?:not\s+self\.\w+|self\.\w+\s*==\s*(?:0|False|empty\([^)]*\)))",
        re.MULTILINE,
    )
    STATE_WRITE_RE = re.compile(r"\bself\.\w+\s*(\[[^\]]*\])?\s*(\+=|-=|\*=|/=|=[^=])")
    # A caller guard: msg.sender compared or tested for membership in an assert/if, a
    # `self.is_admin[msg.sender]`-style flag used as a boolean, or a module helper such
    # as snekmate's `ownable._check_owner()`. A numeric check on a mapping keyed by
    # msg.sender (`assert self.balances[msg.sender] >= x`) is a balance check, not a guard.
    ACCESS_CHECK_RE = re.compile(
        r"\b(?:assert|if)\b[^\n]*(?:msg\.sender\s*(?:[!=]=|(?:not\s+)?in\b)|[!=]=\s*msg\.sender\b"
        r"|\[\s*msg\.sender\s*\]\s*(?:$|[,:#]|\band\b|\bor\b))"
        r"|^\s*\w+\._?(?:check|only|assert)\w*\s*\(",
        re.MULTILINE,
    )
    # What makes an unguarded function a bug: it reconfigures the contract (owner, admin,
    # fees, oracle, pause/kill switch, implementation) or can destroy or drain it. Every
    # other state write - transfer, exchange, add_liquidity, deposit - is meant to be
    # public. Same criterion as miesc/detectors/access_guards.py for Solidity.
    PRIVILEGED_WRITE_RE = re.compile(
        r"\bself\.(?:future_|pending_|suggested_|new_)?(?:owner|admin|governance|guardian"
        r"|manager|operator|minter|implementation|paused|is_paused|is_killed|killed|fee"
        r"|admin_fee|oracle|controller|treasury)\b\s*(?:\[[^\]]*\])?\s*=[^=]"
        r"|\bselfdestruct\s*\(|\bis_delegate_call\s*=\s*True|\bself\.balance\b"
    )
    # Vyper 0.4: `# pragma nonreentrancy on` guards every external function of the module.
    NONREENTRANCY_PRAGMA_RE = re.compile(r"^#\s*pragma\s+nonreentrancy\s+on\b", re.MULTILINE)

    def detect_simple_patterns(self, source_code: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect single-statement vulnerability patterns in the code (not in comments)."""
        code = strip_comments(source_code)
        lines = code.splitlines()
        hits: List[tuple] = []
        for pattern, vuln_type, severity in self.SIMPLE_PATTERNS:
            for match in pattern.finditer(code):
                hits.append((match.start(), vuln_type, severity))
        hits += [
            (pos, VyperVulnerability.DANGEROUS_DELEGATECALL, "High")
            for pos in self._delegatecalls(code)
        ]
        hits += [
            (pos, VyperVulnerability.UNSAFE_PROXY_CREATION, "Medium")
            for pos in self._uninitialized_clones(code)
        ]
        findings: List[Dict[str, Any]] = []
        for pos, vuln_type, severity in hits:
            line = code[:pos].count("\n") + 1
            text = lines[line - 1] if line <= len(lines) else ""
            # `msg.sender == tx.origin` only rejects contract callers (Slither's
            # tx-origin rule excludes it too); it authorizes nobody.
            if vuln_type == VyperVulnerability.TX_ORIGIN_AUTH and "msg.sender" in text:
                continue
            findings.append(
                {
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "line": line,
                    "file": file_path,
                    "code": text.strip(),
                }
            )
        return findings

    def _delegatecalls(self, code: str) -> List[int]:
        """`raw_call(target, ..., is_delegate_call=True)` whose target is not `self`."""
        hits = []
        for match in self.RAW_CALL_RE.finditer(code):
            depth, end = 1, match.end()
            while end < len(code) and depth:
                depth += {"(": 1, ")": -1}.get(code[end], 0)
                end += 1
            args = code[match.end() : end - 1]
            if re.search(r"\bis_delegate_call\s*=\s*True\b", args) and not re.match(
                r"\s*self\s*,", args
            ):
                hits.append(match.start())
        return hits

    def _uninitialized_clones(self, code: str) -> List[int]:
        """A forwarder/minimal proxy with no `.init*()`/`.initialize*()` later in the function."""
        hits = []
        for match in self.CLONE_RE.finditer(code):
            next_def = self.TOP_LEVEL_RE.search(code, match.end())
            rest = code[match.end() : next_def.start() if next_def else len(code)]
            if not self.CLONE_INIT_RE.search(rest):
                hits.append(match.start())
        return hits

    def extract_version(self, source_code: str) -> Optional[str]:
        """The version spec as written (``0.3.7``, ``^0.3.0``, ``>=0.3.0 <0.4.0``)."""
        match = self.VERSION_RE.search(source_code)
        if not match:
            return None
        return match.group(1).strip()

    def version_line(self, source_code: str) -> int:
        match = self.VERSION_RE.search(source_code)
        return source_code[: match.start()].count("\n") + 1 if match else 1

    def extract_functions(self, source_code: str, file_path: str) -> List[VyperFunction]:
        """Extract top-level (0-indent) function definitions with their decorators."""
        functions: List[VyperFunction] = []
        source_code = strip_comments(source_code)
        lines = source_code.split("\n")

        for match in self.FUNCTION_RE.finditer(source_code):
            name = match.group("name")
            decorators = self.DECORATOR_RE.findall(match.group("decorators") or "")
            # Line the `def` keyword itself is on (i.e. after the decorator lines).
            def_offset = match.start(0) + len(match.group("decorators") or "")
            def_line = source_code[:def_offset].count("\n") + 1
            signature_end_line = source_code[: match.end()].count("\n") + 1

            body = self._extract_body(lines, def_line, signature_end_line)

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

    def _extract_body(self, lines: List[str], def_line: int, signature_end_line: int) -> str:
        """Collect the lines after the signature indented deeper than the `def`.

        A multi-line signature closes with `):` or `) -> T:` at the `def`'s column, so
        the body starts after the signature's last line, not after the `def` line.
        """
        if def_line < 1 or def_line > len(lines):
            return ""
        def_indent = len(lines[def_line - 1]) - len(lines[def_line - 1].lstrip())
        body_lines: List[str] = []
        for line in lines[signature_end_line:]:
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
    the `vyper` compiler being installed (a contract's `@version` pragma very
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
            finding = self._simple_match_to_finding(match)
            if finding is not None:
                findings.append(finding)

        if SecurityProperty.ACCESS_CONTROL in properties:
            findings.extend(self._check_missing_access_control(contract))

        return findings

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
                "create_forwarder_to/create_minimal_proxy_to deploy an uninitialized clone — if "
                "initialization isn't atomic with deployment, an attacker can front-run it and "
                "take ownership of the clone. (create_from_blueprint is not reported: the "
                "blueprint receives its constructor arguments and initializes in the deploy.)",
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
        spec = contract.compiler_version
        if not spec or "@nonreentrant" not in strip_comments(contract.source_code or ""):
            return []
        admitted = sorted(
            v for v in BROKEN_REENTRANCY_LOCK_VERSIONS if version_spec_admits(spec, v)
        )
        if not admitted:
            return []
        location = Location(
            file=contract.source_path,
            line=self.pattern_detector.version_line(contract.source_code or ""),
        )
        terms = version_spec_terms(spec)
        if not (len(terms) == 1 and terms[0][0] in ("", "=", "==")):
            # A range compiles with whatever version the build picked; only a pin
            # proves the broken lock is there.
            return [
                self.normalize_finding(
                    vuln_type=VyperVulnerability.BROKEN_REENTRANCY_LOCK_COMPILER.value,
                    severity="Low",
                    message=(
                        f"Version range '{spec}' admits Vyper {', '.join(admitted)}, which "
                        "shipped a broken @nonreentrant lock; confirm the compiled version"
                    ),
                    location=location,
                    description=(
                        "The pragma is a range, so the compiled version is not known from the "
                        "source. Vyper 0.2.15, 0.2.16 and 0.3.0 shipped a broken @nonreentrant "
                        "lock (GHSA-5824-cm3x-3c38, the Curve Finance incident)."
                    ),
                    recommendation=(
                        "Check the deployed bytecode's compiler version, or pin a patched "
                        "version in the pragma."
                    ),
                    confidence=0.4,
                )
            ]

        return [
            self.normalize_finding(
                vuln_type=VyperVulnerability.BROKEN_REENTRANCY_LOCK_COMPILER.value,
                severity="Critical",
                message=(
                    f"@nonreentrant used under Vyper {spec}, a compiler "
                    "version with a documented broken reentrancy lock"
                ),
                location=location,
                description=(
                    "Vyper compiler versions 0.2.15, 0.2.16 and 0.3.0 shipped a broken "
                    "@nonreentrant lock implementation — the root cause of the Curve Finance "
                    "incident (2023-07-30, ~$70M across multiple pools). Contracts compiled "
                    "with one of these versions have a reentrancy guard that does not "
                    "actually block reentrancy."
                ),
                recommendation=(
                    "Recompile with a patched Vyper version and redeploy, or verify against "
                    "the official advisory (GHSA-5824-cm3x-3c38) whether this exact version "
                    "and pattern combination is affected."
                ),
                confidence=0.6,
            )
        ]

    def _check_missing_reentrancy_guard(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        source = contract.source_code or ""
        detector = self.pattern_detector
        if detector.NONREENTRANCY_PRAGMA_RE.search(source):
            return findings
        views = detector.ERC20_VIEWS | set(detector.VIEW_METHOD_RE.findall(strip_comments(source)))
        bodies_by_name = {f.name: f.body_source or "" for f in contract.functions}
        for func in contract.functions:
            if func.visibility != Visibility.EXTERNAL or func.name == "__init__":
                continue
            if not func.calls_external or not func.writes_state:
                continue
            if func.has_reentrancy_guard:
                continue
            body = func.body_source or ""
            # A reentrant call arrives with msg.sender = the called contract, which an
            # owner-only function rejects.
            if self._caller_restricted(body, bodies_by_name):
                continue
            # Checks-effects-interactions: reentering is harmless when no state write
            # follows the first state-changing external call.
            first_call = next(
                (
                    m
                    for m in detector.EXTERNAL_CALL_RE.finditer(body)
                    if not self._is_view_call(m, views)
                ),
                None,
            )
            if not first_call or not detector.STATE_WRITE_RE.search(body, first_call.end()):
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

    def _is_view_call(self, match: "re.Match[str]", views: AbstractSet[str]) -> bool:
        method = self.pattern_detector.INTERFACE_CALL_RE.match(match.group(0))
        return method is not None and method.group(1) in views

    def _caller_restricted(self, body: str, bodies_by_name: Dict[str, str]) -> bool:
        # Vyper has no modifiers, so `self._check_admin()`-style internal helpers are the
        # idiomatic way to share an access check across functions — look one call deep
        # before flagging, or every such contract is 100% false positives.
        check = self.pattern_detector.ACCESS_CHECK_RE
        return bool(check.search(body)) or any(
            check.search(bodies_by_name.get(callee, ""))
            for callee in re.findall(r"self\.(\w+)\s*\(", body)
        )

    def _check_missing_access_control(self, contract: AbstractContract) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        bodies_by_name = {f.name: f.body_source or "" for f in contract.functions}
        for func in contract.functions:
            if func.visibility != Visibility.EXTERNAL:
                continue
            if not func.writes_state:
                continue
            if func.name in ("__init__",):
                continue
            body = func.body_source or ""
            if not self.pattern_detector.PRIVILEGED_WRITE_RE.search(body):
                continue
            if self._caller_restricted(body, bodies_by_name):
                continue
            if func.name.startswith("init") and self.pattern_detector.ONE_TIME_INIT_RE.search(body):
                continue
            findings.append(
                self.normalize_finding(
                    vuln_type=VyperVulnerability.MISSING_ACCESS_CONTROL.value,
                    severity="Medium",
                    message=f"'{func.name}' is external, performs a privileged operation "
                    "(owner/admin/fee/oracle/pause/kill, selfdestruct, delegatecall or the "
                    "whole balance) and has no visible msg.sender check",
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
# VyperAnalyzer the same way as any Solidity tool (before this, `.vy` files
# had no route into the evaluate/scan tool-execution path; `miesc analyze`
# invoked VyperAnalyzer directly instead).
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
        # apply here. Never read a file it does not understand (Solidity on the
        # ML path, which does not consult can_analyze).
        if not self.can_analyze(contract_path):
            return {
                "tool": self.name,
                "status": "skipped",
                "reason": "unsupported_source",
                "findings": [],
                "error": f"{self.name} only analyzes .vy files",
            }
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
]
