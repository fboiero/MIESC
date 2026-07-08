"""
PoC Generator - Automated Proof-of-Concept Exploit Generation
==============================================================

Generates Foundry test templates from vulnerability findings.
Each template is a working test that demonstrates the exploit.

Usage:
    generator = PoCGenerator()
    poc = generator.generate(finding, target_contract="Token.sol")
    poc.save("test/exploits/")
    poc.run()  # forge test --match-contract PoCTest

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

import logging
import re
import string
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

_FILENAME_SAFE_CHARS = f"-_() {string.ascii_letters}{string.digits}"
_SOLIDITY_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SOLIDITY_LITERAL_SAFE_RE = re.compile(r"^[A-Za-z0-9_ .()+\-*/]+$")
_ERROR_TEXT_LIMIT = 500
_TRACE_TEXT_LIMIT = 20_000


def _safe_filename_part(value: Any, default: str = "template") -> str:
    """Return a bounded filename segment without path separators."""
    text = value.strip() if isinstance(value, str) else ""
    if text and any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return default
    safe = "".join(ch for ch in text if ch in _FILENAME_SAFE_CHARS).strip()
    if text and not safe:
        return default
    return safe[:80] or default


def _normalize_output_text(value: Any) -> str:
    """Normalize subprocess output fields without leaking container reprs."""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return ""


def _safe_error_text(value: Any) -> str:
    """Return bounded printable error text without trusting object reprs."""
    try:
        text = str(value)
    except Exception:
        return f"<unprintable:{type(value).__name__}>"
    if not text:
        return f"<empty:{type(value).__name__}>"
    safe_chars = []
    for char in text[:_ERROR_TEXT_LIMIT]:
        ordinal = ord(char)
        if char == "\n":
            safe_chars.append("\\n")
        elif char == "\r":
            safe_chars.append("\\r")
        elif char == "\t":
            safe_chars.append("\\t")
        elif ordinal < 32 or ordinal == 127:
            safe_chars.append(f"\\x{ordinal:02x}")
        else:
            safe_chars.append(char)
    safe_text = "".join(safe_chars)
    if len(text) > _ERROR_TEXT_LIMIT:
        safe_text += "...<truncated>"
    return safe_text


def _safe_optional_text(value: Any) -> Optional[str]:
    """Return optional text fields only when the template supplied text."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None
    return text


def _safe_text_list(value: Any) -> List[str]:
    """Return only string list entries from template metadata."""
    if not isinstance(value, list):
        return []
    return [
        text
        for item in value
        if isinstance(item, str)
        and (text := item.strip())
        and not any(ord(ch) < 32 or ord(ch) == 127 for ch in text)
    ]


def _safe_import_path(value: Any) -> bool:
    """Accept only local/package-style Solidity import paths."""
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text or "\\" in text or ".." in text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return False
    return ":" not in text and not text.startswith("/")


def _safe_contract_text(value: Any) -> str:
    """Return a contract identifier only from plain text or path objects."""
    if isinstance(value, (str, Path)):
        text = str(value).strip()
        if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
            return ""
        return text
    return ""


def _safe_solidity_identifier(value: Any) -> Optional[str]:
    """Return a Solidity identifier suitable for generated test names/functions."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None
    return text if _SOLIDITY_IDENTIFIER_RE.fullmatch(text) else None


def _safe_solidity_literal(value: Any, default: str) -> str:
    """Return a conservative Solidity literal/expression used in template slots."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return default
    if not isinstance(value, str):
        return default
    text = value.strip()
    if (
        not text
        or len(text) > 200
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in text)
        or not _SOLIDITY_LITERAL_SAFE_RE.fullmatch(text)
    ):
        return default
    return text


def _safe_isoformat(value: Any) -> str:
    """Return ISO timestamps only from datetime-like values."""
    try:
        text = value.isoformat() if hasattr(value, "isoformat") else ""
    except (AttributeError, TypeError, ValueError):
        return ""
    if not isinstance(text, str):
        text = str(text)
    text = text.strip()
    if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return ""
    return text


def _safe_vulnerability_type_value(value: Any) -> str:
    """Return vulnerability type values only from the expected enum shape."""
    raw_value = getattr(value, "value", None)
    if not isinstance(raw_value, str):
        return "unknown"
    text = raw_value.strip()
    if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return "unknown"
    return text


class VulnerabilityType(Enum):
    """Supported vulnerability types for PoC generation."""

    REENTRANCY = "reentrancy"
    FLASH_LOAN = "flash_loan"
    ORACLE_MANIPULATION = "oracle_manipulation"
    ACCESS_CONTROL = "access_control"
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    UNCHECKED_CALL = "unchecked_call"
    FRONT_RUNNING = "front_running"
    DENIAL_OF_SERVICE = "dos"
    TIMESTAMP_DEPENDENCE = "timestamp_dependence"
    TX_ORIGIN = "tx_origin"
    SELFDESTRUCT = "selfdestruct"
    DELEGATECALL = "delegatecall"
    SIGNATURE_REPLAY = "signature_replay"
    ERC4626_INFLATION = "erc4626_inflation"
    PRICE_MANIPULATION = "price_manipulation"


@dataclass
class GenerationOptions:
    """Options for PoC generation."""

    include_setup: bool = True
    include_comments: bool = True
    include_console_logs: bool = True
    attacker_balance: str = "100 ether"
    victim_balance: str = "10 ether"
    fork_block: Optional[int] = None
    fork_url: Optional[str] = None
    custom_imports: List[str] = field(default_factory=list)
    custom_setup_code: Optional[str] = None


@dataclass
class PoCTemplate:
    """A generated PoC template."""

    name: str
    vulnerability_type: VulnerabilityType
    solidity_code: str
    target_contract: str
    target_function: Optional[str]
    finding_id: Optional[str] = None
    description: str = ""
    prerequisites: List[str] = field(default_factory=list)
    expected_outcome: str = ""
    created_at: datetime = field(default_factory=datetime.now)

    def save(self, output_dir: Union[str, Path]) -> Path:
        """
        Save PoC to file.

        Args:
            output_dir: Directory to save the PoC

        Returns:
            Path to saved file
        """
        if not isinstance(output_dir, (str, Path)):
            raise ValueError("Malformed PoC output directory")
        if isinstance(output_dir, str) and not output_dir.strip():
            raise ValueError("Malformed PoC output directory")
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        filename = (
            f"PoC_{_safe_filename_part(_safe_vulnerability_type_value(self.vulnerability_type), 'unknown')}_"
            f"{_safe_filename_part(self.name)}.t.sol"
        )
        filepath = output_path / filename

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(_normalize_output_text(self.solidity_code))

        logger.info(f"PoC saved to {filepath}")
        return filepath

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name if isinstance(self.name, str) else "template",
            "vulnerability_type": _safe_vulnerability_type_value(self.vulnerability_type),
            "target_contract": self.target_contract if isinstance(self.target_contract, str) else "",
            "target_function": _safe_optional_text(self.target_function),
            "finding_id": _safe_optional_text(self.finding_id),
            "description": self.description if isinstance(self.description, str) else "",
            "prerequisites": _safe_text_list(self.prerequisites),
            "expected_outcome": self.expected_outcome if isinstance(self.expected_outcome, str) else "",
            "created_at": _safe_isoformat(self.created_at),
        }


@dataclass
class PoCResult:
    """Result of running a PoC."""

    success: bool
    output: str
    gas_used: Optional[int] = None
    execution_time_ms: float = 0
    error: Optional[str] = None
    traces: Optional[str] = None


class PoCGenerator:
    """
    Generates Proof-of-Concept exploits from vulnerability findings.

    Supports multiple vulnerability types with Foundry test templates.
    """

    # Template directory
    TEMPLATES_DIR = Path(__file__).parent / "templates"

    # Vulnerability type to template mapping
    TEMPLATE_MAP = {
        VulnerabilityType.REENTRANCY: "reentrancy.t.sol",
        VulnerabilityType.FLASH_LOAN: "flash_loan.t.sol",
        VulnerabilityType.ORACLE_MANIPULATION: "oracle_manipulation.t.sol",
        VulnerabilityType.ACCESS_CONTROL: "access_control.t.sol",
        VulnerabilityType.INTEGER_OVERFLOW: "arithmetic.t.sol",
        VulnerabilityType.INTEGER_UNDERFLOW: "arithmetic.t.sol",
        VulnerabilityType.UNCHECKED_CALL: "unchecked_call.t.sol",
        VulnerabilityType.TX_ORIGIN: "tx_origin.t.sol",
        VulnerabilityType.SELFDESTRUCT: "selfdestruct.t.sol",
        VulnerabilityType.DELEGATECALL: "delegatecall.t.sol",
    }

    # Type aliases for finding type strings
    TYPE_ALIASES = {
        "reentrancy": VulnerabilityType.REENTRANCY,
        "reentrant": VulnerabilityType.REENTRANCY,
        "re-entrancy": VulnerabilityType.REENTRANCY,
        "flash-loan": VulnerabilityType.FLASH_LOAN,
        "flash_loan": VulnerabilityType.FLASH_LOAN,
        "flashloan": VulnerabilityType.FLASH_LOAN,
        "oracle": VulnerabilityType.ORACLE_MANIPULATION,
        "oracle-manipulation": VulnerabilityType.ORACLE_MANIPULATION,
        "price-manipulation": VulnerabilityType.PRICE_MANIPULATION,
        "access-control": VulnerabilityType.ACCESS_CONTROL,
        "access_control": VulnerabilityType.ACCESS_CONTROL,
        "authorization": VulnerabilityType.ACCESS_CONTROL,
        "overflow": VulnerabilityType.INTEGER_OVERFLOW,
        "integer-overflow": VulnerabilityType.INTEGER_OVERFLOW,
        "underflow": VulnerabilityType.INTEGER_UNDERFLOW,
        "integer-underflow": VulnerabilityType.INTEGER_UNDERFLOW,
        "arithmetic": VulnerabilityType.INTEGER_OVERFLOW,
        "unchecked-call": VulnerabilityType.UNCHECKED_CALL,
        "unchecked_call": VulnerabilityType.UNCHECKED_CALL,
        "tx-origin": VulnerabilityType.TX_ORIGIN,
        "tx_origin": VulnerabilityType.TX_ORIGIN,
        "selfdestruct": VulnerabilityType.SELFDESTRUCT,
        "self-destruct": VulnerabilityType.SELFDESTRUCT,
        "delegatecall": VulnerabilityType.DELEGATECALL,
        "delegate-call": VulnerabilityType.DELEGATECALL,
        "front-running": VulnerabilityType.FRONT_RUNNING,
        "frontrunning": VulnerabilityType.FRONT_RUNNING,
        "dos": VulnerabilityType.DENIAL_OF_SERVICE,
        "denial-of-service": VulnerabilityType.DENIAL_OF_SERVICE,
        "timestamp": VulnerabilityType.TIMESTAMP_DEPENDENCE,
        "block-timestamp": VulnerabilityType.TIMESTAMP_DEPENDENCE,
        "signature-replay": VulnerabilityType.SIGNATURE_REPLAY,
        "replay": VulnerabilityType.SIGNATURE_REPLAY,
        "erc4626": VulnerabilityType.ERC4626_INFLATION,
        "inflation": VulnerabilityType.ERC4626_INFLATION,
        # Aderyn-specific finding types
        "selfdestruct-identifier": VulnerabilityType.SELFDESTRUCT,
        "selfdestruct_identifier": VulnerabilityType.SELFDESTRUCT,
        "uninitialized-state-variable": VulnerabilityType.ACCESS_CONTROL,
        "uninitialized_state_variable": VulnerabilityType.ACCESS_CONTROL,
        "unchecked-send": VulnerabilityType.UNCHECKED_CALL,
        "unchecked_send": VulnerabilityType.UNCHECKED_CALL,
        "weak-randomness": VulnerabilityType.TIMESTAMP_DEPENDENCE,
        "weak_randomness": VulnerabilityType.TIMESTAMP_DEPENDENCE,
        "tx-origin-used-for-auth": VulnerabilityType.TX_ORIGIN,
        "tx_origin_used_for_auth": VulnerabilityType.TX_ORIGIN,
        "unsafe-erc20-functions": VulnerabilityType.UNCHECKED_CALL,
        "unsafe_erc20_functions": VulnerabilityType.UNCHECKED_CALL,
    }

    def __init__(
        self,
        templates_dir: Optional[Path] = None,
        options: Optional[GenerationOptions] = None,
    ):
        """
        Initialize PoC generator.

        Args:
            templates_dir: Custom templates directory
            options: Generation options
        """
        if templates_dir is None:
            self.templates_dir = self.TEMPLATES_DIR
        elif isinstance(templates_dir, (str, Path)) and str(templates_dir).strip():
            self.templates_dir = Path(templates_dir)
        else:
            logger.warning("Ignoring malformed templates_dir for PoC generator")
            self.templates_dir = self.TEMPLATES_DIR

        self.options = options if isinstance(options, GenerationOptions) else GenerationOptions()
        if options is not None and not isinstance(options, GenerationOptions):
            logger.warning("Ignoring malformed PoC generation options")
        self._template_cache: Dict[str, str] = {}

        logger.debug(f"PoCGenerator initialized (templates_dir={self.templates_dir})")

    def generate(
        self,
        finding: Dict[str, Any],
        target_contract: str,
        options: Optional[GenerationOptions] = None,
    ) -> PoCTemplate:
        """
        Generate a PoC from a vulnerability finding.

        Args:
            finding: Vulnerability finding dict with type, severity, location, etc.
            target_contract: Name of the target contract
            options: Optional generation options override

        Returns:
            PoCTemplate with generated Solidity test code
        """
        if not isinstance(finding, dict):
            raise ValueError("Malformed vulnerability finding")
        opts = self._options_state(options)

        # Determine vulnerability type
        vuln_type = self._resolve_vulnerability_type(finding)

        # Extract finding details
        target_function = self._extract_function_name(finding)
        target_contract_text = _safe_contract_text(target_contract)
        description = self._finding_text_field(finding, "description", "")
        severity = self._finding_text_field(finding, "severity", "medium")
        finding_id = self._finding_text_field(finding, "id") or self._finding_text_field(
            finding, "rule"
        )

        # Generate PoC name
        poc_name = self._generate_poc_name(target_contract, vuln_type, target_function)

        # Load and customize template
        template_code = self._load_template(vuln_type)

        # Apply customizations
        solidity_code = self._customize_template(
            template_code,
            vuln_type=vuln_type,
            target_contract=target_contract,
            target_function=target_function,
            finding=finding,
            options=opts,
        )

        poc = PoCTemplate(
            name=poc_name,
            vulnerability_type=vuln_type,
            solidity_code=solidity_code,
            target_contract=target_contract_text,
            target_function=target_function,
            finding_id=finding_id,
            description=description,
            prerequisites=self._get_prerequisites(vuln_type),
            expected_outcome=self._get_expected_outcome(vuln_type, severity),
        )

        logger.info(f"Generated PoC: {poc.name} for {vuln_type.value}")
        return poc

    def generate_batch(
        self,
        findings: Any,
        target_contract: str,
        options: Optional[GenerationOptions] = None,
    ) -> List[PoCTemplate]:
        """
        Generate PoCs for multiple findings.

        Args:
            findings: List of vulnerability findings
            target_contract: Target contract name
            options: Generation options

        Returns:
            List of generated PoCTemplates
        """
        pocs = []
        if not isinstance(findings, list):
            logger.warning("Skipping malformed findings container in PoC batch")
            return pocs

        for finding in findings:
            if not isinstance(finding, dict):
                logger.warning("Skipping malformed finding entry in PoC batch")
                continue

            try:
                poc = self.generate(finding, target_contract, options)
                pocs.append(poc)
            except (AttributeError, KeyError, TypeError, ValueError) as e:
                logger.warning("Failed to generate PoC for finding: %s", _safe_error_text(e))

        return pocs

    def run(
        self,
        poc: PoCTemplate,
        project_dir: Union[str, Path],
        verbose: bool = True,
    ) -> PoCResult:
        """
        Run a PoC using Foundry.

        Args:
            poc: The PoC template to run
            project_dir: Foundry project directory
            verbose: Show detailed output

        Returns:
            PoCResult with execution results
        """
        import time

        start_time = time.time()
        verbose = verbose is True
        if not isinstance(project_dir, (str, Path)):
            return PoCResult(
                success=False,
                output="",
                execution_time_ms=0,
                error="Malformed project directory",
            )
        if isinstance(project_dir, str) and not project_dir.strip():
            return PoCResult(
                success=False,
                output="",
                execution_time_ms=0,
                error="Malformed project directory",
            )
        project_path = Path(project_dir)
        if not isinstance(poc, PoCTemplate):
            return PoCResult(
                success=False,
                output="",
                execution_time_ms=0,
                error="Malformed PoC template",
            )

        # Save PoC to project
        test_dir = project_path / "test" / "exploits"
        poc_path = poc.save(test_dir)

        try:
            # Run forge test
            cmd = [
                "forge",
                "test",
                "--match-path",
                str(poc_path),
                "-vvv",  # Verbose output with traces
            ]

            if verbose:
                print(f"Running: {' '.join(cmd)}")  # noqa: T201

            result = subprocess.run(
                cmd,
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=300,
            )

            execution_time = (time.time() - start_time) * 1000

            # Parse output
            returncode = result.returncode if isinstance(result.returncode, int) else 1
            success = returncode == 0
            stdout = _normalize_output_text(getattr(result, "stdout", ""))
            stderr = _normalize_output_text(getattr(result, "stderr", ""))
            output = stdout + stderr

            # Extract gas used
            gas_used = self._extract_gas_from_output(output)

            return PoCResult(
                success=success,
                output=output,
                gas_used=gas_used,
                execution_time_ms=execution_time,
                error=None if success else stderr,
                traces=self._extract_traces(output),
            )

        except subprocess.TimeoutExpired:
            execution_time = max((time.time() - start_time) * 1000, 0)
            return PoCResult(
                success=False,
                output="",
                execution_time_ms=execution_time,
                error="PoC execution timed out",
            )
        except FileNotFoundError:
            return PoCResult(
                success=False,
                output="",
                execution_time_ms=0,
                error="Foundry (forge) not installed",
            )
        except (OSError, RuntimeError, subprocess.SubprocessError) as e:
            execution_time = max((time.time() - start_time) * 1000, 0)
            return PoCResult(
                success=False,
                output="",
                execution_time_ms=execution_time,
                error=_safe_error_text(e),
            )

    def _options_state(self, options: Optional[GenerationOptions] = None) -> GenerationOptions:
        """Return valid generation options, resetting malformed in-memory state."""
        if isinstance(options, GenerationOptions):
            return options
        if options is not None:
            logger.warning("Ignoring malformed PoC generation options override")
            return GenerationOptions()
        if isinstance(self.options, GenerationOptions):
            return self.options
        logger.warning("Resetting malformed PoC generator options state")
        self.options = GenerationOptions()
        return self.options

    def _template_cache_state(self) -> Dict[str, str]:
        """Return usable template cache state."""
        if isinstance(self._template_cache, dict):
            return self._template_cache
        logger.warning("Resetting malformed PoC template cache state")
        self._template_cache = {}
        return self._template_cache

    def _resolve_vulnerability_type(self, finding: Dict[str, Any]) -> VulnerabilityType:
        """Resolve finding type to VulnerabilityType enum."""
        if not isinstance(finding, dict):
            logger.warning("Malformed finding type container, defaulting to REENTRANCY")
            return VulnerabilityType.REENTRANCY
        raw_finding_type = finding.get("type", "")
        if isinstance(raw_finding_type, bytes):
            try:
                raw_finding_type = raw_finding_type.decode("utf-8", errors="replace")
            except Exception:
                raw_finding_type = ""
        finding_type = raw_finding_type.lower().strip() if isinstance(raw_finding_type, str) else ""
        if not finding_type or len(finding_type) > 120 or any(
            ord(ch) < 32 or ord(ch) == 127 for ch in finding_type
        ):
            finding_type = ""

        # Try direct alias lookup
        if finding_type in self.TYPE_ALIASES:
            return self.TYPE_ALIASES[finding_type]

        # Try partial matching
        for alias, vuln_type in self.TYPE_ALIASES.items():
            if alias in finding_type or finding_type in alias:
                return vuln_type

        # Default to reentrancy as most common
        logger.warning(f"Unknown vulnerability type: {finding_type}, defaulting to REENTRANCY")
        return VulnerabilityType.REENTRANCY

    def _finding_text_field(
        self, finding: Dict[str, Any], key: str, default: Optional[str] = None
    ) -> Optional[str]:
        """Return string finding fields only; ignore malformed object/list shapes."""
        if not isinstance(finding, dict) or not isinstance(key, str):
            return default
        value = finding.get(key, default)
        if isinstance(value, str):
            text = value.strip()
            if text and not any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
                return text
        return default

    def _option_text_field(self, options: GenerationOptions, key: str, default: str) -> str:
        """Return string option fields only; ignore malformed object/list shapes."""
        if not isinstance(key, str):
            return default
        value = getattr(options, key, default)
        if key in {"attacker_balance", "victim_balance"}:
            return _safe_solidity_literal(value, default)
        return _safe_optional_text(value) or default

    def _custom_import_lines(self, options: GenerationOptions) -> str:
        """Build custom import statements from a list of string paths."""
        imports = getattr(options, "custom_imports", [])
        if not isinstance(imports, list):
            logger.warning("Skipping malformed custom imports container in PoC options")
            return ""

        import_paths = []
        seen = set()
        for imp in imports:
            if not _safe_import_path(imp):
                continue
            normalized = imp.strip()
            if len(normalized) > 120 or normalized in seen:
                continue
            seen.add(normalized)
            import_paths.append(normalized)
        if len(import_paths) != len(imports):
            logger.warning("Skipping malformed custom import entry in PoC options")

        return "\n".join(f'import "{imp}";' for imp in import_paths)

    def _fork_config(self, options: GenerationOptions) -> str:
        """Build fork setup only from well-formed option fields."""
        fork_url = getattr(options, "fork_url", None)
        fork_block = getattr(options, "fork_block", None)

        if fork_url is None or fork_block is None:
            return ""

        if (
            not isinstance(fork_url, str)
            or not fork_url.strip()
            or len(fork_url.strip()) > 2048
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in fork_url)
            or not isinstance(fork_block, int)
            or isinstance(fork_block, bool)
            or fork_block <= 0
        ):
            logger.warning("Skipping malformed fork configuration in PoC options")
            return ""

        return f"""
        // Fork mainnet
        vm.createSelectFork("{fork_url.strip()}", {fork_block});
"""

    def _extract_function_name(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract target function name from finding."""
        if not isinstance(finding, dict):
            return None
        location = finding.get("location", {})

        if isinstance(location, dict):
            function_name = location.get("function") or location.get("func")
            return _safe_solidity_identifier(function_name)
        elif isinstance(location, str):
            if len(location) > 2000 or any(ord(ch) < 32 or ord(ch) == 127 for ch in location):
                return None
            # Try to parse function from string
            match = re.search(r"function\s+(\w+)", location)
            if match:
                return _safe_solidity_identifier(match.group(1))

        return None

    def _generate_poc_name(
        self,
        target_contract: str,
        vuln_type: VulnerabilityType,
        target_function: Optional[str],
    ) -> str:
        """Generate a descriptive PoC name."""
        contract_name = _safe_filename_part(
            Path(target_contract).stem if isinstance(target_contract, (str, Path)) else "",
            "contract",
        )
        type_name = _safe_filename_part(
            _safe_vulnerability_type_value(vuln_type).replace("_", ""),
            "unknown",
        )
        function_name = _safe_filename_part(target_function, "") if target_function else ""

        if function_name:
            generated_name = f"{contract_name[:40]}_{function_name[:40]}_{type_name}"
        else:
            generated_name = f"{contract_name[:40]}_{type_name}"
        return generated_name[:120]

    def _load_template(self, vuln_type: VulnerabilityType) -> str:
        """Load template for vulnerability type."""
        template_name = self.TEMPLATE_MAP.get(vuln_type)

        if not template_name:
            # Use generic template
            template_name = "generic.t.sol"
        if not _safe_import_path(template_name) or not template_name.endswith(".sol"):
            logger.warning("Ignoring malformed PoC template name")
            template_name = "generic.t.sol"

        # Check cache
        template_cache = self._template_cache_state()
        cached_template = template_cache.get(template_name)
        if isinstance(cached_template, str):
            return cached_template

        # Load from file
        if not isinstance(self.templates_dir, Path):
            logger.warning("Resetting malformed PoC templates_dir state")
            self.templates_dir = self.TEMPLATES_DIR
        template_path = self.templates_dir / template_name

        if template_path.exists():
            with open(template_path, "r", encoding="utf-8") as f:
                template = f.read()
        else:
            # Use embedded default template
            template = self._get_default_template(vuln_type)

        template_cache[template_name] = template
        return template

    def _customize_template(
        self,
        template: str,
        vuln_type: VulnerabilityType,
        target_contract: str,
        target_function: Optional[str],
        finding: Dict[str, Any],
        options: GenerationOptions,
    ) -> str:
        """Customize template with finding-specific details."""
        if not isinstance(template, str):
            logger.warning("Using default template for malformed PoC template body")
            template = self._get_default_template(vuln_type)
        options = self._options_state(options)
        # Prepare replacements
        contract_name = (
            _safe_filename_part(Path(target_contract).stem, "contract")
            if isinstance(target_contract, (str, Path))
            else "contract"
        )
        vuln_type_value = _safe_vulnerability_type_value(vuln_type)
        test_name = f"test_exploit_{_safe_filename_part(vuln_type_value, 'unknown')}"
        function_name = _safe_filename_part(target_function, "") if target_function else ""

        replacements = {
            "{{CONTRACT_NAME}}": contract_name,
            "{{TARGET_CONTRACT}}": _safe_contract_text(target_contract),
            "{{TARGET_FUNCTION}}": function_name or "vulnerable",
            "{{TEST_NAME}}": test_name,
            "{{VULNERABILITY_TYPE}}": vuln_type_value,
            "{{ATTACKER_BALANCE}}": self._option_text_field(
                options, "attacker_balance", "100 ether"
            ),
            "{{VICTIM_BALANCE}}": self._option_text_field(options, "victim_balance", "10 ether"),
            "{{DESCRIPTION}}": self._finding_text_field(finding, "description", ""),
            "{{SEVERITY}}": self._finding_text_field(finding, "severity", "medium"),
            "{{TIMESTAMP}}": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }

        # Apply replacements
        result = template
        for placeholder, value in replacements.items():
            result = result.replace(placeholder, str(value))

        # Add custom imports
        import_lines = self._custom_import_lines(options)
        if import_lines:
            result = result.replace("// {{CUSTOM_IMPORTS}}", import_lines)

        # Add custom setup
        setup_code = self._option_text_field(options, "custom_setup_code", "")
        if setup_code:
            result = result.replace("// {{CUSTOM_SETUP}}", setup_code)

        # Add fork configuration
        fork_config = self._fork_config(options)
        if fork_config:
            result = result.replace("// {{FORK_CONFIG}}", fork_config)

        # Remove unused placeholders
        result = re.sub(r"// \{\{[A-Z_]+\}\}", "", result)

        return result

    def _get_default_template(self, vuln_type: VulnerabilityType) -> str:
        """Get embedded default template for vulnerability type."""
        # Basic Foundry test template
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title {{CONTRACT_NAME}} Exploit PoC
 * @notice Proof of Concept for {{VULNERABILITY_TYPE}} vulnerability
 * @dev Generated by MIESC PoC Generator
 * @custom:severity {{SEVERITY}}
 * @custom:generated {{TIMESTAMP}}
 */
contract {{CONTRACT_NAME}}ExploitTest is Test {
    // Target contract
    address public target;

    // Attacker
    address public attacker;

    // {{CUSTOM_IMPORTS}}

    function setUp() public {
        // Setup attacker
        attacker = makeAddr("attacker");
        vm.deal(attacker, {{ATTACKER_BALANCE}});

        // {{FORK_CONFIG}}

        // Deploy or connect to target
        // target = address(new {{CONTRACT_NAME}}());

        // {{CUSTOM_SETUP}}
    }

    function {{TEST_NAME}}() public {
        console.log("=== Starting {{VULNERABILITY_TYPE}} Exploit ===");
        console.log("Attacker:", attacker);
        console.log("Target:", target);

        uint256 attackerBalanceBefore = attacker.balance;

        vm.startPrank(attacker);

        // Bind the project-specific exploit path for {{VULNERABILITY_TYPE}}.
        // Typical entry point: target.{{TARGET_FUNCTION}}()

        vm.stopPrank();

        uint256 attackerBalanceAfter = attacker.balance;

        console.log("=== Exploit Complete ===");
        console.log("Balance before:", attackerBalanceBefore);
        console.log("Balance after:", attackerBalanceAfter);

        // Assert exploit success
        // assertGt(attackerBalanceAfter, attackerBalanceBefore, "Exploit should profit");
    }
}
"""

    def _get_prerequisites(self, vuln_type: VulnerabilityType) -> List[str]:
        """Get prerequisites for running PoC."""
        if not isinstance(vuln_type, VulnerabilityType):
            return _safe_text_list(
                ["Foundry installed (forge, cast, anvil)", "Target contract deployed or source available"]
            )
        prereqs = [
            "Foundry installed (forge, cast, anvil)",
            "Target contract deployed or source available",
        ]

        if vuln_type == VulnerabilityType.FLASH_LOAN:
            prereqs.extend(
                [
                    "Flash loan provider (Aave, dYdX) available",
                    "Sufficient liquidity in target pool",
                ]
            )
        elif vuln_type == VulnerabilityType.ORACLE_MANIPULATION:
            prereqs.extend(
                [
                    "Access to oracle price feed",
                    "Ability to manipulate prices (DEX liquidity)",
                ]
            )
        elif vuln_type in (VulnerabilityType.FRONT_RUNNING, VulnerabilityType.PRICE_MANIPULATION):
            prereqs.append("Mempool access or simulation environment")

        return _safe_text_list(prereqs)

    def _get_expected_outcome(self, vuln_type: VulnerabilityType, severity: str) -> str:
        """Get expected outcome description."""
        if isinstance(severity, bytes):
            try:
                severity = severity.decode("utf-8", errors="replace")
            except Exception:
                severity = "medium"
        severity = severity.strip().lower() if isinstance(severity, str) else "medium"
        outcomes = {
            VulnerabilityType.REENTRANCY: "Drain funds from contract through recursive calls",
            VulnerabilityType.FLASH_LOAN: "Profit from flash loan attack",
            VulnerabilityType.ORACLE_MANIPULATION: "Extract value through manipulated prices",
            VulnerabilityType.ACCESS_CONTROL: "Execute privileged functions without authorization",
            VulnerabilityType.INTEGER_OVERFLOW: "Bypass checks through integer overflow",
            VulnerabilityType.INTEGER_UNDERFLOW: "Bypass checks through integer underflow",
            VulnerabilityType.UNCHECKED_CALL: "Exploit unhandled call failure",
            VulnerabilityType.TX_ORIGIN: "Bypass authentication using tx.origin",
            VulnerabilityType.SELFDESTRUCT: "Destroy contract or force ether transfer",
            VulnerabilityType.DELEGATECALL: "Execute arbitrary code in target context",
        }

        vuln_type_value = _safe_vulnerability_type_value(vuln_type)
        return outcomes.get(vuln_type, f"Exploit {vuln_type_value} vulnerability")

    def _extract_gas_from_output(self, output: str) -> Optional[int]:
        """Extract gas used from forge output."""
        if not isinstance(output, str):
            return None
        match = re.search(r"gas:\s*([\d,]+)", output)
        if match:
            gas_text = match.group(1)
            if not re.fullmatch(r"\d{1,3}(,\d{3})*|\d+", gas_text):
                return None
            gas = int(gas_text.replace(",", ""))
            return gas if gas <= 10_000_000_000 else None
        return None

    def _extract_traces(self, output: str) -> Optional[str]:
        """Extract execution traces from forge output."""
        if not isinstance(output, str):
            return None
        # Look for trace section
        trace_start = output.find("Traces:")
        if trace_start >= 0:
            return output[trace_start : trace_start + _TRACE_TEXT_LIMIT]
        return None

    def get_supported_types(self) -> List[str]:
        """Get list of supported vulnerability types."""
        supported_types = []
        seen = set()
        for vuln_type in VulnerabilityType:
            value = _safe_vulnerability_type_value(vuln_type)
            if value != "unknown" and value not in seen:
                supported_types.append(value)
                seen.add(value)
        return supported_types

    def get_template_info(self) -> Dict[str, Any]:
        """Get information about available templates."""
        return {
            "templates_dir": str(self.templates_dir),
            "available_templates": [
                _safe_vulnerability_type_value(vuln_type) for vuln_type in self.TEMPLATE_MAP
            ],
            "type_aliases": {
                key.strip(): _safe_vulnerability_type_value(value)
                for key, value in self.TYPE_ALIASES.items()
                if isinstance(key, str)
                and key.strip()
                and not any(ord(ch) < 32 or ord(ch) == 127 for ch in key)
            },
        }


# Export
__all__ = [
    "PoCGenerator",
    "PoCTemplate",
    "PoCResult",
    "VulnerabilityType",
    "GenerationOptions",
]
