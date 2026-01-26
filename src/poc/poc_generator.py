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
import subprocess
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
import json

logger = logging.getLogger(__name__)


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
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        filename = f"PoC_{self.vulnerability_type.value}_{self.name}.t.sol"
        filepath = output_path / filename

        with open(filepath, 'w') as f:
            f.write(self.solidity_code)

        logger.info(f"PoC saved to {filepath}")
        return filepath

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "vulnerability_type": self.vulnerability_type.value,
            "target_contract": self.target_contract,
            "target_function": self.target_function,
            "finding_id": self.finding_id,
            "description": self.description,
            "prerequisites": self.prerequisites,
            "expected_outcome": self.expected_outcome,
            "created_at": self.created_at.isoformat(),
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
        self.templates_dir = templates_dir or self.TEMPLATES_DIR
        self.options = options or GenerationOptions()
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
        opts = options or self.options

        # Determine vulnerability type
        vuln_type = self._resolve_vulnerability_type(finding)

        # Extract finding details
        target_function = self._extract_function_name(finding)
        description = finding.get("description", "")
        severity = finding.get("severity", "medium")

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
            target_contract=target_contract,
            target_function=target_function,
            finding_id=finding.get("id") or finding.get("rule"),
            description=description,
            prerequisites=self._get_prerequisites(vuln_type),
            expected_outcome=self._get_expected_outcome(vuln_type, severity),
        )

        logger.info(f"Generated PoC: {poc.name} for {vuln_type.value}")
        return poc

    def generate_batch(
        self,
        findings: List[Dict[str, Any]],
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
        for finding in findings:
            try:
                poc = self.generate(finding, target_contract, options)
                pocs.append(poc)
            except Exception as e:
                logger.warning(f"Failed to generate PoC for finding: {e}")

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

        project_path = Path(project_dir)
        start_time = time.time()

        # Save PoC to project
        test_dir = project_path / "test" / "exploits"
        poc_path = poc.save(test_dir)

        try:
            # Run forge test
            cmd = [
                "forge", "test",
                "--match-path", str(poc_path),
                "-vvv",  # Verbose output with traces
            ]

            if verbose:
                print(f"Running: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=300,
            )

            execution_time = (time.time() - start_time) * 1000

            # Parse output
            success = result.returncode == 0
            output = result.stdout + result.stderr

            # Extract gas used
            gas_used = self._extract_gas_from_output(output)

            return PoCResult(
                success=success,
                output=output,
                gas_used=gas_used,
                execution_time_ms=execution_time,
                error=None if success else result.stderr,
                traces=self._extract_traces(output),
            )

        except subprocess.TimeoutExpired:
            return PoCResult(
                success=False,
                output="",
                execution_time_ms=(time.time() - start_time) * 1000,
                error="PoC execution timed out",
            )
        except FileNotFoundError:
            return PoCResult(
                success=False,
                output="",
                execution_time_ms=0,
                error="Foundry (forge) not installed",
            )
        except Exception as e:
            return PoCResult(
                success=False,
                output="",
                execution_time_ms=(time.time() - start_time) * 1000,
                error=str(e),
            )

    def _resolve_vulnerability_type(self, finding: Dict[str, Any]) -> VulnerabilityType:
        """Resolve finding type to VulnerabilityType enum."""
        finding_type = finding.get("type", "").lower().strip()

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

    def _extract_function_name(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract target function name from finding."""
        location = finding.get("location", {})

        if isinstance(location, dict):
            return location.get("function") or location.get("func")
        elif isinstance(location, str):
            # Try to parse function from string
            match = re.search(r'function\s+(\w+)', location)
            if match:
                return match.group(1)

        return None

    def _generate_poc_name(
        self,
        target_contract: str,
        vuln_type: VulnerabilityType,
        target_function: Optional[str],
    ) -> str:
        """Generate a descriptive PoC name."""
        contract_name = Path(target_contract).stem
        type_name = vuln_type.value.replace("_", "")

        if target_function:
            return f"{contract_name}_{target_function}_{type_name}"
        else:
            return f"{contract_name}_{type_name}"

    def _load_template(self, vuln_type: VulnerabilityType) -> str:
        """Load template for vulnerability type."""
        template_name = self.TEMPLATE_MAP.get(vuln_type)

        if not template_name:
            # Use generic template
            template_name = "generic.t.sol"

        # Check cache
        if template_name in self._template_cache:
            return self._template_cache[template_name]

        # Load from file
        template_path = self.templates_dir / template_name

        if template_path.exists():
            with open(template_path, 'r') as f:
                template = f.read()
        else:
            # Use embedded default template
            template = self._get_default_template(vuln_type)

        self._template_cache[template_name] = template
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
        # Prepare replacements
        contract_name = Path(target_contract).stem
        test_name = f"test_exploit_{vuln_type.value}"

        replacements = {
            "{{CONTRACT_NAME}}": contract_name,
            "{{TARGET_CONTRACT}}": target_contract,
            "{{TARGET_FUNCTION}}": target_function or "vulnerable",
            "{{TEST_NAME}}": test_name,
            "{{VULNERABILITY_TYPE}}": vuln_type.value,
            "{{ATTACKER_BALANCE}}": options.attacker_balance,
            "{{VICTIM_BALANCE}}": options.victim_balance,
            "{{DESCRIPTION}}": finding.get("description", ""),
            "{{SEVERITY}}": finding.get("severity", "medium"),
            "{{TIMESTAMP}}": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }

        # Apply replacements
        result = template
        for placeholder, value in replacements.items():
            result = result.replace(placeholder, str(value))

        # Add custom imports
        if options.custom_imports:
            import_lines = "\n".join(f'import "{imp}";' for imp in options.custom_imports)
            result = result.replace("// {{CUSTOM_IMPORTS}}", import_lines)

        # Add custom setup
        if options.custom_setup_code:
            result = result.replace("// {{CUSTOM_SETUP}}", options.custom_setup_code)

        # Add fork configuration
        if options.fork_url and options.fork_block:
            fork_config = f"""
        // Fork mainnet
        vm.createSelectFork("{options.fork_url}", {options.fork_block});
"""
            result = result.replace("// {{FORK_CONFIG}}", fork_config)

        # Remove unused placeholders
        result = re.sub(r'// \{\{[A-Z_]+\}\}', '', result)

        return result

    def _get_default_template(self, vuln_type: VulnerabilityType) -> str:
        """Get embedded default template for vulnerability type."""
        # Basic Foundry test template
        return '''// SPDX-License-Identifier: MIT
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

        // TODO: Implement exploit logic for {{VULNERABILITY_TYPE}}
        // Call vulnerable function: target.{{TARGET_FUNCTION}}()

        vm.stopPrank();

        uint256 attackerBalanceAfter = attacker.balance;

        console.log("=== Exploit Complete ===");
        console.log("Balance before:", attackerBalanceBefore);
        console.log("Balance after:", attackerBalanceAfter);

        // Assert exploit success
        // assertGt(attackerBalanceAfter, attackerBalanceBefore, "Exploit should profit");
    }
}
'''

    def _get_prerequisites(self, vuln_type: VulnerabilityType) -> List[str]:
        """Get prerequisites for running PoC."""
        prereqs = [
            "Foundry installed (forge, cast, anvil)",
            "Target contract deployed or source available",
        ]

        if vuln_type == VulnerabilityType.FLASH_LOAN:
            prereqs.extend([
                "Flash loan provider (Aave, dYdX) available",
                "Sufficient liquidity in target pool",
            ])
        elif vuln_type == VulnerabilityType.ORACLE_MANIPULATION:
            prereqs.extend([
                "Access to oracle price feed",
                "Ability to manipulate prices (DEX liquidity)",
            ])
        elif vuln_type in (VulnerabilityType.FRONT_RUNNING, VulnerabilityType.PRICE_MANIPULATION):
            prereqs.append("Mempool access or simulation environment")

        return prereqs

    def _get_expected_outcome(self, vuln_type: VulnerabilityType, severity: str) -> str:
        """Get expected outcome description."""
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

        return outcomes.get(vuln_type, f"Exploit {vuln_type.value} vulnerability")

    def _extract_gas_from_output(self, output: str) -> Optional[int]:
        """Extract gas used from forge output."""
        match = re.search(r'gas:\s*(\d+)', output)
        if match:
            return int(match.group(1))
        return None

    def _extract_traces(self, output: str) -> Optional[str]:
        """Extract execution traces from forge output."""
        # Look for trace section
        trace_start = output.find("Traces:")
        if trace_start >= 0:
            return output[trace_start:]
        return None

    def get_supported_types(self) -> List[str]:
        """Get list of supported vulnerability types."""
        return [vt.value for vt in VulnerabilityType]

    def get_template_info(self) -> Dict[str, Any]:
        """Get information about available templates."""
        return {
            "templates_dir": str(self.templates_dir),
            "available_templates": list(self.TEMPLATE_MAP.keys()),
            "type_aliases": {k: v.value for k, v in self.TYPE_ALIASES.items()},
        }


# Export
__all__ = [
    "PoCGenerator",
    "PoCTemplate",
    "PoCResult",
    "VulnerabilityType",
    "GenerationOptions",
]
