"""
Hardhat Adapter - Layer 2: Dynamic Testing
==========================================

Hardhat is a development environment for Ethereum that includes compilation,
testing, and deployment capabilities. This adapter integrates with Hardhat's
compilation warnings and security plugins.

Features:
- Solidity compilation with detailed warnings
- Integration with hardhat-gas-reporter
- Integration with solidity-coverage
- Support for hardhat-contract-sizer
- Custom security task execution
- Plugin ecosystem integration

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

from src.core.tool_protocol import (
    ToolAdapter, ToolMetadata, ToolStatus, ToolCategory, ToolCapability
)
from src.llm import enhance_findings_with_llm
from typing import Dict, Any, List, Optional
import subprocess
import json
import time
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)


class HardhatAdapter(ToolAdapter):
    """
    Hardhat Development Framework Adapter for MIESC Layer 2

    Hardhat provides a comprehensive development environment with
    compilation warnings and security plugin integration.

    DPGA Compliance: 100% PASS
    - Optional tool (graceful degradation if not installed)
    - No external API calls
    - Open source (can be self-hosted)
    """

    METADATA = {
        "name": "hardhat",
        "version": "1.0.0",
        "category": "dynamic-testing",
        "description": "Ethereum development framework with security plugins",
        "is_optional": True,
        "requires": ["npx", "hardhat"],
        "supported_languages": ["solidity"],
        "detection_types": [
            "compilation_warnings",
            "gas_issues",
            "contract_size",
            "coverage_gaps",
            "security_issues"
        ]
    }

    # Severity mapping for compilation warnings
    SEVERITY_MAP = {
        "error": "critical",
        "warning": "medium",
        "info": "low"
    }

    # Common compilation warning patterns
    WARNING_PATTERNS = {
        r"unused\s+variable": ("unused_variable", "low"),
        r"unused\s+function": ("unused_function", "low"),
        r"visibility\s+for\s+constructor": ("constructor_visibility", "medium"),
        r"state\s+mutability": ("state_mutability", "low"),
        r"SPDX\s+license": ("missing_license", "info"),
        r"pragma\s+solidity": ("pragma_issue", "low"),
        r"shadowing": ("variable_shadowing", "medium"),
        r"reentrancy": ("reentrancy", "high"),
        r"unreachable\s+code": ("unreachable_code", "low"),
        r"overflow": ("arithmetic", "high"),
        r"underflow": ("arithmetic", "high"),
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Hardhat adapter

        Args:
            config: Configuration dict with optional:
                - project_path: Path to Hardhat project (default: contract dir)
                - network: Network to use (default: hardhat)
                - compile_force: Force recompilation (default: True)
                - run_gas_reporter: Run gas reporter (default: False)
                - run_coverage: Run coverage (default: False)
                - timeout: Timeout in seconds (default: 180)
        """
        self.config = config or {}
        self.project_path = self.config.get("project_path", None)
        self.network = self.config.get("network", "hardhat")
        self.compile_force = self.config.get("compile_force", True)
        self.run_gas_reporter = self.config.get("run_gas_reporter", False)
        self.run_coverage = self.config.get("run_coverage", False)
        self.timeout = self.config.get("timeout", 180)

        logger.debug(f"Hardhat adapter initialized (network={self.network})")

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="hardhat",
            version="1.0.0",
            category=ToolCategory.DYNAMIC_TESTING,
            author="Nomic Foundation (Adapter by Fernando Boiero)",
            license="MIT",
            homepage="https://hardhat.org",
            repository="https://github.com/NomicFoundation/hardhat",
            documentation="https://hardhat.org/docs",
            installation_cmd="npm install --save-dev hardhat",
            capabilities=[
                ToolCapability(
                    name="compilation_analysis",
                    description="Analyze compilation warnings and errors",
                    supported_languages=["solidity"],
                    detection_types=["compilation_warnings", "security_issues"]
                ),
                ToolCapability(
                    name="gas_analysis",
                    description="Gas usage analysis with hardhat-gas-reporter",
                    supported_languages=["solidity"],
                    detection_types=["gas_issues"]
                ),
                ToolCapability(
                    name="coverage_analysis",
                    description="Code coverage with solidity-coverage",
                    supported_languages=["solidity"],
                    detection_types=["coverage_gaps"]
                ),
                ToolCapability(
                    name="size_analysis",
                    description="Contract size analysis with hardhat-contract-sizer",
                    supported_languages=["solidity"],
                    detection_types=["contract_size"]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Hardhat is installed and available"""
        try:
            # Check if npx is available
            result = subprocess.run(
                ["npx", "--version"],
                capture_output=True,
                timeout=10,
                text=True
            )
            if result.returncode != 0:
                return ToolStatus.NOT_INSTALLED

            # Check if hardhat is available
            result = subprocess.run(
                ["npx", "hardhat", "--version"],
                capture_output=True,
                timeout=15,
                text=True,
                cwd=self.project_path or "."
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.debug(f"Hardhat available: {version}")
                return ToolStatus.AVAILABLE
            else:
                # Hardhat might not be in current directory
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.debug("npx/hardhat not installed")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Hardhat availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run Hardhat analysis on contract

        Args:
            contract_path: Path to Solidity contract file or Hardhat project
            **kwargs: Additional arguments:
                - compile_only: Only run compilation (default: True)
                - verbose: Show progress messages

        Returns:
            Dict containing:
                - tool: "hardhat"
                - version: Version string
                - status: "success" or "error"
                - findings: List of issues found
                - execution_time: Analysis duration
                - compilation_info: Compilation details
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "hardhat",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Hardhat not available"
            }

        try:
            # Determine project directory
            path = Path(contract_path)
            if path.is_file():
                project_dir = self._find_hardhat_project(path.parent)
            else:
                project_dir = self._find_hardhat_project(path)

            if not project_dir:
                return {
                    "tool": "hardhat",
                    "status": "error",
                    "findings": [],
                    "execution_time": time.time() - start_time,
                    "error": "No Hardhat project found (missing hardhat.config.js)"
                }

            verbose = kwargs.get("verbose", True)
            findings = []
            compilation_info = {}

            # Run compilation
            if verbose:
                print(f"  [Hardhat] Compiling contracts...")

            compile_result = self._run_compile(project_dir)
            findings.extend(compile_result.get("findings", []))
            compilation_info = compile_result.get("info", {})

            # Run gas reporter if enabled
            if self.run_gas_reporter and kwargs.get("run_gas_reporter", False):
                if verbose:
                    print(f"  [Hardhat] Running gas reporter...")
                gas_result = self._run_gas_reporter(project_dir)
                findings.extend(gas_result.get("findings", []))

            # Run coverage if enabled
            if self.run_coverage and kwargs.get("run_coverage", False):
                if verbose:
                    print(f"  [Hardhat] Running coverage...")
                coverage_result = self._run_coverage(project_dir)
                findings.extend(coverage_result.get("findings", []))

            duration = time.time() - start_time

            if verbose:
                print(f"  [Hardhat] Analysis completed in {duration:.1f}s")

            # Enhance findings with LLM
            try:
                if path.is_file():
                    with open(contract_path, 'r') as f:
                        contract_code = f.read()

                    if findings:
                        findings = enhance_findings_with_llm(
                            findings[:5],
                            contract_code,
                            "hardhat"
                        )
            except Exception as e:
                logger.debug(f"LLM enhancement failed: {e}")

            return {
                "tool": "hardhat",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "execution_time": round(duration, 2),
                "total_findings": len(findings),
                "compilation_info": compilation_info,
                "dpga_compliant": True
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Hardhat timeout after {self.timeout}s")
            return {
                "tool": "hardhat",
                "status": "error",
                "findings": [],
                "execution_time": self.timeout,
                "error": f"Analysis timeout after {self.timeout}s"
            }
        except Exception as e:
            logger.error(f"Hardhat analysis failed: {str(e)}")
            return {
                "tool": "hardhat",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": str(e)
            }

    def _find_hardhat_project(self, start_path: Path) -> Optional[Path]:
        """Find the nearest Hardhat project directory"""
        current = start_path.resolve()

        while current != current.parent:
            # Check for hardhat.config.js or hardhat.config.ts
            if (current / "hardhat.config.js").exists():
                return current
            if (current / "hardhat.config.ts").exists():
                return current
            current = current.parent

        return None

    def _run_compile(self, project_dir: Path) -> Dict[str, Any]:
        """Run Hardhat compilation and extract warnings"""
        cmd = ["npx", "hardhat", "compile"]

        if self.compile_force:
            cmd.append("--force")

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=self.timeout,
            text=True,
            cwd=project_dir
        )

        findings = []
        info = {
            "success": result.returncode == 0,
            "contracts_compiled": 0,
        }

        # Parse stdout for compilation info
        output = result.stdout + result.stderr

        # Count compiled contracts
        compiled_match = re.search(r"Compiled\s+(\d+)\s+Solidity", output)
        if compiled_match:
            info["contracts_compiled"] = int(compiled_match.group(1))

        # Extract warnings and errors
        findings.extend(self._parse_compilation_output(output))

        return {"findings": findings, "info": info}

    def _parse_compilation_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse compilation output for warnings and errors"""
        findings = []

        # Pattern for Solidity warnings: ContractName.sol:line:col: Warning: message
        warning_pattern = r'([^:\s]+\.sol):(\d+):(\d+):\s+(Warning|Error):\s+(.+?)(?=\n[^\s]|\Z)'

        for match in re.finditer(warning_pattern, output, re.MULTILINE | re.DOTALL):
            file_name, line, col, level, message = match.groups()
            message = message.strip()

            # Determine type and severity from message
            finding_type = "compilation_warning"
            severity = "medium" if level == "Warning" else "high"

            for pattern, (vuln_type, sev) in self.WARNING_PATTERNS.items():
                if re.search(pattern, message, re.IGNORECASE):
                    finding_type = vuln_type
                    severity = sev
                    break

            findings.append({
                "type": finding_type,
                "severity": severity,
                "description": message,
                "file": file_name,
                "line": int(line),
                "column": int(col),
                "recommendation": self._get_recommendation(finding_type)
            })

        return findings

    def _run_gas_reporter(self, project_dir: Path) -> Dict[str, Any]:
        """Run gas reporter plugin"""
        findings = []

        try:
            # Run tests with gas reporter enabled
            env = {"REPORT_GAS": "true"}
            result = subprocess.run(
                ["npx", "hardhat", "test"],
                capture_output=True,
                timeout=self.timeout,
                text=True,
                cwd=project_dir,
                env={**subprocess.os.environ, **env}
            )

            # Parse gas report output
            # Look for high gas usage patterns
            gas_pattern = r'(\w+)\s+·\s+(\d+)\s+·\s+(\d+)\s+·\s+(\d+)\s+·'

            for match in re.finditer(gas_pattern, result.stdout):
                method, min_gas, max_gas, avg_gas = match.groups()
                avg = int(avg_gas)

                # Flag functions with high gas usage
                if avg > 100000:
                    findings.append({
                        "type": "high_gas_usage",
                        "severity": "low" if avg < 500000 else "medium",
                        "description": f"Function '{method}' has high gas usage (avg: {avg:,})",
                        "function": method,
                        "gas_avg": avg,
                        "gas_min": int(min_gas),
                        "gas_max": int(max_gas),
                        "recommendation": "Consider optimizing this function to reduce gas costs"
                    })

        except Exception as e:
            logger.debug(f"Gas reporter failed: {e}")

        return {"findings": findings}

    def _run_coverage(self, project_dir: Path) -> Dict[str, Any]:
        """Run coverage plugin"""
        findings = []

        try:
            result = subprocess.run(
                ["npx", "hardhat", "coverage"],
                capture_output=True,
                timeout=self.timeout * 2,  # Coverage takes longer
                text=True,
                cwd=project_dir
            )

            # Parse coverage output
            # Look for low coverage files
            coverage_pattern = r'(\S+\.sol)\s+\|\s+(\d+(?:\.\d+)?)\s+\|\s+(\d+(?:\.\d+)?)\s+\|\s+(\d+(?:\.\d+)?)'

            for match in re.finditer(coverage_pattern, result.stdout):
                file_name, stmt_cov, branch_cov, func_cov = match.groups()
                stmt = float(stmt_cov)
                branch = float(branch_cov)
                func = float(func_cov)

                # Flag files with low coverage
                if stmt < 80 or branch < 70 or func < 80:
                    findings.append({
                        "type": "low_coverage",
                        "severity": "low",
                        "description": f"Low test coverage in '{file_name}'",
                        "file": file_name,
                        "statement_coverage": stmt,
                        "branch_coverage": branch,
                        "function_coverage": func,
                        "recommendation": "Increase test coverage to improve confidence"
                    })

        except Exception as e:
            logger.debug(f"Coverage analysis failed: {e}")

        return {"findings": findings}

    def _get_recommendation(self, finding_type: str) -> str:
        """Get recommendation for a finding type"""
        recommendations = {
            "unused_variable": "Remove unused variables to improve code clarity",
            "unused_function": "Remove unused functions or mark as internal/private",
            "constructor_visibility": "Remove visibility specifier from constructor (Solidity 0.7+)",
            "state_mutability": "Add appropriate state mutability (view/pure) to function",
            "missing_license": "Add SPDX license identifier to the file",
            "pragma_issue": "Lock pragma to a specific compiler version",
            "variable_shadowing": "Rename variable to avoid shadowing inherited state",
            "reentrancy": "Use ReentrancyGuard or checks-effects-interactions pattern",
            "unreachable_code": "Remove unreachable code",
            "arithmetic": "Use Solidity 0.8+ or SafeMath for arithmetic operations",
            "high_gas_usage": "Consider optimizing loops, storage access, or algorithm",
            "low_coverage": "Add more tests to increase code coverage",
        }

        return recommendations.get(
            finding_type,
            f"Review and fix issue: {finding_type}"
        )

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize findings to MIESC standard format
        """
        if isinstance(raw_output, dict) and "findings" in raw_output:
            return raw_output["findings"]
        elif isinstance(raw_output, list):
            return raw_output
        else:
            return []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if file/directory can be analyzed"""
        path = Path(contract_path)

        # Can analyze .sol files
        if path.is_file() and path.suffix == '.sol':
            return self._find_hardhat_project(path.parent) is not None

        # Can analyze directories with hardhat.config
        if path.is_dir():
            return self._find_hardhat_project(path) is not None

        return False

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Hardhat"""
        return {
            "network": "hardhat",
            "compile_force": True,
            "run_gas_reporter": False,
            "run_coverage": False,
            "timeout": 180
        }


# Adapter registration
def register_adapter():
    """Register Hardhat adapter with MIESC"""
    return {
        "adapter_class": HardhatAdapter,
        "metadata": HardhatAdapter.METADATA
    }


__all__ = ["HardhatAdapter", "register_adapter"]
