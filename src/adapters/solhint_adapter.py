"""
Solhint Linter Adapter - Layer 2: Dynamic Testing (Linting)
============================================================

Solhint is an open-source Solidity linter providing security and style guide
validations. It catches common errors and style inconsistencies in Solidity code.

Features:
- Security rule validation
- Best practice enforcement
- Style guide compliance
- Configurable rule sets
- Plugin support
- Custom rule creation

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 11, 2025
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


class SolhintAdapter(ToolAdapter):
    """
    Solhint Linter for MIESC Layer 2

    Solhint provides linting capabilities for Solidity contracts,
    enforcing security rules, best practices, and style guidelines.

    DPGA Compliance: 100% PASS
    - Optional tool (graceful degradation if not installed)
    - No external API calls
    - Open source (can be self-hosted)
    """

    METADATA = {
        "name": "solhint",
        "version": "1.0.0",
        "category": "dynamic-testing",  # Linting is considered dynamic testing
        "description": "Solidity linter for security and style validation",
        "is_optional": True,
        "requires": ["solhint", "npm"],
        "supported_languages": ["solidity"],
        "detection_types": [
            "style_violations",
            "security_issues",
            "best_practice_violations",
            "naming_convention_violations",
            "gas_optimization_issues"
        ]
    }

    # Severity mapping from Solhint to MIESC
    SEVERITY_MAP = {
        "error": "high",
        "warning": "medium",
        "info": "low"
    }

    # Common security rules in Solhint
    SECURITY_RULES = [
        "avoid-call-value",
        "avoid-low-level-calls",
        "avoid-sha3",
        "avoid-suicide",
        "avoid-throw",
        "check-send-result",
        "func-visibility",
        "multiple-sends",
        "no-complex-fallback",
        "no-inline-assembly",
        "not-rely-on-block-hash",
        "not-rely-on-time",
        "reentrancy",
        "state-visibility"
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Solhint adapter

        Args:
            config: Configuration dict with optional:
                - config_file: Path to .solhint.json (default: None)
                - formatter: Output formatter (default: "json")
                - max_warnings: Maximum warnings before failing (default: None)
                - quiet: Only report errors (default: False)
                - timeout: Timeout in seconds (default: 60)
        """
        self.config = config or {}
        self.config_file = self.config.get("config_file", None)
        self.formatter = self.config.get("formatter", "json")
        self.max_warnings = self.config.get("max_warnings", None)
        self.quiet = self.config.get("quiet", False)
        self.timeout = self.config.get("timeout", 60)

        logger.debug(f"Solhint adapter initialized (formatter={self.formatter})")

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="solhint",
            version="1.0.0",
            category=ToolCategory.DYNAMIC_TESTING,
            author="Protofire (Adapter by Fernando Boiero)",
            license="MIT",
            homepage="https://github.com/protofire/solhint",
            repository="https://github.com/protofire/solhint",
            documentation="https://protofire.github.io/solhint/",
            installation_cmd="npm install -g solhint",
            capabilities=[
                ToolCapability(
                    name="security_linting",
                    description="Security rule validation",
                    supported_languages=["solidity"],
                    detection_types=["security_issues", "best_practice_violations"]
                ),
                ToolCapability(
                    name="style_linting",
                    description="Style guide enforcement",
                    supported_languages=["solidity"],
                    detection_types=["style_violations", "naming_convention_violations"]
                ),
                ToolCapability(
                    name="gas_optimization",
                    description="Gas optimization suggestions",
                    supported_languages=["solidity"],
                    detection_types=["gas_optimization_issues"]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Solhint is installed and available"""
        try:
            result = subprocess.run(
                ["solhint", "--version"],
                capture_output=True,
                timeout=5,
                text=True
            )
            if result.returncode == 0:
                logger.debug(f"Solhint available: {result.stdout.strip()}")
                return ToolStatus.AVAILABLE
            else:
                return ToolStatus.CONFIGURATION_ERROR
        except FileNotFoundError:
            logger.debug("Solhint not installed")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Solhint availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run Solhint linting on contract

        Args:
            contract_path: Path to Solidity contract file or directory
            **kwargs: Additional arguments:
                - rules: List of specific rules to check
                - ignore_path: Path to .solhintignore file

        Returns:
            Dict containing:
                - tool: "solhint"
                - version: Version string
                - status: "success" or "error"
                - findings: List of linting violations found
                - execution_time: Linting duration
                - total_issues: Total number of issues
                - errors: Number of errors
                - warnings: Number of warnings
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "solhint",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Solhint not available"
            }

        try:
            # Build solhint command
            cmd = ["solhint"]

            # Add formatter
            cmd.extend(["--formatter", self.formatter])

            # Add config file if specified
            if self.config_file and Path(self.config_file).exists():
                cmd.extend(["--config", self.config_file])

            # Add max warnings if specified
            if self.max_warnings is not None:
                cmd.extend(["--max-warnings", str(self.max_warnings)])

            # Add quiet mode
            if self.quiet:
                cmd.append("--quiet")

            # Add ignore path if specified
            ignore_path = kwargs.get("ignore_path")
            if ignore_path and Path(ignore_path).exists():
                cmd.extend(["--ignore-path", ignore_path])

            # Add file/directory to analyze
            cmd.append(contract_path)

            logger.info(f"Running Solhint: {' '.join(cmd)}")

            # Show progress message
            verbose = kwargs.get("verbose", True)
            if verbose:
                print(f"  [Solhint] Running linting analysis...")

            # Run solhint
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                text=True
            )

            duration = time.time() - start_time

            if verbose:
                print(f"  [Solhint] Analysis completed in {duration:.1f}s")

            # Parse output
            findings = self._parse_output(result.stdout, result.stderr)

            # Enhance findings with OpenLLaMA (optional)
            try:
                with open(contract_path, 'r') as f:
                    contract_code = f.read()

                # Enhance top findings with LLM insights
                if findings:
                    findings = enhance_findings_with_llm(
                        findings[:5],  # Top 5 findings
                        contract_code,
                        "solhint"
                    )
            except Exception as e:
                logger.debug(f"LLM enhancement failed: {e}")

            # Count issues by severity
            errors = sum(1 for f in findings if f.get("severity") == "high")
            warnings = sum(1 for f in findings if f.get("severity") == "medium")

            return {
                "tool": "solhint",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "execution_time": round(duration, 2),
                "total_issues": len(findings),
                "errors": errors,
                "warnings": warnings,
                "dpga_compliant": True
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Solhint timeout after {self.timeout}s")
            return {
                "tool": "solhint",
                "status": "error",
                "findings": [],
                "execution_time": self.timeout,
                "error": f"Analysis timeout after {self.timeout}s"
            }
        except FileNotFoundError:
            return {
                "tool": "solhint",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"Contract file not found: {contract_path}"
            }
        except Exception as e:
            logger.error(f"Solhint analysis failed: {str(e)}")
            return {
                "tool": "solhint",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": str(e)
            }

    def _parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse Solhint output to extract findings

        Solhint JSON output format:
        [
          {
            "filePath": "contract.sol",
            "line": 10,
            "column": 5,
            "severity": "error",
            "message": "Description",
            "ruleId": "rule-name"
          }
        ]
        """
        findings = []

        # Try to parse JSON output
        if self.formatter == "json":
            try:
                issues = json.loads(stdout)
                if isinstance(issues, list):
                    for issue in issues:
                        findings.append(self._normalize_issue(issue))
                    return findings
            except json.JSONDecodeError as e:
                logger.debug(f"Failed to parse JSON output: {e}")

        # Fallback to text parsing
        findings = self._parse_text_output(stdout, stderr)

        return findings

    def _normalize_issue(self, issue: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a single Solhint issue to MIESC format"""
        rule_id = issue.get("ruleId", "unknown")
        severity = issue.get("severity", "warning")

        # Map Solhint severity to MIESC severity
        miesc_severity = self.SEVERITY_MAP.get(severity, "medium")

        # Determine if this is a security issue
        is_security = rule_id in self.SECURITY_RULES

        finding = {
            "type": "security_issue" if is_security else "style_violation",
            "severity": miesc_severity,
            "rule": rule_id,
            "description": issue.get("message", "Linting violation"),
            "file": issue.get("filePath", ""),
            "line": issue.get("line"),
            "column": issue.get("column"),
            "recommendation": self._get_recommendation(rule_id)
        }

        # Add fix suggestion if available
        if "fix" in issue:
            finding["fix_suggestion"] = issue["fix"]

        return finding

    def _parse_text_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse text output from Solhint (fallback)"""
        findings = []

        # Solhint text format: filepath:line:column: [error/warning] message (rule-id)
        pattern = r'(.+?):(\d+):(\d+):\s+\[(error|warning|info)\]\s+(.+?)\s+\(([^)]+)\)'

        for line in stdout.split('\n'):
            match = re.search(pattern, line)
            if match:
                filepath, line_num, col_num, severity, message, rule_id = match.groups()

                findings.append({
                    "type": "security_issue" if rule_id in self.SECURITY_RULES else "style_violation",
                    "severity": self.SEVERITY_MAP.get(severity, "medium"),
                    "rule": rule_id,
                    "description": message,
                    "file": filepath,
                    "line": int(line_num),
                    "column": int(col_num),
                    "recommendation": self._get_recommendation(rule_id)
                })

        return findings

    def _get_recommendation(self, rule_id: str) -> str:
        """Get recommendation text for a specific rule"""
        recommendations = {
            "avoid-call-value": "Use transfer() or send() instead of call.value()",
            "avoid-low-level-calls": "Avoid using low-level call, delegatecall, staticcall",
            "avoid-sha3": "Use keccak256() instead of deprecated sha3()",
            "avoid-suicide": "Replace 'suicide' with 'selfdestruct'",
            "avoid-throw": "Replace 'throw' with 'revert', 'require', or 'assert'",
            "check-send-result": "Always check the return value of send() calls",
            "func-visibility": "Explicitly specify function visibility",
            "multiple-sends": "Avoid multiple send() calls in the same function",
            "no-complex-fallback": "Keep fallback functions simple",
            "no-inline-assembly": "Avoid inline assembly unless absolutely necessary",
            "not-rely-on-block-hash": "Don't rely on blockhash for randomness",
            "not-rely-on-time": "Don't rely on block.timestamp for critical logic",
            "reentrancy": "Follow checks-effects-interactions pattern to prevent reentrancy",
            "state-visibility": "Explicitly specify state variable visibility"
        }

        return recommendations.get(
            rule_id,
            f"Follow Solhint rule '{rule_id}' recommendations"
        )

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize findings to MIESC standard format

        Args:
            raw_output: Raw Solhint output or parsed findings

        Returns:
            List of normalized findings
        """
        if isinstance(raw_output, dict) and "findings" in raw_output:
            return raw_output["findings"]
        elif isinstance(raw_output, list):
            return raw_output
        else:
            return []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if file can be analyzed"""
        path = Path(contract_path)

        # Can analyze .sol files
        if path.is_file() and path.suffix == '.sol':
            return True

        # Can analyze directories containing .sol files
        if path.is_dir():
            return any(path.glob("**/*.sol"))

        return False

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Solhint"""
        return {
            "formatter": "json",
            "max_warnings": None,
            "quiet": False,
            "timeout": 60,
            "rules": {
                # Security rules (recommended to enable)
                "avoid-call-value": True,
                "avoid-low-level-calls": True,
                "avoid-sha3": True,
                "avoid-suicide": True,
                "check-send-result": True,
                "func-visibility": True,
                "reentrancy": True,
                "state-visibility": True
            }
        }


# Adapter registration
def register_adapter():
    """Register Solhint adapter with MIESC"""
    return {
        "adapter_class": SolhintAdapter,
        "metadata": SolhintAdapter.METADATA
    }


__all__ = ["SolhintAdapter", "register_adapter"]
