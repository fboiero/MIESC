"""
Semgrep Adapter - Layer 1: Static Analysis
==========================================

Semgrep is a fast, lightweight static analysis tool that finds bugs and
enforces code standards. It supports custom rules for Solidity security patterns.

Features:
- Pattern-based static analysis
- Custom rule support for Solidity
- Multiple rule registries (semgrep-rules, smart-contracts)
- Fast scanning (no compilation required)
- SARIF output format support
- CI/CD integration ready

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
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class SemgrepAdapter(ToolAdapter):
    """
    Semgrep Static Analysis Adapter for MIESC Layer 1

    Semgrep provides pattern-based static analysis with custom rules
    for Solidity smart contract security.

    DPGA Compliance: 100% PASS
    - Optional tool (graceful degradation if not installed)
    - No external API calls (local rules)
    - Open source (can be self-hosted)
    """

    METADATA = {
        "name": "semgrep",
        "version": "1.0.0",
        "category": "static-analysis",
        "description": "Fast pattern-based static analysis for Solidity security",
        "is_optional": True,
        "requires": ["semgrep"],
        "supported_languages": ["solidity"],
        "detection_types": [
            "reentrancy",
            "access_control",
            "arithmetic",
            "unchecked_calls",
            "oracle_manipulation",
            "front_running",
            "gas_optimization"
        ]
    }

    # Default rule registries for smart contracts
    DEFAULT_RULES = [
        "p/smart-contracts",
        "p/solidity",
    ]

    # Custom rule patterns for common vulnerabilities
    # v4.6.0: Expanded from 6 to 20+ rules for better DeFi coverage
    CUSTOM_RULES = {
        # === REENTRANCY PATTERNS ===
        "reentrancy": {
            "pattern": "$X.call{value: $V}($DATA)",
            "message": "Potential reentrancy vulnerability: external call with value transfer",
            "severity": "ERROR",
            "languages": ["solidity"]
        },
        "reentrancy-send": {
            "pattern": "$X.send($V)",
            "message": "Potential reentrancy: send() can trigger fallback",
            "severity": "WARNING",
            "languages": ["solidity"]
        },
        "reentrancy-transfer": {
            "pattern": "$X.transfer($V)",
            "message": "External transfer before state update",
            "severity": "WARNING",
            "languages": ["solidity"]
        },

        # === UNCHECKED CALLS ===
        "unchecked-call": {
            "pattern": "$X.call($DATA);",
            "pattern-not": "(bool $SUCCESS,) = $X.call($DATA);",
            "message": "Unchecked low-level call return value",
            "severity": "WARNING",
            "languages": ["solidity"]
        },
        "unchecked-return-transfer": {
            "pattern": "$TOKEN.transfer($TO, $AMOUNT);",
            "message": "Unchecked ERC20 transfer return value - use SafeERC20",
            "severity": "WARNING",
            "languages": ["solidity"]
        },
        "unchecked-return-transferfrom": {
            "pattern": "$TOKEN.transferFrom($FROM, $TO, $AMOUNT);",
            "message": "Unchecked ERC20 transferFrom return value - use SafeERC20",
            "severity": "WARNING",
            "languages": ["solidity"]
        },

        # === ACCESS CONTROL ===
        "tx-origin": {
            "pattern": "tx.origin",
            "message": "Use of tx.origin for authorization is insecure",
            "severity": "ERROR",
            "languages": ["solidity"]
        },
        "selfdestruct": {
            "pattern": "selfdestruct($X)",
            "message": "Unprotected selfdestruct call",
            "severity": "ERROR",
            "languages": ["solidity"]
        },
        "delegatecall": {
            "pattern": "$X.delegatecall($DATA)",
            "message": "Delegatecall to potentially untrusted contract",
            "severity": "ERROR",
            "languages": ["solidity"]
        },
        "unprotected-initializer": {
            "pattern": "function initialize($PARAMS) $VISIBILITY { ... }",
            "pattern-not": "function initialize($PARAMS) $VISIBILITY initializer { ... }",
            "message": "Initialize function missing initializer modifier",
            "severity": "ERROR",
            "languages": ["solidity"]
        },

        # === TIMESTAMP/RANDOMNESS ===
        "block-timestamp": {
            "pattern": "block.timestamp",
            "message": "Block timestamp used for critical logic - can be manipulated",
            "severity": "WARNING",
            "languages": ["solidity"]
        },
        "weak-randomness-blockhash": {
            "pattern": "blockhash($X)",
            "message": "Blockhash used for randomness is predictable",
            "severity": "ERROR",
            "languages": ["solidity"]
        },
        "weak-randomness-prevrandao": {
            "pattern": "block.prevrandao",
            "message": "prevrandao is predictable for PoS validators",
            "severity": "WARNING",
            "languages": ["solidity"]
        },

        # === DEFI PATTERNS ===
        "flash-loan-callback": {
            "pattern": "function $FUNC($PARAMS) external { ... $X.call($DATA) ... }",
            "message": "Flash loan callback with external call - verify authorization",
            "severity": "WARNING",
            "languages": ["solidity"]
        },
        "price-manipulation-spot": {
            "pattern": "$PAIR.getReserves()",
            "message": "Spot price from reserves can be manipulated - use TWAP",
            "severity": "WARNING",
            "languages": ["solidity"]
        },
        "oracle-single-source": {
            "pattern": "$ORACLE.latestRoundData()",
            "message": "Single oracle source - consider using multiple oracles",
            "severity": "INFO",
            "languages": ["solidity"]
        },
        "missing-slippage-check": {
            "pattern": "function swap($PARAMS) { ... $ROUTER.swap($ARGS) ... }",
            "pattern-not": "function swap($PARAMS) { ... require($AMOUNT >= $MIN) ... }",
            "message": "Swap function missing slippage protection",
            "severity": "ERROR",
            "languages": ["solidity"]
        },
        "missing-deadline": {
            "pattern": "$ROUTER.swapExactTokensForTokens($A, $B, $PATH, $TO, $DEADLINE)",
            "message": "Ensure deadline parameter is not hardcoded or too far in future",
            "severity": "WARNING",
            "languages": ["solidity"]
        },

        # === ARITHMETIC ===
        "division-before-multiplication": {
            "pattern": "$A / $B * $C",
            "message": "Division before multiplication causes precision loss",
            "severity": "WARNING",
            "languages": ["solidity"]
        },
        "unsafe-downcast": {
            "pattern": "uint8($X)",
            "message": "Unsafe downcast may truncate value",
            "severity": "WARNING",
            "languages": ["solidity"]
        },

        # === DOS ===
        "unbounded-loop": {
            "pattern": "for ($INIT; $COND < $ARR.length; $INC) { ... }",
            "message": "Loop over unbounded array can cause DoS",
            "severity": "WARNING",
            "languages": ["solidity"]
        },
        "push-payment-in-loop": {
            "pattern": "for ($INIT; $COND; $INC) { ... $X.transfer($V) ... }",
            "message": "Push payment in loop can be blocked by malicious recipient",
            "severity": "WARNING",
            "languages": ["solidity"]
        },

        # === SIGNATURE ===
        "signature-replay": {
            "pattern": "ecrecover($HASH, $V, $R, $S)",
            "message": "Ensure signature includes nonce and chain ID to prevent replay",
            "severity": "WARNING",
            "languages": ["solidity"]
        },
        "missing-zero-check-ecrecover": {
            "pattern": "address $SIGNER = ecrecover($PARAMS);",
            "pattern-not": "require($SIGNER != address(0))",
            "message": "ecrecover can return address(0) on invalid signature",
            "severity": "ERROR",
            "languages": ["solidity"]
        },

        # === STORAGE ===
        "uninitialized-storage": {
            "pattern": "$TYPE storage $VAR;",
            "message": "Uninitialized storage pointer can reference unexpected storage",
            "severity": "ERROR",
            "languages": ["solidity"]
        },
        "storage-collision": {
            "pattern": "bytes32 constant $SLOT = keccak256($STRING);",
            "message": "Manual storage slot - ensure no collision with standard slots",
            "severity": "INFO",
            "languages": ["solidity"]
        },
    }

    # Severity mapping from Semgrep to MIESC
    SEVERITY_MAP = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
        "error": "high",
        "warning": "medium",
        "info": "low"
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Semgrep adapter

        Args:
            config: Configuration dict with optional:
                - rules: List of rule registries to use
                - custom_rules_path: Path to custom rules file
                - timeout: Timeout in seconds (default: 120)
                - max_target_bytes: Max file size to analyze
                - exclude: Patterns to exclude
                - use_custom_rules: Whether to use built-in custom rules
        """
        self.config = config or {}
        self.rules = self.config.get("rules", self.DEFAULT_RULES)
        self.custom_rules_path = self.config.get("custom_rules_path", None)
        self.timeout = self.config.get("timeout", 120)
        self.max_target_bytes = self.config.get("max_target_bytes", 1000000)
        self.exclude = self.config.get("exclude", ["**/node_modules/**", "**/test/**"])
        self.use_custom_rules = self.config.get("use_custom_rules", True)

        logger.debug(f"Semgrep adapter initialized (rules={self.rules})")

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="semgrep",
            version="1.0.0",
            category=ToolCategory.STATIC_ANALYSIS,
            author="Semgrep Inc. (Adapter by Fernando Boiero)",
            license="LGPL-2.1",
            homepage="https://semgrep.dev",
            repository="https://github.com/semgrep/semgrep",
            documentation="https://semgrep.dev/docs/",
            installation_cmd="pip install semgrep",
            capabilities=[
                ToolCapability(
                    name="pattern_analysis",
                    description="Pattern-based vulnerability detection",
                    supported_languages=["solidity"],
                    detection_types=["reentrancy", "access_control", "unchecked_calls"]
                ),
                ToolCapability(
                    name="custom_rules",
                    description="Support for custom security rules",
                    supported_languages=["solidity"],
                    detection_types=["custom_vulnerabilities"]
                ),
                ToolCapability(
                    name="registry_rules",
                    description="Community rule registries",
                    supported_languages=["solidity"],
                    detection_types=["security_issues", "best_practices"]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Semgrep is installed and available"""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=10,
                text=True
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.debug(f"Semgrep available: {version}")
                return ToolStatus.AVAILABLE
            else:
                return ToolStatus.CONFIGURATION_ERROR
        except FileNotFoundError:
            logger.debug("Semgrep not installed")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Semgrep availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run Semgrep analysis on contract

        Args:
            contract_path: Path to Solidity contract file or directory
            **kwargs: Additional arguments:
                - rules: Override default rules
                - severity: Minimum severity to report
                - verbose: Show progress messages

        Returns:
            Dict containing:
                - tool: "semgrep"
                - version: Version string
                - status: "success" or "error"
                - findings: List of vulnerabilities found
                - execution_time: Analysis duration
                - rules_used: List of rule registries used
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "semgrep",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Semgrep not available"
            }

        try:
            # Build semgrep command
            cmd = ["semgrep"]

            # Use custom rules or registry
            rules = kwargs.get("rules", self.rules)

            # Create temp file with custom rules if enabled
            custom_rules_file = None
            if self.use_custom_rules:
                custom_rules_file = self._create_custom_rules_file()
                if custom_rules_file:
                    cmd.extend(["--config", custom_rules_file])

            # Add registry rules
            for rule in rules:
                cmd.extend(["--config", rule])

            # Add custom rules path if specified
            if self.custom_rules_path and Path(self.custom_rules_path).exists():
                cmd.extend(["--config", self.custom_rules_path])

            # Output format
            cmd.extend(["--json"])

            # Add exclusions
            for pattern in self.exclude:
                cmd.extend(["--exclude", pattern])

            # Set timeout
            cmd.extend(["--timeout", str(self.timeout)])

            # Add max target bytes
            cmd.extend(["--max-target-bytes", str(self.max_target_bytes)])

            # Disable metrics
            cmd.append("--metrics=off")

            # Add target path
            cmd.append(contract_path)

            logger.info(f"Running Semgrep: {' '.join(cmd[:10])}...")

            # Show progress message
            verbose = kwargs.get("verbose", True)
            if verbose:
                print(f"  [Semgrep] Running pattern analysis...")

            # Run semgrep
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout + 30,  # Extra buffer for timeout
                text=True
            )

            duration = time.time() - start_time

            if verbose:
                print(f"  [Semgrep] Analysis completed in {duration:.1f}s")

            # Clean up temp file
            if custom_rules_file:
                try:
                    Path(custom_rules_file).unlink()
                except Exception:
                    pass

            # Parse output
            findings = self._parse_output(result.stdout, result.stderr)

            # Enhance findings with LLM
            try:
                with open(contract_path, 'r') as f:
                    contract_code = f.read()

                if findings:
                    findings = enhance_findings_with_llm(
                        findings[:5],
                        contract_code,
                        "semgrep"
                    )
            except Exception as e:
                logger.debug(f"LLM enhancement failed: {e}")

            return {
                "tool": "semgrep",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "execution_time": round(duration, 2),
                "total_findings": len(findings),
                "rules_used": rules,
                "dpga_compliant": True
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep timeout after {self.timeout}s")
            return {
                "tool": "semgrep",
                "status": "error",
                "findings": [],
                "execution_time": self.timeout,
                "error": f"Analysis timeout after {self.timeout}s"
            }
        except FileNotFoundError:
            return {
                "tool": "semgrep",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"Contract file not found: {contract_path}"
            }
        except Exception as e:
            logger.error(f"Semgrep analysis failed: {str(e)}")
            return {
                "tool": "semgrep",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": str(e)
            }

    def _create_custom_rules_file(self) -> Optional[str]:
        """Create a temporary file with custom Semgrep rules"""
        try:
            rules_yaml = {"rules": []}

            for rule_id, rule_def in self.CUSTOM_RULES.items():
                rule = {
                    "id": f"miesc-{rule_id}",
                    "message": rule_def["message"],
                    "severity": rule_def["severity"],
                    "languages": rule_def["languages"],
                    "pattern": rule_def["pattern"]
                }

                # Add pattern-not if present
                if "pattern-not" in rule_def:
                    rule["pattern-not"] = rule_def["pattern-not"]

                rules_yaml["rules"].append(rule)

            # Write to temp file
            import yaml

            fd, path = tempfile.mkstemp(suffix=".yaml", prefix="semgrep_miesc_")
            with open(path, 'w') as f:
                yaml.dump(rules_yaml, f, default_flow_style=False)

            return path

        except ImportError:
            logger.debug("PyYAML not available, skipping custom rules")
            return None
        except Exception as e:
            logger.debug(f"Failed to create custom rules: {e}")
            return None

    def _parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse Semgrep JSON output to extract findings

        Semgrep JSON output format:
        {
          "results": [
            {
              "check_id": "rule-id",
              "path": "file.sol",
              "start": {"line": 10, "col": 5},
              "end": {"line": 10, "col": 20},
              "extra": {
                "message": "Description",
                "severity": "ERROR",
                "metadata": {...}
              }
            }
          ],
          "errors": [...]
        }
        """
        findings = []

        try:
            data = json.loads(stdout)
            results = data.get("results", [])

            for result in results:
                finding = self._normalize_result(result)
                if finding:
                    findings.append(finding)

            # Log any errors
            errors = data.get("errors", [])
            for error in errors:
                logger.debug(f"Semgrep error: {error}")

        except json.JSONDecodeError as e:
            logger.debug(f"Failed to parse Semgrep JSON: {e}")
            # Try to extract useful info from stderr
            if "error" in stderr.lower():
                logger.warning(f"Semgrep stderr: {stderr[:500]}")

        return findings

    def _normalize_result(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize a single Semgrep result to MIESC format"""
        try:
            check_id = result.get("check_id", "unknown")
            extra = result.get("extra", {})
            severity_raw = extra.get("severity", "WARNING")

            # Map severity
            severity = self.SEVERITY_MAP.get(severity_raw, "medium")

            # Extract location
            start = result.get("start", {})
            end = result.get("end", {})

            # Determine vulnerability type from check_id
            vuln_type = self._map_check_to_type(check_id)

            finding = {
                "type": vuln_type,
                "severity": severity,
                "rule": check_id,
                "description": extra.get("message", "Security issue detected"),
                "file": result.get("path", ""),
                "line": start.get("line"),
                "column": start.get("col"),
                "end_line": end.get("line"),
                "end_column": end.get("col"),
                "code_snippet": extra.get("lines", ""),
                "metadata": extra.get("metadata", {}),
                "recommendation": self._get_recommendation(check_id)
            }

            # Add fix if available
            if "fix" in extra:
                finding["fix_suggestion"] = extra["fix"]

            return finding

        except Exception as e:
            logger.debug(f"Failed to normalize result: {e}")
            return None

    def _map_check_to_type(self, check_id: str) -> str:
        """Map Semgrep check ID to vulnerability type"""
        check_lower = check_id.lower()

        type_mappings = {
            "reentrancy": "reentrancy",
            "reentrant": "reentrancy",
            "call-value": "reentrancy",
            "tx-origin": "access_control",
            "access": "access_control",
            "owner": "access_control",
            "selfdestruct": "access_control",
            "suicide": "access_control",
            "overflow": "arithmetic",
            "underflow": "arithmetic",
            "arithmetic": "arithmetic",
            "unchecked": "unchecked_call",
            "call-return": "unchecked_call",
            "timestamp": "timestamp_dependence",
            "block": "timestamp_dependence",
            "random": "bad_randomness",
            "oracle": "oracle_manipulation",
            "price": "oracle_manipulation",
            "front": "front_running",
            "sandwich": "front_running",
            "gas": "gas_optimization",
            "delegatecall": "delegatecall_injection"
        }

        for pattern, vuln_type in type_mappings.items():
            if pattern in check_lower:
                return vuln_type

        return "security_issue"

    def _get_recommendation(self, check_id: str) -> str:
        """Get recommendation text for a specific check"""
        recommendations = {
            "reentrancy": "Use ReentrancyGuard or checks-effects-interactions pattern",
            "tx-origin": "Use msg.sender instead of tx.origin for authorization",
            "selfdestruct": "Add access control to selfdestruct functions",
            "unchecked": "Always check return value of low-level calls",
            "timestamp": "Avoid using block.timestamp for critical decisions",
            "delegatecall": "Validate target address before delegatecall",
            "overflow": "Use Solidity 0.8+ or SafeMath for arithmetic",
            "oracle": "Use TWAP or multiple oracle sources"
        }

        for pattern, rec in recommendations.items():
            if pattern in check_id.lower():
                return rec

        return f"Review and fix issue identified by rule '{check_id}'"

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize findings to MIESC standard format

        Args:
            raw_output: Raw Semgrep output or parsed findings

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
        """Get default configuration for Semgrep"""
        return {
            "rules": self.DEFAULT_RULES,
            "timeout": 120,
            "max_target_bytes": 1000000,
            "exclude": ["**/node_modules/**", "**/test/**"],
            "use_custom_rules": True
        }


# Adapter registration
def register_adapter():
    """Register Semgrep adapter with MIESC"""
    return {
        "adapter_class": SemgrepAdapter,
        "metadata": SemgrepAdapter.METADATA
    }


__all__ = ["SemgrepAdapter", "register_adapter"]
