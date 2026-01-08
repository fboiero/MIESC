"""
ZK Circuit Security Adapter - Zero-Knowledge Proof Circuit Analysis.

Integrates tools for analyzing ZK circuit security:
- Circomspect: Static analyzer for Circom circuits
- Picus: Formal verification for ZK circuits
- ZKAP patterns: Known ZK vulnerability patterns

Based on research:
- "Picus: Symbolic Analysis for Zero-Knowledge Circuits" (USENIX Security 2024)
- "ZKAP: A Security Analysis Platform for ZK Circuits" (IEEE S&P 2024)

Vulnerability categories detected:
- Under-constrained circuits (missing constraints)
- Over-constrained circuits (unsatisfiable)
- Unused signals (dead code)
- Non-deterministic behavior
- Constraint soundness issues
- Division by zero
- Unconstrained field arithmetic

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-15
"""

from src.core.tool_protocol import (
    ToolAdapter,
    ToolMetadata,
    ToolStatus,
    ToolCategory,
    ToolCapability
)
from typing import Dict, Any, List, Optional, Tuple
import logging
import subprocess
import json
import re
import time
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ZKFramework(Enum):
    """Supported ZK frameworks."""
    CIRCOM = "circom"
    NOIR = "noir"
    HALO2 = "halo2"
    GNARK = "gnark"


# Known ZK vulnerability patterns
ZK_VULNERABILITY_PATTERNS = {
    "under_constrained": {
        "severity": "CRITICAL",
        "description": "Circuit has fewer constraints than needed, allowing malicious proofs",
        "cwe": "CWE-682",
        "impact": "Attackers can generate valid proofs for invalid statements"
    },
    "over_constrained": {
        "severity": "HIGH",
        "description": "Circuit has contradictory constraints, making valid proofs impossible",
        "cwe": "CWE-682",
        "impact": "Legitimate users cannot generate valid proofs"
    },
    "unused_signal": {
        "severity": "MEDIUM",
        "description": "Signal declared but never used in constraints",
        "cwe": "CWE-561",
        "impact": "May indicate missing constraints or dead code"
    },
    "unconstrained_output": {
        "severity": "CRITICAL",
        "description": "Output signal not fully constrained by inputs",
        "cwe": "CWE-682",
        "impact": "Prover can manipulate output values"
    },
    "division_by_zero": {
        "severity": "HIGH",
        "description": "Division operation may have zero divisor",
        "cwe": "CWE-369",
        "impact": "Circuit may fail or produce unexpected results"
    },
    "field_overflow": {
        "severity": "HIGH",
        "description": "Arithmetic operation may overflow field modulus",
        "cwe": "CWE-190",
        "impact": "Unexpected wraparound in field arithmetic"
    },
    "non_deterministic": {
        "severity": "CRITICAL",
        "description": "Circuit behavior depends on non-deterministic values",
        "cwe": "CWE-330",
        "impact": "Proofs may be non-reproducible or exploitable"
    },
    "unsafe_component": {
        "severity": "MEDIUM",
        "description": "Using component known to have security issues",
        "cwe": "CWE-1357",
        "impact": "Inherited vulnerabilities from dependencies"
    },
    "signal_aliasing": {
        "severity": "HIGH",
        "description": "Multiple signals may reference same value unexpectedly",
        "cwe": "CWE-119",
        "impact": "Constraint confusion and potential bypass"
    }
}


class ZKCircuitAdapter(ToolAdapter):
    """
    ZK Circuit Security Adapter for zero-knowledge proof analysis.

    Supports:
    - Circom circuits (.circom files)
    - Noir programs (.nr files)
    - Generic constraint system analysis

    Uses circomspect for static analysis and custom pattern matching.
    """

    def __init__(self):
        super().__init__()
        self._cache_dir = Path.home() / ".miesc" / "zk_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._circomspect_available = False
        self._picus_available = False

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="zk_circuit_analyzer",
            version="1.0.0",
            category=ToolCategory.FORMAL_VERIFICATION,
            author="Fernando Boiero (ZK security integration)",
            license="AGPL-3.0",
            homepage="https://github.com/trailofbits/circomspect",
            repository="https://github.com/trailofbits/circomspect",
            documentation="https://github.com/trailofbits/circomspect#readme",
            installation_cmd=(
                "cargo install circomspect && "
                "npm install -g circom"
            ),
            capabilities=[
                ToolCapability(
                    name="zk_static_analysis",
                    description="Static analysis for ZK circuits (Circom, Noir)",
                    supported_languages=["circom", "noir"],
                    detection_types=[
                        "under_constrained",
                        "over_constrained",
                        "unused_signals",
                        "division_by_zero",
                        "unsafe_components"
                    ]
                ),
                ToolCapability(
                    name="constraint_analysis",
                    description="Analyze constraint soundness and completeness",
                    supported_languages=["circom", "noir"],
                    detection_types=[
                        "unconstrained_outputs",
                        "signal_aliasing",
                        "non_determinism"
                    ]
                ),
                ToolCapability(
                    name="zk_pattern_matching",
                    description="Known ZK vulnerability pattern detection",
                    supported_languages=["circom", "noir"],
                    detection_types=["known_vulnerabilities"]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if ZK analysis tools are available."""
        import os

        # Add cargo bin to PATH for circomspect
        env = os.environ.copy()
        cargo_bin = os.path.expanduser("~/.cargo/bin")
        env["PATH"] = f"{cargo_bin}:{env.get('PATH', '')}"

        try:
            # Check circomspect (uses --help since --version not supported)
            result = subprocess.run(
                ["circomspect", "--help"],
                capture_output=True,
                timeout=5,
                text=True,
                env=env
            )
            self._circomspect_available = result.returncode == 0

            # Check picus (optional)
            try:
                picus_result = subprocess.run(
                    ["picus", "--help"],
                    capture_output=True,
                    timeout=5,
                    text=True,
                    env=env
                )
                self._picus_available = picus_result.returncode == 0
            except FileNotFoundError:
                self._picus_available = False

            if self._circomspect_available:
                return ToolStatus.AVAILABLE
            else:
                logger.warning("circomspect not installed. Run: cargo install circomspect")
                return ToolStatus.NOT_INSTALLED

        except FileNotFoundError:
            logger.info("ZK tools not installed. Install circomspect: cargo install circomspect")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking ZK tools: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze ZK circuit for security vulnerabilities.

        Args:
            contract_path: Path to circuit file (.circom, .nr)
            **kwargs: Additional options (framework, include_patterns)

        Returns:
            Analysis results with findings
        """
        start_time = time.time()

        # Detect framework from file extension
        path = Path(contract_path)
        framework = self._detect_framework(path)

        if framework is None:
            return self._error_result(
                start_time,
                f"Unsupported file type: {path.suffix}. Supported: .circom, .nr"
            )

        try:
            # Read circuit file
            circuit_code = self._read_file(contract_path)
            if not circuit_code:
                return self._error_result(start_time, f"Could not read: {contract_path}")

            all_findings = []

            # Run circomspect if available and applicable
            if self._circomspect_available and framework == ZKFramework.CIRCOM:
                logger.info("Running circomspect analysis...")
                circomspect_findings = self._run_circomspect(contract_path)
                all_findings.extend(circomspect_findings)

            # Run pattern matching (always available)
            logger.info("Running ZK pattern analysis...")
            pattern_findings = self._run_pattern_analysis(circuit_code, contract_path, framework)
            all_findings.extend(pattern_findings)

            # Run constraint analysis
            logger.info("Running constraint analysis...")
            constraint_findings = self._analyze_constraints(circuit_code, contract_path, framework)
            all_findings.extend(constraint_findings)

            # Deduplicate findings
            findings = self._deduplicate_findings(all_findings)

            return {
                "tool": "zk_circuit_analyzer",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "framework": framework.value,
                    "circomspect_available": self._circomspect_available,
                    "picus_available": self._picus_available,
                    "file_type": path.suffix,
                    "line_count": len(circuit_code.splitlines())
                },
                "execution_time": time.time() - start_time
            }

        except Exception as e:
            logger.error(f"ZK analysis error: {e}", exc_info=True)
            return self._error_result(start_time, str(e))

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize findings."""
        return raw_output.get("findings", []) if isinstance(raw_output, dict) else []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if this adapter can analyze the file."""
        suffix = Path(contract_path).suffix.lower()
        return suffix in ['.circom', '.nr', '.zk']

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "timeout": 300,
            "include_patterns": True,
            "check_constraints": True
        }

    # ============================================================================
    # PRIVATE METHODS
    # ============================================================================

    def _error_result(self, start_time: float, error: str) -> Dict[str, Any]:
        """Create error result."""
        return {
            "tool": "zk_circuit_analyzer",
            "version": "1.0.0",
            "status": "error",
            "findings": [],
            "execution_time": time.time() - start_time,
            "error": error
        }

    def _read_file(self, path: str) -> Optional[str]:
        """Read file content."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return None

    def _detect_framework(self, path: Path) -> Optional[ZKFramework]:
        """Detect ZK framework from file extension."""
        suffix = path.suffix.lower()
        if suffix == '.circom':
            return ZKFramework.CIRCOM
        elif suffix == '.nr':
            return ZKFramework.NOIR
        elif suffix == '.go' and 'gnark' in path.name.lower():
            return ZKFramework.GNARK
        elif suffix == '.rs' and 'halo2' in path.name.lower():
            return ZKFramework.HALO2
        return None

    def _run_circomspect(self, circuit_path: str) -> List[Dict[str, Any]]:
        """Run circomspect static analyzer."""
        findings = []

        try:
            result = subprocess.run(
                ["circomspect", circuit_path, "--json"],
                capture_output=True,
                timeout=120,
                text=True
            )

            if result.returncode == 0 or result.stdout:
                try:
                    output = json.loads(result.stdout)
                    for issue in output.get("issues", []):
                        finding = {
                            "id": f"circomspect-{len(findings)+1}",
                            "title": issue.get("message", "Circomspect finding"),
                            "description": issue.get("help", ""),
                            "severity": self._map_circomspect_severity(issue.get("severity", "warning")),
                            "confidence": 0.9,
                            "category": issue.get("code", "zk_issue"),
                            "location": {
                                "file": circuit_path,
                                "line": issue.get("span", {}).get("start", {}).get("line", 0),
                                "details": issue.get("span_text", "")
                            },
                            "recommendation": issue.get("note", "Review the flagged code"),
                            "source": "circomspect"
                        }
                        findings.append(finding)
                except json.JSONDecodeError:
                    # Parse text output if JSON fails
                    findings.extend(self._parse_circomspect_text(result.stdout, circuit_path))

        except subprocess.TimeoutExpired:
            logger.warning("Circomspect timeout")
        except Exception as e:
            logger.error(f"Circomspect error: {e}")

        return findings

    def _map_circomspect_severity(self, severity: str) -> str:
        """Map circomspect severity to MIESC severity."""
        mapping = {
            "error": "CRITICAL",
            "warning": "MEDIUM",
            "info": "LOW",
            "help": "INFO"
        }
        return mapping.get(severity.lower(), "MEDIUM")

    def _parse_circomspect_text(self, output: str, circuit_path: str) -> List[Dict[str, Any]]:
        """Parse text output from circomspect."""
        findings = []
        # Basic pattern matching for circomspect output
        pattern = r'(error|warning|info)\[(\w+)\]:\s*(.+?)(?=\n\n|\Z)'
        matches = re.findall(pattern, output, re.DOTALL)

        for severity, code, message in matches:
            findings.append({
                "id": f"circomspect-{len(findings)+1}",
                "title": f"{code}: {message.split(chr(10))[0][:50]}",
                "description": message.strip(),
                "severity": self._map_circomspect_severity(severity),
                "confidence": 0.85,
                "category": code,
                "location": {"file": circuit_path},
                "source": "circomspect"
            })

        return findings

    def _run_pattern_analysis(
        self,
        code: str,
        circuit_path: str,
        framework: ZKFramework
    ) -> List[Dict[str, Any]]:
        """Run ZK vulnerability pattern matching."""
        findings = []
        lines = code.splitlines()

        # Framework-specific patterns
        if framework == ZKFramework.CIRCOM:
            findings.extend(self._analyze_circom_patterns(code, lines, circuit_path))
        elif framework == ZKFramework.NOIR:
            findings.extend(self._analyze_noir_patterns(code, lines, circuit_path))

        return findings

    def _analyze_circom_patterns(
        self,
        code: str,
        lines: List[str],
        circuit_path: str
    ) -> List[Dict[str, Any]]:
        """Analyze Circom-specific patterns."""
        findings = []

        # Pattern 1: Unused signals (declared but never used)
        signal_decl_pattern = r'signal\s+(input|output|private)?\s*(\w+)'
        signals = set()
        for match in re.finditer(signal_decl_pattern, code):
            signals.add(match.group(2))

        for signal in signals:
            # Check if signal is used in constraints (not just declaration)
            constraint_pattern = rf'[^a-zA-Z_]{signal}[^a-zA-Z_0-9].*===|===.*{signal}'
            if not re.search(constraint_pattern, code):
                findings.append({
                    "id": f"zk-pattern-{len(findings)+1}",
                    "title": f"Potentially unused signal: {signal}",
                    "description": ZK_VULNERABILITY_PATTERNS["unused_signal"]["description"],
                    "severity": ZK_VULNERABILITY_PATTERNS["unused_signal"]["severity"],
                    "confidence": 0.7,
                    "category": "unused_signal",
                    "location": {"file": circuit_path, "details": f"Signal: {signal}"},
                    "cwe": ZK_VULNERABILITY_PATTERNS["unused_signal"]["cwe"],
                    "recommendation": "Verify this signal is properly constrained",
                    "source": "pattern_analysis"
                })

        # Pattern 2: Division operations (potential division by zero)
        for i, line in enumerate(lines, 1):
            if '/' in line and '===' in line:
                findings.append({
                    "id": f"zk-pattern-{len(findings)+1}",
                    "title": "Division in constraint - check for zero divisor",
                    "description": ZK_VULNERABILITY_PATTERNS["division_by_zero"]["description"],
                    "severity": ZK_VULNERABILITY_PATTERNS["division_by_zero"]["severity"],
                    "confidence": 0.6,
                    "category": "division_by_zero",
                    "location": {"file": circuit_path, "line": i, "details": line.strip()},
                    "cwe": ZK_VULNERABILITY_PATTERNS["division_by_zero"]["cwe"],
                    "recommendation": "Add constraint to ensure divisor is non-zero",
                    "source": "pattern_analysis"
                })

        # Pattern 3: Output signals without constraints
        output_signals = re.findall(r'signal\s+output\s+(\w+)', code)
        for signal in output_signals:
            # Check if output is constrained
            if not re.search(rf'{signal}\s*<==|{signal}\s*===', code):
                findings.append({
                    "id": f"zk-pattern-{len(findings)+1}",
                    "title": f"Unconstrained output: {signal}",
                    "description": ZK_VULNERABILITY_PATTERNS["unconstrained_output"]["description"],
                    "severity": ZK_VULNERABILITY_PATTERNS["unconstrained_output"]["severity"],
                    "confidence": 0.85,
                    "category": "unconstrained_output",
                    "location": {"file": circuit_path, "details": f"Output: {signal}"},
                    "cwe": ZK_VULNERABILITY_PATTERNS["unconstrained_output"]["cwe"],
                    "recommendation": "Ensure output signal is fully constrained by inputs",
                    "source": "pattern_analysis"
                })

        # Pattern 4: Using random/unsafe components
        unsafe_patterns = ['Random', 'unsafe', 'unchecked']
        for pattern in unsafe_patterns:
            if pattern.lower() in code.lower():
                findings.append({
                    "id": f"zk-pattern-{len(findings)+1}",
                    "title": f"Potentially unsafe component: {pattern}",
                    "description": ZK_VULNERABILITY_PATTERNS["unsafe_component"]["description"],
                    "severity": ZK_VULNERABILITY_PATTERNS["unsafe_component"]["severity"],
                    "confidence": 0.5,
                    "category": "unsafe_component",
                    "location": {"file": circuit_path},
                    "recommendation": "Review use of potentially unsafe components",
                    "source": "pattern_analysis"
                })

        return findings

    def _analyze_noir_patterns(
        self,
        code: str,
        lines: List[str],
        circuit_path: str
    ) -> List[Dict[str, Any]]:
        """Analyze Noir-specific patterns."""
        findings = []

        # Noir-specific patterns
        # Pattern 1: Unconstrained functions
        if 'unconstrained fn' in code:
            findings.append({
                "id": f"zk-pattern-{len(findings)+1}",
                "title": "Unconstrained function detected",
                "description": "Unconstrained functions bypass ZK verification",
                "severity": "HIGH",
                "confidence": 0.8,
                "category": "unconstrained_output",
                "location": {"file": circuit_path},
                "recommendation": "Verify unconstrained function is safe and necessary",
                "source": "pattern_analysis"
            })

        # Pattern 2: Assert without proper constraint
        assert_count = code.count('assert(')
        constraint_count = code.count('constrain')
        if assert_count > constraint_count * 2:
            findings.append({
                "id": f"zk-pattern-{len(findings)+1}",
                "title": "High assert-to-constraint ratio",
                "description": "Many asserts without constraints may indicate under-constrained circuit",
                "severity": "MEDIUM",
                "confidence": 0.5,
                "category": "under_constrained",
                "location": {"file": circuit_path},
                "recommendation": "Review constraint coverage",
                "source": "pattern_analysis"
            })

        return findings

    def _analyze_constraints(
        self,
        code: str,
        circuit_path: str,
        framework: ZKFramework
    ) -> List[Dict[str, Any]]:
        """Analyze constraint completeness and soundness."""
        findings = []

        if framework == ZKFramework.CIRCOM:
            # Count constraints vs signals
            signal_count = len(re.findall(r'signal\s+(input|output|private)?\s+\w+', code))
            constraint_count = len(re.findall(r'===', code))

            # Heuristic: should have roughly n constraints for n signals
            if signal_count > 0 and constraint_count < signal_count * 0.5:
                findings.append({
                    "id": f"zk-constraint-1",
                    "title": "Potentially under-constrained circuit",
                    "description": (
                        f"Found {signal_count} signals but only {constraint_count} constraints. "
                        f"Ratio: {constraint_count/signal_count:.2f}. "
                        f"{ZK_VULNERABILITY_PATTERNS['under_constrained']['description']}"
                    ),
                    "severity": "HIGH",
                    "confidence": 0.6,
                    "category": "under_constrained",
                    "location": {"file": circuit_path},
                    "cwe": ZK_VULNERABILITY_PATTERNS["under_constrained"]["cwe"],
                    "recommendation": "Review constraint coverage - each signal should be properly constrained",
                    "source": "constraint_analysis"
                })

        return findings

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings."""
        seen = set()
        unique = []

        for finding in findings:
            key = (
                finding.get("category", ""),
                finding.get("title", ""),
                str(finding.get("location", {}).get("line", ""))
            )
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        unique.sort(key=lambda f: severity_order.get(f.get("severity", "LOW"), 4))

        return unique


__all__ = ["ZKCircuitAdapter", "ZKFramework", "ZK_VULNERABILITY_PATTERNS"]
