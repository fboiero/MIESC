#!/usr/bin/env python3
"""
MIESC Complete Multi-Layer Audit Script
========================================

Ejecuta auditoría completa usando TODAS las capas del framework MIESC:
- Layer 1: Static Analysis (Slither, Aderyn, Solhint)
- Layer 2: Fuzzing (Echidna, Foundry)
- Layer 3: Symbolic Execution (Mythril, Manticore, Oyente)
- Layer 4: Invariant Testing (Foundry Invariants)
- Layer 5: Formal Verification (Certora, SMTChecker)
- Layer 6: Property-Based Testing (PropertyGPT simulation)
- Layer 7: AI Correlation (SmartLLM, DA-GNN, Threat Model)

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
"""

import os
import sys
import json
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import hashlib

# Add src to path for remediations module
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Try to import remediations database
try:
    from security.remediations import get_remediation_by_swc, get_remediation_by_type, get_security_checklist
    REMEDIATIONS_AVAILABLE = True
except ImportError:
    REMEDIATIONS_AVAILABLE = False

# Try to import Smart Correlation Engine
try:
    from ml.correlation_engine import SmartCorrelationEngine
    CORRELATION_ENGINE_AVAILABLE = True
except ImportError:
    CORRELATION_ENGINE_AVAILABLE = False

# Configuration
CONTRACTS_DIR = Path(__file__).parent / "contracts" / "audit"
OUTPUT_DIR = Path(__file__).parent / "audit_results"
VENV_BIN = Path(__file__).parent / "venv" / "bin"

@dataclass
class Finding:
    """Normalized finding structure"""
    tool: str
    layer: int
    layer_name: str
    severity: str
    title: str
    description: str
    location: Dict[str, Any]
    swc_id: Optional[str] = None
    cwe_id: Optional[str] = None
    confidence: str = "Medium"

    def to_dict(self):
        return asdict(self)

class MultiLayerAuditor:
    """Complete multi-layer security auditor"""

    def __init__(self, contract_path: str):
        self.contract_path = Path(contract_path)
        self.contract_name = self.contract_path.stem
        self.findings: List[Finding] = []
        self.correlated_findings: List = []  # Smart Correlation Engine results
        self.layer_results: Dict[str, Any] = {}
        self.errors: List[str] = []

    def run_complete_audit(self) -> Dict[str, Any]:
        """Execute all layers sequentially"""
        print(f"\n{'='*70}")
        print(f"🔍 MIESC Multi-Layer Audit: {self.contract_name}")
        print(f"{'='*70}")

        # Layer 1: Static Analysis
        self._run_layer_1_static()

        # Layer 2: Fuzzing
        self._run_layer_2_fuzzing()

        # Layer 3: Symbolic Execution
        self._run_layer_3_symbolic()

        # Layer 4: Invariant Testing
        self._run_layer_4_invariants()

        # Layer 5: Formal Verification
        self._run_layer_5_formal()

        # Layer 6: Property-Based Testing
        self._run_layer_6_property()

        # Layer 7: AI Correlation
        self._run_layer_7_ai()

        return self._generate_report()

    def _run_layer_1_static(self):
        """Layer 1: Static Analysis Tools"""
        print(f"\n📊 Layer 1: Static Analysis")
        print("-" * 40)

        # 1.1 Slither
        self._run_slither()

        # 1.2 Aderyn
        self._run_aderyn()

        # 1.3 Solhint
        self._run_solhint()

    def _run_slither(self):
        """Run Slither static analyzer"""
        try:
            print("   → Slither...")
            cmd = [str(VENV_BIN / "slither"), str(self.contract_path), "--json", "-"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.stdout:
                data = json.loads(result.stdout)
                detectors = data.get("results", {}).get("detectors", [])

                for d in detectors:
                    self.findings.append(Finding(
                        tool="Slither",
                        layer=1,
                        layer_name="Static Analysis",
                        severity=d.get("impact", "Medium"),
                        title=d.get("check", "Unknown"),
                        description=d.get("description", "")[:200],
                        location={"elements": len(d.get("elements", []))},
                        confidence=d.get("confidence", "Medium")
                    ))

                self.layer_results["slither"] = {
                    "status": "success",
                    "findings": len(detectors),
                    "detectors": [d.get("check") for d in detectors[:10]]
                }
                print(f"      ✓ {len(detectors)} findings")
            else:
                self.layer_results["slither"] = {"status": "no_output", "findings": 0}
                print("      ✓ No issues")

        except Exception as e:
            self.errors.append(f"Slither: {str(e)}")
            self.layer_results["slither"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_aderyn(self):
        """Run Aderyn static analyzer"""
        try:
            print("   → Aderyn...")
            # Aderyn needs to run from project root with foundry structure
            cmd = ["aderyn", str(self.contract_path), "--output", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=str(self.contract_path.parent))

            # Aderyn outputs to report.json by default
            report_path = self.contract_path.parent / "report.json"
            if report_path.exists():
                with open(report_path) as f:
                    data = json.load(f)
                findings = data.get("high_issues", []) + data.get("medium_issues", []) + data.get("low_issues", [])

                for issue in findings[:20]:
                    self.findings.append(Finding(
                        tool="Aderyn",
                        layer=1,
                        layer_name="Static Analysis",
                        severity=issue.get("severity", "Medium"),
                        title=issue.get("title", "Unknown"),
                        description=issue.get("description", "")[:200],
                        location={"instances": issue.get("instances", [])}
                    ))

                self.layer_results["aderyn"] = {"status": "success", "findings": len(findings)}
                print(f"      ✓ {len(findings)} findings")
                report_path.unlink()  # Clean up
            else:
                self.layer_results["aderyn"] = {"status": "no_output", "findings": 0}
                print("      ✓ No issues")

        except Exception as e:
            self.errors.append(f"Aderyn: {str(e)}")
            self.layer_results["aderyn"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_solhint(self):
        """Run Solhint linter"""
        try:
            print("   → Solhint...")
            cmd = ["solhint", str(self.contract_path), "-f", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, list):
                        for file_result in data:
                            for msg in file_result.get("messages", [])[:10]:
                                self.findings.append(Finding(
                                    tool="Solhint",
                                    layer=1,
                                    layer_name="Static Analysis",
                                    severity="Low" if msg.get("severity") == 1 else "Medium",
                                    title=msg.get("ruleId", "Unknown"),
                                    description=msg.get("message", ""),
                                    location={"line": msg.get("line", 0)}
                                ))
                        total = sum(len(f.get("messages", [])) for f in data)
                        self.layer_results["solhint"] = {"status": "success", "findings": total}
                        print(f"      ✓ {total} findings")
                except json.JSONDecodeError:
                    self.layer_results["solhint"] = {"status": "parse_error"}
                    print("      ⚠ Parse error")
            else:
                self.layer_results["solhint"] = {"status": "no_output", "findings": 0}
                print("      ✓ No issues")

        except Exception as e:
            self.errors.append(f"Solhint: {str(e)}")
            self.layer_results["solhint"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_layer_2_fuzzing(self):
        """Layer 2: Fuzzing Tools"""
        print(f"\n🎲 Layer 2: Fuzzing")
        print("-" * 40)

        # 2.1 Echidna
        self._run_echidna()

        # 2.2 Foundry Fuzz
        self._run_foundry_fuzz()

    def _run_echidna(self):
        """Run Echidna fuzzer"""
        try:
            print("   → Echidna...")
            # Echidna needs test contract with properties
            cmd = ["echidna", str(self.contract_path), "--test-mode", "assertion",
                   "--test-limit", "1000", "--format", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                self.layer_results["echidna"] = {
                    "status": "success",
                    "message": "Fuzzing completed - no property violations"
                }
                print("      ✓ Fuzzing passed")
            else:
                # Check for violations
                if "failed" in result.stdout.lower() or "failed" in result.stderr.lower():
                    self.findings.append(Finding(
                        tool="Echidna",
                        layer=2,
                        layer_name="Fuzzing",
                        severity="High",
                        title="Property Violation",
                        description="Echidna found a property violation during fuzzing",
                        location={"output": result.stdout[:200]}
                    ))
                    self.layer_results["echidna"] = {"status": "violation_found", "findings": 1}
                    print("      ⚠ Property violation found!")
                else:
                    self.layer_results["echidna"] = {"status": "completed", "findings": 0}
                    print("      ✓ No violations")

        except subprocess.TimeoutExpired:
            self.layer_results["echidna"] = {"status": "timeout"}
            print("      ⚠ Timeout")
        except Exception as e:
            self.errors.append(f"Echidna: {str(e)}")
            self.layer_results["echidna"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_foundry_fuzz(self):
        """Run Foundry fuzzer"""
        try:
            print("   → Foundry Fuzz...")
            # Check if there's a foundry project
            foundry_toml = self.contract_path.parent.parent / "foundry.toml"
            if foundry_toml.exists():
                cmd = ["forge", "test", "--fuzz-runs", "256", "--json"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                                       cwd=str(self.contract_path.parent.parent))
                self.layer_results["foundry_fuzz"] = {
                    "status": "success" if result.returncode == 0 else "test_failures",
                    "output": result.stdout[:500] if result.stdout else "No output"
                }
                print(f"      ✓ Fuzz tests {'passed' if result.returncode == 0 else 'completed with failures'}")
            else:
                self.layer_results["foundry_fuzz"] = {"status": "no_foundry_project"}
                print("      ⚠ No foundry.toml found")

        except Exception as e:
            self.errors.append(f"Foundry Fuzz: {str(e)}")
            self.layer_results["foundry_fuzz"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_layer_3_symbolic(self):
        """Layer 3: Symbolic Execution"""
        print(f"\n🔬 Layer 3: Symbolic Execution")
        print("-" * 40)

        # 3.1 Mythril
        self._run_mythril()

        # 3.2 Manticore (if available)
        self._run_manticore()

        # 3.3 Oyente (via Docker)
        self._run_oyente()

    def _run_mythril(self):
        """Run Mythril symbolic analyzer"""
        try:
            print("   → Mythril...")
            cmd = [str(VENV_BIN / "myth"), "analyze", str(self.contract_path),
                   "-o", "json", "--execution-timeout", "60"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    issues = data.get("issues", [])

                    for issue in issues:
                        self.findings.append(Finding(
                            tool="Mythril",
                            layer=3,
                            layer_name="Symbolic Execution",
                            severity=issue.get("severity", "Medium"),
                            title=issue.get("title", "Unknown"),
                            description=issue.get("description", "")[:200],
                            location={"address": issue.get("address", "")},
                            swc_id=issue.get("swc-id", "")
                        ))

                    self.layer_results["mythril"] = {"status": "success", "findings": len(issues)}
                    print(f"      ✓ {len(issues)} findings")
                except json.JSONDecodeError:
                    self.layer_results["mythril"] = {"status": "no_issues", "findings": 0}
                    print("      ✓ No issues")
            else:
                self.layer_results["mythril"] = {"status": "no_output", "findings": 0}
                print("      ✓ No issues")

        except subprocess.TimeoutExpired:
            self.layer_results["mythril"] = {"status": "timeout"}
            print("      ⚠ Timeout (symbolic execution is slow)")
        except Exception as e:
            self.errors.append(f"Mythril: {str(e)}")
            self.layer_results["mythril"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_manticore(self):
        """Run Manticore symbolic analyzer"""
        try:
            print("   → Manticore...")
            # Manticore has issues with Python 3.11, try anyway
            env = os.environ.copy()
            env["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

            cmd = [str(VENV_BIN / "manticore"), str(self.contract_path),
                   "--quick-mode", "--contract", self.contract_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)

            if "vulnerability" in result.stdout.lower() or "bug" in result.stdout.lower():
                self.findings.append(Finding(
                    tool="Manticore",
                    layer=3,
                    layer_name="Symbolic Execution",
                    severity="High",
                    title="Potential Vulnerability",
                    description="Manticore detected potential vulnerability",
                    location={"output": result.stdout[:200]}
                ))
                self.layer_results["manticore"] = {"status": "success", "findings": 1}
                print("      ✓ Vulnerability found")
            else:
                self.layer_results["manticore"] = {"status": "success", "findings": 0}
                print("      ✓ No vulnerabilities")

        except subprocess.TimeoutExpired:
            self.layer_results["manticore"] = {"status": "timeout"}
            print("      ⚠ Timeout")
        except Exception as e:
            self.errors.append(f"Manticore: {str(e)}")
            self.layer_results["manticore"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_oyente(self):
        """Run Oyente via Docker"""
        try:
            print("   → Oyente (Docker)...")
            # Check if docker is available
            docker_check = subprocess.run(["docker", "info"], capture_output=True)
            if docker_check.returncode != 0:
                self.layer_results["oyente"] = {"status": "docker_not_running"}
                print("      ⚠ Docker not running")
                return

            # Run Oyente container
            cmd = [
                "docker", "run", "--rm", "-v", f"{self.contract_path.parent}:/contracts",
                "luongnguyen/oyente", "-s", f"/contracts/{self.contract_path.name}"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            # Parse Oyente output
            vuln_keywords = ["vulnerability", "reentrancy", "timestamp", "callstack"]
            findings_count = 0
            for keyword in vuln_keywords:
                if keyword in result.stdout.lower():
                    findings_count += 1
                    self.findings.append(Finding(
                        tool="Oyente",
                        layer=3,
                        layer_name="Symbolic Execution",
                        severity="Medium",
                        title=f"Potential {keyword.title()} Issue",
                        description=f"Oyente detected potential {keyword} vulnerability",
                        location={}
                    ))

            self.layer_results["oyente"] = {"status": "success", "findings": findings_count}
            print(f"      ✓ {findings_count} potential issues")

        except subprocess.TimeoutExpired:
            self.layer_results["oyente"] = {"status": "timeout"}
            print("      ⚠ Timeout")
        except Exception as e:
            self.errors.append(f"Oyente: {str(e)}")
            self.layer_results["oyente"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_layer_4_invariants(self):
        """Layer 4: Invariant Testing"""
        print(f"\n🔒 Layer 4: Invariant Testing")
        print("-" * 40)

        # Foundry Invariants
        try:
            print("   → Foundry Invariants...")
            foundry_toml = self.contract_path.parent.parent / "foundry.toml"
            if foundry_toml.exists():
                cmd = ["forge", "test", "--match-test", "invariant", "--json"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                                       cwd=str(self.contract_path.parent.parent))
                self.layer_results["foundry_invariants"] = {
                    "status": "success" if result.returncode == 0 else "failures",
                }
                print(f"      ✓ Invariant tests {'passed' if result.returncode == 0 else 'completed'}")
            else:
                self.layer_results["foundry_invariants"] = {"status": "no_project"}
                print("      ⚠ No foundry project")
        except Exception as e:
            self.layer_results["foundry_invariants"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_layer_5_formal(self):
        """Layer 5: Formal Verification"""
        print(f"\n📐 Layer 5: Formal Verification")
        print("-" * 40)

        # 5.1 Certora
        self._run_certora()

        # 5.2 SMTChecker
        self._run_smtchecker()

    def _run_certora(self):
        """Run Certora Prover"""
        try:
            print("   → Certora...")
            certora_key = os.environ.get("CERTORAKEY")
            if not certora_key:
                self.layer_results["certora"] = {"status": "no_api_key"}
                print("      ⚠ No CERTORAKEY set")
                return

            # Check for spec file
            spec_file = self.contract_path.parent / "certora" / f"{self.contract_name}.spec"
            if not spec_file.exists():
                self.layer_results["certora"] = {"status": "no_spec_file"}
                print("      ⚠ No spec file found")
                return

            # Run Certora
            cmd = [str(VENV_BIN / "certoraRun"), str(self.contract_path),
                   "--verify", f"{self.contract_name}:{spec_file}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if "PASSED" in result.stdout:
                self.layer_results["certora"] = {"status": "verified"}
                print("      ✓ Verification passed")
            elif "FAILED" in result.stdout:
                self.findings.append(Finding(
                    tool="Certora",
                    layer=5,
                    layer_name="Formal Verification",
                    severity="Critical",
                    title="Specification Violation",
                    description="Certora found specification violation",
                    location={}
                ))
                self.layer_results["certora"] = {"status": "violation", "findings": 1}
                print("      ⚠ Specification violation found!")
            else:
                self.layer_results["certora"] = {"status": "submitted"}
                print("      ✓ Job submitted to Certora cloud")

        except Exception as e:
            self.errors.append(f"Certora: {str(e)}")
            self.layer_results["certora"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_smtchecker(self):
        """Run Solidity SMTChecker"""
        try:
            print("   → SMTChecker...")
            cmd = ["solc", str(self.contract_path), "--model-checker-engine", "all",
                   "--model-checker-timeout", "60000"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            warnings = result.stderr.count("Warning")
            errors = result.stderr.count("Error")

            if warnings > 0 or errors > 0:
                self.findings.append(Finding(
                    tool="SMTChecker",
                    layer=5,
                    layer_name="Formal Verification",
                    severity="Medium" if warnings > 0 else "High",
                    title="SMT Analysis Warning",
                    description=f"SMTChecker found {warnings} warnings, {errors} errors",
                    location={}
                ))

            self.layer_results["smtchecker"] = {
                "status": "success",
                "warnings": warnings,
                "errors": errors
            }
            print(f"      ✓ {warnings} warnings, {errors} errors")

        except Exception as e:
            self.errors.append(f"SMTChecker: {str(e)}")
            self.layer_results["smtchecker"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_layer_6_property(self):
        """Layer 6: Property-Based Testing (PropertyGPT simulation)"""
        print(f"\n🧪 Layer 6: Property-Based Testing")
        print("-" * 40)

        try:
            print("   → PropertyGPT Analysis...")
            # Read contract and analyze for common property patterns
            with open(self.contract_path) as f:
                code = f.read()

            properties_found = []

            # Check for common vulnerability patterns
            patterns = {
                "reentrancy": r"\.call\{.*value.*\}.*\(",
                "unchecked_return": r"\.call\(",
                "tx_origin": r"tx\.origin",
                "selfdestruct": r"selfdestruct\(",
                "delegatecall": r"\.delegatecall\(",
                "timestamp": r"block\.timestamp",
                "access_control": r"onlyOwner|require\s*\(\s*msg\.sender",
            }

            import re
            for name, pattern in patterns.items():
                if re.search(pattern, code):
                    properties_found.append(name)

            if properties_found:
                for prop in properties_found:
                    self.findings.append(Finding(
                        tool="PropertyGPT",
                        layer=6,
                        layer_name="Property-Based Testing",
                        severity="Medium",
                        title=f"Property Check: {prop}",
                        description=f"Contract uses pattern that requires property verification: {prop}",
                        location={}
                    ))

            self.layer_results["propertygpt"] = {
                "status": "success",
                "properties_identified": properties_found
            }
            print(f"      ✓ {len(properties_found)} properties identified")

        except Exception as e:
            self.layer_results["propertygpt"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_layer_7_ai(self):
        """Layer 7: AI Correlation & Threat Modeling"""
        print(f"\n🤖 Layer 7: AI Correlation & Risk Engine")
        print("-" * 40)

        # 7.1 SmartLLM (Ollama)
        self._run_smartllm()

        # 7.2 Threat Model Analysis
        self._run_threat_model()

        # 7.3 Risk Correlation
        self._run_risk_correlation()

    def _run_smartllm(self):
        """Run SmartLLM analysis via Ollama"""
        try:
            print("   → SmartLLM (Ollama)...")
            # Check if Ollama is running
            ollama_check = subprocess.run(["ollama", "list"], capture_output=True, text=True)
            if ollama_check.returncode != 0:
                self.layer_results["smartllm"] = {"status": "ollama_not_running"}
                print("      ⚠ Ollama not running")
                return

            # Read contract
            with open(self.contract_path) as f:
                code = f.read()[:3000]  # Limit size

            # Run analysis with deepseek-coder or openhermes
            prompt = f"""Analyze this Solidity smart contract for security vulnerabilities.
List the top 3 security issues you find:

```solidity
{code}
```

Respond in JSON format: {{"vulnerabilities": [{{"name": "...", "severity": "High/Medium/Low", "description": "..."}}]}}"""

            cmd = ["ollama", "run", "deepseek-coder:6.7b", prompt]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.stdout:
                # Try to parse JSON from response
                try:
                    # Find JSON in response
                    import re
                    json_match = re.search(r'\{.*\}', result.stdout, re.DOTALL)
                    if json_match:
                        data = json.loads(json_match.group())
                        vulns = data.get("vulnerabilities", [])
                        for v in vulns[:3]:
                            self.findings.append(Finding(
                                tool="SmartLLM",
                                layer=7,
                                layer_name="AI Correlation",
                                severity=v.get("severity", "Medium"),
                                title=v.get("name", "AI-Detected Issue"),
                                description=v.get("description", "")[:200],
                                location={},
                                confidence="Medium"
                            ))
                        self.layer_results["smartllm"] = {"status": "success", "findings": len(vulns)}
                        print(f"      ✓ {len(vulns)} AI-detected issues")
                    else:
                        self.layer_results["smartllm"] = {"status": "no_json", "raw": result.stdout[:200]}
                        print("      ✓ Analysis complete (unstructured)")
                except:
                    self.layer_results["smartllm"] = {"status": "parse_error"}
                    print("      ✓ Analysis complete")
            else:
                self.layer_results["smartllm"] = {"status": "no_output"}
                print("      ⚠ No output")

        except subprocess.TimeoutExpired:
            self.layer_results["smartllm"] = {"status": "timeout"}
            print("      ⚠ Timeout")
        except Exception as e:
            self.layer_results["smartllm"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_threat_model(self):
        """Run STRIDE threat modeling"""
        try:
            print("   → Threat Model (STRIDE)...")

            with open(self.contract_path) as f:
                code = f.read()

            # STRIDE analysis patterns
            stride_threats = {
                "Spoofing": ["tx.origin", "ecrecover"],
                "Tampering": ["delegatecall", "selfdestruct", "sstore"],
                "Repudiation": ["emit", "event"],
                "Information Disclosure": ["public", "view", "pure"],
                "Denial of Service": ["loop", "while", "for", "require"],
                "Elevation of Privilege": ["onlyOwner", "admin", "owner", "require"]
            }

            threats_found = {}
            for threat, patterns in stride_threats.items():
                for pattern in patterns:
                    if pattern.lower() in code.lower():
                        if threat not in threats_found:
                            threats_found[threat] = []
                        threats_found[threat].append(pattern)

            for threat, patterns in threats_found.items():
                self.findings.append(Finding(
                    tool="ThreatModel",
                    layer=7,
                    layer_name="AI Correlation",
                    severity="Medium",
                    title=f"STRIDE: {threat}",
                    description=f"Potential {threat} threat vectors: {', '.join(patterns[:3])}",
                    location={}
                ))

            self.layer_results["threat_model"] = {
                "status": "success",
                "stride_analysis": threats_found
            }
            print(f"      ✓ {len(threats_found)} STRIDE categories identified")

        except Exception as e:
            self.layer_results["threat_model"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_risk_correlation(self):
        """Correlate findings using Smart Correlation Engine and calculate risk score"""
        try:
            print("   → Smart Correlation Engine...")

            # Use Smart Correlation Engine if available
            if CORRELATION_ENGINE_AVAILABLE and self.findings:
                self._run_smart_correlation()
            else:
                self._run_basic_correlation()

        except Exception as e:
            self.layer_results["risk_correlation"] = {"status": "error", "error": str(e)}
            print(f"      ✗ Error: {str(e)[:50]}")

    def _run_smart_correlation(self):
        """Run Smart Correlation Engine for advanced deduplication and confidence scoring"""
        engine = SmartCorrelationEngine(
            min_tools_for_validation=2,
            similarity_threshold=0.75,
        )

        # Group findings by tool
        findings_by_tool: Dict[str, List[Dict]] = {}
        for finding in self.findings:
            tool = finding.tool
            if tool not in findings_by_tool:
                findings_by_tool[tool] = []
            findings_by_tool[tool].append({
                'type': finding.title,
                'severity': finding.severity,
                'message': finding.description,
                'location': finding.location,
                'swc_id': finding.swc_id,
                'confidence': 0.7 if finding.confidence == "Medium" else (0.9 if finding.confidence == "High" else 0.5),
            })

        # Add findings to correlation engine
        for tool, tool_findings in findings_by_tool.items():
            engine.add_findings(tool, tool_findings)

        # Run correlation
        correlated = engine.correlate()
        stats = engine.get_statistics()

        # Store correlated findings for report
        self.correlated_findings = correlated

        # Calculate risk score from correlated findings
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "informational": 0.5}
        total_risk = 0
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for cf in correlated:
            sev = cf.severity.capitalize()
            if sev in severity_counts:
                severity_counts[sev] += 1
            # Weight by confidence
            total_risk += severity_weights.get(cf.severity, 1) * cf.final_confidence

        max_possible = len(correlated) * 10 if correlated else 1
        risk_score = min(100, (total_risk / max_possible) * 100)

        # Determine risk level
        if severity_counts["Critical"] > 0:
            risk_level = "CRITICAL"
        elif severity_counts["High"] > 2:
            risk_level = "HIGH"
        elif severity_counts["High"] > 0 or severity_counts["Medium"] > 3:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        self.layer_results["risk_correlation"] = {
            "status": "success",
            "engine": "SmartCorrelationEngine",
            "risk_score": round(risk_score, 1),
            "risk_level": risk_level,
            "severity_breakdown": severity_counts,
            "correlation_stats": {
                "original_findings": stats.get("original_findings", len(self.findings)),
                "correlated_findings": stats.get("total_correlated", len(correlated)),
                "deduplication_rate": stats.get("deduplication_rate", 0),
                "cross_validated": stats.get("cross_validated", 0),
                "avg_confidence": stats.get("average_confidence", 0),
            }
        }

        dedup_rate = stats.get("deduplication_rate", 0) * 100
        print(f"      ✓ Risk Score: {risk_score:.1f}/100 ({risk_level})")
        print(f"      ✓ Correlated: {len(correlated)}/{len(self.findings)} findings ({dedup_rate:.1f}% dedup)")
        print(f"      ✓ Cross-validated: {stats.get('cross_validated', 0)}")

    def _run_basic_correlation(self):
        """Fallback basic correlation without ML engine"""
        severity_weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0.5}

        total_risk = 0
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for finding in self.findings:
            sev = finding.severity
            if sev in severity_counts:
                severity_counts[sev] += 1
                total_risk += severity_weights.get(sev, 1)

        max_possible = len(self.findings) * 10 if self.findings else 1
        risk_score = min(100, (total_risk / max_possible) * 100)

        if severity_counts["Critical"] > 0:
            risk_level = "CRITICAL"
        elif severity_counts["High"] > 2:
            risk_level = "HIGH"
        elif severity_counts["High"] > 0 or severity_counts["Medium"] > 3:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        self.layer_results["risk_correlation"] = {
            "status": "success",
            "engine": "basic",
            "risk_score": round(risk_score, 1),
            "risk_level": risk_level,
            "severity_breakdown": severity_counts
        }
        print(f"      ✓ Risk Score: {risk_score:.1f}/100 ({risk_level})")

    def _generate_report(self) -> Dict[str, Any]:
        """Generate final audit report with remediations"""

        # Count findings by layer
        findings_by_layer = {}
        for finding in self.findings:
            layer_name = finding.layer_name
            if layer_name not in findings_by_layer:
                findings_by_layer[layer_name] = 0
            findings_by_layer[layer_name] += 1

        # Count findings by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for finding in self.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1

        # Count findings by tool
        findings_by_tool = {}
        for finding in self.findings:
            if finding.tool not in findings_by_tool:
                findings_by_tool[finding.tool] = 0
            findings_by_tool[finding.tool] += 1

        # Generate findings with remediations
        findings_with_remediations = []
        for f in self.findings:
            finding_dict = f.to_dict()

            # Try to add remediation
            if REMEDIATIONS_AVAILABLE:
                remediation = None
                # Try by SWC ID first
                if f.swc_id:
                    remediation = get_remediation_by_swc(f.swc_id)
                # Fallback to type matching
                if not remediation:
                    remediation = get_remediation_by_type(f.title)

                if remediation:
                    finding_dict["remediation"] = {
                        "title": remediation.title,
                        "fix": remediation.fix,
                        "example": remediation.example if remediation.example else None,
                        "references": remediation.references
                    }

            findings_with_remediations.append(finding_dict)

        # Get correlation stats
        correlation_stats = self.layer_results.get("risk_correlation", {}).get("correlation_stats", {})

        report = {
            "audit_info": {
                "contract": self.contract_name,
                "contract_path": str(self.contract_path),
                "timestamp": datetime.now().isoformat(),
                "miesc_version": "4.2.0",
                "total_layers_executed": 7,
                "remediations_enabled": REMEDIATIONS_AVAILABLE,
                "correlation_engine_enabled": CORRELATION_ENGINE_AVAILABLE
            },
            "summary": {
                "total_findings": len(self.findings),
                "correlated_findings": correlation_stats.get("correlated_findings", len(self.findings)),
                "deduplication_rate": correlation_stats.get("deduplication_rate", 0),
                "cross_validated": correlation_stats.get("cross_validated", 0),
                "by_severity": severity_counts,
                "by_layer": findings_by_layer,
                "by_tool": findings_by_tool,
                "risk_level": self.layer_results.get("risk_correlation", {}).get("risk_level", "UNKNOWN"),
                "risk_score": self.layer_results.get("risk_correlation", {}).get("risk_score", 0)
            },
            "layer_results": self.layer_results,
            "findings": findings_with_remediations,
            "correlated_findings": [f.to_dict() for f in self.correlated_findings] if self.correlated_findings else [],
            "errors": self.errors
        }

        # Add security checklist if available
        if REMEDIATIONS_AVAILABLE:
            report["security_checklist"] = get_security_checklist()

        return report


def main():
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║            MIESC v4.0.0 - Complete Multi-Layer Security Audit              ║
║          Multi-layer Intelligent Evaluation for Smart Contracts            ║
╠════════════════════════════════════════════════════════════════════════════╣
║  7 Defense Layers | 15+ Security Tools | AI-Powered Correlation            ║
║  Author: Fernando Boiero | UNDEF - IUA Córdoba                             ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)

    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Find contracts
    contracts = list(CONTRACTS_DIR.glob("*.sol"))

    if not contracts:
        print(f"❌ No contracts found in {CONTRACTS_DIR}")
        return

    print(f"📁 Found {len(contracts)} contracts to audit")

    all_results = []

    for contract in contracts:
        auditor = MultiLayerAuditor(str(contract))
        result = auditor.run_complete_audit()
        all_results.append(result)

        # Save individual result
        output_file = OUTPUT_DIR / f"{contract.stem}_multilayer_audit.json"
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n💾 Saved: {output_file.name}")

    # Generate consolidated report
    total_findings = sum(r["summary"]["total_findings"] for r in all_results)
    total_by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    total_by_layer = {}
    total_by_tool = {}

    for r in all_results:
        for sev, count in r["summary"]["by_severity"].items():
            if sev in total_by_severity:
                total_by_severity[sev] += count
        for layer, count in r["summary"]["by_layer"].items():
            total_by_layer[layer] = total_by_layer.get(layer, 0) + count
        for tool, count in r["summary"]["by_tool"].items():
            total_by_tool[tool] = total_by_tool.get(tool, 0) + count

    consolidated = {
        "audit_info": {
            "timestamp": datetime.now().isoformat(),
            "miesc_version": "4.0.0",
            "contracts_audited": len(all_results),
            "total_layers": 7
        },
        "summary": {
            "total_findings": total_findings,
            "by_severity": total_by_severity,
            "by_layer": total_by_layer,
            "by_tool": total_by_tool
        },
        "contracts": all_results
    }

    consolidated_file = OUTPUT_DIR / "consolidated_multilayer_report.json"
    with open(consolidated_file, "w") as f:
        json.dump(consolidated, f, indent=2)

    print(f"""
╔════════════════════════════════════════════════════════════════════════════╗
║                        MULTI-LAYER AUDIT COMPLETE                          ║
╠════════════════════════════════════════════════════════════════════════════╣
║  Contracts Audited: {len(all_results):>3}                                                   ║
║  Total Findings:    {total_findings:>3}                                                   ║
║                                                                            ║
║  📊 By Severity:                                                           ║
║     Critical: {total_by_severity['Critical']:>3}    High: {total_by_severity['High']:>3}    Medium: {total_by_severity['Medium']:>3}                       ║
║     Low:      {total_by_severity['Low']:>3}    Info: {total_by_severity['Info']:>3}                                       ║
║                                                                            ║
║  🏗️  By Layer:                                                              ║""")

    for layer, count in sorted(total_by_layer.items()):
        print(f"║     {layer:<30}: {count:>3}                            ║")

    print(f"""║                                                                            ║
║  🔧 By Tool:                                                               ║""")

    for tool, count in sorted(total_by_tool.items(), key=lambda x: -x[1])[:8]:
        print(f"║     {tool:<20}: {count:>3}                                        ║")

    print(f"""╠════════════════════════════════════════════════════════════════════════════╣
║  📂 Results: {str(OUTPUT_DIR):<59} ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)

    return consolidated


if __name__ == "__main__":
    main()
