"""
Formal Verification Agent for MCP Architecture

Wraps Layer 5 tools: Certora Prover (Open Source), Z3
Publishes formal verification results and correctness proofs to Context Bus

Certora Prover Update (2025):
- Certora went open source in 2025!
- Install: npm install -g @certora/prover
- GitHub: https://github.com/Certora/CertoraProver
- No license required, community-driven
"""
import json
import logging
import subprocess
from typing import Dict, Any, List
from pathlib import Path
from src.agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class FormalAgent(BaseAgent):
    """
    Agent for formal verification (Layer 5 - MIESC)

    Capabilities:
    - Mathematical correctness proofs (Certora)
    - Temporal logic verification (CTL)
    - Invariant checking
    - Property verification with SMT solvers

    Published Context Types:
    - "formal_findings": Unified formal verification results
    - "certora_results": Certora Prover verification results
    - "z3_results": Z3 SMT solver results
    """

    def __init__(self):
        super().__init__(
            agent_name="FormalAgent",
            capabilities=[
                "formal_verification",
                "mathematical_proofs",
                "invariant_checking",
                "temporal_logic"
            ],
            agent_type="formal"
        )

    def get_context_types(self) -> List[str]:
        return [
            "formal_findings",
            "certora_results",
            "z3_results"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run formal verification tools on contract

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional parameters
                - spec_file: Path to CVL specification file
                - timeout: Timeout per tool in seconds (default: 1800)

        Returns:
            Dictionary with formal verification results
        """
        results = {
            "formal_findings": [],
            "certora_results": {},
            "z3_results": {}
        }

        spec_file = kwargs.get("spec_file")
        timeout = kwargs.get("timeout", 1800)  # 30 minutes default

        # Run Certora Prover
        if spec_file:
            logger.info(f"FormalAgent: Running Certora on {contract_path}")
            certora_data = self._run_certora(contract_path, spec_file, timeout)
            results["certora_results"] = certora_data
        else:
            logger.warning("FormalAgent: No spec file provided, skipping Certora")
            results["certora_results"] = {
                "error": "no_spec_file",
                "violations": []
            }

        # Z3 can be used for specific constraint solving
        logger.info(f"FormalAgent: Z3 available for constraint solving")
        results["z3_results"] = {
            "tool": "Z3",
            "status": "available",
            "message": "Z3 SMT solver ready for constraint solving"
        }

        # Aggregate findings
        results["formal_findings"] = self._aggregate_findings(
            results["certora_results"], results["z3_results"]
        )

        return results

    def _run_certora(self, contract_path: str, spec_file: str,
                     timeout: int) -> Dict[str, Any]:
        """
        Execute Certora Prover formal verification

        Returns:
            Dictionary with verification results
        """
        try:
            # Certora requires configuration and spec files
            cmd = [
                "certoraRun",
                contract_path,
                "--verify", f"{Path(contract_path).stem}:{spec_file}",
                "--msg", "MIESC automated verification"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Parse Certora output
            output = result.stdout
            violations = []
            verified_rules = []

            for line in output.split('\n'):
                if 'violation' in line.lower() or 'failed' in line.lower():
                    violations.append({
                        "rule": self._extract_rule_name(line),
                        "status": "violated",
                        "description": line.strip()
                    })
                elif 'verified' in line.lower() or 'passed' in line.lower():
                    verified_rules.append({
                        "rule": self._extract_rule_name(line),
                        "status": "verified"
                    })

            return {
                "tool": "Certora",
                "violations": violations,
                "verified_rules": verified_rules,
                "total_rules": len(violations) + len(verified_rules),
                "metadata": {
                    "exit_code": result.returncode,
                    "spec_file": spec_file,
                    "verification_type": "formal_proof"
                }
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Certora timeout after {timeout} seconds")
            return {"error": "timeout", "violations": []}
        except FileNotFoundError:
            logger.warning("Certora not installed. Install with: npm install -g @certora/prover")
            return {
                "error": "not_installed",
                "violations": [],
                "suggestion": "Install Certora open source: npm install -g @certora/prover"
            }
        except Exception as e:
            logger.error(f"Certora execution error: {e}")
            return {"error": str(e), "violations": []}

    def _extract_rule_name(self, line: str) -> str:
        """
        Extract rule name from Certora output

        Args:
            line: Output line from Certora

        Returns:
            Rule name or "unknown"
        """
        # Simple heuristic
        words = line.split()
        for word in words:
            if word.startswith("rule_") or word.endswith("Rule"):
                return word
        return "unknown"

    def _aggregate_findings(self, certora_data: Dict,
                           z3_data: Dict) -> List[Dict[str, Any]]:
        """
        Aggregate formal verification results into unified format

        Returns:
            List of unified findings
        """
        unified = []

        # Add Certora violations
        for violation in certora_data.get("violations", []):
            unified.append({
                "source": "Certora",
                "type": "rule_violation",
                "rule": violation.get("rule"),
                "severity": "Critical",
                "description": violation.get("description"),
                "layer": "formal",
                "verification_type": "mathematical_proof",
                "confidence": "Very High",  # Formal proofs have highest confidence
                "owasp_category": "SC10-Unknown-Unknowns"  # Spec-specific
            })

        # Add verified rules as positive findings
        for verified in certora_data.get("verified_rules", []):
            unified.append({
                "source": "Certora",
                "type": "verified_property",
                "rule": verified.get("rule"),
                "severity": "Info",
                "description": f"Rule {verified.get('rule')} mathematically verified",
                "layer": "formal",
                "status": "verified"
            })

        return unified

    def verify_invariant(self, invariant_spec: str) -> Dict[str, Any]:
        """
        Verify a specific invariant using Z3

        Args:
            invariant_spec: Invariant specification in SMT-LIB format

        Returns:
            Verification result
        """
        try:
            # Write spec to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
                f.write(invariant_spec)
                temp_path = f.name

            # Run Z3
            cmd = ["z3", temp_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            output = result.stdout.strip()

            return {
                "tool": "Z3",
                "result": output,
                "satisfiable": "sat" in output.lower(),
                "valid": "unsat" in output.lower()
            }

        except Exception as e:
            logger.error(f"Z3 verification error: {e}")
            return {"error": str(e)}
