"""
Dynamic Testing Agent for MCP Architecture

Wraps Layer 2 tools: Echidna, Medusa, Foundry Fuzz
Enhanced with Tool Adapters: VertigoAdapter (mutation testing)
Publishes fuzzing results and property violations to Context Bus
"""
import json
import logging
import subprocess
from typing import Dict, Any, List
from pathlib import Path
from src.agents.base_agent import BaseAgent
from src.integration.adapter_integration import integrate_dynamic_testing

logger = logging.getLogger(__name__)


class DynamicAgent(BaseAgent):
    """
    Agent for dynamic testing and fuzzing (Layer 2 - MIESC)

    Capabilities:
    - Property-based fuzzing (Echidna)
    - Coverage-guided fuzzing (Medusa)
    - Integrated fuzz testing (Foundry)
    - Invariant violation detection

    Published Context Types:
    - "dynamic_findings": Unified findings from all fuzzing tools
    - "echidna_results": Property violations from Echidna
    - "medusa_results": Coverage-guided fuzzing results
    - "foundry_results": Foundry fuzz test results
    """

    def __init__(self):
        super().__init__(
            agent_name="DynamicAgent",
            capabilities=[
                "property_fuzzing",
                "coverage_fuzzing",
                "invariant_testing",
                "edge_case_detection"
            ],
            agent_type="dynamic"
        )

    def get_context_types(self) -> List[str]:
        return [
            "dynamic_findings",
            "echidna_results",
            "medusa_results",
            "foundry_results",
            "vertigo_results"  # From VertigoAdapter (mutation testing)
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run all dynamic testing tools on contract

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional parameters
                - test_dir: Directory with test files
                - fuzz_runs: Number of fuzzing runs (default: 10000)
                - timeout: Timeout per tool in seconds (default: 300)

        Returns:
            Dictionary with results from all tools
        """
        results = {
            "dynamic_findings": [],
            "echidna_results": {},
            "medusa_results": {},
            "foundry_results": {}
        }

        fuzz_runs = kwargs.get("fuzz_runs", 10000)
        timeout = kwargs.get("timeout", 300)
        test_dir = kwargs.get("test_dir", "test")

        # Run Echidna
        logger.info(f"DynamicAgent: Running Echidna on {contract_path}")
        echidna_data = self._run_echidna(contract_path, fuzz_runs, timeout)
        results["echidna_results"] = echidna_data

        # Run Medusa
        logger.info(f"DynamicAgent: Running Medusa on {contract_path}")
        medusa_data = self._run_medusa(contract_path, fuzz_runs, timeout)
        results["medusa_results"] = medusa_data

        # Run Foundry Fuzz
        logger.info(f"DynamicAgent: Running Foundry Fuzz on {contract_path}")
        foundry_data = self._run_foundry_fuzz(test_dir, fuzz_runs, timeout)
        results["foundry_results"] = foundry_data

        # Aggregate findings from traditional tools
        results["dynamic_findings"] = self._aggregate_findings(
            echidna_data, medusa_data, foundry_data
        )

        # === ENHANCED: Integrate Tool Adapters (Layer 2 Enhancement) ===
        # Run VertigoAdapter for mutation testing via Integration Layer
        # This is OPTIONAL (DPGA compliant) - agent works without it
        try:
            logger.info("DynamicAgent: Integrating Vertigo Adapter (mutation testing)...")
            adapter_results = integrate_dynamic_testing(contract_path, **kwargs)

            # Extract Vertigo-specific results
            if "adapter_results" in adapter_results:
                vertigo_result = adapter_results["adapter_results"].get("vertigo", {})
                results["vertigo_results"] = vertigo_result

                # Merge adapter findings into dynamic_findings
                if "findings" in adapter_results:
                    results["dynamic_findings"].extend(adapter_results["findings"])

                # Add mutation testing metadata
                results["adapter_metadata"] = {
                    "mutation_score": adapter_results.get("metadata", {}).get("mutation_score", 0),
                    "adapters_executed": adapter_results.get("successful", 0),
                    "adapters_failed": adapter_results.get("failed", 0)
                }

                logger.info(
                    f"DynamicAgent: Vertigo adapter completed - "
                    f"Mutation score: {results['adapter_metadata']['mutation_score']}%"
                )

        except Exception as e:
            # Graceful degradation: Agent works even if adapter fails
            logger.warning(f"DynamicAgent: Vertigo adapter failed (non-critical): {e}")
            results["adapter_metadata"] = {
                "error": str(e),
                "adapters_executed": 0
            }

        return results

    def _run_echidna(self, contract_path: str, runs: int, timeout: int) -> Dict[str, Any]:
        """
        Execute Echidna property-based fuzzing

        Returns:
            Dictionary with property violations
        """
        try:
            # Echidna requires a config file
            echidna_config = {
                "testLimit": runs,
                "testMode": "property",
                "format": "json"
            }

            config_path = Path("echidna.yaml")

            # Run Echidna
            cmd = [
                "echidna",
                contract_path,
                "--config", str(config_path)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Parse output (Echidna outputs test results)
            output = result.stdout
            violations = []

            # Parse property violations from output
            for line in output.split('\n'):
                if 'failed' in line.lower() or 'violation' in line.lower():
                    violations.append({
                        "property": self._extract_property_name(line),
                        "status": "failed",
                        "description": line.strip()
                    })

            return {
                "tool": "Echidna",
                "violations": violations,
                "total_tests": runs,
                "metadata": {
                    "exit_code": result.returncode,
                    "mode": "property-based"
                }
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Echidna timeout after {timeout} seconds")
            return {"error": "timeout", "violations": []}
        except FileNotFoundError:
            logger.warning("Echidna not installed, skipping")
            return {"error": "not_installed", "violations": []}
        except Exception as e:
            logger.error(f"Echidna execution error: {e}")
            return {"error": str(e), "violations": []}

    def _run_medusa(self, contract_path: str, runs: int, timeout: int) -> Dict[str, Any]:
        """
        Execute Medusa coverage-guided fuzzing

        Returns:
            Dictionary with fuzzing results
        """
        try:
            cmd = [
                "medusa",
                "fuzz",
                "--target", contract_path,
                "--test-limit", str(runs)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Parse Medusa output
            output = result.stdout
            violations = []

            for line in output.split('\n'):
                if 'failed' in line.lower() or 'assertion' in line.lower():
                    violations.append({
                        "type": "assertion_failure",
                        "description": line.strip()
                    })

            return {
                "tool": "Medusa",
                "violations": violations,
                "total_runs": runs,
                "metadata": {
                    "exit_code": result.returncode,
                    "mode": "coverage-guided"
                }
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Medusa timeout after {timeout} seconds")
            return {"error": "timeout", "violations": []}
        except FileNotFoundError:
            logger.warning("Medusa not installed, skipping")
            return {"error": "not_installed", "violations": []}
        except Exception as e:
            logger.error(f"Medusa execution error: {e}")
            return {"error": str(e), "violations": []}

    def _run_foundry_fuzz(self, test_dir: str, runs: int, timeout: int) -> Dict[str, Any]:
        """
        Execute Foundry integrated fuzz testing

        Returns:
            Dictionary with fuzz test results
        """
        try:
            cmd = [
                "forge",
                "test",
                "--fuzz-runs", str(runs),
                "--json"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=Path.cwd()
            )

            # Parse JSON output
            failures = []
            try:
                # Foundry outputs JSON lines
                for line in result.stdout.split('\n'):
                    if line.strip():
                        data = json.loads(line)
                        if data.get("status") == "failure":
                            failures.append({
                                "test": data.get("test", "unknown"),
                                "reason": data.get("reason", ""),
                                "counterexample": data.get("counterexample")
                            })
            except json.JSONDecodeError:
                logger.warning("Failed to parse Foundry JSON output")

            return {
                "tool": "Foundry",
                "failures": failures,
                "fuzz_runs": runs,
                "metadata": {
                    "exit_code": result.returncode
                }
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Foundry timeout after {timeout} seconds")
            return {"error": "timeout", "failures": []}
        except FileNotFoundError:
            logger.warning("Foundry not installed, skipping")
            return {"error": "not_installed", "failures": []}
        except Exception as e:
            logger.error(f"Foundry execution error: {e}")
            return {"error": str(e), "failures": []}

    def _extract_property_name(self, line: str) -> str:
        """
        Extract property name from Echidna output line

        Args:
            line: Output line from Echidna

        Returns:
            Property name or "unknown"
        """
        # Simple heuristic: look for property names
        words = line.split()
        for word in words:
            if word.startswith("echidna_") or word.startswith("test_"):
                return word
        return "unknown"

    def _aggregate_findings(self, echidna_data: Dict, medusa_data: Dict,
                           foundry_data: Dict) -> List[Dict[str, Any]]:
        """
        Aggregate findings from all fuzzing tools into unified format

        Returns:
            List of unified findings with severity and mapping
        """
        unified = []

        # Add Echidna violations
        for violation in echidna_data.get("violations", []):
            unified.append({
                "source": "Echidna",
                "type": "property_violation",
                "property": violation.get("property"),
                "severity": "High",
                "description": violation.get("description"),
                "layer": "dynamic",
                "tool_type": "property-based_fuzzing",
                "swc_id": "SWC-110",  # Assert violation
                "owasp_category": "SC05-DoS"
            })

        # Add Medusa violations
        for violation in medusa_data.get("violations", []):
            unified.append({
                "source": "Medusa",
                "type": "assertion_failure",
                "severity": "High",
                "description": violation.get("description"),
                "layer": "dynamic",
                "tool_type": "coverage-guided_fuzzing",
                "swc_id": "SWC-110",
                "owasp_category": "SC05-DoS"
            })

        # Add Foundry failures
        for failure in foundry_data.get("failures", []):
            unified.append({
                "source": "Foundry",
                "type": "fuzz_failure",
                "test": failure.get("test"),
                "severity": "Medium",
                "description": failure.get("reason"),
                "counterexample": failure.get("counterexample"),
                "layer": "dynamic",
                "tool_type": "integrated_fuzzing",
                "swc_id": "SWC-110",
                "owasp_category": "SC05-DoS"
            })

        return unified
