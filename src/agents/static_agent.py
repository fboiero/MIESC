"""
Static Analysis Agent for MCP Architecture

Wraps Layer 1 tools: Slither, Solhint, Surya
Enhanced with Tool Adapters: GasAnalyzer, MEVDetector
Publishes static analysis findings to Context Bus
"""
import json
import logging
import subprocess
from typing import Dict, Any, List
from pathlib import Path
from src.agents.base_agent import BaseAgent
from src.integration.adapter_integration import integrate_static_analysis

logger = logging.getLogger(__name__)


class StaticAgent(BaseAgent):
    """
    Agent for static analysis tools (Layer 1 - MIESC)

    Capabilities:
    - Pattern detection (Slither detectors)
    - Code quality checks (Solhint)
    - Architecture analysis (Surya)

    Published Context Types:
    - "static_findings": Unified findings from all tools
    - "slither_results": Raw Slither detector results
    - "solhint_results": Linting and style issues
    - "surya_results": Architecture visualization data
    """

    def __init__(self):
        super().__init__(
            agent_name="StaticAgent",
            capabilities=[
                "static_analysis",
                "pattern_detection",
                "code_quality",
                "architecture_analysis"
            ],
            agent_type="static"
        )

    def get_context_types(self) -> List[str]:
        return [
            "static_findings",
            "slither_results",
            "solhint_results",
            "surya_results",
            "gas_analysis_results",  # From GasAnalyzer adapter
            "mev_detection_results"  # From MEVDetector adapter
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run all static analysis tools on contract

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional parameters
                - solc_version: Solidity compiler version
                - slither_detectors: Comma-separated list of detectors to run
                - output_dir: Directory for outputs

        Returns:
            Dictionary with results from all tools
        """
        results = {
            "static_findings": [],
            "slither_results": {},
            "solhint_results": {},
            "surya_results": {}
        }

        solc_version = kwargs.get("solc_version", "0.8.0")
        output_dir = kwargs.get("output_dir", "outputs/evidence")

        # Run Slither
        logger.info(f"StaticAgent: Running Slither on {contract_path}")
        slither_data = self._run_slither(contract_path, solc_version)
        results["slither_results"] = slither_data

        # Run Solhint
        logger.info(f"StaticAgent: Running Solhint on {contract_path}")
        solhint_data = self._run_solhint(contract_path)
        results["solhint_results"] = solhint_data

        # Run Surya (architecture analysis)
        logger.info(f"StaticAgent: Running Surya on {contract_path}")
        surya_data = self._run_surya(contract_path)
        results["surya_results"] = surya_data

        # Aggregate findings from traditional tools
        results["static_findings"] = self._aggregate_findings(
            slither_data, solhint_data, surya_data
        )

        # === ENHANCED: Integrate Tool Adapters (Layer 1 Enhancements) ===
        # Run GasAnalyzer and MEVDetector adapters via Integration Layer
        # These are OPTIONAL (DPGA compliant) - agent works without them
        try:
            logger.info("StaticAgent: Integrating enhanced adapters (GasAnalyzer, MEVDetector)...")
            adapter_results = integrate_static_analysis(contract_path, **kwargs)

            # Extract adapter-specific results
            if "adapter_results" in adapter_results:
                gas_result = adapter_results["adapter_results"].get("gas_analyzer", {})
                mev_result = adapter_results["adapter_results"].get("mev_detector", {})

                results["gas_analysis_results"] = gas_result
                results["mev_detection_results"] = mev_result

                # Merge adapter findings into static_findings
                if "findings" in adapter_results:
                    results["static_findings"].extend(adapter_results["findings"])

                # Add aggregate metadata
                results["adapter_metadata"] = {
                    "total_gas_savings": adapter_results.get("metadata", {}).get("total_gas_savings", 0),
                    "mev_risk_score": adapter_results.get("metadata", {}).get("mev_risk_score", 0),
                    "adapters_executed": adapter_results.get("successful", 0),
                    "adapters_failed": adapter_results.get("failed", 0)
                }

                logger.info(
                    f"StaticAgent: Enhanced adapters completed - "
                    f"{adapter_results.get('successful', 0)} successful, "
                    f"Gas savings: {results['adapter_metadata']['total_gas_savings']}, "
                    f"MEV risk: {results['adapter_metadata']['mev_risk_score']}"
                )

        except Exception as e:
            # Graceful degradation: Agent works even if adapters fail
            logger.warning(f"StaticAgent: Enhanced adapters failed (non-critical): {e}")
            results["adapter_metadata"] = {
                "error": str(e),
                "adapters_executed": 0
            }

        return results

    def _run_slither(self, contract_path: str, solc_version: str) -> Dict[str, Any]:
        """
        Execute Slither static analysis

        Returns:
            Dictionary with vulnerabilities and metadata
        """
        try:
            # Run Slither with JSON output
            cmd = [
                "slither",
                contract_path,
                "--solc-remaps", "@openzeppelin=node_modules/@openzeppelin",
                "--json", "-"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0 and not result.stdout:
                logger.warning(f"Slither failed: {result.stderr}")
                return {"error": result.stderr, "vulnerabilities": []}

            # Parse JSON output
            data = json.loads(result.stdout) if result.stdout else {}

            # Extract vulnerabilities
            vulnerabilities = []
            if "results" in data and "detectors" in data["results"]:
                for finding in data["results"]["detectors"]:
                    vulnerabilities.append({
                        "id": finding.get("check", "UNKNOWN"),
                        "severity": finding.get("impact", "Unknown"),
                        "confidence": finding.get("confidence", "Unknown"),
                        "description": finding.get("description", ""),
                        "location": self._extract_location(finding),
                        "tool": "Slither"
                    })

            return {
                "tool": "Slither",
                "vulnerabilities": vulnerabilities,
                "total_findings": len(vulnerabilities),
                "metadata": {
                    "detectors_run": data.get("success", True),
                    "solc_version": solc_version
                }
            }

        except subprocess.TimeoutExpired:
            logger.error("Slither timeout after 300 seconds")
            return {"error": "timeout", "vulnerabilities": []}
        except json.JSONDecodeError as e:
            logger.error(f"Slither JSON parse error: {e}")
            return {"error": str(e), "vulnerabilities": []}
        except Exception as e:
            logger.error(f"Slither execution error: {e}")
            return {"error": str(e), "vulnerabilities": []}

    def _run_solhint(self, contract_path: str) -> Dict[str, Any]:
        """
        Execute Solhint linting

        Returns:
            Dictionary with linting issues
        """
        try:
            cmd = [
                "solhint",
                contract_path,
                "--formatter", "json"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Solhint returns issues in JSON
            issues = json.loads(result.stdout) if result.stdout else []

            findings = []
            for issue in issues:
                findings.append({
                    "rule": issue.get("ruleId", "UNKNOWN"),
                    "severity": issue.get("severity", "warning"),
                    "message": issue.get("message", ""),
                    "line": issue.get("line", 0),
                    "column": issue.get("column", 0),
                    "tool": "Solhint"
                })

            return {
                "tool": "Solhint",
                "issues": findings,
                "total_issues": len(findings),
                "metadata": {
                    "rules_applied": True
                }
            }

        except subprocess.TimeoutExpired:
            logger.error("Solhint timeout")
            return {"error": "timeout", "issues": []}
        except Exception as e:
            logger.error(f"Solhint error: {e}")
            return {"error": str(e), "issues": []}

    def _run_surya(self, contract_path: str) -> Dict[str, Any]:
        """
        Execute Surya architecture analysis

        Returns:
            Dictionary with contract structure data
        """
        try:
            # Run Surya describe
            cmd = [
                "surya",
                "describe",
                contract_path
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Parse Surya output (text-based)
            output = result.stdout

            return {
                "tool": "Surya",
                "description": output,
                "metadata": {
                    "analysis_type": "architecture"
                }
            }

        except subprocess.TimeoutExpired:
            logger.error("Surya timeout")
            return {"error": "timeout", "description": ""}
        except Exception as e:
            logger.error(f"Surya error: {e}")
            return {"error": str(e), "description": ""}

    def _extract_location(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract source location from Slither finding

        Args:
            finding: Slither finding dictionary

        Returns:
            Dictionary with file, line, function
        """
        location = {
            "file": "unknown",
            "line": 0,
            "function": "unknown"
        }

        if "elements" in finding and len(finding["elements"]) > 0:
            element = finding["elements"][0]
            if "source_mapping" in element:
                mapping = element["source_mapping"]
                location["file"] = mapping.get("filename_short", "unknown")
                location["line"] = mapping.get("lines", [0])[0] if mapping.get("lines") else 0
            if "name" in element:
                location["function"] = element["name"]

        return location

    def _aggregate_findings(self, slither_data: Dict, solhint_data: Dict,
                           surya_data: Dict) -> List[Dict[str, Any]]:
        """
        Aggregate findings from all tools into unified format

        Returns:
            List of unified findings with OWASP/SWC/CWE mappings
        """
        unified = []

        # Add Slither vulnerabilities
        for vuln in slither_data.get("vulnerabilities", []):
            unified.append({
                "source": "Slither",
                "type": "vulnerability",
                "id": vuln["id"],
                "severity": vuln["severity"],
                "confidence": vuln["confidence"],
                "description": vuln["description"],
                "location": vuln["location"],
                "layer": "static",
                # TODO: Add SWC/CWE/OWASP mapping
                "swc_id": self._map_to_swc(vuln["id"]),
                "owasp_category": self._map_to_owasp(vuln["id"])
            })

        # Add Solhint issues (lower severity)
        for issue in solhint_data.get("issues", []):
            unified.append({
                "source": "Solhint",
                "type": "code_quality",
                "id": issue["rule"],
                "severity": "Info",
                "description": issue["message"],
                "location": {
                    "file": "unknown",
                    "line": issue["line"],
                    "function": "unknown"
                },
                "layer": "static"
            })

        return unified

    def _map_to_swc(self, slither_id: str) -> str:
        """
        Map Slither detector ID to SWC ID

        Args:
            slither_id: Slither detector name

        Returns:
            SWC ID or "UNKNOWN"
        """
        # Mapping based on standards/owasp_sc_top10_mapping.md
        mapping = {
            "reentrancy-eth": "SWC-107",
            "reentrancy-no-eth": "SWC-107",
            "arbitrary-send-eth": "SWC-105",
            "suicidal": "SWC-106",
            "unchecked-send": "SWC-104",
            "unchecked-lowlevel": "SWC-104",
            "weak-prng": "SWC-120",
            "timestamp": "SWC-116",
            "tx-origin": "SWC-115"
        }
        return mapping.get(slither_id, "UNKNOWN")

    def _map_to_owasp(self, slither_id: str) -> str:
        """
        Map Slither detector ID to OWASP SC Top 10 category

        Args:
            slither_id: Slither detector name

        Returns:
            OWASP category or "SC10-Unknown-Unknowns"
        """
        mapping = {
            "reentrancy-eth": "SC01-Reentrancy",
            "reentrancy-no-eth": "SC01-Reentrancy",
            "arbitrary-send-eth": "SC02-Access-Control",
            "suicidal": "SC02-Access-Control",
            "unchecked-send": "SC04-Unchecked-Calls",
            "unchecked-lowlevel": "SC04-Unchecked-Calls",
            "weak-prng": "SC06-Bad-Randomness",
            "timestamp": "SC08-Time-Manipulation",
            "tx-origin": "SC02-Access-Control"
        }
        return mapping.get(slither_id, "SC10-Unknown-Unknowns")
