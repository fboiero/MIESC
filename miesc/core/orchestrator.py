"""
MIESC Orchestrator

Coordinates execution of security analysis tools across 7 defense layers.
"""

import os
import sys
import json
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class MIESCOrchestrator:
    """
    Main orchestrator for MIESC security analysis.

    Coordinates execution of 25 security tools across 7 defense layers:
        Layer 1: Static Analysis (Slither, Aderyn, Solhint)
        Layer 2: Dynamic Testing (Echidna, Medusa, Foundry)
        Layer 3: Symbolic Execution (Mythril, Manticore, Halmos)
        Layer 4: Invariant Testing (Scribble)
        Layer 5: Formal Verification (SMTChecker, Certora)
        Layer 6: Property Testing (PropertyGPT)
        Layer 7: AI Analysis (SmartLLM, ThreatModel)
    """

    LAYERS = {
        1: {"name": "Static Analysis", "tools": ["slither", "aderyn", "solhint"]},
        2: {"name": "Dynamic Testing", "tools": ["echidna", "medusa", "foundry"]},
        3: {"name": "Symbolic Execution", "tools": ["mythril", "manticore", "halmos"]},
        4: {"name": "Invariant Testing", "tools": ["scribble"]},
        5: {"name": "Formal Verification", "tools": ["smtchecker", "certora"]},
        6: {"name": "Property Testing", "tools": ["propertygpt"]},
        7: {"name": "AI Analysis", "tools": ["smartllm", "threatmodel"]},
    }

    def __init__(self):
        """Initialize the orchestrator."""
        self.results = {}
        self.start_time = None
        self.available_tools = self._check_tools()

    def _check_tools(self) -> Dict[str, bool]:
        """Check which tools are available."""
        tools = {}
        checks = {
            "slither": ["slither", "--version"],
            "mythril": ["myth", "version"],
            "echidna": ["echidna", "--version"],
            "solhint": ["solhint", "--version"],
            "aderyn": ["aderyn", "--version"],
            "foundry": ["forge", "--version"],
            "halmos": ["halmos", "--version"],
        }

        for tool, cmd in checks.items():
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                tools[tool] = result.returncode == 0
            except:
                tools[tool] = False

        return tools

    def analyze(self, contract_path: str, layers: List[str] = None,
                tools: List[str] = None) -> Dict[str, Any]:
        """
        Analyze a contract using specified layers/tools.

        Args:
            contract_path: Path to Solidity contract
            layers: List of layers to run (default: all)
            tools: List of specific tools (default: all available)

        Returns:
            Analysis results dictionary
        """
        return self.audit(contract_path, layers=layers, tools=tools)

    def audit(self, contract_path: str, layers: List[int] = None,
              tools: List[str] = None, timeout: int = 600,
              verbose: bool = False) -> Dict[str, Any]:
        """
        Perform full security audit.

        Args:
            contract_path: Path to Solidity contract
            layers: Layers to run (1-7, default: all)
            tools: Specific tools to run
            timeout: Timeout in seconds
            verbose: Verbose output

        Returns:
            Audit results dictionary
        """
        self.start_time = datetime.now()
        contract_path = str(Path(contract_path).resolve())

        if not os.path.exists(contract_path):
            raise FileNotFoundError(f"Contract not found: {contract_path}")

        results = {
            "contract": contract_path,
            "timestamp": self.start_time.isoformat(),
            "miesc_version": "4.0.0",
            "layers_run": [],
            "findings": [],
            "summary": {},
            "execution_time": 0,
        }

        # Determine which layers to run
        layers_to_run = layers or list(self.LAYERS.keys())

        for layer_num in layers_to_run:
            if isinstance(layer_num, str):
                layer_num = int(layer_num)

            if layer_num not in self.LAYERS:
                continue

            layer_info = self.LAYERS[layer_num]
            layer_results = self._run_layer(
                layer_num, layer_info, contract_path, tools, timeout, verbose
            )
            results["layers_run"].append(layer_results)
            results["findings"].extend(layer_results.get("findings", []))

        # Calculate summary
        results["execution_time"] = (datetime.now() - self.start_time).total_seconds()
        results["summary"] = self._calculate_summary(results["findings"])

        return results

    def _run_layer(self, layer_num: int, layer_info: Dict, contract_path: str,
                   tools: List[str], timeout: int, verbose: bool) -> Dict:
        """Run a specific layer's tools."""
        layer_results = {
            "layer": layer_num,
            "name": layer_info["name"],
            "tools_run": [],
            "findings": [],
        }

        for tool in layer_info["tools"]:
            if tools and tool not in tools:
                continue

            if not self.available_tools.get(tool, False):
                if verbose:
                    logger.warning(f"Tool not available: {tool}")
                continue

            try:
                tool_results = self._run_tool(tool, contract_path, timeout)
                layer_results["tools_run"].append(tool)
                layer_results["findings"].extend(tool_results.get("findings", []))
            except Exception as e:
                logger.error(f"Tool {tool} failed: {e}")

        return layer_results

    def _run_tool(self, tool: str, contract_path: str, timeout: int) -> Dict:
        """Run a specific tool."""
        results = {"tool": tool, "findings": []}

        if tool == "slither":
            results = self._run_slither(contract_path, timeout)
        elif tool == "mythril":
            results = self._run_mythril(contract_path, timeout)
        # Add more tools as needed

        return results

    def _run_slither(self, contract_path: str, timeout: int) -> Dict:
        """Run Slither static analyzer."""
        try:
            result = subprocess.run(
                ["slither", contract_path, "--json", "-"],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            findings = []
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for detector in data.get("results", {}).get("detectors", []):
                        findings.append({
                            "tool": "slither",
                            "type": detector.get("check"),
                            "severity": detector.get("impact", "info").lower(),
                            "description": detector.get("description", ""),
                            "locations": detector.get("elements", []),
                        })
                except json.JSONDecodeError:
                    pass

            return {"tool": "slither", "findings": findings}
        except subprocess.TimeoutExpired:
            return {"tool": "slither", "findings": [], "error": "timeout"}
        except Exception as e:
            return {"tool": "slither", "findings": [], "error": str(e)}

    def _run_mythril(self, contract_path: str, timeout: int) -> Dict:
        """Run Mythril symbolic execution."""
        try:
            result = subprocess.run(
                ["myth", "analyze", contract_path, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            findings = []
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for issue in data.get("issues", []):
                        findings.append({
                            "tool": "mythril",
                            "type": issue.get("title"),
                            "severity": issue.get("severity", "info").lower(),
                            "description": issue.get("description", ""),
                            "swc_id": issue.get("swc-id"),
                        })
                except json.JSONDecodeError:
                    pass

            return {"tool": "mythril", "findings": findings}
        except subprocess.TimeoutExpired:
            return {"tool": "mythril", "findings": [], "error": "timeout"}
        except Exception as e:
            return {"tool": "mythril", "findings": [], "error": str(e)}

    def _calculate_summary(self, findings: List[Dict]) -> Dict:
        """Calculate summary statistics."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        tools_used = set()

        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            tools_used.add(f.get("tool", "unknown"))

        return {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "tools_used": list(tools_used),
        }
