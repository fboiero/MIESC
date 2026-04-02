"""
MIESC Core - Compatibility shim for webapp imports.

.. deprecated:: 5.1.1
    Use ``from miesc.api import run_full_audit`` instead.
    This module will be removed in v6.0.0.
"""

import warnings

from src.core.optimized_orchestrator import OptimizedOrchestrator

warnings.warn(
    "src.miesc_core is deprecated. Use miesc.api instead. "
    "This module will be removed in v6.0.0.",
    DeprecationWarning,
    stacklevel=2,
)


class MIESCCore:
    """
    Compatibility wrapper around OptimizedOrchestrator.

    .. deprecated:: 5.1.1
        Use ``from miesc.api import run_full_audit`` instead.
    """

    def __init__(self, config=None):
        """Initialize MIESC Core with optional config."""
        self.orchestrator = OptimizedOrchestrator()
        self.config = config or {}

    def analyze(self, contract_path: str, tools: list = None) -> dict:
        """
        Analyze a smart contract.

        Args:
            contract_path: Path to the Solidity contract
            tools: Optional list of tools to use

        Returns:
            dict with 'findings' and 'metadata'
        """
        try:
            result = self.orchestrator.analyze(contract_path, tools=tools)

            # Extract findings from aggregated report or raw results
            findings = []
            if hasattr(result, "aggregated_results"):
                report = result.aggregated_results
                if isinstance(report, dict):
                    findings = report.get("findings", [])
            if not findings and hasattr(result, "raw_results"):
                for tool_data in result.raw_results.values():
                    if isinstance(tool_data, dict):
                        findings.extend(tool_data.get("findings", []))

            return {
                "findings": findings,
                "metadata": {
                    "contract": contract_path,
                    "tools_used": result.tools_success if hasattr(result, "tools_success") else (tools or []),
                    "tools_failed": result.tools_failed if hasattr(result, "tools_failed") else [],
                    "total_findings": result.total_findings if hasattr(result, "total_findings") else len(findings),
                    "layers_executed": 9,
                    "version": "5.1.1",
                },
                "summary": result.severity_counts if hasattr(result, "severity_counts") else {},
                "success": True,
            }
        except Exception as e:
            return {"findings": [], "metadata": {"error": str(e)}, "success": False}

    def scan(self, contract_path: str, tools: list = None) -> dict:
        """Alias for analyze() - backwards compatibility with webapp."""
        return self.analyze(contract_path, tools=tools)

    def get_available_tools(self) -> list:
        """Return list of available security tools."""
        return [
            "slither",
            "mythril",
            "aderyn",
            "solhint",
            "echidna",
            "medusa",
            "halmos",
            "certora",
            "smartllm",
            "gptscan",
        ]

    def get_version(self) -> str:
        """Return MIESC version."""
        return "5.1.1"
