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
            result = self.orchestrator.run_audit(contract_path)
            return {
                "findings": result.get("findings", []),
                "metadata": {
                    "contract": contract_path,
                    "tools_used": tools or ["slither", "mythril", "aderyn"],
                    "layers_executed": 7,
                    "version": "5.1.1",
                },
                "summary": result.get("summary", {}),
                "success": True,
            }
        except Exception as e:
            return {"findings": [], "metadata": {"error": str(e)}, "success": False}

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
