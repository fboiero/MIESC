"""
MIESC Core - Compatibility shim for legacy webapp imports.
Redirects to src.core.optimized_orchestrator for v4.2+ compatibility.
"""

from src.core.optimized_orchestrator import OptimizedOrchestrator


class MIESCCore:
    """
    Legacy compatibility wrapper around OptimizedOrchestrator.
    Used by webapp/app.py and webapp/dashboard_enhanced.py.
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
                'findings': result.get('findings', []),
                'metadata': {
                    'contract': contract_path,
                    'tools_used': tools or ['slither', 'mythril', 'aderyn'],
                    'layers_executed': 7,
                    'version': '4.2.0'
                },
                'summary': result.get('summary', {}),
                'success': True
            }
        except Exception as e:
            return {
                'findings': [],
                'metadata': {'error': str(e)},
                'success': False
            }

    def get_available_tools(self) -> list:
        """Return list of available security tools."""
        return [
            'slither', 'mythril', 'aderyn', 'solhint',
            'echidna', 'medusa', 'halmos', 'certora',
            'smartllm', 'gptscan'
        ]

    def get_version(self) -> str:
        """Return MIESC version."""
        return '4.2.0'
