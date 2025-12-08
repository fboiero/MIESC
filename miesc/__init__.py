"""
MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

A defense-in-depth security analysis framework for Ethereum smart contracts.
Orchestrates 25 specialized tools across 7 defense layers with AI-assisted
correlation and ML-based detection.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

__version__ = "4.0.0"
__author__ = "Fernando Boiero"
__email__ = "fboiero@frvm.utn.edu.ar"

# Lazy imports to avoid loading heavy dependencies on import
def get_version():
    """Return the current version of MIESC."""
    return __version__


def analyze(contract_path: str, layers: list = None, tools: list = None):
    """
    Analyze a smart contract using MIESC framework.

    Args:
        contract_path: Path to the Solidity contract file
        layers: List of layers to run (default: all 7 layers)
        tools: List of specific tools to run (default: all available)

    Returns:
        dict: Analysis results with findings, metrics, and recommendations

    Example:
        >>> import miesc
        >>> results = miesc.analyze("MyToken.sol")
        >>> print(f"Found {len(results['findings'])} issues")
    """
    from miesc.core.orchestrator import MIESCOrchestrator
    orchestrator = MIESCOrchestrator()
    return orchestrator.analyze(contract_path, layers=layers, tools=tools)


def quick_scan(contract_path: str):
    """
    Perform a quick scan using only static analysis tools.

    Args:
        contract_path: Path to the Solidity contract file

    Returns:
        dict: Quick scan results

    Example:
        >>> import miesc
        >>> results = miesc.quick_scan("MyToken.sol")
    """
    return analyze(contract_path, layers=["static"])


# Define public API
__all__ = [
    "__version__",
    "__author__",
    "get_version",
    "analyze",
    "quick_scan",
]
