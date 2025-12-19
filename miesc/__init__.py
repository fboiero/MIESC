"""
MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

A defense-in-depth security analysis framework for Ethereum smart contracts.
Orchestrates 35 specialized tools across 7 defense layers with AI-assisted
correlation and ML-based detection.

Author: Fernando Boiero <fboiero@undef.edu.ar>
License: GPL-3.0
"""

__version__ = "4.2.0"
__author__ = "Fernando Boiero"
__email__ = "fboiero@undef.edu.ar"


def get_version():
    """Return the current version of MIESC."""
    return __version__


def analyze(contract_path: str, layers: list = None, tools: list = None):
    """
    Analyze a smart contract using MIESC framework.

    Args:
        contract_path: Path to the Solidity contract file
        layers: List of layers to run (1-7, default: all)
        tools: List of specific tools to run (default: all available)

    Returns:
        dict: Analysis results with findings, metrics, and recommendations

    Example:
        >>> import miesc
        >>> results = miesc.analyze("MyToken.sol", layers=[1, 3, 7])
        >>> print(f"Found {len(results['findings'])} issues")
    """
    from src.core.optimized_orchestrator import OptimizedOrchestrator
    orchestrator = OptimizedOrchestrator()
    return orchestrator.run_audit(contract_path, layers=layers)


def quick_scan(contract_path: str):
    """
    Perform a quick scan using only Layer 1 (static analysis).

    Args:
        contract_path: Path to the Solidity contract file

    Returns:
        dict: Quick scan results with static analysis findings
    """
    return analyze(contract_path, layers=[1])


def deep_audit(contract_path: str):
    """
    Perform a comprehensive audit using all 7 layers.

    Args:
        contract_path: Path to the Solidity contract file

    Returns:
        dict: Full audit results with all findings
    """
    return analyze(contract_path, layers=[1, 2, 3, 4, 5, 6, 7])


# Define public API
__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "get_version",
    "analyze",
    "quick_scan",
    "deep_audit",
]
