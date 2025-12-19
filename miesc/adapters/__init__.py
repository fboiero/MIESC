"""
MIESC Adapters Module

Re-exports tool adapters for 35 security analysis tools.
Adapters provide a unified interface for different security tools.
"""

try:
    from src.adapters.base_adapter import BaseAdapter
    from src.adapters.slither_adapter import SlitherAdapter
    from src.adapters.mythril_adapter import MythrilAdapter
    from src.adapters.solhint_adapter import SolhintAdapter
    from src.adapters.echidna_adapter import EchidnaAdapter
    from src.adapters.manticore_adapter import ManticoreAdapter
    from src.adapters.halmos_adapter import HalmosAdapter
    from src.adapters.certora_adapter import CertoraAdapter
    from src.adapters.smartllm_adapter import SmartLLMAdapter
    from src.adapters.gptscan_adapter import GPTScanAdapter
except ImportError:
    BaseAdapter = None
    SlitherAdapter = None
    MythrilAdapter = None
    SolhintAdapter = None
    EchidnaAdapter = None
    ManticoreAdapter = None
    HalmosAdapter = None
    CertoraAdapter = None
    SmartLLMAdapter = None
    GPTScanAdapter = None

__all__ = [
    "BaseAdapter",
    "SlitherAdapter",
    "MythrilAdapter",
    "SolhintAdapter",
    "EchidnaAdapter",
    "ManticoreAdapter",
    "HalmosAdapter",
    "CertoraAdapter",
    "SmartLLMAdapter",
    "GPTScanAdapter",
]
