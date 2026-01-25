"""
MIESC Tool Adapters Registry
=============================

Central registry for security analysis tool adapters.
Enables dynamic tool discovery without modifying core code.

All adapters implement the Tool Adapter Protocol defined in
src/core/tool_protocol.py. This design satisfies DPGA requirements:
- All tools are optional (is_optional=True)
- No vendor lock-in (MIESC works without specific tools)
- Community-extensible

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-09
"""

import logging

# Layer 1 - Static Analysis
from src.adapters.aderyn_adapter import AderynAdapter
from src.adapters.slither_adapter import SlitherAdapter
from src.adapters.solhint_adapter import SolhintAdapter
from src.adapters.semgrep_adapter import SemgrepAdapter

# Layer 2 - Dynamic Testing
from src.adapters.echidna_adapter import EchidnaAdapter
from src.adapters.medusa_adapter import MedusaAdapter
from src.adapters.foundry_adapter import FoundryAdapter
from src.adapters.dogefuzz_adapter import DogeFuzzAdapter
from src.adapters.hardhat_adapter import HardhatAdapter

# Layer 3 - Symbolic Execution
from src.adapters.mythril_adapter import MythrilAdapter
from src.adapters.manticore_adapter import ManticoreAdapter
from src.adapters.halmos_adapter import HalmosAdapter

# Layer 4 - Formal Verification
from src.adapters.certora_adapter import CertoraAdapter
from src.adapters.smtchecker_adapter import SMTCheckerAdapter
from src.adapters.wake_adapter import WakeAdapter

# Layer 5 - Property Testing
from src.adapters.propertygpt_adapter import PropertyGPTAdapter
from src.adapters.vertigo_adapter import VertigoAdapter

# Layer 6 - AI/LLM Analysis
from src.adapters.smartllm_adapter import SmartLLMAdapter
from src.adapters.gptscan_adapter import GPTScanAdapter
from src.adapters.llmsmartaudit_adapter import LLMSmartAuditAdapter
from src.adapters.llmbugscanner_adapter import LLMBugScannerAdapter

# Layer 7 - Pattern Recognition / ML
from src.adapters.dagnn_adapter import DAGNNAdapter
from src.adapters.smartguard_adapter import SmartGuardAdapter
from src.adapters.smartbugs_ml_adapter import SmartBugsMLAdapter
from src.adapters.contract_clone_detector_adapter import ContractCloneDetectorAdapter

# Layer 8 - DeFi Security
from src.adapters.defi_adapter import DeFiAdapter
from src.adapters.mev_detector_adapter import MEVDetectorAdapter
from src.adapters.gas_analyzer_adapter import GasAnalyzerAdapter
from src.adapters.crosschain_adapter import CrossChainAdapter

# Layer 9 - Advanced Detection
from src.adapters.advanced_detector_adapter import AdvancedDetectorAdapter
from src.adapters.smartbugs_detector_adapter import SmartBugsDetectorAdapter
from src.adapters.threat_model_adapter import ThreatModelAdapter
from src.adapters.zk_circuit_adapter import ZKCircuitAdapter

# Invariant Synthesis (v4.2.3)
from src.adapters.invariant_synthesizer import (
    InvariantCategory,
    InvariantFormat,
    InvariantSynthesizer,
    SynthesizedInvariant,
    synthesize_invariants,
)
from src.core.tool_protocol import ToolStatus, get_tool_registry

logger = logging.getLogger(__name__)


def register_all_adapters():
    """
    Register all available tool adapters in the system.

    Main entry point for initializing the tool registry.
    Should be called during MIESC initialization.

    Returns:
        dict: Registration status report
    """
    registry = get_tool_registry()
    registered = []
    failed = []

    # Lista de adaptadores a registrar (33 adapters - 9 layers)
    adapters_to_register = [
        # Layer 1 - Static Analysis (4 tools)
        ("slither", SlitherAdapter),
        ("aderyn", AderynAdapter),
        ("solhint", SolhintAdapter),
        ("semgrep", SemgrepAdapter),
        # Layer 2 - Dynamic Testing (5 tools)
        ("echidna", EchidnaAdapter),
        ("medusa", MedusaAdapter),
        ("foundry", FoundryAdapter),
        ("dogefuzz", DogeFuzzAdapter),
        ("hardhat", HardhatAdapter),
        # Layer 3 - Symbolic Execution (3 tools)
        ("mythril", MythrilAdapter),
        ("manticore", ManticoreAdapter),
        ("halmos", HalmosAdapter),
        # Layer 4 - Formal Verification (3 tools)
        ("certora", CertoraAdapter),
        ("smtchecker", SMTCheckerAdapter),
        ("wake", WakeAdapter),
        # Layer 5 - Property Testing (2 tools)
        ("propertygpt", PropertyGPTAdapter),
        ("vertigo", VertigoAdapter),
        # Layer 6 - AI/LLM Analysis (4 tools)
        ("smartllm", SmartLLMAdapter),
        ("gptscan", GPTScanAdapter),
        ("llmsmartaudit", LLMSmartAuditAdapter),
        ("llmbugscanner", LLMBugScannerAdapter),
        # Layer 7 - Pattern Recognition / ML (4 tools)
        ("dagnn", DAGNNAdapter),
        ("smartguard", SmartGuardAdapter),
        ("smartbugs_ml", SmartBugsMLAdapter),
        ("contract_clone_detector", ContractCloneDetectorAdapter),
        # Layer 8 - DeFi Security (4 tools)
        ("defi_analyzer", DeFiAdapter),
        ("mev_detector", MEVDetectorAdapter),
        ("gas_analyzer", GasAnalyzerAdapter),
        ("crosschain", CrossChainAdapter),
        # Layer 9 - Advanced Detection (4 tools)
        ("advanced_detector", AdvancedDetectorAdapter),
        ("smartbugs_detector", SmartBugsDetectorAdapter),
        ("threat_model", ThreatModelAdapter),
        ("zk_circuit", ZKCircuitAdapter),
    ]

    logger.info("Initializing tool adapter registration...")

    for name, adapter_class in adapters_to_register:
        try:
            # Instantiate adapter
            adapter = adapter_class()

            # Register in the registry
            registry.register(adapter)

            # Check availability
            status = adapter.is_available()
            metadata = adapter.get_metadata()

            registered.append(
                {
                    "name": name,
                    "status": status.value,
                    "version": metadata.version,
                    "category": metadata.category.value,
                    "optional": metadata.is_optional,
                }
            )

            status_symbol = "✅" if status == ToolStatus.AVAILABLE else "⚠️"
            logger.info(
                f"{status_symbol} {name} v{metadata.version} "
                f"({metadata.category.value}) - {status.value}"
            )

        except Exception as e:
            failed.append({"name": name, "error": str(e)})
            logger.error(f"❌ Error registering {name}: {e}")

    # Registration report
    report = {
        "total_adapters": len(adapters_to_register),
        "registered": len(registered),
        "failed": len(failed),
        "adapters": registered,
        "failures": failed,
    }

    # Log summary
    logger.info(f"\n{'='*60}")
    logger.info("Adapter registration complete:")
    logger.info(f"  Total: {report['total_adapters']}")
    logger.info(f"  Registered: {report['registered']}")
    logger.info(f"  Failed: {report['failed']}")
    logger.info(f"{'='*60}\n")

    # Verify DPGA compliance: ALL tools must be optional
    non_optional = [a for a in registered if not a.get("optional", True)]
    if non_optional:
        logger.warning(f"⚠️ DPGA WARNING: Non-optional tools detected: {non_optional}")
    else:
        logger.info("✅ DPGA compliance verified: All tools are optional")

    return report


def get_available_adapters():
    """
    Return list of available adapters (installed and ready).

    Returns:
        list: List of available ToolAdapters
    """
    registry = get_tool_registry()
    return registry.get_available_tools()


def get_adapter_status_report():
    """
    Generate complete adapter status report.

    Returns:
        dict: Report with status of all tools
    """
    registry = get_tool_registry()
    return registry.get_tool_status_report()


def get_adapter_by_name(name: str):
    """
    Get specific adapter by name.

    Args:
        name: Adapter name (e.g., "gas_analyzer")

    Returns:
        ToolAdapter or None: Requested adapter
    """
    registry = get_tool_registry()
    return registry.get_tool(name)


# Auto-register on module import (optional)
# Uncomment the following line for auto-registration
# register_all_adapters()


__all__ = [
    # Registry functions
    "register_all_adapters",
    "get_available_adapters",
    "get_adapter_status_report",
    "get_adapter_by_name",
    # Layer 1 - Static Analysis
    "SlitherAdapter",
    "AderynAdapter",
    "SolhintAdapter",
    "SemgrepAdapter",
    # Layer 2 - Dynamic Testing
    "EchidnaAdapter",
    "MedusaAdapter",
    "FoundryAdapter",
    "DogeFuzzAdapter",
    "HardhatAdapter",
    # Layer 3 - Symbolic Execution
    "MythrilAdapter",
    "ManticoreAdapter",
    "HalmosAdapter",
    # Layer 4 - Formal Verification
    "CertoraAdapter",
    "SMTCheckerAdapter",
    "WakeAdapter",
    # Layer 5 - Property Testing
    "PropertyGPTAdapter",
    "VertigoAdapter",
    # Layer 6 - AI/LLM Analysis
    "SmartLLMAdapter",
    "GPTScanAdapter",
    "LLMSmartAuditAdapter",
    "LLMBugScannerAdapter",
    # Layer 7 - Pattern Recognition / ML
    "DAGNNAdapter",
    "SmartGuardAdapter",
    "SmartBugsMLAdapter",
    "ContractCloneDetectorAdapter",
    # Layer 8 - DeFi Security
    "DeFiAdapter",
    "MEVDetectorAdapter",
    "GasAnalyzerAdapter",
    "CrossChainAdapter",
    # Layer 9 - Advanced Detection
    "AdvancedDetectorAdapter",
    "SmartBugsDetectorAdapter",
    "ThreatModelAdapter",
    "ZKCircuitAdapter",
    # Invariant Synthesis (v4.2.3)
    "InvariantSynthesizer",
    "InvariantFormat",
    "InvariantCategory",
    "SynthesizedInvariant",
    "synthesize_invariants",
]
