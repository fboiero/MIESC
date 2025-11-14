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
from src.core.tool_protocol import get_tool_registry, ToolStatus

# Importar todos los adapters
from src.adapters.gas_analyzer_adapter import GasAnalyzerAdapter
from src.adapters.mev_detector_adapter import MEVDetectorAdapter
from src.adapters.vertigo_adapter import VertigoAdapter
from src.adapters.oyente_adapter import OyenteAdapter
from src.adapters.threat_model_adapter import ThreatModelAdapter
from src.adapters.aderyn_adapter import AderynAdapter
from src.adapters.medusa_adapter import MedusaAdapter
from src.adapters.slither_adapter import SlitherAdapter
from src.adapters.solhint_adapter import SolhintAdapter
from src.adapters.echidna_adapter import EchidnaAdapter
from src.adapters.foundry_adapter import FoundryAdapter
# Layer 3 - Symbolic Execution (Fase 3 - 2025)
from src.adapters.mythril_adapter import MythrilAdapter
from src.adapters.manticore_adapter import ManticoreAdapter
from src.adapters.halmos_adapter import HalmosAdapter
# Layer 4 - Formal Verification (Fase 4 - 2025)
from src.adapters.smtchecker_adapter import SMTCheckerAdapter
from src.adapters.wake_adapter import WakeAdapter
from src.adapters.certora_adapter import CertoraAdapter
from src.adapters.propertygpt_adapter import PropertyGPTAdapter
# Layer 5 - AI-Powered Analysis (Fase 5 - 2025)
from src.adapters.smartllm_adapter import SmartLLMAdapter
from src.adapters.gptscan_adapter import GPTScanAdapter
from src.adapters.llmsmartaudit_adapter import LLMSmartAuditAdapter
# Layer 6 - ML-Based Detection (Fase 6 - 2025)
from src.adapters.smartbugs_ml_adapter import SmartBugsMLAdapter
from src.adapters.contract_clone_detector_adapter import ContractCloneDetectorAdapter
from src.adapters.dagnn_adapter import DAGNNAdapter

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

    # Lista de adaptadores a registrar (24 adapters - 7 layers)
    adapters_to_register = [
        # Layer 0 - Built-in analyzers
        ("gas_analyzer", GasAnalyzerAdapter),
        ("mev_detector", MEVDetectorAdapter),
        ("vertigo", VertigoAdapter),
        ("oyente", OyenteAdapter),
        ("threat_model", ThreatModelAdapter),
        # Layer 1 - Static Analysis
        ("aderyn", AderynAdapter),
        ("slither", SlitherAdapter),
        ("solhint", SolhintAdapter),
        # Layer 2 - Dynamic Testing
        ("medusa", MedusaAdapter),
        ("echidna", EchidnaAdapter),
        ("foundry", FoundryAdapter),
        # Layer 3 - Symbolic Execution (Fase 3 - 2025)
        ("mythril", MythrilAdapter),
        ("manticore", ManticoreAdapter),
        ("halmos", HalmosAdapter),
        # Layer 4 - Formal Verification (Fase 4 - 2025)
        ("smtchecker", SMTCheckerAdapter),
        ("wake", WakeAdapter),
        ("certora", CertoraAdapter),
        ("propertygpt", PropertyGPTAdapter),
        # Layer 5 - AI-Powered Analysis (Fase 5 - 2025)
        ("smartllm", SmartLLMAdapter),
        ("gptscan", GPTScanAdapter),
        ("llmsmartaudit", LLMSmartAuditAdapter),
        # Layer 6 - ML-Based Detection (Fase 6 - 2025)
        ("smartbugs_ml", SmartBugsMLAdapter),
        ("contract_clone_detector", ContractCloneDetectorAdapter),
        ("dagnn", DAGNNAdapter),
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

            registered.append({
                "name": name,
                "status": status.value,
                "version": metadata.version,
                "category": metadata.category.value,
                "optional": metadata.is_optional
            })

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
        "failures": failed
    }

    # Log summary
    logger.info(f"\n{'='*60}")
    logger.info(f"Adapter registration complete:")
    logger.info(f"  Total: {report['total_adapters']}")
    logger.info(f"  Registered: {report['registered']}")
    logger.info(f"  Failed: {report['failed']}")
    logger.info(f"{'='*60}\n")

    # Verify DPGA compliance: ALL tools must be optional
    non_optional = [a for a in registered if not a.get("optional", True)]
    if non_optional:
        logger.warning(
            f"⚠️ DPGA WARNING: Non-optional tools detected: {non_optional}"
        )
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
    "register_all_adapters",
    "get_available_adapters",
    "get_adapter_status_report",
    "get_adapter_by_name",
    "GasAnalyzerAdapter",
    "MEVDetectorAdapter",
    "VertigoAdapter",
    "OyenteAdapter",
    "ThreatModelAdapter",
    "AderynAdapter",
    "MedusaAdapter",
    "SlitherAdapter",
    "SolhintAdapter",
    "EchidnaAdapter",
    "FoundryAdapter",
]
