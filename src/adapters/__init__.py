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

# Layer 1 - Static Analysis (6 tools)
from src.adapters.aderyn_adapter import AderynAdapter
from src.adapters.slither_adapter import SlitherAdapter
from src.adapters.solhint_adapter import SolhintAdapter
from src.adapters.semgrep_adapter import SemgrepAdapter
from src.adapters.wake_adapter import WakeAdapter
from src.adapters.fouranalyzer_adapter import FourAnalyzerAdapter

# Layer 2 - Dynamic Testing (6 tools)
from src.adapters.echidna_adapter import EchidnaAdapter
from src.adapters.medusa_adapter import MedusaAdapter
from src.adapters.foundry_adapter import FoundryAdapter
from src.adapters.dogefuzz_adapter import DogeFuzzAdapter
from src.adapters.hardhat_adapter import HardhatAdapter
from src.adapters.vertigo_adapter import VertigoAdapter

# Layer 3 - Symbolic Execution (5 tools)
from src.adapters.mythril_adapter import MythrilAdapter
from src.adapters.manticore_adapter import ManticoreAdapter
from src.adapters.halmos_adapter import HalmosAdapter
from src.adapters.oyente_adapter import OyenteAdapter
from src.adapters.pakala_adapter import PakalaAdapter

# Layer 4 - Formal Verification (5 tools)
from src.adapters.certora_adapter import CertoraAdapter
from src.adapters.smtchecker_adapter import SMTCheckerAdapter
from src.adapters.propertygpt_adapter import PropertyGPTAdapter
from src.adapters.scribble_adapter import ScribbleAdapter
from src.adapters.solcmc_adapter import SolCMCAdapter

# Layer 5 - AI Analysis (6 tools)
from src.adapters.smartllm_adapter import SmartLLMAdapter
from src.adapters.gptscan_adapter import GPTScanAdapter
from src.adapters.llmsmartaudit_adapter import LLMSmartAuditAdapter
from src.adapters.gptlens_adapter import GPTLensAdapter
from src.adapters.llamaaudit_adapter import LlamaAuditAdapter
from src.adapters.iaudit_adapter import IAuditAdapter

# Layer 6 - ML Detection (5 tools)
from src.adapters.dagnn_adapter import DAGNNAdapter
from src.adapters.smartguard_adapter import SmartGuardAdapter
from src.adapters.smartbugs_ml_adapter import SmartBugsMLAdapter
from src.adapters.smartbugs_detector_adapter import SmartBugsDetectorAdapter
from src.adapters.peculiar_adapter import PeculiarAdapter

# Layer 7 - Specialized Analysis (7 tools)
from src.adapters.gas_analyzer_adapter import GasAnalyzerAdapter
from src.adapters.mev_detector_adapter import MEVDetectorAdapter
from src.adapters.threat_model_adapter import ThreatModelAdapter
from src.adapters.contract_clone_detector_adapter import ContractCloneDetectorAdapter
from src.adapters.defi_adapter import DeFiAdapter
from src.adapters.advanced_detector_adapter import AdvancedDetectorAdapter
from src.adapters.upgradability_checker_adapter import UpgradabilityCheckerAdapter

# Layer 8 - Cross-Chain & ZK Security (5 tools)
from src.adapters.crosschain_adapter import CrossChainAdapter
from src.adapters.zk_circuit_adapter import ZKCircuitAdapter
from src.adapters.bridge_monitor_adapter import BridgeMonitorAdapter
from src.adapters.l2_validator_adapter import L2ValidatorAdapter
from src.adapters.circom_analyzer_adapter import CircomAnalyzerAdapter

# Layer 9 - Advanced AI Ensemble (5 tools)
from src.adapters.llmbugscanner_adapter import LLMBugScannerAdapter
from src.adapters.audit_consensus_adapter import AuditConsensusAdapter
from src.adapters.exploit_synthesizer_adapter import ExploitSynthesizerAdapter
from src.adapters.vuln_verifier_adapter import VulnVerifierAdapter
from src.adapters.remediation_validator_adapter import RemediationValidatorAdapter

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

    # Lista de adaptadores a registrar (50 adapters - 9 layers)
    adapters_to_register = [
        # Layer 1 - Static Analysis (6 tools)
        ("slither", SlitherAdapter),
        ("aderyn", AderynAdapter),
        ("solhint", SolhintAdapter),
        ("semgrep", SemgrepAdapter),
        ("wake", WakeAdapter),
        ("fouranalyzer", FourAnalyzerAdapter),
        # Layer 2 - Dynamic Testing (6 tools)
        ("echidna", EchidnaAdapter),
        ("medusa", MedusaAdapter),
        ("foundry", FoundryAdapter),
        ("dogefuzz", DogeFuzzAdapter),
        ("hardhat", HardhatAdapter),
        ("vertigo", VertigoAdapter),
        # Layer 3 - Symbolic Execution (5 tools)
        ("mythril", MythrilAdapter),
        ("manticore", ManticoreAdapter),
        ("halmos", HalmosAdapter),
        ("oyente", OyenteAdapter),
        ("pakala", PakalaAdapter),
        # Layer 4 - Formal Verification (5 tools)
        ("certora", CertoraAdapter),
        ("smtchecker", SMTCheckerAdapter),
        ("propertygpt", PropertyGPTAdapter),
        ("scribble", ScribbleAdapter),
        ("solcmc", SolCMCAdapter),
        # Layer 5 - AI Analysis (6 tools)
        ("smartllm", SmartLLMAdapter),
        ("gptscan", GPTScanAdapter),
        ("llmsmartaudit", LLMSmartAuditAdapter),
        ("gptlens", GPTLensAdapter),
        ("llamaaudit", LlamaAuditAdapter),
        ("iaudit", IAuditAdapter),
        # Layer 6 - ML Detection (5 tools)
        ("dagnn", DAGNNAdapter),
        ("smartguard", SmartGuardAdapter),
        ("smartbugs_ml", SmartBugsMLAdapter),
        ("smartbugs_detector", SmartBugsDetectorAdapter),
        ("peculiar", PeculiarAdapter),
        # Layer 7 - Specialized Analysis (7 tools)
        ("gas_analyzer", GasAnalyzerAdapter),
        ("mev_detector", MEVDetectorAdapter),
        ("threat_model", ThreatModelAdapter),
        ("contract_clone_detector", ContractCloneDetectorAdapter),
        ("defi", DeFiAdapter),
        ("advanced_detector", AdvancedDetectorAdapter),
        ("upgradability_checker", UpgradabilityCheckerAdapter),
        # Layer 8 - Cross-Chain & ZK Security (5 tools)
        ("crosschain", CrossChainAdapter),
        ("zk_circuit", ZKCircuitAdapter),
        ("bridge_monitor", BridgeMonitorAdapter),
        ("l2_validator", L2ValidatorAdapter),
        ("circom_analyzer", CircomAnalyzerAdapter),
        # Layer 9 - Advanced AI Ensemble (5 tools)
        ("llmbugscanner", LLMBugScannerAdapter),
        ("audit_consensus", AuditConsensusAdapter),
        ("exploit_synthesizer", ExploitSynthesizerAdapter),
        ("vuln_verifier", VulnVerifierAdapter),
        ("remediation_validator", RemediationValidatorAdapter),
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
    # Layer 1 - Static Analysis (6 tools)
    "SlitherAdapter",
    "AderynAdapter",
    "SolhintAdapter",
    "SemgrepAdapter",
    "WakeAdapter",
    "FourAnalyzerAdapter",
    # Layer 2 - Dynamic Testing (6 tools)
    "EchidnaAdapter",
    "MedusaAdapter",
    "FoundryAdapter",
    "DogeFuzzAdapter",
    "HardhatAdapter",
    "VertigoAdapter",
    # Layer 3 - Symbolic Execution (5 tools)
    "MythrilAdapter",
    "ManticoreAdapter",
    "HalmosAdapter",
    "OyenteAdapter",
    "PakalaAdapter",
    # Layer 4 - Formal Verification (5 tools)
    "CertoraAdapter",
    "SMTCheckerAdapter",
    "PropertyGPTAdapter",
    "ScribbleAdapter",
    "SolCMCAdapter",
    # Layer 5 - AI Analysis (6 tools)
    "SmartLLMAdapter",
    "GPTScanAdapter",
    "LLMSmartAuditAdapter",
    "GPTLensAdapter",
    "LlamaAuditAdapter",
    "IAuditAdapter",
    # Layer 6 - ML Detection (5 tools)
    "DAGNNAdapter",
    "SmartGuardAdapter",
    "SmartBugsMLAdapter",
    "SmartBugsDetectorAdapter",
    "PeculiarAdapter",
    # Layer 7 - Specialized Analysis (7 tools)
    "GasAnalyzerAdapter",
    "MEVDetectorAdapter",
    "ThreatModelAdapter",
    "ContractCloneDetectorAdapter",
    "DeFiAdapter",
    "AdvancedDetectorAdapter",
    "UpgradabilityCheckerAdapter",
    # Layer 8 - Cross-Chain & ZK Security (5 tools)
    "CrossChainAdapter",
    "ZKCircuitAdapter",
    "BridgeMonitorAdapter",
    "L2ValidatorAdapter",
    "CircomAnalyzerAdapter",
    # Layer 9 - Advanced AI Ensemble (5 tools)
    "LLMBugScannerAdapter",
    "AuditConsensusAdapter",
    "ExploitSynthesizerAdapter",
    "VulnVerifierAdapter",
    "RemediationValidatorAdapter",
    # Invariant Synthesis (v4.2.3)
    "InvariantSynthesizer",
    "InvariantFormat",
    "InvariantCategory",
    "SynthesizedInvariant",
    "synthesize_invariants",
]
