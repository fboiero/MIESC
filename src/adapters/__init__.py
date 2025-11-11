"""
MIESC Tool Adapters Registry
=============================

Registro central de adaptadores de herramientas de análisis.
Permite descubrimiento dinámico de herramientas sin modificar código core.

Este módulo registra todos los adaptadores disponibles siguiendo el
Tool Adapter Protocol definido en src/core/tool_protocol.py.

Cumple con requisitos DPGA:
- Todas las herramientas son opcionales (is_optional=True)
- Sin vendor lock-in (MIESC funciona sin herramientas específicas)
- Extensible por la comunidad

Autor: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Fecha: 2025-01-09
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
# Layer 5 - AI-Powered Analysis (Fase 5 - 2025)
from src.adapters.smartllm_adapter import SmartLLMAdapter
from src.adapters.gptscan_adapter import GPTScanAdapter
from src.adapters.llmsmartaudit_adapter import LLMSmartAuditAdapter
# Layer 6 - ML-Based Detection (Fase 6 - 2025)
from src.adapters.smartbugs_ml_adapter import SmartBugsMLAdapter
from src.adapters.contract_clone_detector_adapter import ContractCloneDetectorAdapter

logger = logging.getLogger(__name__)


def register_all_adapters():
    """
    Registra todos los adaptadores disponibles en el sistema.

    Este es el punto de entrada principal para inicializar el registro
    de herramientas. Debe ser llamado al inicio de MIESC.

    Returns:
        dict: Reporte de estado de registro
    """
    registry = get_tool_registry()
    registered = []
    failed = []

    # Lista de adaptadores a registrar (22 adapters - 7 layers)
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
        # Layer 5 - AI-Powered Analysis (Fase 5 - 2025)
        ("smartllm", SmartLLMAdapter),
        ("gptscan", GPTScanAdapter),
        ("llmsmartaudit", LLMSmartAuditAdapter),
        # Layer 6 - ML-Based Detection (Fase 6 - 2025)
        ("smartbugs_ml", SmartBugsMLAdapter),
        ("contract_clone_detector", ContractCloneDetectorAdapter),
    ]

    logger.info("Iniciando registro de adaptadores de herramientas...")

    for name, adapter_class in adapters_to_register:
        try:
            # Instanciar adapter
            adapter = adapter_class()

            # Registrar en el registry
            registry.register(adapter)

            # Verificar disponibilidad
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
            logger.error(f"❌ Error registrando {name}: {e}")

    # Reporte de registro
    report = {
        "total_adapters": len(adapters_to_register),
        "registered": len(registered),
        "failed": len(failed),
        "adapters": registered,
        "failures": failed
    }

    # Log resumen
    logger.info(f"\n{'='*60}")
    logger.info(f"Registro de adaptadores completado:")
    logger.info(f"  Total: {report['total_adapters']}")
    logger.info(f"  Registrados: {report['registered']}")
    logger.info(f"  Fallidos: {report['failed']}")
    logger.info(f"{'='*60}\n")

    # Verificar cumplimiento DPGA: TODAS las tools deben ser opcionales
    non_optional = [a for a in registered if not a.get("optional", True)]
    if non_optional:
        logger.warning(
            f"⚠️ ADVERTENCIA DPGA: Herramientas no-opcionales detectadas: {non_optional}"
        )
    else:
        logger.info("✅ Cumplimiento DPGA verificado: Todas las herramientas son opcionales")

    return report


def get_available_adapters():
    """
    Retorna lista de adaptadores disponibles (instalados y listos).

    Returns:
        list: Lista de ToolAdapter disponibles
    """
    registry = get_tool_registry()
    return registry.get_available_tools()


def get_adapter_status_report():
    """
    Genera reporte completo de estado de adaptadores.

    Returns:
        dict: Reporte con estado de todas las herramientas
    """
    registry = get_tool_registry()
    return registry.get_tool_status_report()


def get_adapter_by_name(name: str):
    """
    Obtiene un adapter específico por nombre.

    Args:
        name: Nombre del adapter (ej: "gas_analyzer")

    Returns:
        ToolAdapter or None: Adapter solicitado
    """
    registry = get_tool_registry()
    return registry.get_tool(name)


# Auto-registro al importar el módulo (optional)
# Descomenta la siguiente línea si quieres auto-registro
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
