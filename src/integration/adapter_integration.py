"""
Adapter Integration Layer
==========================

Bridges MIESC Agents with Tool Adapters via Tool Registry.

Architecture:
    Agent → Integration Layer → Tool Registry → Adapter → External Tool

DPGA Compliance:
    - All adapters are optional
    - Graceful degradation if adapter unavailable
    - Agents work independently of adapters
    - No vendor lock-in

Integration Patterns:
    - Layer 1 (Static): GasAnalyzer, MEVDetector
    - Layer 2 (Dynamic): VertigoAdapter
    - Layer 3 (Symbolic): OyenteAdapter
    - Layer 7 (Audit): ThreatModelAdapter

Autor: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Fecha: 2025-01-10
"""

import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

from src.core.tool_protocol import get_tool_registry, ToolStatus
from src.adapters import register_all_adapters

logger = logging.getLogger(__name__)


class AdapterIntegration:
    """
    Central integration manager for Tool Adapters.

    Responsibilities:
    - Initialize Tool Registry with all adapters
    - Route analysis requests to appropriate adapters
    - Aggregate results from multiple adapters
    - Handle adapter failures gracefully (DPGA compliance)
    """

    def __init__(self, auto_register: bool = True):
        """
        Initialize Adapter Integration Layer

        Args:
            auto_register: Automatically register all adapters on init (default: True)
        """
        self.registry = get_tool_registry()
        self._initialized = False

        if auto_register:
            self.initialize()

    def initialize(self) -> Dict[str, Any]:
        """
        Initialize integration layer by registering all adapters

        Returns:
            Registration report
        """
        if self._initialized:
            logger.info("AdapterIntegration already initialized")
            return {"status": "already_initialized"}

        logger.info("Initializing Adapter Integration Layer...")
        report = register_all_adapters()
        self._initialized = True

        logger.info(
            f"Adapter Integration initialized: {report['registered']}/{report['total_adapters']} adapters"
        )
        return report

    def get_adapter(self, name: str):
        """
        Get adapter by name from registry

        Args:
            name: Adapter name (e.g., "gas_analyzer")

        Returns:
            ToolAdapter instance or None if not found/unavailable
        """
        adapter = self.registry.get_tool(name)

        if adapter is None:
            logger.warning(f"Adapter '{name}' not found in registry")
            return None

        # Check availability
        status = adapter.is_available()
        if status != ToolStatus.AVAILABLE:
            logger.warning(f"Adapter '{name}' not available: {status.value}")
            return None

        return adapter

    def run_adapter(self, name: str, contract_path: str, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Run a specific adapter on contract

        Args:
            name: Adapter name
            contract_path: Path to Solidity contract
            **kwargs: Adapter-specific parameters

        Returns:
            Adapter results or None if adapter unavailable
        """
        adapter = self.get_adapter(name)
        if adapter is None:
            return None

        try:
            logger.info(f"Running adapter '{name}' on {contract_path}")
            result = adapter.analyze(contract_path, **kwargs)
            return result
        except Exception as e:
            logger.error(f"Adapter '{name}' failed: {e}", exc_info=True)
            return None

    def run_multiple_adapters(
        self,
        adapter_names: List[str],
        contract_path: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Run multiple adapters and aggregate results

        Args:
            adapter_names: List of adapter names to run
            contract_path: Path to Solidity contract
            **kwargs: Common parameters for all adapters

        Returns:
            Aggregated results from all adapters
        """
        results = {
            "total_adapters": len(adapter_names),
            "successful": 0,
            "failed": 0,
            "findings": [],
            "adapter_results": {}
        }

        for name in adapter_names:
            adapter_result = self.run_adapter(name, contract_path, **kwargs)

            if adapter_result is not None:
                results["successful"] += 1
                results["adapter_results"][name] = adapter_result

                # Extract and normalize findings
                if "findings" in adapter_result:
                    results["findings"].extend(adapter_result["findings"])
            else:
                results["failed"] += 1
                results["adapter_results"][name] = {"status": "unavailable"}

        return results

    def get_status_report(self) -> Dict[str, Any]:
        """
        Get status report of all adapters

        Returns:
            Status report with adapter availability
        """
        return self.registry.get_tool_status_report()


# ============================================================================
# Layer-Specific Integration Functions
# ============================================================================

def integrate_static_analysis(contract_path: str, **kwargs) -> Dict[str, Any]:
    """
    Integrate Layer 1 (Static Analysis) adapters:
    - GasAnalyzer: Gas optimization patterns
    - MEVDetector: MEV vulnerability detection

    Args:
        contract_path: Path to Solidity contract
        **kwargs: Optional parameters for adapters

    Returns:
        Aggregated static analysis results
    """
    integration = AdapterIntegration()

    adapters = ["gas_analyzer", "mev_detector"]
    results = integration.run_multiple_adapters(adapters, contract_path, **kwargs)

    # Calculate aggregate metrics
    total_gas_savings = 0
    mev_risk_score = 0

    for adapter_name, adapter_result in results["adapter_results"].items():
        if adapter_result.get("status") == "success":
            if adapter_name == "gas_analyzer":
                total_gas_savings = adapter_result.get("metadata", {}).get("total_gas_savings", 0)
            elif adapter_name == "mev_detector":
                mev_risk_score = adapter_result.get("metadata", {}).get("mev_risk_score", 0)

    results["metadata"] = {
        "total_gas_savings": total_gas_savings,
        "mev_risk_score": mev_risk_score,
        "total_findings": len(results["findings"])
    }

    return results


def integrate_dynamic_testing(contract_path: str, **kwargs) -> Dict[str, Any]:
    """
    Integrate Layer 2 (Dynamic Testing) adapters:
    - VertigoAdapter: Mutation testing for test quality

    Args:
        contract_path: Path to Solidity contract
        **kwargs: Optional parameters
            - test_command: Test command to run (default: "forge test")
            - mutation_count: Number of mutations (default: 10)
            - sample_ratio: Mutation sampling ratio (default: 0.1)

    Returns:
        Dynamic testing results
    """
    integration = AdapterIntegration()

    adapters = ["vertigo"]
    results = integration.run_multiple_adapters(adapters, contract_path, **kwargs)

    # Extract mutation score
    mutation_score = 0
    if "vertigo" in results["adapter_results"]:
        vertigo_result = results["adapter_results"]["vertigo"]
        if vertigo_result.get("status") == "success":
            mutation_score = vertigo_result.get("metadata", {}).get("mutation_score", 0)

    results["metadata"] = {
        "mutation_score": mutation_score,
        "total_findings": len(results["findings"])
    }

    return results


def integrate_symbolic_execution(contract_path: str, **kwargs) -> Dict[str, Any]:
    """
    Integrate Layer 3 (Symbolic Execution) adapters:
    - OyenteAdapter: Docker-based symbolic execution

    Args:
        contract_path: Path to Solidity contract
        **kwargs: Optional parameters
            - timeout: Analysis timeout in seconds (default: 300)

    Returns:
        Symbolic execution results
    """
    integration = AdapterIntegration()

    adapters = ["oyente"]
    results = integration.run_multiple_adapters(adapters, contract_path, **kwargs)

    # Extract vulnerability types
    vuln_types = set()
    if "oyente" in results["adapter_results"]:
        oyente_result = results["adapter_results"]["oyente"]
        if oyente_result.get("status") == "success":
            for finding in oyente_result.get("findings", []):
                vuln_types.add(finding.get("type", "unknown"))

    results["metadata"] = {
        "vulnerability_types": list(vuln_types),
        "total_findings": len(results["findings"])
    }

    return results


def integrate_threat_modeling(contract_path: str, **kwargs) -> Dict[str, Any]:
    """
    Integrate Layer 7 (Audit Readiness) adapters:
    - ThreatModelAdapter: STRIDE/DREAD threat analysis

    Args:
        contract_path: Path to Solidity contract
        **kwargs: Optional parameters
            - framework: "STRIDE" or "DREAD" (default: "STRIDE")
            - min_dread_score: Minimum DREAD score to include (default: 0.0)

    Returns:
        Threat modeling results
    """
    integration = AdapterIntegration()

    adapters = ["threat_model"]
    results = integration.run_multiple_adapters(adapters, contract_path, **kwargs)

    # Extract threat metrics
    stride_breakdown = {}
    audit_readiness_score = 0
    avg_dread = 0

    if "threat_model" in results["adapter_results"]:
        threat_result = results["adapter_results"]["threat_model"]
        if threat_result.get("status") == "success":
            metadata = threat_result.get("metadata", {})
            stride_breakdown = metadata.get("stride_breakdown", {})
            audit_readiness_score = metadata.get("audit_readiness_score", 0)
            avg_dread = metadata.get("average_dread_score", 0)

    results["metadata"] = {
        "stride_breakdown": stride_breakdown,
        "audit_readiness_score": audit_readiness_score,
        "average_dread_score": avg_dread,
        "total_threats": len(results["findings"])
    }

    return results


# ============================================================================
# Convenience Function: Run All Available Adapters
# ============================================================================

def run_all_adapters(contract_path: str, **kwargs) -> Dict[str, Any]:
    """
    Run ALL available adapters on contract (convenience function)

    Args:
        contract_path: Path to Solidity contract
        **kwargs: Optional parameters for adapters

    Returns:
        Complete analysis results from all adapters
    """
    logger.info(f"Running complete adapter analysis on {contract_path}")

    # Layer 1: Static Analysis
    logger.info("Layer 1: Running Static Analysis adapters...")
    static_results = integrate_static_analysis(contract_path, **kwargs)

    # Layer 2: Dynamic Testing
    logger.info("Layer 2: Running Dynamic Testing adapters...")
    dynamic_results = integrate_dynamic_testing(contract_path, **kwargs)

    # Layer 3: Symbolic Execution
    logger.info("Layer 3: Running Symbolic Execution adapters...")
    symbolic_results = integrate_symbolic_execution(contract_path, **kwargs)

    # Layer 7: Threat Modeling
    logger.info("Layer 7: Running Threat Modeling adapters...")
    threat_results = integrate_threat_modeling(contract_path, **kwargs)

    # Aggregate all results
    all_findings = (
        static_results["findings"] +
        dynamic_results["findings"] +
        symbolic_results["findings"] +
        threat_results["findings"]
    )

    complete_results = {
        "contract_path": contract_path,
        "total_findings": len(all_findings),
        "findings": all_findings,
        "layer_results": {
            "layer_1_static": static_results,
            "layer_2_dynamic": dynamic_results,
            "layer_3_symbolic": symbolic_results,
            "layer_7_threat": threat_results
        },
        "summary": {
            "total_gas_savings": static_results["metadata"].get("total_gas_savings", 0),
            "mev_risk_score": static_results["metadata"].get("mev_risk_score", 0),
            "mutation_score": dynamic_results["metadata"].get("mutation_score", 0),
            "audit_readiness_score": threat_results["metadata"].get("audit_readiness_score", 0),
            "total_adapters_run": (
                static_results["successful"] +
                dynamic_results["successful"] +
                symbolic_results["successful"] +
                threat_results["successful"]
            )
        }
    }

    logger.info(
        f"Complete analysis finished: {complete_results['total_findings']} findings, "
        f"{complete_results['summary']['total_adapters_run']} adapters executed"
    )

    return complete_results
