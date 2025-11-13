"""
MIESC Integration Layer
=======================

Provides bridge between Agents and Tool Adapters via Tool Registry.
Ensures DPGA compliance by making all adapter integrations optional.

Autor: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Fecha: 2025-01-10
"""

from src.integration.adapter_integration import (
    AdapterIntegration,
    integrate_static_analysis,
    integrate_dynamic_testing,
    integrate_symbolic_execution,
    integrate_threat_modeling
)

__all__ = [
    "AdapterIntegration",
    "integrate_static_analysis",
    "integrate_dynamic_testing",
    "integrate_symbolic_execution",
    "integrate_threat_modeling",
]
