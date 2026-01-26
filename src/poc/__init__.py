"""
MIESC PoC Generator Module
==========================

Automated Proof-of-Concept exploit generation from vulnerability findings.
Generates Foundry test templates that demonstrate exploitability.

Features:
- Finding-to-PoC mapping
- Foundry test template generation
- Multiple vulnerability type support
- Customizable exploit parameters
- Automatic PoC validation

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

from .poc_generator import (
    PoCGenerator,
    PoCTemplate,
    PoCResult,
    VulnerabilityType,
    GenerationOptions,
)

__all__ = [
    "PoCGenerator",
    "PoCTemplate",
    "PoCResult",
    "VulnerabilityType",
    "GenerationOptions",
]

__version__ = "1.0.0"
