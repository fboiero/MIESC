"""
MIESC Built-in Detectors - Re-exports for entry point registration.

This module provides re-exports from src.detectors.example_detectors
to enable proper namespace resolution for the miesc.detectors entry points.

For creating custom detectors, see the miesc.detectors module documentation.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

# Re-export detector classes from src.detectors for entry point registration
from src.detectors.example_detectors import (
    AccessControlDetector,
    FlashLoanDetector,
    MEVDetector,
    UncheckedCallDetector,
)

__all__ = [
    "UncheckedCallDetector",
    "FlashLoanDetector",
    "MEVDetector",
    "AccessControlDetector",
]
