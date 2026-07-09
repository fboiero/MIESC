"""
MIESC Detectors Module

Provides custom vulnerability detection capabilities for smart contracts.
"""

from .advanced_detectors import (
    AdvancedDetectorEngine,
    AdvancedFinding,
    CentralizationDetector,
    GovernanceDetector,
    ProxyUpgradeDetector,
    RugPullDetector,
    TokenSecurityDetector,
)
from .detector_api import (
    BaseDetector,
    Category,
    DetectorRegistry,
    Finding,
    Location,
    PatternDetector,
    Severity,
    get_registry,
    register_detector,
)
from .transient_storage_detector import (
    TransientStorageDetector,
    detect_transient_storage_risks,
)

__all__ = [
    # Base API
    "Severity",
    "Category",
    "Location",
    "Finding",
    "BaseDetector",
    "PatternDetector",
    "DetectorRegistry",
    "register_detector",
    "get_registry",
    # Advanced detectors
    "AdvancedFinding",
    "AdvancedDetectorEngine",
    "RugPullDetector",
    "GovernanceDetector",
    "TokenSecurityDetector",
    "ProxyUpgradeDetector",
    "CentralizationDetector",
    "TransientStorageDetector",
    "detect_transient_storage_risks",
]
