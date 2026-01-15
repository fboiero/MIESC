"""
MIESC Custom Detector API
=========================

This module provides the API for creating custom security detectors.
Researchers and developers can create their own detectors by subclassing
the BaseDetector class.

Example:
    from miesc.detectors import BaseDetector, Finding, Severity

    class FlashLoanDetector(BaseDetector):
        name = "flash-loan-attack"
        description = "Detects flash loan attack patterns"
        category = "defi"

        def analyze(self, source_code: str, file_path: str = None) -> list[Finding]:
            findings = []
            # Your detection logic here
            return findings

    # Register the detector
    from miesc.detectors import register_detector
    register_detector(FlashLoanDetector)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Type
from abc import ABC, abstractmethod
from pathlib import Path
import logging
import importlib
import pkgutil

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Severity levels for security findings."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(Enum):
    """Confidence levels for findings."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Location:
    """Location of a finding in the source code."""
    file: str
    line: int
    column: int = 0
    end_line: int = 0
    end_column: int = 0
    function: str = ""
    contract: str = ""


@dataclass
class Finding:
    """
    A security finding from a detector.

    Attributes:
        detector: Name of the detector that found this issue
        title: Short title of the finding
        description: Detailed description of the issue
        severity: Severity level (Critical, High, Medium, Low, Info)
        confidence: Confidence level (high, medium, low)
        location: Source code location
        recommendation: How to fix the issue
        references: Links to relevant documentation
        metadata: Additional detector-specific data
    """
    detector: str
    title: str
    description: str
    severity: Severity
    location: Location
    confidence: Confidence = Confidence.MEDIUM
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    swc_id: Optional[str] = None
    cwe_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary format."""
        return {
            "id": f"{self.detector}-{id(self)}",
            "detector": self.detector,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "location": {
                "file": self.location.file,
                "line": self.location.line,
                "column": self.location.column,
                "function": self.location.function,
                "contract": self.location.contract,
            },
            "recommendation": self.recommendation,
            "references": self.references,
            "swc_id": self.swc_id,
            "cwe_id": self.cwe_id,
            "metadata": self.metadata,
        }


class BaseDetector(ABC):
    """
    Base class for custom security detectors.

    To create a custom detector:
    1. Subclass BaseDetector
    2. Set the class attributes (name, description, category)
    3. Implement the analyze() method
    4. Register with register_detector()

    Example:
        class MyDetector(BaseDetector):
            name = "my-detector"
            description = "Detects my custom vulnerability pattern"
            category = "custom"
            severity_default = Severity.MEDIUM

            def analyze(self, source_code, file_path=None):
                findings = []
                # Detection logic here
                if "dangerous_pattern" in source_code:
                    findings.append(Finding(
                        detector=self.name,
                        title="Dangerous Pattern Found",
                        description="The code contains a dangerous pattern",
                        severity=self.severity_default,
                        location=Location(file=file_path, line=1),
                        recommendation="Remove the dangerous pattern"
                    ))
                return findings
    """

    # Required class attributes
    name: str = "base-detector"
    description: str = "Base detector class"
    category: str = "general"

    # Optional class attributes
    severity_default: Severity = Severity.MEDIUM
    confidence_default: Confidence = Confidence.MEDIUM
    version: str = "1.0.0"
    author: str = ""
    references: List[str] = []

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the detector with optional configuration.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self._enabled = True

    @abstractmethod
    def analyze(self, source_code: str, file_path: str = None) -> List[Finding]:
        """
        Analyze source code and return findings.

        Args:
            source_code: The Solidity source code to analyze
            file_path: Optional path to the source file

        Returns:
            List of Finding objects
        """
        pass

    def is_enabled(self) -> bool:
        """Check if the detector is enabled."""
        return self._enabled

    def enable(self):
        """Enable the detector."""
        self._enabled = True

    def disable(self):
        """Disable the detector."""
        self._enabled = False

    def get_metadata(self) -> Dict[str, Any]:
        """Get detector metadata."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity_default.value,
            "version": self.version,
            "author": self.author,
            "references": self.references,
        }

    def create_finding(
        self,
        title: str,
        description: str,
        line: int,
        file_path: str = "",
        severity: Severity = None,
        confidence: Confidence = None,
        function: str = "",
        contract: str = "",
        recommendation: str = "",
        **kwargs
    ) -> Finding:
        """
        Helper method to create a Finding with common defaults.

        Args:
            title: Short title of the finding
            description: Detailed description
            line: Line number in source
            file_path: Path to source file
            severity: Severity level (defaults to detector's default)
            confidence: Confidence level (defaults to detector's default)
            function: Function name if applicable
            contract: Contract name if applicable
            recommendation: How to fix
            **kwargs: Additional metadata

        Returns:
            Finding object
        """
        return Finding(
            detector=self.name,
            title=title,
            description=description,
            severity=severity or self.severity_default,
            confidence=confidence or self.confidence_default,
            location=Location(
                file=file_path or "",
                line=line,
                function=function,
                contract=contract,
            ),
            recommendation=recommendation,
            references=self.references.copy(),
            metadata=kwargs,
        )


# Global detector registry
_detector_registry: Dict[str, Type[BaseDetector]] = {}


def register_detector(detector_class: Type[BaseDetector]) -> None:
    """
    Register a custom detector.

    Args:
        detector_class: A class that inherits from BaseDetector

    Example:
        @register_detector
        class MyDetector(BaseDetector):
            ...

        # Or without decorator:
        register_detector(MyDetector)
    """
    if not issubclass(detector_class, BaseDetector):
        raise TypeError(f"{detector_class} must be a subclass of BaseDetector")

    name = detector_class.name
    if name in _detector_registry:
        logger.warning(f"Detector '{name}' already registered, overwriting")

    _detector_registry[name] = detector_class
    logger.info(f"Registered detector: {name}")

    return detector_class  # Allow use as decorator


def unregister_detector(name: str) -> bool:
    """
    Unregister a detector by name.

    Args:
        name: Name of the detector to unregister

    Returns:
        True if unregistered, False if not found
    """
    if name in _detector_registry:
        del _detector_registry[name]
        logger.info(f"Unregistered detector: {name}")
        return True
    return False


def get_detector(name: str) -> Optional[Type[BaseDetector]]:
    """Get a detector class by name."""
    return _detector_registry.get(name)


def get_all_detectors() -> Dict[str, Type[BaseDetector]]:
    """Get all registered detectors."""
    return _detector_registry.copy()


def list_detectors() -> List[Dict[str, Any]]:
    """List all registered detectors with metadata."""
    result = []
    for name, detector_class in _detector_registry.items():
        try:
            detector = detector_class()
            result.append(detector.get_metadata())
        except Exception as e:
            logger.error(f"Error getting metadata for {name}: {e}")
    return result


def run_detector(name: str, source_code: str, file_path: str = None, config: Dict = None) -> List[Finding]:
    """
    Run a specific detector on source code.

    Args:
        name: Name of the detector
        source_code: Solidity source code
        file_path: Optional file path
        config: Optional detector configuration

    Returns:
        List of findings
    """
    detector_class = get_detector(name)
    if not detector_class:
        raise ValueError(f"Detector '{name}' not found")

    detector = detector_class(config)
    if not detector.is_enabled():
        return []

    return detector.analyze(source_code, file_path)


def run_all_detectors(source_code: str, file_path: str = None, categories: List[str] = None) -> List[Finding]:
    """
    Run all registered detectors on source code.

    Args:
        source_code: Solidity source code
        file_path: Optional file path
        categories: Optional list of categories to filter by

    Returns:
        Combined list of findings from all detectors
    """
    all_findings = []

    for name, detector_class in _detector_registry.items():
        try:
            detector = detector_class()

            # Filter by category if specified
            if categories and detector.category not in categories:
                continue

            if not detector.is_enabled():
                continue

            findings = detector.analyze(source_code, file_path)
            all_findings.extend(findings)
            logger.debug(f"Detector {name}: {len(findings)} findings")

        except Exception as e:
            logger.error(f"Error running detector {name}: {e}")

    return all_findings


def load_detectors_from_package(package_name: str) -> int:
    """
    Load detectors from a Python package.

    Searches for classes that inherit from BaseDetector
    in the specified package and registers them.

    Args:
        package_name: Name of the package to load from

    Returns:
        Number of detectors loaded
    """
    loaded = 0
    try:
        package = importlib.import_module(package_name)

        for _, module_name, _ in pkgutil.iter_modules(package.__path__):
            try:
                module = importlib.import_module(f"{package_name}.{module_name}")

                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and
                        issubclass(attr, BaseDetector) and
                        attr is not BaseDetector):
                        register_detector(attr)
                        loaded += 1

            except Exception as e:
                logger.error(f"Error loading module {module_name}: {e}")

    except Exception as e:
        logger.error(f"Error loading package {package_name}: {e}")

    return loaded


def load_local_plugins() -> int:
    """
    Load detectors from local plugins directory (~/.miesc/plugins/).

    Returns:
        Number of detectors loaded
    """
    loaded = 0
    try:
        from miesc.plugins import PluginManager

        manager = PluginManager()
        local_detectors = manager.get_local_plugin_detectors()

        for name, detector_class in local_detectors:
            try:
                register_detector(detector_class)
                loaded += 1
            except Exception as e:
                logger.error(f"Error registering local detector {name}: {e}")

    except ImportError:
        logger.debug("Plugin manager not available, skipping local plugins")
    except Exception as e:
        logger.error(f"Error loading local plugins: {e}")

    return loaded


# Export public API
__all__ = [
    "Severity",
    "Confidence",
    "Location",
    "Finding",
    "BaseDetector",
    "register_detector",
    "unregister_detector",
    "get_detector",
    "get_all_detectors",
    "list_detectors",
    "run_detector",
    "run_all_detectors",
    "load_detectors_from_package",
    "load_local_plugins",
]
