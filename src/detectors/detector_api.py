#!/usr/bin/env python3
"""
MIESC v4.3 - Custom Detector API

Provides a simple, extensible API for creating custom vulnerability detectors.
Security researchers can create their own detectors by subclassing BaseDetector.

Usage:
    from miesc.detectors import BaseDetector, Finding, Severity

    class MyCustomDetector(BaseDetector):
        name = "my-custom-detector"
        description = "Detects my custom vulnerability pattern"

        def analyze(self, source_code: str, file_path: Path = None) -> list[Finding]:
            findings = []
            # Your detection logic here
            return findings

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Any, Pattern
import re
import importlib.metadata


class Severity(Enum):
    """Vulnerability severity levels following CVSS classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Convert string to Severity enum."""
        return cls(value.lower())

    def __lt__(self, other):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


class Category(Enum):
    """Vulnerability categories for classification."""
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"
    FLASH_LOAN = "flash_loan"
    ORACLE_MANIPULATION = "oracle_manipulation"
    GOVERNANCE = "governance"
    RUG_PULL = "rug_pull"
    HONEYPOT = "honeypot"
    PROXY_UPGRADE = "proxy_upgrade"
    CENTRALIZATION = "centralization"
    DOS = "denial_of_service"
    FRONT_RUNNING = "front_running"
    TIMESTAMP_DEPENDENCY = "timestamp_dependency"
    UNCHECKED_RETURN = "unchecked_return"
    GAS_OPTIMIZATION = "gas_optimization"
    CUSTOM = "custom"


@dataclass
class Location:
    """Source code location information."""
    file_path: Optional[Path] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None

    def __str__(self) -> str:
        if self.file_path and self.line_start:
            return f"{self.file_path}:{self.line_start}"
        elif self.line_start:
            return f"line {self.line_start}"
        return "unknown"


@dataclass
class Finding:
    """
    Represents a security finding/vulnerability.

    This is the standard output format for all MIESC detectors.
    Custom detectors should return a list of Finding objects.
    """
    # Required fields
    detector: str
    title: str
    description: str
    severity: Severity

    # Optional fields with defaults
    category: Category = Category.CUSTOM
    confidence: str = "high"  # high, medium, low
    location: Optional[Location] = None
    code_snippet: Optional[str] = None
    recommendation: str = ""
    references: List[str] = field(default_factory=list)

    # For correlation with other tools
    cwe_id: Optional[str] = None
    swc_id: Optional[str] = None

    # Custom metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "detector": self.detector,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": self.confidence,
            "location": str(self.location) if self.location else None,
            "line": self.location.line_start if self.location else None,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "references": self.references,
            "cwe_id": self.cwe_id,
            "swc_id": self.swc_id,
            "metadata": self.metadata,
        }


class BaseDetector(ABC):
    r"""
    Abstract base class for custom vulnerability detectors.

    To create a custom detector:
    1. Subclass BaseDetector
    2. Set the class attributes (name, description, etc.)
    3. Implement the analyze() method
    4. Register your detector with MIESC

    Example:
        class FlashLoanDetector(BaseDetector):
            name = "flash-loan"
            description = "Detects flash loan attack patterns"
            category = Category.FLASH_LOAN
            default_severity = Severity.HIGH

            PATTERNS = [
                (r'balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)', "Direct balance check"),
            ]

            def analyze(self, source_code: str, file_path: Path = None) -> list[Finding]:
                findings = []
                for pattern, desc in self.PATTERNS:
                    for match in re.finditer(pattern, source_code):
                        findings.append(self.create_finding(
                            title="Flash Loan Vulnerability",
                            description=desc,
                            line=source_code[:match.start()].count('\\n') + 1,
                            code_snippet=match.group(0),
                        ))
                return findings
    """

    # Class attributes (override in subclass)
    name: str = "base-detector"
    description: str = "Base detector class"
    version: str = "1.0.0"
    author: str = ""
    category: Category = Category.CUSTOM
    default_severity: Severity = Severity.MEDIUM

    # Optional: target contract types (if empty, runs on all)
    target_patterns: List[str] = []  # e.g., ["ERC20", "Governor"]

    def __init__(self):
        """Initialize detector."""
        self._enabled = True
        self._config: Dict[str, Any] = {}

    @property
    def enabled(self) -> bool:
        """Check if detector is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        """Enable or disable detector."""
        self._enabled = value

    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure detector with custom settings.

        Override this method to handle detector-specific configuration.
        """
        self._config = config

    def should_run(self, source_code: str) -> bool:
        """
        Check if detector should run on this source code.

        Override for custom logic. By default, checks target_patterns.
        """
        if not self.target_patterns:
            return True
        return any(
            re.search(pattern, source_code, re.IGNORECASE)
            for pattern in self.target_patterns
        )

    @abstractmethod
    def analyze(self, source_code: str, file_path: Optional[Path] = None) -> List[Finding]:
        """
        Analyze source code and return findings.

        This is the main method to implement in custom detectors.

        Args:
            source_code: The Solidity source code to analyze
            file_path: Optional path to the source file

        Returns:
            List of Finding objects representing detected vulnerabilities
        """
        pass

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """
        Convenience method to analyze a file directly.

        Args:
            file_path: Path to the Solidity file

        Returns:
            List of Finding objects
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        return self.analyze(source_code, file_path)

    def create_finding(
        self,
        title: str,
        description: str,
        severity: Optional[Severity] = None,
        line: Optional[int] = None,
        code_snippet: Optional[str] = None,
        recommendation: str = "",
        references: Optional[List[str]] = None,
        **kwargs
    ) -> Finding:
        """
        Helper method to create a Finding with detector defaults.

        This simplifies finding creation in the analyze() method.
        """
        location = None
        if line:
            location = Location(line_start=line)

        return Finding(
            detector=self.name,
            title=title,
            description=description,
            severity=severity or self.default_severity,
            category=self.category,
            location=location,
            code_snippet=code_snippet,
            recommendation=recommendation,
            references=references or [],
            **kwargs
        )

    def find_pattern(
        self,
        source_code: str,
        pattern: str,
        flags: int = re.IGNORECASE
    ) -> List[tuple]:
        """
        Find all matches of a pattern in source code.

        Returns list of (match_object, line_number, line_content) tuples.
        """
        results = []
        lines = source_code.split('\n')

        for i, line in enumerate(lines, 1):
            for match in re.finditer(pattern, line, flags):
                results.append((match, i, line.strip()))

        return results

    def find_multiline_pattern(
        self,
        source_code: str,
        pattern: str,
        flags: int = re.IGNORECASE | re.DOTALL
    ) -> List[tuple]:
        """
        Find multiline patterns in source code.

        Returns list of (match_object, start_line, end_line) tuples.
        """
        results = []

        for match in re.finditer(pattern, source_code, flags):
            start_line = source_code[:match.start()].count('\n') + 1
            end_line = source_code[:match.end()].count('\n') + 1
            results.append((match, start_line, end_line))

        return results


class PatternDetector(BaseDetector):
    r"""
    Simplified detector for pattern-based detection.

    Define PATTERNS as a list of (regex_pattern, description, severity) tuples.
    The detector will automatically scan for all patterns.

    Example:
        class UnsafeExternalCallDetector(PatternDetector):
            name = "unsafe-external-call"
            description = "Detects unsafe external calls"

            PATTERNS = [
                (r'\.call\{value:', "Unchecked external call with value", Severity.HIGH),
                (r'\.delegatecall\(', "Delegatecall detected", Severity.MEDIUM),
            ]
    """

    # Define patterns as: (regex, description, severity)
    # Override in subclass
    PATTERNS: List[tuple] = []

    def analyze(self, source_code: str, file_path: Optional[Path] = None) -> List[Finding]:
        """Analyze source code using defined patterns."""
        if not self.should_run(source_code):
            return []

        findings = []

        for pattern_tuple in self.PATTERNS:
            if len(pattern_tuple) == 2:
                pattern, description = pattern_tuple
                severity = self.default_severity
            else:
                pattern, description, severity = pattern_tuple

            matches = self.find_pattern(source_code, pattern)

            for match, line, code in matches:
                findings.append(self.create_finding(
                    title=f"{self.name}: {description[:50]}",
                    description=description,
                    severity=severity,
                    line=line,
                    code_snippet=code,
                ))

        return findings


class DetectorRegistry:
    """
    Registry for managing custom detectors.

    Detectors can be registered manually or discovered via entry points.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._detectors: Dict[str, BaseDetector] = {}
            cls._instance._loaded_plugins = False
        return cls._instance

    @property
    def detectors(self) -> Dict[str, BaseDetector]:
        """Get all registered detectors."""
        if not self._loaded_plugins:
            self._load_plugins()
        return self._detectors

    def register(self, detector: BaseDetector) -> None:
        """
        Register a detector instance.

        Args:
            detector: Detector instance to register
        """
        self._detectors[detector.name] = detector

    def register_class(self, detector_class: type) -> None:
        """
        Register a detector class (will be instantiated).

        Args:
            detector_class: Detector class to register
        """
        detector = detector_class()
        self.register(detector)

    def unregister(self, name: str) -> None:
        """Remove a detector from registry."""
        if name in self._detectors:
            del self._detectors[name]

    def get(self, name: str) -> Optional[BaseDetector]:
        """Get a detector by name."""
        return self.detectors.get(name)

    def list_detectors(self) -> List[str]:
        """List all registered detector names."""
        return list(self.detectors.keys())

    def _load_plugins(self) -> None:
        """Load detectors from entry points."""
        self._loaded_plugins = True

        try:
            # Python 3.10+ style
            entry_points = importlib.metadata.entry_points()
            if hasattr(entry_points, 'select'):
                detectors_eps = entry_points.select(group='miesc.detectors')
            else:
                detectors_eps = entry_points.get('miesc.detectors', [])

            for ep in detectors_eps:
                try:
                    detector_class = ep.load()
                    self.register_class(detector_class)
                except Exception as e:
                    print(f"Warning: Failed to load detector {ep.name}: {e}")
        except Exception:
            pass  # Entry points not available

    def run_all(
        self,
        source_code: str,
        file_path: Optional[Path] = None,
        enabled_only: bool = True
    ) -> List[Finding]:
        """
        Run all registered detectors on source code.

        Args:
            source_code: Source code to analyze
            file_path: Optional file path
            enabled_only: Only run enabled detectors

        Returns:
            Combined list of findings from all detectors
        """
        all_findings = []

        for detector in self.detectors.values():
            if enabled_only and not detector.enabled:
                continue

            try:
                findings = detector.analyze(source_code, file_path)
                all_findings.extend(findings)
            except Exception as e:
                print(f"Warning: Detector {detector.name} failed: {e}")

        return all_findings

    def get_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate summary statistics for findings."""
        summary = {
            'total': len(findings),
            'by_severity': {},
            'by_category': {},
            'by_detector': {},
        }

        for finding in findings:
            sev = finding.severity.value
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1

            cat = finding.category.value
            summary['by_category'][cat] = summary['by_category'].get(cat, 0) + 1

            det = finding.detector
            summary['by_detector'][det] = summary['by_detector'].get(det, 0) + 1

        return summary


# Global registry instance
_registry = DetectorRegistry()


def register_detector(detector: BaseDetector) -> None:
    """
    Register a custom detector with MIESC.

    Example:
        from miesc.detectors import register_detector, BaseDetector

        class MyDetector(BaseDetector):
            ...

        register_detector(MyDetector())
    """
    _registry.register(detector)


def get_registry() -> DetectorRegistry:
    """Get the global detector registry."""
    return _registry


# Export public API
__all__ = [
    'Severity',
    'Category',
    'Location',
    'Finding',
    'BaseDetector',
    'PatternDetector',
    'DetectorRegistry',
    'register_detector',
    'get_registry',
]
