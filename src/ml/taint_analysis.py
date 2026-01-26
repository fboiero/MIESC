"""
MIESC Taint Analysis Module v4.6.0
==================================

Basic taint analysis for smart contracts.
Tracks flow of user-controlled data to dangerous sinks.

Features:
- Source identification (msg.sender, msg.value, parameters, etc.)
- Sink detection (call, delegatecall, selfdestruct, sstore)
- Sanitizer recognition (require, assert, if checks)
- Tainted path detection

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
License: AGPL-3.0
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class TaintSource(Enum):
    """Sources of user-controlled (tainted) data."""
    MSG_SENDER = "msg.sender"
    MSG_VALUE = "msg.value"
    MSG_DATA = "msg.data"
    TX_ORIGIN = "tx.origin"
    BLOCK_TIMESTAMP = "block.timestamp"
    BLOCK_NUMBER = "block.number"
    BLOCK_COINBASE = "block.coinbase"
    FUNCTION_PARAM = "function_parameter"
    EXTERNAL_CALL_RETURN = "external_call_return"
    STORAGE_READ = "storage_read"


class TaintSink(Enum):
    """Dangerous operations (sinks) that should not receive untrusted data."""
    CALL = "call"
    DELEGATECALL = "delegatecall"
    STATICCALL = "staticcall"
    TRANSFER = "transfer"
    SEND = "send"
    SELFDESTRUCT = "selfdestruct"
    SSTORE = "sstore"  # Storage write
    ARRAY_INDEX = "array_index"
    ARITHMETIC = "arithmetic"


class SanitizerType(Enum):
    """Types of sanitizers that validate/constrain tainted data."""
    REQUIRE = "require"
    ASSERT = "assert"
    IF_CHECK = "if_check"
    MODIFIER_CHECK = "modifier_check"
    BOUNDS_CHECK = "bounds_check"
    ZERO_CHECK = "zero_check"
    OWNER_CHECK = "owner_check"


@dataclass
class TaintedVariable:
    """A variable that holds tainted (user-controlled) data."""
    name: str
    source: TaintSource
    line: int = 0
    is_sanitized: bool = False
    sanitizers: List[SanitizerType] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'source': self.source.value,
            'line': self.line,
            'is_sanitized': self.is_sanitized,
            'sanitizers': [s.value for s in self.sanitizers],
        }


@dataclass
class TaintedPath:
    """
    A path from a taint source to a dangerous sink.

    Represents a potential vulnerability where user-controlled
    data flows to a dangerous operation without proper validation.
    """
    source: TaintedVariable
    sink: TaintSink
    sink_line: int
    path_variables: List[str] = field(default_factory=list)
    is_sanitized: bool = False
    sanitizers: List[SanitizerType] = field(default_factory=list)
    code_snippet: str = ""
    severity: str = "medium"

    @property
    def is_vulnerable(self) -> bool:
        """Check if path is potentially vulnerable (unsanitized)."""
        return not self.is_sanitized

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source': self.source.to_dict(),
            'sink': self.sink.value,
            'sink_line': self.sink_line,
            'path_variables': self.path_variables,
            'is_sanitized': self.is_sanitized,
            'sanitizers': [s.value for s in self.sanitizers],
            'is_vulnerable': self.is_vulnerable,
            'severity': self.severity,
            'code_snippet': self.code_snippet[:200] if self.code_snippet else "",
        }


class TaintAnalyzer:
    """
    Analyzes Solidity code for tainted data flows.

    Tracks how user-controlled data (from msg.sender, msg.value,
    function parameters, etc.) flows through the code and whether
    it reaches dangerous operations without proper validation.
    """

    # Patterns for identifying taint sources
    SOURCE_PATTERNS = {
        TaintSource.MSG_SENDER: r'\bmsg\.sender\b',
        TaintSource.MSG_VALUE: r'\bmsg\.value\b',
        TaintSource.MSG_DATA: r'\bmsg\.data\b',
        TaintSource.TX_ORIGIN: r'\btx\.origin\b',
        TaintSource.BLOCK_TIMESTAMP: r'\bblock\.timestamp\b|\bnow\b',
        TaintSource.BLOCK_NUMBER: r'\bblock\.number\b',
        TaintSource.BLOCK_COINBASE: r'\bblock\.coinbase\b',
    }

    # Patterns for identifying sinks
    SINK_PATTERNS = {
        TaintSink.CALL: r'\.call\s*[\{(]',
        TaintSink.DELEGATECALL: r'\.delegatecall\s*\(',
        TaintSink.STATICCALL: r'\.staticcall\s*\(',
        TaintSink.TRANSFER: r'\.transfer\s*\(',
        TaintSink.SEND: r'\.send\s*\(',
        TaintSink.SELFDESTRUCT: r'\bselfdestruct\s*\(|\bsuicide\s*\(',
    }

    # Patterns for identifying sanitizers
    SANITIZER_PATTERNS = {
        SanitizerType.REQUIRE: r'\brequire\s*\(',
        SanitizerType.ASSERT: r'\bassert\s*\(',
        SanitizerType.IF_CHECK: r'\bif\s*\([^)]*(?:==|!=|>=|<=|>|<)[^)]*\)',
        SanitizerType.OWNER_CHECK: r'require\s*\(\s*msg\.sender\s*==\s*owner',
        SanitizerType.ZERO_CHECK: r'require\s*\([^)]*!=\s*(?:0|address\(0\))',
        SanitizerType.BOUNDS_CHECK: r'require\s*\([^)]*[<>=]\s*\d+',
    }

    # High severity sink patterns
    HIGH_SEVERITY_SINKS = {
        TaintSink.CALL,
        TaintSink.DELEGATECALL,
        TaintSink.SELFDESTRUCT,
    }

    # Critical source patterns (user can fully control)
    CRITICAL_SOURCES = {
        TaintSource.MSG_VALUE,
        TaintSource.TX_ORIGIN,
        TaintSource.FUNCTION_PARAM,
    }

    def __init__(self):
        """Initialize the taint analyzer."""
        self._tainted_vars: Dict[str, TaintedVariable] = {}
        self._paths: List[TaintedPath] = []

    def analyze(
        self,
        source_code: str,
        function_name: Optional[str] = None,
    ) -> List[TaintedPath]:
        """
        Analyze source code for tainted data flows.

        Args:
            source_code: Solidity source code to analyze
            function_name: Optional specific function to analyze

        Returns:
            List of TaintedPath objects representing potential vulnerabilities
        """
        self._tainted_vars = {}
        self._paths = []

        # If function name specified, extract that function's code
        if function_name:
            source_code = self._extract_function(source_code, function_name)

        # Step 1: Find taint sources
        self._find_taint_sources(source_code)

        # Step 2: Track taint propagation
        self._propagate_taint(source_code)

        # Step 3: Find sinks and check if tainted data reaches them
        self._find_tainted_paths(source_code)

        # Step 4: Check for sanitizers
        self._check_sanitizers(source_code)

        return self._paths

    def _find_taint_sources(self, source_code: str) -> None:
        """Identify taint sources in the code."""
        lines = source_code.split('\n')

        for line_num, line in enumerate(lines, 1):
            for source, pattern in self.SOURCE_PATTERNS.items():
                if re.search(pattern, line):
                    # Try to find variable assignment
                    var_name = self._extract_assigned_variable(line, pattern)
                    if var_name:
                        self._tainted_vars[var_name] = TaintedVariable(
                            name=var_name,
                            source=source,
                            line=line_num,
                        )
                    else:
                        # Direct usage without assignment
                        self._tainted_vars[f"_direct_{source.value}_{line_num}"] = TaintedVariable(
                            name=source.value,
                            source=source,
                            line=line_num,
                        )

        # Also mark function parameters as tainted
        self._find_function_parameters(source_code)

    def _extract_assigned_variable(
        self,
        line: str,
        source_pattern: str,
    ) -> Optional[str]:
        """Extract variable name from an assignment statement."""
        # Pattern: type varName = source;
        # Or: varName = source;
        assignment_pattern = r'(?:(?:uint|int|address|bytes|bool)\d*\s+)?(\w+)\s*=\s*.*' + source_pattern

        match = re.search(assignment_pattern, line)
        if match:
            return match.group(1)

        return None

    def _find_function_parameters(self, source_code: str) -> None:
        """Find and mark function parameters as tainted."""
        # Match function definitions with parameters
        func_pattern = r'function\s+\w+\s*\(([^)]+)\)'

        for match in re.finditer(func_pattern, source_code):
            params_str = match.group(1)
            # Parse parameters
            params = params_str.split(',')

            for param in params:
                param = param.strip()
                if not param:
                    continue

                # Extract parameter name (last word before any array brackets)
                parts = param.split()
                if parts:
                    param_name = parts[-1].strip('[]')
                    if param_name:
                        # Mark parameter as tainted
                        self._tainted_vars[param_name] = TaintedVariable(
                            name=param_name,
                            source=TaintSource.FUNCTION_PARAM,
                            line=0,
                        )

    def _propagate_taint(self, source_code: str) -> None:
        """
        Propagate taint through assignments.

        If a tainted variable is assigned to another variable,
        that variable also becomes tainted.
        """
        lines = source_code.split('\n')
        iterations = 0
        max_iterations = 10  # Prevent infinite loops

        changed = True
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for line_num, line in enumerate(lines, 1):
                # Pattern: varName = expression
                assignment_match = re.search(
                    r'(\w+)\s*=\s*([^;]+);',
                    line
                )

                if assignment_match:
                    target_var = assignment_match.group(1)
                    expression = assignment_match.group(2)

                    # Check if any tainted variable is in the expression
                    for tainted_name, tainted_var in list(self._tainted_vars.items()):
                        if re.search(rf'\b{re.escape(tainted_name)}\b', expression):
                            if target_var not in self._tainted_vars:
                                self._tainted_vars[target_var] = TaintedVariable(
                                    name=target_var,
                                    source=tainted_var.source,
                                    line=line_num,
                                )
                                changed = True

    def _find_tainted_paths(self, source_code: str) -> None:
        """Find paths from tainted sources to sinks."""
        lines = source_code.split('\n')

        for line_num, line in enumerate(lines, 1):
            for sink, pattern in self.SINK_PATTERNS.items():
                sink_match = re.search(pattern, line)
                if sink_match:
                    # Check if any tainted variable is used in this line
                    for tainted_name, tainted_var in self._tainted_vars.items():
                        # Skip internal tracking variables
                        if tainted_name.startswith('_direct_'):
                            actual_name = tainted_var.name
                        else:
                            actual_name = tainted_name

                        if re.search(rf'\b{re.escape(actual_name)}\b', line):
                            # Found tainted data reaching a sink
                            severity = self._calculate_severity(
                                tainted_var.source, sink
                            )

                            path = TaintedPath(
                                source=tainted_var,
                                sink=sink,
                                sink_line=line_num,
                                path_variables=[tainted_name],
                                severity=severity,
                                code_snippet=line.strip(),
                            )

                            self._paths.append(path)

    def _check_sanitizers(self, source_code: str) -> None:
        """Check if tainted paths are sanitized."""
        for path in self._paths:
            # Get code between source and sink
            source_line = path.source.line
            sink_line = path.sink_line

            # Get lines between source and sink
            lines = source_code.split('\n')
            start = max(0, min(source_line, sink_line) - 1)
            end = max(source_line, sink_line)
            code_between = '\n'.join(lines[start:end])

            # Check for each sanitizer type
            sanitizers_found = []
            for sanitizer, pattern in self.SANITIZER_PATTERNS.items():
                if re.search(pattern, code_between, re.IGNORECASE):
                    # Check if the sanitizer references the tainted variable
                    sanitizer_match = re.search(pattern, code_between)
                    if sanitizer_match:
                        var_name = path.source.name
                        # Get surrounding context
                        match_start = sanitizer_match.start()
                        context = code_between[match_start:match_start + 100]

                        if re.search(rf'\b{re.escape(var_name)}\b', context):
                            sanitizers_found.append(sanitizer)

            if sanitizers_found:
                path.is_sanitized = True
                path.sanitizers = sanitizers_found

    def _calculate_severity(
        self,
        source: TaintSource,
        sink: TaintSink,
    ) -> str:
        """Calculate severity based on source and sink combination."""
        # Critical: Critical source + High severity sink
        if source in self.CRITICAL_SOURCES and sink in self.HIGH_SEVERITY_SINKS:
            return "critical"

        # High: Any source + High severity sink
        if sink in self.HIGH_SEVERITY_SINKS:
            return "high"

        # Medium: Critical source + Other sink
        if source in self.CRITICAL_SOURCES:
            return "medium"

        # Low: Everything else
        return "low"

    def _extract_function(
        self,
        source_code: str,
        function_name: str,
    ) -> str:
        """Extract a specific function's code."""
        # Find function definition
        func_pattern = rf'function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\{{'

        match = re.search(func_pattern, source_code)
        if not match:
            return source_code

        # Find matching closing brace
        start = match.end()
        brace_count = 1
        end = start

        for i, char in enumerate(source_code[start:], start):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break

        return source_code[match.start():end]

    def get_vulnerable_paths(self) -> List[TaintedPath]:
        """Get only paths that are not sanitized (potentially vulnerable)."""
        return [p for p in self._paths if p.is_vulnerable]

    def get_summary(self) -> Dict[str, Any]:
        """Generate summary of taint analysis."""
        vulnerable = self.get_vulnerable_paths()

        severity_counts = {
            'critical': sum(1 for p in vulnerable if p.severity == 'critical'),
            'high': sum(1 for p in vulnerable if p.severity == 'high'),
            'medium': sum(1 for p in vulnerable if p.severity == 'medium'),
            'low': sum(1 for p in vulnerable if p.severity == 'low'),
        }

        sink_counts = {}
        for path in vulnerable:
            sink_name = path.sink.value
            sink_counts[sink_name] = sink_counts.get(sink_name, 0) + 1

        source_counts = {}
        for path in vulnerable:
            source_name = path.source.source.value
            source_counts[source_name] = source_counts.get(source_name, 0) + 1

        return {
            'total_tainted_variables': len(self._tainted_vars),
            'total_paths': len(self._paths),
            'vulnerable_paths': len(vulnerable),
            'sanitized_paths': len(self._paths) - len(vulnerable),
            'by_severity': severity_counts,
            'by_sink': sink_counts,
            'by_source': source_counts,
        }

    def to_findings(self) -> List[Dict[str, Any]]:
        """Convert vulnerable paths to MIESC finding format."""
        findings = []

        for path in self.get_vulnerable_paths():
            finding = {
                'type': f'tainted-{path.sink.value}',
                'severity': path.severity.capitalize(),
                'confidence': 0.75,
                'location': {
                    'line': path.sink_line,
                    'function': '',
                },
                'message': f'User-controlled data ({path.source.source.value}) flows to {path.sink.value} without sanitization',
                'description': f'Tainted data from {path.source.source.value} reaches dangerous sink {path.sink.value}',
                'recommendation': self._get_recommendation(path.sink),
                'swc_id': self._get_swc_id(path.sink),
                'tool': 'taint-analyzer',
                '_taint_analysis': path.to_dict(),
            }
            findings.append(finding)

        return findings

    def _get_recommendation(self, sink: TaintSink) -> str:
        """Get recommendation for a specific sink type."""
        recommendations = {
            TaintSink.CALL: "Validate the call target and parameters. Use reentrancy guards.",
            TaintSink.DELEGATECALL: "Never use user-controlled addresses with delegatecall.",
            TaintSink.SELFDESTRUCT: "Add proper access control to selfdestruct.",
            TaintSink.TRANSFER: "Validate the recipient address.",
            TaintSink.SEND: "Validate the recipient address and check return value.",
            TaintSink.STATICCALL: "Validate the call target.",
            TaintSink.SSTORE: "Validate data before storing.",
            TaintSink.ARRAY_INDEX: "Check array bounds before access.",
            TaintSink.ARITHMETIC: "Use SafeMath or Solidity 0.8+.",
        }
        return recommendations.get(sink, "Validate user input before use.")

    def _get_swc_id(self, sink: TaintSink) -> Optional[str]:
        """Get SWC ID for a specific sink type."""
        swc_mapping = {
            TaintSink.CALL: "SWC-107",  # Reentrancy
            TaintSink.DELEGATECALL: "SWC-112",  # Delegatecall
            TaintSink.SELFDESTRUCT: "SWC-106",  # Unprotected selfdestruct
            TaintSink.ARITHMETIC: "SWC-101",  # Integer overflow
        }
        return swc_mapping.get(sink)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def analyze_taint(
    source_code: str,
    function_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function to analyze taint in source code.

    Args:
        source_code: Solidity source code
        function_name: Optional specific function to analyze

    Returns:
        Analysis results including paths and summary
    """
    analyzer = TaintAnalyzer()
    paths = analyzer.analyze(source_code, function_name)

    return {
        'paths': [p.to_dict() for p in paths],
        'vulnerable_paths': [p.to_dict() for p in analyzer.get_vulnerable_paths()],
        'findings': analyzer.to_findings(),
        'summary': analyzer.get_summary(),
    }


def find_tainted_sinks(
    source_code: str,
    sink_type: Optional[TaintSink] = None,
) -> List[TaintedPath]:
    """
    Find all tainted paths to a specific sink type.

    Args:
        source_code: Solidity source code
        sink_type: Optional specific sink type to find

    Returns:
        List of tainted paths
    """
    analyzer = TaintAnalyzer()
    paths = analyzer.analyze(source_code)

    if sink_type:
        return [p for p in paths if p.sink == sink_type]

    return paths


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TaintSource",
    "TaintSink",
    "SanitizerType",
    "TaintedVariable",
    "TaintedPath",
    "TaintAnalyzer",
    "analyze_taint",
    "find_tainted_sinks",
]
