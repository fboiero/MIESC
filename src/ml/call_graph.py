"""
MIESC Call Graph Module v4.6.0
==============================

Constructs and analyzes function call graphs for smart contracts.
Enables cross-function vulnerability analysis and exploit path detection.

Features:
- Function-level call graph construction
- Entry point identification (external/public functions)
- Path finding to dangerous sinks
- External call chain analysis
- State variable read/write tracking

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
License: AGPL-3.0
"""

import hashlib
import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class Visibility(Enum):
    """Function visibility levels in Solidity."""
    EXTERNAL = "external"
    PUBLIC = "public"
    INTERNAL = "internal"
    PRIVATE = "private"


class Mutability(Enum):
    """Function mutability modifiers."""
    PAYABLE = "payable"
    NONPAYABLE = "nonpayable"
    VIEW = "view"
    PURE = "pure"


@dataclass
class FunctionNode:
    """
    Represents a function in the call graph.

    Contains information about:
    - Function signature and visibility
    - Modifiers applied
    - State variables read and written
    - External calls made
    - Internal calls made
    """
    name: str
    visibility: Visibility
    mutability: Mutability = Mutability.NONPAYABLE
    modifiers: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    returns: List[str] = field(default_factory=list)

    # State access
    state_vars_read: Set[str] = field(default_factory=set)
    state_vars_written: Set[str] = field(default_factory=set)

    # Calls
    internal_calls: List[str] = field(default_factory=list)
    external_calls: List[str] = field(default_factory=list)

    # Code location
    start_line: int = 0
    end_line: int = 0

    # Flags
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False
    has_reentrancy_guard: bool = False
    has_access_control: bool = False

    @property
    def is_entry_point(self) -> bool:
        """Check if function can be called externally."""
        return self.visibility in [Visibility.EXTERNAL, Visibility.PUBLIC]

    @property
    def is_payable(self) -> bool:
        """Check if function can receive ETH."""
        return self.mutability == Mutability.PAYABLE

    @property
    def modifies_state(self) -> bool:
        """Check if function modifies state variables."""
        return len(self.state_vars_written) > 0

    @property
    def makes_external_calls(self) -> bool:
        """Check if function makes external calls."""
        return len(self.external_calls) > 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'visibility': self.visibility.value,
            'mutability': self.mutability.value,
            'modifiers': self.modifiers,
            'parameters': self.parameters,
            'returns': self.returns,
            'state_vars_read': list(self.state_vars_read),
            'state_vars_written': list(self.state_vars_written),
            'internal_calls': self.internal_calls,
            'external_calls': self.external_calls,
            'is_entry_point': self.is_entry_point,
            'is_payable': self.is_payable,
            'modifies_state': self.modifies_state,
            'makes_external_calls': self.makes_external_calls,
            'has_reentrancy_guard': self.has_reentrancy_guard,
            'has_access_control': self.has_access_control,
            'location': {'start': self.start_line, 'end': self.end_line},
        }


@dataclass
class CallEdge:
    """Represents a call relationship between functions."""
    caller: str
    callee: str
    call_type: str  # "internal", "external", "delegatecall", "staticcall"
    line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'caller': self.caller,
            'callee': self.callee,
            'type': self.call_type,
            'line': self.line,
        }


@dataclass
class CallPath:
    """Represents a path through the call graph."""
    nodes: List[str]
    edges: List[CallEdge]
    has_external_call: bool = False
    has_state_modification: bool = False

    @property
    def length(self) -> int:
        return len(self.nodes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'path': self.nodes,
            'length': self.length,
            'has_external_call': self.has_external_call,
            'has_state_modification': self.has_state_modification,
        }


class CallGraph:
    """
    Call graph for a smart contract.

    Provides methods for:
    - Building the graph from source code or Slither output
    - Finding paths to dangerous sinks
    - Identifying entry points
    - Analyzing external call chains
    """

    # Dangerous sink patterns (potential vulnerability targets)
    DANGEROUS_SINKS = {
        "call": "external_call",
        "delegatecall": "delegatecall",
        "staticcall": "staticcall",
        "transfer": "eth_transfer",
        "send": "eth_send",
        "selfdestruct": "selfdestruct",
        "sstore": "storage_write",
    }

    # Access control modifiers
    ACCESS_CONTROL_MODIFIERS = {
        "onlyOwner", "onlyAdmin", "onlyRole", "onlyMinter",
        "onlyOperator", "onlyGovernance", "onlyAuthorized",
        "whenNotPaused", "whenPaused",
    }

    # Reentrancy guard modifiers
    REENTRANCY_GUARD_MODIFIERS = {
        "nonReentrant", "noReentrant", "lock", "locked",
    }

    def __init__(self, contract_name: str = "Contract"):
        """Initialize empty call graph."""
        self.contract_name = contract_name
        self.nodes: Dict[str, FunctionNode] = {}
        self.edges: List[CallEdge] = []
        self._adjacency: Dict[str, List[str]] = defaultdict(list)
        self._reverse_adjacency: Dict[str, List[str]] = defaultdict(list)

    def add_function(self, func: FunctionNode) -> None:
        """Add a function node to the graph."""
        self.nodes[func.name] = func

    def add_edge(self, edge: CallEdge) -> None:
        """Add a call edge to the graph."""
        self.edges.append(edge)
        self._adjacency[edge.caller].append(edge.callee)
        self._reverse_adjacency[edge.callee].append(edge.caller)

    def get_entry_points(self) -> List[FunctionNode]:
        """Get all functions that can be called externally."""
        return [
            func for func in self.nodes.values()
            if func.is_entry_point
        ]

    def get_callees(self, func_name: str) -> List[str]:
        """Get functions called by the given function."""
        return self._adjacency.get(func_name, [])

    def get_callers(self, func_name: str) -> List[str]:
        """Get functions that call the given function."""
        return self._reverse_adjacency.get(func_name, [])

    def reachable_from(self, func_name: str) -> Set[str]:
        """
        Get all functions reachable from a given function.

        Uses BFS to find all reachable nodes.
        """
        if func_name not in self.nodes:
            return set()

        visited = set()
        queue = deque([func_name])

        while queue:
            current = queue.popleft()
            if current in visited:
                continue

            visited.add(current)

            for callee in self._adjacency.get(current, []):
                if callee not in visited:
                    queue.append(callee)

        return visited

    def can_reach(self, source: str, target: str) -> bool:
        """Check if target is reachable from source."""
        return target in self.reachable_from(source)

    def paths_to_sink(
        self,
        sink: str,
        max_depth: int = 10,
    ) -> List[CallPath]:
        """
        Find all paths from entry points to a sink function.

        Args:
            sink: Target sink function name
            max_depth: Maximum path length to search

        Returns:
            List of CallPath objects representing paths to the sink
        """
        paths = []

        for entry_point in self.get_entry_points():
            entry_paths = self._find_paths_bfs(
                entry_point.name, sink, max_depth
            )
            paths.extend(entry_paths)

        return paths

    def _find_paths_bfs(
        self,
        start: str,
        end: str,
        max_depth: int,
    ) -> List[CallPath]:
        """BFS to find all paths from start to end."""
        paths = []
        queue = deque([(start, [start], [])])

        while queue:
            current, path, edges = queue.popleft()

            if len(path) > max_depth:
                continue

            if current == end:
                # Build CallPath
                call_path = CallPath(
                    nodes=path,
                    edges=edges,
                    has_external_call=any(
                        self.nodes.get(n, FunctionNode(n, Visibility.INTERNAL)).makes_external_calls
                        for n in path
                    ),
                    has_state_modification=any(
                        self.nodes.get(n, FunctionNode(n, Visibility.INTERNAL)).modifies_state
                        for n in path
                    ),
                )
                paths.append(call_path)
                continue

            for callee in self._adjacency.get(current, []):
                if callee not in path:  # Avoid cycles
                    edge = CallEdge(current, callee, "internal")
                    queue.append((callee, path + [callee], edges + [edge]))

        return paths

    def external_call_chains(self) -> List[CallPath]:
        """
        Find all call chains that end in external calls.

        Returns paths from entry points that lead to .call(), .delegatecall(),
        .transfer(), .send(), etc.
        """
        chains = []

        for func in self.nodes.values():
            if func.makes_external_calls and func.is_entry_point:
                # Direct external call from entry point
                chains.append(CallPath(
                    nodes=[func.name],
                    edges=[],
                    has_external_call=True,
                    has_state_modification=func.modifies_state,
                ))

        # Find indirect paths
        for func in self.nodes.values():
            if func.makes_external_calls and not func.is_entry_point:
                # Find entry points that can reach this function
                for entry in self.get_entry_points():
                    if self.can_reach(entry.name, func.name):
                        paths = self._find_paths_bfs(
                            entry.name, func.name, max_depth=5
                        )
                        for path in paths:
                            path.has_external_call = True
                            chains.append(path)

        return chains

    def get_reentrancy_risk_paths(self) -> List[CallPath]:
        """
        Find paths with potential reentrancy risk.

        A path is risky if it:
        1. Starts from an entry point
        2. Has state modifications
        3. Makes external calls
        4. Does NOT have reentrancy guard

        Returns:
            List of risky paths
        """
        risky_paths = []

        for chain in self.external_call_chains():
            # Check if any function in the path has reentrancy guard
            has_guard = any(
                self.nodes.get(n, FunctionNode(n, Visibility.INTERNAL)).has_reentrancy_guard
                for n in chain.nodes
            )

            if not has_guard and chain.has_state_modification:
                risky_paths.append(chain)

        return risky_paths

    def get_unprotected_state_modifiers(self) -> List[FunctionNode]:
        """
        Find entry points that modify state without access control.

        Returns:
            List of unprotected functions
        """
        unprotected = []

        for func in self.get_entry_points():
            if func.modifies_state and not func.has_access_control:
                # Check if it's a common safe pattern
                if not func.is_constructor and not func.name.startswith("_"):
                    unprotected.append(func)

        return unprotected

    def get_summary(self) -> Dict[str, Any]:
        """Generate summary statistics for the call graph."""
        entry_points = self.get_entry_points()
        external_chains = self.external_call_chains()
        reentrancy_risks = self.get_reentrancy_risk_paths()
        unprotected = self.get_unprotected_state_modifiers()

        return {
            'contract': self.contract_name,
            'total_functions': len(self.nodes),
            'entry_points': len(entry_points),
            'total_edges': len(self.edges),
            'external_call_chains': len(external_chains),
            'reentrancy_risk_paths': len(reentrancy_risks),
            'unprotected_state_modifiers': len(unprotected),
            'functions_with_guards': sum(
                1 for f in self.nodes.values()
                if f.has_reentrancy_guard
            ),
            'functions_with_access_control': sum(
                1 for f in self.nodes.values()
                if f.has_access_control
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert call graph to dictionary."""
        return {
            'contract': self.contract_name,
            'nodes': {
                name: node.to_dict()
                for name, node in self.nodes.items()
            },
            'edges': [edge.to_dict() for edge in self.edges],
            'summary': self.get_summary(),
        }


class CallGraphBuilder:
    """
    Builds call graphs from Solidity source code or Slither output.

    Supports:
    - Direct source code parsing (regex-based, limited)
    - Slither JSON output parsing (recommended)
    """

    # Regex patterns for source code parsing
    FUNCTION_PATTERN = re.compile(
        r'function\s+(\w+)\s*\(([^)]*)\)\s*'
        r'((?:public|external|internal|private)\s*)?'
        r'((?:view|pure|payable)\s*)?'
        r'((?:\w+\s*)*?)'  # Modifiers
        r'(?:returns\s*\([^)]*\))?\s*\{',
        re.MULTILINE
    )

    CALL_PATTERN = re.compile(
        r'(\w+)\s*\.\s*(call|delegatecall|staticcall|transfer|send)\s*[{(]',
        re.MULTILINE
    )

    INTERNAL_CALL_PATTERN = re.compile(
        r'(?<![.\w])(\w+)\s*\(',
        re.MULTILINE
    )

    STATE_WRITE_PATTERN = re.compile(
        r'(\w+)\s*(?:\[[^\]]*\])?\s*[+\-*/]?=(?!=)',
        re.MULTILINE
    )

    def __init__(self):
        """Initialize the call graph builder."""
        pass

    def build_from_source(
        self,
        source_code: str,
        contract_name: str = "Contract",
    ) -> CallGraph:
        """
        Build call graph from Solidity source code.

        Note: This is a simplified parser. For accurate results,
        use build_from_slither() with Slither's JSON output.
        """
        graph = CallGraph(contract_name)

        # Extract functions
        for match in self.FUNCTION_PATTERN.finditer(source_code):
            func_name = match.group(1)
            params = match.group(2)
            visibility_str = (match.group(3) or "public").strip()
            mutability_str = (match.group(4) or "").strip()
            modifiers_str = match.group(5) or ""

            # Parse visibility
            visibility = Visibility.PUBLIC
            for v in Visibility:
                if v.value in visibility_str.lower():
                    visibility = v
                    break

            # Parse mutability
            mutability = Mutability.NONPAYABLE
            for m in Mutability:
                if m.value in mutability_str.lower():
                    mutability = m
                    break

            # Parse modifiers
            modifiers = [m.strip() for m in modifiers_str.split() if m.strip()]

            # Check for guards
            has_reentrancy_guard = any(
                guard in modifiers_str
                for guard in CallGraph.REENTRANCY_GUARD_MODIFIERS
            )
            has_access_control = any(
                ac in modifiers_str
                for ac in CallGraph.ACCESS_CONTROL_MODIFIERS
            )

            func = FunctionNode(
                name=func_name,
                visibility=visibility,
                mutability=mutability,
                modifiers=modifiers,
                has_reentrancy_guard=has_reentrancy_guard,
                has_access_control=has_access_control,
                start_line=source_code[:match.start()].count('\n') + 1,
            )

            graph.add_function(func)

        # Extract calls (simplified)
        self._extract_calls_from_source(source_code, graph)

        return graph

    def _extract_calls_from_source(
        self,
        source_code: str,
        graph: CallGraph,
    ) -> None:
        """Extract call relationships from source code."""
        # This is a simplified extraction
        # For accurate results, use Slither output

        for func_name, func in graph.nodes.items():
            # Find function body (simplified - won't work for all cases)
            func_match = re.search(
                rf'function\s+{func_name}\s*\([^)]*\)[^{{]*\{{',
                source_code
            )
            if not func_match:
                continue

            # Find matching closing brace (simplified)
            start = func_match.end()
            brace_count = 1
            end = start

            for i, char in enumerate(source_code[start:], start):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = i
                        break

            func_body = source_code[start:end]

            # Find external calls
            for match in self.CALL_PATTERN.finditer(func_body):
                target = match.group(1)
                call_type = match.group(2)

                func.external_calls.append(f"{target}.{call_type}")
                graph.add_edge(CallEdge(
                    caller=func_name,
                    callee=f"{target}.{call_type}",
                    call_type=call_type,
                ))

            # Find state writes
            for match in self.STATE_WRITE_PATTERN.finditer(func_body):
                var_name = match.group(1)
                if not var_name.startswith(('uint', 'int', 'bool', 'address', 'bytes')):
                    func.state_vars_written.add(var_name)

    def build_from_slither(
        self,
        slither_output: Dict[str, Any],
        contract_name: Optional[str] = None,
    ) -> CallGraph:
        """
        Build call graph from Slither's JSON output.

        This is the recommended method for accurate call graph construction.

        Args:
            slither_output: Parsed JSON from Slither
            contract_name: Optional contract name filter

        Returns:
            CallGraph instance
        """
        graph = CallGraph(contract_name or "Contract")

        # Extract from Slither's call graph data
        results = slither_output.get("results", {})
        printers = results.get("printers", [])

        # Look for call-graph printer output
        for printer in printers:
            if printer.get("printer", "") == "call-graph":
                self._parse_slither_call_graph(printer, graph)
                break

        # If no call-graph printer, try to extract from detectors
        if not graph.nodes:
            self._extract_from_detectors(slither_output, graph)

        return graph

    def _parse_slither_call_graph(
        self,
        printer_output: Dict[str, Any],
        graph: CallGraph,
    ) -> None:
        """Parse Slither's call-graph printer output."""
        # Slither's call-graph output format varies by version
        # This handles common formats

        elements = printer_output.get("elements", [])

        for element in elements:
            if element.get("type") == "function":
                name = element.get("name", "unknown")
                func = FunctionNode(
                    name=name,
                    visibility=Visibility.PUBLIC,  # Default
                )

                # Extract additional info if available
                additional = element.get("additional_fields", {})
                if "visibility" in additional:
                    for v in Visibility:
                        if v.value == additional["visibility"]:
                            func.visibility = v
                            break

                graph.add_function(func)

            elif element.get("type") == "edge":
                source = element.get("source", "")
                target = element.get("target", "")

                if source and target:
                    graph.add_edge(CallEdge(
                        caller=source,
                        callee=target,
                        call_type="internal",
                    ))

    def _extract_from_detectors(
        self,
        slither_output: Dict[str, Any],
        graph: CallGraph,
    ) -> None:
        """Extract call graph info from detector results."""
        detectors = slither_output.get("results", {}).get("detectors", [])

        functions_seen = set()

        for detector in detectors:
            elements = detector.get("elements", [])

            for element in elements:
                if element.get("type") == "function":
                    name = element.get("name", "")
                    if name and name not in functions_seen:
                        functions_seen.add(name)

                        # Extract visibility from type_specific_fields
                        type_fields = element.get("type_specific_fields", {})
                        visibility_str = type_fields.get("visibility", "public")

                        visibility = Visibility.PUBLIC
                        for v in Visibility:
                            if v.value == visibility_str:
                                visibility = v
                                break

                        func = FunctionNode(
                            name=name,
                            visibility=visibility,
                        )

                        graph.add_function(func)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def build_call_graph(
    source_code: str,
    contract_name: str = "Contract",
) -> CallGraph:
    """
    Convenience function to build a call graph from source code.

    Args:
        source_code: Solidity source code
        contract_name: Name of the contract

    Returns:
        CallGraph instance
    """
    builder = CallGraphBuilder()
    return builder.build_from_source(source_code, contract_name)


def analyze_reentrancy_risk(
    source_code: str,
) -> Dict[str, Any]:
    """
    Analyze source code for reentrancy risk using call graph.

    Returns:
        Analysis results including risky paths
    """
    graph = build_call_graph(source_code)
    risky_paths = graph.get_reentrancy_risk_paths()

    return {
        'risky_paths_count': len(risky_paths),
        'risky_paths': [p.to_dict() for p in risky_paths],
        'summary': graph.get_summary(),
    }


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "Visibility",
    "Mutability",
    "FunctionNode",
    "CallEdge",
    "CallPath",
    "CallGraph",
    "CallGraphBuilder",
    "build_call_graph",
    "analyze_reentrancy_risk",
]
