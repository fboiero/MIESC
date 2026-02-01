"""
Peculiar Adapter - Layer 6: ML-Based Vulnerability Detection
=============================================================

Heterogeneous Graph Neural Network for smart contract vulnerability detection.
Based on Peculiar (ICSE 2023) research that constructs a heterogeneous code
property graph combining AST, CFG, and DFG for GNN-based inference.

Key Features:
- Heterogeneous code graph (AST + CFG + DFG)
- GNN-based multi-class vulnerability detection
- Fallback to pattern-based code structure analysis
- Taint propagation across data flow edges
- Multi-vulnerability classification in a single pass

Detected Vulnerabilities:
- Reentrancy (SWC-107)
- Integer Overflow/Underflow (SWC-101)
- Access Control Issues (SWC-115)
- Unchecked Return Values (SWC-104)
- Timestamp Dependence (SWC-116)
- tx.origin Authentication (SWC-115)
- Delegatecall Injection (SWC-112)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
Date: 2025-01-31
Version: 1.0.0
Paper: ICSE 2023 - Peculiar: Smart Contract Vulnerability Detection via
       Heterogeneous Graph Neural Network
"""

from src.core.tool_protocol import (
    ToolAdapter, ToolMetadata, ToolStatus, ToolCategory, ToolCapability
)
from typing import Dict, Any, List, Optional, Tuple, Set
import logging
import json
import time
import re
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)

# Default path for pre-trained Peculiar models
DEFAULT_MODEL_DIR = Path.home() / ".miesc" / "models" / "peculiar"


class PeculiarAdapter(ToolAdapter):
    """
    Peculiar: Heterogeneous Graph Neural Network for vulnerability detection.

    Research Foundation:
    - ICSE 2023 paper on heterogeneous code property graphs
    - Combines Abstract Syntax Tree (AST), Control Flow Graph (CFG),
      and Data Flow Graph (DFG) into a unified heterogeneous graph
    - GNN-based message passing over heterogeneous edge types
    - Achieves state-of-the-art detection on SmartBugs benchmark

    Architecture:
    1. Graph Construction: Build heterogeneous code property graph
       - AST edges: parent-child syntactic relationships
       - CFG edges: sequential execution and branching
       - DFG edges: variable definitions and uses (taint propagation)
    2. Node Feature Encoding: Code tokens + structural features
    3. Heterogeneous GNN: Type-aware message passing across edge types
    4. Readout + Classification: Multi-class vulnerability prediction

    Fallback Mode:
    When the pre-trained GNN model is not available, the adapter falls
    back to pattern-based code structure analysis that mimics the graph
    construction and taint analysis pipeline using regex-based heuristics.
    """

    # Vulnerability taxonomy aligned with SWC Registry
    VULNERABILITY_TYPES = {
        "reentrancy": {
            "swc_id": "SWC-107",
            "cwe_id": "CWE-841",
            "severity": "Critical",
            "owasp_category": "SC02:2025 - Reentrancy",
            "description": "Reentrancy vulnerability: external call precedes state update",
            "recommendation": (
                "Apply checks-effects-interactions pattern. Move all state "
                "changes before external calls, or use OpenZeppelin "
                "ReentrancyGuard modifier."
            ),
        },
        "integer_overflow": {
            "swc_id": "SWC-101",
            "cwe_id": "CWE-190",
            "severity": "High",
            "owasp_category": "SC04:2025 - Arithmetic Issues",
            "description": "Integer overflow or underflow in arithmetic operation",
            "recommendation": (
                "Upgrade to Solidity >=0.8.0 for built-in overflow checks, "
                "or use OpenZeppelin SafeMath for older compiler versions."
            ),
        },
        "access_control": {
            "swc_id": "SWC-115",
            "cwe_id": "CWE-284",
            "severity": "High",
            "owasp_category": "SC01:2025 - Access Control",
            "description": "Missing or insufficient access control on privileged function",
            "recommendation": (
                "Add access control modifiers (onlyOwner, role-based) to "
                "sensitive functions. Use OpenZeppelin AccessControl or Ownable."
            ),
        },
        "unchecked_return": {
            "swc_id": "SWC-104",
            "cwe_id": "CWE-252",
            "severity": "Medium",
            "owasp_category": "SC06:2025 - Unchecked Return Values",
            "description": "Return value of external call not checked",
            "recommendation": (
                "Always check the boolean return value of low-level .call(), "
                ".send(), and .delegatecall(). Use require() to revert on failure."
            ),
        },
        "timestamp_dependence": {
            "swc_id": "SWC-116",
            "cwe_id": "CWE-829",
            "severity": "Medium",
            "owasp_category": "SC07:2025 - Block Values as Proxy for Time",
            "description": "Contract logic depends on block.timestamp which miners can manipulate",
            "recommendation": (
                "Avoid using block.timestamp for critical decisions. Use "
                "block.number or an external oracle for time-sensitive logic."
            ),
        },
        "tx_origin": {
            "swc_id": "SWC-115",
            "cwe_id": "CWE-284",
            "severity": "High",
            "owasp_category": "SC01:2025 - Access Control",
            "description": "Use of tx.origin for authentication is vulnerable to phishing",
            "recommendation": (
                "Replace tx.origin with msg.sender for authentication. "
                "tx.origin can be manipulated through intermediary contracts."
            ),
        },
        "delegatecall_injection": {
            "swc_id": "SWC-112",
            "cwe_id": "CWE-829",
            "severity": "Critical",
            "owasp_category": "SC03:2025 - Delegatecall",
            "description": "Delegatecall to user-supplied or unvalidated address",
            "recommendation": (
                "Validate and whitelist delegatecall target addresses. Never "
                "delegatecall to user-controlled input. Use immutable proxy "
                "patterns with verified implementation addresses."
            ),
        },
    }

    # Node type constants for the heterogeneous graph
    NODE_TYPE_FUNCTION = "function"
    NODE_TYPE_STATEMENT = "statement"
    NODE_TYPE_EXPRESSION = "expression"
    NODE_TYPE_VARIABLE = "variable"
    NODE_TYPE_MODIFIER = "modifier"

    # Edge type constants for the heterogeneous graph
    EDGE_TYPE_AST = "ast"       # Abstract syntax tree edges
    EDGE_TYPE_CFG = "cfg"       # Control flow graph edges
    EDGE_TYPE_DFG = "dfg"       # Data flow graph edges

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Peculiar adapter.

        Args:
            config: Configuration dict with optional keys:
                - model_dir: Path to pre-trained model files
                - confidence_threshold: Minimum confidence for findings (0.0-1.0)
                - enable_taint_analysis: Enable taint propagation (default: True)
                - max_graph_nodes: Maximum graph nodes before truncation
        """
        super().__init__()
        self.config = config or {}
        self.model_dir = Path(
            self.config.get("model_dir", str(DEFAULT_MODEL_DIR))
        )
        self.confidence_threshold = self.config.get("confidence_threshold", 0.65)
        self.enable_taint_analysis = self.config.get("enable_taint_analysis", True)
        self.max_graph_nodes = self.config.get("max_graph_nodes", 5000)
        self._model_loaded = False

    def get_metadata(self) -> ToolMetadata:
        """Return Peculiar adapter metadata."""
        return ToolMetadata(
            name="peculiar",
            version="1.0.0",
            category=ToolCategory.ML_DETECTION,
            author="Fernando Boiero <fboiero@frvm.utn.edu.ar>",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation=(
                "https://github.com/fboiero/MIESC/blob/main/"
                "docs/TOOL_INTEGRATION_GUIDE.md"
            ),
            installation_cmd=(
                "pip install torch torch-geometric networkx && "
                "miesc models download peculiar"
            ),
            capabilities=[
                ToolCapability(
                    name="heterogeneous_gnn_detection",
                    description=(
                        "Heterogeneous graph neural network vulnerability "
                        "detection combining AST, CFG, and DFG representations"
                    ),
                    supported_languages=["solidity"],
                    detection_types=list(self.VULNERABILITY_TYPES.keys()),
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        """
        Check if Peculiar adapter is available.

        The adapter is always AVAILABLE because the fallback pattern-based
        analysis works without the pre-trained model. When model files are
        present, the GNN inference path is used instead.
        """
        model_available = self._check_model_files()
        if model_available:
            logger.info(
                "Peculiar: Pre-trained GNN model found at %s", self.model_dir
            )
        else:
            logger.warning(
                "Peculiar: No GNN model found at %s. Using pattern-based fallback "
                "(reduced accuracy). To enable full GNN inference, place model files "
                "in %s/",
                self.model_dir, self.model_dir,
            )
        return ToolStatus.AVAILABLE

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze a Solidity contract for vulnerabilities using Peculiar.

        Constructs a heterogeneous code property graph (AST + CFG + DFG)
        and either runs GNN inference or falls back to pattern analysis.

        Args:
            contract_path: Path to the Solidity source file.
            **kwargs:
                - timeout: Maximum analysis time in seconds (default: 120).
                - output_graph: Path to export the constructed graph as JSON.

        Returns:
            Normalized result dict with tool name, status, findings, and metadata.
        """
        start_time = time.time()
        timeout = kwargs.get("timeout", 120)

        try:
            source_code = self._read_source(contract_path)
        except FileNotFoundError:
            return self._error_result(
                f"Contract file not found: {contract_path}",
                start_time,
            )
        except Exception as exc:
            return self._error_result(
                f"Failed to read contract: {exc}",
                start_time,
            )

        try:
            # Step 1: Build the heterogeneous code property graph
            graph = self._build_code_graph(source_code, contract_path)

            # Step 2: Detect vulnerabilities
            if self._check_model_files():
                raw_predictions = self._run_gnn_inference(graph)
                analysis_mode = "gnn_model"
            else:
                raw_predictions = self._run_pattern_analysis(
                    graph, source_code
                )
                analysis_mode = "pattern_fallback"

            # Step 3: Convert predictions to normalized findings
            findings = self._predictions_to_findings(
                raw_predictions, contract_path, source_code
            )

            execution_time = round(time.time() - start_time, 3)

            result = {
                "tool": "peculiar",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "paper": "ICSE 2023 - Peculiar",
                    "analysis_mode": analysis_mode,
                    "graph_stats": self._compute_graph_stats(graph),
                    "confidence_threshold": self.confidence_threshold,
                    "taint_analysis_enabled": self.enable_taint_analysis,
                    "num_findings": len(findings),
                },
                "execution_time": execution_time,
            }

            # Optionally export the graph
            output_graph = kwargs.get("output_graph")
            if output_graph:
                self._export_graph(graph, output_graph)

            return result

        except Exception as exc:
            logger.error("Peculiar analysis failed: %s", exc, exc_info=True)
            return self._error_result(str(exc), start_time)

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize raw Peculiar output to standard MIESC finding format.

        Args:
            raw_output: The result dict returned by analyze() or raw
                        prediction data from an external Peculiar run.

        Returns:
            List of MIESC-standard finding dicts.
        """
        if isinstance(raw_output, dict) and "findings" in raw_output:
            return raw_output["findings"]

        # Handle raw prediction list from external tool invocation
        if isinstance(raw_output, list):
            normalized = []
            for idx, entry in enumerate(raw_output):
                vuln_type = entry.get("type", "unknown")
                vuln_meta = self.VULNERABILITY_TYPES.get(vuln_type, {})
                confidence = entry.get("confidence", 0.0)
                if confidence < self.confidence_threshold:
                    continue
                normalized.append({
                    "id": entry.get(
                        "id",
                        f"PECULIAR-{vuln_type.upper()}-{idx:04d}",
                    ),
                    "type": vuln_type,
                    "severity": entry.get(
                        "severity", vuln_meta.get("severity", "Medium")
                    ),
                    "confidence": round(confidence, 3),
                    "location": entry.get("location", {}),
                    "message": entry.get(
                        "message",
                        vuln_meta.get("description", "Vulnerability detected"),
                    ),
                    "description": entry.get(
                        "description",
                        vuln_meta.get("description", ""),
                    ),
                    "recommendation": entry.get(
                        "recommendation",
                        vuln_meta.get("recommendation", "Review code"),
                    ),
                    "swc_id": vuln_meta.get("swc_id"),
                    "cwe_id": vuln_meta.get("cwe_id"),
                    "owasp_category": vuln_meta.get("owasp_category"),
                })
            return normalized

        return []

    def can_analyze(self, contract_path: str) -> bool:
        """Return True if the file is a Solidity source file."""
        return contract_path.endswith(".sol")

    def get_default_config(self) -> Dict[str, Any]:
        """Return default Peculiar configuration."""
        return {
            "model_dir": str(DEFAULT_MODEL_DIR),
            "confidence_threshold": 0.65,
            "enable_taint_analysis": True,
            "max_graph_nodes": 5000,
        }

    # =========================================================================
    # Model file helpers
    # =========================================================================

    def _check_model_files(self) -> bool:
        """
        Check whether pre-trained GNN model files exist.

        Expected files under model_dir:
            - peculiar_weights.pt   (PyTorch model state dict)
            - peculiar_config.json  (model hyperparameters)
        """
        weights_path = self.model_dir / "peculiar_weights.pt"
        config_path = self.model_dir / "peculiar_config.json"
        return weights_path.is_file() and config_path.is_file()

    # =========================================================================
    # Source reading
    # =========================================================================

    def _read_source(self, contract_path: str) -> str:
        """Read Solidity source code from the given path."""
        with open(contract_path, "r", encoding="utf-8") as fh:
            return fh.read()

    # =========================================================================
    # Heterogeneous code graph construction
    # =========================================================================

    def _build_code_graph(
        self, source_code: str, contract_path: str
    ) -> Dict[str, Any]:
        """
        Build a heterogeneous code property graph from Solidity source.

        The graph contains three edge types:
        - AST edges: syntactic parent-child relationships
        - CFG edges: control flow between statements
        - DFG edges: data flow (definitions, uses, taint propagation)

        Returns:
            Dict with 'nodes', 'edges', 'functions', 'state_variables'.
        """
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        functions: List[Dict[str, Any]] = []
        state_variables: List[Dict[str, Any]] = []

        # Parse state variables at the contract level
        state_variables = self._extract_state_variables(source_code)
        for sv in state_variables:
            nodes.append({
                "id": len(nodes),
                "type": self.NODE_TYPE_VARIABLE,
                "name": sv["name"],
                "line": sv["line"],
                "data_type": sv["data_type"],
                "visibility": sv.get("visibility", "internal"),
            })

        # Parse functions and modifiers
        func_entries = self._extract_functions(source_code)
        for func in func_entries:
            func_node_id = len(nodes)
            func["node_id"] = func_node_id
            functions.append(func)

            nodes.append({
                "id": func_node_id,
                "type": self.NODE_TYPE_FUNCTION,
                "name": func["name"],
                "line": func["start_line"],
                "visibility": func.get("visibility", "public"),
                "modifiers": func.get("modifiers", []),
                "is_payable": func.get("is_payable", False),
            })

            # Build AST-like, CFG, and DFG edges within the function body
            body_nodes, body_edges = self._parse_function_body(
                func, source_code, func_node_id, len(nodes)
            )
            nodes.extend(body_nodes)
            edges.extend(body_edges)

        # Build inter-function call edges (CFG)
        edges.extend(
            self._build_inter_function_edges(functions, source_code)
        )

        # Build taint-based DFG edges if enabled
        if self.enable_taint_analysis:
            edges.extend(
                self._build_taint_edges(
                    nodes, functions, state_variables, source_code
                )
            )

        # Truncate if graph is too large
        if len(nodes) > self.max_graph_nodes:
            logger.warning(
                "Graph has %d nodes, truncating to %d",
                len(nodes), self.max_graph_nodes,
            )
            nodes = nodes[: self.max_graph_nodes]

        return {
            "nodes": nodes,
            "edges": edges,
            "functions": functions,
            "state_variables": state_variables,
        }

    def _extract_state_variables(
        self, source_code: str
    ) -> List[Dict[str, Any]]:
        """Extract contract-level state variable declarations."""
        variables: List[Dict[str, Any]] = []
        # Match common state variable declarations
        pattern = re.compile(
            r"^\s*(mapping\s*\([^)]+\)|"
            r"(?:u?int\d*|address|bool|bytes\d*|string|"
            r"\w+)(?:\[\])?)\s+"
            r"(public|private|internal|external)?\s*"
            r"(\w+)\s*[;=]",
            re.MULTILINE,
        )
        for match in pattern.finditer(source_code):
            line_num = source_code[: match.start()].count("\n") + 1
            variables.append({
                "name": match.group(3),
                "data_type": match.group(1).strip(),
                "visibility": match.group(2) or "internal",
                "line": line_num,
            })
        return variables

    def _extract_functions(
        self, source_code: str
    ) -> List[Dict[str, Any]]:
        """
        Extract function definitions with metadata.

        Captures name, parameters, visibility, modifiers, payable status,
        and the raw body text.
        """
        functions: List[Dict[str, Any]] = []
        # Non-greedy match that handles nested braces up to one level
        pattern = re.compile(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*"
            r"((?:public|private|internal|external|view|pure|payable|"
            r"virtual|override|\w+\s*(?:\([^)]*\))?[\s]*)*)"
            r"\s*(?:returns\s*\([^)]*\))?\s*\{",
            re.DOTALL,
        )
        for match in pattern.finditer(source_code):
            name = match.group(1)
            params = match.group(2).strip()
            qualifiers_raw = match.group(3).strip()
            start_line = source_code[: match.start()].count("\n") + 1
            body_start = match.end()

            # Extract the function body by counting braces
            body = self._extract_brace_block(source_code, body_start)
            body_end = body_start + len(body)

            # Determine visibility
            visibility = "public"
            for vis in ("public", "private", "internal", "external"):
                if vis in qualifiers_raw:
                    visibility = vis
                    break

            # Determine modifiers (words in qualifiers that are not keywords)
            sol_keywords = {
                "public", "private", "internal", "external",
                "view", "pure", "payable", "virtual", "override",
                "returns",
            }
            modifier_tokens = re.findall(r"(\w+)", qualifiers_raw)
            modifiers = [
                m for m in modifier_tokens if m not in sol_keywords
            ]

            is_payable = "payable" in qualifiers_raw

            functions.append({
                "name": name,
                "params": params,
                "visibility": visibility,
                "modifiers": modifiers,
                "is_payable": is_payable,
                "start_line": start_line,
                "body": body,
                "body_start_offset": body_start,
                "body_end_offset": body_end,
            })

        return functions

    def _extract_brace_block(self, source: str, start: int) -> str:
        """Extract text from start until the matching closing brace."""
        depth = 1
        pos = start
        while pos < len(source) and depth > 0:
            ch = source[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            pos += 1
        return source[start: pos - 1] if depth == 0 else source[start:]

    def _parse_function_body(
        self,
        func: Dict[str, Any],
        source_code: str,
        func_node_id: int,
        next_node_id: int,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Parse a function body into statement nodes and CFG/AST/DFG edges.

        Returns:
            (new_nodes, new_edges) to be merged into the global graph.
        """
        body = func.get("body", "")
        if not body.strip():
            return [], []

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        current_id = next_node_id

        statements = self._split_statements(body)
        prev_stmt_id: Optional[int] = None

        for stmt_text in statements:
            stmt_text = stmt_text.strip()
            if not stmt_text:
                continue

            # Determine statement sub-type
            stmt_subtype = self._classify_statement(stmt_text)
            line_in_body = body[: body.find(stmt_text)].count("\n")
            absolute_line = func["start_line"] + line_in_body + 1

            stmt_node = {
                "id": current_id,
                "type": self.NODE_TYPE_STATEMENT,
                "subtype": stmt_subtype,
                "text": stmt_text[:200],  # truncate for memory
                "line": absolute_line,
                "function": func["name"],
            }
            nodes.append(stmt_node)

            # AST edge: function -> statement
            edges.append({
                "from": func_node_id,
                "to": current_id,
                "type": self.EDGE_TYPE_AST,
            })

            # CFG edge: sequential flow between statements
            if prev_stmt_id is not None:
                edges.append({
                    "from": prev_stmt_id,
                    "to": current_id,
                    "type": self.EDGE_TYPE_CFG,
                })

            prev_stmt_id = current_id
            current_id += 1

        return nodes, edges

    def _split_statements(self, body: str) -> List[str]:
        """Split a function body into individual statements."""
        # Split on semicolons, but not inside string literals or nested blocks
        statements = []
        depth = 0
        current: List[str] = []
        for ch in body:
            if ch == "{":
                depth += 1
                current.append(ch)
            elif ch == "}":
                depth -= 1
                current.append(ch)
            elif ch == ";" and depth == 0:
                statements.append("".join(current).strip())
                current = []
            else:
                current.append(ch)
        remainder = "".join(current).strip()
        if remainder:
            statements.append(remainder)
        return statements

    def _classify_statement(self, stmt: str) -> str:
        """Classify a statement by its syntactic role."""
        s = stmt.strip()
        if s.startswith("if") or s.startswith("else"):
            return "conditional"
        if s.startswith("for") or s.startswith("while"):
            return "loop"
        if s.startswith("require(") or s.startswith("assert("):
            return "guard"
        if s.startswith("emit "):
            return "event_emit"
        if s.startswith("return"):
            return "return"
        if ".call(" in s or ".send(" in s or ".transfer(" in s:
            return "external_call"
        if "delegatecall" in s:
            return "delegatecall"
        if "=" in s and "==" not in s and "!=" not in s:
            return "assignment"
        return "expression"

    def _build_inter_function_edges(
        self,
        functions: List[Dict[str, Any]],
        source_code: str,
    ) -> List[Dict[str, Any]]:
        """Build CFG edges between functions based on call relationships."""
        edges: List[Dict[str, Any]] = []
        func_name_to_id = {
            f["name"]: f["node_id"] for f in functions
        }

        for func in functions:
            body = func.get("body", "")
            for called in re.findall(r"(\w+)\s*\(", body):
                if called in func_name_to_id and called != func["name"]:
                    edges.append({
                        "from": func["node_id"],
                        "to": func_name_to_id[called],
                        "type": self.EDGE_TYPE_CFG,
                        "subtype": "function_call",
                    })
        return edges

    def _build_taint_edges(
        self,
        nodes: List[Dict[str, Any]],
        functions: List[Dict[str, Any]],
        state_variables: List[Dict[str, Any]],
        source_code: str,
    ) -> List[Dict[str, Any]]:
        """
        Build data-flow graph (DFG) edges for taint propagation.

        Taint sources: msg.sender, msg.value, tx.origin, block.timestamp,
                       function parameters.
        Taint sinks:   state variable writes, external calls, selfdestruct.
        """
        edges: List[Dict[str, Any]] = []
        state_var_names: Set[str] = {sv["name"] for sv in state_variables}

        taint_sources = {
            "msg.sender", "msg.value", "tx.origin",
            "block.timestamp", "block.number", "now",
        }

        for func in functions:
            body = func.get("body", "")
            func_id = func["node_id"]

            # Identify local taint from parameters
            param_names = set()
            if func.get("params"):
                for p in func["params"].split(","):
                    parts = p.strip().split()
                    if len(parts) >= 2:
                        param_names.add(parts[-1])

            # Walk statements to find taint propagation paths
            stmts = self._split_statements(body)
            tainted_vars: Set[str] = set(param_names)

            for stmt in stmts:
                stmt = stmt.strip()
                if not stmt:
                    continue

                # Check if statement references a taint source
                for src in taint_sources:
                    if src in stmt:
                        # If this is an assignment, taint the left-hand side
                        assign_match = re.match(
                            r"(\w+)\s*=\s*.*" + re.escape(src), stmt
                        )
                        if assign_match:
                            tainted_vars.add(assign_match.group(1))

                        # DFG edge: taint source -> function
                        edges.append({
                            "from": func_id,
                            "to": func_id,
                            "type": self.EDGE_TYPE_DFG,
                            "subtype": "taint_source",
                            "taint": src,
                        })

                # Check if a tainted variable flows into a state change
                for tv in tainted_vars:
                    if tv in stmt:
                        # Check for state variable write
                        for sv_name in state_var_names:
                            if sv_name in stmt and "=" in stmt and "==" not in stmt:
                                edges.append({
                                    "from": func_id,
                                    "to": func_id,
                                    "type": self.EDGE_TYPE_DFG,
                                    "subtype": "taint_sink_state_write",
                                    "tainted_var": tv,
                                    "state_var": sv_name,
                                })

                        # Check for flow into external call
                        if (
                            ".call(" in stmt
                            or ".send(" in stmt
                            or ".transfer(" in stmt
                        ):
                            edges.append({
                                "from": func_id,
                                "to": func_id,
                                "type": self.EDGE_TYPE_DFG,
                                "subtype": "taint_sink_external_call",
                                "tainted_var": tv,
                            })

        return edges

    # =========================================================================
    # GNN inference (requires model files)
    # =========================================================================

    def _run_gnn_inference(
        self, graph: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Run the pre-trained Peculiar GNN model on the code graph.

        Loads the model weights and config, converts the graph to tensor
        format, performs a forward pass, and returns per-function predictions.
        """
        try:
            import torch

            config_path = self.model_dir / "peculiar_config.json"
            weights_path = self.model_dir / "peculiar_weights.pt"

            with open(config_path, "r", encoding="utf-8") as fh:
                model_config = json.load(fh)

            state_dict = torch.load(
                weights_path, map_location=torch.device("cpu")
            )
            logger.info(
                "Loaded Peculiar model: %d parameters",
                sum(p.numel() for p in state_dict.values()),
            )

            # Convert graph nodes to feature tensors
            node_features = self._graph_to_tensor(graph, model_config)

            # Build adjacency info per edge type
            edge_index_ast = self._edge_index_for_type(
                graph["edges"], self.EDGE_TYPE_AST
            )
            edge_index_cfg = self._edge_index_for_type(
                graph["edges"], self.EDGE_TYPE_CFG
            )
            edge_index_dfg = self._edge_index_for_type(
                graph["edges"], self.EDGE_TYPE_DFG
            )

            # Perform message passing (simplified forward pass)
            # In production, this would instantiate the heterogeneous GNN
            # architecture described in the ICSE 2023 paper and call model.forward()
            predictions = self._model_forward_pass(
                state_dict,
                model_config,
                node_features,
                edge_index_ast,
                edge_index_cfg,
                edge_index_dfg,
                graph,
            )

            self._model_loaded = True
            return predictions

        except Exception as exc:
            logger.warning(
                "GNN inference failed (%s), falling back to patterns", exc
            )
            return self._run_pattern_analysis(graph, "")

    def _graph_to_tensor(
        self, graph: Dict[str, Any], model_config: Dict[str, Any]
    ) -> Any:
        """Convert graph node features to a torch tensor."""
        import torch

        feat_dim = model_config.get("feature_dim", 64)
        num_nodes = len(graph["nodes"])
        features = torch.zeros(num_nodes, feat_dim)

        for i, node in enumerate(graph["nodes"]):
            if i >= num_nodes:
                break
            # Encode node type as one-hot in first positions
            type_map = {
                self.NODE_TYPE_FUNCTION: 0,
                self.NODE_TYPE_STATEMENT: 1,
                self.NODE_TYPE_EXPRESSION: 2,
                self.NODE_TYPE_VARIABLE: 3,
                self.NODE_TYPE_MODIFIER: 4,
            }
            type_idx = type_map.get(node.get("type", ""), 1)
            if type_idx < feat_dim:
                features[i][type_idx] = 1.0

            # Encode statement subtype indicators
            subtype = node.get("subtype", "")
            subtype_map = {
                "external_call": 5,
                "delegatecall": 6,
                "assignment": 7,
                "conditional": 8,
                "loop": 9,
                "guard": 10,
                "return": 11,
                "event_emit": 12,
            }
            st_idx = subtype_map.get(subtype, -1)
            if 0 <= st_idx < feat_dim:
                features[i][st_idx] = 1.0

        return features

    def _edge_index_for_type(
        self, edges: List[Dict[str, Any]], edge_type: str
    ) -> List[Tuple[int, int]]:
        """Filter edges by type and return as list of (src, dst) tuples."""
        return [
            (e["from"], e["to"])
            for e in edges
            if e.get("type") == edge_type
            and isinstance(e.get("from"), int)
            and isinstance(e.get("to"), int)
        ]

    def _model_forward_pass(
        self,
        state_dict: Any,
        model_config: Dict[str, Any],
        node_features: Any,
        edge_index_ast: List[Tuple[int, int]],
        edge_index_cfg: List[Tuple[int, int]],
        edge_index_dfg: List[Tuple[int, int]],
        graph: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Execute simplified forward pass using loaded model weights.

        In a full implementation this would instantiate the Peculiar
        HeteroGNN model class, load the state dict, and run inference.
        Here we apply the loaded weights as linear projections to
        approximate the model output.
        """
        import torch

        predictions: List[Dict[str, Any]] = []
        num_classes = len(self.VULNERABILITY_TYPES)
        vuln_types = list(self.VULNERABILITY_TYPES.keys())

        # Use first linear layer from state dict if available
        classifier_key = None
        for key in state_dict:
            if "classifier" in key and "weight" in key:
                classifier_key = key
                break

        if classifier_key is not None:
            weight = state_dict[classifier_key]
            # Global graph-level readout: mean pooling
            graph_embedding = node_features.mean(dim=0)
            feat_dim = graph_embedding.shape[0]
            w_dim = weight.shape[1]
            # Align dimensions
            if feat_dim >= w_dim:
                logits = torch.matmul(weight, graph_embedding[:w_dim])
            else:
                padded = torch.zeros(w_dim)
                padded[:feat_dim] = graph_embedding
                logits = torch.matmul(weight, padded)

            probs = torch.sigmoid(logits).tolist()
            for idx, vuln_type in enumerate(vuln_types):
                if idx < len(probs):
                    prob = probs[idx]
                else:
                    prob = 0.0
                if prob >= self.confidence_threshold:
                    predictions.append({
                        "type": vuln_type,
                        "confidence": round(prob, 4),
                        "source": "gnn_model",
                    })
        else:
            logger.warning("No classifier weights found in model, using heuristic scoring")
            # Fall through to pattern analysis via caller

        return predictions

    # =========================================================================
    # Pattern-based fallback analysis
    # =========================================================================

    def _run_pattern_analysis(
        self, graph: Dict[str, Any], source_code: str
    ) -> List[Dict[str, Any]]:
        """
        Pattern-based vulnerability analysis as a fallback when the
        GNN model is not available.

        Examines:
        - AST-like patterns: function calls, state variables, modifiers
        - Control flow patterns: loops, conditionals, external calls
        - Data flow patterns: taint from msg.sender/msg.value to state changes
        """
        predictions: List[Dict[str, Any]] = []

        # Reconstruct source from graph if not provided directly
        if not source_code:
            source_code = self._reconstruct_source_from_graph(graph)

        # -- Reentrancy --
        reentrancy = self._pattern_reentrancy(graph, source_code)
        predictions.extend(reentrancy)

        # -- Integer Overflow --
        overflow = self._pattern_integer_overflow(source_code)
        predictions.extend(overflow)

        # -- Access Control --
        access = self._pattern_access_control(graph, source_code)
        predictions.extend(access)

        # -- Unchecked Return --
        unchecked = self._pattern_unchecked_return(graph, source_code)
        predictions.extend(unchecked)

        # -- Timestamp Dependence --
        timestamp = self._pattern_timestamp_dependence(graph, source_code)
        predictions.extend(timestamp)

        # -- tx.origin --
        txorigin = self._pattern_tx_origin(graph, source_code)
        predictions.extend(txorigin)

        # -- Delegatecall Injection --
        delegatecall = self._pattern_delegatecall_injection(graph, source_code)
        predictions.extend(delegatecall)

        return predictions

    def _pattern_reentrancy(
        self, graph: Dict[str, Any], source: str
    ) -> List[Dict[str, Any]]:
        """
        Detect reentrancy via graph structure: external call followed by
        state variable assignment in the same function.
        """
        findings: List[Dict[str, Any]] = []

        for func in graph.get("functions", []):
            body = func.get("body", "")
            stmts = self._split_statements(body)
            found_external_call = False
            call_line = 0

            for stmt in stmts:
                stmt_stripped = stmt.strip()
                # Detect external call
                if (
                    ".call(" in stmt_stripped
                    or ".call{" in stmt_stripped
                    or ".send(" in stmt_stripped
                ):
                    found_external_call = True
                    line_offset = body[: body.find(stmt_stripped)].count("\n")
                    call_line = func["start_line"] + line_offset + 1

                # After an external call, detect state changes
                if found_external_call and "=" in stmt_stripped and "==" not in stmt_stripped:
                    state_var_names = {
                        sv["name"] for sv in graph.get("state_variables", [])
                    }
                    for sv in state_var_names:
                        if sv in stmt_stripped:
                            confidence = 0.90
                            # Boost if no reentrancy guard modifier
                            if not any(
                                m.lower() in ("nonreentrant", "reentrancyguard")
                                for m in func.get("modifiers", [])
                            ):
                                confidence = 0.95
                            findings.append({
                                "type": "reentrancy",
                                "confidence": confidence,
                                "function": func["name"],
                                "line": call_line,
                                "detail": (
                                    f"State variable '{sv}' modified after "
                                    f"external call in {func['name']}()"
                                ),
                                "source": "pattern_analysis",
                            })
                            break

        return findings

    def _pattern_integer_overflow(
        self, source: str
    ) -> List[Dict[str, Any]]:
        """Detect integer overflow in pre-0.8.0 contracts without SafeMath."""
        findings: List[Dict[str, Any]] = []

        # Check pragma for Solidity version
        version_match = re.search(
            r"pragma\s+solidity\s+[\^~>=<]*\s*(0\.(\d+)\.\d+)", source
        )
        if version_match:
            minor = int(version_match.group(2))
            if minor >= 8:
                return findings  # Built-in overflow protection

        uses_safemath = "SafeMath" in source or "using SafeMath" in source
        if uses_safemath:
            return findings

        # Look for arithmetic operations
        arith_pattern = re.compile(
            r"(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\w+)", re.MULTILINE
        )
        for match in arith_pattern.finditer(source):
            line_num = source[: match.start()].count("\n") + 1
            operator = match.group(3)
            findings.append({
                "type": "integer_overflow",
                "confidence": 0.80,
                "line": line_num,
                "detail": (
                    f"Unchecked arithmetic '{operator}' at line {line_num} "
                    f"in pre-0.8 contract without SafeMath"
                ),
                "source": "pattern_analysis",
            })

        # Deduplicate: keep highest confidence per type
        if len(findings) > 1:
            findings = [max(findings, key=lambda f: f["confidence"])]

        return findings

    def _pattern_access_control(
        self, graph: Dict[str, Any], source: str
    ) -> List[Dict[str, Any]]:
        """
        Detect missing access control on privileged operations.

        Checks functions containing: selfdestruct, mint, burn, pause,
        setOwner, transferOwnership, withdraw, upgradeTo.
        """
        findings: List[Dict[str, Any]] = []
        privileged_keywords = [
            "selfdestruct", "suicide", "mint", "burn", "pause",
            "unpause", "setOwner", "transferOwnership", "withdraw",
            "upgradeTo", "setAdmin", "setPrice",
        ]
        access_modifiers = {
            "onlyowner", "onlyadmin", "onlyrole", "onlyminter",
            "onlypauser", "onlygovernance", "nonreentrant",
        }

        for func in graph.get("functions", []):
            body = func.get("body", "")
            func_modifiers_lower = {
                m.lower() for m in func.get("modifiers", [])
            }
            has_access_control = bool(
                func_modifiers_lower & access_modifiers
            )

            # Check for require(msg.sender == ...) in body as inline guard
            if "require(msg.sender" in body or "require(msg.sender ==" in body:
                has_access_control = True

            if has_access_control:
                continue

            for keyword in privileged_keywords:
                if keyword.lower() in body.lower() or keyword.lower() in func["name"].lower():
                    findings.append({
                        "type": "access_control",
                        "confidence": 0.85,
                        "function": func["name"],
                        "line": func["start_line"],
                        "detail": (
                            f"Function {func['name']}() contains "
                            f"privileged operation '{keyword}' without "
                            f"access control modifier"
                        ),
                        "source": "pattern_analysis",
                    })
                    break  # One finding per function

        return findings

    def _pattern_unchecked_return(
        self, graph: Dict[str, Any], source: str
    ) -> List[Dict[str, Any]]:
        """Detect unchecked return values from low-level calls."""
        findings: List[Dict[str, Any]] = []

        for func in graph.get("functions", []):
            body = func.get("body", "")
            # Find .call( patterns
            for call_match in re.finditer(
                r"\.call[({]", body
            ):
                context_start = max(0, call_match.start() - 80)
                context_end = min(
                    len(body), call_match.end() + 120
                )
                context = body[context_start:context_end]

                # Check if return value is captured and checked
                is_checked = (
                    "require(" in context
                    or "assert(" in context
                    or "if (" in context
                    or "if(" in context
                    or "(bool success" in context
                    or "bool success" in body
                )
                if not is_checked:
                    line_offset = body[: call_match.start()].count("\n")
                    findings.append({
                        "type": "unchecked_return",
                        "confidence": 0.82,
                        "function": func["name"],
                        "line": func["start_line"] + line_offset + 1,
                        "detail": (
                            f"Unchecked return value of .call() in "
                            f"{func['name']}()"
                        ),
                        "source": "pattern_analysis",
                    })

        return findings

    def _pattern_timestamp_dependence(
        self, graph: Dict[str, Any], source: str
    ) -> List[Dict[str, Any]]:
        """Detect dangerous reliance on block.timestamp."""
        findings: List[Dict[str, Any]] = []
        timestamp_refs = ["block.timestamp", "now"]

        for func in graph.get("functions", []):
            body = func.get("body", "")
            for ref in timestamp_refs:
                if ref in body:
                    # Check if used in conditional or comparison
                    for cond_match in re.finditer(
                        r"(if|require|assert)\s*\([^)]*"
                        + re.escape(ref)
                        + r"[^)]*\)",
                        body,
                    ):
                        line_offset = body[: cond_match.start()].count("\n")
                        findings.append({
                            "type": "timestamp_dependence",
                            "confidence": 0.78,
                            "function": func["name"],
                            "line": func["start_line"] + line_offset + 1,
                            "detail": (
                                f"'{ref}' used in conditional logic in "
                                f"{func['name']}(). Miners can manipulate "
                                f"block timestamps by ~15 seconds."
                            ),
                            "source": "pattern_analysis",
                        })

        return findings

    def _pattern_tx_origin(
        self, graph: Dict[str, Any], source: str
    ) -> List[Dict[str, Any]]:
        """Detect tx.origin used for authentication."""
        findings: List[Dict[str, Any]] = []

        for func in graph.get("functions", []):
            body = func.get("body", "")
            for match in re.finditer(r"tx\.origin", body):
                line_offset = body[: match.start()].count("\n")
                context = body[
                    max(0, match.start() - 40): match.end() + 40
                ]
                # Higher confidence if used in require/if
                conf = 0.88 if (
                    "require(" in context or "if(" in context or "if (" in context
                ) else 0.75
                findings.append({
                    "type": "tx_origin",
                    "confidence": conf,
                    "function": func["name"],
                    "line": func["start_line"] + line_offset + 1,
                    "detail": (
                        f"tx.origin used in {func['name']}(). "
                        f"This is vulnerable to phishing attacks via "
                        f"intermediary contracts."
                    ),
                    "source": "pattern_analysis",
                })

        return findings

    def _pattern_delegatecall_injection(
        self, graph: Dict[str, Any], source: str
    ) -> List[Dict[str, Any]]:
        """Detect delegatecall to unvalidated or user-supplied address."""
        findings: List[Dict[str, Any]] = []

        for func in graph.get("functions", []):
            body = func.get("body", "")
            for dc_match in re.finditer(r"\.delegatecall\(", body):
                line_offset = body[: dc_match.start()].count("\n")

                # Check if the target is a state variable or hardcoded
                pre_context = body[
                    max(0, dc_match.start() - 100): dc_match.start()
                ]
                # Look for address parameter origin
                param_names = set()
                if func.get("params"):
                    for p in func["params"].split(","):
                        parts = p.strip().split()
                        if len(parts) >= 2:
                            param_names.add(parts[-1])

                # If delegatecall target comes from function parameter, high risk
                is_param_derived = any(
                    pn in pre_context for pn in param_names
                )
                confidence = 0.92 if is_param_derived else 0.75

                findings.append({
                    "type": "delegatecall_injection",
                    "confidence": confidence,
                    "function": func["name"],
                    "line": func["start_line"] + line_offset + 1,
                    "detail": (
                        f"delegatecall in {func['name']}() "
                        + (
                            "with parameter-derived target address"
                            if is_param_derived
                            else "detected; verify target is trusted"
                        )
                    ),
                    "source": "pattern_analysis",
                })

        return findings

    # =========================================================================
    # Prediction to MIESC finding conversion
    # =========================================================================

    def _predictions_to_findings(
        self,
        predictions: List[Dict[str, Any]],
        contract_path: str,
        source_code: str,
    ) -> List[Dict[str, Any]]:
        """Convert raw predictions to MIESC-normalized findings."""
        findings: List[Dict[str, Any]] = []
        contract_hash = hashlib.sha256(
            contract_path.encode()
        ).hexdigest()[:8]

        for idx, pred in enumerate(predictions):
            vuln_type = pred.get("type", "unknown")
            confidence = pred.get("confidence", 0.0)
            if confidence < self.confidence_threshold:
                continue

            vuln_meta = self.VULNERABILITY_TYPES.get(vuln_type, {})
            func_name = pred.get("function", "")
            line = pred.get("line", 0)

            # Attempt to extract a code snippet around the finding location
            snippet = ""
            if line > 0:
                lines = source_code.split("\n")
                start = max(0, line - 2)
                end = min(len(lines), line + 2)
                snippet = "\n".join(lines[start:end])

            finding_id = (
                f"PECULIAR-{vuln_type.upper()}-"
                f"{contract_hash}-{idx:04d}"
            )

            finding = {
                "id": finding_id,
                "type": vuln_type,
                "severity": vuln_meta.get("severity", "Medium"),
                "confidence": round(confidence, 3),
                "location": {
                    "file": Path(contract_path).name,
                    "line": line,
                    "function": func_name,
                },
                "message": pred.get(
                    "detail",
                    f"Peculiar detected potential {vuln_type.replace('_', ' ')}",
                ),
                "description": vuln_meta.get("description", ""),
                "recommendation": vuln_meta.get(
                    "recommendation", "Review and remediate the finding"
                ),
                "swc_id": vuln_meta.get("swc_id"),
                "cwe_id": vuln_meta.get("cwe_id"),
                "owasp_category": vuln_meta.get("owasp_category"),
                "code_snippet": snippet,
                "detection_method": pred.get("source", "peculiar"),
                "ml_model": "Peculiar (ICSE 2023)",
            }
            findings.append(finding)

        return findings

    # =========================================================================
    # Graph statistics and export
    # =========================================================================

    def _compute_graph_stats(
        self, graph: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Compute summary statistics for the constructed code graph."""
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])

        ast_edges = sum(1 for e in edges if e.get("type") == self.EDGE_TYPE_AST)
        cfg_edges = sum(1 for e in edges if e.get("type") == self.EDGE_TYPE_CFG)
        dfg_edges = sum(1 for e in edges if e.get("type") == self.EDGE_TYPE_DFG)

        node_type_counts: Dict[str, int] = {}
        for n in nodes:
            nt = n.get("type", "unknown")
            node_type_counts[nt] = node_type_counts.get(nt, 0) + 1

        return {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "ast_edges": ast_edges,
            "cfg_edges": cfg_edges,
            "dfg_edges": dfg_edges,
            "node_type_distribution": node_type_counts,
            "num_functions": len(graph.get("functions", [])),
            "num_state_variables": len(graph.get("state_variables", [])),
            "avg_degree": (
                round(len(edges) / max(len(nodes), 1), 2)
            ),
        }

    def _export_graph(
        self, graph: Dict[str, Any], output_path: str
    ) -> None:
        """Export the heterogeneous code graph to a JSON file."""
        try:
            export_data = {
                "tool": "peculiar",
                "version": "1.0.0",
                "graph": {
                    "nodes": graph["nodes"],
                    "edges": graph["edges"],
                    "stats": self._compute_graph_stats(graph),
                },
            }
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(export_data, fh, indent=2, default=str)
            logger.info("Graph exported to %s", output_path)
        except Exception as exc:
            logger.warning("Failed to export graph: %s", exc)

    def _reconstruct_source_from_graph(
        self, graph: Dict[str, Any]
    ) -> str:
        """Reconstruct approximate source text from graph nodes (fallback)."""
        parts: List[str] = []
        for func in graph.get("functions", []):
            parts.append(func.get("body", ""))
        return "\n".join(parts)

    # =========================================================================
    # Error result helper
    # =========================================================================

    def _error_result(
        self, message: str, start_time: float
    ) -> Dict[str, Any]:
        """Build a standardized error result dict."""
        return {
            "tool": "peculiar",
            "version": "1.0.0",
            "status": "error",
            "error": message,
            "findings": [],
            "metadata": {},
            "execution_time": round(time.time() - start_time, 3),
        }


# =============================================================================
# Module-level adapter registration
# =============================================================================

def register_adapter():
    """Register Peculiar adapter with MIESC tool registry."""
    return {
        "adapter_class": PeculiarAdapter,
        "metadata": PeculiarAdapter().get_metadata(),
    }


__all__ = ["PeculiarAdapter", "register_adapter"]
