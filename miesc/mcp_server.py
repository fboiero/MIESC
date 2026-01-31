"""
MIESC MCP Server - Model Context Protocol stdio Server for Claude Desktop.

Exposes MIESC's 9-layer, 50-tool smart contract security analysis
as MCP tools accessible from Claude Desktop and other MCP clients.

Transport: stdio (JSON-RPC 2.0 over stdin/stdout)

Usage:
    python -m miesc.mcp_server
    # Or via entry point:
    miesc-mcp

Claude Desktop config.json:
    {
        "mcpServers": {
            "miesc": {
                "command": "python",
                "args": ["-m", "miesc.mcp_server"],
                "cwd": "/path/to/MIESC",
                "env": {"OLLAMA_HOST": "http://localhost:11434"}
            }
        }
    }

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2026-01-31
License: AGPL-3.0
"""

import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in path
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print(
        "Error: MCP SDK not installed. Install with: pip install 'mcp[cli]>=1.0.0'",
        file=sys.stderr,
    )
    sys.exit(1)

from miesc import __version__

logger = logging.getLogger("miesc.mcp_server")

# Initialize FastMCP server
mcp = FastMCP(
    "miesc",
    version=__version__,
    description=(
        "MIESC - Multi-layer Intelligent Evaluation for Smart Contracts. "
        "9 defense layers, 50 security tools, AI-powered correlation."
    ),
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_adapter_loader():
    """Lazy import of AdapterLoader to avoid circular imports."""
    from miesc.cli.main import AdapterLoader
    return AdapterLoader


def _get_layers():
    """Get LAYERS configuration."""
    from miesc.cli.main import LAYERS
    return LAYERS


def _get_adapter_map():
    """Get ADAPTER_MAP configuration."""
    from miesc.cli.main import ADAPTER_MAP
    return ADAPTER_MAP


def _run_tool_internal(tool: str, contract: str, timeout: int = 300, **kwargs) -> Dict[str, Any]:
    """Run a single tool via its adapter."""
    from miesc.cli.main import _run_tool
    return _run_tool(tool, contract, timeout, **kwargs)


def _run_layer_internal(layer: int, contract: str, timeout: int = 300) -> List[Dict[str, Any]]:
    """Run all tools in a specific layer."""
    from miesc.cli.main import _run_layer
    return _run_layer(layer, contract, timeout)


def _validate_contract_path(contract_path: str) -> str:
    """Validate and resolve contract path."""
    path = Path(contract_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Contract not found: {contract_path}")
    if not path.suffix in (".sol", ".circom"):
        raise ValueError(f"Unsupported file type: {path.suffix}. Expected .sol or .circom")
    return str(path)


def _summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create summary from tool results."""
    total_findings = 0
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    for result in results:
        for finding in result.get("findings", []):
            total_findings += 1
            sev = str(finding.get("severity", "Info")).capitalize()
            if sev in ("Critical", "Crit"):
                severity_counts["Critical"] += 1
            elif sev == "High":
                severity_counts["High"] += 1
            elif sev in ("Medium", "Med"):
                severity_counts["Medium"] += 1
            elif sev == "Low":
                severity_counts["Low"] += 1
            else:
                severity_counts["Info"] += 1

    return {
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "tools_run": len(results),
        "tools_succeeded": sum(1 for r in results if r.get("status") == "success"),
    }


# ===========================================================================
# MCP Tools - Analysis
# ===========================================================================

@mcp.tool()
async def miesc_quick_scan(contract_path: str, timeout: int = 60) -> str:
    """
    Fast Layer 1 static analysis using Slither, Aderyn, and Solhint.
    Ideal for CI/CD pipelines and quick feedback.
    Returns JSON with findings and severity counts.
    """
    contract_path = _validate_contract_path(contract_path)
    results = _run_layer_internal(1, contract_path, timeout)
    summary = _summarize_results(results)

    return json.dumps({
        "scan_type": "quick",
        "contract": contract_path,
        "summary": summary,
        "results": results,
        "timestamp": datetime.now().isoformat(),
    }, indent=2, default=str)


@mcp.tool()
async def miesc_deep_scan(contract_path: str, timeout: int = 300) -> str:
    """
    Comprehensive security scan using all 9 defense layers (50 tools).
    Includes static analysis, fuzzing, symbolic execution, formal verification,
    AI analysis, ML detection, and advanced ensemble methods.
    Recommended for pre-deployment audits.
    """
    contract_path = _validate_contract_path(contract_path)
    LAYERS = _get_layers()
    all_results = []

    for layer_num in sorted(LAYERS.keys()):
        layer_results = _run_layer_internal(layer_num, contract_path, timeout)
        all_results.extend(layer_results)

    summary = _summarize_results(all_results)

    return json.dumps({
        "scan_type": "deep",
        "contract": contract_path,
        "layers_scanned": len(LAYERS),
        "summary": summary,
        "results": all_results,
        "timestamp": datetime.now().isoformat(),
    }, indent=2, default=str)


@mcp.tool()
async def miesc_run_tool(tool_name: str, contract_path: str, timeout: int = 300) -> str:
    """
    Run a specific security tool on a contract.
    Available tools include: slither, aderyn, mythril, echidna, halmos,
    certora, smartllm, dagnn, and many more (50 total).
    Use miesc_list_tools to see all available tools.
    """
    contract_path = _validate_contract_path(contract_path)
    ADAPTER_MAP = _get_adapter_map()

    if tool_name not in ADAPTER_MAP:
        return json.dumps({
            "error": f"Unknown tool: {tool_name}",
            "available_tools": sorted(ADAPTER_MAP.keys()),
        })

    result = _run_tool_internal(tool_name, contract_path, timeout)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def miesc_run_layer(layer: int, contract_path: str, timeout: int = 300) -> str:
    """
    Run all tools in a specific defense layer (1-9).
    Layers: 1=Static, 2=Dynamic/Fuzzing, 3=Symbolic, 4=Formal Verification,
    5=AI Analysis, 6=ML Detection, 7=Specialized, 8=Cross-Chain/ZK, 9=Advanced Ensemble.
    """
    contract_path = _validate_contract_path(contract_path)
    LAYERS = _get_layers()

    if layer not in LAYERS:
        return json.dumps({
            "error": f"Invalid layer: {layer}. Valid layers: 1-{max(LAYERS.keys())}",
            "layers": {k: v["name"] for k, v in LAYERS.items()},
        })

    results = _run_layer_internal(layer, contract_path, timeout)
    summary = _summarize_results(results)

    return json.dumps({
        "layer": layer,
        "layer_name": LAYERS[layer]["name"],
        "contract": contract_path,
        "summary": summary,
        "results": results,
        "timestamp": datetime.now().isoformat(),
    }, indent=2, default=str)


@mcp.tool()
async def miesc_analyze_defi(
    contract_path: str,
    protocol_type: str = "generic",
    timeout: int = 120,
) -> str:
    """
    Specialized DeFi vulnerability analysis.
    Detects flash loan attacks, oracle manipulation, MEV vulnerabilities,
    reentrancy in DeFi contexts, and protocol-specific issues.
    Protocol types: lending, dex, yield, bridge, nft, dao, generic.
    """
    contract_path = _validate_contract_path(contract_path)

    defi_tools = ["defi_analyzer", "mev_detector", "advanced_detector"]
    results = []
    for tool in defi_tools:
        r = _run_tool_internal(tool, contract_path, timeout, protocol_type=protocol_type)
        results.append(r)

    summary = _summarize_results(results)

    return json.dumps({
        "scan_type": "defi",
        "protocol_type": protocol_type,
        "contract": contract_path,
        "summary": summary,
        "results": results,
        "timestamp": datetime.now().isoformat(),
    }, indent=2, default=str)


@mcp.tool()
async def miesc_profile_scan(
    contract_path: str,
    profile: str = "balanced",
    timeout: int = 300,
) -> str:
    """
    Run analysis with a predefined profile.
    Profiles: quick (L1 only), balanced (L1+L3+L5), thorough (all layers),
    defi (DeFi-focused), formal (L1+L3+L4).
    """
    contract_path = _validate_contract_path(contract_path)
    LAYERS = _get_layers()

    profiles = {
        "quick": [1],
        "balanced": [1, 3, 5],
        "thorough": list(range(1, 10)),
        "defi": [1, 7],
        "formal": [1, 3, 4],
    }

    if profile not in profiles:
        return json.dumps({
            "error": f"Unknown profile: {profile}",
            "available_profiles": list(profiles.keys()),
        })

    all_results = []
    for layer_num in profiles[profile]:
        if layer_num in LAYERS:
            layer_results = _run_layer_internal(layer_num, contract_path, timeout)
            all_results.extend(layer_results)

    summary = _summarize_results(all_results)

    return json.dumps({
        "scan_type": "profile",
        "profile": profile,
        "layers_scanned": profiles[profile],
        "contract": contract_path,
        "summary": summary,
        "results": all_results,
        "timestamp": datetime.now().isoformat(),
    }, indent=2, default=str)


# ===========================================================================
# MCP Tools - Correlation
# ===========================================================================

@mcp.tool()
async def miesc_correlate(findings_json: str, min_tools: int = 2, confidence_threshold: float = 0.5) -> str:
    """
    Correlate findings from multiple tools using the Smart Correlation Engine.
    Applies cross-validation, deduplication, and false positive filtering.
    Input: JSON string mapping tool names to their findings arrays.
    """
    try:
        findings_map = json.loads(findings_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input for findings_map"})

    try:
        from src.core.correlation_api import SmartCorrelationEngine
        engine = SmartCorrelationEngine()
        correlated = engine.correlate(
            findings_map,
            min_confirmations=min_tools,
            confidence_threshold=confidence_threshold,
        )
        return json.dumps(correlated, indent=2, default=str)
    except ImportError:
        return json.dumps({
            "error": "Correlation engine not available",
            "hint": "Ensure src.core.correlation_api is installed",
        })


@mcp.tool()
async def miesc_filter_fp(findings_json: str, threshold: float = 0.50) -> str:
    """
    Filter false positives from findings using ML-based classifier.
    Threshold: probability above which a finding is considered FP (default 0.50).
    Lower threshold = more aggressive filtering.
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"})

    try:
        from src.ml.false_positive_filter import FalsePositiveFilter
        fp_filter = FalsePositiveFilter()
        filtered = fp_filter.filter_findings(findings, fp_threshold=threshold)
        return json.dumps({
            "original_count": len(findings) if isinstance(findings, list) else 0,
            "filtered_count": len(filtered) if isinstance(filtered, list) else 0,
            "findings": filtered,
        }, indent=2, default=str)
    except ImportError:
        return json.dumps({"error": "FalsePositiveFilter not available"})


@mcp.tool()
async def miesc_detect_exploit_chains(findings_json: str) -> str:
    """
    Analyze findings to detect exploit chains - combinations of vulnerabilities
    that create more severe multi-step attack paths.
    Input: JSON string with tool findings.
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"})

    # Simple chain detection logic
    chains = []
    finding_list = findings if isinstance(findings, list) else []

    # Group by location
    by_file = {}
    for f in finding_list:
        loc = f.get("location", {})
        file_key = loc.get("file", "unknown")
        by_file.setdefault(file_key, []).append(f)

    # Detect common exploit chains
    chain_patterns = [
        {
            "name": "Reentrancy + Unchecked Return",
            "requires": ["reentrancy", "unchecked"],
            "severity": "Critical",
        },
        {
            "name": "Access Control + State Manipulation",
            "requires": ["access", "state"],
            "severity": "Critical",
        },
        {
            "name": "Oracle Manipulation + Flash Loan",
            "requires": ["oracle", "flash"],
            "severity": "Critical",
        },
    ]

    for file_path, file_findings in by_file.items():
        types_str = " ".join(str(f.get("type", "")) for f in file_findings).lower()
        for pattern in chain_patterns:
            if all(req in types_str for req in pattern["requires"]):
                chains.append({
                    "chain": pattern["name"],
                    "severity": pattern["severity"],
                    "file": file_path,
                    "contributing_findings": len(file_findings),
                })

    return json.dumps({
        "chains_detected": len(chains),
        "chains": chains,
    }, indent=2, default=str)


@mcp.tool()
async def miesc_verify_finding(
    finding_json: str,
    contract_path: str,
) -> str:
    """
    Verify a specific finding using Z3 counter-example generation (Layer 9).
    Input: JSON string with the finding to verify.
    """
    contract_path = _validate_contract_path(contract_path)

    try:
        finding = json.loads(finding_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input for finding"})

    result = _run_tool_internal(
        "vuln_verifier", contract_path, 120, findings=[finding]
    )
    return json.dumps(result, indent=2, default=str)


# ===========================================================================
# MCP Tools - Reports
# ===========================================================================

@mcp.tool()
async def miesc_generate_report(
    audit_results_json: str,
    format: str = "json",
    include_compliance: bool = True,
) -> str:
    """
    Generate a structured security audit report.
    Formats: json, markdown, html, pdf, sarif.
    Input: JSON string with complete audit results.
    """
    try:
        audit_results = json.loads(audit_results_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON for audit_results"})

    if format == "json":
        return json.dumps(audit_results, indent=2, default=str)

    if format == "sarif":
        try:
            from miesc.cli.main import _to_sarif
            results = audit_results.get("results", [])
            sarif = _to_sarif(results)
            return json.dumps(sarif, indent=2, default=str)
        except ImportError:
            return json.dumps({"error": "SARIF export not available"})

    if format == "markdown":
        lines = ["# MIESC Security Audit Report\n"]
        lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}\n")

        summary = audit_results.get("summary", {})
        lines.append("## Summary\n")
        for k, v in summary.items():
            lines.append(f"- **{k}:** {v}")

        results = audit_results.get("results", [])
        for result in results:
            tool = result.get("tool", "unknown")
            findings = result.get("findings", [])
            if findings:
                lines.append(f"\n## {tool} ({len(findings)} findings)\n")
                for f in findings[:20]:
                    sev = f.get("severity", "Info")
                    msg = f.get("message", f.get("description", ""))
                    lines.append(f"- **[{sev}]** {msg}")

        return "\n".join(lines)

    return json.dumps({"error": f"Format '{format}' requires file output. Use CLI instead."})


@mcp.tool()
async def miesc_map_compliance(findings_json: str, frameworks: Optional[str] = None) -> str:
    """
    Map security findings to compliance frameworks.
    Supports: ISO27001, NIST, OWASP, CWE, SWC, MITRE.
    Input: JSON string with list of findings.
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"})

    try:
        from src.security.compliance_mapper import ComplianceMapper
        mapper = ComplianceMapper()
        framework_list = frameworks.split(",") if frameworks else None
        mapping = mapper.map_findings(findings, frameworks=framework_list)
        return json.dumps(mapping, indent=2, default=str)
    except ImportError:
        return json.dumps({"error": "ComplianceMapper not available"})


@mcp.tool()
async def miesc_remediate(findings_json: str, contract_name: str = "") -> str:
    """
    Enrich vulnerabilities with remediation suggestions.
    Provides SWC-based fix patterns, code examples, and prioritized fix plans.
    Input: JSON string with list of vulnerability findings.
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"})

    try:
        from src.security.remediation_engine import RemediationEngine
        engine = RemediationEngine()
        remediated = engine.enrich_findings(findings, contract_name=contract_name)
        return json.dumps(remediated, indent=2, default=str)
    except ImportError:
        # Fallback: basic remediation from finding data
        for f in (findings if isinstance(findings, list) else []):
            if not f.get("recommendation"):
                vuln_type = str(f.get("type", "")).lower()
                if "reentrancy" in vuln_type:
                    f["recommendation"] = "Add ReentrancyGuard or follow CEI pattern"
                elif "access" in vuln_type:
                    f["recommendation"] = "Add onlyOwner or role-based access control"
                elif "overflow" in vuln_type:
                    f["recommendation"] = "Use Solidity >=0.8.0 or SafeMath"
                else:
                    f["recommendation"] = "Review and fix the identified vulnerability"
        return json.dumps(findings, indent=2, default=str)


@mcp.tool()
async def miesc_get_metrics() -> str:
    """
    Retrieve MIESC's scientific validation metrics.
    Returns precision, recall, F1-score from thesis experiments
    (analysis of 5,127 smart contracts).
    """
    return json.dumps({
        "framework": "MIESC",
        "version": __version__,
        "layers": 9,
        "tools": 50,
        "validation": {
            "contracts_analyzed": 5127,
            "dataset": "SmartBugs Curated + Real-world DeFi",
            "metrics": {
                "precision": 0.89,
                "recall": 0.84,
                "f1_score": 0.86,
                "cohens_kappa": 0.72,
                "false_positive_rate": 0.11,
            },
            "cross_validation_improvement": {
                "precision_delta": "+12%",
                "fp_reduction": "-45%",
            },
        },
        "thesis": {
            "title": "Multi-layer Intelligent Evaluation for Smart Contracts",
            "institution": "UNDEF - IUA Cordoba",
            "author": "Fernando Boiero",
            "degree": "Master's in Cyberdefense",
        },
    }, indent=2)


# ===========================================================================
# MCP Tools - System
# ===========================================================================

@mcp.tool()
async def miesc_get_status() -> str:
    """
    Get MIESC agent status, available tools, and health information.
    Returns version, active capabilities, tool availability, and component health.
    """
    LAYERS = _get_layers()
    ADAPTER_MAP = _get_adapter_map()
    AdapterLoader = _get_adapter_loader()

    available_tools = AdapterLoader.get_available_tools()

    layer_info = {}
    for num, layer in LAYERS.items():
        layer_tools = layer["tools"]
        available_in_layer = [t for t in layer_tools if t in available_tools]
        layer_info[str(num)] = {
            "name": layer["name"],
            "total": len(layer_tools),
            "available": len(available_in_layer),
            "tools": layer_tools,
        }

    return json.dumps({
        "name": "MIESC",
        "version": __version__,
        "status": "operational",
        "architecture": {
            "layers": 9,
            "total_tools": len(ADAPTER_MAP),
            "available_tools": len(available_tools),
        },
        "layers": layer_info,
        "timestamp": datetime.now().isoformat(),
    }, indent=2)


@mcp.tool()
async def miesc_list_tools(layer: Optional[int] = None) -> str:
    """
    List all available security analysis tools.
    Optionally filter by layer number (1-9).
    Returns tool names, categories, and availability status.
    """
    LAYERS = _get_layers()
    ADAPTER_MAP = _get_adapter_map()
    AdapterLoader = _get_adapter_loader()

    available = set(AdapterLoader.get_available_tools())
    tools = []

    if layer is not None:
        if layer not in LAYERS:
            return json.dumps({"error": f"Invalid layer: {layer}"})
        layer_tools = LAYERS[layer]["tools"]
        for t in layer_tools:
            tools.append({
                "name": t,
                "layer": layer,
                "layer_name": LAYERS[layer]["name"],
                "available": t in available,
            })
    else:
        for num, layer_info in sorted(LAYERS.items()):
            for t in layer_info["tools"]:
                tools.append({
                    "name": t,
                    "layer": num,
                    "layer_name": layer_info["name"],
                    "available": t in available,
                })

    return json.dumps({
        "total": len(tools),
        "available": sum(1 for t in tools if t["available"]),
        "tools": tools,
    }, indent=2)


@mcp.tool()
async def miesc_get_tool_info(tool_name: str) -> str:
    """
    Get detailed information about a specific security tool.
    Returns metadata, capabilities, installation instructions, and status.
    """
    ADAPTER_MAP = _get_adapter_map()
    AdapterLoader = _get_adapter_loader()

    if tool_name not in ADAPTER_MAP:
        return json.dumps({
            "error": f"Unknown tool: {tool_name}",
            "available_tools": sorted(ADAPTER_MAP.keys()),
        })

    adapter = AdapterLoader.get_adapter(tool_name)
    if not adapter:
        return json.dumps({
            "name": tool_name,
            "status": "adapter_not_loaded",
            "class": ADAPTER_MAP[tool_name],
        })

    try:
        metadata = adapter.get_metadata()
        status = adapter.is_available()
        return json.dumps({
            "name": metadata.name,
            "version": metadata.version,
            "category": metadata.category.value,
            "author": metadata.author,
            "license": metadata.license,
            "homepage": metadata.homepage,
            "installation": metadata.installation_cmd,
            "status": status.value,
            "capabilities": [
                {
                    "name": c.name,
                    "description": c.description,
                    "languages": c.supported_languages,
                    "detection_types": c.detection_types,
                }
                for c in metadata.capabilities
            ],
            "is_optional": metadata.is_optional,
            "cost": metadata.cost,
        }, indent=2, default=str)
    except Exception as e:
        return json.dumps({"name": tool_name, "error": str(e)})


@mcp.tool()
async def miesc_read_contract(contract_path: str) -> str:
    """
    Read a smart contract file and return its contents with metadata.
    Useful for reviewing contract source code before analysis.
    """
    contract_path = _validate_contract_path(contract_path)

    with open(contract_path, "r", errors="ignore") as f:
        source = f.read()

    lines = source.split("\n")

    # Extract basic info
    pragma_match = None
    contract_names = []
    import re
    for line in lines:
        if not pragma_match:
            m = re.search(r"pragma\s+solidity\s+([^;]+)", line)
            if m:
                pragma_match = m.group(1).strip()
        m = re.search(r"(?:contract|interface|library)\s+(\w+)", line)
        if m:
            contract_names.append(m.group(1))

    return json.dumps({
        "path": contract_path,
        "lines": len(lines),
        "size_bytes": len(source),
        "solidity_version": pragma_match,
        "contracts": contract_names,
        "source": source[:50000],  # Cap at 50KB
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run MIESC MCP server via stdio transport."""
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
