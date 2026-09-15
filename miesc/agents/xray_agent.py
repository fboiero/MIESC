"""
X-Ray Agent — standalone pre-audit protocol map (MEJORAS.md item #4).

Wraps DeepAuditAgent's Phase-1 reconnaissance (call graph, risk profile, attack
surface score — see miesc/agents/deep_audit_agent.py) as a fast, LLM-free,
directory-capable report: what to look at before running the expensive tools.

Reuses the existing risk-profile classifier (defi/token/proxy/bridge) as the
"protocol type" — no second taxonomy is invented here. The one genuinely new
piece is entry-point permission classification (permissionless / role-gated /
admin), built from FunctionNode fields the call graph already exposes.

License: AGPL-3.0
"""

from pathlib import Path
from typing import Any, Dict, List

from miesc.agents.deep_audit_agent import DeepAuditAgent
from miesc.ml.protocol_graph import ProtocolGraph, build_protocol_graph

ADMIN_MODIFIERS = {"onlyOwner", "onlyAdmin", "onlyGovernance"}


def _classify_entry_points(call_graph: Any) -> Dict[str, List[Dict[str, Any]]]:
    """Bucket entry points into permissionless / role_gated / admin."""
    buckets: Dict[str, List[Dict[str, Any]]] = {
        "permissionless": [],
        "role_gated": [],
        "admin": [],
    }
    if call_graph is None or not hasattr(call_graph, "get_entry_points"):
        return buckets

    for fn in call_graph.get_entry_points():
        entry = {
            "name": fn.name,
            "start_line": fn.start_line,
            "end_line": fn.end_line,
            "modifiers": list(fn.modifiers),
        }
        if not fn.has_access_control:
            buckets["permissionless"].append(entry)
        elif ADMIN_MODIFIERS.intersection(fn.modifiers):
            buckets["admin"].append(entry)
        else:
            buckets["role_gated"].append(entry)
    return buckets


def _serialize_protocol_graph(graph: ProtocolGraph) -> Dict[str, Any]:
    """Report-friendly view — drops each contract's full source text."""
    return {
        "contracts": {
            name: {k: v for k, v in info.items() if k != "source"}
            for name, info in graph.contracts.items()
        },
        "inheritance_edges": graph.inheritance_edges,
        "call_edges": graph.call_edges,
        "unresolved_imports": graph.unresolved_imports,
        "storage_risk": graph.storage_risk,
    }


def run_xray(paths: List[str]) -> Dict[str, Any]:
    """Run X-Ray reconnaissance over one or more .sol files.

    Returns a dict with a per-file report plus, when more than one file is
    given: a `hotspots` list (entry points ranked by git commit count) and a
    `protocol` key — the cross-file dependency graph (inheritance, external
    calls between contracts, a storage-risk heuristic) from MEJORAS.md #5.
    Single-file calls omit `protocol` (nothing to merge across).
    """
    files_report: List[Dict[str, Any]] = []
    hotspots: List[Dict[str, Any]] = []

    for path in paths:
        agent = DeepAuditAgent()
        recon = agent.run_reconnaissance(path)
        entry_points = _classify_entry_points(recon.call_graph)

        file_report = {
            "contract": path,
            "protocol_type": recon.risk_profile.get("primary", "general"),
            "risk_profile": recon.risk_profile,
            "framework": recon.framework,
            "attack_surface_score": recon.attack_surface_score,
            "git_commits": recon.git_commits,
            "entry_points": entry_points,
            "duration_ms": recon.duration_ms,
        }
        files_report.append(file_report)

        for bucket in entry_points.values():
            for entry in bucket:
                hotspots.append(
                    {
                        "contract": Path(path).name,
                        "function": entry["name"],
                        "git_commits": recon.git_commits,
                    }
                )

    hotspots.sort(key=lambda h: h["git_commits"], reverse=True)

    report: Dict[str, Any] = {
        "files": files_report,
        "hotspots": hotspots[:10],
    }
    if len(paths) > 1:
        report["protocol"] = _serialize_protocol_graph(build_protocol_graph(paths))
    return report
