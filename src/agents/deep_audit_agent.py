"""
MIESC Deep Audit Agent - Agentic Security Analysis

Implements a 4-phase iterative audit loop:
  Phase 1: Reconnaissance (call graph, taint, risk profiling)
  Phase 2: Targeted Scan (adaptive tool selection)
  Phase 3: Deep Investigation (agentic loop with RAG enrichment)
  Phase 4: Synthesis (correlation, exploit chains, LLM narrative)

DPGA Compliant: 100% local execution, no telemetry, privacy-preserving.
Ollama/Claude API are optional - graceful degradation to ML-only.

Author: Fernando Boiero
License: AGPL-3.0
"""

import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from src.agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class DeepAuditConfig:
    """Configuration for the agentic deep audit.

    LLM priority (local-first, cloud optional):
      1. Ollama (local) - default, DPGA compliant
      2. Anthropic Claude API - if ANTHROPIC_API_KEY set
      3. OpenAI API - if OPENAI_API_KEY set
      4. No LLM - graceful degradation to template narrative
    """

    timeout_seconds: int = 600
    max_iterations: int = 5
    min_severity_for_deep: str = "high"
    enable_llm: bool = True
    llm_provider: str = "auto"  # "auto", "ollama", "anthropic", "openai"
    llm_model: str = "mistral:latest"
    enable_rag: bool = True
    enable_taint: bool = True
    enable_call_graph: bool = True
    enable_exploit_chains: bool = True
    fp_threshold: float = 0.5
    max_workers: int = 4


class AuditPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    TARGETED_SCAN = "targeted_scan"
    DEEP_INVESTIGATION = "deep_investigation"
    SYNTHESIS = "synthesis"


# ---------------------------------------------------------------------------
# Internal result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ReconResult:
    """Phase 1 output."""

    call_graph: Any = None
    taint_results: List[Any] = field(default_factory=list)
    risk_profile: Dict[str, Any] = field(default_factory=dict)
    entry_points: List[str] = field(default_factory=list)
    external_calls: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    framework: str = "unknown"
    duration_ms: float = 0.0


@dataclass
class ScanResult:
    """Phase 2 output."""

    tools_run: List[str] = field(default_factory=list)
    tools_available: List[str] = field(default_factory=list)
    raw_findings: List[Dict[str, Any]] = field(default_factory=list)
    filtered_findings: List[Dict[str, Any]] = field(default_factory=list)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Risk Profile Patterns
# ---------------------------------------------------------------------------

RISK_PATTERNS = {
    "defi": [
        r"\bswap\b", r"\bliquidity\b", r"\bpool\b", r"\boracle\b",
        r"\bflash\s*loan\b", r"\bprice\b", r"\bamm\b", r"\bvault\b",
        r"\byield\b", r"\bstake\b", r"\blend\b", r"\bborrow\b",
    ],
    "token": [
        r"\bTransfer\b", r"\bApproval\b", r"\bbalanceOf\b",
        r"\btotalSupply\b", r"\bmint\b", r"\bburn\b",
        r"\bERC20\b", r"\bERC721\b", r"\bERC1155\b",
    ],
    "proxy": [
        r"\bdelegatecall\b", r"\bimplementation\b", r"\bupgradeTo\b",
        r"\bUUPS\b", r"\bBeacon\b", r"\bTransparentProxy\b",
        r"\bInitializable\b",
    ],
    "bridge": [
        r"\block\b.*\bunlock\b", r"\brelay\b", r"\bcrosschain\b",
        r"\bmessage\b.*\bpass\b", r"\bbridge\b", r"\bwormhole\b",
    ],
}


# ---------------------------------------------------------------------------
# DeepAuditAgent
# ---------------------------------------------------------------------------

class DeepAuditAgent(BaseAgent):
    """
    Agentic deep audit agent with iterative investigation loop.

    Unlike ``audit smart`` which runs a fixed set of tools, this agent:
    - Analyzes contract structure before selecting tools
    - Adaptively chooses tools based on risk profile
    - Iteratively investigates HIGH/CRITICAL findings
    - Enriches findings with RAG vulnerability knowledge
    - Detects exploit chains across findings
    - Generates LLM narrative (local Ollama, optional Claude API)
    """

    def __init__(self, config: Optional[DeepAuditConfig] = None):
        super().__init__(
            agent_name="DeepAuditAgent",
            capabilities=[
                "agentic_audit",
                "adaptive_tool_selection",
                "iterative_investigation",
                "rag_enrichment",
                "exploit_chain_detection",
            ],
            agent_type="coordinator",
        )
        self.config = config or DeepAuditConfig()
        self._start_time: float = 0.0
        self._current_phase = AuditPhase.RECONNAISSANCE

    def get_context_types(self) -> List[str]:
        return [
            "deep_audit_reconnaissance",
            "deep_audit_initial_findings",
            "deep_audit_enriched_findings",
            "deep_audit_report",
        ]

    # -----------------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------------

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Run the 4-phase agentic deep audit."""
        self._start_time = time.monotonic()
        self.contract_path = contract_path
        source_code = Path(contract_path).read_text()

        logger.info(f"DeepAuditAgent starting on {contract_path}")
        report = {
            "contract": contract_path,
            "agent": "DeepAuditAgent",
            "phases": {},
            "findings": [],
            "exploit_chains": [],
            "metadata": {"config": self.config.__dict__.copy()},
        }

        # Phase 1: Reconnaissance
        self._current_phase = AuditPhase.RECONNAISSANCE
        logger.info("Phase 1: Reconnaissance")
        recon = self._phase_reconnaissance(contract_path, source_code)
        report["phases"]["reconnaissance"] = {
            "risk_profile": recon.risk_profile,
            "entry_points": recon.entry_points[:10],
            "attack_surface_score": recon.attack_surface_score,
            "framework": recon.framework,
            "duration_ms": recon.duration_ms,
        }
        self.publish_findings("deep_audit_reconnaissance", report["phases"]["reconnaissance"])

        if self._timeout_exceeded():
            report["metadata"]["timed_out_in"] = "reconnaissance"
            return report

        # Phase 2: Targeted Scan
        self._current_phase = AuditPhase.TARGETED_SCAN
        logger.info("Phase 2: Targeted Scan")
        scan = self._phase_targeted_scan(contract_path, recon)
        report["phases"]["targeted_scan"] = {
            "tools_run": scan.tools_run,
            "raw_count": len(scan.raw_findings),
            "filtered_count": len(scan.filtered_findings),
            "severity_distribution": scan.severity_distribution,
            "duration_ms": scan.duration_ms,
        }
        self.publish_findings("deep_audit_initial_findings", {
            "findings": scan.filtered_findings,
            "tools_run": scan.tools_run,
        })

        if self._timeout_exceeded():
            report["findings"] = scan.filtered_findings
            report["metadata"]["timed_out_in"] = "targeted_scan"
            return report

        # Phase 3: Deep Investigation (agentic loop)
        self._current_phase = AuditPhase.DEEP_INVESTIGATION
        logger.info("Phase 3: Deep Investigation (agentic loop)")
        investigation = self._phase_deep_investigation(
            contract_path, source_code, recon, scan
        )
        report["phases"]["deep_investigation"] = {
            "iterations": investigation.get("iterations", 0),
            "findings_enriched": investigation.get("enriched_count", 0),
            "additional_tools": investigation.get("additional_tools", []),
            "chains_detected": len(investigation.get("exploit_chains", [])),
            "mitigated": investigation.get("mitigated_count", 0),
        }

        if self._timeout_exceeded():
            report["findings"] = investigation.get("findings", scan.filtered_findings)
            report["exploit_chains"] = investigation.get("exploit_chains", [])
            report["metadata"]["timed_out_in"] = "deep_investigation"
            return report

        # Phase 4: Synthesis
        self._current_phase = AuditPhase.SYNTHESIS
        logger.info("Phase 4: Synthesis")
        synthesis = self._phase_synthesis(
            contract_path, source_code, recon, scan, investigation
        )
        report["findings"] = synthesis.get("findings", [])
        report["exploit_chains"] = synthesis.get("exploit_chains", [])
        report["phases"]["synthesis"] = {
            "final_count": len(report["findings"]),
            "chains": len(report["exploit_chains"]),
            "llm_narrative": synthesis.get("has_llm_narrative", False),
        }
        report["summary"] = synthesis.get("summary", {})
        report["narrative"] = synthesis.get("narrative", "")

        self.publish_findings("deep_audit_report", report)

        elapsed = (time.monotonic() - self._start_time) * 1000
        report["metadata"]["total_duration_ms"] = elapsed
        logger.info(
            f"DeepAuditAgent complete: {len(report['findings'])} findings, "
            f"{len(report['exploit_chains'])} chains, {elapsed:.0f}ms"
        )
        return report

    # -----------------------------------------------------------------------
    # Phase 1: Reconnaissance
    # -----------------------------------------------------------------------

    def _phase_reconnaissance(self, contract_path: str, source_code: str) -> ReconResult:
        t0 = time.monotonic()
        result = ReconResult()

        # Call graph analysis
        if self.config.enable_call_graph:
            result.call_graph, result.entry_points, result.external_calls = (
                self._build_call_graph(source_code)
            )

        # Taint analysis
        if self.config.enable_taint:
            result.taint_results = self._run_taint_analysis(source_code)

        # Risk profiling
        result.risk_profile = self._classify_risk_profile(source_code)

        # Framework detection
        result.framework = self._detect_framework(contract_path)

        # Attack surface score
        result.attack_surface_score = self._compute_attack_surface(
            result.entry_points, result.external_calls, result.taint_results
        )

        result.duration_ms = (time.monotonic() - t0) * 1000
        logger.info(
            f"Recon complete: profile={result.risk_profile.get('primary', 'general')}, "
            f"entries={len(result.entry_points)}, surface={result.attack_surface_score:.1f}"
        )
        return result

    def _build_call_graph(self, source_code: str):
        """Build call graph and extract entry points."""
        try:
            from src.ml.call_graph import CallGraphBuilder
            builder = CallGraphBuilder()
            cg = builder.build_from_source(source_code)
            entries = [n.name for n in cg.get_entry_points()] if hasattr(cg, "get_entry_points") else []
            ext_calls = []
            if hasattr(cg, "external_call_chains"):
                for chain in cg.external_call_chains():
                    ext_calls.extend([str(c) for c in chain[:2]])
            return cg, entries, ext_calls[:20]
        except Exception as e:
            logger.debug(f"Call graph analysis failed: {e}")
            return None, [], []

    def _run_taint_analysis(self, source_code: str):
        """Run taint analysis to find data flow vulnerabilities."""
        try:
            from src.ml.taint_analysis import TaintAnalyzer
            analyzer = TaintAnalyzer()
            return analyzer.analyze(source_code)
        except Exception as e:
            logger.debug(f"Taint analysis failed: {e}")
            return []

    def _classify_risk_profile(self, source_code: str) -> Dict[str, Any]:
        """Classify contract risk profile based on code patterns."""
        scores: Dict[str, int] = {}
        code_lower = source_code.lower()
        for profile, patterns in RISK_PATTERNS.items():
            count = sum(1 for p in patterns if re.search(p, code_lower))
            if count > 0:
                scores[profile] = count

        primary = max(scores, key=scores.get) if scores else "general"
        return {
            "primary": primary,
            "scores": scores,
            "is_defi": scores.get("defi", 0) >= 2,
            "is_token": scores.get("token", 0) >= 2,
            "is_proxy": scores.get("proxy", 0) >= 1,
            "is_bridge": scores.get("bridge", 0) >= 1,
            "has_external_calls": bool(re.search(r"\.call\{|\.delegatecall|\.send\(|\.transfer\(", source_code)),
            "has_selfdestruct": "selfdestruct" in code_lower,
            "has_assembly": "assembly" in code_lower,
            "solidity_version": self._extract_solidity_version(source_code),
        }

    def _extract_solidity_version(self, source_code: str) -> str:
        m = re.search(r"pragma\s+solidity\s+([^;]+)", source_code)
        return m.group(1).strip() if m else "unknown"

    def _detect_framework(self, contract_path: str) -> str:
        """Detect if contract uses known frameworks."""
        try:
            code = Path(contract_path).read_text()
            if "@openzeppelin" in code:
                return "openzeppelin"
            if "solmate" in code:
                return "solmate"
            if "solady" in code:
                return "solady"
        except Exception:
            pass
        return "custom"

    def _compute_attack_surface(
        self, entries: List[str], ext_calls: List[str], taint: list
    ) -> float:
        """Compute attack surface score 0-100."""
        score = min(len(entries) * 5, 30)
        score += min(len(ext_calls) * 10, 40)
        score += min(len(taint) * 5, 30) if isinstance(taint, list) else 0
        return min(score, 100.0)

    # -----------------------------------------------------------------------
    # Phase 2: Targeted Scan
    # -----------------------------------------------------------------------

    def _phase_targeted_scan(self, contract_path: str, recon: ReconResult) -> ScanResult:
        t0 = time.monotonic()
        result = ScanResult()

        # Select tools based on risk profile
        selected_tools = self._select_tools(recon)
        result.tools_run = selected_tools

        logger.info(f"Selected tools for profile '{recon.risk_profile.get('primary')}': {selected_tools}")

        # Use MLOrchestrator for reliable tool execution (same as audit smart)
        ml_orch = self._get_ml_orchestrator()
        if ml_orch:
            try:
                timeout_per_tool = int(self._remaining_seconds() * 0.7 / max(len(selected_tools), 1))
                ml_result = ml_orch.analyze(
                    contract_path=contract_path,
                    tools=selected_tools,
                    timeout=max(timeout_per_tool, 30),
                )
                result.raw_findings = ml_result.raw_findings if hasattr(ml_result, "raw_findings") else []
                result.filtered_findings = (
                    ml_result.ml_filtered_findings
                    if hasattr(ml_result, "ml_filtered_findings")
                    else result.raw_findings
                )
                result.tools_run = ml_result.tools_success if hasattr(ml_result, "tools_success") else selected_tools
            except Exception as e:
                logger.warning(f"MLOrchestrator failed, falling back to direct execution: {e}")
                result.raw_findings = self._run_tools_parallel(selected_tools, contract_path)
                result.filtered_findings = self._filter_false_positives(result.raw_findings)
        else:
            # Fallback: direct adapter execution
            result.raw_findings = self._run_tools_parallel(selected_tools, contract_path)
            result.filtered_findings = self._filter_false_positives(result.raw_findings)

        # Severity distribution
        for f in result.filtered_findings:
            sev = f.get("severity", "unknown").lower()
            result.severity_distribution[sev] = result.severity_distribution.get(sev, 0) + 1

        result.duration_ms = (time.monotonic() - t0) * 1000
        logger.info(
            f"Scan complete: {len(result.tools_run)} tools, "
            f"{len(result.raw_findings)} raw -> {len(result.filtered_findings)} filtered"
        )
        return result

    def _get_ml_orchestrator(self):
        """Get MLOrchestrator instance (same as audit smart)."""
        try:
            from miesc.cli.utils import get_ml_orchestrator
            return get_ml_orchestrator()
        except Exception:
            try:
                from src.core.ml_orchestrator import MLOrchestrator
                return MLOrchestrator()
            except Exception:
                return None

    def _select_tools(self, recon: ReconResult) -> List[str]:
        """Adaptively select tools based on risk profile."""
        tools = ["slither", "aderyn"]
        profile = recon.risk_profile

        if profile.get("is_defi"):
            tools.extend(["defi", "mev_detector"])
        if profile.get("is_token"):
            tools.append("advanced_detector")
        if profile.get("is_proxy"):
            tools.append("upgradability_checker")
        if profile.get("is_bridge"):
            tools.extend(["crosschain", "bridge_monitor"])
        if profile.get("has_external_calls"):
            tools.append("mythril")
        if profile.get("has_selfdestruct"):
            tools.append("mythril")
        if profile.get("has_assembly"):
            tools.append("halmos")

        # Deduplicate preserving order
        seen: Set[str] = set()
        unique = []
        for t in tools:
            if t not in seen:
                seen.add(t)
                unique.append(t)
        return unique

    def _get_available_tools(self) -> List[str]:
        """Get list of actually available/installed tools."""
        try:
            from miesc.cli.utils import load_adapters
            adapters = load_adapters()
            available = []
            for name, adapter in adapters.items():
                try:
                    if hasattr(adapter, "is_available") and adapter.is_available():
                        available.append(name)
                    else:
                        available.append(name)
                except Exception:
                    pass
            return available
        except Exception:
            return ["slither", "aderyn"]

    def _run_tools_parallel(
        self, tools: List[str], contract_path: str
    ) -> List[Dict[str, Any]]:
        """Run multiple tools in parallel and collect findings."""
        all_findings: List[Dict[str, Any]] = []
        remaining = self._remaining_seconds() * 0.8

        try:
            from miesc.cli.utils import load_adapters
            adapters = load_adapters()
        except Exception as e:
            logger.warning(f"Could not load adapters: {e}")
            return []

        timeout_per_tool = max(30, remaining / max(len(tools), 1))

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {}
            for tool_name in tools:
                adapter = adapters.get(tool_name)
                if not adapter:
                    continue
                future = executor.submit(
                    self._run_single_tool, adapter, tool_name, contract_path, timeout_per_tool
                )
                futures[future] = tool_name

            for future in as_completed(futures, timeout=remaining):
                tool_name = futures[future]
                try:
                    findings = future.result(timeout=10)
                    for f in findings:
                        f["tool"] = tool_name
                    all_findings.extend(findings)
                except Exception as e:
                    logger.debug(f"Tool {tool_name} failed: {e}")

        return all_findings

    def _run_single_tool(
        self, adapter, tool_name: str, contract_path: str, timeout: float
    ) -> List[Dict[str, Any]]:
        """Run a single tool adapter and return normalized findings."""
        try:
            result = adapter.analyze(contract_path, timeout=int(timeout))
            findings = result.get("findings", []) if isinstance(result, dict) else []
            return findings if isinstance(findings, list) else []
        except Exception as e:
            logger.debug(f"{tool_name} error: {e}")
            return []

    def _filter_false_positives(self, findings: List[Dict]) -> List[Dict]:
        """Apply FP filter to findings."""
        try:
            from src.ml.fp_filter import FalsePositiveFilter
            fp = FalsePositiveFilter()
            source = Path(self.contract_path).read_text() if self.contract_path else ""
            result = fp.filter_findings(findings, source)
            return result.get("filtered", findings) if isinstance(result, dict) else findings
        except Exception:
            return findings

    # -----------------------------------------------------------------------
    # Phase 3: Deep Investigation (Agentic Loop)
    # -----------------------------------------------------------------------

    def _phase_deep_investigation(
        self,
        contract_path: str,
        source_code: str,
        recon: ReconResult,
        scan: ScanResult,
    ) -> Dict[str, Any]:
        investigated: Set[str] = set()
        enriched_findings: List[Dict[str, Any]] = []
        additional_tools: List[str] = set()
        mitigated_count = 0
        exploit_chains: List[Dict] = []

        # Start with HIGH/CRITICAL from initial scan
        queue = [
            f for f in scan.filtered_findings
            if f.get("severity", "").lower() in ("critical", "high")
        ]

        iteration = 0
        while queue and iteration < self.config.max_iterations and not self._timeout_exceeded():
            iteration += 1
            logger.info(f"Investigation iteration {iteration}: {len(queue)} findings to investigate")
            next_queue: List[Dict] = []

            for finding in queue:
                fid = finding.get("id", finding.get("title", str(hash(str(finding)))))
                if fid in investigated:
                    continue
                investigated.add(fid)

                enriched = dict(finding)
                enriched["investigation"] = {}

                # Step 1: RAG enrichment
                if self.config.enable_rag:
                    rag_data = self._enrich_with_rag(finding)
                    enriched["investigation"]["rag"] = rag_data
                    if rag_data.get("fix_pattern_present"):
                        if self._check_mitigation(source_code, rag_data):
                            enriched["mitigated"] = True
                            enriched["severity"] = "low"
                            mitigated_count += 1

                # Step 2: Taint analysis on affected function
                if self.config.enable_taint:
                    func = self._extract_function_name(finding)
                    if func:
                        taint = self._targeted_taint_for_function(source_code, func)
                        enriched["investigation"]["taint_paths"] = len(taint)

                # Step 3: Call graph attack paths
                if self.config.enable_call_graph and recon.call_graph:
                    func = self._extract_function_name(finding)
                    paths = self._find_attack_paths(recon.call_graph, func)
                    enriched["investigation"]["attack_paths"] = paths

                # Step 4: Check if we need additional tools
                extra_tool = self._should_trigger_tool(finding, scan.tools_run, additional_tools)
                if extra_tool:
                    logger.info(f"Triggering additional tool: {extra_tool}")
                    additional_tools.add(extra_tool)
                    new_findings = self._run_tools_parallel([extra_tool], contract_path)
                    high_new = [
                        f for f in new_findings
                        if f.get("severity", "").lower() in ("critical", "high")
                    ]
                    next_queue.extend(high_new)
                    scan.filtered_findings.extend(new_findings)

                enriched_findings.append(enriched)

            queue = next_queue

        # Exploit chain detection
        if self.config.enable_exploit_chains:
            exploit_chains = self._detect_exploit_chains(
                enriched_findings + [
                    f for f in scan.filtered_findings
                    if f.get("severity", "").lower() not in ("critical", "high")
                ]
            )

        return {
            "findings": enriched_findings + [
                f for f in scan.filtered_findings
                if f.get("id", f.get("title", "")) not in investigated
            ],
            "exploit_chains": exploit_chains,
            "iterations": iteration,
            "enriched_count": len(enriched_findings),
            "additional_tools": list(additional_tools),
            "mitigated_count": mitigated_count,
        }

    def _enrich_with_rag(self, finding: Dict) -> Dict[str, Any]:
        """Enrich a finding with RAG vulnerability knowledge."""
        try:
            from src.llm.embedding_rag import EmbeddingRAG
            rag = EmbeddingRAG()
            results = rag.search_by_finding(finding)
            if not results:
                return {"matched": False}

            top = results[0] if isinstance(results, list) else results
            doc = top if isinstance(top, dict) else getattr(top, "__dict__", {})
            return {
                "matched": True,
                "similar_vuln": doc.get("title", ""),
                "real_exploit": doc.get("real_exploit", ""),
                "fix_pattern": doc.get("fixed_code", ""),
                "fix_pattern_present": bool(doc.get("fixed_code")),
                "severity_match": doc.get("severity", "") == finding.get("severity", ""),
                "similarity": doc.get("similarity", 0.0),
            }
        except Exception as e:
            logger.debug(f"RAG enrichment failed: {e}")
            return {"matched": False, "error": str(e)}

    def _check_mitigation(self, source_code: str, rag_data: Dict) -> bool:
        """Check if the fix pattern from RAG is present in source code."""
        fix = rag_data.get("fix_pattern", "")
        if not fix:
            return False
        keywords = re.findall(r"\b\w{4,}\b", fix)
        matches = sum(1 for kw in keywords if kw.lower() in source_code.lower())
        return matches >= 2

    def _targeted_taint_for_function(self, source_code: str, func_name: str) -> list:
        """Run taint analysis targeting a specific function."""
        try:
            from src.ml.taint_analysis import TaintAnalyzer
            analyzer = TaintAnalyzer()
            results = analyzer.analyze(source_code)
            if isinstance(results, list):
                return [r for r in results if func_name in str(r)]
            return []
        except Exception:
            return []

    def _find_attack_paths(self, call_graph, func_name: str) -> List[str]:
        """Find attack paths from entry points to the vulnerable function."""
        if not call_graph or not func_name:
            return []
        try:
            if hasattr(call_graph, "paths_to_sink"):
                paths = call_graph.paths_to_sink(func_name)
                return [" -> ".join(str(n) for n in p[:5]) for p in paths[:3]]
        except Exception:
            pass
        return []

    def _extract_function_name(self, finding: Dict) -> Optional[str]:
        """Extract function name from finding location."""
        loc = finding.get("location", {})
        if isinstance(loc, dict):
            func = loc.get("function", "")
            if func and func != "unknown":
                return func
        loc_str = str(loc)
        m = re.search(r"function\s+(\w+)", loc_str)
        if m:
            return m.group(1)
        return None

    def _should_trigger_tool(
        self, finding: Dict, tools_run: List[str], already_triggered: Set[str]
    ) -> Optional[str]:
        """Decide if an additional tool should be triggered for this finding."""
        ftype = finding.get("type", "").lower()
        sev = finding.get("severity", "").lower()

        if sev not in ("critical", "high"):
            return None

        # Reentrancy without symbolic execution confirmation
        if "reentran" in ftype and "mythril" not in tools_run and "mythril" not in already_triggered:
            return "mythril"

        # Delegatecall without formal verification
        if "delegatecall" in ftype and "halmos" not in tools_run and "halmos" not in already_triggered:
            return "halmos"

        # Access control without fuzzing
        if "access" in ftype and "echidna" not in tools_run and "echidna" not in already_triggered:
            return "echidna"

        return None

    def _detect_exploit_chains(self, findings: List[Dict]) -> List[Dict]:
        """Detect exploit chains across findings."""
        try:
            from src.ml.correlation_engine import ExploitChainAnalyzer
            analyzer = ExploitChainAnalyzer()
            chains = analyzer.analyze(findings)
            if isinstance(chains, list):
                return [c.__dict__ if hasattr(c, "__dict__") else c for c in chains]
            return []
        except Exception as e:
            logger.debug(f"Exploit chain detection failed: {e}")
            return []

    # -----------------------------------------------------------------------
    # Phase 4: Synthesis
    # -----------------------------------------------------------------------

    def _phase_synthesis(
        self,
        contract_path: str,
        source_code: str,
        recon: ReconResult,
        scan: ScanResult,
        investigation: Dict[str, Any],
    ) -> Dict[str, Any]:
        findings = investigation.get("findings", scan.filtered_findings)
        chains = investigation.get("exploit_chains", [])

        # Correlation pass
        correlated = self._correlate_findings(findings)

        # Compute severity distribution
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in correlated:
            sev = f.get("severity", "unknown").upper()
            if sev in summary:
                summary[sev] += 1

        summary["total"] = sum(summary.values())
        summary["tools_used"] = scan.tools_run
        summary["iterations"] = investigation.get("iterations", 0)
        summary["exploit_chains"] = len(chains)
        summary["risk_profile"] = recon.risk_profile.get("primary", "general")
        summary["attack_surface"] = recon.attack_surface_score

        # LLM narrative (optional)
        narrative = ""
        has_llm = False
        if self.config.enable_llm and not self._timeout_exceeded():
            narrative = self._generate_narrative(correlated, summary, chains)
            has_llm = bool(narrative)

        if not narrative:
            narrative = self._template_narrative(summary, chains)

        return {
            "findings": correlated,
            "exploit_chains": chains,
            "summary": summary,
            "narrative": narrative,
            "has_llm_narrative": has_llm,
        }

    def _correlate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Correlate and deduplicate findings."""
        try:
            from src.ml.correlation_engine import correlate_findings
            result = correlate_findings(findings)
            if isinstance(result, dict):
                return result.get("findings", findings)
            return findings
        except Exception:
            return findings

    def _generate_narrative(
        self, findings: List[Dict], summary: Dict, chains: List[Dict]
    ) -> str:
        """Generate LLM narrative using available provider (local-first).

        Priority: Ollama (local) -> Anthropic Claude -> OpenAI -> template.
        """
        provider = self.config.llm_provider

        # Try LLMOrchestrator (supports Ollama, Anthropic, OpenAI with fallback)
        if provider == "auto" or provider in ("anthropic", "openai"):
            narrative = self._try_llm_orchestrator(findings, summary, chains)
            if narrative:
                return narrative

        # Try Ollama directly (local-first default)
        if provider in ("auto", "ollama"):
            narrative = self._try_ollama_interpreter(findings, summary)
            if narrative:
                return narrative

        return ""

    def _try_llm_orchestrator(
        self, findings: List[Dict], summary: Dict, chains: List[Dict]
    ) -> str:
        """Try LLMOrchestrator with multi-provider fallback."""
        try:
            import asyncio
            import os
            from src.llm.llm_orchestrator import (
                AnthropicBackend, LLMConfig, LLMOrchestrator, LLMProvider,
                OllamaBackend, OpenAIBackend,
            )

            configs = []
            provider = self.config.llm_provider

            # Local-first: always add Ollama
            if provider in ("auto", "ollama"):
                configs.append(LLMConfig(
                    provider=LLMProvider.OLLAMA,
                    model=self.config.llm_model,
                    base_url="http://localhost:11434",
                ))

            # Anthropic Claude (optional, if API key available)
            if provider in ("auto", "anthropic") and os.getenv("ANTHROPIC_API_KEY"):
                configs.append(LLMConfig(
                    provider=LLMProvider.ANTHROPIC,
                    model="claude-sonnet-4-20250514",
                    api_key=os.getenv("ANTHROPIC_API_KEY"),
                ))

            # OpenAI (optional, if API key available)
            if provider in ("auto", "openai") and os.getenv("OPENAI_API_KEY"):
                configs.append(LLMConfig(
                    provider=LLMProvider.OPENAI,
                    model="gpt-4o",
                    api_key=os.getenv("OPENAI_API_KEY"),
                ))

            if not configs:
                return ""

            orch = LLMOrchestrator(configs=configs)

            # Build prompt
            contract_name = Path(self.contract_path).stem if self.contract_path else "Contract"
            critical = summary.get("CRITICAL", 0)
            high = summary.get("HIGH", 0)
            total = summary.get("total", 0)
            chain_count = len(chains)

            top_findings = "\n".join(
                f"- [{f.get('severity', '?').upper()}] {f.get('title', f.get('type', '?'))}: {f.get('description', '')[:100]}"
                for f in findings[:8]
            )

            prompt = f"""Analyze this smart contract security audit for {contract_name} and write a 200-word executive summary.

Findings: {total} total ({critical} critical, {high} high)
Exploit chains detected: {chain_count}

Top findings:
{top_findings}

Focus on: business risk, deployment recommendation (GO/NO-GO/CONDITIONAL), and top 3 remediation priorities.
Write for a non-technical executive audience."""

            async def run():
                await orch.initialize()
                response = await orch.analyze(prompt)
                return response.content if response else ""

            result = asyncio.run(run())
            if result:
                logger.info(f"LLM narrative generated via LLMOrchestrator")
            return result
        except Exception as e:
            logger.debug(f"LLMOrchestrator narrative failed: {e}")
            return ""

    def _try_ollama_interpreter(self, findings: List[Dict], summary: Dict) -> str:
        """Try Ollama via LLMReportInterpreter (existing module)."""
        try:
            from src.reports.llm_interpreter import LLMReportInterpreter
            interp = LLMReportInterpreter()
            if not interp.is_available():
                return ""
            result = interp.generate_executive_interpretation(
                findings=findings,
                summary=summary,
                contract_name=Path(self.contract_path).stem if self.contract_path else "Contract",
            )
            return result if isinstance(result, str) else ""
        except Exception as e:
            logger.debug(f"Ollama interpreter failed: {e}")
            return ""

    def _template_narrative(self, summary: Dict, chains: List[Dict]) -> str:
        """Generate template-based narrative without LLM."""
        total = summary.get("total", 0)
        critical = summary.get("CRITICAL", 0)
        high = summary.get("HIGH", 0)
        chain_count = len(chains)

        if critical > 0:
            risk = "CRITICAL"
            action = "Immediate remediation required before deployment."
        elif high > 0:
            risk = "HIGH"
            action = "Address high-severity findings before mainnet deployment."
        elif total > 0:
            risk = "MEDIUM"
            action = "Review findings and apply recommended fixes."
        else:
            risk = "LOW"
            action = "No significant security issues detected."

        parts = [
            f"The deep agentic audit analyzed the contract across {len(summary.get('tools_used', []))} "
            f"tools in {summary.get('iterations', 0)} investigation iterations.",
            f"\n\nOverall risk level: {risk}. {total} findings detected "
            f"({critical} critical, {high} high).",
        ]
        if chain_count:
            parts.append(
                f"\n\n{chain_count} exploit chain(s) detected, indicating "
                f"vulnerabilities that can be combined for cascading attacks."
            )
        parts.append(f"\n\nRecommendation: {action}")
        return "".join(parts)

    # -----------------------------------------------------------------------
    # Timeout management
    # -----------------------------------------------------------------------

    def _timeout_exceeded(self) -> bool:
        return (time.monotonic() - self._start_time) > self.config.timeout_seconds

    def _remaining_seconds(self) -> float:
        return max(0, self.config.timeout_seconds - (time.monotonic() - self._start_time))


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def run_deep_audit(contract_path: str, **kwargs) -> Dict[str, Any]:
    """Run a deep agentic audit on a contract.

    Args:
        contract_path: Path to Solidity contract file.
        **kwargs: Override DeepAuditConfig fields.

    Returns:
        Dict with findings, exploit chains, summary, and narrative.
    """
    config = DeepAuditConfig(**{
        k: v for k, v in kwargs.items()
        if k in DeepAuditConfig.__dataclass_fields__
    })
    agent = DeepAuditAgent(config=config)
    return agent.analyze(contract_path)
