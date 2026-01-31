"""
Audit Consensus Adapter - Bayesian Meta-Analyzer.

Aggregates findings from Layer 5 (AI), Layer 6 (ML), and Layer 9 tools
using Bayesian scoring with prior probabilities per tool.

Computes posterior confidence for each finding based on:
- Number of tools confirming
- Individual tool reliability weights
- Vulnerability type base rates
- Cross-layer agreement boost

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2026-01-31
License: AGPL-3.0
"""

import hashlib
import logging
import math
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from src.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

logger = logging.getLogger(__name__)


# Tool reliability weights (precision scores from benchmarks)
TOOL_WEIGHTS = {
    # Layer 9 - Highest reliability (verified findings)
    "exploit_synthesizer": 0.95,
    "vuln_verifier": 0.92,
    "remediation_validator": 0.88,
    "audit_consensus": 0.90,
    # Layer 5 - AI Analysis
    "smartllm": 0.80,
    "gptscan": 0.75,
    "llmsmartaudit": 0.73,
    "gptlens": 0.82,
    "llamaaudit": 0.70,
    "iaudit": 0.78,
    # Layer 6 - ML Detection
    "dagnn": 0.72,
    "smartbugs_ml": 0.68,
    "smartbugs_detector": 0.65,
    "smartguard": 0.70,
    "peculiar": 0.74,
    # Layer 9 - Ensemble
    "llmbugscanner": 0.83,
    # Other layers (for cross-layer validation)
    "slither": 0.85,
    "mythril": 0.78,
    "echidna": 0.88,
    "certora": 0.92,
    "smtchecker": 0.85,
    "solcmc": 0.85,
}

# Base rates for vulnerability types (prior probability)
VULN_BASE_RATES = {
    "reentrancy": 0.15,
    "access_control": 0.20,
    "integer_overflow": 0.10,
    "unchecked_return": 0.25,
    "front_running": 0.12,
    "oracle_manipulation": 0.08,
    "flash_loan": 0.06,
    "timestamp_dependence": 0.30,
    "tx_origin": 0.05,
    "delegatecall": 0.07,
    "logic_error": 0.18,
    "denial_of_service": 0.15,
    "default": 0.15,
}


class AuditConsensusAdapter(ToolAdapter):
    """
    Bayesian meta-analyzer for cross-tool consensus scoring.

    Aggregates findings from multiple tools using Bayesian inference
    to compute posterior confidence scores.
    """

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="audit_consensus",
            version="1.0.0",
            category=ToolCategory.ADVANCED_AI_ENSEMBLE,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://github.com/fboiero/MIESC#consensus",
            installation_cmd="pip install miesc",
            capabilities=[
                ToolCapability(
                    name="bayesian_consensus",
                    description="Bayesian meta-analysis across AI, ML, and ensemble tools",
                    supported_languages=["solidity"],
                    detection_types=[
                        "consensus_finding",
                        "cross_layer_validation",
                        "bayesian_scoring",
                    ],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        return ToolStatus.AVAILABLE

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()
        findings_map = kwargs.get("findings_map", {})

        if not findings_map:
            return {
                "tool": "audit_consensus",
                "version": "1.0.0",
                "status": "success",
                "findings": [],
                "metadata": {"reason": "no findings_map provided"},
                "execution_time": time.time() - start_time,
                "error": None,
            }

        # Group findings by vulnerability type and location
        grouped = self._group_findings(findings_map)

        # Apply Bayesian scoring
        consensus_findings = []
        for key, group in grouped.items():
            consensus = self._compute_consensus(group)
            if consensus["posterior_confidence"] >= 0.30:
                consensus_findings.append(consensus)

        # Sort by posterior confidence
        consensus_findings.sort(key=lambda x: x["posterior_confidence"], reverse=True)

        findings = self.normalize_findings(consensus_findings)

        return {
            "tool": "audit_consensus",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {
                "contract": contract_path,
                "tools_analyzed": list(findings_map.keys()),
                "total_input_findings": sum(len(v) for v in findings_map.values()),
                "consensus_findings": len(findings),
            },
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def _group_findings(self, findings_map: Dict[str, List]) -> Dict[str, Dict]:
        """Group findings by vulnerability type and approximate location."""
        groups = defaultdict(lambda: {"findings": [], "tools": set(), "tool_findings": {}})

        for tool_name, tool_findings in findings_map.items():
            if not isinstance(tool_findings, list):
                continue
            for finding in tool_findings:
                if not isinstance(finding, dict):
                    continue

                vuln_type = self._normalize_vuln_type(
                    finding.get("type", finding.get("check", "unknown"))
                )
                file_path = finding.get("location", {}).get("file", "")
                line = finding.get("location", {}).get("line", 0)

                # Group by type + file + approximate line (bucket of 10)
                line_bucket = (line // 10) * 10
                key = f"{vuln_type}:{file_path}:{line_bucket}"

                groups[key]["findings"].append(finding)
                groups[key]["tools"].add(tool_name)
                groups[key]["tool_findings"][tool_name] = finding
                groups[key]["vuln_type"] = vuln_type
                groups[key]["file"] = file_path
                groups[key]["line"] = line

        return dict(groups)

    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type names across tools."""
        vuln_lower = vuln_type.lower().replace("-", "_").replace(" ", "_")

        type_mapping = {
            "reentrancy_eth": "reentrancy",
            "reentrancy_no_eth": "reentrancy",
            "reentrancy_benign": "reentrancy",
            "re_entrancy": "reentrancy",
            "access_control": "access_control",
            "unprotected_function": "access_control",
            "integer_overflow": "integer_overflow",
            "integer_underflow": "integer_overflow",
            "overflow": "integer_overflow",
            "underflow": "integer_overflow",
            "unchecked_return": "unchecked_return",
            "unchecked_call": "unchecked_return",
            "unchecked_transfer": "unchecked_return",
            "front_running": "front_running",
            "frontrunning": "front_running",
            "mev": "front_running",
            "oracle_manipulation": "oracle_manipulation",
            "price_manipulation": "oracle_manipulation",
            "flash_loan": "flash_loan",
            "flashloan": "flash_loan",
            "timestamp": "timestamp_dependence",
            "block_timestamp": "timestamp_dependence",
            "tx_origin": "tx_origin",
            "delegatecall": "delegatecall",
            "controlled_delegatecall": "delegatecall",
        }

        for key, normalized in type_mapping.items():
            if key in vuln_lower:
                return normalized

        return vuln_lower

    def _compute_consensus(self, group: Dict) -> Dict[str, Any]:
        """Compute Bayesian consensus for a group of findings."""
        tools = group["tools"]
        vuln_type = group.get("vuln_type", "default")

        # Prior probability
        prior = VULN_BASE_RATES.get(vuln_type, VULN_BASE_RATES["default"])

        # Compute likelihood ratio using tool weights
        log_lr = 0.0
        for tool in tools:
            weight = TOOL_WEIGHTS.get(tool, 0.60)
            # Likelihood ratio: P(tool reports | TP) / P(tool reports | FP)
            # Approximation: weight / (1 - weight)
            if weight < 1.0:
                lr = weight / (1.0 - weight)
                log_lr += math.log(lr)

        # Cross-layer bonus
        layers = self._get_tool_layers(tools)
        if len(layers) >= 2:
            log_lr += 0.5  # Inter-layer agreement boost
        if len(layers) >= 3:
            log_lr += 0.3  # Strong inter-layer agreement

        # Posterior using log-odds form
        log_prior_odds = math.log(prior / (1.0 - prior)) if 0 < prior < 1 else 0
        log_posterior_odds = log_prior_odds + log_lr
        posterior = 1.0 / (1.0 + math.exp(-log_posterior_odds))

        # Cap at 0.98
        posterior = min(posterior, 0.98)

        # Select best finding for reporting
        best_finding = self._select_best_finding(group)

        return {
            "vuln_type": vuln_type,
            "posterior_confidence": round(posterior, 4),
            "prior": prior,
            "confirming_tools": list(tools),
            "tool_count": len(tools),
            "layers": list(layers),
            "layer_count": len(layers),
            "best_finding": best_finding,
            "file": group.get("file", ""),
            "line": group.get("line", 0),
        }

    def _get_tool_layers(self, tools: set) -> set:
        """Map tools to their layer numbers."""
        tool_layer_map = {
            "smartllm": 5, "gptscan": 5, "llmsmartaudit": 5,
            "gptlens": 5, "llamaaudit": 5, "iaudit": 5,
            "dagnn": 6, "smartbugs_ml": 6, "smartbugs_detector": 6,
            "smartguard": 6, "peculiar": 6,
            "llmbugscanner": 9, "exploit_synthesizer": 9,
            "vuln_verifier": 9, "remediation_validator": 9,
            "slither": 1, "aderyn": 1,
            "mythril": 3, "manticore": 3,
            "certora": 4, "smtchecker": 4,
        }
        return {tool_layer_map.get(t, 0) for t in tools if tool_layer_map.get(t, 0) > 0}

    def _select_best_finding(self, group: Dict) -> Dict:
        """Select the finding with highest original confidence."""
        best = None
        best_conf = -1

        for finding in group["findings"]:
            conf = finding.get("confidence", 0)
            if isinstance(conf, str):
                conf_map = {"critical": 0.95, "high": 0.85, "medium": 0.70, "low": 0.50}
                conf = conf_map.get(conf.lower(), 0.50)
            if conf > best_conf:
                best_conf = conf
                best = finding

        return best or group["findings"][0]

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        if not raw_output:
            return []

        findings = []
        for item in raw_output:
            if not isinstance(item, dict):
                continue

            best = item.get("best_finding", {})
            finding_id = hashlib.md5(
                f"consensus:{item.get('vuln_type', '')}:{item.get('file', '')}:{item.get('line', 0)}".encode()
            ).hexdigest()[:12]

            severity = best.get("severity", "Medium")
            tools_str = ", ".join(item.get("confirming_tools", []))

            findings.append({
                "id": f"CON-{finding_id}",
                "type": f"consensus_{item.get('vuln_type', 'unknown')}",
                "severity": severity,
                "confidence": item["posterior_confidence"],
                "location": {
                    "file": item.get("file", best.get("location", {}).get("file", "")),
                    "line": item.get("line", best.get("location", {}).get("line", 0)),
                    "function": best.get("location", {}).get("function", ""),
                },
                "message": (
                    f"Consensus finding ({item['tool_count']} tools, "
                    f"{item['layer_count']} layers): {best.get('message', best.get('description', ''))}"
                ),
                "description": (
                    f"Bayesian consensus (posterior={item['posterior_confidence']:.2f}) "
                    f"confirmed by: {tools_str}"
                ),
                "recommendation": best.get("recommendation", "Review finding confirmed by multiple tools"),
                "swc_id": best.get("swc_id"),
                "cwe_id": best.get("cwe_id"),
                "tool": "audit_consensus",
            })

        return findings
