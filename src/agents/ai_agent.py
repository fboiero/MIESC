"""
AI Agent for MCP Architecture

Wraps Layer 6 (Cognitive Intelligence): GPTLens AI Triage
Consumes findings from other agents and performs intelligent triage
"""
import json
import logging
from typing import Dict, Any, List, Optional

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    openai = None  # type: ignore
    OPENAI_AVAILABLE = False
from pathlib import Path
from src.agents.base_agent import BaseAgent
from src.mcp.context_bus import MCPMessage

logger = logging.getLogger(__name__)


class AIAgent(BaseAgent):
    """
    Agent for AI-assisted analysis and triage (Layer 6 - MIESC)

    Capabilities:
    - Context-aware vulnerability triage
    - False positive reduction
    - Root cause analysis
    - Cross-layer correlation
    - Remediation recommendations

    Subscribes to:
    - "static_findings": From StaticAgent
    - "dynamic_findings": From DynamicAgent
    - "formal_findings": From FormalAgent
    - "symbolic_findings": From SymbolicAgent

    Published Context Types:
    - "ai_triage": Triaged and prioritized findings
    - "false_positives": Identified false positives
    - "root_cause_analysis": Deep analysis of critical issues
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        super().__init__(
            agent_name="AIAgent",
            capabilities=[
                "ai_triage",
                "false_positive_detection",
                "root_cause_analysis",
                "cross_layer_correlation",
                "remediation_generation",
                "exploitability_assessment",
                "chain_of_thought_reasoning"
            ],
            agent_type="ai"
        )

        self.model = model  # Updated to GPT-4o for superior reasoning
        self.api_key = api_key
        if api_key and OPENAI_AVAILABLE:
            openai.api_key = api_key

        # Advanced triage configuration
        self.use_chain_of_thought = True  # Enable CoT reasoning for complex analysis

        # Subscribe to findings from other agents
        self.subscribe_to(
            context_types=[
                "static_findings",
                "dynamic_findings",
                "formal_findings",
                "symbolic_findings"
            ],
            callback=self._handle_findings
        )

    def get_context_types(self) -> List[str]:
        return [
            "ai_triage",
            "false_positives",
            "root_cause_analysis"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Perform AI-assisted triage on aggregated findings

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional parameters
                - aggregated_findings: Pre-aggregated findings from multiple agents
                - contract_source: Source code for context

        Returns:
            Dictionary with triage results
        """
        results = {
            "ai_triage": [],
            "false_positives": [],
            "root_cause_analysis": []
        }

        # Aggregate findings from all layers
        aggregated = kwargs.get("aggregated_findings")
        if not aggregated:
            aggregated = self._aggregate_all_findings()

        if not aggregated:
            logger.warning("AIAgent: No findings to triage")
            return results

        # Read contract source for context
        contract_source = kwargs.get("contract_source")
        if not contract_source:
            try:
                with open(contract_path, 'r') as f:
                    contract_source = f.read()
            except Exception as e:
                logger.error(f"AIAgent: Could not read contract source: {e}")
                contract_source = ""

        # Perform triage
        logger.info(f"AIAgent: Triaging {len(aggregated)} findings")
        triage_results = self._triage_findings(aggregated, contract_source)
        results["ai_triage"] = triage_results["triaged"]
        results["false_positives"] = triage_results["false_positives"]

        # Perform root cause analysis on critical issues
        critical_findings = [
            f for f in triage_results["triaged"]
            if f.get("severity") in ["Critical", "High"]
        ]

        if critical_findings:
            logger.info(f"AIAgent: Analyzing {len(critical_findings)} critical issues")
            for finding in critical_findings[:3]:  # Analyze top 3 critical
                rca = self._root_cause_analysis(finding, contract_source)
                results["root_cause_analysis"].append(rca)

        return results

    def _handle_findings(self, message: MCPMessage) -> None:
        """
        Callback to handle incoming findings from other agents

        Args:
            message: MCP message with findings
        """
        logger.info(f"AIAgent: Received {message.context_type} from {message.agent}")
        # Findings are stored in Context Bus, will be aggregated when analyze() is called

    def _aggregate_all_findings(self) -> List[Dict[str, Any]]:
        """
        Aggregate findings from all subscribed context types

        Returns:
            List of all findings from Context Bus
        """
        context_types = [
            "static_findings",
            "dynamic_findings",
            "formal_findings",
            "symbolic_findings"
        ]

        aggregated_contexts = self.aggregate_contexts(context_types)
        all_findings = []

        for context_type, messages in aggregated_contexts.items():
            for message in messages:
                if isinstance(message.data, list):
                    all_findings.extend(message.data)
                elif isinstance(message.data, dict) and "findings" in message.data:
                    all_findings.extend(message.data["findings"])

        return all_findings

    def _triage_findings(self, findings: List[Dict[str, Any]],
                        contract_source: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Triage findings using AI (GPT-4)

        Args:
            findings: List of findings from all tools
            contract_source: Contract source code for context

        Returns:
            Dictionary with "triaged" and "false_positives" lists
        """
        if not OPENAI_AVAILABLE:
            logger.warning("AIAgent: openai package not installed, skipping AI triage")
            return {"triaged": findings, "false_positives": []}
        if not self.api_key:
            logger.warning("AIAgent: No API key, skipping AI triage")
            return {"triaged": findings, "false_positives": []}

        try:
            # Build prompt with findings and contract context
            prompt = self._build_triage_prompt(findings, contract_source)

            # Call GPT-4 for triage
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert smart contract security auditor. "
                            "Your task is to triage vulnerability findings, identify false positives, "
                            "and prioritize real issues based on severity and exploitability. "
                            "Respond in JSON format."
                        )
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=4000
            )

            # Parse response
            triage_result = json.loads(response.choices[0].message.content)

            return {
                "triaged": triage_result.get("real_vulnerabilities", []),
                "false_positives": triage_result.get("false_positives", [])
            }

        except json.JSONDecodeError as e:
            logger.error(f"AIAgent: Failed to parse triage response: {e}")
            return {"triaged": findings, "false_positives": []}
        except Exception as e:
            logger.error(f"AIAgent: Triage error: {e}")
            return {"triaged": findings, "false_positives": []}

    def _build_triage_prompt(self, findings: List[Dict[str, Any]],
                            contract_source: str) -> str:
        """
        Build prompt for AI triage

        Args:
            findings: List of findings
            contract_source: Contract source code

        Returns:
            Prompt string
        """
        # Truncate contract source if too long
        max_source_len = 3000
        if len(contract_source) > max_source_len:
            contract_source = contract_source[:max_source_len] + "\n... (truncated)"

        chain_of_thought_instruction = ""
        if self.use_chain_of_thought:
            chain_of_thought_instruction = """
Before classifying each finding, reason through it step-by-step:
- Step 1: Understand what the tool detected
- Step 2: Analyze the contract context around this finding
- Step 3: Consider if there are mitigating factors or protections
- Step 4: Assess real-world exploitability
- Step 5: Determine final classification and severity

Include your reasoning in the "reasoning" field for each finding.
"""

        prompt = f"""
You are an expert smart contract security auditor performing advanced triage on vulnerability findings.

Contract Source Code:
```solidity
{contract_source}
```

Findings to triage ({len(findings)} total):
{json.dumps(findings, indent=2)}

{chain_of_thought_instruction}

For each finding, determine:
1. Is it a real vulnerability or false positive?
2. What is the actual severity (Critical/High/Medium/Low/Info)?
3. Is it exploitable in practice? Provide exploitability score (0.0-1.0)
4. What is the root cause?
5. Recommended remediation with concrete code examples
6. Historical context: Does this match known vulnerability patterns?

Respond in this JSON format:
{{
  "real_vulnerabilities": [
    {{
      "id": "finding_id",
      "original_severity": "High",
      "adjusted_severity": "Critical",
      "is_exploitable": true,
      "exploitability_score": 0.9,
      "confidence": "High",
      "reasoning": "step-by-step reasoning here",
      "justification": "...",
      "root_cause": "...",
      "remediation": "...",
      "code_fix_example": "// Fixed code here",
      "source": "tool_name",
      "location": {{"file": "...", "line": 0, "function": "..."}},
      "swc_id": "SWC-107|SWC-105|SWC-106|etc",
      "owasp_category": "SC01-Reentrancy|SC02-Access-Control|etc",
      "cwe_id": "CWE-862|CWE-287|CWE-691|etc",
      "historical_reference": "The DAO 2016|Parity Wallet|Poly Network|None"
    }}
  ],
  "false_positives": [
    {{
      "id": "finding_id",
      "reason": "...",
      "reasoning": "step-by-step reasoning why this is a false positive",
      "source": "tool_name",
      "confidence": 0.0-1.0
    }}
  ],
  "triage_summary": {{
    "total_analyzed": 0,
    "real_vulnerabilities": 0,
    "false_positives": 0,
    "reduction_rate": "0%"
  }}
}}
"""
        return prompt

    def _root_cause_analysis(self, finding: Dict[str, Any],
                            contract_source: str) -> Dict[str, Any]:
        """
        Perform deep root cause analysis on critical finding

        Args:
            finding: Vulnerability finding
            contract_source: Contract source code

        Returns:
            Dictionary with root cause analysis
        """
        if not OPENAI_AVAILABLE or not self.api_key:
            return {
                "finding_id": finding.get("id"),
                "root_cause": "AI analysis not available (openai not installed or no API key)",
                "attack_scenario": "",
                "remediation_steps": []
            }

        try:
            prompt = f"""
Perform a deep root cause analysis for this critical smart contract vulnerability:

Finding:
{json.dumps(finding, indent=2)}

Contract Source:
```solidity
{contract_source[:2000]}
```

Provide:
1. Root cause explanation
2. Detailed attack scenario with step-by-step exploitation
3. Impact assessment (financial, operational, reputational)
4. Concrete remediation steps with code examples
5. References to similar vulnerabilities (CVE, exploit examples)

Respond in JSON format:
{{
  "finding_id": "...",
  "root_cause": "...",
  "attack_scenario": "...",
  "impact_assessment": {{"financial": "...", "operational": "...", "reputational": "..."}},
  "remediation_steps": ["...", "..."],
  "code_example": "...",
  "references": ["..."]
}}
"""

            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a smart contract security expert performing root cause analysis."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )

            return json.loads(response.choices[0].message.content)

        except Exception as e:
            logger.error(f"AIAgent: Root cause analysis error: {e}")
            return {
                "finding_id": finding.get("id"),
                "root_cause": f"Analysis failed: {str(e)}",
                "attack_scenario": "",
                "remediation_steps": []
            }

    def cross_layer_correlation(self, finding_id: str) -> Dict[str, Any]:
        """
        Correlate a finding across multiple detection layers

        Args:
            finding_id: ID of finding to correlate

        Returns:
            Dictionary with correlated findings from different layers
        """
        all_contexts = self.aggregate_contexts([
            "static_findings",
            "dynamic_findings",
            "symbolic_findings",
            "formal_findings"
        ])

        correlated = {
            "finding_id": finding_id,
            "detected_by": [],
            "consistency_score": 0.0,
            "cross_layer_confidence": "Unknown"
        }

        # Search for same vulnerability across layers
        for context_type, messages in all_contexts.items():
            for message in messages:
                findings = message.data if isinstance(message.data, list) else []
                for f in findings:
                    if f.get("id") == finding_id or f.get("swc_id") == finding_id:
                        correlated["detected_by"].append({
                            "layer": context_type.replace("_findings", ""),
                            "agent": message.agent,
                            "severity": f.get("severity"),
                            "confidence": f.get("confidence")
                        })

        # Calculate consistency score
        num_detections = len(correlated["detected_by"])
        if num_detections >= 3:
            correlated["consistency_score"] = 1.0
            correlated["cross_layer_confidence"] = "High"
        elif num_detections == 2:
            correlated["consistency_score"] = 0.7
            correlated["cross_layer_confidence"] = "Medium"
        elif num_detections == 1:
            correlated["consistency_score"] = 0.4
            correlated["cross_layer_confidence"] = "Low"

        return correlated
