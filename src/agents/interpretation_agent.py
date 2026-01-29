"""
Interpretation Agent for MCP Architecture

Advanced LLM-based agent that intelligently interprets outputs from security tools
Provides context-aware analysis, semantic understanding, and cross-tool correlation
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
from datetime import datetime
from src.agents.base_agent import BaseAgent
from src.mcp.context_bus import MCPMessage

logger = logging.getLogger(__name__)


class InterpretationAgent(BaseAgent):
    """
    Interpretation Agent (Advanced Output Analysis)

    Capabilities:
    - Semantic understanding of tool outputs
    - Context-aware interpretation
    - Cross-tool correlation and validation
    - Confidence scoring for findings
    - Duplicate detection across tools
    - Severity normalization
    - Vulnerability pattern recognition

    Subscribes to:
    - All *_findings context types from detection agents

    Published Context Types:
    - "interpreted_findings": Enhanced findings with context
    - "correlation_analysis": Cross-tool correlation results
    - "confidence_scores": Confidence metrics for each finding
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        super().__init__(
            agent_name="InterpretationAgent",
            capabilities=[
                "semantic_understanding",
                "context_aware_interpretation",
                "cross_tool_correlation",
                "confidence_scoring",
                "duplicate_detection",
                "severity_normalization",
                "pattern_recognition"
            ],
            agent_type="interpretation"
        )

        self.model = model  # GPT-4o for better reasoning
        self.api_key = api_key
        if api_key and OPENAI_AVAILABLE:
            openai.api_key = api_key

        # Knowledge base for vulnerability patterns
        self.vulnerability_patterns = self._load_vulnerability_patterns()

        # Subscribe to all detection agent outputs
        self.subscribe_to(
            context_types=[
                "static_findings",
                "dynamic_findings",
                "symbolic_findings",
                "formal_findings",
                "runtime_findings"
            ],
            callback=self._handle_findings
        )

    def get_context_types(self) -> List[str]:
        return [
            "interpreted_findings",
            "correlation_analysis",
            "confidence_scores"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Interpret and enhance findings from all detection agents

        Args:
            contract_path: Path to analyzed contract
            **kwargs: Optional parameters
                - raw_findings: Pre-collected findings
                - contract_source: Source code for context
                - enable_deep_analysis: Enable deep interpretation (slower)

        Returns:
            Dictionary with interpreted findings and analysis
        """
        results = {
            "interpreted_findings": [],
            "correlation_analysis": {},
            "confidence_scores": {},
            "duplicate_groups": [],
            "normalized_severity": {}
        }

        # Collect raw findings
        raw_findings = kwargs.get("raw_findings")
        if not raw_findings:
            raw_findings = self._collect_all_findings()

        if not raw_findings:
            logger.warning("InterpretationAgent: No findings to interpret")
            return results

        logger.info(f"InterpretationAgent: Interpreting {len(raw_findings)} raw findings")

        # Read contract source for context
        contract_source = kwargs.get("contract_source")
        if not contract_source:
            try:
                with open(contract_path, 'r') as f:
                    contract_source = f.read()
            except Exception as e:
                logger.error(f"InterpretationAgent: Could not read contract: {e}")
                contract_source = ""

        # Phase 1: Semantic interpretation of each finding
        interpreted = self._interpret_findings(raw_findings, contract_source)
        results["interpreted_findings"] = interpreted

        # Phase 2: Cross-tool correlation
        correlation = self._correlate_findings(interpreted)
        results["correlation_analysis"] = correlation

        # Phase 3: Duplicate detection
        duplicates = self._detect_duplicates(interpreted)
        results["duplicate_groups"] = duplicates

        # Phase 4: Confidence scoring
        confidence_scores = self._calculate_confidence_scores(
            interpreted,
            correlation
        )
        results["confidence_scores"] = confidence_scores

        # Phase 5: Severity normalization
        normalized = self._normalize_severity(interpreted, confidence_scores)
        results["normalized_severity"] = normalized

        # Publish interpreted results
        self.publish_findings("interpreted_findings", interpreted)
        self.publish_findings("correlation_analysis", correlation)
        self.publish_findings("confidence_scores", confidence_scores)

        return results

    def _handle_findings(self, message: MCPMessage) -> None:
        """Handle incoming findings from detection agents"""
        logger.info(
            f"InterpretationAgent: Received {message.context_type} "
            f"from {message.agent}"
        )

    def _collect_all_findings(self) -> List[Dict[str, Any]]:
        """Collect findings from all subscribed context types"""
        context_types = [
            "static_findings",
            "dynamic_findings",
            "symbolic_findings",
            "formal_findings",
            "runtime_findings"
        ]

        all_contexts = self.aggregate_contexts(context_types)
        all_findings = []

        for context_type, messages in all_contexts.items():
            for message in messages:
                findings = message.data if isinstance(message.data, list) else []
                for finding in findings:
                    # Add metadata about source
                    finding["source_context"] = context_type
                    finding["source_agent"] = message.agent
                    finding["detection_timestamp"] = message.timestamp
                    all_findings.append(finding)

        return all_findings

    def _interpret_findings(self, findings: List[Dict[str, Any]],
                           contract_source: str) -> List[Dict[str, Any]]:
        """
        Perform semantic interpretation of findings using LLM

        Args:
            findings: Raw findings from tools
            contract_source: Contract source code

        Returns:
            List of interpreted findings with enhanced context
        """
        if not OPENAI_AVAILABLE or not self.api_key:
            logger.warning("InterpretationAgent: openai not available or no API key, returning raw findings")
            return findings

        interpreted_findings = []

        # Batch process findings for efficiency
        batch_size = 5
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]

            try:
                batch_interpreted = self._interpret_batch(batch, contract_source)
                interpreted_findings.extend(batch_interpreted)
            except Exception as e:
                logger.error(f"InterpretationAgent: Batch interpretation failed: {e}")
                # Fall back to raw findings for this batch
                interpreted_findings.extend(batch)

        return interpreted_findings

    def _interpret_batch(self, findings: List[Dict[str, Any]],
                        contract_source: str) -> List[Dict[str, Any]]:
        """Interpret a batch of findings using GPT-4o"""

        # Truncate source if too long
        max_source_len = 2000
        if len(contract_source) > max_source_len:
            contract_source = contract_source[:max_source_len] + "\n... (truncated)"

        prompt = f"""
You are an expert smart contract security analyst interpreting vulnerability findings from security tools.

Contract Source:
```solidity
{contract_source}
```

Raw Findings ({len(findings)} items):
{json.dumps(findings, indent=2)}

For each finding, provide:
1. **Semantic Understanding**: What is the actual vulnerability in plain language?
2. **Exploitability**: How easily can this be exploited? (None/Low/Medium/High/Critical)
3. **Business Impact**: What is the real-world impact? (funds loss, DoS, data leak, etc.)
4. **Context Analysis**: Does the contract context affect this vulnerability?
5. **Attack Scenario**: Brief step-by-step attack scenario if exploitable
6. **Confidence**: How confident are you in this interpretation? (0.0-1.0)
7. **Pattern Match**: Does this match known vulnerability patterns? (e.g., "DAO Reentrancy 2016")

Respond in JSON format:
{{
  "interpreted_findings": [
    {{
      "original_finding_id": "...",
      "semantic_description": "...",
      "exploitability": "High|Medium|Low|None",
      "exploitability_score": 0.0-1.0,
      "business_impact": "...",
      "business_impact_category": "funds_loss|dos|data_leak|access_control|other",
      "context_affects_severity": true|false,
      "context_explanation": "...",
      "attack_scenario": ["step 1", "step 2", "..."],
      "interpretation_confidence": 0.0-1.0,
      "matched_pattern": "pattern_name or null",
      "recommended_priority": "Critical|High|Medium|Low|Info",
      "false_positive_likelihood": 0.0-1.0,
      "additional_checks_needed": ["check1", "check2", "..."]
    }}
  ]
}}
"""

        response = openai.ChatCompletion.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert smart contract security analyst with deep knowledge "
                        "of Solidity, EVM, and historical vulnerabilities. You interpret tool "
                        "outputs and provide actionable insights."
                    )
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,  # Low temperature for consistent analysis
            max_tokens=4000
        )

        result = json.loads(response.choices[0].message.content)

        # Merge interpretation with original findings
        interpreted = []
        for original, interp in zip(findings, result["interpreted_findings"]):
            merged = {**original, **interp}
            interpreted.append(merged)

        return interpreted

    def _correlate_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Correlate findings across multiple tools to identify consensus

        Args:
            findings: Interpreted findings

        Returns:
            Correlation analysis dictionary
        """
        correlation = {
            "high_confidence_findings": [],
            "single_tool_findings": [],
            "conflicting_findings": [],
            "consensus_level": {}
        }

        # Group findings by location (file, function, line)
        location_groups = {}
        for finding in findings:
            location_key = self._get_location_key(finding)
            if location_key not in location_groups:
                location_groups[location_key] = []
            location_groups[location_key].append(finding)

        # Analyze each location group
        for location, group_findings in location_groups.items():
            if len(group_findings) > 1:
                # Multiple tools detected same location
                sources = [f.get("source_agent", "unknown") for f in group_findings]
                severities = [f.get("severity", "Unknown") for f in group_findings]

                correlation["consensus_level"][location] = {
                    "detection_count": len(group_findings),
                    "sources": sources,
                    "severities": severities,
                    "consensus_strength": len(set(sources)) / len(sources)
                }

                # High confidence if multiple tools agree
                if len(set(sources)) >= 2:
                    correlation["high_confidence_findings"].append({
                        "location": location,
                        "findings": group_findings,
                        "consensus": "strong"
                    })
                else:
                    correlation["conflicting_findings"].append({
                        "location": location,
                        "findings": group_findings,
                        "conflict_reason": "severity_mismatch"
                    })
            else:
                # Single tool detection
                correlation["single_tool_findings"].append({
                    "location": location,
                    "finding": group_findings[0],
                    "note": "requires_validation"
                })

        return correlation

    def _detect_duplicates(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect duplicate findings reported by different tools

        Args:
            findings: Interpreted findings

        Returns:
            List of duplicate groups
        """
        duplicates = []
        processed = set()

        for i, finding1 in enumerate(findings):
            if i in processed:
                continue

            duplicate_group = [finding1]

            for j, finding2 in enumerate(findings[i+1:], start=i+1):
                if j in processed:
                    continue

                # Check if findings are duplicates
                if self._is_duplicate(finding1, finding2):
                    duplicate_group.append(finding2)
                    processed.add(j)

            if len(duplicate_group) > 1:
                duplicates.append({
                    "group_id": f"dup_{len(duplicates)}",
                    "findings": duplicate_group,
                    "canonical": duplicate_group[0],  # Use first as canonical
                    "redundant_count": len(duplicate_group) - 1
                })

            processed.add(i)

        return duplicates

    def _is_duplicate(self, finding1: Dict[str, Any],
                     finding2: Dict[str, Any]) -> bool:
        """Check if two findings are duplicates"""
        # Same location
        loc1 = self._get_location_key(finding1)
        loc2 = self._get_location_key(finding2)

        if loc1 != loc2:
            return False

        # Similar vulnerability type
        type1 = finding1.get("type", "").lower()
        type2 = finding2.get("type", "").lower()

        # Simple similarity check (could be improved with NLP)
        common_keywords = set(type1.split()) & set(type2.split())
        if len(common_keywords) >= 1:
            return True

        return False

    def _calculate_confidence_scores(self, findings: List[Dict[str, Any]],
                                     correlation: Dict[str, Any]) -> Dict[str, float]:
        """
        Calculate confidence scores for each finding

        Args:
            findings: Interpreted findings
            correlation: Correlation analysis

        Returns:
            Dictionary mapping finding ID to confidence score
        """
        confidence_scores = {}

        for finding in findings:
            finding_id = finding.get("id", finding.get("original_finding_id", "unknown"))

            # Base confidence from interpretation
            base_confidence = finding.get("interpretation_confidence", 0.5)

            # Boost confidence if multiple tools detected
            location = self._get_location_key(finding)
            if location in correlation.get("consensus_level", {}):
                detection_count = correlation["consensus_level"][location]["detection_count"]
                correlation_boost = min(detection_count * 0.2, 0.4)
                base_confidence += correlation_boost

            # Reduce confidence if high false positive likelihood
            fp_likelihood = finding.get("false_positive_likelihood", 0.0)
            base_confidence -= fp_likelihood * 0.3

            # Clamp to [0.0, 1.0]
            confidence_scores[finding_id] = max(0.0, min(1.0, base_confidence))

        return confidence_scores

    def _normalize_severity(self, findings: List[Dict[str, Any]],
                           confidence_scores: Dict[str, float]) -> Dict[str, str]:
        """
        Normalize severity levels across different tools

        Args:
            findings: Interpreted findings
            confidence_scores: Confidence scores

        Returns:
            Dictionary mapping finding ID to normalized severity
        """
        normalized = {}

        severity_map = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
            "informational": 1
        }

        for finding in findings:
            finding_id = finding.get("id", finding.get("original_finding_id", "unknown"))

            # Get interpreted severity
            recommended_severity = finding.get("recommended_priority", "Medium")
            exploitability = finding.get("exploitability", "Medium")
            impact = finding.get("business_impact_category", "other")

            # Calculate weighted severity
            severity_score = severity_map.get(recommended_severity.lower(), 3)

            # Adjust based on exploitability
            if exploitability == "Critical":
                severity_score += 1
            elif exploitability == "None" or exploitability == "Low":
                severity_score -= 1

            # Adjust based on business impact
            if impact == "funds_loss":
                severity_score += 1
            elif impact == "other":
                severity_score -= 1

            # Adjust based on confidence
            confidence = confidence_scores.get(finding_id, 0.5)
            if confidence < 0.4:
                severity_score -= 1

            # Map back to severity level
            severity_score = max(1, min(5, severity_score))
            severity_levels = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info"}
            normalized[finding_id] = severity_levels[severity_score]

        return normalized

    def _get_location_key(self, finding: Dict[str, Any]) -> str:
        """Generate unique location key for finding"""
        file = finding.get("file", finding.get("contract", "unknown"))
        function = finding.get("function", "unknown")
        line = finding.get("line", finding.get("line_start", "unknown"))

        return f"{file}:{function}:{line}"

    def _load_vulnerability_patterns(self) -> Dict[str, Any]:
        """Load known vulnerability patterns"""
        return {
            "dao_reentrancy": {
                "keywords": ["reentrancy", "external call", "state change"],
                "severity": "Critical",
                "historical_incidents": ["The DAO 2016"],
                "swc_id": "SWC-107"
            },
            "integer_overflow": {
                "keywords": ["overflow", "underflow", "arithmetic"],
                "severity": "High",
                "historical_incidents": ["BeautyChain 2018"],
                "swc_id": "SWC-101"
            },
            "unchecked_return": {
                "keywords": ["unchecked", "return value", "call"],
                "severity": "Medium",
                "swc_id": "SWC-104"
            }
            # Add more patterns as needed
        }
