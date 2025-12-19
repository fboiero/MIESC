"""
MIESC AI Layer - Machine Learning and LLM-based Classification

Applies AI-driven correlation, false positive reduction, and vulnerability
classification to improve accuracy over individual tools.

Scientific Foundation:
- Cross-tool correlation reduces false positives (Durieux et al., 2020)
- LLM-based triage improves precision (GPTScan, 2024)
- Ensemble methods for vulnerability classification

Author: Fernando Boiero
Thesis: Master's in Cyberdefense - UNDEF
"""

import json
import logging
import openai
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from sklearn.metrics import precision_score, recall_score, f1_score, cohen_kappa_score
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedFinding:
    """Finding after AI correlation and classification"""
    original_findings: List[Dict[str, Any]]
    vulnerability_type: str
    severity: str
    confidence: float  # 0.0-1.0
    is_false_positive: bool
    false_positive_confidence: float
    root_cause: str
    affected_locations: List[Dict[str, Any]]
    remediation_priority: int  # 1 (highest) - 5 (lowest)
    cwe_id: Optional[str]
    swc_id: Optional[str]
    owasp_category: Optional[str]
    mitre_tactics: List[str]
    explanation: str


class AICorrelator:
    """
    AI-powered correlation engine for vulnerability findings

    Capabilities:
    - Cross-tool correlation (identify duplicates)
    - False positive filtering
    - Severity re-ranking
    - Root cause analysis
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        """
        Initialize AI correlator

        Args:
            api_key: OpenAI API key (optional, uses env if not provided)
            model: LLM model to use
        """
        self.model = model
        if api_key:
            openai.api_key = api_key

    def correlate_findings(
        self,
        findings: List[Dict[str, Any]],
        contract_source: Optional[str] = None
    ) -> List[CorrelatedFinding]:
        """
        Correlate findings from multiple tools

        Args:
            findings: Raw findings from MIESC core
            contract_source: Optional contract source code for context

        Returns:
            List of correlated findings with reduced false positives
        """
        if not findings:
            return []

        logger.info(f"Correlating {len(findings)} raw findings")

        # Step 1: Group similar findings
        grouped = self._group_similar_findings(findings)
        logger.info(f"Grouped into {len(grouped)} clusters")

        # Step 2: Apply ML-based false positive detection
        filtered_groups = self._filter_false_positives(grouped, contract_source)
        logger.info(f"Filtered to {len(filtered_groups)} likely true positives")

        # Step 3: Re-rank severity
        correlated = self._rerank_and_explain(filtered_groups, contract_source)

        logger.info(f"AI correlation complete: {len(correlated)} correlated findings")

        return correlated

    def _group_similar_findings(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[List[Dict[str, Any]]]:
        """
        Group findings that likely refer to the same vulnerability

        Uses:
        - Location similarity (file, line number)
        - Vulnerability type similarity
        - Description similarity
        """
        groups: List[List[Dict[str, Any]]] = []

        for finding in findings:
            # Try to find matching group
            matched = False
            for group in groups:
                if self._are_similar(finding, group[0]):
                    group.append(finding)
                    matched = True
                    break

            # Create new group if no match
            if not matched:
                groups.append([finding])

        return groups

    def _are_similar(self, f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
        """
        Check if two findings are similar (same vulnerability)

        Args:
            f1, f2: Findings to compare

        Returns:
            True if likely the same vulnerability
        """
        # Same file and close line numbers
        loc1 = f1.get('location', {})
        loc2 = f2.get('location', {})

        same_file = loc1.get('file') == loc2.get('file')
        line1 = loc1.get('line', 0)
        line2 = loc2.get('line', 0)
        close_lines = abs(line1 - line2) < 5

        # Similar vulnerability types
        vuln1 = f1.get('vulnerability_type', '').lower()
        vuln2 = f2.get('vulnerability_type', '').lower()
        similar_type = (
            vuln1 in vuln2 or vuln2 in vuln1 or
            f1.get('swc_id') == f2.get('swc_id') and f1.get('swc_id') is not None
        )

        return same_file and close_lines and similar_type

    def _filter_false_positives(
        self,
        grouped_findings: List[List[Dict[str, Any]]],
        contract_source: Optional[str]
    ) -> List[List[Dict[str, Any]]]:
        """
        Filter out likely false positives using heuristics and ML

        Args:
            grouped_findings: Grouped findings
            contract_source: Contract source code

        Returns:
            Filtered groups (likely true positives)
        """
        filtered = []

        for group in grouped_findings:
            # Heuristic 1: Multiple tools agree = higher confidence
            num_tools = len(set(f['tool'] for f in group))
            if num_tools >= 2:
                filtered.append(group)
                continue

            # Heuristic 2: High severity from reliable tools
            reliable_tools = {'mythril', 'slither'}
            has_reliable_high_severity = any(
                f['tool'] in reliable_tools and f['severity'] in ['Critical', 'High']
                for f in group
            )
            if has_reliable_high_severity:
                filtered.append(group)
                continue

            # Heuristic 3: LLM-based validation (if available)
            if openai.api_key:
                is_valid = self._llm_validate_finding(group, contract_source)
                if is_valid:
                    filtered.append(group)
            else:
                # Without LLM, keep medium+ severity
                if any(f['severity'] in ['Critical', 'High', 'Medium'] for f in group):
                    filtered.append(group)

        return filtered

    def _llm_validate_finding(
        self,
        finding_group: List[Dict[str, Any]],
        contract_source: Optional[str]
    ) -> bool:
        """
        Use LLM to validate if finding is a true positive

        Args:
            finding_group: Group of similar findings
            contract_source: Contract source code

        Returns:
            True if likely a true positive
        """
        try:
            # Prepare context
            finding = finding_group[0]  # Representative finding
            description = finding.get('description', '')
            vuln_type = finding.get('vulnerability_type', '')

            # Truncate contract source
            source_snippet = contract_source[:2000] if contract_source else "N/A"

            prompt = f"""
You are an expert smart contract auditor. Analyze this security finding:

**Vulnerability Type:** {vuln_type}
**Description:** {description}
**Detected by:** {len(finding_group)} tool(s)

**Contract Code (snippet):**
```solidity
{source_snippet}
```

**Question:** Is this a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE?

Respond with JSON:
{{
  "is_true_positive": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation"
}}
"""

            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a smart contract security expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=500
            )

            result = json.loads(response.choices[0].message.content)
            return result.get('is_true_positive', False)

        except Exception as e:
            logger.warning(f"LLM validation failed: {e}")
            return True  # Default to keeping finding

    def _rerank_and_explain(
        self,
        grouped_findings: List[List[Dict[str, Any]]],
        contract_source: Optional[str]
    ) -> List[CorrelatedFinding]:
        """
        Re-rank severity and generate explanations for findings

        Args:
            grouped_findings: Filtered grouped findings
            contract_source: Contract source

        Returns:
            List of CorrelatedFinding objects with explanations
        """
        correlated = []

        for i, group in enumerate(grouped_findings):
            # Calculate consensus severity
            severities = [f['severity'] for f in group]
            consensus_severity = self._consensus_severity(severities)

            # Calculate confidence based on tool agreement
            confidence = min(len(group) / 3.0, 1.0)  # 3+ tools = 100% confidence

            # Extract unique locations
            locations = []
            seen_locs = set()
            for f in group:
                loc = f.get('location', {})
                loc_key = (loc.get('file'), loc.get('line'))
                if loc_key not in seen_locs:
                    locations.append(loc)
                    seen_locs.add(loc_key)

            # Get best CWE/SWC/OWASP mapping
            cwe = next((f['cwe_id'] for f in group if f.get('cwe_id')), None)
            swc = next((f['swc_id'] for f in group if f.get('swc_id')), None)
            owasp = next((f['owasp_category'] for f in group if f.get('owasp_category')), None)

            # Generate explanation (LLM or template)
            explanation = self._generate_explanation(group, contract_source)

            # Create correlated finding
            correlated_finding = CorrelatedFinding(
                original_findings=group,
                vulnerability_type=group[0]['vulnerability_type'],
                severity=consensus_severity,
                confidence=confidence,
                is_false_positive=False,  # Already filtered
                false_positive_confidence=1.0 - confidence,
                root_cause=explanation,
                affected_locations=locations,
                remediation_priority=self._calculate_priority(consensus_severity, confidence),
                cwe_id=cwe,
                swc_id=swc,
                owasp_category=owasp,
                mitre_tactics=self._map_to_mitre(group[0]['vulnerability_type']),
                explanation=explanation
            )

            correlated.append(correlated_finding)

        return correlated

    @staticmethod
    def _consensus_severity(severities: List[str]) -> str:
        """Calculate consensus severity from multiple tools"""
        severity_rank = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}

        # Get highest severity (most conservative)
        ranked = [severity_rank.get(s, 0) for s in severities]
        max_rank = max(ranked) if ranked else 0

        # Reverse map
        for sev, rank in severity_rank.items():
            if rank == max_rank:
                return sev

        return 'Low'

    def _generate_explanation(
        self,
        finding_group: List[Dict[str, Any]],
        contract_source: Optional[str]
    ) -> str:
        """Generate human-readable explanation for finding"""
        if not openai.api_key:
            # Fallback to template
            return finding_group[0].get('description', 'No description available')

        try:
            finding = finding_group[0]
            tools_detected = ', '.join(set(f['tool'] for f in finding_group))

            prompt = f"""
You are a smart contract security auditor. Explain this vulnerability in clear, actionable terms:

**Vulnerability:** {finding['vulnerability_type']}
**Severity:** {finding['severity']}
**Detected by:** {tools_detected}
**Description:** {finding.get('description', 'N/A')}

Provide:
1. What the vulnerability is
2. Why it's dangerous
3. How to fix it

Be concise (2-3 sentences).
"""

            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a smart contract security expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=300
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            logger.warning(f"Explanation generation failed: {e}")
            return finding_group[0].get('description', 'No description available')

    @staticmethod
    def _calculate_priority(severity: str, confidence: float) -> int:
        """Calculate remediation priority (1=highest, 5=lowest)"""
        severity_score = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}

        base_priority = 5 - severity_score.get(severity, 0)  # Invert (1=worst)

        # Adjust for confidence
        if confidence < 0.5:
            base_priority = min(base_priority + 1, 5)

        return max(1, min(base_priority, 5))

    @staticmethod
    def _map_to_mitre(vuln_type: str) -> List[str]:
        """Map vulnerability to MITRE ATT&CK tactics"""
        mapping = {
            'reentrancy': ['TA0040-Impact'],
            'access-control': ['TA0004-Privilege-Escalation'],
            'arithmetic': ['TA0040-Impact'],
            'unchecked-send': ['TA0040-Impact'],
            'delegatecall': ['TA0005-Defense-Evasion']
        }

        for key, tactics in mapping.items():
            if key in vuln_type.lower():
                return tactics

        return ['TA0040-Impact']  # Default


class MetricsCalculator:
    """
    Calculate scientific metrics for validation

    Metrics:
    - Precision: TP / (TP + FP)
    - Recall: TP / (TP + FN)
    - F1 Score: Harmonic mean of precision and recall
    - Cohen's Kappa: Inter-rater agreement
    """

    @staticmethod
    def calculate_metrics(
        predictions: List[int],
        ground_truth: List[int]
    ) -> Dict[str, float]:
        """
        Calculate all metrics

        Args:
            predictions: Binary predictions (1=vulnerable, 0=safe)
            ground_truth: Ground truth labels

        Returns:
            Dictionary with precision, recall, F1, kappa
        """
        if len(predictions) != len(ground_truth):
            raise ValueError("Predictions and ground truth must have same length")

        precision = precision_score(ground_truth, predictions, zero_division=0)
        recall = recall_score(ground_truth, predictions, zero_division=0)
        f1 = f1_score(ground_truth, predictions, zero_division=0)
        kappa = cohen_kappa_score(ground_truth, predictions)

        return {
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'cohens_kappa': round(kappa, 4),
            'total_samples': len(predictions),
            'true_positives': int(np.sum((np.array(predictions) == 1) & (np.array(ground_truth) == 1))),
            'false_positives': int(np.sum((np.array(predictions) == 1) & (np.array(ground_truth) == 0))),
            'true_negatives': int(np.sum((np.array(predictions) == 0) & (np.array(ground_truth) == 0))),
            'false_negatives': int(np.sum((np.array(predictions) == 0) & (np.array(ground_truth) == 1)))
        }

    @staticmethod
    def compare_tools(
        tool_results: Dict[str, List[int]],
        ground_truth: List[int]
    ) -> Dict[str, Dict[str, float]]:
        """
        Compare multiple tools against ground truth

        Args:
            tool_results: Dictionary mapping tool name to predictions
            ground_truth: Ground truth labels

        Returns:
            Dictionary mapping tool name to metrics
        """
        comparison = {}

        for tool_name, predictions in tool_results.items():
            metrics = MetricsCalculator.calculate_metrics(predictions, ground_truth)
            comparison[tool_name] = metrics

        return comparison


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Example correlation
    correlator = AICorrelator()

    example_findings = [
        {
            'tool': 'slither',
            'vulnerability_type': 'reentrancy-eth',
            'severity': 'High',
            'location': {'file': 'contract.sol', 'line': 42},
            'description': 'Reentrancy vulnerability detected'
        },
        {
            'tool': 'mythril',
            'vulnerability_type': 'Reentrancy',
            'severity': 'High',
            'location': {'file': 'contract.sol', 'line': 43},
            'description': 'Potential reentrancy attack'
        }
    ]

    correlated = correlator.correlate_findings(example_findings)
    print(f"Correlated {len(correlated)} findings")
