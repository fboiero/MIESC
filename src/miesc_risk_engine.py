"""
MIESC Risk Engine - Risk Assessment and Prioritization

Calculates risk scores, prioritizes vulnerabilities, and provides
actionable recommendations for remediation.

Scientific Foundation:
- CVSS v3.1 scoring methodology
- Risk = Likelihood × Impact × Exploitability
- NIST Risk Management Framework

Author: Fernando Boiero
Thesis: Master's in Cyberdefense - UNDEF
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level enumeration"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


@dataclass
class RiskAssessment:
    """Complete risk assessment for a vulnerability"""
    vulnerability_type: str
    severity: str
    risk_score: float  # 0.0-10.0 (CVSS-style)
    risk_level: str
    exploitability: float  # 0.0-1.0
    impact: float  # 0.0-1.0
    likelihood: float  # 0.0-1.0
    business_criticality: float  # 0.0-1.0
    remediation_priority: int  # 1 (immediate) - 5 (low)
    remediation_effort: str  # Trivial, Minor, Moderate, Major, Extensive
    estimated_fix_time: str  # Hours/days
    risk_factors: List[str]
    mitigation_steps: List[str]
    residual_risk: float  # Risk after mitigation

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RiskEngine:
    """
    Risk assessment and prioritization engine

    Capabilities:
    - CVSS-based risk scoring
    - Exploitability assessment
    - Business impact analysis
    - Remediation prioritization
    - Risk trend analysis
    """

    def __init__(self, business_context: Optional[Dict[str, Any]] = None):
        """
        Initialize risk engine

        Args:
            business_context: Optional business context (contract value, users, etc.)
        """
        self.business_context = business_context or {}

    def assess_vulnerability(
        self,
        finding: Dict[str, Any],
        contract_context: Optional[Dict[str, Any]] = None
    ) -> RiskAssessment:
        """
        Perform comprehensive risk assessment for a vulnerability

        Args:
            finding: Vulnerability finding
            contract_context: Contract-specific context

        Returns:
            RiskAssessment object
        """
        vuln_type = finding.get('vulnerability_type', 'unknown')
        severity = finding.get('severity', 'Low')

        # Calculate risk components
        exploitability = self._calculate_exploitability(finding)
        impact = self._calculate_impact(finding, contract_context)
        likelihood = self._calculate_likelihood(finding, exploitability)
        business_criticality = self._assess_business_criticality(finding, contract_context)

        # Calculate overall risk score (CVSS-inspired)
        risk_score = self._calculate_risk_score(
            exploitability, impact, likelihood, business_criticality
        )

        # Determine risk level
        risk_level = self._determine_risk_level(risk_score)

        # Calculate remediation priority
        priority = self._calculate_priority(risk_score, exploitability, impact)

        # Estimate remediation effort
        effort, fix_time = self._estimate_remediation(finding)

        # Identify risk factors
        risk_factors = self._identify_risk_factors(finding, contract_context)

        # Generate mitigation steps
        mitigation_steps = self._generate_mitigation_steps(finding)

        # Calculate residual risk (after mitigation)
        residual_risk = risk_score * 0.1  # Assume 90% risk reduction with proper fix

        return RiskAssessment(
            vulnerability_type=vuln_type,
            severity=severity,
            risk_score=risk_score,
            risk_level=risk_level.value,
            exploitability=exploitability,
            impact=impact,
            likelihood=likelihood,
            business_criticality=business_criticality,
            remediation_priority=priority,
            remediation_effort=effort,
            estimated_fix_time=fix_time,
            risk_factors=risk_factors,
            mitigation_steps=mitigation_steps,
            residual_risk=residual_risk
        )

    def _calculate_exploitability(self, finding: Dict[str, Any]) -> float:
        """Calculate exploitability score (0.0-1.0)"""
        vuln_type = finding.get('vulnerability_type', '').lower()
        confidence = finding.get('confidence', 'Medium')

        # Base exploitability by vulnerability type
        exploitability_map = {
            'reentrancy': 0.7,
            'access-control': 0.9,
            'unchecked-send': 0.6,
            'arithmetic': 0.5,
            'tx-origin': 0.9,
            'delegatecall': 0.4,
            'timestamp': 0.6,
            'uninitialized-storage': 0.7,
            'locked-ether': 0.8
        }

        base_exploit = 0.5  # Default
        for key, value in exploitability_map.items():
            if key in vuln_type:
                base_exploit = value
                break

        # Adjust for confidence
        confidence_multiplier = {
            'High': 1.0,
            'Medium': 0.8,
            'Low': 0.5
        }.get(confidence, 0.7)

        return min(base_exploit * confidence_multiplier, 1.0)

    def _calculate_impact(
        self,
        finding: Dict[str, Any],
        contract_context: Optional[Dict[str, Any]]
    ) -> float:
        """Calculate impact score (0.0-1.0)"""
        severity = finding.get('severity', 'Low')

        # Base impact by severity
        severity_impact = {
            'Critical': 1.0,
            'High': 0.8,
            'Medium': 0.5,
            'Low': 0.3,
            'Info': 0.1
        }.get(severity, 0.5)

        # Adjust for contract context
        if contract_context:
            value_at_risk = contract_context.get('value_locked', 0)
            if value_at_risk > 1000000:  # $1M+
                severity_impact = min(severity_impact * 1.5, 1.0)
            elif value_at_risk > 100000:  # $100K+
                severity_impact = min(severity_impact * 1.2, 1.0)

        return severity_impact

    def _calculate_likelihood(self, finding: Dict[str, Any], exploitability: float) -> float:
        """Calculate likelihood score (0.0-1.0)"""
        # Likelihood = exploitability × visibility
        # Vulnerabilities in public functions are more likely to be exploited

        location = finding.get('location', {})
        function_name = location.get('function', '')

        # Public functions are more visible
        if function_name and not function_name.startswith('_'):
            visibility_factor = 1.0
        else:
            visibility_factor = 0.7

        return exploitability * visibility_factor

    def _assess_business_criticality(
        self,
        finding: Dict[str, Any],
        contract_context: Optional[Dict[str, Any]]
    ) -> float:
        """Assess business criticality (0.0-1.0)"""
        if not contract_context:
            return 0.5  # Default medium criticality

        # Factors affecting business criticality
        criticality = 0.5

        # High-value contracts
        if contract_context.get('value_locked', 0) > 1000000:
            criticality = max(criticality, 0.9)

        # Many users affected
        if contract_context.get('user_count', 0) > 10000:
            criticality = max(criticality, 0.8)

        # Production deployment
        if contract_context.get('is_production', False):
            criticality = max(criticality, 0.7)

        # DeFi protocol
        if contract_context.get('category') == 'defi':
            criticality = max(criticality, 0.8)

        return min(criticality, 1.0)

    @staticmethod
    def _calculate_risk_score(
        exploitability: float,
        impact: float,
        likelihood: float,
        business_criticality: float
    ) -> float:
        """
        Calculate overall risk score (0.0-10.0, CVSS-style)

        Formula: Risk = (Exploitability + Impact + Likelihood) × Business_Criticality × 3.33
        """
        base_risk = (exploitability + impact + likelihood) / 3.0  # Average
        adjusted_risk = base_risk * business_criticality
        cvss_score = adjusted_risk * 10.0  # Scale to 0-10

        return round(min(cvss_score, 10.0), 2)

    @staticmethod
    def _determine_risk_level(risk_score: float) -> RiskLevel:
        """Determine risk level from score"""
        if risk_score >= 9.0:
            return RiskLevel.CRITICAL
        elif risk_score >= 7.0:
            return RiskLevel.HIGH
        elif risk_score >= 4.0:
            return RiskLevel.MEDIUM
        elif risk_score >= 1.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFORMATIONAL

    @staticmethod
    def _calculate_priority(risk_score: float, exploitability: float, impact: float) -> int:
        """Calculate remediation priority (1=immediate, 5=low)"""
        if risk_score >= 9.0 or (exploitability > 0.8 and impact > 0.8):
            return 1  # Immediate
        elif risk_score >= 7.0:
            return 2  # High
        elif risk_score >= 4.0:
            return 3  # Medium
        elif risk_score >= 1.0:
            return 4  # Low
        else:
            return 5  # Informational

    def _estimate_remediation(self, finding: Dict[str, Any]) -> Tuple[str, str]:
        """
        Estimate remediation effort and time

        Returns:
            Tuple of (effort level, estimated time)
        """
        vuln_type = finding.get('vulnerability_type', '').lower()

        # Remediation effort mapping
        effort_map = {
            'reentrancy': ('Moderate', '4-8 hours'),
            'access-control': ('Minor', '1-2 hours'),
            'unchecked-send': ('Minor', '1-2 hours'),
            'arithmetic': ('Trivial', '30 minutes'),
            'tx-origin': ('Trivial', '30 minutes'),
            'delegatecall': ('Major', '1-2 days'),
            'timestamp': ('Minor', '2-4 hours'),
            'uninitialized-storage': ('Minor', '1-2 hours'),
            'locked-ether': ('Moderate', '4-8 hours')
        }

        for key, (effort, time) in effort_map.items():
            if key in vuln_type:
                return effort, time

        return 'Moderate', '4-8 hours'  # Default

    def _identify_risk_factors(
        self,
        finding: Dict[str, Any],
        contract_context: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Identify specific risk factors"""
        factors = []

        severity = finding.get('severity', 'Low')
        if severity in ['Critical', 'High']:
            factors.append(f"{severity} severity vulnerability")

        vuln_type = finding.get('vulnerability_type', '')
        if 'reentrancy' in vuln_type.lower():
            factors.append("External calls to untrusted contracts")
        if 'access' in vuln_type.lower():
            factors.append("Missing or inadequate access controls")
        if 'delegatecall' in vuln_type.lower():
            factors.append("Dangerous delegatecall usage")

        if contract_context:
            if contract_context.get('is_production', False):
                factors.append("Contract deployed in production")
            if contract_context.get('value_locked', 0) > 100000:
                factors.append("High-value contract ($100K+ at risk)")
            if contract_context.get('category') == 'defi':
                factors.append("DeFi protocol - systemic risk potential")

        return factors

    def _generate_mitigation_steps(self, finding: Dict[str, Any]) -> List[str]:
        """Generate specific mitigation steps"""
        vuln_type = finding.get('vulnerability_type', '').lower()

        mitigation_map = {
            'reentrancy': [
                "1. Apply checks-effects-interactions pattern",
                "2. Use ReentrancyGuard from OpenZeppelin",
                "3. Review all external calls for reentrancy risk",
                "4. Add comprehensive integration tests"
            ],
            'access-control': [
                "1. Implement proper access control modifiers (onlyOwner, etc.)",
                "2. Use role-based access control (RBAC) if needed",
                "3. Review all privileged functions",
                "4. Add access control tests"
            ],
            'unchecked-send': [
                "1. Always check return values with require()",
                "2. Consider using transfer() instead of send()",
                "3. Implement withdrawal pattern",
                "4. Add error handling tests"
            ],
            'arithmetic': [
                "1. Upgrade to Solidity 0.8+ with built-in checks",
                "2. Or use SafeMath library",
                "3. Review all arithmetic operations",
                "4. Add boundary condition tests"
            ],
            'tx-origin': [
                "1. Replace tx.origin with msg.sender",
                "2. Review authentication logic",
                "3. Update documentation",
                "4. Add phishing attack tests"
            ]
        }

        for key, steps in mitigation_map.items():
            if key in vuln_type:
                return steps

        return [
            "1. Review vulnerability details",
            "2. Consult security best practices",
            "3. Implement recommended fix",
            "4. Test thoroughly before deployment"
        ]

    def prioritize_findings(
        self,
        findings: List[Dict[str, Any]],
        contract_context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[Dict[str, Any], RiskAssessment]]:
        """
        Prioritize all findings by risk score

        Args:
            findings: List of vulnerability findings
            contract_context: Contract context

        Returns:
            List of (finding, risk_assessment) tuples, sorted by priority
        """
        assessed = []

        for finding in findings:
            assessment = self.assess_vulnerability(finding, contract_context)
            assessed.append((finding, assessment))

        # Sort by risk score (descending) and priority (ascending)
        assessed.sort(
            key=lambda x: (-x[1].risk_score, x[1].remediation_priority)
        )

        return assessed

    def generate_risk_report(
        self,
        findings: List[Dict[str, Any]],
        contract_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive risk report

        Args:
            findings: List of findings
            contract_context: Contract context

        Returns:
            Risk report dictionary
        """
        prioritized = self.prioritize_findings(findings, contract_context)

        # Aggregate statistics
        total_risk = sum(assessment.risk_score for _, assessment in prioritized)
        avg_risk = total_risk / len(prioritized) if prioritized else 0

        risk_by_level = {}
        for _, assessment in prioritized:
            level = assessment.risk_level
            risk_by_level[level] = risk_by_level.get(level, 0) + 1

        # Top critical issues
        critical_issues = [
            (finding, assessment)
            for finding, assessment in prioritized
            if assessment.risk_level == 'Critical'
        ][:5]  # Top 5

        return {
            'total_findings': len(findings),
            'total_risk_score': round(total_risk, 2),
            'average_risk_score': round(avg_risk, 2),
            'risk_by_level': risk_by_level,
            'critical_issues_count': len([a for _, a in prioritized if a.risk_level == 'Critical']),
            'top_critical_issues': [
                {
                    'vulnerability': finding['vulnerability_type'],
                    'risk_score': assessment.risk_score,
                    'priority': assessment.remediation_priority
                }
                for finding, assessment in critical_issues
            ],
            'prioritized_findings': [
                {
                    'finding': finding,
                    'assessment': assessment.to_dict()
                }
                for finding, assessment in prioritized
            ],
            'recommendations': self._generate_report_recommendations(risk_by_level)
        }

    @staticmethod
    def _generate_report_recommendations(risk_by_level: Dict[str, int]) -> List[str]:
        """Generate high-level recommendations"""
        recommendations = []

        critical_count = risk_by_level.get('Critical', 0)
        high_count = risk_by_level.get('High', 0)

        if critical_count > 0:
            recommendations.append(
                f"⛔ {critical_count} CRITICAL risk(s) - DO NOT DEPLOY until resolved"
            )

        if high_count > 0:
            recommendations.append(
                f"⚠️ {high_count} HIGH risk(s) - Address before production deployment"
            )

        if critical_count == 0 and high_count == 0:
            recommendations.append(
                "✅ No critical or high-risk vulnerabilities detected"
            )

        recommendations.append(
            "📋 Review all findings in priority order"
        )
        recommendations.append(
            "🧪 Conduct manual security audit before mainnet launch"
        )

        return recommendations


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = RiskEngine()

    example_finding = {
        'vulnerability_type': 'reentrancy-eth',
        'severity': 'High',
        'confidence': 'High',
        'location': {'function': 'withdraw'}
    }

    assessment = engine.assess_vulnerability(example_finding)
    print(f"Risk Score: {assessment.risk_score}/10.0")
    print(f"Priority: {assessment.remediation_priority}")
