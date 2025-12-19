"""
MIESC Risk Engine - Compatibility shim for legacy webapp imports.
Provides risk assessment functionality for v4.2+ compatibility.
"""


class RiskEngine:
    """
    Risk assessment engine for smart contract analysis.
    Used by webapp/app.py.
    """

    SEVERITY_WEIGHTS = {
        'critical': 10,
        'high': 7,
        'medium': 4,
        'low': 2,
        'info': 1
    }

    def __init__(self):
        """Initialize Risk Engine."""
        pass

    def calculate_risk(self, findings: list) -> dict:
        """
        Calculate risk score from findings.

        Args:
            findings: List of vulnerability findings

        Returns:
            dict with risk level, score, and breakdown
        """
        if not findings:
            return {
                'risk_level': 'LOW',
                'risk_score': 0,
                'breakdown': {}
            }

        # Count by severity
        severity_counts = {}
        for finding in findings:
            sev = finding.get('severity', 'info').lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Calculate score
        total_score = sum(
            self.SEVERITY_WEIGHTS.get(sev, 1) * count
            for sev, count in severity_counts.items()
        )

        # Determine risk level
        if total_score >= 50 or severity_counts.get('critical', 0) > 0:
            risk_level = 'CRITICAL'
        elif total_score >= 30 or severity_counts.get('high', 0) > 0:
            risk_level = 'HIGH'
        elif total_score >= 15:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        return {
            'risk_level': risk_level,
            'risk_score': total_score,
            'breakdown': severity_counts,
            'total_findings': len(findings)
        }

    def get_risk_summary(self, findings: list) -> str:
        """Generate human-readable risk summary."""
        risk = self.calculate_risk(findings)
        return f"Risk Level: {risk['risk_level']} (Score: {risk['risk_score']})"
