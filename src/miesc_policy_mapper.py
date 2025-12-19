"""
MIESC Policy Mapper - Compatibility shim for legacy webapp imports.
Redirects to src.security.compliance_mapper for v4.2+ compatibility.
"""

from src.security.compliance_mapper import ComplianceMapper


class PolicyMapper:
    """
    Legacy compatibility wrapper around ComplianceMapper.
    Used by webapp/app.py.
    """

    def __init__(self):
        """Initialize Policy Mapper."""
        self.mapper = ComplianceMapper()

    def map_findings(self, findings: list) -> dict:
        """
        Map findings to compliance policies.

        Args:
            findings: List of vulnerability findings

        Returns:
            dict with policy mappings and compliance score
        """
        mapped = self.mapper.map_findings(findings)
        return {
            'policies': mapped.get('mappings', []),
            'compliance_score': mapped.get('score', 0),
            'standards': ['OWASP', 'SWC', 'CWE', 'ISO27001']
        }

    def get_compliance_report(self, findings: list) -> dict:
        """Generate compliance report from findings."""
        return self.map_findings(findings)
