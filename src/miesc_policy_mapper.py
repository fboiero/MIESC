"""
MIESC Policy Mapper - Compatibility shim for webapp imports.

.. deprecated:: 5.1.1
    Use ``from src.security.compliance_mapper import ComplianceMapper`` instead.
    This module will be removed in v6.0.0.
"""

import warnings

from src.security.compliance_mapper import ComplianceMapper

warnings.warn(
    "src.miesc_policy_mapper is deprecated. Use src.security.compliance_mapper instead. "
    "This module will be removed in v6.0.0.",
    DeprecationWarning,
    stacklevel=2,
)


class PolicyMapper:
    """
    Compatibility wrapper around ComplianceMapper.

    .. deprecated:: 5.1.1
        Use ``ComplianceMapper`` directly instead.
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
            "policies": mapped.get("mappings", []),
            "compliance_score": mapped.get("score", 0),
            "standards": ["OWASP", "SWC", "CWE", "ISO27001"],
        }

    def get_compliance_report(self, findings: list) -> dict:
        """Generate compliance report from findings."""
        return self.map_findings(findings)
