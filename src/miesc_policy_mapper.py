"""
MIESC Policy Mapper - Standards Compliance Mapping

Maps vulnerabilities to international security standards:
- OWASP Smart Contract Top 10
- CWE (Common Weakness Enumeration)
- ISO/IEC 27001:2022
- NIST Cybersecurity Framework
- MITRE ATT&CK for ICS/Blockchain
- SWC Registry (Smart Contract Weakness)

Scientific Foundation:
- Compliance-driven security (ISO 27001, NIST)
- Standardized vulnerability taxonomies
- Defense-in-depth policy enforcement

Author: Fernando Boiero
Thesis: Master's in Cyberdefense - UNDEF
"""

import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ComplianceMapping:
    """Compliance mapping for a vulnerability"""
    vulnerability_type: str
    severity: str

    # Standard mappings
    cwe_ids: List[str]
    swc_ids: List[str]
    owasp_categories: List[str]
    iso27001_controls: List[str]
    nist_csf_functions: List[str]
    mitre_tactics: List[str]

    # Regulatory
    gdpr_articles: List[str]
    eu_mica_requirements: List[str]
    eu_dora_requirements: List[str]

    # Risk assessment
    cvss_score: Optional[float]
    exploitability: str  # Easy, Medium, Hard
    business_impact: str

    # Recommendations
    remediation_guidance: str
    compliance_notes: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PolicyMapper:
    """
    Maps vulnerabilities to security standards and policies

    Features:
    - Multi-standard mapping
    - Compliance gap analysis
    - Automated evidence generation
    - Regulatory alignment (EU MiCA, DORA, GDPR)
    """

    def __init__(self, mapping_db_path: Optional[str] = None):
        """
        Initialize policy mapper

        Args:
            mapping_db_path: Path to custom mapping database (JSON)
        """
        self.mapping_db = self._load_mapping_db(mapping_db_path)

    def _load_mapping_db(self, custom_path: Optional[str]) -> Dict[str, Any]:
        """Load vulnerability-to-standard mapping database"""
        # Built-in comprehensive mapping
        default_db = {
            # Reentrancy vulnerabilities
            "reentrancy": {
                "cwe": ["CWE-841"],
                "swc": ["SWC-107"],
                "owasp": ["SC01-Reentrancy"],
                "iso27001": ["A.8.8", "A.14.2.5"],
                "nist_csf": ["PR.DS-6", "DE.CM-1"],
                "mitre": ["TA0040-Impact"],
                "cvss_base": 9.1,
                "exploitability": "Medium",
                "remediation": "Use checks-effects-interactions pattern or reentrancy guards"
            },

            # Access control
            "access-control": {
                "cwe": ["CWE-284", "CWE-862"],
                "swc": ["SWC-105", "SWC-106"],
                "owasp": ["SC02-Access-Control"],
                "iso27001": ["A.5.15", "A.5.16", "A.8.2"],
                "nist_csf": ["PR.AC-4", "PR.AC-7"],
                "mitre": ["TA0004-Privilege-Escalation"],
                "cvss_base": 8.8,
                "exploitability": "Easy",
                "remediation": "Implement role-based access control (RBAC) with modifiers"
            },

            # Arithmetic issues
            "arithmetic": {
                "cwe": ["CWE-190", "CWE-191"],
                "swc": ["SWC-101"],
                "owasp": ["SC03-Arithmetic"],
                "iso27001": ["A.8.8"],
                "nist_csf": ["PR.DS-6"],
                "mitre": ["TA0040-Impact"],
                "cvss_base": 7.5,
                "exploitability": "Medium",
                "remediation": "Use Solidity 0.8+ with built-in overflow checks or SafeMath"
            },

            # Unchecked calls
            "unchecked-send": {
                "cwe": ["CWE-252", "CWE-754"],
                "swc": ["SWC-104"],
                "owasp": ["SC04-Unchecked-Call"],
                "iso27001": ["A.8.8", "A.14.2.5"],
                "nist_csf": ["DE.CM-1"],
                "mitre": ["TA0040-Impact"],
                "cvss_base": 6.5,
                "exploitability": "Medium",
                "remediation": "Always check return values of external calls"
            },

            # Delegatecall
            "delegatecall": {
                "cwe": ["CWE-829"],
                "swc": ["SWC-112"],
                "owasp": ["SC05-Delegatecall"],
                "iso27001": ["A.8.8", "A.14.2.5"],
                "nist_csf": ["PR.AC-4"],
                "mitre": ["TA0005-Defense-Evasion"],
                "cvss_base": 8.1,
                "exploitability": "Hard",
                "remediation": "Avoid delegatecall to untrusted contracts, use libraries"
            },

            # tx.origin
            "tx-origin": {
                "cwe": ["CWE-346"],
                "swc": ["SWC-115"],
                "owasp": ["SC02-Access-Control"],
                "iso27001": ["A.5.16", "A.8.2"],
                "nist_csf": ["PR.AC-7"],
                "mitre": ["TA0006-Credential-Access"],
                "cvss_base": 7.3,
                "exploitability": "Easy",
                "remediation": "Use msg.sender instead of tx.origin for authorization"
            },

            # Timestamp dependence
            "timestamp": {
                "cwe": ["CWE-330"],
                "swc": ["SWC-116"],
                "owasp": ["SC07-Bad-Randomness"],
                "iso27001": ["A.8.8"],
                "nist_csf": ["PR.DS-6"],
                "mitre": ["TA0040-Impact"],
                "cvss_base": 5.3,
                "exploitability": "Medium",
                "remediation": "Avoid using block.timestamp for critical logic, use oracles"
            },

            # Uninitialized storage
            "uninitialized-storage": {
                "cwe": ["CWE-824"],
                "swc": ["SWC-109"],
                "owasp": ["SC06-Uninitialized-Storage"],
                "iso27001": ["A.8.8", "A.14.2.5"],
                "nist_csf": ["PR.DS-6"],
                "mitre": ["TA0040-Impact"],
                "cvss_base": 7.8,
                "exploitability": "Medium",
                "remediation": "Always initialize storage variables explicitly"
            },

            # Locked ether
            "locked-ether": {
                "cwe": ["CWE-1082"],
                "swc": ["SWC-132"],
                "owasp": ["SC10-Denial-of-Service"],
                "iso27001": ["A.8.6"],
                "nist_csf": ["PR.DS-6"],
                "mitre": ["TA0040-Impact"],
                "cvss_base": 5.0,
                "exploitability": "Easy",
                "remediation": "Implement withdrawal pattern or payable functions"
            }
        }

        # Load custom mappings if provided
        if custom_path and Path(custom_path).exists():
            try:
                with open(custom_path, 'r') as f:
                    custom_db = json.load(f)
                default_db.update(custom_db)
                logger.info(f"Loaded custom mappings from {custom_path}")
            except Exception as e:
                logger.warning(f"Could not load custom mappings: {e}")

        return default_db

    def map_finding(
        self,
        vulnerability_type: str,
        severity: str,
        **kwargs
    ) -> ComplianceMapping:
        """
        Map a vulnerability finding to all applicable standards

        Args:
            vulnerability_type: Type of vulnerability
            severity: Severity level
            **kwargs: Additional context

        Returns:
            ComplianceMapping object
        """
        # Find best matching pattern
        mapping_key = self._find_mapping_key(vulnerability_type)
        mapping_data = self.mapping_db.get(mapping_key, {})

        # Build compliance mapping
        compliance = ComplianceMapping(
            vulnerability_type=vulnerability_type,
            severity=severity,
            cwe_ids=mapping_data.get('cwe', []),
            swc_ids=mapping_data.get('swc', []),
            owasp_categories=mapping_data.get('owasp', []),
            iso27001_controls=mapping_data.get('iso27001', ['A.8.8']),  # Default control
            nist_csf_functions=mapping_data.get('nist_csf', ['DE.CM-1']),
            mitre_tactics=mapping_data.get('mitre', ['TA0040-Impact']),
            gdpr_articles=self._map_to_gdpr(severity),
            eu_mica_requirements=self._map_to_mica(severity),
            eu_dora_requirements=self._map_to_dora(severity),
            cvss_score=self._calculate_cvss(mapping_data, severity),
            exploitability=mapping_data.get('exploitability', 'Medium'),
            business_impact=self._assess_business_impact(severity),
            remediation_guidance=mapping_data.get('remediation', 'Review and fix vulnerability'),
            compliance_notes=self._generate_compliance_notes(mapping_data, severity)
        )

        return compliance

    def _find_mapping_key(self, vuln_type: str) -> str:
        """Find best matching key in mapping database"""
        vuln_lower = vuln_type.lower()

        # Try exact match first
        if vuln_lower in self.mapping_db:
            return vuln_lower

        # Try partial matches
        for key in self.mapping_db.keys():
            if key in vuln_lower or vuln_lower in key:
                return key

        # Default to generic
        return "access-control"

    @staticmethod
    def _map_to_gdpr(severity: str) -> List[str]:
        """Map to GDPR articles (if applicable to smart contracts handling personal data)"""
        if severity in ['Critical', 'High']:
            return ['Article 32 (Security)', 'Article 33 (Breach Notification)']
        return ['Article 32 (Security)']

    @staticmethod
    def _map_to_mica(severity: str) -> List[str]:
        """Map to EU Markets in Crypto-Assets (MiCA) requirements"""
        if severity in ['Critical', 'High']:
            return [
                'MiCA Art. 60 (Operational Resilience)',
                'MiCA Art. 73 (Technology Risk)'
            ]
        return ['MiCA Art. 60 (Operational Resilience)']

    @staticmethod
    def _map_to_dora(severity: str) -> List[str]:
        """Map to EU Digital Operational Resilience Act (DORA)"""
        if severity in ['Critical', 'High']:
            return [
                'DORA Art. 8 (ICT Risk Management)',
                'DORA Art. 11 (Testing)',
                'DORA Art. 19 (Incident Reporting)'
            ]
        return ['DORA Art. 8 (ICT Risk Management)']

    @staticmethod
    def _calculate_cvss(mapping_data: Dict[str, Any], severity: str) -> float:
        """Calculate CVSS score"""
        base_score = mapping_data.get('cvss_base', 5.0)

        # Adjust for severity
        severity_adjustment = {
            'Critical': 1.5,
            'High': 1.2,
            'Medium': 1.0,
            'Low': 0.7,
            'Info': 0.3
        }

        adjusted = base_score * severity_adjustment.get(severity, 1.0)
        return min(round(adjusted, 1), 10.0)

    @staticmethod
    def _assess_business_impact(severity: str) -> str:
        """Assess business impact"""
        impact_map = {
            'Critical': 'Complete loss of funds or contract functionality',
            'High': 'Significant financial loss or service disruption',
            'Medium': 'Moderate risk to assets or reputation',
            'Low': 'Minor impact on operations',
            'Info': 'Informational, no direct impact'
        }
        return impact_map.get(severity, 'Unknown impact')

    def _generate_compliance_notes(
        self,
        mapping_data: Dict[str, Any],
        severity: str
    ) -> str:
        """Generate compliance notes"""
        notes = []

        # ISO 27001
        if severity in ['Critical', 'High']:
            notes.append(
                "🔴 ISO 27001: Immediate action required (A.8.8 - Technical Vulnerability Management)"
            )
        else:
            notes.append(
                "🟡 ISO 27001: Schedule remediation (A.8.8)"
            )

        # NIST CSF
        nist = mapping_data.get('nist_csf', [])
        if nist:
            notes.append(f"NIST CSF: {', '.join(nist)}")

        # OWASP
        owasp = mapping_data.get('owasp', [])
        if owasp:
            notes.append(f"OWASP SC Top 10: {', '.join(owasp)}")

        return ' | '.join(notes)

    def generate_compliance_matrix(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate compliance matrix for all findings

        Args:
            findings: List of vulnerability findings

        Returns:
            Comprehensive compliance matrix
        """
        matrix = {
            'total_findings': len(findings),
            'by_severity': {},
            'standards_coverage': {
                'cwe': set(),
                'swc': set(),
                'owasp': set(),
                'iso27001': set(),
                'nist_csf': set(),
                'mitre': set()
            },
            'regulatory_compliance': {
                'gdpr': [],
                'eu_mica': [],
                'eu_dora': []
            },
            'compliance_score': 0.0,
            'critical_gaps': [],
            'recommendations': []
        }

        # Process each finding
        for finding in findings:
            severity = finding.get('severity', 'Unknown')
            matrix['by_severity'][severity] = matrix['by_severity'].get(severity, 0) + 1

            # Map to standards
            mapping = self.map_finding(
                finding.get('vulnerability_type', ''),
                severity
            )

            # Aggregate coverage
            matrix['standards_coverage']['cwe'].update(mapping.cwe_ids)
            matrix['standards_coverage']['swc'].update(mapping.swc_ids)
            matrix['standards_coverage']['owasp'].update(mapping.owasp_categories)
            matrix['standards_coverage']['iso27001'].update(mapping.iso27001_controls)
            matrix['standards_coverage']['nist_csf'].update(mapping.nist_csf_functions)
            matrix['standards_coverage']['mitre'].update(mapping.mitre_tactics)

            # Regulatory
            matrix['regulatory_compliance']['gdpr'].extend(mapping.gdpr_articles)
            matrix['regulatory_compliance']['eu_mica'].extend(mapping.eu_mica_requirements)
            matrix['regulatory_compliance']['eu_dora'].extend(mapping.eu_dora_requirements)

        # Convert sets to lists
        for key in matrix['standards_coverage']:
            matrix['standards_coverage'][key] = sorted(list(matrix['standards_coverage'][key]))

        # Calculate compliance score (0-100)
        matrix['compliance_score'] = self._calculate_compliance_score(matrix)

        # Identify gaps
        matrix['critical_gaps'] = self._identify_gaps(matrix)

        # Generate recommendations
        matrix['recommendations'] = self._generate_recommendations(matrix)

        return matrix

    @staticmethod
    def _calculate_compliance_score(matrix: Dict[str, Any]) -> float:
        """Calculate overall compliance score"""
        total_findings = matrix['total_findings']
        if total_findings == 0:
            return 100.0

        # Penalize based on severity
        critical = matrix['by_severity'].get('Critical', 0)
        high = matrix['by_severity'].get('High', 0)
        medium = matrix['by_severity'].get('Medium', 0)

        penalty = (critical * 20) + (high * 10) + (medium * 5)
        score = max(0, 100 - penalty)

        return round(score, 2)

    @staticmethod
    def _identify_gaps(matrix: Dict[str, Any]) -> List[str]:
        """Identify critical compliance gaps"""
        gaps = []

        if matrix['by_severity'].get('Critical', 0) > 0:
            gaps.append("🔴 Critical vulnerabilities present - deployment not recommended")

        if matrix['by_severity'].get('High', 0) > 3:
            gaps.append("🟠 Multiple high-severity issues - thorough remediation required")

        # Check ISO 27001 coverage
        iso_controls = matrix['standards_coverage']['iso27001']
        if 'A.14.2.5' in iso_controls:
            gaps.append("ISO 27001 A.14.2.5 (Secure Engineering Principles) - violations detected")

        return gaps

    @staticmethod
    def _generate_recommendations(matrix: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        score = matrix['compliance_score']

        if score < 50:
            recommendations.append("⛔ Contract requires major rework - do not deploy")
        elif score < 70:
            recommendations.append("⚠️ Address all critical and high-severity issues before deployment")
        elif score < 90:
            recommendations.append("✅ Address medium-severity issues and conduct manual audit")
        else:
            recommendations.append("✅ Contract passes automated checks - ready for manual audit")

        # Standard-specific recommendations
        recommendations.append(
            "ISO 27001: Document all findings in vulnerability management log (A.8.8)"
        )
        recommendations.append(
            "NIST CSF: Validate remediation through testing (PR.IP-10)"
        )

        return recommendations

    def export_evidence(
        self,
        matrix: Dict[str, Any],
        output_path: str
    ) -> None:
        """
        Export compliance evidence for auditors

        Args:
            matrix: Compliance matrix
            output_path: Path to output JSON file
        """
        evidence = {
            'generated_at': '2025-01-01T00:00:00Z',  # Use actual timestamp
            'miesc_version': '3.0.0',
            'compliance_matrix': matrix,
            'attestation': 'This report was generated by MIESC - an automated security assessment tool'
        }

        with open(output_path, 'w') as f:
            json.dump(evidence, f, indent=2)

        logger.info(f"Compliance evidence exported to {output_path}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    mapper = PolicyMapper()

    # Example finding
    finding = {
        'vulnerability_type': 'reentrancy-eth',
        'severity': 'High'
    }

    mapping = mapper.map_finding(**finding)
    print(json.dumps(mapping.to_dict(), indent=2))
