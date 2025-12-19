"""
MIESC Compliance Mapper - Multi-Framework Security Standards Mapping

Maps security findings to international compliance frameworks:
- SWC (Smart Contract Weakness Classification)
- CWE (Common Weakness Enumeration)
- ISO/IEC 27001:2022
- NIST Cybersecurity Framework (CSF)
- OWASP Smart Contract Top 10
- MITRE ATT&CK (Blockchain-specific TTPs)

Scientific Foundation:
- Compliance mapping methodology based on ISO 27001 Annex A controls
- Cross-referencing using official SWC Registry and CWE database
- NIST CSF function mapping (Identify, Protect, Detect, Respond, Recover)

Author: Fernando Boiero
Thesis: Master's in Cyberdefense - UNDEF
Version: 4.1.0
"""

import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    SWC = "SWC"  # Smart Contract Weakness Classification
    CWE = "CWE"  # Common Weakness Enumeration
    ISO27001 = "ISO27001"  # ISO/IEC 27001:2022
    NIST_CSF = "NIST_CSF"  # NIST Cybersecurity Framework
    OWASP_SC = "OWASP_SC"  # OWASP Smart Contract Top 10
    MITRE = "MITRE"  # MITRE ATT&CK


@dataclass
class ComplianceMapping:
    """Mapping of a finding to compliance frameworks."""
    swc_id: Optional[str] = None
    swc_title: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    iso27001_controls: List[str] = field(default_factory=list)
    nist_csf_functions: List[str] = field(default_factory=list)
    owasp_sc_categories: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    compliance_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ComplianceReport:
    """Compliance assessment report."""
    total_findings: int
    mapped_findings: int
    frameworks_covered: List[str]
    coverage_by_framework: Dict[str, float]
    gaps: List[Dict[str, Any]]
    recommendations: List[str]
    overall_score: float
    findings_by_control: Dict[str, List[str]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ComplianceMapper:
    """
    Maps security vulnerabilities to compliance frameworks.

    Provides comprehensive mapping from smart contract vulnerabilities
    to international security standards for compliance reporting.

    Usage:
        mapper = ComplianceMapper()

        # Map a single finding
        mapping = mapper.map_finding(finding)

        # Generate compliance report
        report = mapper.generate_report(findings)

        # Get ISO 27001 gaps
        gaps = mapper.get_iso27001_gaps(findings)
    """

    # =========================================================================
    # SWC TO CWE MAPPING
    # Based on SWC Registry: https://swcregistry.io/
    # =========================================================================
    SWC_TO_CWE = {
        "SWC-100": ["CWE-676"],  # Function Default Visibility
        "SWC-101": ["CWE-190", "CWE-191"],  # Integer Overflow/Underflow
        "SWC-102": ["CWE-824"],  # Outdated Compiler Version
        "SWC-103": ["CWE-749"],  # Floating Pragma
        "SWC-104": ["CWE-284"],  # Unchecked Call Return Value
        "SWC-105": ["CWE-693"],  # Unprotected Ether Withdrawal
        "SWC-106": ["CWE-362"],  # Unprotected SELFDESTRUCT
        "SWC-107": ["CWE-841"],  # Reentrancy
        "SWC-108": ["CWE-676"],  # State Variable Default Visibility
        "SWC-109": ["CWE-691"],  # Uninitialized Storage Pointer
        "SWC-110": ["CWE-670"],  # Assert Violation
        "SWC-111": ["CWE-703"],  # Use of Deprecated Functions
        "SWC-112": ["CWE-829"],  # Delegatecall to Untrusted Callee
        "SWC-113": ["CWE-400"],  # DoS with Failed Call
        "SWC-114": ["CWE-362"],  # Transaction Order Dependence
        "SWC-115": ["CWE-330"],  # Authorization through tx.origin
        "SWC-116": ["CWE-330"],  # Block values as proxy for time
        "SWC-117": ["CWE-749"],  # Signature Malleability
        "SWC-118": ["CWE-1104"],  # Incorrect Constructor Name
        "SWC-119": ["CWE-20"],  # Shadowing State Variables
        "SWC-120": ["CWE-330"],  # Weak Sources of Randomness
        "SWC-121": ["CWE-345"],  # Missing Protection against Signature Replay
        "SWC-122": ["CWE-345"],  # Lack of Proper Signature Verification
        "SWC-123": ["CWE-703"],  # Requirement Violation
        "SWC-124": ["CWE-22"],  # Write to Arbitrary Storage Location
        "SWC-125": ["CWE-284"],  # Incorrect Inheritance Order
        "SWC-126": ["CWE-330"],  # Insufficient Gas Griefing
        "SWC-127": ["CWE-22"],  # Arbitrary Jump with Function Type Variable
        "SWC-128": ["CWE-400"],  # DoS With Block Gas Limit
        "SWC-129": ["CWE-330"],  # Typographical Error
        "SWC-130": ["CWE-691"],  # Right-To-Left Override Control Character
        "SWC-131": ["CWE-330"],  # Presence of Unused Variables
        "SWC-132": ["CWE-400"],  # Unexpected Ether Balance
        "SWC-133": ["CWE-476"],  # Hash Collision with Multiple Variable Length Arguments
        "SWC-134": ["CWE-680"],  # Message call with hardcoded gas amount
        "SWC-135": ["CWE-471"],  # Code With No Effects
        "SWC-136": ["CWE-829"],  # Unencrypted Private Data On-Chain
    }

    # =========================================================================
    # CWE TO ISO 27001:2022 MAPPING
    # Based on ISO 27001 Annex A controls
    # =========================================================================
    CWE_TO_ISO27001 = {
        "CWE-20": ["A.8.28"],  # Input validation
        "CWE-22": ["A.8.3", "A.8.9"],  # Path traversal -> Access control
        "CWE-190": ["A.8.28", "A.8.26"],  # Integer overflow -> Secure coding
        "CWE-191": ["A.8.28", "A.8.26"],  # Integer underflow
        "CWE-284": ["A.5.15", "A.8.2", "A.8.3"],  # Access control
        "CWE-330": ["A.8.24"],  # Weak randomness -> Cryptography
        "CWE-345": ["A.8.24", "A.8.5"],  # Signature verification
        "CWE-362": ["A.8.26", "A.8.28"],  # Race conditions
        "CWE-400": ["A.8.6", "A.8.22"],  # Resource consumption -> Capacity mgmt
        "CWE-471": ["A.8.25"],  # Modification of assumed-immutable data
        "CWE-476": ["A.8.28"],  # NULL pointer dereference
        "CWE-670": ["A.8.28", "A.8.29"],  # Incorrect control flow
        "CWE-676": ["A.8.26", "A.8.28"],  # Use of potentially dangerous function
        "CWE-680": ["A.8.9"],  # Integer overflow to buffer overflow
        "CWE-691": ["A.8.28"],  # Insufficient control flow management
        "CWE-693": ["A.8.3", "A.5.15"],  # Protection mechanism failure
        "CWE-703": ["A.8.28", "A.8.29"],  # Improper error handling
        "CWE-749": ["A.8.26", "A.8.32"],  # Exposed dangerous method
        "CWE-824": ["A.8.9", "A.8.31"],  # Uninitialized pointer
        "CWE-829": ["A.8.21", "A.5.19"],  # Inclusion of untrusted functionality
        "CWE-841": ["A.8.26", "A.8.28"],  # Improper enforcement of behavioral workflow
        "CWE-1104": ["A.8.26", "A.8.28"],  # Use of unmaintained third-party components
    }

    # =========================================================================
    # ISO 27001:2022 CONTROLS DESCRIPTION
    # =========================================================================
    ISO27001_CONTROLS = {
        "A.5.15": "Access control - Policies and rules",
        "A.5.19": "Information security in supplier relationships",
        "A.8.2": "Privileged access rights",
        "A.8.3": "Information access restriction",
        "A.8.5": "Secure authentication",
        "A.8.6": "Capacity management",
        "A.8.9": "Configuration management",
        "A.8.21": "Security of network services",
        "A.8.22": "Segregation of networks",
        "A.8.24": "Use of cryptography",
        "A.8.25": "Secure development life cycle",
        "A.8.26": "Application security requirements",
        "A.8.28": "Secure coding",
        "A.8.29": "Security testing in development and acceptance",
        "A.8.31": "Separation of development, test and production environments",
        "A.8.32": "Change management",
    }

    # =========================================================================
    # CWE TO NIST CSF MAPPING
    # =========================================================================
    CWE_TO_NIST_CSF = {
        "CWE-20": ["PR.DS-6", "DE.CM-4"],  # Protect Data Security, Detect CM
        "CWE-22": ["PR.AC-4", "PR.DS-5"],  # Access Control, Data Protection
        "CWE-190": ["PR.DS-6", "ID.RA-1"],  # Data Security, Risk Assessment
        "CWE-191": ["PR.DS-6", "ID.RA-1"],
        "CWE-284": ["PR.AC-1", "PR.AC-4", "PR.AC-6"],  # Access Control
        "CWE-330": ["PR.DS-2", "PR.DS-6"],  # Data Protection
        "CWE-345": ["PR.DS-6", "DE.CM-4"],  # Data Security
        "CWE-362": ["PR.DS-6", "DE.CM-1"],  # Detect Continuous Monitoring
        "CWE-400": ["PR.DS-4", "DE.AE-1"],  # Capacity, Anomaly Detection
        "CWE-471": ["PR.DS-6"],
        "CWE-476": ["PR.DS-6"],
        "CWE-670": ["PR.IP-2"],  # Information Protection Processes
        "CWE-676": ["PR.IP-2", "ID.RA-1"],
        "CWE-680": ["PR.DS-6"],
        "CWE-691": ["PR.IP-2"],
        "CWE-693": ["PR.AC-4", "PR.AC-5"],  # Access Control
        "CWE-703": ["RS.AN-1", "DE.AE-2"],  # Response Analysis
        "CWE-749": ["PR.AC-4"],
        "CWE-824": ["PR.DS-6"],
        "CWE-829": ["PR.DS-6", "ID.SC-2"],  # Supply Chain
        "CWE-841": ["PR.IP-2", "DE.CM-4"],
        "CWE-1104": ["ID.SC-2", "PR.IP-2"],  # Supply Chain Risk
    }

    # =========================================================================
    # NIST CSF FUNCTIONS
    # =========================================================================
    NIST_CSF_FUNCTIONS = {
        "ID": "Identify",
        "PR": "Protect",
        "DE": "Detect",
        "RS": "Respond",
        "RC": "Recover",
    }

    # =========================================================================
    # OWASP SMART CONTRACT TOP 10 (2023)
    # =========================================================================
    SWC_TO_OWASP_SC = {
        "SWC-107": ["SC01"],  # Reentrancy
        "SWC-101": ["SC02"],  # Arithmetic Issues
        "SWC-104": ["SC03"],  # Unchecked Return Values
        "SWC-115": ["SC04"],  # Access Control
        "SWC-105": ["SC04"],
        "SWC-106": ["SC04"],
        "SWC-114": ["SC05"],  # Front-Running
        "SWC-113": ["SC06"],  # Denial of Service
        "SWC-128": ["SC06"],
        "SWC-120": ["SC07"],  # Bad Randomness
        "SWC-116": ["SC07"],
        "SWC-112": ["SC08"],  # Delegatecall
        "SWC-100": ["SC09"],  # Gas Griefing
        "SWC-126": ["SC09"],
        "SWC-136": ["SC10"],  # Privacy
    }

    OWASP_SC_CATEGORIES = {
        "SC01": "Reentrancy Attacks",
        "SC02": "Arithmetic Issues",
        "SC03": "Unchecked External Calls",
        "SC04": "Access Control Vulnerabilities",
        "SC05": "Front-Running / Transaction Ordering",
        "SC06": "Denial of Service",
        "SC07": "Bad Randomness",
        "SC08": "Delegatecall Vulnerabilities",
        "SC09": "Gas Griefing",
        "SC10": "Privacy Violations",
    }

    # =========================================================================
    # VULNERABILITY TYPE TO SWC MAPPING
    # =========================================================================
    VULN_TYPE_TO_SWC = {
        # Reentrancy variants
        "reentrancy": "SWC-107",
        "reentrancy-eth": "SWC-107",
        "reentrancy-no-eth": "SWC-107",
        "reentrancy-benign": "SWC-107",
        "reentrancy-events": "SWC-107",
        "reentrancy-unlimited-gas": "SWC-107",

        # Integer issues
        "integer-overflow": "SWC-101",
        "integer-underflow": "SWC-101",
        "arithmetic": "SWC-101",
        "unchecked-math": "SWC-101",

        # Access control
        "unprotected-upgrade": "SWC-105",
        "suicidal": "SWC-106",
        "selfdestruct": "SWC-106",
        "tx-origin": "SWC-115",
        "tx.origin": "SWC-115",
        "missing-access-control": "SWC-105",
        "access-control": "SWC-105",

        # External calls
        "unchecked-call": "SWC-104",
        "unchecked-lowlevel": "SWC-104",
        "unchecked-send": "SWC-104",
        "unchecked-return": "SWC-104",
        "low-level-calls": "SWC-104",

        # Delegatecall
        "delegatecall": "SWC-112",
        "delegatecall-loop": "SWC-112",
        "controlled-delegatecall": "SWC-112",

        # DoS
        "dos": "SWC-113",
        "dos-with-block-gas-limit": "SWC-128",
        "gas-limit": "SWC-128",

        # Randomness
        "weak-randomness": "SWC-120",
        "bad-randomness": "SWC-120",
        "block-timestamp": "SWC-116",
        "timestamp": "SWC-116",

        # Front-running
        "front-running": "SWC-114",
        "transaction-order-dependence": "SWC-114",
        "tod": "SWC-114",

        # Signature
        "signature-malleability": "SWC-117",
        "missing-signature-verification": "SWC-122",
        "signature-replay": "SWC-121",

        # Visibility
        "function-visibility": "SWC-100",
        "state-visibility": "SWC-108",

        # Compiler
        "outdated-compiler": "SWC-102",
        "floating-pragma": "SWC-103",
        "pragma": "SWC-103",

        # Storage
        "uninitialized-storage": "SWC-109",
        "arbitrary-storage": "SWC-124",
        "storage-pointer": "SWC-109",

        # Assert
        "assert-violation": "SWC-110",
        "require-violation": "SWC-123",

        # Shadowing
        "shadowing": "SWC-119",
        "shadowing-state": "SWC-119",

        # Other
        "deprecated-functions": "SWC-111",
        "incorrect-constructor": "SWC-118",
        "unused-variables": "SWC-131",
        "code-with-no-effects": "SWC-135",
        "right-to-left-override": "SWC-130",
        "hash-collision": "SWC-133",
        "hardcoded-gas": "SWC-134",
    }

    def __init__(self):
        """Initialize the compliance mapper."""
        logger.info("ComplianceMapper initialized")

    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type string."""
        return vuln_type.lower().replace("_", "-").replace(" ", "-")

    def get_swc_for_type(self, vuln_type: str) -> Optional[str]:
        """Get SWC ID for a vulnerability type."""
        normalized = self._normalize_vuln_type(vuln_type)
        return self.VULN_TYPE_TO_SWC.get(normalized)

    def map_finding(self, finding: Dict[str, Any]) -> ComplianceMapping:
        """
        Map a single finding to compliance frameworks.

        Args:
            finding: Finding dictionary with 'type' or 'vulnerability_type' field

        Returns:
            ComplianceMapping with all framework mappings
        """
        vuln_type = finding.get("type") or finding.get("vulnerability_type", "")
        existing_swc = finding.get("swc_id") or finding.get("swc")
        existing_cwe = finding.get("cwe_id") or finding.get("cwe")

        # Determine SWC
        swc_id = existing_swc or self.get_swc_for_type(vuln_type)

        # Get CWE mappings
        cwe_ids = []
        if existing_cwe:
            cwe_ids = [existing_cwe] if isinstance(existing_cwe, str) else existing_cwe
        elif swc_id and swc_id in self.SWC_TO_CWE:
            cwe_ids = self.SWC_TO_CWE[swc_id]

        # Get ISO 27001 controls
        iso_controls = set()
        for cwe in cwe_ids:
            if cwe in self.CWE_TO_ISO27001:
                iso_controls.update(self.CWE_TO_ISO27001[cwe])

        # Get NIST CSF functions
        nist_functions = set()
        for cwe in cwe_ids:
            if cwe in self.CWE_TO_NIST_CSF:
                nist_functions.update(self.CWE_TO_NIST_CSF[cwe])

        # Get OWASP SC categories
        owasp_categories = set()
        if swc_id and swc_id in self.SWC_TO_OWASP_SC:
            owasp_categories.update(self.SWC_TO_OWASP_SC[swc_id])

        # Calculate compliance score (based on coverage)
        total_possible = 4  # SWC, CWE, ISO, NIST
        covered = sum([
            1 if swc_id else 0,
            1 if cwe_ids else 0,
            1 if iso_controls else 0,
            1 if nist_functions else 0,
        ])
        compliance_score = covered / total_possible

        # Get SWC title
        swc_title = None
        if swc_id:
            # Extract from SWC registry (simplified)
            swc_titles = {
                "SWC-100": "Function Default Visibility",
                "SWC-101": "Integer Overflow and Underflow",
                "SWC-102": "Outdated Compiler Version",
                "SWC-103": "Floating Pragma",
                "SWC-104": "Unchecked Call Return Value",
                "SWC-105": "Unprotected Ether Withdrawal",
                "SWC-106": "Unprotected SELFDESTRUCT",
                "SWC-107": "Reentrancy",
                "SWC-108": "State Variable Default Visibility",
                "SWC-109": "Uninitialized Storage Pointer",
                "SWC-110": "Assert Violation",
                "SWC-111": "Use of Deprecated Solidity Functions",
                "SWC-112": "Delegatecall to Untrusted Callee",
                "SWC-113": "DoS with Failed Call",
                "SWC-114": "Transaction Order Dependence",
                "SWC-115": "Authorization through tx.origin",
                "SWC-116": "Block values as a proxy for time",
                "SWC-117": "Signature Malleability",
                "SWC-118": "Incorrect Constructor Name",
                "SWC-119": "Shadowing State Variables",
                "SWC-120": "Weak Sources of Randomness",
                "SWC-121": "Missing Protection against Signature Replay",
                "SWC-122": "Lack of Proper Signature Verification",
                "SWC-123": "Requirement Violation",
                "SWC-124": "Write to Arbitrary Storage Location",
                "SWC-125": "Incorrect Inheritance Order",
                "SWC-126": "Insufficient Gas Griefing",
                "SWC-127": "Arbitrary Jump with Function Type Variable",
                "SWC-128": "DoS With Block Gas Limit",
                "SWC-129": "Typographical Error",
                "SWC-130": "Right-To-Left Override Control Character",
                "SWC-131": "Presence of Unused Variables",
                "SWC-132": "Unexpected Ether Balance",
                "SWC-133": "Hash Collision with Variable Length Arguments",
                "SWC-134": "Message call with hardcoded gas amount",
                "SWC-135": "Code With No Effects",
                "SWC-136": "Unencrypted Private Data On-Chain",
            }
            swc_title = swc_titles.get(swc_id)

        return ComplianceMapping(
            swc_id=swc_id,
            swc_title=swc_title,
            cwe_ids=list(cwe_ids),
            iso27001_controls=sorted(list(iso_controls)),
            nist_csf_functions=sorted(list(nist_functions)),
            owasp_sc_categories=sorted(list(owasp_categories)),
            compliance_score=compliance_score,
        )

    def map_findings(self, findings: List[Dict[str, Any]]) -> List[Tuple[Dict, ComplianceMapping]]:
        """Map multiple findings to compliance frameworks."""
        return [(f, self.map_finding(f)) for f in findings]

    def generate_report(self, findings: List[Dict[str, Any]]) -> ComplianceReport:
        """
        Generate comprehensive compliance report.

        Args:
            findings: List of security findings

        Returns:
            ComplianceReport with coverage analysis and gaps
        """
        mappings = self.map_findings(findings)

        # Count mapped findings
        mapped_count = sum(1 for _, m in mappings if m.swc_id or m.cwe_ids)

        # Collect all controls/functions used
        all_iso_controls: Set[str] = set()
        all_nist_functions: Set[str] = set()
        all_owasp_categories: Set[str] = set()
        findings_by_control: Dict[str, List[str]] = {}

        for finding, mapping in mappings:
            all_iso_controls.update(mapping.iso27001_controls)
            all_nist_functions.update(mapping.nist_csf_functions)
            all_owasp_categories.update(mapping.owasp_sc_categories)

            # Track findings by ISO control
            for control in mapping.iso27001_controls:
                if control not in findings_by_control:
                    findings_by_control[control] = []
                findings_by_control[control].append(
                    finding.get("title", finding.get("type", "Unknown"))
                )

        # Calculate coverage
        total_iso_controls = len(self.ISO27001_CONTROLS)
        total_owasp = len(self.OWASP_SC_CATEGORIES)

        coverage = {
            "ISO27001": len(all_iso_controls) / total_iso_controls if total_iso_controls else 0,
            "NIST_CSF": len(all_nist_functions) / 23 if all_nist_functions else 0,  # ~23 subcategories
            "OWASP_SC": len(all_owasp_categories) / total_owasp if total_owasp else 0,
        }

        # Identify gaps (ISO controls not covered)
        covered_controls = set(findings_by_control.keys())
        gap_controls = set(self.ISO27001_CONTROLS.keys()) - covered_controls

        gaps = [
            {
                "framework": "ISO27001",
                "control": ctrl,
                "description": self.ISO27001_CONTROLS.get(ctrl, ""),
                "severity": "info",
            }
            for ctrl in sorted(gap_controls)
        ]

        # Generate recommendations
        recommendations = []
        if coverage["ISO27001"] < 0.5:
            recommendations.append(
                "Consider additional security controls to improve ISO 27001 compliance coverage"
            )
        if not all_nist_functions or len(all_nist_functions) < 5:
            recommendations.append(
                "Expand monitoring to cover more NIST CSF functions"
            )
        if mapped_count < len(findings):
            recommendations.append(
                f"{len(findings) - mapped_count} findings could not be mapped to standards - review for custom categorization"
            )

        # Calculate overall score
        overall_score = sum(coverage.values()) / len(coverage)

        return ComplianceReport(
            total_findings=len(findings),
            mapped_findings=mapped_count,
            frameworks_covered=["SWC", "CWE", "ISO27001", "NIST_CSF", "OWASP_SC"],
            coverage_by_framework=coverage,
            gaps=gaps,
            recommendations=recommendations,
            overall_score=round(overall_score, 4),
            findings_by_control=findings_by_control,
        )

    def get_iso27001_gaps(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get ISO 27001 controls not covered by findings."""
        report = self.generate_report(findings)
        return [g for g in report.gaps if g["framework"] == "ISO27001"]

    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a finding with compliance mappings.

        Args:
            finding: Original finding

        Returns:
            Finding with added compliance data
        """
        mapping = self.map_finding(finding)

        enriched = finding.copy()
        enriched["compliance"] = {
            "swc_id": mapping.swc_id,
            "swc_title": mapping.swc_title,
            "cwe_ids": mapping.cwe_ids,
            "iso27001_controls": mapping.iso27001_controls,
            "nist_csf_functions": mapping.nist_csf_functions,
            "owasp_sc_categories": mapping.owasp_sc_categories,
            "compliance_score": mapping.compliance_score,
        }

        return enriched


# Singleton instance
_mapper_instance: Optional[ComplianceMapper] = None


def get_compliance_mapper() -> ComplianceMapper:
    """Get singleton ComplianceMapper instance."""
    global _mapper_instance
    if _mapper_instance is None:
        _mapper_instance = ComplianceMapper()
    return _mapper_instance
