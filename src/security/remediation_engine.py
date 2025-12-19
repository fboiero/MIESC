#!/usr/bin/env python3
"""
MIESC Remediation Engine

Enriches vulnerability findings with actionable remediation suggestions,
prioritized fix recommendations, and code examples.

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from pathlib import Path
import re

from .remediations import (
    Remediation,
    REMEDIATIONS,
    get_remediation,
    get_remediation_by_type,
    SECURITY_CHECKLIST,
)


class FixEffort(Enum):
    """Estimated effort to implement fix."""
    TRIVIAL = "trivial"      # < 30 min
    LOW = "low"              # 30 min - 2 hours
    MEDIUM = "medium"        # 2 - 8 hours
    HIGH = "high"            # 1 - 3 days
    COMPLEX = "complex"      # > 3 days


class FixRisk(Enum):
    """Risk level of applying fix."""
    SAFE = "safe"            # No breaking changes expected
    LOW = "low"              # Minor changes, easy rollback
    MEDIUM = "medium"        # May affect dependent code
    HIGH = "high"            # Breaking changes likely


@dataclass
class EnrichedFinding:
    """A finding enriched with remediation information."""
    # Original finding data
    id: str
    type: str
    severity: str
    message: str
    location: Dict[str, Any]

    # Remediation data
    swc_id: Optional[str] = None
    remediation: Optional[Remediation] = None
    fix_effort: FixEffort = FixEffort.MEDIUM
    fix_risk: FixRisk = FixRisk.LOW

    # Prioritization
    priority_score: float = 0.0
    priority_rank: int = 0

    # Additional context
    affected_functions: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'id': self.id,
            'type': self.type,
            'severity': self.severity,
            'message': self.message,
            'location': self.location,
            'swc_id': self.swc_id,
            'priority': {
                'score': round(self.priority_score, 2),
                'rank': self.priority_rank,
            },
            'fix': {
                'effort': self.fix_effort.value,
                'risk': self.fix_risk.value,
            },
        }

        if self.remediation:
            result['remediation'] = {
                'title': self.remediation.title,
                'description': self.remediation.description,
                'fix': self.remediation.fix,
                'example_vulnerable': self.remediation.example_vulnerable,
                'example_fixed': self.remediation.example_fixed,
                'references': self.remediation.references,
                'gas_impact': self.remediation.gas_impact,
                'breaking_change': self.remediation.breaking_change,
            }

        if self.affected_functions:
            result['affected_functions'] = self.affected_functions
        if self.related_findings:
            result['related_findings'] = self.related_findings

        return result


@dataclass
class RemediationReport:
    """Complete remediation report for a contract."""
    contract_name: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    enriched_findings: List[EnrichedFinding]
    fix_plan: List[Dict[str, Any]]
    estimated_total_effort: str
    security_checklist_status: Dict[str, bool]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'contract': self.contract_name,
            'summary': {
                'total_findings': self.total_findings,
                'by_severity': {
                    'critical': self.critical_count,
                    'high': self.high_count,
                    'medium': self.medium_count,
                    'low': self.low_count,
                },
            },
            'findings': [f.to_dict() for f in self.enriched_findings],
            'fix_plan': self.fix_plan,
            'estimated_effort': self.estimated_total_effort,
            'checklist_status': self.security_checklist_status,
        }


class RemediationEngine:
    """
    Engine for enriching findings with remediation suggestions.

    Features:
    - Maps findings to SWC-based remediations
    - Calculates fix effort and risk
    - Prioritizes fixes by severity and effort
    - Generates actionable fix plans
    - Tracks security checklist compliance
    """

    # Severity weights for prioritization
    SEVERITY_WEIGHTS = {
        'critical': 10.0,
        'high': 7.0,
        'medium': 4.0,
        'low': 2.0,
        'informational': 1.0,
        'info': 1.0,
    }

    # Effort estimates based on SWC ID
    EFFORT_MAP = {
        'SWC-100': FixEffort.TRIVIAL,   # Add visibility
        'SWC-101': FixEffort.MEDIUM,    # SafeMath / 0.8
        'SWC-102': FixEffort.TRIVIAL,   # Update pragma
        'SWC-103': FixEffort.TRIVIAL,   # Lock pragma
        'SWC-104': FixEffort.LOW,       # Check return value
        'SWC-105': FixEffort.MEDIUM,    # Access control
        'SWC-106': FixEffort.MEDIUM,    # Protected selfdestruct
        'SWC-107': FixEffort.HIGH,      # Reentrancy
        'SWC-108': FixEffort.TRIVIAL,   # Variable visibility
        'SWC-109': FixEffort.MEDIUM,    # Storage pointer
        'SWC-110': FixEffort.LOW,       # Assert -> require
        'SWC-111': FixEffort.LOW,       # Update deprecated
        'SWC-112': FixEffort.HIGH,      # Delegatecall
        'SWC-113': FixEffort.HIGH,      # DoS - pull pattern
        'SWC-114': FixEffort.HIGH,      # Front-running
        'SWC-115': FixEffort.LOW,       # tx.origin
        'SWC-116': FixEffort.LOW,       # Timestamp
        'SWC-117': FixEffort.MEDIUM,    # Signature
        'SWC-120': FixEffort.HIGH,      # VRF integration
        'SWC-123': FixEffort.MEDIUM,    # Requirements
        'SWC-124': FixEffort.MEDIUM,    # Bounds check
        'SWC-126': FixEffort.LOW,       # Gas forwarding
        'SWC-128': FixEffort.MEDIUM,    # Gas limit DoS
        'SWC-129': FixEffort.LOW,       # Short address
    }

    # Risk levels based on SWC ID
    RISK_MAP = {
        'SWC-100': FixRisk.SAFE,
        'SWC-101': FixRisk.LOW,
        'SWC-102': FixRisk.LOW,
        'SWC-103': FixRisk.SAFE,
        'SWC-104': FixRisk.LOW,
        'SWC-105': FixRisk.HIGH,      # Breaking change
        'SWC-106': FixRisk.HIGH,      # Breaking change
        'SWC-107': FixRisk.MEDIUM,
        'SWC-108': FixRisk.SAFE,
        'SWC-109': FixRisk.MEDIUM,
        'SWC-110': FixRisk.SAFE,
        'SWC-111': FixRisk.LOW,
        'SWC-112': FixRisk.HIGH,
        'SWC-113': FixRisk.MEDIUM,
        'SWC-114': FixRisk.MEDIUM,
        'SWC-115': FixRisk.LOW,
        'SWC-116': FixRisk.LOW,
        'SWC-117': FixRisk.LOW,
        'SWC-120': FixRisk.MEDIUM,
        'SWC-123': FixRisk.LOW,
        'SWC-124': FixRisk.LOW,
        'SWC-126': FixRisk.SAFE,
        'SWC-128': FixRisk.MEDIUM,
        'SWC-129': FixRisk.LOW,
    }

    # Type to canonical mapping for better remediation matching
    TYPE_CANONICAL = {
        'reentrancy-eth': 'reentrancy',
        'reentrancy-benign': 'reentrancy',
        'reentrancy-no-eth': 'reentrancy',
        'reentrancy-events': 'reentrancy',
        'arbitrary-send': 'access-control',
        'arbitrary-send-eth': 'access-control',
        'unprotected-upgrade': 'access-control',
        'controlled-delegatecall': 'delegatecall',
        'unchecked-lowlevel': 'unchecked-call',
        'unchecked-send': 'unchecked-call',
        'integer-overflow': 'overflow',
        'integer-underflow': 'underflow',
        'weak-prng': 'weak-randomness',
        'block-timestamp': 'timestamp',
        'denial-of-service': 'dos',
    }

    def __init__(self):
        """Initialize the remediation engine."""
        self._enriched_findings: List[EnrichedFinding] = []
        self._findings_by_type: Dict[str, List[EnrichedFinding]] = {}

    def enrich_finding(self, finding: Dict[str, Any]) -> EnrichedFinding:
        """
        Enrich a single finding with remediation information.

        Args:
            finding: Raw finding dictionary

        Returns:
            EnrichedFinding with remediation data
        """
        # Extract basic info
        finding_id = finding.get('id', f"FIND-{hash(str(finding)) % 10000:04d}")
        finding_type = finding.get('type', finding.get('canonical_type', 'unknown'))
        severity = finding.get('severity', 'medium').lower()
        message = finding.get('message', finding.get('description', ''))
        location = finding.get('location', {})
        swc_id = finding.get('swc_id', '')

        # Normalize type
        canonical_type = self.TYPE_CANONICAL.get(finding_type.lower(), finding_type.lower())

        # Find remediation
        remediation = None
        if swc_id:
            remediation = get_remediation(swc_id)
        if not remediation:
            remediation = get_remediation_by_type(canonical_type)
        if not remediation:
            remediation = get_remediation_by_type(finding_type)

        # Determine effort and risk
        fix_effort = self.EFFORT_MAP.get(swc_id, FixEffort.MEDIUM)
        fix_risk = self.RISK_MAP.get(swc_id, FixRisk.LOW)

        # Calculate priority score
        priority_score = self._calculate_priority(severity, swc_id, fix_effort)

        # Extract affected functions from location
        affected_functions = []
        if 'function' in location:
            affected_functions.append(location['function'])

        return EnrichedFinding(
            id=finding_id,
            type=finding_type,
            severity=severity,
            message=message,
            location=location,
            swc_id=swc_id if swc_id else (remediation.swc_id if remediation else None),
            remediation=remediation,
            fix_effort=fix_effort,
            fix_risk=fix_risk,
            priority_score=priority_score,
            affected_functions=affected_functions,
        )

    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[EnrichedFinding]:
        """
        Enrich multiple findings with remediation information.

        Args:
            findings: List of raw finding dictionaries

        Returns:
            List of EnrichedFindings, sorted by priority
        """
        enriched = [self.enrich_finding(f) for f in findings]

        # Sort by priority score (descending)
        enriched.sort(key=lambda f: f.priority_score, reverse=True)

        # Assign priority ranks
        for i, finding in enumerate(enriched, 1):
            finding.priority_rank = i

        # Group by type for related findings
        self._findings_by_type.clear()
        for finding in enriched:
            normalized_type = self.TYPE_CANONICAL.get(finding.type.lower(), finding.type.lower())
            if normalized_type not in self._findings_by_type:
                self._findings_by_type[normalized_type] = []
            self._findings_by_type[normalized_type].append(finding)

        # Mark related findings
        for finding in enriched:
            normalized_type = self.TYPE_CANONICAL.get(finding.type.lower(), finding.type.lower())
            related = self._findings_by_type.get(normalized_type, [])
            finding.related_findings = [f.id for f in related if f.id != finding.id]

        self._enriched_findings = enriched
        return enriched

    def _calculate_priority(
        self,
        severity: str,
        swc_id: str,
        effort: FixEffort
    ) -> float:
        """
        Calculate priority score for a finding.

        Formula: severity_weight * (1 + exploitability_bonus) / effort_penalty
        """
        # Base severity weight
        severity_weight = self.SEVERITY_WEIGHTS.get(severity.lower(), 3.0)

        # Exploitability bonus for critical vulnerabilities
        exploitability_bonus = 0.0
        if swc_id in ['SWC-107', 'SWC-105', 'SWC-106', 'SWC-112']:  # High exploitability
            exploitability_bonus = 0.5
        elif swc_id in ['SWC-104', 'SWC-101', 'SWC-124']:  # Medium exploitability
            exploitability_bonus = 0.25

        # Effort penalty (quick fixes get priority boost)
        effort_multipliers = {
            FixEffort.TRIVIAL: 1.5,
            FixEffort.LOW: 1.2,
            FixEffort.MEDIUM: 1.0,
            FixEffort.HIGH: 0.8,
            FixEffort.COMPLEX: 0.6,
        }
        effort_multiplier = effort_multipliers.get(effort, 1.0)

        return severity_weight * (1 + exploitability_bonus) * effort_multiplier

    def generate_fix_plan(self) -> List[Dict[str, Any]]:
        """
        Generate a prioritized fix plan.

        Returns:
            List of fix steps ordered by priority
        """
        if not self._enriched_findings:
            return []

        fix_plan = []

        # Group findings by SWC ID to consolidate similar fixes
        by_swc: Dict[str, List[EnrichedFinding]] = {}
        for finding in self._enriched_findings:
            swc = finding.swc_id or 'unknown'
            if swc not in by_swc:
                by_swc[swc] = []
            by_swc[swc].append(finding)

        # Create fix steps
        step_num = 1
        for swc_id, findings in sorted(by_swc.items(),
                                        key=lambda x: max(f.priority_score for f in x[1]),
                                        reverse=True):
            if swc_id == 'unknown':
                continue

            remediation = findings[0].remediation
            if not remediation:
                continue

            # Collect all affected locations
            locations = []
            for f in findings:
                if f.location:
                    loc_str = f.location.get('file', '')
                    if f.location.get('line'):
                        loc_str += f":{f.location['line']}"
                    if f.location.get('function'):
                        loc_str += f" ({f.location['function']})"
                    if loc_str:
                        locations.append(loc_str)

            fix_plan.append({
                'step': step_num,
                'swc_id': swc_id,
                'title': remediation.title,
                'severity': findings[0].severity,
                'instances': len(findings),
                'locations': locations[:5],  # Limit to 5 locations
                'effort': findings[0].fix_effort.value,
                'risk': findings[0].fix_risk.value,
                'action': remediation.fix,
                'example': {
                    'before': remediation.example_vulnerable,
                    'after': remediation.example_fixed,
                },
                'references': remediation.references,
            })
            step_num += 1

        return fix_plan

    def estimate_total_effort(self) -> str:
        """
        Estimate total effort to fix all findings.

        Returns:
            Human-readable effort estimate
        """
        if not self._enriched_findings:
            return "No findings to fix"

        # Count findings by effort level
        effort_counts = {e: 0 for e in FixEffort}
        for finding in self._enriched_findings:
            effort_counts[finding.fix_effort] += 1

        # Estimate hours
        effort_hours = {
            FixEffort.TRIVIAL: 0.5,
            FixEffort.LOW: 1.5,
            FixEffort.MEDIUM: 4.0,
            FixEffort.HIGH: 12.0,
            FixEffort.COMPLEX: 32.0,
        }

        total_hours = sum(
            count * effort_hours[effort]
            for effort, count in effort_counts.items()
        )

        if total_hours < 2:
            return f"~{int(total_hours * 60)} minutes"
        elif total_hours < 8:
            return f"~{total_hours:.1f} hours"
        elif total_hours < 40:
            return f"~{total_hours / 8:.1f} days"
        else:
            return f"~{total_hours / 40:.1f} weeks"

    def check_security_checklist(
        self,
        source_code: Optional[str] = None
    ) -> Dict[str, bool]:
        """
        Check compliance with security checklist.

        Args:
            source_code: Optional source code to analyze

        Returns:
            Dictionary of checklist items and their status
        """
        status = {}

        # Check based on findings
        finding_types = {f.type.lower() for f in self._enriched_findings}
        finding_swcs = {f.swc_id for f in self._enriched_findings if f.swc_id}

        # Access Control
        status['No unprotected ether withdrawal'] = 'SWC-105' not in finding_swcs
        status['No tx.origin for authentication'] = 'SWC-115' not in finding_swcs
        status['Protected selfdestruct'] = 'SWC-106' not in finding_swcs

        # Reentrancy
        status['No reentrancy vulnerabilities'] = 'SWC-107' not in finding_swcs

        # Arithmetic
        status['No integer overflow/underflow'] = 'SWC-101' not in finding_swcs

        # External Calls
        status['All call return values checked'] = 'SWC-104' not in finding_swcs
        status['No DoS vulnerabilities'] = 'SWC-113' not in finding_swcs

        # Best Practices
        status['No floating pragma'] = 'SWC-103' not in finding_swcs
        status['No deprecated functions'] = 'SWC-111' not in finding_swcs
        status['No weak randomness'] = 'SWC-120' not in finding_swcs

        # Source code analysis (if provided)
        if source_code:
            status['Uses Solidity 0.8+'] = bool(re.search(r'pragma\s+solidity\s*[\^>=]*\s*0\.8', source_code))
            status['Has ReentrancyGuard'] = bool(re.search(r'ReentrancyGuard|nonReentrant', source_code))
            status['Uses SafeMath or 0.8'] = (
                status['Uses Solidity 0.8+'] or
                bool(re.search(r'using\s+SafeMath', source_code))
            )

        return status

    def generate_report(
        self,
        contract_name: str = "Unknown",
        source_code: Optional[str] = None
    ) -> RemediationReport:
        """
        Generate a complete remediation report.

        Args:
            contract_name: Name of the contract
            source_code: Optional source code for additional analysis

        Returns:
            Complete RemediationReport
        """
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in self._enriched_findings:
            sev = finding.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            elif sev in ['informational', 'info']:
                severity_counts['low'] += 1

        return RemediationReport(
            contract_name=contract_name,
            total_findings=len(self._enriched_findings),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            enriched_findings=self._enriched_findings,
            fix_plan=self.generate_fix_plan(),
            estimated_total_effort=self.estimate_total_effort(),
            security_checklist_status=self.check_security_checklist(source_code),
        )

    def get_quick_wins(self, max_effort: FixEffort = FixEffort.LOW) -> List[EnrichedFinding]:
        """
        Get findings that are quick to fix.

        Args:
            max_effort: Maximum effort level to include

        Returns:
            List of quick-win findings
        """
        effort_order = [FixEffort.TRIVIAL, FixEffort.LOW, FixEffort.MEDIUM, FixEffort.HIGH, FixEffort.COMPLEX]
        max_idx = effort_order.index(max_effort)

        return [
            f for f in self._enriched_findings
            if effort_order.index(f.fix_effort) <= max_idx
        ]

    def get_critical_fixes(self) -> List[EnrichedFinding]:
        """Get only critical and high severity findings."""
        return [
            f for f in self._enriched_findings
            if f.severity.lower() in ['critical', 'high']
        ]


# Convenience function
def enrich_with_remediations(
    findings: List[Dict[str, Any]],
    contract_name: str = "Unknown",
    source_code: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience function to enrich findings with remediations.

    Args:
        findings: List of raw findings
        contract_name: Name of the contract
        source_code: Optional source code

    Returns:
        Complete remediation report as dictionary
    """
    engine = RemediationEngine()
    engine.enrich_findings(findings)
    report = engine.generate_report(contract_name, source_code)
    return report.to_dict()
