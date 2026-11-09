"""
MIESC Risk Calculator

Provides CVSS-like scoring and risk matrix generation for smart contract
security findings. Designed for premium audit reports.
"""

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Optional, TypedDict

from miesc.core.finding_taxonomy import CanonicalCategory, normalize_finding_type


class EffortImpactCell(TypedDict):
    """Prioritization cell used by the effort/impact matrix."""

    count: int
    findings: list[dict[str, Any]]
    action: str


def _get_finding_title(finding: dict[str, Any]) -> str:
    """Get finding title with fallbacks for different adapter formats."""
    title = finding.get("title") or finding.get("type") or finding.get("message", "Unknown")
    return str(title)[:100]


class AttackVector(Enum):
    """Attack vector component."""

    NETWORK = "N"  # Remote/network exploitable
    ADJACENT = "A"  # Adjacent network
    LOCAL = "L"  # Local access needed
    PHYSICAL = "P"  # Physical access needed


class AttackComplexity(Enum):
    """Attack complexity component."""

    LOW = "L"  # Easy to exploit
    HIGH = "H"  # Complex conditions required


class PrivilegesRequired(Enum):
    """Privileges required component."""

    NONE = "N"  # No privileges needed
    LOW = "L"  # Low privileges (e.g., user account)
    HIGH = "H"  # High privileges (e.g., admin)


class UserInteraction(Enum):
    """User interaction component."""

    NONE = "N"  # No user interaction
    REQUIRED = "R"  # User must take action


class Impact(Enum):
    """Impact level for C/I/A."""

    NONE = "N"
    LOW = "L"
    HIGH = "H"


@dataclass
class CVSSVector:
    """CVSS-like vector for smart contract vulnerabilities."""

    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    confidentiality_impact: Impact = Impact.NONE
    integrity_impact: Impact = Impact.HIGH
    availability_impact: Impact = Impact.NONE

    def to_string(self) -> str:
        """Generate CVSS vector string."""
        return (
            f"AV:{self.attack_vector.value}/"
            f"AC:{self.attack_complexity.value}/"
            f"PR:{self.privileges_required.value}/"
            f"UI:{self.user_interaction.value}/"
            f"C:{self.confidentiality_impact.value}/"
            f"I:{self.integrity_impact.value}/"
            f"A:{self.availability_impact.value}"
        )


@dataclass
class CVSSScore:
    """CVSS score result."""

    finding_id: str
    title: str
    base_score: float
    severity: str
    vector: str
    exploitability_subscore: float = 0.0
    impact_subscore: float = 0.0
    # True when no category vector matched, so the score was NOT computed and
    # must be rendered as "not scored" rather than a fabricated default.
    uncategorized: bool = False


@dataclass
class RiskMatrixCell:
    """Cell in the risk matrix."""

    impact: str
    likelihood: str
    count: int = 0
    findings: list = field(default_factory=list)


class RiskCalculator:
    """
    Calculate CVSS-like scores and risk metrics for smart contract findings.

    This uses a simplified CVSS v3.1-like methodology adapted for
    smart contract security analysis.
    """

    # CVSS weights
    ATTACK_VECTOR_WEIGHTS = {
        AttackVector.NETWORK: 0.85,
        AttackVector.ADJACENT: 0.62,
        AttackVector.LOCAL: 0.55,
        AttackVector.PHYSICAL: 0.20,
    }

    ATTACK_COMPLEXITY_WEIGHTS = {
        AttackComplexity.LOW: 0.77,
        AttackComplexity.HIGH: 0.44,
    }

    PRIVILEGES_REQUIRED_WEIGHTS = {
        PrivilegesRequired.NONE: 0.85,
        PrivilegesRequired.LOW: 0.62,
        PrivilegesRequired.HIGH: 0.27,
    }

    USER_INTERACTION_WEIGHTS = {
        UserInteraction.NONE: 0.85,
        UserInteraction.REQUIRED: 0.62,
    }

    IMPACT_WEIGHTS = {
        Impact.NONE: 0.0,
        Impact.LOW: 0.22,
        Impact.HIGH: 0.56,
    }

    # Severity mapping from score
    SEVERITY_THRESHOLDS = [
        (9.0, "Critical"),
        (7.0, "High"),
        (4.0, "Medium"),
        (0.1, "Low"),
        (0.0, "Info"),
    ]

    # Canonical-category -> CVSS vector mapping.
    #
    # Phase 1: these are keyed by ``CanonicalCategory`` (a ``str`` enum, so a
    # plain string such as ``"reentrancy"`` still matches a key). A tool check
    # name is first run through ``normalize_finding_type`` so idiosyncratic
    # detector strings (``weak-prng``, ``suicidal``, ``unchecked-return`` …)
    # resolve to the right canonical vector instead of silently missing.
    #
    # ``CanonicalCategory.OTHER`` is intentionally absent: a finding that only
    # maps to OTHER is "not scored (uncategorized)", never a fabricated default.
    CATEGORY_VECTORS = {
        CanonicalCategory.REENTRANCY: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.HIGH,
        ),
        CanonicalCategory.ACCESS_CONTROL: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            confidentiality_impact=Impact.HIGH,
            integrity_impact=Impact.HIGH,
        ),
        CanonicalCategory.ORACLE_MANIPULATION: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.LOW,
        ),
        CanonicalCategory.FLASH_LOAN: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            confidentiality_impact=Impact.HIGH,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.HIGH,
        ),
        CanonicalCategory.ARITHMETIC: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.HIGH,
        ),
        CanonicalCategory.UNCHECKED_CALL: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.LOW,
            availability_impact=Impact.LOW,
        ),
        CanonicalCategory.INITIALIZATION: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.LOW,
        ),
        CanonicalCategory.SIGNATURE_VERIFICATION: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.HIGH,
        ),
        CanonicalCategory.BAD_RANDOMNESS: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.HIGH,
        ),
        CanonicalCategory.TIME_MANIPULATION: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.LOW,
        ),
        CanonicalCategory.DENIAL_OF_SERVICE: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            availability_impact=Impact.HIGH,
        ),
        CanonicalCategory.FRONT_RUNNING: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.HIGH,
        ),
        CanonicalCategory.PROXY_UPGRADE: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            confidentiality_impact=Impact.HIGH,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.HIGH,
        ),
        CanonicalCategory.CENTRALIZATION: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.LOW,
        ),
        CanonicalCategory.INPUT_VALIDATION: CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.LOW,
            availability_impact=Impact.LOW,
        ),
    }

    # Hygiene / best-practice detector names that carry no canonical category
    # (they normalize to OTHER) but still have a well-understood, low risk
    # profile. Kept keyed by raw substring so PR-0 scoring coverage for these
    # does not regress. These are NOT security-impact categories.
    HYGIENE_VECTORS = {
        "solc-version": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.LOW,
        ),
        "pragma": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.LOW,
        ),
        "zero-address": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.LOW,
            availability_impact=Impact.LOW,
        ),
        "unindexed": CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
        ),
        "push-zero": CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.NONE,
        ),
        "unsafe-erc20": CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            integrity_impact=Impact.LOW,
            availability_impact=Impact.LOW,
        ),
    }

    def __init__(self) -> None:
        """Initialize the risk calculator."""
        pass

    @staticmethod
    def _canonical_of(text: str) -> Optional[CanonicalCategory]:
        """Normalize a category string to a canonical category.

        Tries the raw string first, then a dash-normalized variant so
        underscore/space spellings (``access_control``, ``access control``)
        resolve the same as the canonical dashed form.
        """
        canonical = normalize_finding_type(text)
        if canonical is None or canonical is CanonicalCategory.OTHER:
            variant = text.replace(" ", "-").replace("_", "-")
            if variant != text:
                canonical = normalize_finding_type(variant)
        return canonical

    def _hygiene_vector(self, category: str) -> Optional[CVSSVector]:
        """Return a hygiene vector (copy) for a best-practice detector name."""
        category_lower = category.lower().replace(" ", "-").replace("_", "-")
        for key, vector in self.HYGIENE_VECTORS.items():
            if key in category_lower or category_lower in key:
                return replace(vector)
        return None

    def get_vector_for_category(self, category: str) -> Optional[CVSSVector]:
        """Get the CVSS vector for a vulnerability category.

        The category string is routed through ``normalize_finding_type`` first,
        so raw tool check names (``weak-prng``, ``suicidal``, ``unused-return`` …)
        resolve to their canonical category vector. Hygiene/best-practice names
        that carry no canonical category fall back to :attr:`HYGIENE_VECTORS`.

        Returns a **fresh copy** so callers that adjust the vector cannot mutate
        the shared class-level template. Returns ``None`` when nothing matches,
        so the caller renders "not scored" rather than a fabricated default.
        """
        if not isinstance(category, str) or not category.strip():
            return None

        canonical = self._canonical_of(category)
        if canonical is not None and canonical is not CanonicalCategory.OTHER:
            vector = self.CATEGORY_VECTORS.get(canonical)
            if vector is not None:
                return replace(vector)

        # No real category: last-resort hygiene lookup for best-practice checks.
        return self._hygiene_vector(category)

    def _vector_for_finding(self, finding: dict[str, Any]) -> Optional[CVSSVector]:
        """Resolve a CVSS vector from a finding, normalizing its taxonomy first.

        Builds the normalization candidates from ``type``/``check``/``swc_id``
        (deliberately **excluding** ``title``/``message`` so an over-eager
        ``owner``/``price`` substring in free text cannot inflate a hygiene nit
        into a high-impact category). Falls back to the ``category`` string for
        hygiene detectors.
        """
        type_str = str(finding.get("type") or finding.get("category") or "")
        norm_input = {
            "type": type_str,
            "check": str(finding.get("check") or ""),
            "swc_id": str(finding.get("swc_id") or ""),
        }
        canonical = normalize_finding_type(norm_input)
        if canonical is None or canonical is CanonicalCategory.OTHER:
            # Retry with separator-normalized type (access_control -> access-control).
            canonical = self._canonical_of(type_str)
        if canonical is not None and canonical is not CanonicalCategory.OTHER:
            vector = self.CATEGORY_VECTORS.get(canonical)
            if vector is not None:
                return replace(vector)

        for key in ("category", "type", "check"):
            value = finding.get(key)
            if isinstance(value, str) and value.strip():
                hygiene = self._hygiene_vector(value)
                if hygiene is not None:
                    return hygiene
        return None

    def calculate_exploitability(self, vector: CVSSVector) -> float:
        """Calculate exploitability subscore."""
        return (
            8.22
            * self.ATTACK_VECTOR_WEIGHTS[vector.attack_vector]
            * self.ATTACK_COMPLEXITY_WEIGHTS[vector.attack_complexity]
            * self.PRIVILEGES_REQUIRED_WEIGHTS[vector.privileges_required]
            * self.USER_INTERACTION_WEIGHTS[vector.user_interaction]
        )

    def calculate_impact(self, vector: CVSSVector) -> float:
        """Calculate impact subscore."""
        isc_base = 1 - (
            (1 - self.IMPACT_WEIGHTS[vector.confidentiality_impact])
            * (1 - self.IMPACT_WEIGHTS[vector.integrity_impact])
            * (1 - self.IMPACT_WEIGHTS[vector.availability_impact])
        )

        if isc_base <= 0:
            return 0.0

        return 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    def calculate_base_score(self, vector: CVSSVector) -> float:
        """Calculate CVSS base score (0-10)."""
        impact = self.calculate_impact(vector)

        if impact <= 0:
            return 0.0

        exploitability = self.calculate_exploitability(vector)
        base = min(impact + exploitability, 10.0)

        # Round up to nearest 0.1
        return round(base * 10) / 10

    def get_severity_from_score(self, score: float) -> str:
        """Convert numeric score to severity label."""
        for threshold, severity in self.SEVERITY_THRESHOLDS:
            if score >= threshold:
                return severity
        return "Info"

    def adjust_vector_by_severity(self, vector: CVSSVector, severity: str) -> CVSSVector:
        """Nudge a category vector toward the tool-reported severity.

        Category vectors already encode the right risk profile, so the nudge is
        deliberately light and **symmetric**: a reported-critical finding gets an
        easier attack complexity, while a reported-low/info finding has its HIGH
        impacts and complexity relaxed. This keeps the computed CVSS direction
        consistent with the reported severity (no LOW finding scoring 9.x).

        Mutates and returns the passed vector, which callers already own as a
        fresh copy (see :meth:`get_vector_for_category`).
        """
        severity_lower = severity.lower().strip()

        if severity_lower == "critical":
            vector.attack_complexity = AttackComplexity.LOW
        elif severity_lower in ("low", "info", "informational"):
            # Relax a high-impact category vector down toward the reported low
            # severity instead of printing an inflated score.
            vector.attack_complexity = AttackComplexity.HIGH
            if vector.integrity_impact == Impact.HIGH:
                vector.integrity_impact = Impact.LOW
            if vector.availability_impact == Impact.HIGH:
                vector.availability_impact = Impact.LOW
            if vector.confidentiality_impact == Impact.HIGH:
                vector.confidentiality_impact = Impact.LOW

        return vector

    # Severity band index used to check CVSS/severity directional consistency.
    _SEVERITY_BANDS = {
        "info": 0,
        "informational": 0,
        "none": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def _severity_band(self, severity: str) -> Optional[int]:
        """Return the band index for a severity label, or ``None`` if unknown."""
        if not isinstance(severity, str):
            return None
        return self._SEVERITY_BANDS.get(severity.lower().strip())

    def calculate_finding_score(self, finding: dict[str, Any]) -> CVSSScore:
        """Calculate CVSS score for a single finding.

        The finding's taxonomy is normalized first so recognized categories get
        a real vector/score. A finding with no real category stays "not scored
        (uncategorized)", and a score whose severity band is more than one step
        away from the tool-reported severity is withheld as "not scored
        (inconsistent with reported severity)" rather than printed — honest
        blanks over misleading numbers.
        """
        finding_id = finding.get("id", "UNK")
        title = _get_finding_title(finding)
        severity = str(finding.get("severity", "Medium"))

        # Route through the taxonomy so raw tool check names resolve correctly.
        vector = self._vector_for_finding(finding)

        if vector is None:
            # Uncategorized: do not fabricate a vector/score. Flag it so the
            # report renders "not scored" instead of a misleading default.
            return CVSSScore(
                finding_id=finding_id,
                title=title,
                base_score=0.0,
                severity=severity,
                vector="not scored (uncategorized)",
                uncategorized=True,
            )

        # Adjust based on reported severity
        vector = self.adjust_vector_by_severity(vector, severity)

        # Calculate scores
        base_score = self.calculate_base_score(vector)
        exploitability = self.calculate_exploitability(vector)
        impact = self.calculate_impact(vector)
        computed_severity = self.get_severity_from_score(base_score)

        # Directional-consistency guard: never let a LOW finding show a high
        # CVSS (or vice versa). If the computed band is more than one step from
        # the reported band, withhold the score instead of printing it.
        reported_band = self._severity_band(severity)
        computed_band = self._severity_band(computed_severity)
        if (
            reported_band is not None
            and computed_band is not None
            and abs(reported_band - computed_band) > 1
        ):
            return CVSSScore(
                finding_id=finding_id,
                title=title,
                base_score=0.0,
                severity=severity,
                vector="not scored (inconsistent with reported severity)",
                uncategorized=True,
            )

        return CVSSScore(
            finding_id=finding_id,
            title=title,
            base_score=base_score,
            severity=computed_severity,
            vector=vector.to_string(),
            exploitability_subscore=round(exploitability, 1),
            impact_subscore=round(impact, 1),
        )

    def calculate_all_scores(self, findings: list[dict[str, Any]]) -> list[CVSSScore]:
        """Calculate CVSS scores for all findings."""
        return [self.calculate_finding_score(f) for f in findings]

    def generate_risk_matrix(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        """
        Generate a 3x3 risk matrix based on impact and likelihood.

        Returns a dict with keys like 'high_high', 'medium_low', etc.
        containing counts of findings in each cell.
        """
        matrix = {
            "high_high": 0,
            "high_med": 0,
            "high_low": 0,
            "med_high": 0,
            "med_med": 0,
            "med_low": 0,
            "low_high": 0,
            "low_med": 0,
            "low_low": 0,
        }

        for finding in findings:
            severity = finding.get("severity", "Medium").lower()

            # Map severity to impact/likelihood
            if severity == "critical":
                impact, likelihood = "high", "high"
            elif severity == "high":
                impact, likelihood = "high", "med"
            elif severity == "medium":
                impact, likelihood = "med", "med"
            elif severity == "low":
                impact, likelihood = "low", "med"
            else:  # info
                impact, likelihood = "low", "low"

            key = f"{impact}_{likelihood}"
            if key in matrix:
                matrix[key] += 1

        return matrix

    def calculate_overall_risk_score(self, findings: list[dict[str, Any]]) -> int:
        """
        Calculate overall risk score (0-100).

        Higher scores indicate higher risk.
        """
        if not findings:
            return 0

        # Weight by severity
        severity_weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1,
            "informational": 1,
        }

        total_weight = 0
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            total_weight += severity_weights.get(severity, 5)

        # Cap at 100
        return min(100, total_weight)

    def get_deployment_recommendation(
        self, findings: list[dict[str, Any]]
    ) -> tuple[str, str, str, str]:
        """
        Generate deployment recommendation based on findings.

        Returns (recommendation, justification, border_color, background_color).
        """
        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        medium_count = sum(1 for f in findings if f.get("severity", "").lower() == "medium")

        if critical_count > 0:
            return (
                "NO-GO",
                f"Contract has {critical_count} critical vulnerabilities that "
                "must be fixed before deployment. Immediate remediation required.",
                "#dc3545",  # Red border
                "#fef2f2",  # Light red background
            )

        if high_count >= 2:
            return (
                "NO-GO",
                f"Contract has {high_count} high severity vulnerabilities. "
                "Fix all high severity issues before deployment.",
                "#dc3545",  # Red border
                "#fef2f2",  # Light red background
            )

        if high_count == 1 or medium_count >= 3:
            return (
                "CONDITIONAL",
                f"Contract has {high_count} high and {medium_count} medium "
                "severity findings. Address these issues and re-audit before "
                "production deployment.",
                "#ff9800",  # Orange border
                "#fff8e1",  # Light orange background
            )

        if medium_count > 0:
            return (
                "CONDITIONAL",
                f"Contract has {medium_count} medium severity findings. "
                "Review and address these issues before deployment.",
                "#ffc107",  # Yellow border
                "#fffde7",  # Light yellow background
            )

        return (
            "GO",
            "No critical or high severity issues found. Contract appears "
            "suitable for deployment after addressing any minor findings.",
            "#28a745",  # Green border
            "#f0fdf4",  # Light green background
        )

    # Effort classification for vulnerability types
    # Low effort: simple config/pragma changes, adding modifiers
    # Medium effort: adding validation, checks, events
    # High effort: architectural changes, complex refactoring
    EFFORT_CLASSIFICATION = {
        # Low effort fixes
        "pragma": "low",
        "solidity-version": "low",
        "naming": "low",
        "visibility": "low",
        "constant": "low",
        "immutable": "low",
        "dead-code": "low",
        "unused": "low",
        "similar-names": "low",
        "assembly": "low",
        "low-level-calls": "low",
        # Medium effort fixes
        "unchecked": "medium",
        "require": "medium",
        "event": "medium",
        "timestamp": "medium",
        "block-timestamp": "medium",
        "tx-origin": "medium",
        "delegatecall": "medium",
        "external-call": "medium",
        "gas": "medium",
        "loop": "medium",
        "division": "medium",
        "zero-check": "medium",
        "missing-zero": "medium",
        # High effort fixes
        "reentrancy": "high",
        "reentrant": "high",
        "access-control": "high",
        "authorization": "high",
        "owner": "high",
        "overflow": "high",
        "underflow": "high",
        "integer": "high",
        "dos": "high",
        "denial": "high",
        "front-running": "high",
        "oracle": "high",
        "price": "high",
        "flash": "high",
        "storage": "high",
        "upgrade": "high",
        "proxy": "high",
        "selfdestruct": "high",
        "suicide": "high",
    }

    def classify_effort(self, finding: dict[str, Any]) -> str:
        """
        Classify the remediation effort for a finding.

        Returns: 'low', 'medium', or 'high'
        """
        title = _get_finding_title(finding).lower()
        category = finding.get("category", "").lower()
        check = finding.get("check", "").lower()
        vuln_type = finding.get("type", "").lower()

        combined = f"{title} {category} {check} {vuln_type}"

        # Check for pattern matches
        for pattern, effort in self.EFFORT_CLASSIFICATION.items():
            if pattern in combined:
                return effort

        # Default based on severity
        severity = finding.get("severity", "medium").lower()
        if severity in ["critical", "high"]:
            return "high"
        elif severity == "medium":
            return "medium"
        return "low"

    def classify_impact(self, finding: dict[str, Any]) -> str:
        """
        Classify the security impact of a finding.

        Returns: 'low', 'medium', or 'high'
        """
        severity = finding.get("severity", "medium").lower()

        if severity in ["critical", "high"]:
            return "high"
        elif severity == "medium":
            return "medium"
        return "low"

    def generate_effort_impact_matrix(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Generate effort vs impact matrix for prioritization.

        Matrix cells:
        - high_effort_low_impact: Avoid
        - high_effort_medium_impact: Consider
        - high_effort_high_impact: Schedule
        - medium_effort_low_impact: Defer
        - medium_effort_medium_impact: Plan
        - medium_effort_high_impact: Priority
        - low_effort_low_impact: If Time
        - low_effort_medium_impact: Quick Win
        - low_effort_high_impact: DO FIRST!

        Returns dict with counts and finding lists per cell.
        """
        matrix: dict[str, EffortImpactCell] = {
            "high_low": {"count": 0, "findings": [], "action": "Avoid"},
            "high_medium": {"count": 0, "findings": [], "action": "Consider"},
            "high_high": {"count": 0, "findings": [], "action": "Schedule"},
            "medium_low": {"count": 0, "findings": [], "action": "Defer"},
            "medium_medium": {"count": 0, "findings": [], "action": "Plan"},
            "medium_high": {"count": 0, "findings": [], "action": "Priority"},
            "low_low": {"count": 0, "findings": [], "action": "If Time"},
            "low_medium": {"count": 0, "findings": [], "action": "Quick Win"},
            "low_high": {"count": 0, "findings": [], "action": "DO FIRST!"},
        }

        for finding in findings:
            effort = self.classify_effort(finding)
            impact = self.classify_impact(finding)
            key = f"{effort}_{impact}"

            if key in matrix:
                matrix[key]["count"] += 1
                matrix[key]["findings"].append(
                    {
                        "id": finding.get("id", "?"),
                        "title": _get_finding_title(finding)[:50],
                        "severity": finding.get("severity", "Unknown"),
                    }
                )

        return matrix

    def identify_quick_wins(self, findings: list[dict[str, Any]]) -> list[dict[str, str]]:
        """
        Identify quick win fixes - high impact, low effort.

        Returns list of quick win descriptions.
        """
        quick_wins = []

        # Categories that are typically quick to fix
        quick_fix_patterns = [
            ("pragma", "Update Solidity version pragma"),
            ("visibility", "Add explicit visibility modifiers"),
            ("event", "Add missing events for state changes"),
            ("require", "Add input validation with require statements"),
            ("locked", "Add reentrancy guard modifier"),
            ("naming", "Fix naming convention issues"),
        ]

        for finding in findings:
            title_lower = _get_finding_title(finding).lower()
            category_lower = finding.get("category", "").lower()
            desc_lower = finding.get("description", "").lower()

            combined = f"{title_lower} {category_lower} {desc_lower}"

            for pattern, description in quick_fix_patterns:
                if pattern in combined:
                    quick_wins.append(
                        {
                            "title": _get_finding_title(finding),
                            "description": description,
                            "finding_id": finding.get("id", "?"),
                        }
                    )
                    break

        return quick_wins[:5]  # Return top 5 quick wins

    def get_severity_percentages(self, findings: list[dict[str, Any]]) -> dict[str, float]:
        """Calculate percentage of findings by severity."""
        total = len(findings) if findings else 1

        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity == "informational":
                severity = "info"
            if severity in counts:
                counts[severity] += 1

        return {f"{k}_percent": round(v / total * 100, 1) for k, v in counts.items()}


def calculate_premium_risk_data(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Calculate all risk data needed for premium reports.

    This is the main entry point for the risk calculator.
    Returns a dict with all calculated risk metrics.
    """
    calculator = RiskCalculator()

    # Calculate CVSS scores
    cvss_scores = calculator.calculate_all_scores(findings)

    # Generate risk matrix
    risk_matrix = calculator.generate_risk_matrix(findings)

    # Overall score
    overall_score = calculator.calculate_overall_risk_score(findings)

    # Deployment recommendation
    recommendation, justification, color, bg_color = calculator.get_deployment_recommendation(
        findings
    )

    # Quick wins
    quick_wins = calculator.identify_quick_wins(findings)

    # Effort vs Impact matrix
    effort_impact_matrix = calculator.generate_effort_impact_matrix(findings)

    # Severity percentages
    percentages = calculator.get_severity_percentages(findings)

    return {
        "cvss_scores": [
            {
                "finding_id": s.finding_id,
                "title": s.title,
                "base_score": ("not scored (uncategorized)" if s.uncategorized else s.base_score),
                "severity": s.severity,
                "vector": s.vector,
                "uncategorized": s.uncategorized,
            }
            for s in cvss_scores
        ],
        "risk_matrix": risk_matrix,
        "overall_risk_score": overall_score,
        "deployment_recommendation": recommendation,
        "deployment_justification": justification,
        "deployment_recommendation_color": color,
        "deployment_recommendation_bg": bg_color,
        "quick_wins": quick_wins,
        "effort_impact_matrix": effort_impact_matrix,
        **percentages,
    }
