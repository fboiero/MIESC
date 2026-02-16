"""
Tests for MIESC Risk Calculator

Comprehensive tests for CVSS scoring and risk matrix generation.
"""

import pytest

from src.reports.risk_calculator import (
    AttackComplexity,
    AttackVector,
    CVSSScore,
    CVSSVector,
    Impact,
    PrivilegesRequired,
    RiskCalculator,
    RiskMatrixCell,
    UserInteraction,
    _get_finding_title,
    calculate_premium_risk_data,
)


# =============================================================================
# Test Enums
# =============================================================================


class TestEnums:
    """Tests for CVSS enum classes."""

    def test_attack_vector_values(self):
        """Test AttackVector enum values."""
        assert AttackVector.NETWORK.value == "N"
        assert AttackVector.ADJACENT.value == "A"
        assert AttackVector.LOCAL.value == "L"
        assert AttackVector.PHYSICAL.value == "P"

    def test_attack_complexity_values(self):
        """Test AttackComplexity enum values."""
        assert AttackComplexity.LOW.value == "L"
        assert AttackComplexity.HIGH.value == "H"

    def test_privileges_required_values(self):
        """Test PrivilegesRequired enum values."""
        assert PrivilegesRequired.NONE.value == "N"
        assert PrivilegesRequired.LOW.value == "L"
        assert PrivilegesRequired.HIGH.value == "H"

    def test_user_interaction_values(self):
        """Test UserInteraction enum values."""
        assert UserInteraction.NONE.value == "N"
        assert UserInteraction.REQUIRED.value == "R"

    def test_impact_values(self):
        """Test Impact enum values."""
        assert Impact.NONE.value == "N"
        assert Impact.LOW.value == "L"
        assert Impact.HIGH.value == "H"


# =============================================================================
# Test Dataclasses
# =============================================================================


class TestCVSSVector:
    """Tests for CVSSVector dataclass."""

    def test_default_values(self):
        """Test CVSSVector default values."""
        vector = CVSSVector()
        assert vector.attack_vector == AttackVector.NETWORK
        assert vector.attack_complexity == AttackComplexity.LOW
        assert vector.privileges_required == PrivilegesRequired.NONE
        assert vector.user_interaction == UserInteraction.NONE
        assert vector.confidentiality_impact == Impact.NONE
        assert vector.integrity_impact == Impact.HIGH
        assert vector.availability_impact == Impact.NONE

    def test_custom_values(self):
        """Test CVSSVector with custom values."""
        vector = CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.REQUIRED,
            confidentiality_impact=Impact.HIGH,
            integrity_impact=Impact.LOW,
            availability_impact=Impact.HIGH,
        )
        assert vector.attack_vector == AttackVector.LOCAL
        assert vector.attack_complexity == AttackComplexity.HIGH

    def test_to_string(self):
        """Test CVSSVector string representation."""
        vector = CVSSVector()
        string = vector.to_string()
        assert string == "AV:N/AC:L/PR:N/UI:N/C:N/I:H/A:N"

    def test_to_string_custom(self):
        """Test CVSSVector string with custom values."""
        vector = CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            confidentiality_impact=Impact.HIGH,
        )
        string = vector.to_string()
        assert "AV:L" in string
        assert "AC:H" in string
        assert "C:H" in string


class TestCVSSScore:
    """Tests for CVSSScore dataclass."""

    def test_creation(self):
        """Test CVSSScore creation."""
        score = CVSSScore(
            finding_id="TEST-001",
            title="Test Finding",
            base_score=7.5,
            severity="High",
            vector="AV:N/AC:L/PR:N/UI:N/C:N/I:H/A:N",
            exploitability_subscore=3.9,
            impact_subscore=3.6,
        )
        assert score.finding_id == "TEST-001"
        assert score.base_score == 7.5
        assert score.severity == "High"

    def test_default_subscores(self):
        """Test CVSSScore default subscore values."""
        score = CVSSScore(
            finding_id="TEST",
            title="Test",
            base_score=5.0,
            severity="Medium",
            vector="test",
        )
        assert score.exploitability_subscore == 0.0
        assert score.impact_subscore == 0.0


class TestRiskMatrixCell:
    """Tests for RiskMatrixCell dataclass."""

    def test_default_values(self):
        """Test RiskMatrixCell defaults."""
        cell = RiskMatrixCell(impact="high", likelihood="high")
        assert cell.count == 0
        assert cell.findings == []

    def test_custom_values(self):
        """Test RiskMatrixCell with values."""
        findings = [{"id": "1"}, {"id": "2"}]
        cell = RiskMatrixCell(
            impact="medium",
            likelihood="low",
            count=2,
            findings=findings,
        )
        assert cell.count == 2
        assert len(cell.findings) == 2


# =============================================================================
# Test Helper Functions
# =============================================================================


class TestGetFindingTitle:
    """Tests for _get_finding_title helper."""

    def test_with_title(self):
        """Test with title field."""
        finding = {"title": "Reentrancy Vulnerability"}
        assert _get_finding_title(finding) == "Reentrancy Vulnerability"

    def test_with_type_fallback(self):
        """Test fallback to type field."""
        finding = {"type": "reentrancy-eth"}
        assert _get_finding_title(finding) == "reentrancy-eth"

    def test_with_message_fallback(self):
        """Test fallback to message field."""
        finding = {"message": "Potential reentrancy detected"}
        assert _get_finding_title(finding) == "Potential reentrancy detected"

    def test_message_truncation(self):
        """Test message truncation to 100 chars."""
        long_message = "A" * 150
        finding = {"message": long_message}
        result = _get_finding_title(finding)
        assert len(result) == 100

    def test_unknown_fallback(self):
        """Test fallback to Unknown."""
        finding = {}
        assert _get_finding_title(finding) == "Unknown"

    def test_priority_order(self):
        """Test that title takes precedence."""
        finding = {
            "title": "Title",
            "type": "Type",
            "message": "Message",
        }
        assert _get_finding_title(finding) == "Title"


# =============================================================================
# Test RiskCalculator
# =============================================================================


class TestRiskCalculatorInit:
    """Tests for RiskCalculator initialization."""

    def test_init(self):
        """Test basic initialization."""
        calc = RiskCalculator()
        assert calc is not None

    def test_weights_defined(self):
        """Test that all weight dictionaries are defined."""
        calc = RiskCalculator()
        assert len(calc.ATTACK_VECTOR_WEIGHTS) == 4
        assert len(calc.ATTACK_COMPLEXITY_WEIGHTS) == 2
        assert len(calc.PRIVILEGES_REQUIRED_WEIGHTS) == 3
        assert len(calc.USER_INTERACTION_WEIGHTS) == 2
        assert len(calc.IMPACT_WEIGHTS) == 3

    def test_category_vectors_defined(self):
        """Test that category vectors are defined."""
        calc = RiskCalculator()
        assert "reentrancy" in calc.CATEGORY_VECTORS
        assert "default" in calc.CATEGORY_VECTORS


class TestGetVectorForCategory:
    """Tests for get_vector_for_category method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_reentrancy_category(self, calc):
        """Test reentrancy category mapping."""
        vector = calc.get_vector_for_category("reentrancy")
        assert vector.attack_vector == AttackVector.NETWORK
        assert vector.integrity_impact == Impact.HIGH

    def test_access_control_category(self, calc):
        """Test access control category mapping."""
        vector = calc.get_vector_for_category("access-control")
        assert vector.confidentiality_impact == Impact.HIGH
        assert vector.integrity_impact == Impact.HIGH

    def test_integer_overflow_category(self, calc):
        """Test integer overflow category mapping."""
        vector = calc.get_vector_for_category("integer-overflow")
        assert vector.attack_complexity == AttackComplexity.HIGH

    def test_dos_category(self, calc):
        """Test DOS category mapping."""
        vector = calc.get_vector_for_category("dos")
        assert vector.availability_impact == Impact.HIGH

    def test_unknown_category_returns_default(self, calc):
        """Test unknown category returns default vector."""
        vector = calc.get_vector_for_category("unknown-xyz")
        default = calc.CATEGORY_VECTORS["default"]
        assert vector.attack_vector == default.attack_vector

    def test_no_partial_match(self, calc):
        """Test that partial names don't match - requires exact category."""
        # "reentrant" does NOT match "reentrancy" - returns default
        vector = calc.get_vector_for_category("reentrant-issue")
        default = calc.CATEGORY_VECTORS["default"]
        assert vector.integrity_impact == default.integrity_impact

    def test_case_insensitive(self, calc):
        """Test case insensitive matching."""
        vector = calc.get_vector_for_category("REENTRANCY")
        assert vector.integrity_impact == Impact.HIGH

    def test_underscore_handling(self, calc):
        """Test underscore to dash conversion."""
        vector = calc.get_vector_for_category("access_control")
        assert vector.confidentiality_impact == Impact.HIGH


class TestCalculateExploitability:
    """Tests for calculate_exploitability method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_max_exploitability(self, calc):
        """Test maximum exploitability score."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
        )
        score = calc.calculate_exploitability(vector)
        # 8.22 * 0.85 * 0.77 * 0.85 * 0.85 = 3.89
        assert score > 3.5
        assert score < 4.0

    def test_min_exploitability(self, calc):
        """Test minimum exploitability score."""
        vector = CVSSVector(
            attack_vector=AttackVector.PHYSICAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.REQUIRED,
        )
        score = calc.calculate_exploitability(vector)
        assert score < 0.5


class TestCalculateImpact:
    """Tests for calculate_impact method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_max_impact(self, calc):
        """Test maximum impact score."""
        vector = CVSSVector(
            confidentiality_impact=Impact.HIGH,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.HIGH,
        )
        score = calc.calculate_impact(vector)
        assert score > 5.0

    def test_zero_impact(self, calc):
        """Test zero impact score."""
        vector = CVSSVector(
            confidentiality_impact=Impact.NONE,
            integrity_impact=Impact.NONE,
            availability_impact=Impact.NONE,
        )
        score = calc.calculate_impact(vector)
        assert score == 0.0

    def test_single_high_impact(self, calc):
        """Test single high impact component."""
        vector = CVSSVector(
            confidentiality_impact=Impact.NONE,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.NONE,
        )
        score = calc.calculate_impact(vector)
        assert score > 2.0
        assert score < 4.0


class TestCalculateBaseScore:
    """Tests for calculate_base_score method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_critical_score(self, calc):
        """Test critical severity score."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            confidentiality_impact=Impact.HIGH,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.HIGH,
        )
        score = calc.calculate_base_score(vector)
        assert score >= 9.0

    def test_zero_score(self, calc):
        """Test zero impact results in zero score."""
        vector = CVSSVector(
            confidentiality_impact=Impact.NONE,
            integrity_impact=Impact.NONE,
            availability_impact=Impact.NONE,
        )
        score = calc.calculate_base_score(vector)
        assert score == 0.0

    def test_score_capped_at_10(self, calc):
        """Test score is capped at 10."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            confidentiality_impact=Impact.HIGH,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.HIGH,
        )
        score = calc.calculate_base_score(vector)
        assert score <= 10.0


class TestGetSeverityFromScore:
    """Tests for get_severity_from_score method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_critical_threshold(self, calc):
        """Test critical severity threshold."""
        assert calc.get_severity_from_score(9.5) == "Critical"
        assert calc.get_severity_from_score(9.0) == "Critical"

    def test_high_threshold(self, calc):
        """Test high severity threshold."""
        assert calc.get_severity_from_score(8.9) == "High"
        assert calc.get_severity_from_score(7.0) == "High"

    def test_medium_threshold(self, calc):
        """Test medium severity threshold."""
        assert calc.get_severity_from_score(6.9) == "Medium"
        assert calc.get_severity_from_score(4.0) == "Medium"

    def test_low_threshold(self, calc):
        """Test low severity threshold."""
        assert calc.get_severity_from_score(3.9) == "Low"
        assert calc.get_severity_from_score(0.1) == "Low"

    def test_info_threshold(self, calc):
        """Test info severity threshold."""
        assert calc.get_severity_from_score(0.0) == "Info"


class TestAdjustVectorBySeverity:
    """Tests for adjust_vector_by_severity method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_critical_adjustment(self, calc):
        """Test critical severity adjustments."""
        vector = CVSSVector()
        adjusted = calc.adjust_vector_by_severity(vector, "critical")
        assert adjusted.attack_complexity == AttackComplexity.LOW
        assert adjusted.privileges_required == PrivilegesRequired.NONE
        assert adjusted.integrity_impact == Impact.HIGH
        assert adjusted.availability_impact == Impact.HIGH

    def test_high_adjustment(self, calc):
        """Test high severity adjustments."""
        vector = CVSSVector()
        adjusted = calc.adjust_vector_by_severity(vector, "high")
        assert adjusted.attack_complexity == AttackComplexity.LOW
        assert adjusted.integrity_impact == Impact.HIGH

    def test_medium_adjustment(self, calc):
        """Test medium severity adjustments."""
        vector = CVSSVector(integrity_impact=Impact.HIGH)
        adjusted = calc.adjust_vector_by_severity(vector, "medium")
        assert adjusted.attack_complexity == AttackComplexity.HIGH

    def test_low_adjustment(self, calc):
        """Test low severity adjustments."""
        vector = CVSSVector()
        adjusted = calc.adjust_vector_by_severity(vector, "low")
        assert adjusted.attack_complexity == AttackComplexity.HIGH
        assert adjusted.integrity_impact == Impact.LOW
        assert adjusted.availability_impact == Impact.NONE

    def test_info_adjustment(self, calc):
        """Test informational severity adjustments."""
        vector = CVSSVector()
        adjusted = calc.adjust_vector_by_severity(vector, "informational")
        assert adjusted.attack_complexity == AttackComplexity.HIGH


class TestCalculateFindingScore:
    """Tests for calculate_finding_score method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_basic_finding(self, calc):
        """Test scoring a basic finding."""
        finding = {
            "id": "TEST-001",
            "title": "Reentrancy",
            "category": "reentrancy",
            "severity": "Critical",
        }
        score = calc.calculate_finding_score(finding)
        assert score.finding_id == "TEST-001"
        assert score.base_score >= 7.0
        assert score.severity in ["Critical", "High"]

    def test_finding_without_id(self, calc):
        """Test finding without ID uses UNK."""
        finding = {"title": "Test", "category": "test", "severity": "Low"}
        score = calc.calculate_finding_score(finding)
        assert score.finding_id == "UNK"

    def test_finding_with_type_instead_of_title(self, calc):
        """Test finding with type field."""
        finding = {"type": "access-control", "severity": "High"}
        score = calc.calculate_finding_score(finding)
        assert score.title == "access-control"


class TestCalculateAllScores:
    """Tests for calculate_all_scores method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_multiple_findings(self, calc):
        """Test scoring multiple findings."""
        findings = [
            {"id": "1", "title": "Bug 1", "severity": "High"},
            {"id": "2", "title": "Bug 2", "severity": "Low"},
        ]
        scores = calc.calculate_all_scores(findings)
        assert len(scores) == 2
        assert scores[0].finding_id == "1"
        assert scores[1].finding_id == "2"

    def test_empty_findings(self, calc):
        """Test with empty findings list."""
        scores = calc.calculate_all_scores([])
        assert scores == []


class TestGenerateRiskMatrix:
    """Tests for generate_risk_matrix method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_empty_findings(self, calc):
        """Test risk matrix with no findings."""
        matrix = calc.generate_risk_matrix([])
        assert all(v == 0 for v in matrix.values())

    def test_critical_finding(self, calc):
        """Test critical finding placement."""
        findings = [{"severity": "Critical"}]
        matrix = calc.generate_risk_matrix(findings)
        assert matrix["high_high"] == 1

    def test_high_finding(self, calc):
        """Test high finding placement."""
        findings = [{"severity": "High"}]
        matrix = calc.generate_risk_matrix(findings)
        assert matrix["high_med"] == 1

    def test_medium_finding(self, calc):
        """Test medium finding placement."""
        findings = [{"severity": "Medium"}]
        matrix = calc.generate_risk_matrix(findings)
        assert matrix["med_med"] == 1

    def test_low_finding(self, calc):
        """Test low finding placement."""
        findings = [{"severity": "Low"}]
        matrix = calc.generate_risk_matrix(findings)
        assert matrix["low_med"] == 1

    def test_info_finding(self, calc):
        """Test info finding placement."""
        findings = [{"severity": "Informational"}]
        matrix = calc.generate_risk_matrix(findings)
        assert matrix["low_low"] == 1

    def test_multiple_findings(self, calc):
        """Test multiple findings."""
        findings = [
            {"severity": "Critical"},
            {"severity": "Critical"},
            {"severity": "High"},
        ]
        matrix = calc.generate_risk_matrix(findings)
        assert matrix["high_high"] == 2
        assert matrix["high_med"] == 1


class TestCalculateOverallRiskScore:
    """Tests for calculate_overall_risk_score method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_empty_findings(self, calc):
        """Test empty findings returns 0."""
        assert calc.calculate_overall_risk_score([]) == 0

    def test_critical_finding(self, calc):
        """Test critical finding weight."""
        findings = [{"severity": "Critical"}]
        score = calc.calculate_overall_risk_score(findings)
        assert score == 25

    def test_mixed_findings(self, calc):
        """Test mixed severity findings."""
        findings = [
            {"severity": "Critical"},  # 25
            {"severity": "High"},      # 15
            {"severity": "Medium"},    # 8
        ]
        score = calc.calculate_overall_risk_score(findings)
        assert score == 48

    def test_capped_at_100(self, calc):
        """Test score is capped at 100."""
        # 5 critical findings = 125, should cap at 100
        findings = [{"severity": "Critical"} for _ in range(5)]
        score = calc.calculate_overall_risk_score(findings)
        assert score == 100


class TestGetDeploymentRecommendation:
    """Tests for get_deployment_recommendation method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_critical_is_no_go(self, calc):
        """Test critical finding results in NO-GO."""
        findings = [{"severity": "Critical"}]
        rec, just, color, bg = calc.get_deployment_recommendation(findings)
        assert rec == "NO-GO"
        assert "critical" in just.lower()
        assert color == "#dc3545"

    def test_two_high_is_no_go(self, calc):
        """Test 2+ high findings results in NO-GO."""
        findings = [
            {"severity": "High"},
            {"severity": "High"},
        ]
        rec, _, _, _ = calc.get_deployment_recommendation(findings)
        assert rec == "NO-GO"

    def test_one_high_is_conditional(self, calc):
        """Test 1 high finding results in CONDITIONAL."""
        findings = [{"severity": "High"}]
        rec, _, color, _ = calc.get_deployment_recommendation(findings)
        assert rec == "CONDITIONAL"
        assert color == "#ff9800"

    def test_three_medium_is_conditional(self, calc):
        """Test 3+ medium findings results in CONDITIONAL."""
        findings = [
            {"severity": "Medium"},
            {"severity": "Medium"},
            {"severity": "Medium"},
        ]
        rec, _, _, _ = calc.get_deployment_recommendation(findings)
        assert rec == "CONDITIONAL"

    def test_few_medium_is_conditional(self, calc):
        """Test 1-2 medium findings results in CONDITIONAL."""
        findings = [{"severity": "Medium"}]
        rec, _, color, _ = calc.get_deployment_recommendation(findings)
        assert rec == "CONDITIONAL"
        assert color == "#ffc107"

    def test_only_low_is_go(self, calc):
        """Test only low findings results in GO."""
        findings = [{"severity": "Low"}, {"severity": "Informational"}]
        rec, _, color, _ = calc.get_deployment_recommendation(findings)
        assert rec == "GO"
        assert color == "#28a745"

    def test_empty_is_go(self, calc):
        """Test no findings results in GO."""
        rec, _, _, _ = calc.get_deployment_recommendation([])
        assert rec == "GO"


class TestClassifyEffort:
    """Tests for classify_effort method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_low_effort_pragma(self, calc):
        """Test pragma issues are low effort."""
        finding = {"title": "Floating pragma version"}
        assert calc.classify_effort(finding) == "low"

    def test_medium_effort_require(self, calc):
        """Test require issues are medium effort."""
        finding = {"title": "Missing require statement"}
        assert calc.classify_effort(finding) == "medium"

    def test_high_effort_reentrancy(self, calc):
        """Test reentrancy is high effort."""
        finding = {"title": "Reentrancy vulnerability"}
        assert calc.classify_effort(finding) == "high"

    def test_default_by_severity_critical(self, calc):
        """Test default for critical is high."""
        finding = {"title": "Unknown issue", "severity": "Critical"}
        assert calc.classify_effort(finding) == "high"

    def test_default_by_severity_medium(self, calc):
        """Test default for medium is medium."""
        finding = {"title": "Unknown issue", "severity": "Medium"}
        assert calc.classify_effort(finding) == "medium"

    def test_default_by_severity_low(self, calc):
        """Test default for low is low."""
        finding = {"title": "Unknown issue", "severity": "Low"}
        assert calc.classify_effort(finding) == "low"


class TestClassifyImpact:
    """Tests for classify_impact method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_critical_is_high_impact(self, calc):
        """Test critical is high impact."""
        finding = {"severity": "Critical"}
        assert calc.classify_impact(finding) == "high"

    def test_high_is_high_impact(self, calc):
        """Test high is high impact."""
        finding = {"severity": "High"}
        assert calc.classify_impact(finding) == "high"

    def test_medium_is_medium_impact(self, calc):
        """Test medium is medium impact."""
        finding = {"severity": "Medium"}
        assert calc.classify_impact(finding) == "medium"

    def test_low_is_low_impact(self, calc):
        """Test low is low impact."""
        finding = {"severity": "Low"}
        assert calc.classify_impact(finding) == "low"


class TestGenerateEffortImpactMatrix:
    """Tests for generate_effort_impact_matrix method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_empty_findings(self, calc):
        """Test with empty findings."""
        matrix = calc.generate_effort_impact_matrix([])
        assert all(cell["count"] == 0 for cell in matrix.values())

    def test_low_effort_high_impact(self, calc):
        """Test low effort high impact classification."""
        findings = [
            {"id": "1", "title": "Event emission missing", "severity": "Critical"}
        ]
        matrix = calc.generate_effort_impact_matrix(findings)
        # Event is medium effort, critical is high impact
        assert matrix["medium_high"]["count"] == 1

    def test_action_labels(self, calc):
        """Test action labels are set."""
        matrix = calc.generate_effort_impact_matrix([])
        assert matrix["low_high"]["action"] == "DO FIRST!"
        assert matrix["high_low"]["action"] == "Avoid"

    def test_finding_details_stored(self, calc):
        """Test finding details are stored."""
        findings = [{"id": "TEST", "title": "Test", "severity": "High"}]
        matrix = calc.generate_effort_impact_matrix(findings)
        # Find the cell with our finding
        for cell in matrix.values():
            if cell["count"] > 0:
                assert cell["findings"][0]["id"] == "TEST"
                break


class TestIdentifyQuickWins:
    """Tests for identify_quick_wins method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_pragma_quick_win(self, calc):
        """Test pragma issues are quick wins."""
        findings = [{"id": "1", "title": "Pragma version issue"}]
        quick_wins = calc.identify_quick_wins(findings)
        assert len(quick_wins) == 1
        assert "pragma" in quick_wins[0]["description"].lower()

    def test_visibility_quick_win(self, calc):
        """Test visibility issues are quick wins."""
        findings = [{"id": "1", "title": "Missing visibility modifier"}]
        quick_wins = calc.identify_quick_wins(findings)
        assert len(quick_wins) == 1

    def test_max_5_quick_wins(self, calc):
        """Test maximum 5 quick wins returned."""
        findings = [
            {"id": str(i), "title": f"Pragma issue {i}"}
            for i in range(10)
        ]
        quick_wins = calc.identify_quick_wins(findings)
        assert len(quick_wins) <= 5

    def test_no_quick_wins(self, calc):
        """Test no quick wins for non-matching findings."""
        findings = [{"id": "1", "title": "Complex architectural issue"}]
        quick_wins = calc.identify_quick_wins(findings)
        assert len(quick_wins) == 0


class TestGetSeverityPercentages:
    """Tests for get_severity_percentages method."""

    @pytest.fixture
    def calc(self):
        return RiskCalculator()

    def test_empty_findings(self, calc):
        """Test with empty findings."""
        percentages = calc.get_severity_percentages([])
        assert percentages["critical_percent"] == 0.0
        assert percentages["high_percent"] == 0.0

    def test_single_severity(self, calc):
        """Test with single severity."""
        findings = [{"severity": "High"}]
        percentages = calc.get_severity_percentages(findings)
        assert percentages["high_percent"] == 100.0

    def test_mixed_severities(self, calc):
        """Test with mixed severities."""
        findings = [
            {"severity": "Critical"},
            {"severity": "High"},
            {"severity": "Medium"},
            {"severity": "Low"},
        ]
        percentages = calc.get_severity_percentages(findings)
        assert percentages["critical_percent"] == 25.0
        assert percentages["high_percent"] == 25.0

    def test_informational_mapped_to_info(self, calc):
        """Test informational mapped to info."""
        findings = [{"severity": "Informational"}]
        percentages = calc.get_severity_percentages(findings)
        assert percentages["info_percent"] == 100.0


# =============================================================================
# Test Main Entry Point
# =============================================================================


class TestCalculatePremiumRiskData:
    """Tests for calculate_premium_risk_data function."""

    def test_empty_findings(self):
        """Test with empty findings."""
        data = calculate_premium_risk_data([])
        assert data["overall_risk_score"] == 0
        assert data["deployment_recommendation"] == "GO"
        assert data["cvss_scores"] == []

    def test_with_findings(self):
        """Test with findings."""
        findings = [
            {
                "id": "1",
                "title": "Reentrancy",
                "category": "reentrancy",
                "severity": "Critical",
            },
            {
                "id": "2",
                "title": "Missing event",
                "category": "event",
                "severity": "Low",
            },
        ]
        data = calculate_premium_risk_data(findings)

        # Check structure
        assert "cvss_scores" in data
        assert "risk_matrix" in data
        assert "overall_risk_score" in data
        assert "deployment_recommendation" in data
        assert "quick_wins" in data
        assert "effort_impact_matrix" in data
        assert "critical_percent" in data

        # Check values
        assert len(data["cvss_scores"]) == 2
        assert data["deployment_recommendation"] == "NO-GO"

    def test_cvss_scores_structure(self):
        """Test CVSS scores have correct structure."""
        findings = [{"id": "TEST", "title": "Test", "severity": "High"}]
        data = calculate_premium_risk_data(findings)

        score = data["cvss_scores"][0]
        assert "finding_id" in score
        assert "title" in score
        assert "base_score" in score
        assert "severity" in score
        assert "vector" in score
