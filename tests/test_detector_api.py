"""
Tests for MIESC Detector API

Tests the core detector API classes and utilities.

Author: Fernando Boiero
License: AGPL-3.0
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from src.detectors.detector_api import (
    BaseDetector,
    Category,
    Finding,
    Location,
    PatternDetector,
    Severity,
    get_registry,
    register_detector,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test all severity values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "informational"

    def test_severity_from_string(self):
        """Test converting string to Severity."""
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("Medium") == Severity.MEDIUM

    def test_severity_comparison(self):
        """Test severity comparison operators."""
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL
        assert Severity.INFO < Severity.LOW


class TestCategory:
    """Tests for Category enum."""

    def test_category_values(self):
        """Test common category values."""
        assert Category.REENTRANCY.value == "reentrancy"
        assert Category.ACCESS_CONTROL.value == "access_control"
        assert Category.ARITHMETIC.value == "arithmetic"
        assert Category.FLASH_LOAN.value == "flash_loan"
        assert Category.CUSTOM.value == "custom"

    def test_all_categories_defined(self):
        """Test that expected categories exist."""
        expected = [
            "REENTRANCY",
            "ACCESS_CONTROL",
            "ARITHMETIC",
            "FLASH_LOAN",
            "ORACLE_MANIPULATION",
            "GOVERNANCE",
            "RUG_PULL",
            "HONEYPOT",
            "PROXY_UPGRADE",
            "CENTRALIZATION",
            "DOS",
            "FRONT_RUNNING",
            "TIMESTAMP_DEPENDENCY",
            "UNCHECKED_RETURN",
            "GAS_OPTIMIZATION",
            "CUSTOM",
        ]
        for cat in expected:
            assert hasattr(Category, cat)


class TestLocation:
    """Tests for Location dataclass."""

    def test_location_creation(self):
        """Test creating a Location."""
        loc = Location(
            file_path=Path("Contract.sol"),
            line_start=10,
            line_end=15,
        )
        assert loc.file_path == Path("Contract.sol")
        assert loc.line_start == 10
        assert loc.line_end == 15

    def test_location_str_with_file_and_line(self):
        """Test Location string representation with file and line."""
        loc = Location(file_path=Path("Token.sol"), line_start=42)
        assert str(loc) == "Token.sol:42"

    def test_location_str_line_only(self):
        """Test Location string with line only."""
        loc = Location(line_start=100)
        assert str(loc) == "line 100"

    def test_location_str_unknown(self):
        """Test Location string when nothing is set."""
        loc = Location()
        assert str(loc) == "unknown"


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        """Test creating a Finding with all fields."""
        finding = Finding(
            detector="test-detector",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            category=Category.REENTRANCY,
            confidence="high",
            location=Location(line_start=10),
            code_snippet="test code",
            recommendation="Fix it",
            references=["https://example.com"],
            cwe_id="CWE-123",
            swc_id="SWC-107",
            metadata={"custom": "value"},
        )

        assert finding.detector == "test-detector"
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert finding.category == Category.REENTRANCY

    def test_finding_defaults(self):
        """Test Finding default values."""
        finding = Finding(
            detector="test",
            title="Test",
            description="Desc",
            severity=Severity.LOW,
        )

        assert finding.category == Category.CUSTOM
        assert finding.confidence == "high"
        assert finding.location is None
        assert finding.references == []
        assert finding.metadata == {}

    def test_finding_to_dict(self):
        """Test Finding serialization."""
        finding = Finding(
            detector="test-detector",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            category=Category.REENTRANCY,
            location=Location(line_start=10),
            cwe_id="CWE-123",
            swc_id="SWC-107",
        )

        data = finding.to_dict()

        assert data["detector"] == "test-detector"
        assert data["title"] == "Test Finding"
        assert data["severity"] == "high"
        assert data["category"] == "reentrancy"
        assert data["line"] == 10
        assert data["cwe_id"] == "CWE-123"
        assert data["swc_id"] == "SWC-107"

    def test_finding_to_dict_no_location(self):
        """Test Finding serialization without location."""
        finding = Finding(
            detector="test",
            title="Test",
            description="Desc",
            severity=Severity.LOW,
        )

        data = finding.to_dict()
        assert data["location"] is None
        assert data["line"] is None


class TestBaseDetector:
    """Tests for BaseDetector abstract class."""

    def test_concrete_detector(self):
        """Test creating a concrete detector."""

        class MyDetector(BaseDetector):
            name = "my-detector"
            description = "My test detector"
            category = Category.CUSTOM

            def analyze(self, source_code, file_path=None):
                return []

        detector = MyDetector()
        assert detector.name == "my-detector"
        assert detector.enabled is True

    def test_detector_enabled_property(self):
        """Test enabling/disabling detector."""

        class TestDetector(BaseDetector):
            name = "test"

            def analyze(self, source_code, file_path=None):
                return []

        detector = TestDetector()
        assert detector.enabled is True

        detector.enabled = False
        assert detector.enabled is False

    def test_detector_configure(self):
        """Test detector configuration."""

        class ConfigurableDetector(BaseDetector):
            name = "configurable"

            def analyze(self, source_code, file_path=None):
                return []

        detector = ConfigurableDetector()
        detector.configure({"option": "value", "threshold": 5})

        assert detector._config == {"option": "value", "threshold": 5}

    def test_should_run_no_patterns(self):
        """Test should_run with no target patterns."""

        class UniversalDetector(BaseDetector):
            name = "universal"
            target_patterns = []

            def analyze(self, source_code, file_path=None):
                return []

        detector = UniversalDetector()
        assert detector.should_run("any source code") is True

    def test_should_run_with_patterns(self):
        """Test should_run with target patterns."""

        class ERC20Detector(BaseDetector):
            name = "erc20"
            target_patterns = ["ERC20", "balanceOf"]

            def analyze(self, source_code, file_path=None):
                return []

        detector = ERC20Detector()

        # Should match
        assert detector.should_run("contract MyToken is ERC20 {}") is True
        assert detector.should_run("mapping balanceOf;") is True

        # Should not match
        assert detector.should_run("contract SimpleStorage {}") is False

    def test_analyze_file(self):
        """Test analyze_file convenience method."""

        class SimpleDetector(BaseDetector):
            name = "simple"

            def analyze(self, source_code, file_path=None):
                if "vulnerable" in source_code:
                    return [
                        self.create_finding(
                            title="Vulnerability Found",
                            description="Found vulnerable keyword",
                        )
                    ]
                return []

        detector = SimpleDetector()

        with TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.sol"
            test_file.write_text("contract Vulnerable { // vulnerable }")

            findings = detector.analyze_file(test_file)
            assert len(findings) == 1
            assert findings[0].title == "Vulnerability Found"

    def test_create_finding(self):
        """Test create_finding helper method."""

        class TestDetector(BaseDetector):
            name = "test-detector"
            category = Category.REENTRANCY
            default_severity = Severity.HIGH

            def analyze(self, source_code, file_path=None):
                return []

        detector = TestDetector()

        finding = detector.create_finding(
            title="Test Finding",
            description="Test description",
            line=42,
            code_snippet="test code",
        )

        assert finding.detector == "test-detector"
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH  # Default
        assert finding.category == Category.REENTRANCY
        assert finding.location.line_start == 42
        assert finding.code_snippet == "test code"

    def test_create_finding_custom_severity(self):
        """Test create_finding with custom severity."""

        class TestDetector(BaseDetector):
            name = "test"
            default_severity = Severity.MEDIUM

            def analyze(self, source_code, file_path=None):
                return []

        detector = TestDetector()

        finding = detector.create_finding(
            title="Critical Issue",
            description="Very bad",
            severity=Severity.CRITICAL,  # Override default
        )

        assert finding.severity == Severity.CRITICAL

    def test_find_pattern(self):
        """Test find_pattern helper method."""

        class PatternMatchingDetector(BaseDetector):
            name = "pattern-matcher"

            def analyze(self, source_code, file_path=None):
                return []

        detector = PatternMatchingDetector()
        source = """
        line 1: safe code
        line 2: dangerous call here
        line 3: another dangerous thing
        line 4: safe again
        """

        results = detector.find_pattern(source, r"dangerous")

        assert len(results) == 2
        # Each result is (match, line_number, line_content)
        assert results[0][1] == 3  # Line 2 (0-indexed would be different)
        assert results[1][1] == 4


class TestPatternDetector:
    """Tests for PatternDetector class."""

    def test_pattern_detector_analyze(self):
        """Test PatternDetector with PATTERNS attribute."""

        class SimplePatternDetector(PatternDetector):
            name = "simple-patterns"
            category = Category.UNCHECKED_RETURN
            default_severity = Severity.HIGH

            PATTERNS = [
                (r"\.call\{", "Unchecked low-level call", Severity.HIGH),
                (r"\.send\(", "Unchecked send", Severity.MEDIUM),
            ]

        detector = SimplePatternDetector()
        source = """
        function withdraw() {
            msg.sender.call{value: amount}("");
            msg.sender.send(amount);
        }
        """

        findings = detector.analyze(source)

        assert len(findings) >= 2
        severities = {f.severity for f in findings}
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities

    def test_pattern_detector_no_matches(self):
        """Test PatternDetector with no matches."""

        class NoMatchDetector(PatternDetector):
            name = "no-match"
            PATTERNS = [
                (r"selfdestruct\(", "Selfdestruct found", Severity.CRITICAL),
            ]

        detector = NoMatchDetector()
        source = "contract Safe { function safeMethod() {} }"

        findings = detector.analyze(source)
        assert len(findings) == 0


class TestDetectorRegistry:
    """Tests for detector registry functions."""

    def test_registry_singleton(self):
        """Test registry is a singleton."""
        reg1 = get_registry()
        reg2 = get_registry()
        assert reg1 is reg2

    def test_register_detector(self):
        """Test registering a detector."""
        registry = get_registry()

        class TestDetector(BaseDetector):
            name = "registry-test"

            def analyze(self, source_code, file_path=None):
                return []

        detector = TestDetector()
        register_detector(detector)

        assert registry.get("registry-test") is detector

    def test_list_detectors(self):
        """Test listing registered detectors."""
        registry = get_registry()

        class Detector1(BaseDetector):
            name = "detector-1"

            def analyze(self, source_code, file_path=None):
                return []

        class Detector2(BaseDetector):
            name = "detector-2"

            def analyze(self, source_code, file_path=None):
                return []

        register_detector(Detector1())
        register_detector(Detector2())

        names = registry.list_detectors()

        assert "detector-1" in names
        assert "detector-2" in names

    def test_get_detector_not_found(self):
        """Test getting non-existent detector."""
        registry = get_registry()
        result = registry.get("nonexistent-12345")
        assert result is None

    def test_unregister_detector(self):
        """Test unregistering a detector."""
        registry = get_registry()

        class TempDetector(BaseDetector):
            name = "temp-to-remove"

            def analyze(self, source_code, file_path=None):
                return []

        register_detector(TempDetector())
        assert registry.get("temp-to-remove") is not None

        registry.unregister("temp-to-remove")
        assert registry.get("temp-to-remove") is None

    def test_register_class(self):
        """Test registering a detector class."""
        registry = get_registry()

        class ClassBasedDetector(BaseDetector):
            name = "class-based"

            def analyze(self, source_code, file_path=None):
                return []

        registry.register_class(ClassBasedDetector)
        assert registry.get("class-based") is not None

    def test_run_all(self):
        """Test running all detectors."""
        registry = get_registry()

        class RunAllDetector(BaseDetector):
            name = "run-all-test"

            def analyze(self, source_code, file_path=None):
                if "test" in source_code:
                    return [
                        self.create_finding(
                            title="Test found",
                            description="Found test keyword",
                        )
                    ]
                return []

        register_detector(RunAllDetector())

        findings = registry.run_all("some test source code")
        assert any(f.detector == "run-all-test" for f in findings)

    def test_get_summary(self):
        """Test getting findings summary."""
        registry = get_registry()

        findings = [
            Finding(
                detector="test",
                title="Finding 1",
                description="Desc",
                severity=Severity.HIGH,
                category=Category.REENTRANCY,
            ),
            Finding(
                detector="test",
                title="Finding 2",
                description="Desc",
                severity=Severity.HIGH,
                category=Category.ACCESS_CONTROL,
            ),
            Finding(
                detector="other",
                title="Finding 3",
                description="Desc",
                severity=Severity.LOW,
                category=Category.REENTRANCY,
            ),
        ]

        summary = registry.get_summary(findings)

        assert summary["total"] == 3
        assert summary["by_severity"]["high"] == 2
        assert summary["by_severity"]["low"] == 1
        assert summary["by_category"]["reentrancy"] == 2
        assert summary["by_detector"]["test"] == 2


class TestIntegration:
    """Integration tests for detector API."""

    def test_full_detector_workflow(self):
        """Test complete detector workflow."""

        class ReentrancyDetector(BaseDetector):
            name = "reentrancy"
            description = "Detects reentrancy vulnerabilities"
            category = Category.REENTRANCY
            default_severity = Severity.CRITICAL
            target_patterns = ["call", "transfer", "send"]

            def analyze(self, source_code, file_path=None):
                findings = []

                # Check for state changes after external calls
                call_matches = self.find_pattern(source_code, r"\.call\{")
                for _match, line, code in call_matches:
                    findings.append(
                        self.create_finding(
                            title="Potential Reentrancy",
                            description="External call detected, verify state changes",
                            line=line,
                            code_snippet=code,
                            swc_id="SWC-107",
                            cwe_id="CWE-841",
                        )
                    )

                return findings

        detector = ReentrancyDetector()

        source = """
        contract Vulnerable {
            mapping(address => uint) balances;

            function withdraw() external {
                uint balance = balances[msg.sender];
                (bool success,) = msg.sender.call{value: balance}("");
                require(success);
                balances[msg.sender] = 0;
            }
        }
        """

        # Check if should run
        assert detector.should_run(source) is True

        # Run analysis
        findings = detector.analyze(source)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.detector == "reentrancy"
        assert finding.severity == Severity.CRITICAL
        assert finding.category == Category.REENTRANCY
        assert finding.swc_id == "SWC-107"

        # Test serialization
        data = finding.to_dict()
        assert data["detector"] == "reentrancy"
        assert data["swc_id"] == "SWC-107"

    def test_multiple_detectors_on_same_source(self):
        """Test running multiple detectors on same source."""

        class CallDetector(BaseDetector):
            name = "call-detector"
            category = Category.UNCHECKED_RETURN

            def analyze(self, source_code, file_path=None):
                findings = []
                for _match, line, _code in self.find_pattern(source_code, r"\.call\{"):
                    findings.append(
                        self.create_finding(
                            title="Call detected",
                            description="Low-level call",
                            line=line,
                        )
                    )
                return findings

        class TransferDetector(BaseDetector):
            name = "transfer-detector"
            category = Category.ARITHMETIC

            def analyze(self, source_code, file_path=None):
                findings = []
                for _match, line, _code in self.find_pattern(source_code, r"\.transfer\("):
                    findings.append(
                        self.create_finding(
                            title="Transfer detected",
                            description="Transfer call",
                            line=line,
                        )
                    )
                return findings

        source = """
        function test() {
            addr.call{value: 1}("");
            payable(addr).transfer(1);
        }
        """

        call_findings = CallDetector().analyze(source)
        transfer_findings = TransferDetector().analyze(source)

        assert len(call_findings) >= 1
        assert len(transfer_findings) >= 1
        assert call_findings[0].category != transfer_findings[0].category

    def test_find_multiline_pattern(self):
        """Test find_multiline_pattern method."""
        from src.detectors.detector_api import BaseDetector, Category

        class MultilineDetector(BaseDetector):
            name = "multiline-detector"
            category = Category.REENTRANCY

            def analyze(self, source_code, file_path=None):
                return []

        source = """
contract Test {
    function unsafe() external {
        require(
            msg.sender == owner,
            "Not owner"
        );
        doSomething();
    }
}
"""

        detector = MultilineDetector()
        pattern = r"require\s*\([^;]+\);"
        results = detector.find_multiline_pattern(source, pattern)

        assert isinstance(results, list)
        assert len(results) >= 1
        for _match, start_line, end_line in results:
            assert start_line >= 1
            assert end_line >= start_line

    def test_pattern_detector_with_two_element_tuple(self):
        """Test PatternDetector with patterns that have no severity."""
        from src.detectors.detector_api import Category, PatternDetector, Severity

        class TwoElementPatternDetector(PatternDetector):
            name = "two-element-pattern"
            category = Category.ARITHMETIC
            default_severity = Severity.MEDIUM

            # Patterns with only (regex, description) - no severity
            PATTERNS = [
                (r"unchecked\s*\{", "Unchecked arithmetic block"),
                (r"assembly\s*\{", "Assembly block"),
            ]

        source = """
        function test() {
            unchecked {
                x++;
            }
            assembly {
                // some inline assembly
            }
        }
        """

        detector = TwoElementPatternDetector()
        findings = detector.analyze(source)

        # Should find both patterns
        assert len(findings) >= 2

        # All findings should use default severity
        for finding in findings:
            assert finding.severity == Severity.MEDIUM

    def test_pattern_detector_should_run_false(self):
        """Test PatternDetector when should_run returns False."""
        from src.detectors.detector_api import Category, PatternDetector, Severity

        class ConditionalPatternDetector(PatternDetector):
            name = "conditional-pattern"
            category = Category.REENTRANCY
            # target_patterns must match for should_run to return True
            target_patterns = [r"NonExistentPattern123"]

            PATTERNS = [
                (r"\.call\{", "Call detected", Severity.HIGH),
            ]

        source = """
        contract Test {
            function test() { addr.call{value: 1}(""); }
        }
        """

        detector = ConditionalPatternDetector()
        findings = detector.analyze(source)

        # should_run should return False because target pattern doesn't match
        assert len(findings) == 0

    def test_pattern_detector_three_element_tuple(self):
        """Test PatternDetector with patterns that include severity."""
        from src.detectors.detector_api import Category, PatternDetector, Severity

        class ThreeElementPatternDetector(PatternDetector):
            name = "three-element-pattern"
            category = Category.UNCHECKED_RETURN
            default_severity = Severity.LOW

            # Patterns with (regex, description, severity)
            PATTERNS = [
                (r"\.call\{value:", "External call with value", Severity.HIGH),
                (r"\.delegatecall\(", "Delegatecall detected", Severity.CRITICAL),
            ]

        source = """
        function test() {
            addr.call{value: 1}("");
            addr.delegatecall(data);
        }
        """

        detector = ThreeElementPatternDetector()
        findings = detector.analyze(source)

        assert len(findings) >= 2

        # Check that each pattern uses its specified severity
        severities = {f.severity for f in findings}
        assert Severity.HIGH in severities or Severity.CRITICAL in severities
