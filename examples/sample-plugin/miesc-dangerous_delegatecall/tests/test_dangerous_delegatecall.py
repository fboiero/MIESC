"""Tests for dangerous_delegatecall detector."""

import pytest
from dangerous_delegatecall.detectors import DangerousDelegatecallDetector


class TestDangerousDelegatecallDetector:
    """Test suite for DangerousDelegatecallDetector."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = DangerousDelegatecallDetector()

    def test_detector_metadata(self):
        """Test detector has correct metadata."""
        assert self.detector.name == "dangerous_delegatecall"
        assert self.detector.version == "0.1.0"
        assert self.detector.category == "security"

    def test_analyze_empty_source(self):
        """Test analyzing empty source code."""
        findings = self.detector.analyze("")
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_analyze_safe_contract(self):
        """Test analyzing a safe contract without delegatecall."""
        safe_code = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract SafeContract {
            uint256 public value;

            function setValue(uint256 _value) external {
                value = _value;
            }
        }
        """
        findings = self.detector.analyze(safe_code)
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_detect_basic_delegatecall(self):
        """Test detecting basic delegatecall usage."""
        vulnerable_code = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract Proxy {
            address public implementation;

            function forward(bytes memory data) external {
                implementation.delegatecall(data);
            }
        }
        """
        findings = self.detector.analyze(vulnerable_code)
        assert len(findings) > 0

        # Should detect delegatecall and proxy pattern
        titles = [f.title for f in findings]
        assert any("Delegatecall" in t for t in titles)

    def test_detect_user_supplied_address(self):
        """Test detecting delegatecall to user-supplied address."""
        vulnerable_code = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract Vulnerable {
            function execute(address target, bytes memory data) public {
                target.delegatecall(data);
            }
        }
        """
        findings = self.detector.analyze(vulnerable_code)
        assert len(findings) > 0

        # Should detect critical user-supplied address issue
        severities = [f.severity.name for f in findings]
        assert "CRITICAL" in severities

    def test_detect_unprotected_delegatecall(self):
        """Test detecting unprotected delegatecall in public function."""
        vulnerable_code = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract Vulnerable {
            address public impl;

            function forward(bytes memory data) public {
                impl.delegatecall(data);
            }
        }
        """
        findings = self.detector.analyze(vulnerable_code)

        # Should detect unprotected delegatecall
        titles = [f.title for f in findings]
        assert any("Unprotected" in t for t in titles)

    def test_protected_delegatecall_not_flagged_as_unprotected(self):
        """Test that protected delegatecall is not flagged as unprotected."""
        safe_code = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract Safe {
            address public impl;
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner);
                _;
            }

            function forward(bytes memory data) public onlyOwner {
                impl.delegatecall(data);
            }
        }
        """
        findings = self.detector.analyze(safe_code)

        # Should NOT detect "Unprotected delegatecall" (it has onlyOwner)
        titles = [f.title for f in findings]
        unprotected_findings = [t for t in titles if "Unprotected" in t]
        assert len(unprotected_findings) == 0

    def test_findings_have_recommendations(self):
        """Test that all findings have recommendations."""
        vulnerable_code = """
        pragma solidity ^0.8.0;
        contract Test {
            function exec(address t, bytes memory d) public {
                t.delegatecall(d);
            }
        }
        """
        findings = self.detector.analyze(vulnerable_code)

        for finding in findings:
            assert finding.recommendation, f"Finding '{finding.title}' has no recommendation"
