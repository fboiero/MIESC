#!/usr/bin/env python3
"""
MIESC v4.1 - SmartBugs Detector Adapter

Integrates SmartBugs-specific vulnerability detectors into the MIESC pipeline.
These detectors target vulnerability categories with historically low recall:
- Arithmetic (overflow/underflow)
- Bad Randomness
- Denial of Service
- Front Running
- Short Addresses

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from miesc.core.tool_protocol import (  # noqa: E402
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)
from miesc.detectors.smartbugs_detectors import SmartBugsDetectorEngine  # noqa: E402
from miesc.detectors.transient_storage_detector import TransientStorageDetector  # noqa: E402


class SmartBugsDetectorAdapter:
    """
    Adapter for SmartBugs-specific vulnerability detection.

    Targets categories with historically 0% recall in SmartBugs benchmark:
    - arithmetic (overflow/underflow for Solidity < 0.8)
    - bad_randomness (weak PRNG sources)
    - denial_of_service (gas limit, failed calls)
    - front_running (transaction ordering)
    - short_addresses (input validation)
    """

    name = "smartbugs-detector"
    layer = 6  # Layer 6: ML and specialized benchmark detectors
    description = "SmartBugs-specific vulnerability detection"

    SEVERITY_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Info",
    }

    def __init__(self) -> None:
        self.engine = SmartBugsDetectorEngine()
        self.transient_detector = TransientStorageDetector()

    def is_available(self) -> ToolStatus:
        """Check if SmartBugs detector engine is available."""
        try:
            from miesc.detectors.smartbugs_detectors import SmartBugsDetectorEngine  # noqa: F401

            return ToolStatus.AVAILABLE
        except ImportError:
            return ToolStatus.NOT_INSTALLED

    def get_metadata(self) -> ToolMetadata:
        """Return tool metadata."""
        return ToolMetadata(
            name=self.name,
            version="1.0.0",
            category=ToolCategory.STATIC_ANALYSIS,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://fboiero.github.io/MIESC",
            installation_cmd="pip install -e .",
            capabilities=[
                ToolCapability(
                    name="smartbugs_vulnerability_detection",
                    description="SmartBugs-specific vulnerability detection",
                    supported_languages=["solidity"],
                    detection_types=[
                        "arithmetic",
                        "bad_randomness",
                        "denial_of_service",
                        "front_running",
                        "transient_storage_reentrancy",
                    ],
                )
            ],
            is_optional=True,
        )

    def analyze(self, contract_path: str, **kwargs: Any) -> Dict[str, Any]:
        """Analyze a contract for SmartBugs-category vulnerabilities."""
        path = Path(contract_path)

        if not path.exists():
            return {"success": False, "error": f"File not found: {contract_path}", "findings": []}

        try:
            findings = self.engine.analyze_file(path)
            source_code = path.read_text(encoding="utf-8")
            findings.extend(self.transient_detector.analyze(source_code, path))
            miesc_findings = self._convert_findings(findings, path)

            return {
                "success": True,
                "tool": self.name,
                "layer": self.layer,
                "file": str(path),
                "timestamp": datetime.now().isoformat(),
                "findings": miesc_findings,
                "summary": self._build_summary(findings),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "findings": []}

    def _convert_findings(
        self, findings: List[Any], file_path: Optional[Path] = None
    ) -> List[Dict[str, Any]]:
        """Convert SmartBugs findings to MIESC standard format."""
        miesc_findings: List[Dict[str, Any]] = []

        for finding in findings:
            category = self._finding_category(finding)
            line = self._finding_line(finding)
            snippet = self._finding_snippet(finding)
            miesc_finding = {
                "id": f"SB-{category.upper()}-{len(miesc_findings)+1}",
                "title": finding.title,
                "description": finding.description,
                "severity": self.SEVERITY_MAP.get(self._finding_severity(finding), "Medium"),
                "confidence": finding.confidence,
                "category": category,
                "swc_id": getattr(finding, "swc_id", None) or "",
                "location": {
                    "file": str(file_path) if file_path else None,
                    "line": line,
                    "snippet": snippet,
                },
                "tool": self.name,
                "layer": self.layer,
            }

            recommendation = getattr(finding, "recommendation", "")
            references = getattr(finding, "references", [])
            metadata = getattr(finding, "metadata", {})
            if recommendation:
                miesc_finding["recommendation"] = recommendation
            if references:
                miesc_finding["references"] = references
            if metadata:
                miesc_finding["metadata"] = metadata

            miesc_findings.append(miesc_finding)

        return miesc_findings

    def analyze_source(self, source_code: str) -> Dict[str, Any]:
        """Analyze source code directly."""
        try:
            findings = self.engine.analyze(source_code)
            findings.extend(self.transient_detector.analyze(source_code))
            miesc_findings = self._convert_findings(findings)

            return {
                "success": True,
                "tool": self.name,
                "layer": self.layer,
                "timestamp": datetime.now().isoformat(),
                "findings": miesc_findings,
                "summary": self._build_summary(findings),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "findings": []}

    def _build_summary(self, findings: List[Any]) -> Dict[str, Any]:
        """Generate a summary for legacy SmartBugs and generic detector findings."""
        summary: Dict[str, Any] = {
            "total": len(findings),
            "by_severity": {},
            "by_category": {},
            "by_detector": {},
        }
        for finding in findings:
            severity = self._finding_severity(finding)
            category = self._finding_category(finding)
            detector = getattr(finding, "detector", self.name)
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
            summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
            summary["by_detector"][detector] = summary["by_detector"].get(detector, 0) + 1
        return summary

    @staticmethod
    def _finding_category(finding: Any) -> str:
        category = getattr(finding, "category", "unknown")
        value = getattr(category, "value", category)
        return str(value)

    @staticmethod
    def _finding_severity(finding: Any) -> str:
        severity = getattr(finding, "severity", "medium")
        value = getattr(severity, "value", severity)
        return str(value).lower()

    @staticmethod
    def _finding_line(finding: Any) -> Optional[int]:
        if hasattr(finding, "line"):
            return finding.line
        location = getattr(finding, "location", None)
        return getattr(location, "line_start", None)

    @staticmethod
    def _finding_snippet(finding: Any) -> Optional[str]:
        return getattr(finding, "code_snippet", None)

    @staticmethod
    def get_detector_info() -> Dict[str, Any]:
        """Return detector information."""
        return {
            "layer": 6,
            "name": "SmartBugs-Specific Detection",
            "description": "Targets SmartBugs vulnerability categories with historically low recall",
            "detectors": [
                "Arithmetic Overflow/Underflow (SWC-101)",
                "Bad Randomness (SWC-120)",
                "Denial of Service (SWC-113/128)",
                "Front Running (SWC-114)",
                "Short Address Attack (SWC-129)",
                "EIP-1153 Transient Storage Reentrancy",
            ],
            "categories": [
                "arithmetic",
                "bad_randomness",
                "denial_of_service",
                "front_running",
                "short_addresses",
                "reentrancy",
            ],
        }


def main() -> None:  # pragma: no cover - manual demo harness, not shipped logic
    """Test the adapter."""
    adapter = SmartBugsDetectorAdapter()

    print("\n" + "=" * 60)  # noqa: T201
    print("  MIESC SmartBugs Detector Adapter")  # noqa: T201
    print("=" * 60)  # noqa: T201

    info = adapter.get_detector_info()
    print(f"\nLayer: {info['layer']}")  # noqa: T201
    print(f"Detectors: {len(info['detectors'])}")  # noqa: T201
    for d in info["detectors"]:
        print(f"  - {d}")  # noqa: T201

    # Test with sample vulnerable code
    sample = """
    pragma solidity ^0.4.24;

    contract VulnerableContract {
        uint256 public totalSupply;
        mapping(address => uint256) public balances;
        address[] public investors;

        function deposit() public payable {
            balances[msg.sender] += msg.value;  // Overflow!
            investors.push(msg.sender);
        }

        function withdraw(uint256 amount) public {
            balances[msg.sender] -= amount;  // Underflow!
            msg.sender.transfer(amount);
        }

        function random() public view returns (uint) {
            return uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
        }

        function pickWinner() public {
            uint winner = random() % investors.length;
            // Front-running target
        }

        function refundAll() public {
            for (uint i = 0; i < investors.length; i++) {
                investors[i].transfer(balances[investors[i]]);
            }
        }

        function transfer(address to, uint256 value) public returns (bool) {
            balances[msg.sender] -= value;
            balances[to] += value;
            return true;
        }
    }
    """

    print("\n" + "-" * 60)  # noqa: T201
    print("  Testing with vulnerable sample contract")  # noqa: T201
    print("-" * 60)  # noqa: T201

    result = adapter.analyze_source(sample)

    if result["success"]:
        print(f"\nFindings: {len(result['findings'])}")  # noqa: T201
        for f in result["findings"]:
            print(f"  [{f['severity']}] {f['title']} - {f['category']}")  # noqa: T201
            if f["location"].get("line"):
                print(f"    Line {f['location']['line']}: {f['location']['snippet']}")  # noqa: T201
        print(f"\nSummary: {result['summary']}")  # noqa: T201
    else:
        print(f"Error: {result['error']}")  # noqa: T201


if __name__ == "__main__":
    main()
