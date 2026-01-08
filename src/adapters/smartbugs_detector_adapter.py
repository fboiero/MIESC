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
from typing import Any, Dict, List

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from detectors.smartbugs_detectors import SmartBugsDetectorEngine, SmartBugsFinding
from src.core.tool_protocol import (
    ToolMetadata,
    ToolStatus,
    ToolCategory,
    ToolCapability,
)


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
    layer = 9  # Layer 9: Advanced Detection
    description = "SmartBugs-specific vulnerability detection"

    SEVERITY_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Info",
    }

    def __init__(self):
        self.engine = SmartBugsDetectorEngine()

    def is_available(self) -> ToolStatus:
        """Check if SmartBugs detector engine is available."""
        try:
            from detectors.smartbugs_detectors import SmartBugsDetectorEngine

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
                    detection_types=["arithmetic", "bad_randomness", "denial_of_service", "front_running"],
                )
            ],
            is_optional=True,
        )

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Analyze a contract for SmartBugs-category vulnerabilities."""
        path = Path(contract_path)

        if not path.exists():
            return {"success": False, "error": f"File not found: {contract_path}", "findings": []}

        try:
            findings = self.engine.analyze_file(path)
            miesc_findings = self._convert_findings(findings, path)

            return {
                "success": True,
                "tool": self.name,
                "layer": self.layer,
                "file": str(path),
                "timestamp": datetime.now().isoformat(),
                "findings": miesc_findings,
                "summary": self.engine.get_summary(findings),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "findings": []}

    def _convert_findings(
        self, findings: List[SmartBugsFinding], file_path: Path
    ) -> List[Dict[str, Any]]:
        """Convert SmartBugs findings to MIESC standard format."""
        miesc_findings = []

        for finding in findings:
            miesc_finding = {
                "id": f"SB-{finding.category.upper()}-{len(miesc_findings)+1}",
                "title": finding.title,
                "description": finding.description,
                "severity": self.SEVERITY_MAP.get(finding.severity.value, "Medium"),
                "confidence": finding.confidence,
                "category": finding.category,
                "swc_id": finding.swc_id,
                "location": {
                    "file": str(file_path),
                    "line": finding.line,
                    "snippet": finding.code_snippet,
                },
                "tool": self.name,
                "layer": self.layer,
            }

            miesc_findings.append(miesc_finding)

        return miesc_findings

    def analyze_source(self, source_code: str) -> Dict[str, Any]:
        """Analyze source code directly."""
        try:
            findings = self.engine.analyze(source_code)
            miesc_findings = []

            for finding in findings:
                miesc_finding = {
                    "id": f"SB-{finding.category.upper()}-{len(miesc_findings)+1}",
                    "title": finding.title,
                    "description": finding.description,
                    "severity": self.SEVERITY_MAP.get(finding.severity.value, "Medium"),
                    "confidence": finding.confidence,
                    "category": finding.category,
                    "swc_id": finding.swc_id,
                    "location": {"line": finding.line, "snippet": finding.code_snippet},
                    "tool": self.name,
                    "layer": self.layer,
                }

                miesc_findings.append(miesc_finding)

            return {
                "success": True,
                "tool": self.name,
                "layer": self.layer,
                "timestamp": datetime.now().isoformat(),
                "findings": miesc_findings,
                "summary": self.engine.get_summary(findings),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "findings": []}

    @staticmethod
    def get_detector_info() -> Dict[str, Any]:
        """Return detector information."""
        return {
            "layer": 2,
            "name": "SmartBugs-Specific Detection",
            "description": "Targets SmartBugs vulnerability categories with historically low recall",
            "detectors": [
                "Arithmetic Overflow/Underflow (SWC-101)",
                "Bad Randomness (SWC-120)",
                "Denial of Service (SWC-113/128)",
                "Front Running (SWC-114)",
                "Short Address Attack (SWC-129)",
            ],
            "categories": [
                "arithmetic",
                "bad_randomness",
                "denial_of_service",
                "front_running",
                "short_addresses",
            ],
        }


def main():
    """Test the adapter."""
    adapter = SmartBugsDetectorAdapter()

    print("\n" + "=" * 60)
    print("  MIESC SmartBugs Detector Adapter")
    print("=" * 60)

    info = adapter.get_detector_info()
    print(f"\nLayer: {info['layer']}")
    print(f"Detectors: {len(info['detectors'])}")
    for d in info["detectors"]:
        print(f"  - {d}")

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

    print("\n" + "-" * 60)
    print("  Testing with vulnerable sample contract")
    print("-" * 60)

    result = adapter.analyze_source(sample)

    if result["success"]:
        print(f"\nFindings: {len(result['findings'])}")
        for f in result["findings"]:
            print(f"  [{f['severity']}] {f['title']} - {f['category']}")
            if f["location"].get("line"):
                print(f"    Line {f['location']['line']}: {f['location']['snippet']}")
        print(f"\nSummary: {result['summary']}")
    else:
        print(f"Error: {result['error']}")


if __name__ == "__main__":
    main()
