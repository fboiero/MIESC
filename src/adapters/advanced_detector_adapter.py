#!/usr/bin/env python3
"""
MIESC v4.1 - Advanced Detector Adapter

Integrates advanced vulnerability detectors into the MIESC pipeline:
- Rug Pull Detection
- Governance Attacks
- Token Security (Honeypot)
- Proxy/Upgrade Vulnerabilities
- Centralization Risks

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

from detectors.advanced_detectors import AdvancedDetectorEngine, AdvancedFinding
from src.core.tool_protocol import (
    ToolMetadata,
    ToolStatus,
    ToolCategory,
    ToolCapability,
)


class AdvancedDetectorAdapter:
    """
    Adapter for advanced vulnerability detection.

    Integrates rug pull, governance, token security, proxy,
    and centralization detectors into the MIESC pipeline.
    """

    name = "advanced-detector"
    layer = 9  # Layer 9: Advanced Detection
    description = "Advanced vulnerability detection (rug pull, honeypot, governance)"

    def is_available(self) -> ToolStatus:
        """Check if advanced detector engine is available."""
        try:
            from detectors.advanced_detectors import AdvancedDetectorEngine

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
                    name="advanced_vulnerability_detection",
                    description="Advanced vulnerability detection (rug pull, honeypot, governance)",
                    supported_languages=["solidity"],
                    detection_types=["rug_pull", "governance_attack", "honeypot", "proxy_upgrade"],
                )
            ],
            is_optional=True,
        )

    # SWC mappings for advanced vulnerabilities
    CATEGORY_TO_SWC = {
        "rug_pull": "SWC-105",  # Access Control
        "governance_attack": "SWC-105",
        "honeypot": "SWC-132",  # Unexpected Ether balance
        "token_security": "SWC-132",
        "proxy_upgrade": "SWC-112",  # Delegatecall
        "centralization_risk": "SWC-105",
    }

    SEVERITY_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Info",
    }

    def __init__(self):
        self.engine = AdvancedDetectorEngine()

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Analyze a contract for advanced vulnerabilities."""
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
        self, findings: List[AdvancedFinding], file_path: Path
    ) -> List[Dict[str, Any]]:
        """Convert advanced findings to MIESC standard format."""
        miesc_findings = []

        for finding in findings:
            swc_id = self.CATEGORY_TO_SWC.get(finding.category.value, "SWC-000")

            miesc_finding = {
                "id": f"ADV-{finding.category.value.upper()}-{len(miesc_findings)+1}",
                "title": finding.title,
                "description": finding.description,
                "severity": self.SEVERITY_MAP.get(finding.severity.value, "Medium"),
                "confidence": finding.confidence,
                "category": finding.category.value,
                "swc_id": swc_id,
                "location": {
                    "file": str(file_path),
                    "line": finding.line,
                    "snippet": finding.code_snippet,
                },
                "recommendation": finding.recommendation,
                "references": finding.references,
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
                swc_id = self.CATEGORY_TO_SWC.get(finding.category.value, "SWC-000")

                miesc_finding = {
                    "id": f"ADV-{finding.category.value.upper()}-{len(miesc_findings)+1}",
                    "title": finding.title,
                    "description": finding.description,
                    "severity": self.SEVERITY_MAP.get(finding.severity.value, "Medium"),
                    "confidence": finding.confidence,
                    "category": finding.category.value,
                    "swc_id": swc_id,
                    "location": {"line": finding.line, "snippet": finding.code_snippet},
                    "recommendation": finding.recommendation,
                    "references": finding.references,
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
            "name": "Advanced Vulnerability Detection",
            "description": "Specialized detection for modern attack patterns",
            "detectors": [
                "Rug Pull Detector",
                "Governance Attack Detector",
                "Token Security Detector (Honeypot)",
                "Proxy/Upgrade Detector",
                "Centralization Risk Detector",
            ],
            "categories": [
                "rug_pull",
                "governance_attack",
                "honeypot",
                "token_security",
                "proxy_upgrade",
                "centralization_risk",
            ],
        }


def main():
    """Test the adapter."""
    adapter = AdvancedDetectorAdapter()

    print("\n" + "=" * 60)
    print("  MIESC Advanced Detector Adapter")
    print("=" * 60)

    info = adapter.get_detector_info()
    print(f"\nLayer: {info['layer']}")
    print(f"Detectors: {len(info['detectors'])}")
    for d in info["detectors"]:
        print(f"  - {d}")

    # Test with sample code
    sample = """
    pragma solidity ^0.8.0;
    contract Test {
        address public owner;
        mapping(address => bool) public blacklist;

        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }

        function setBlacklist(address a, bool v) external onlyOwner {
            blacklist[a] = v;
        }

        function withdrawAll() external onlyOwner {
            payable(owner).transfer(address(this).balance);
        }
    }
    """

    print("\n" + "-" * 60)
    print("  Testing with sample contract")
    print("-" * 60)

    result = adapter.analyze_source(sample)

    if result["success"]:
        print(f"\nFindings: {len(result['findings'])}")
        for f in result["findings"]:
            print(f"  [{f['severity']}] {f['title']}")
        print(f"\nSummary: {result['summary']}")
    else:
        print(f"Error: {result['error']}")


if __name__ == "__main__":
    main()
