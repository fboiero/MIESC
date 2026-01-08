#!/usr/bin/env python3
"""
MIESC v4.1 - DeFi Security Adapter

Layer 8: DeFi-Specific Security Analysis
Integrates custom DeFi vulnerability detectors into the MIESC pipeline.

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

from detectors.defi_detectors import DeFiDetectorEngine, DeFiFinding
from src.core.tool_protocol import (
    ToolMetadata,
    ToolStatus,
    ToolCategory,
    ToolCapability,
)


class DeFiAdapter:
    """
    Adapter for DeFi vulnerability detection.

    Integrates custom DeFi detectors into the MIESC pipeline,
    converting findings to the standard MIESC format.
    """

    name = "defi-analyzer"
    layer = 8  # Layer 8: DeFi Security (post-thesis extension)
    description = "DeFi-specific vulnerability detection"

    def is_available(self) -> ToolStatus:
        """Check if DeFi detector engine is available."""
        try:
            from detectors.defi_detectors import DeFiDetectorEngine

            return ToolStatus.AVAILABLE
        except ImportError:
            return ToolStatus.NOT_INSTALLED

    def get_metadata(self) -> ToolMetadata:
        """Return tool metadata."""
        return ToolMetadata(
            name=self.name,
            version="1.0.0",
            category=ToolCategory.MEV_DETECTION,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://fboiero.github.io/MIESC",
            installation_cmd="pip install -e .",
            capabilities=[
                ToolCapability(
                    name="defi_vulnerability_detection",
                    description="DeFi-specific vulnerability detection",
                    supported_languages=["solidity"],
                    detection_types=["flash_loan", "oracle_manipulation", "mev_exposure"],
                )
            ],
            is_optional=True,
        )

    # SWC mappings for DeFi vulnerabilities
    CATEGORY_TO_SWC = {
        "flash_loan": "SWC-137",  # Custom: Flash Loan Vulnerability
        "oracle_manipulation": "SWC-120",  # Weak Sources of Randomness
        "price_manipulation": "SWC-120",
        "sandwich_attack": "SWC-114",  # Transaction Order Dependence
        "mev_exposure": "SWC-114",
        "slippage": "SWC-114",
        "liquidity": "SWC-113",  # DoS
    }

    # Severity mapping
    SEVERITY_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Info",
    }

    def __init__(self):
        self.engine = DeFiDetectorEngine()

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze a contract for DeFi vulnerabilities.

        Args:
            contract_path: Path to the Solidity file

        Returns:
            Dictionary with findings in MIESC standard format
        """
        path = Path(contract_path)

        if not path.exists():
            return {"success": False, "error": f"File not found: {contract_path}", "findings": []}

        try:
            # Run analysis
            findings = self.engine.analyze_file(path)

            # Convert to MIESC format
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
        self, findings: List[DeFiFinding], file_path: Path
    ) -> List[Dict[str, Any]]:
        """Convert DeFi findings to MIESC standard format."""
        miesc_findings = []

        for finding in findings:
            swc_id = self.CATEGORY_TO_SWC.get(finding.category.value, "SWC-000")

            miesc_finding = {
                "id": f"DEFI-{finding.category.value.upper()}-{len(miesc_findings)+1}",
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
        """Analyze source code directly (without file)."""
        try:
            findings = self.engine.analyze(source_code)
            miesc_findings = []

            for finding in findings:
                swc_id = self.CATEGORY_TO_SWC.get(finding.category.value, "SWC-000")

                miesc_finding = {
                    "id": f"DEFI-{finding.category.value.upper()}-{len(miesc_findings)+1}",
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
    def get_layer_info() -> Dict[str, Any]:
        """Return layer information for MIESC architecture."""
        return {
            "layer": 8,
            "name": "DeFi Security Analysis",
            "description": "Specialized detection for DeFi vulnerabilities",
            "tools": ["MIESC DeFi Detectors"],
            "categories": [
                "flash_loan",
                "oracle_manipulation",
                "price_manipulation",
                "sandwich_attack",
                "mev_exposure",
                "slippage",
                "liquidity",
            ],
            "supported_vulnerabilities": [
                "Flash Loan Attacks",
                "Oracle Manipulation",
                "Price Manipulation",
                "Sandwich Attacks",
                "MEV Exposure",
                "Slippage Issues",
                "Liquidity Vulnerabilities",
            ],
        }


def main():
    """Test the DeFi adapter."""

    adapter = DeFiAdapter()

    # Print layer info
    print("\n" + "=" * 60)
    print("  MIESC Layer 8: DeFi Security Analysis")
    print("=" * 60)

    info = adapter.get_layer_info()
    print(f"\nLayer: {info['layer']}")
    print(f"Name: {info['name']}")
    print(f"Description: {info['description']}")
    print(f"Categories: {', '.join(info['categories'])}")

    # Test with sample contract
    sample_code = """
    pragma solidity ^0.8.0;

    contract FlashLoanArbitrage {
        function executeOperation(
            address[] calldata assets,
            uint256[] calldata amounts,
            uint256[] calldata premiums,
            address initiator,
            bytes calldata params
        ) external returns (bool) {
            // Get spot price
            (uint112 r0, uint112 r1,) = pair.getReserves();

            // Swap with no protection
            router.swapExactTokensForTokens(amount, 0, path, address(this), block.timestamp);

            return true;
        }
    }
    """

    print("\n" + "-" * 60)
    print("  Analyzing Sample DeFi Contract")
    print("-" * 60)

    result = adapter.analyze_source(sample_code)

    if result["success"]:
        print(f"\nFindings: {len(result['findings'])}")
        for finding in result["findings"]:
            print(f"\n  [{finding['severity']}] {finding['title']}")
            print(f"    Category: {finding['category']}")
            print(f"    SWC: {finding['swc_id']}")
            if finding["location"].get("line"):
                print(f"    Line: {finding['location']['line']}")

        print(f"\nSummary: {result['summary']}")
    else:
        print(f"Error: {result['error']}")


if __name__ == "__main__":
    main()
