#!/usr/bin/env python3
"""
MIESC Advanced Regression Test Suite v2.0

Enhanced testing framework with:
- Multi-contract testing
- Vulnerability-specific detection validation
- Tool comparison matrix
- Performance benchmarking
- False positive analysis
- HTML report generation

Usage:
    python scripts/run_advanced_tests.py --mode full
    python scripts/run_advanced_tests.py --contract reentrancy_simple.sol
    python scripts/run_advanced_tests.py --vulnerability reentrancy
    python scripts/run_advanced_tests.py --compare slither,mythril,aderyn
    python scripts/run_advanced_tests.py --profile --all-contracts
"""

import sys
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

class AdvancedTestSuite:
    """Enhanced test suite with multi-contract and tool comparison support"""

    def __init__(self, mode: str = "critical"):
        self.mode = mode
        self.project_root = Path(__file__).parent.parent
        self.contract_db = self.load_contract_database()
        self.results = {
            "test_run": {
                "timestamp": datetime.now().isoformat(),
                "mode": mode,
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "duration": 0
            },
            "contracts": {},
            "tools": {},
            "vulnerabilities": {}
        }

    def load_contract_database(self) -> Dict:
        """Load contract database JSON"""
        db_path = self.project_root / "tests" / "contract_database.json"
        if db_path.exists():
            with open(db_path, 'r') as f:
                return json.load(f)
        else:
            print(f"⚠️  Warning: Contract database not found at {db_path}")
            return {"contracts": []}

    def get_contracts_by_priority(self, priority: str) -> List[Dict]:
        """Get contracts filtered by priority"""
        return [
            c for c in self.contract_db.get("contracts", [])
            if c.get("testing_priority", "").upper() == priority.upper()
        ]

    def get_contracts_by_vulnerability(self, vuln_type: str) -> List[Dict]:
        """Get contracts with specific vulnerability type"""
        result = []
        for contract in self.contract_db.get("contracts", []):
            for vuln in contract.get("vulnerabilities", []):
                if vuln_type.lower() in vuln.get("type", "").lower():
                    result.append(contract)
                    break
        return result

    def test_contract_with_tool(self, contract: Dict, tool_name: str) -> Dict:
        """Test a specific contract with a specific tool"""
        print(f"  🔍 Testing {contract['filename']} with {tool_name}...")

        start_time = time.time()
        result = {
            "contract": contract["filename"],
            "tool": tool_name,
            "status": "pending",
            "duration": 0,
            "findings": [],
            "expected": None,
            "actual": None
        }

        try:
            # Get expected detections
            expected = contract.get("expected_tool_detections", {}).get(tool_name, {})
            result["expected"] = expected.get("should_detect", False)

            # TODO: Actually run the tool here
            # For now, simulate with expected results
            if tool_name == "slither":
                result = self.run_slither(contract)
            elif tool_name == "mythril":
                result = self.run_mythril(contract)
            elif tool_name == "aderyn":
                result = self.run_aderyn(contract)
            else:
                result["status"] = "not_implemented"
                result["actual"] = False

            result["duration"] = time.time() - start_time

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            result["duration"] = time.time() - start_time

        return result

    def run_slither(self, contract: Dict) -> Dict:
        """Run Slither on contract"""
        # Placeholder - implement actual Slither execution
        return {
            "status": "simulated",
            "actual": True,
            "findings": ["reentrancy-eth"],
            "note": "Slither execution not yet implemented"
        }

    def run_mythril(self, contract: Dict) -> Dict:
        """Run Mythril on contract"""
        # Placeholder - implement actual Mythril execution
        return {
            "status": "simulated",
            "actual": True,
            "findings": ["Reentrancy"],
            "note": "Mythril execution not yet implemented"
        }

    def run_aderyn(self, contract: Dict) -> Dict:
        """Run Aderyn on contract"""
        # Placeholder - implement actual Aderyn execution
        return {
            "status": "simulated",
            "actual": False,
            "findings": [],
            "note": "Aderyn execution not yet implemented"
        }

    def compare_tools(self, contracts: List[Dict], tools: List[str]) -> Dict:
        """Compare multiple tools across multiple contracts"""
        print(f"\n🔬 Comparing tools: {', '.join(tools)}")
        print(f"📊 Contracts: {len(contracts)}")
        print("="*80)

        comparison = {
            "tools": tools,
            "contracts": [c["filename"] for c in contracts],
            "matrix": {},
            "summary": {}
        }

        for tool in tools:
            comparison["matrix"][tool] = {}
            true_positives = 0
            false_positives = 0
            true_negatives = 0
            false_negatives = 0

            for contract in contracts:
                result = self.test_contract_with_tool(contract, tool)
                comparison["matrix"][tool][contract["filename"]] = result

                # Calculate metrics
                expected = result.get("expected", False)
                actual = result.get("actual", False)

                if expected and actual:
                    true_positives += 1
                elif not expected and actual:
                    false_positives += 1
                elif not expected and not actual:
                    true_negatives += 1
                elif expected and not actual:
                    false_negatives += 1

            # Calculate summary metrics
            total = len(contracts)
            precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
            recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

            comparison["summary"][tool] = {
                "true_positives": true_positives,
                "false_positives": false_positives,
                "true_negatives": true_negatives,
                "false_negatives": false_negatives,
                "precision": round(precision * 100, 2),
                "recall": round(recall * 100, 2),
                "f1_score": round(f1 * 100, 2)
            }

        return comparison

    def generate_html_report(self, comparison: Dict, output_path: str):
        """Generate HTML comparison report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MIESC Tool Comparison Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; font-weight: bold; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .metric {{ display: inline-block; margin: 10px 20px 10px 0; padding: 15px; background: #ecf0f1; border-radius: 5px; }}
        .metric-label {{ font-size: 12px; color: #7f8c8d; text-transform: uppercase; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
        .pass {{ color: #27ae60; font-weight: bold; }}
        .fail {{ color: #e74c3c; font-weight: bold; }}
        .timestamp {{ color: #7f8c8d; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔬 MIESC Tool Comparison Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <h2>📊 Summary</h2>
        <div>
            <div class="metric">
                <div class="metric-label">Tools Compared</div>
                <div class="metric-value">{len(comparison['tools'])}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Contracts Tested</div>
                <div class="metric-value">{len(comparison['contracts'])}</div>
            </div>
        </div>

        <h2>🎯 Tool Performance</h2>
        <table>
            <thead>
                <tr>
                    <th>Tool</th>
                    <th>Precision (%)</th>
                    <th>Recall (%)</th>
                    <th>F1-Score (%)</th>
                    <th>True Positives</th>
                    <th>False Positives</th>
                    <th>False Negatives</th>
                </tr>
            </thead>
            <tbody>
"""

        for tool, metrics in comparison["summary"].items():
            html += f"""
                <tr>
                    <td><strong>{tool}</strong></td>
                    <td>{metrics['precision']}</td>
                    <td>{metrics['recall']}</td>
                    <td>{metrics['f1_score']}</td>
                    <td class="pass">{metrics['true_positives']}</td>
                    <td class="fail">{metrics['false_positives']}</td>
                    <td class="fail">{metrics['false_negatives']}</td>
                </tr>
"""

        html += """
            </tbody>
        </table>

        <h2>📋 Detailed Results Matrix</h2>
        <table>
            <thead>
                <tr>
                    <th>Contract</th>
"""

        for tool in comparison["tools"]:
            html += f"<th>{tool}</th>"

        html += """
                </tr>
            </thead>
            <tbody>
"""

        for contract in comparison["contracts"]:
            html += f"<tr><td><strong>{contract}</strong></td>"
            for tool in comparison["tools"]:
                result = comparison["matrix"][tool].get(contract, {})
                status = "✅" if result.get("actual") else "❌"
                html += f"<td>{status}</td>"
            html += "</tr>"

        html += """
            </tbody>
        </table>

        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 12px;">
            <p>Generated by MIESC Advanced Test Suite v2.0 | Fernando Boiero - UNDEF IUA 2025</p>
        </footer>
    </div>
</body>
</html>
"""

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(html)

        print(f"\n✅ HTML report generated: {output_path}")

    def run_batch_tests(self, args):
        """Run batch tests across all high-priority contracts"""
        print("\n" + "="*80)
        print("🚀 MIESC Advanced Test Suite - Batch Mode")
        print("="*80)

        # Get high-priority contracts
        contracts = self.get_contracts_by_priority("HIGH")
        print(f"\n📊 Testing {len(contracts)} high-priority contracts")

        # Define tools to test
        tools = ["slither", "mythril", "aderyn"]

        # Run comparison
        comparison = self.compare_tools(contracts, tools)

        # Generate report
        if args.output:
            self.generate_html_report(comparison, args.output)

        # Print summary
        print("\n" + "="*80)
        print("📈 SUMMARY")
        print("="*80)
        for tool, metrics in comparison["summary"].items():
            print(f"\n{tool.upper()}:")
            print(f"  Precision: {metrics['precision']}%")
            print(f"  Recall: {metrics['recall']}%")
            print(f"  F1-Score: {metrics['f1_score']}%")


def main():
    parser = argparse.ArgumentParser(description="MIESC Advanced Test Suite v2.0")
    parser.add_argument("--mode", choices=["fast", "critical", "full"], default="critical",
                       help="Test mode")
    parser.add_argument("--contract", type=str, help="Test specific contract")
    parser.add_argument("--vulnerability", type=str, help="Test specific vulnerability type")
    parser.add_argument("--compare", type=str, help="Compare tools (comma-separated)")
    parser.add_argument("--batch", action="store_true", help="Run batch tests")
    parser.add_argument("--profile", action="store_true", help="Enable performance profiling")
    parser.add_argument("--all-contracts", action="store_true", help="Test all contracts")
    parser.add_argument("--output", type=str, default="outputs/comparison_report.html",
                       help="Output report path")

    args = parser.parse_args()

    suite = AdvancedTestSuite(mode=args.mode)

    if args.batch:
        suite.run_batch_tests(args)
    elif args.contract:
        print(f"Testing specific contract: {args.contract}")
        # TODO: Implement single contract testing
    elif args.vulnerability:
        print(f"Testing vulnerability type: {args.vulnerability}")
        contracts = suite.get_contracts_by_vulnerability(args.vulnerability)
        print(f"Found {len(contracts)} contracts with {args.vulnerability}")
    else:
        print("Please specify a test mode: --batch, --contract, or --vulnerability")
        parser.print_help()


if __name__ == "__main__":
    main()
