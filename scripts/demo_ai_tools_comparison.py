#!/usr/bin/env python3
"""
Demo: AI Tools Comparison for Thesis Defense

Compares MIESC with integrated AI tools:
- StaticAgent (MIESC baseline)
- GPTScan (ICSE 2024)
- AI Triage (MIESC Layer 6)

Usage:
    python demo_ai_tools_comparison.py examples/vulnerable_bank.sol
"""

import sys
import os
import time
from pathlib import Path
from typing import Dict, List, Any
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agents.static_agent import StaticAgent
from src.agents.gptscan_agent import GPTScanAgent
from src.agents.ai_agent import AIAgent
from src.mcp.context_bus import get_context_bus

class AIToolsComparison:
    """Compare different AI-assisted security analysis tools"""

    def __init__(self, contract_path: str):
        self.contract_path = contract_path
        self.contract_name = Path(contract_path).name
        self.results = {}

        print("\n" + "=" * 80)
        print("🛡️  MIESC - AI Tools Comparison Demo")
        print("=" * 80)
        print(f"\nContract: {self.contract_name}")
        print(f"Path: {contract_path}\n")

    def run_static_baseline(self) -> Dict[str, Any]:
        """Run MIESC StaticAgent (baseline)"""
        print("\n" + "-" * 80)
        print("1️⃣  MIESC StaticAgent (Baseline)")
        print("-" * 80)

        try:
            agent = StaticAgent()
            start_time = time.time()
            results = agent.run(self.contract_path, solc_version="0.8.0")
            execution_time = time.time() - start_time

            findings = results.get("static_findings", [])

            print(f"✅ Analysis complete in {execution_time:.2f}s")
            print(f"📊 Found {len(findings)} issues")

            # Count by severity
            severity_count = self._count_by_severity(findings)
            for severity, count in severity_count.items():
                print(f"   - {severity}: {count}")

            return {
                "tool": "MIESC StaticAgent",
                "findings": findings,
                "count": len(findings),
                "severity_count": severity_count,
                "execution_time": execution_time,
                "success": True
            }

        except Exception as e:
            print(f"❌ Error: {e}")
            return {
                "tool": "MIESC StaticAgent",
                "error": str(e),
                "success": False
            }

    def run_gptscan(self) -> Dict[str, Any]:
        """Run GPTScan integration"""
        print("\n" + "-" * 80)
        print("2️⃣  GPTScan (ICSE 2024)")
        print("-" * 80)

        try:
            agent = GPTScanAgent()
            start_time = time.time()
            results = agent.run(self.contract_path, solc_version="0.8.0")
            execution_time = time.time() - start_time

            findings = results.get("gptscan_findings", [])
            analysis = results.get("gptscan_analysis", {})

            print(f"✅ Analysis complete in {execution_time:.2f}s")
            print(f"📊 Found {len(findings)} issues")
            print(f"   - GPT Analyzed: {analysis.get('gpt_analyzed', 0)} patterns")

            # Count by severity
            severity_count = self._count_by_severity(findings)
            for severity, count in severity_count.items():
                print(f"   - {severity}: {count}")

            return {
                "tool": "GPTScan",
                "findings": findings,
                "count": len(findings),
                "severity_count": severity_count,
                "execution_time": execution_time,
                "gpt_analyzed": analysis.get("gpt_analyzed", 0),
                "success": True
            }

        except Exception as e:
            print(f"❌ Error: {e}")
            return {
                "tool": "GPTScan",
                "error": str(e),
                "success": False
            }

    def run_ai_triage(self) -> Dict[str, Any]:
        """Run MIESC AIAgent (Layer 6 triage)"""
        print("\n" + "-" * 80)
        print("3️⃣  MIESC AIAgent (Layer 6 Triage)")
        print("-" * 80)

        try:
            # First get static findings
            static_agent = StaticAgent()
            static_results = static_agent.run(self.contract_path, solc_version="0.8.0")
            static_findings = static_results.get("static_findings", [])

            if not static_findings:
                print("ℹ️  No static findings to triage")
                return {
                    "tool": "MIESC AIAgent",
                    "findings": [],
                    "count": 0,
                    "success": True,
                    "message": "No findings to triage"
                }

            # Run AI triage
            ai_agent = AIAgent()
            start_time = time.time()
            results = ai_agent.run(self.contract_path, findings=static_findings)
            execution_time = time.time() - start_time

            triaged = results.get("ai_triage", [])
            false_positives = results.get("false_positives", [])

            real_vulnerabilities = [f for f in triaged if not f.get("is_false_positive", False)]

            print(f"✅ Triage complete in {execution_time:.2f}s")
            print(f"📊 Input: {len(static_findings)} findings")
            print(f"   - Real vulnerabilities: {len(real_vulnerabilities)}")
            print(f"   - False positives: {len(false_positives)}")
            print(f"   - FP Rate: {len(false_positives)/len(static_findings)*100:.1f}%")

            # Count real vulnerabilities by severity
            severity_count = self._count_by_severity(real_vulnerabilities)
            for severity, count in severity_count.items():
                print(f"   - {severity}: {count}")

            return {
                "tool": "MIESC AIAgent",
                "findings": real_vulnerabilities,
                "count": len(real_vulnerabilities),
                "severity_count": severity_count,
                "false_positives": len(false_positives),
                "fp_rate": len(false_positives)/len(static_findings) if static_findings else 0,
                "execution_time": execution_time,
                "success": True
            }

        except Exception as e:
            print(f"❌ Error: {e}")
            return {
                "tool": "MIESC AIAgent",
                "error": str(e),
                "success": False
            }

    def _count_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        severity_count = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}

        for finding in findings:
            severity = finding.get("severity", "Low")
            if severity in severity_count:
                severity_count[severity] += 1

        return severity_count

    def generate_comparison_report(self):
        """Generate comparison report"""
        print("\n" + "=" * 80)
        print("📊 COMPARISON REPORT")
        print("=" * 80)

        if not self.results:
            print("No results to compare")
            return

        # Summary table
        print("\n┌─────────────────────────┬──────────┬──────────┬──────────┬──────────┐")
        print("│ Tool                    │ Findings │ High     │ Medium   │ Time (s) │")
        print("├─────────────────────────┼──────────┼──────────┼──────────┼──────────┤")

        for tool_name, result in self.results.items():
            if result.get("success"):
                count = result.get("count", 0)
                severity = result.get("severity_count", {})
                exec_time = result.get("execution_time", 0)

                print(f"│ {tool_name:23s} │ {count:8d} │ {severity.get('High', 0):8d} │ {severity.get('Medium', 0):8d} │ {exec_time:8.2f} │")

        print("└─────────────────────────┴──────────┴──────────┴──────────┴──────────┘")

        # Additional metrics
        print("\n📈 Additional Metrics:")

        for tool_name, result in self.results.items():
            if result.get("success"):
                print(f"\n{tool_name}:")

                if "fp_rate" in result:
                    print(f"  False Positive Rate: {result['fp_rate']*100:.1f}%")

                if "gpt_analyzed" in result:
                    print(f"  GPT Patterns Analyzed: {result['gpt_analyzed']}")

        # Key insights
        print("\n💡 Key Insights:")

        # Compare counts
        if "static" in self.results and "ai_triage" in self.results:
            static_count = self.results["static"].get("count", 0)
            triaged_count = self.results["ai_triage"].get("count", 0)
            fp_rate = self.results["ai_triage"].get("fp_rate", 0)

            if static_count > 0:
                reduction = (static_count - triaged_count) / static_count * 100
                print(f"\n✨ AI Triage reduced findings by {reduction:.1f}%")
                print(f"   ({static_count} → {triaged_count} after removing false positives)")
                print(f"   False Positive Rate: {fp_rate*100:.1f}%")

        # Compare with GPTScan
        if "gptscan" in self.results and "static" in self.results:
            gpt_count = self.results["gptscan"].get("count", 0)
            static_count = self.results["static"].get("count", 0)

            if gpt_count != static_count:
                print(f"\n🔍 GPTScan detected {abs(gpt_count - static_count)} different issues")
                if gpt_count > static_count:
                    print(f"   (GPTScan found {gpt_count - static_count} additional logic bugs)")
                else:
                    print(f"   (GPTScan filtered out {static_count - gpt_count} false positives)")

    def export_results(self, output_path: str = None):
        """Export results to JSON"""
        if not output_path:
            output_path = f"outputs/ai_tools_comparison_{Path(self.contract_path).stem}.json"

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        export_data = {
            "contract": self.contract_name,
            "contract_path": self.contract_path,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "results": self.results
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)

        print(f"\n💾 Results exported to: {output_path}")

    def run_full_comparison(self):
        """Run all tools and generate comparison"""

        # 1. MIESC StaticAgent (baseline)
        static_result = self.run_static_baseline()
        self.results["static"] = static_result

        # 2. GPTScan
        gptscan_result = self.run_gptscan()
        self.results["gptscan"] = gptscan_result

        # 3. MIESC AIAgent (triage)
        ai_result = self.run_ai_triage()
        self.results["ai_triage"] = ai_result

        # Generate comparison
        self.generate_comparison_report()

        # Export results
        self.export_results()

        return self.results


def main():
    if len(sys.argv) < 2:
        print("Usage: python demo_ai_tools_comparison.py <contract.sol>")
        print("\nExample:")
        print("  python demo_ai_tools_comparison.py examples/vulnerable_bank.sol")
        sys.exit(1)

    contract_path = sys.argv[1]

    if not os.path.exists(contract_path):
        print(f"❌ Error: Contract not found: {contract_path}")
        sys.exit(1)

    # Run comparison
    comparison = AIToolsComparison(contract_path)
    results = comparison.run_full_comparison()

    print("\n" + "=" * 80)
    print("✅ Demo Complete")
    print("=" * 80)
    print("\nNext steps:")
    print("  1. Review results in outputs/ai_tools_comparison_*.json")
    print("  2. Compare findings across different tools")
    print("  3. Use for thesis defense presentation")
    print()


if __name__ == "__main__":
    main()
