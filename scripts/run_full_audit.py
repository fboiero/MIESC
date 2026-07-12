#!/usr/bin/env python3
"""
MIESC Full Audit Script
Ejecuta auditoría completa en múltiples contratos con todas las herramientas disponibles
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from miesc.miesc_core import MIESCCore
from miesc.miesc_policy_mapper import PolicyMapper
from miesc.miesc_risk_engine import RiskEngine

# Configuration
CONTRACTS_DIR = Path(__file__).parent / "contracts" / "audit"
OUTPUT_DIR = Path(__file__).parent / "audit_results"
TOOLS = ["slither", "mythril"]  # Core tools that are installed


def print_banner():
    """Print MIESC banner"""
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                    MIESC v5.4.3 - Full Security Audit                      ║
║          Multi-layer Intelligent Evaluation for Smart Contracts            ║
╠════════════════════════════════════════════════════════════════════════════╣
║  Author: Fernando Boiero | Institution: UNDEF - IUA Córdoba                ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)


def audit_contract(contract_path: Path, tools: List[str]) -> Dict[str, Any]:
    """
    Audit a single contract with all available tools
    """
    print(f"\n{'='*70}")
    print(f"🔍 Auditing: {contract_path.name}")
    print(f"{'='*70}")

    results = {
        "contract": contract_path.name,
        "path": str(contract_path),
        "timestamp": datetime.now().isoformat(),
        "findings": [],
        "tool_results": {},
        "summary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
    }

    # Run MIESC core analysis
    try:
        core = MIESCCore()
        scan_results = core.scan(str(contract_path), tools=tools)

        results["findings"] = scan_results.get("findings", [])
        results["summary"] = scan_results.get("summary", results["summary"])
        results["tool_results"]["miesc_core"] = scan_results

        print(f"   ✓ MIESC Core: Found {len(results['findings'])} findings")

    except Exception as e:
        print(f"   ✗ MIESC Core error: {str(e)}")
        results["tool_results"]["miesc_core"] = {"error": str(e)}

    # Run Slither directly for detailed output
    try:
        print("   → Running Slither...")
        slither_result = subprocess.run(
            ["slither", str(contract_path), "--json", "-"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if slither_result.stdout:
            slither_json = json.loads(slither_result.stdout)
            detectors = slither_json.get("results", {}).get("detectors", [])
            results["tool_results"]["slither_detailed"] = {
                "detectors_count": len(detectors),
                "detectors": detectors[:20],  # First 20 for brevity
            }
            print(f"   ✓ Slither: {len(detectors)} detectors triggered")
        else:
            results["tool_results"]["slither_detailed"] = {"detectors_count": 0}
            print("   ✓ Slither: No issues detected")

    except subprocess.TimeoutExpired:
        print("   ✗ Slither: Timeout")
        results["tool_results"]["slither_detailed"] = {"error": "timeout"}
    except Exception as e:
        print(f"   ✗ Slither error: {str(e)}")
        results["tool_results"]["slither_detailed"] = {"error": str(e)}

    # Run Mythril for symbolic execution
    try:
        print("   → Running Mythril...")
        myth_result = subprocess.run(
            ["myth", "analyze", str(contract_path), "-o", "json", "--execution-timeout", "60"],
            capture_output=True,
            text=True,
            timeout=180,
        )

        if myth_result.stdout:
            myth_json = json.loads(myth_result.stdout)
            issues = myth_json.get("issues", [])
            results["tool_results"]["mythril_detailed"] = {
                "issues_count": len(issues),
                "issues": issues,
            }
            print(f"   ✓ Mythril: {len(issues)} issues found")
        else:
            results["tool_results"]["mythril_detailed"] = {"issues_count": 0}
            print("   ✓ Mythril: No issues detected")

    except subprocess.TimeoutExpired:
        print("   ⚠ Mythril: Timeout (symbolic execution can be slow)")
        results["tool_results"]["mythril_detailed"] = {"error": "timeout"}
    except Exception as e:
        print(f"   ✗ Mythril error: {str(e)}")
        results["tool_results"]["mythril_detailed"] = {"error": str(e)}

    # Policy mapping
    try:
        mapper = PolicyMapper()
        compliance = mapper.map_to_policies(results["findings"])
        results["compliance"] = compliance
        print(f"   ✓ Compliance score: {compliance.get('score', 'N/A')}/100")
    except Exception as e:
        print(f"   ✗ Policy mapping error: {str(e)}")

    # Risk assessment
    try:
        risk_engine = RiskEngine()
        risk = risk_engine.assess(results["findings"])
        results["risk"] = risk
        print(f"   ✓ Risk score: {risk.get('total_score', 'N/A')}/100")
    except Exception as e:
        print(f"   ✗ Risk assessment error: {str(e)}")

    # Print summary
    print(f"\n   📊 Summary for {contract_path.name}:")
    print(f"      Critical: {results['summary'].get('Critical', 0)}")
    print(f"      High:     {results['summary'].get('High', 0)}")
    print(f"      Medium:   {results['summary'].get('Medium', 0)}")
    print(f"      Low:      {results['summary'].get('Low', 0)}")
    print(f"      Info:     {results['summary'].get('Info', 0)}")

    return results


def generate_consolidated_report(all_results: List[Dict]) -> Dict:
    """Generate consolidated audit report"""

    total_findings = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    for result in all_results:
        for severity, count in result.get("summary", {}).items():
            if severity in total_findings:
                total_findings[severity] += count

    report = {
        "audit_info": {
            "tool": "MIESC v5.4.3",
            "timestamp": datetime.now().isoformat(),
            "contracts_audited": len(all_results),
            "tools_used": TOOLS,
        },
        "summary": {
            "total_findings": sum(total_findings.values()),
            "by_severity": total_findings,
            "risk_level": (
                "CRITICAL"
                if total_findings["Critical"] > 0
                else (
                    "HIGH"
                    if total_findings["High"] > 0
                    else (
                        "MEDIUM"
                        if total_findings["Medium"] > 0
                        else "LOW" if total_findings["Low"] > 0 else "CLEAN"
                    )
                )
            ),
        },
        "contracts": all_results,
    }

    return report


def main():
    print_banner()

    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Find all contracts
    contracts = list(CONTRACTS_DIR.glob("*.sol"))

    if not contracts:
        print(f"❌ No contracts found in {CONTRACTS_DIR}")
        return

    print(f"\n📁 Found {len(contracts)} contracts to audit:")
    for c in contracts:
        print(f"   • {c.name}")

    print(f"\n🛠️  Tools: {', '.join(TOOLS)}")
    print(f"📂 Output: {OUTPUT_DIR}")

    # Audit each contract
    all_results = []

    for contract in contracts:
        result = audit_contract(contract, TOOLS)
        all_results.append(result)

        # Save individual result
        output_file = OUTPUT_DIR / f"{contract.stem}_audit.json"
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"   💾 Saved: {output_file.name}")

    # Generate consolidated report
    print(f"\n{'='*70}")
    print("📋 GENERATING CONSOLIDATED REPORT")
    print(f"{'='*70}")

    consolidated = generate_consolidated_report(all_results)

    consolidated_file = OUTPUT_DIR / "consolidated_audit_report.json"
    with open(consolidated_file, "w") as f:
        json.dump(consolidated, f, indent=2, default=str)

    # Print final summary
    print(f"""
╔════════════════════════════════════════════════════════════════════════════╗
║                           AUDIT COMPLETE                                    ║
╠════════════════════════════════════════════════════════════════════════════╣
║  Contracts Audited: {consolidated['audit_info']['contracts_audited']:>3}                                                   ║
║  Total Findings:    {consolidated['summary']['total_findings']:>3}                                                   ║
║                                                                            ║
║  Critical:  {consolidated['summary']['by_severity']['Critical']:>3}                                                          ║
║  High:      {consolidated['summary']['by_severity']['High']:>3}                                                          ║
║  Medium:    {consolidated['summary']['by_severity']['Medium']:>3}                                                          ║
║  Low:       {consolidated['summary']['by_severity']['Low']:>3}                                                          ║
║  Info:      {consolidated['summary']['by_severity']['Info']:>3}                                                          ║
║                                                                            ║
║  Overall Risk Level: {consolidated['summary']['risk_level']:<10}                                        ║
╠════════════════════════════════════════════════════════════════════════════╣
║  📂 Results saved to: {str(OUTPUT_DIR):<51} ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)

    return consolidated


if __name__ == "__main__":
    main()
