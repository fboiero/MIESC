#!/usr/bin/env python3
"""
MIESC - Specific Use Case Examples

This file demonstrates real-world use cases for Ollama and CrewAI integration:

1. Development Workflow - Fast feedback during development
2. CI/CD Pipeline - Automated security checks
3. Pre-Audit Analysis - Before external audit
4. DeFi Security - DeFi-specific vulnerability detection
5. Compliance Check - Regulatory compliance validation
6. Cost Optimization - Hybrid local/cloud approach
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pathlib import Path
from src.agents.ollama_agent import OllamaAgent
from src.agents.crewai_coordinator import CrewAICoordinator

# Rich console for better output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import track
    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def print_section(title, description=""):
    """Print section header"""
    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]{title}[/bold cyan]")
        if description:
            console.print(f"[white]{description}[/white]\n")
    else:
        print(f"\n{title}")
        if description:
            print(f"{description}\n")


def use_case_1_development_workflow():
    """
    Use Case 1: Development Workflow

    Scenario: Developer wants fast feedback during development
    Goal: Get security feedback in <30 seconds
    Model: codellama:7b (fastest)
    Cost: $0
    """
    print_section(
        "Use Case 1: Development Workflow",
        "Fast security feedback during development (< 30 seconds)"
    )

    # Use fastest model for development
    agent = OllamaAgent(model="codellama:7b")

    # Analyze example contract
    contract_path = Path(__file__).parent / "reentrancy.sol"
    if not contract_path.exists():
        print("⚠️  Example contract not found")
        return

    results = agent.run(str(contract_path))
    findings = results.get("ollama_findings", [])

    print(f"✓ Analysis complete in {results.get('execution_time', 0):.2f}s")
    print(f"✓ Found {len(findings)} potential issues")

    # Show critical/high severity only
    critical_findings = [f for f in findings if f.get('severity') in ['Critical', 'High']]
    print(f"\n🔴 Critical/High severity: {len(critical_findings)}")

    for finding in critical_findings[:3]:
        print(f"  - [{finding.get('severity')}] {finding.get('category')}")
        print(f"    {finding.get('description')[:80]}...")

    print("\n💡 Recommendation:")
    print("  - Fix critical issues immediately")
    print("  - Run full analysis before commit")


def use_case_2_cicd_pipeline():
    """
    Use Case 2: CI/CD Pipeline

    Scenario: Automated security checks in CI/CD
    Goal: Balance speed and quality
    Model: deepseek-coder:6.7b (balanced)
    Cost: $0
    """
    print_section(
        "Use Case 2: CI/CD Pipeline",
        "Automated security checks with balanced speed/quality"
    )

    # GitHub Actions example
    print("Example .github/workflows/security.yml:\n")
    print("""
name: Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Ollama
        run: |
          curl -fsSL https://ollama.ai/install.sh | sh
          ollama pull deepseek-coder:6.7b

      - name: Install Python dependencies
        run: pip install -r requirements_agents.txt

      - name: Run MIESC Analysis
        run: python main_ai.py contracts/*.sol cicd --use-ollama --ollama-model deepseek-coder:6.7b

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: audit-report
          path: output/cicd/
    """)

    print("\n✓ Benefits:")
    print("  - Zero CI/CD costs (no API fees)")
    print("  - Consistent analysis across all commits")
    print("  - Fast feedback (<60 seconds)")


def use_case_3_pre_audit():
    """
    Use Case 3: Pre-Audit Analysis

    Scenario: Before external audit, comprehensive internal check
    Goal: Find as many issues as possible
    Models: Ollama codellama:13b + CrewAI multi-agent
    Cost: $0
    """
    print_section(
        "Use Case 3: Pre-Audit Analysis",
        "Comprehensive analysis before external audit"
    )

    contract_path = Path(__file__).parent / "reentrancy.sol"
    if not contract_path.exists():
        print("⚠️  Example contract not found")
        return

    # Step 1: Single-agent analysis
    print("[1/2] Running Ollama single-agent analysis...")
    ollama_agent = OllamaAgent(model="codellama:13b")
    ollama_results = ollama_agent.run(str(contract_path))
    ollama_findings = ollama_results.get("ollama_findings", [])

    # Step 2: Multi-agent validation
    print("[2/2] Running CrewAI multi-agent validation...")
    crew = CrewAICoordinator(use_local_llm=True)
    crew_results = crew.run(str(contract_path))
    crew_findings = crew_results.get("crew_findings", [])

    print(f"\n✓ Ollama found: {len(ollama_findings)} issues")
    print(f"✓ CrewAI found: {len(crew_findings)} issues")

    # Merge and deduplicate
    all_findings = ollama_findings + crew_findings
    by_severity = {}
    for finding in all_findings:
        severity = finding.get('severity', 'Unknown')
        by_severity[severity] = by_severity.get(severity, 0) + 1

    print("\n📊 Findings by severity:")
    for severity, count in sorted(by_severity.items(), key=lambda x: x[1], reverse=True):
        print(f"  {severity}: {count}")

    print("\n💡 Next steps:")
    print("  1. Fix all Critical and High severity issues")
    print("  2. Review Medium severity issues")
    print("  3. Document accepted risks for Low severity")
    print("  4. Proceed to external audit")


def use_case_4_defi_security():
    """
    Use Case 4: DeFi-Specific Security

    Scenario: DeFi protocol with specific vulnerabilities
    Goal: Focus on DeFi-specific issues (flash loans, oracle manipulation, MEV)
    Approach: Custom prompts with specialized models
    Cost: $0
    """
    print_section(
        "Use Case 4: DeFi-Specific Security",
        "Focus on DeFi-specific vulnerabilities"
    )

    # Custom DeFi-focused prompt
    defi_prompt = """You are a DeFi security expert. Focus on:

1. Flash loan attacks
2. Oracle manipulation (price manipulation, stale prices)
3. MEV vulnerabilities (frontrunning, sandwich attacks)
4. Reentrancy in DeFi contexts
5. Slippage and deadline issues
6. Access control in governance
7. Reward calculation errors

Analyze the following Solidity contract for DeFi-specific vulnerabilities:
"""

    print("Custom DeFi analysis configuration:\n")
    print(f"Prompt focus: {defi_prompt.strip()}\n")

    # Example: Analyze DeFi contract
    print("Example usage:")
    print("""
from src.agents.ollama_agent import OllamaAgent

agent = OllamaAgent(model="deepseek-coder:33b")  # Best quality
agent.SYSTEM_PROMPT = defi_prompt

results = agent.run("contracts/DeFiProtocol.sol")
    """)

    print("\n✓ DeFi-specific findings to watch for:")
    print("  - Unchecked return values from external calls")
    print("  - Missing deadline parameters in swaps")
    print("  - Oracle price not validated")
    print("  - Flash loan callback vulnerabilities")
    print("  - Reward calculation precision loss")


def use_case_5_compliance_check():
    """
    Use Case 5: Compliance Validation

    Scenario: Validate compliance with security standards
    Goal: Map findings to SWC, OWASP, CWE standards
    Tool: CrewAI Compliance Officer agent
    Cost: $0
    """
    print_section(
        "Use Case 5: Compliance Validation",
        "Map findings to security standards (SWC, OWASP, CWE)"
    )

    contract_path = Path(__file__).parent / "reentrancy.sol"
    if not contract_path.exists():
        print("⚠️  Example contract not found")
        return

    print("Running CrewAI with Compliance Officer agent...\n")

    coordinator = CrewAICoordinator(use_local_llm=True)
    results = coordinator.run(str(contract_path))
    findings = results.get("crew_findings", [])

    # Group by standard
    by_swc = {}
    by_owasp = {}

    for finding in findings:
        # SWC mapping
        swc = finding.get('swc_id', 'Unknown')
        if swc not in by_swc:
            by_swc[swc] = []
        by_swc[swc].append(finding)

        # OWASP mapping
        owasp_list = finding.get('owasp_category', [])
        for owasp in owasp_list:
            if owasp not in by_owasp:
                by_owasp[owasp] = []
            by_owasp[owasp].append(finding)

    print("📋 Compliance Report:\n")
    print(f"SWC Categories: {len(by_swc)}")
    for swc, swc_findings in list(by_swc.items())[:5]:
        print(f"  {swc}: {len(swc_findings)} findings")

    print(f"\nOWASP Categories: {len(by_owasp)}")
    for owasp, owasp_findings in list(by_owasp.items())[:5]:
        print(f"  {owasp}: {len(owasp_findings)} findings")

    print("\n💡 Use for:")
    print("  - Regulatory compliance documentation")
    print("  - Internal security standards alignment")
    print("  - Third-party audit preparation")


def use_case_6_cost_optimization():
    """
    Use Case 6: Hybrid Cost Optimization

    Scenario: Optimize costs by using Ollama for bulk + GPT-4 for critical
    Goal: 95% cost reduction while maintaining quality
    Approach: Tiered analysis based on contract value
    Savings: ~$85/year (based on 100 contracts/year)
    """
    print_section(
        "Use Case 6: Cost Optimization",
        "Hybrid local/cloud approach for cost savings"
    )

    print("Strategy: Tiered analysis based on contract value\n")

    # Cost tiers
    tiers = [
        {
            "name": "Development",
            "value": "Any",
            "model": "Ollama codellama:7b",
            "cost": "$0.00",
            "speed": "Fast (30s)"
        },
        {
            "name": "Low-value (<$10k)",
            "value": "<$10,000",
            "model": "Ollama codellama:13b",
            "cost": "$0.00",
            "speed": "Medium (60s)"
        },
        {
            "name": "Medium-value ($10k-$100k)",
            "value": "$10k-$100k",
            "model": "Ollama deepseek-coder:33b",
            "cost": "$0.00",
            "speed": "Slow (120s)"
        },
        {
            "name": "High-value (>$100k)",
            "value": ">$100,000",
            "model": "Ollama + GPT-4",
            "cost": "$0.03",
            "speed": "Medium (45s)"
        }
    ]

    if RICH_AVAILABLE:
        table = Table(title="Cost Optimization Strategy")
        table.add_column("Tier", style="cyan")
        table.add_column("Contract Value", style="yellow")
        table.add_column("Model", style="magenta")
        table.add_column("Cost", style="green")
        table.add_column("Speed", style="white")

        for tier in tiers:
            table.add_row(
                tier["name"],
                tier["value"],
                tier["model"],
                tier["cost"],
                tier["speed"]
            )

        console.print(table)
    else:
        for tier in tiers:
            print(f"\n{tier['name']}:")
            print(f"  Value: {tier['value']}")
            print(f"  Model: {tier['model']}")
            print(f"  Cost: {tier['cost']}")
            print(f"  Speed: {tier['speed']}")

    # Cost comparison
    print("\n💰 Annual Cost Comparison (100 contracts/year):\n")
    print("  All GPT-4:        $3.00")
    print("  Hybrid (95% free): $0.15  (95% savings)")
    print("  All Ollama:       $0.00  (100% savings)")

    print("\n💡 Implementation:")
    print("""
def analyze_contract(contract_path, contract_value):
    if contract_value < 10000:
        agent = OllamaAgent(model="codellama:13b")
    elif contract_value < 100000:
        agent = OllamaAgent(model="deepseek-coder:33b")
    else:
        # High-value: Use both for validation
        ollama = OllamaAgent(model="deepseek-coder:33b")
        gpt4 = GPTAgent(model="gpt-4")
        # Compare results...

    return agent.run(contract_path)
    """)


def main():
    """Run all use case examples"""
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            "[bold cyan]MIESC - Specific Use Case Examples[/bold cyan]\n\n"
            "[white]Demonstrating real-world applications of Ollama & CrewAI[/white]",
            border_style="cyan"
        ))
    else:
        print("=" * 60)
        print("MIESC - Specific Use Case Examples")
        print("=" * 60)

    use_cases = [
        ("Development Workflow", use_case_1_development_workflow),
        ("CI/CD Pipeline", use_case_2_cicd_pipeline),
        ("Pre-Audit Analysis", use_case_3_pre_audit),
        ("DeFi Security", use_case_4_defi_security),
        ("Compliance Check", use_case_5_compliance_check),
        ("Cost Optimization", use_case_6_cost_optimization)
    ]

    print("\nAvailable use cases:")
    for i, (name, _) in enumerate(use_cases, 1):
        print(f"  {i}. {name}")
    print("  0. Run all examples")

    try:
        if RICH_AVAILABLE:
            from rich.prompt import Prompt
            choice = Prompt.ask("\nSelect use case", default="0")
        else:
            choice = input("\nSelect use case (0-6): ").strip()

        choice = int(choice)

        if choice == 0:
            for name, func in use_cases:
                func()
        elif 1 <= choice <= len(use_cases):
            use_cases[choice-1][1]()
        else:
            print("Invalid choice")

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
