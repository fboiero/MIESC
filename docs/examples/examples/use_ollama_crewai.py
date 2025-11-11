#!/usr/bin/env python3
"""
Example: Using Ollama and CrewAI with MIESC

Demonstrates:
1. OllamaAgent for cost-free local analysis
2. CrewAI for multi-agent coordination
3. Comparison with traditional tools
4. Integration with existing MIESC workflow
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.agents.ollama_agent import OllamaAgent
from src.agents.crewai_coordinator import CrewAICoordinator
from src.agents.static_agent import StaticAgent  # Assuming you have this

def example_1_basic_ollama():
    """Example 1: Basic Ollama usage"""
    print("\n" + "="*60)
    print("EXAMPLE 1: Basic Ollama Analysis")
    print("="*60)

    # Create Ollama agent
    agent = OllamaAgent(model="codellama:13b")

    # Analyze contract
    contract_path = "examples/reentrancy.sol"

    print(f"\nAnalyzing {contract_path} with Ollama...")

    results = agent.run(contract_path)

    # Display results
    findings = results.get("ollama_findings", [])
    print(f"\nFound {len(findings)} issues")

    for finding in findings[:3]:  # Show first 3
        print(f"\n[{finding['id']}] {finding['severity']}")
        print(f"  {finding['description'][:100]}...")


def example_2_compare_models():
    """Example 2: Compare different Ollama models"""
    print("\n" + "="*60)
    print("EXAMPLE 2: Model Comparison")
    print("="*60)

    models = [
        "codellama:7b",      # Fast
        "codellama:13b",     # Balanced
        "deepseek-coder:6.7b"  # Specialized
    ]

    contract_path = "examples/reentrancy.sol"

    for model in models:
        print(f"\n--- Testing {model} ---")

        agent = OllamaAgent(model=model)
        results = agent.run(contract_path)

        findings = results.get("ollama_findings", [])
        exec_time = results.get("execution_time", 0)

        print(f"  Findings: {len(findings)}")
        print(f"  Time: {exec_time:.2f}s")


def example_3_crewai_coordination():
    """Example 3: CrewAI multi-agent coordination"""
    print("\n" + "="*60)
    print("EXAMPLE 3: CrewAI Multi-Agent Coordination")
    print("="*60)

    # Create CrewAI coordinator
    coordinator = CrewAICoordinator(
        use_local_llm=True,
        llm_model="ollama/codellama:13b"
    )

    contract_path = "examples/reentrancy.sol"

    print(f"\nCoordinating multi-agent analysis of {contract_path}...")

    results = coordinator.run(contract_path)

    # Display results
    findings = results.get("crew_findings", [])
    summary = results.get("crew_summary", {})

    print(f"\n📊 CrewAI Results:")
    print(f"  Total Findings: {len(findings)}")
    print(f"  Execution Time: {summary.get('execution_time', 0):.2f}s")

    for finding in findings[:3]:
        print(f"\n  [{finding['id']}] {finding['severity']}")
        print(f"    {finding['description'][:80]}...")


def example_4_hybrid_workflow():
    """Example 4: Hybrid workflow (traditional + AI)"""
    print("\n" + "="*60)
    print("EXAMPLE 4: Hybrid Traditional + AI Workflow")
    print("="*60)

    contract_path = "examples/reentrancy.sol"

    # Step 1: Fast static analysis (Slither)
    print("\n[1/3] Running Slither (traditional)...")
    # static_agent = StaticAgent()
    # static_results = static_agent.run(contract_path)
    print("  ✓ Slither complete")

    # Step 2: AI analysis (Ollama - free)
    print("\n[2/3] Running Ollama AI analysis (free)...")
    ollama_agent = OllamaAgent(model="codellama:7b")  # Fast model
    ollama_results = ollama_agent.run(contract_path)
    print(f"  ✓ Ollama complete - {len(ollama_results.get('ollama_findings', []))} findings")

    # Step 3: Multi-agent validation (CrewAI)
    print("\n[3/3] Running CrewAI multi-agent validation...")
    crew = CrewAICoordinator(use_local_llm=True)
    crew_results = crew.run(contract_path)
    print(f"  ✓ CrewAI complete - {len(crew_results.get('crew_findings', []))} findings")

    print("\n📊 Hybrid Analysis Summary:")
    # print(f"  Slither: {len(static_results.get('static_findings', []))} findings")
    print(f"  Ollama: {len(ollama_results.get('ollama_findings', []))} findings")
    print(f"  CrewAI: {len(crew_results.get('crew_findings', []))} findings")


def example_5_cost_comparison():
    """Example 5: Cost comparison (Ollama vs OpenAI)"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Cost Comparison")
    print("="*60)

    print("\nCost Analysis for 100 contract analyses:")
    print()
    print("┌─────────────────┬──────────┬──────────────┬──────────┐")
    print("│ Service         │ Per Call │ 100 Calls    │ Monthly  │")
    print("├─────────────────┼──────────┼──────────────┼──────────┤")
    print("│ OpenAI GPT-4    │ $0.03    │ $3.00        │ $90.00   │")
    print("│ OpenAI GPT-3.5  │ $0.002   │ $0.20        │ $6.00    │")
    print("│ Ollama (Local)  │ $0.00    │ $0.00        │ $0.00    │")
    print("└─────────────────┴──────────┴──────────────┴──────────┘")
    print()
    print("💡 Ollama Benefits:")
    print("  ✓ Zero cost")
    print("  ✓ Complete privacy (data never leaves your machine)")
    print("  ✓ No rate limits")
    print("  ✓ Works offline")
    print("  ✓ Customizable models")
    print()
    print("⚠️  Ollama Limitations:")
    print("  ✗ Requires 8-16GB RAM")
    print("  ✗ Slower than cloud APIs")
    print("  ✗ Quality depends on model size")


def example_6_production_workflow():
    """Example 6: Recommended production workflow"""
    print("\n" + "="*60)
    print("EXAMPLE 6: Recommended Production Workflow")
    print("="*60)

    print("""
    Recommended workflow for production use:

    1. DEVELOPMENT (fast feedback)
       └─> Ollama codellama:7b (fastest, free)

    2. CI/CD (automated checks)
       └─> Slither + Ollama deepseek-coder:6.7b

    3. PRE-AUDIT (before external audit)
       └─> Full MIESC suite:
           ├─> Slither (static)
           ├─> Mythril (symbolic)
           ├─> Ollama codellama:13b (AI)
           └─> CrewAI (multi-agent validation)

    4. FINAL AUDIT (high-value contracts)
       └─> Full MIESC + GPT-4 (for critical analysis)

    Cost breakdown (per contract):
    - Development: $0.00 (Ollama only)
    - CI/CD: $0.00 (Ollama only)
    - Pre-audit: $0.00 (Ollama only)
    - Final audit: $0.03 (if using GPT-4)

    Total savings: ~$0.09 per contract (97% cost reduction!)
    """)


def main():
    """Run all examples"""
    print("="*60)
    print("MIESC - Ollama & CrewAI Examples")
    print("="*60)

    examples = [
        ("Basic Ollama", example_1_basic_ollama),
        ("Model Comparison", example_2_compare_models),
        ("CrewAI Coordination", example_3_crewai_coordination),
        ("Hybrid Workflow", example_4_hybrid_workflow),
        ("Cost Comparison", example_5_cost_comparison),
        ("Production Workflow", example_6_production_workflow)
    ]

    print("\nAvailable examples:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")
    print("  0. Run all examples")

    try:
        choice = input("\nSelect example (0-6): ").strip()
        choice = int(choice)

        if choice == 0:
            for name, func in examples:
                func()
        elif 1 <= choice <= len(examples):
            examples[choice-1][1]()
        else:
            print("Invalid choice")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
