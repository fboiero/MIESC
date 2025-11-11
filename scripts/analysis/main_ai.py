#!/usr/bin/env python3
"""
MIESC - Enhanced Main Entry Point with AI Agents

This is the enhanced version of main.py that includes:
- Traditional static analysis (Slither, Mythril)
- AI-powered analysis (OpenAI, GPTLens, Llama2)
- Open-source AI agents (Ollama, CrewAI)

Usage:
    python main_ai.py <contract_file> <tag> [options]

Examples:
    # Traditional + Ollama
    python main_ai.py contracts/MyToken.sol mytoken --use-ollama

    # Traditional + CrewAI
    python main_ai.py contracts/MyToken.sol mytoken --use-crewai

    # Full AI analysis (Ollama + CrewAI)
    python main_ai.py contracts/MyToken.sol mytoken --use-ollama --use-crewai

    # Custom Ollama model
    python main_ai.py contracts/MyToken.sol mytoken --use-ollama --ollama-model codellama:7b

    # Quick analysis (fast model)
    python main_ai.py contracts/MyToken.sol mytoken --quick
"""

import sys
import os
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config.config import ModelConfig
from src.text_generator import TextGenerator
from src.utils import flatter_contract, remove_file
from src.audit_generator import create_audit_in_pdf

# Import tools conditionally
try:
    from src.Llama2_tool import audit_contract as llama2_audit_contract
    LLAMA2_AVAILABLE = True
except ImportError:
    LLAMA2_AVAILABLE = False
    llama2_audit_contract = None

try:
    from src.rawchatGPT_tool import audit_contract as rawchatGPT_audit_contract
    RAWGPT_AVAILABLE = True
except ImportError:
    RAWGPT_AVAILABLE = False
    rawchatGPT_audit_contract = None

try:
    from src.GPTLens_tool import audit_contract as GPTLens_audit_contract
    GPTLENS_AVAILABLE = True
except ImportError:
    GPTLENS_AVAILABLE = False
    GPTLens_audit_contract = None

try:
    from src.slither_tool import audit_contract as slither_audit_contract
    SLITHER_AVAILABLE = True
except ImportError:
    SLITHER_AVAILABLE = False
    slither_audit_contract = None

try:
    from src.mythril_tool import audit_contract as mythril_audit_contract
    MYTHRIL_AVAILABLE = True
except ImportError:
    MYTHRIL_AVAILABLE = False
    mythril_audit_contract = None

# Import new AI agents
try:
    from src.agents.ollama_agent import OllamaAgent
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

try:
    from src.agents.crewai_coordinator import CrewAICoordinator
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.panel import Panel
    from rich.table import Table
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

import warnings
warnings.filterwarnings('ignore')


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='MIESC - Multi-agent Integrated Security for Smart Contracts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis with default tools
  python main_ai.py contracts/MyToken.sol mytoken

  # Include Ollama (local AI, cost-free)
  python main_ai.py contracts/MyToken.sol mytoken --use-ollama

  # Include CrewAI (multi-agent)
  python main_ai.py contracts/MyToken.sol mytoken --use-crewai

  # Full AI analysis
  python main_ai.py contracts/MyToken.sol mytoken --use-ollama --use-crewai

  # Quick analysis (fast model)
  python main_ai.py contracts/MyToken.sol mytoken --quick

  # Custom Ollama model
  python main_ai.py contracts/MyToken.sol mytoken --use-ollama --ollama-model codellama:7b
        """
    )

    parser.add_argument('contract_file', help='Path to Solidity contract file')
    parser.add_argument('tag', help='Output tag/directory name')

    # Tool selection
    parser.add_argument('--use-slither', action='store_true', default=True,
                        help='Use Slither static analyzer (default: True)')
    parser.add_argument('--use-mythril', action='store_true',
                        help='Use Mythril symbolic analyzer')
    parser.add_argument('--use-rawgpt', action='store_true',
                        help='Use raw ChatGPT analysis')
    parser.add_argument('--use-gptlens', action='store_true',
                        help='Use GPTLens analysis')
    parser.add_argument('--use-llama', action='store_true',
                        help='Use Llama2 analysis')

    # AI agent selection
    parser.add_argument('--use-ollama', action='store_true',
                        help='Use Ollama local LLM (cost-free, private)')
    parser.add_argument('--use-crewai', action='store_true',
                        help='Use CrewAI multi-agent coordination')

    # Ollama options
    parser.add_argument('--ollama-model', default='codellama:13b',
                        help='Ollama model to use (default: codellama:13b)')

    # CrewAI options
    parser.add_argument('--crewai-local', action='store_true', default=True,
                        help='Use local LLM with CrewAI (default: True)')
    parser.add_argument('--crewai-model', default='ollama/codellama:13b',
                        help='Model for CrewAI agents (default: ollama/codellama:13b)')

    # Quick mode
    parser.add_argument('--quick', action='store_true',
                        help='Quick analysis mode (uses codellama:7b)')

    # Report options
    parser.add_argument('--include-summary', action='store_true',
                        help='Include summary in report')
    parser.add_argument('--include-tests', action='store_true',
                        help='Include suggested unit tests')
    parser.add_argument('--include-conclusion', action='store_true',
                        help='Include conclusion in report')

    return parser.parse_args()


def ollama_audit_contract(content, solidity_version, model="codellama:13b"):
    """
    Run Ollama agent analysis

    Args:
        content: Contract source code
        solidity_version: Solidity version
        model: Ollama model to use

    Returns:
        Analysis results as string
    """
    if not OLLAMA_AVAILABLE:
        return "Error: OllamaAgent not available. Install dependencies: pip install -r requirements_agents.txt"

    if RICH_AVAILABLE:
        console.print(f"[cyan]Running Ollama analysis ({model})...[/cyan]")

    agent = OllamaAgent(model=model)

    # Create temporary file for analysis
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
        f.write(content)
        temp_path = f.name

    try:
        results = agent.run(temp_path)
        findings = results.get("ollama_findings", [])

        # Format results
        output = f"Ollama Analysis (Model: {model})\n"
        output += f"=" * 60 + "\n\n"
        output += f"Found {len(findings)} potential issues\n\n"

        for i, finding in enumerate(findings, 1):
            output += f"{i}. [{finding.get('severity', 'Unknown')}] {finding.get('category', 'Unknown')}\n"
            output += f"   Location: {finding.get('location', 'N/A')}\n"
            output += f"   Description: {finding.get('description', 'N/A')}\n"
            output += f"   Recommendation: {finding.get('recommendation', 'N/A')}\n"
            output += f"   SWC-ID: {finding.get('swc_id', 'N/A')}\n"
            output += f"   OWASP: {', '.join(finding.get('owasp_category', []))}\n\n"

        return output

    finally:
        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)


def crewai_audit_contract(content, solidity_version, use_local_llm=True, llm_model="ollama/codellama:13b"):
    """
    Run CrewAI multi-agent analysis

    Args:
        content: Contract source code
        solidity_version: Solidity version
        use_local_llm: Use local LLM (Ollama)
        llm_model: Model for CrewAI agents

    Returns:
        Analysis results as string
    """
    if not CREWAI_AVAILABLE:
        return "Error: CrewAICoordinator not available. Install dependencies: pip install -r requirements_agents.txt"

    if RICH_AVAILABLE:
        console.print(f"[cyan]Running CrewAI multi-agent analysis...[/cyan]")

    coordinator = CrewAICoordinator(
        use_local_llm=use_local_llm,
        llm_model=llm_model
    )

    # Create temporary file for analysis
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
        f.write(content)
        temp_path = f.name

    try:
        results = coordinator.run(temp_path)
        findings = results.get("crew_findings", [])
        summary = results.get("crew_summary", {})

        # Format results
        output = f"CrewAI Multi-Agent Analysis\n"
        output += f"=" * 60 + "\n\n"
        output += f"Agents: {summary.get('agents_involved', 'N/A')}\n"
        output += f"Found {len(findings)} issues\n\n"

        # Group by agent
        by_agent = {}
        for finding in findings:
            agent = finding.get('source', 'Unknown')
            if agent not in by_agent:
                by_agent[agent] = []
            by_agent[agent].append(finding)

        for agent, agent_findings in by_agent.items():
            output += f"\n--- {agent} ---\n"
            for i, finding in enumerate(agent_findings, 1):
                output += f"{i}. [{finding.get('severity', 'Unknown')}] {finding.get('category', 'Unknown')}\n"
                output += f"   {finding.get('description', 'N/A')}\n"
                output += f"   Recommendation: {finding.get('recommendation', 'N/A')}\n\n"

        return output

    finally:
        # Clean up temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)


def main():
    """Main entry point"""
    args = parse_arguments()

    # Print header
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            "[bold cyan]MIESC - Multi-agent Integrated Security[/bold cyan]\n\n"
            f"[white]Contract:[/white] {args.contract_file}\n"
            f"[white]Output:[/white] output/{args.tag}/",
            border_style="cyan"
        ))
    else:
        print("=" * 60)
        print("MIESC - Multi-agent Integrated Security")
        print("=" * 60)
        print(f"Contract: {args.contract_file}")
        print(f"Output: output/{args.tag}/")
        print()

    # Create config from arguments
    config = ModelConfig()
    config.use_slither = args.use_slither
    config.use_mythril = args.use_mythril
    config.use_rawGPT = args.use_rawgpt
    config.use_GPTLens = args.use_gptlens
    config.use_rawLlama = args.use_llama
    config.use_ollama = args.use_ollama
    config.use_crewai = args.use_crewai
    config.include_summary = args.include_summary
    config.include_unitary_test = args.include_tests
    config.include_conclusion = args.include_conclusion

    # Quick mode
    if args.quick:
        config.use_ollama = True
        args.ollama_model = 'codellama:7b'
        if RICH_AVAILABLE:
            console.print("[yellow]Quick mode enabled (using codellama:7b)[/yellow]\n")

    # Read contract
    path_to_file = args.contract_file
    with open(path_to_file, "r") as f:
        content = f.read()
        content = content.replace('"', "'")

    # Extract Solidity version
    solidity_version = ''
    with open(path_to_file, "r") as f:
        for line in f:
            if 'pragma solidity' in line:
                solidity_version = line[line.find('.')-1:line.find(';')]
                break

    # Run analysis tools
    audit_information = {}
    tag = args.tag

    # Display tools being used
    active_tools = []
    if config.use_slither:
        active_tools.append("Slither")
    if config.use_mythril:
        active_tools.append("Mythril")
    if config.use_rawGPT:
        active_tools.append("ChatGPT")
    if config.use_GPTLens:
        active_tools.append("GPTLens")
    if config.use_rawLlama:
        active_tools.append("Llama2")
    if config.use_ollama:
        active_tools.append(f"Ollama ({args.ollama_model})")
    if config.use_crewai:
        active_tools.append("CrewAI")

    if RICH_AVAILABLE:
        table = Table(title="Analysis Tools", show_header=False)
        table.add_column("Tool", style="cyan")
        for tool in active_tools:
            table.add_row(f"✓ {tool}")
        console.print(table)
        console.print()

    # Run traditional tools
    if config.use_rawGPT and RAWGPT_AVAILABLE and not os.path.exists(f'output/{tag}/rawchatGPT.txt'):
        audit_information['rawchatGPT'] = rawchatGPT_audit_contract(content, solidity_version)
    elif config.use_rawGPT and not RAWGPT_AVAILABLE:
        print("Warning: ChatGPT tool not available (missing dependencies)")

    if config.use_GPTLens and GPTLENS_AVAILABLE and not os.path.exists(f'output/{tag}/GPTLens.txt'):
        audit_information['GPTLens'] = GPTLens_audit_contract(content, solidity_version)
    elif config.use_GPTLens and not GPTLENS_AVAILABLE:
        print("Warning: GPTLens tool not available (missing dependencies)")

    if config.use_rawLlama and LLAMA2_AVAILABLE and not os.path.exists(f'output/{tag}/Llama2.txt'):
        audit_information['Llama2'] = llama2_audit_contract(content, solidity_version)
    elif config.use_rawLlama and not LLAMA2_AVAILABLE:
        print("Warning: Llama2 tool not available (missing dependencies)")

    if config.use_slither and SLITHER_AVAILABLE and not os.path.exists(f'output/{tag}/Slither.txt'):
        audit_information['Slither'] = slither_audit_contract(path_to_file, solidity_version)
    elif config.use_slither and not SLITHER_AVAILABLE:
        print("Warning: Slither tool not available (install: pip install slither-analyzer)")

    if config.use_mythril and MYTHRIL_AVAILABLE and not os.path.exists(f'output/{tag}/Mythril.txt'):
        audit_information['Mythril'] = mythril_audit_contract(path_to_file, solidity_version)
    elif config.use_mythril and not MYTHRIL_AVAILABLE:
        print("Warning: Mythril tool not available (install: pip install mythril)")

    # Run new AI agents
    if config.use_ollama and not os.path.exists(f'output/{tag}/Ollama.txt'):
        audit_information['Ollama'] = ollama_audit_contract(
            content,
            solidity_version,
            model=args.ollama_model
        )

    if config.use_crewai and not os.path.exists(f'output/{tag}/CrewAI.txt'):
        audit_information['CrewAI'] = crewai_audit_contract(
            content,
            solidity_version,
            use_local_llm=args.crewai_local,
            llm_model=args.crewai_model
        )

    # Generate tests and conclusion
    suggested_tests = ''
    if config.include_unitary_test:
        suggested_tests += TextGenerator().test_generator(content)

    conclusion_text = ''
    if config.include_conclusion:
        conclusion_text = TextGenerator().conclusion_generator(audit_information)

    # Create audit report
    create_audit_in_pdf(audit_information, suggested_tests, conclusion_text, tag, config_module=config)

    # Success message
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            f"[bold green]✓ Analysis Complete[/bold green]\n\n"
            f"[white]Results saved to:[/white] output/{tag}/\n"
            f"[white]Tools used:[/white] {len(audit_information)}",
            border_style="green"
        ))
    else:
        print("\n" + "=" * 60)
        print("✓ Analysis Complete")
        print("=" * 60)
        print(f"Results saved to: output/{tag}/")
        print(f"Tools used: {len(audit_information)}")


if __name__ == '__main__':
    main()
