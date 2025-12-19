#!/usr/bin/env python3
"""
install_tools.py - Security tool installation for MIESC

Installs all 24 security analysis tools across 7 defense layers.
Handles both local (DPGA-compliant) and API-based tooling.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

import os
import sys
import subprocess
import platform
from typing import Dict, List, Tuple, Optional

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner():
    """Print installer header"""
    banner = f"""
{Colors.HEADER}MIESC Tool Installer v3.5.0{Colors.ENDC}
Multi-layer security analysis framework for Ethereum smart contracts

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0 | Repository: https://github.com/fboiero/MIESC
"""
    print(banner)


def detect_os() -> Tuple[str, str]:
    """Detect operating system and architecture"""
    os_type = platform.system()
    arch = platform.machine()

    print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} Detected OS: {os_type} ({arch})")
    return os_type, arch


def check_command(command: str) -> bool:
    """Check if a command is available"""
    try:
        subprocess.run(
            [command, "--version"],
            capture_output=True,
            timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_command(command: str, shell: bool = False) -> Tuple[bool, str]:
    """Run a shell command and return success status and output"""
    try:
        result = subprocess.run(
            command if shell else command.split(),
            capture_output=True,
            text=True,
            shell=shell,
            timeout=600
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


# Tool definitions
# Format: (name, description, install_cmd, dpga_compliant, layer, dependencies)
TOOLS = {
    # Layer 1: Static Analysis
    "slither": {
        "name": "Slither",
        "description": "Trail of Bits static analyzer (88+ detectors)",
        "install_cmd": "pip3 install slither-analyzer",
        "check_cmd": "slither",
        "dpga_compliant": True,
        "layer": 1,
        "dependencies": ["python3", "pip3"],
        "optional": True
    },
    "aderyn": {
        "name": "Aderyn",
        "description": "Cyfrin Rust-based static analyzer",
        "install_cmd": "cargo install aderyn",
        "check_cmd": "aderyn",
        "dpga_compliant": True,
        "layer": 1,
        "dependencies": ["cargo"],
        "optional": True
    },
    "solhint": {
        "name": "Solhint",
        "description": "Solidity linter (200+ rules)",
        "install_cmd": "npm install -g solhint",
        "check_cmd": "solhint",
        "dpga_compliant": True,
        "layer": 1,
        "dependencies": ["npm"],
        "optional": True
    },
    "semgrep": {
        "name": "Semgrep",
        "description": "Lightweight static analysis with custom rules",
        "install_cmd": "pip3 install semgrep",
        "check_cmd": "semgrep",
        "dpga_compliant": True,
        "layer": 1,
        "dependencies": ["python3", "pip3"],
        "optional": True
    },
    "mythx": {
        "name": "MythX",
        "description": "ConsenSys security API (requires account)",
        "install_cmd": "pip3 install mythx-cli",
        "check_cmd": "mythx",
        "dpga_compliant": False,
        "layer": 1,
        "dependencies": ["python3", "pip3"],
        "optional": True,
        "note": "Requires MythX API credentials"
    },

    # Layer 2: Dynamic Testing
    "echidna": {
        "name": "Echidna",
        "description": "Trail of Bits property-based fuzzer",
        "install_cmd": {
            "Darwin": "brew install echidna",
            "Linux": "wget https://github.com/crytic/echidna/releases/latest/download/echidna-test-$(uname -s)-$(uname -m) -O echidna-test && chmod +x echidna-test && sudo mv echidna-test /usr/local/bin/echidna"
        },
        "check_cmd": "echidna",
        "dpga_compliant": True,
        "layer": 2,
        "dependencies": [],
        "optional": True
    },
    "medusa": {
        "name": "Medusa",
        "description": "Crytic Go-based fuzzer",
        "install_cmd": "go install github.com/crytic/medusa@latest",
        "check_cmd": "medusa",
        "dpga_compliant": True,
        "layer": 2,
        "dependencies": ["go"],
        "optional": True
    },
    "foundry": {
        "name": "Foundry",
        "description": "Paradigm Solidity testing toolkit",
        "install_cmd": "curl -L https://foundry.paradigm.xyz | bash && foundryup",
        "check_cmd": "forge",
        "dpga_compliant": True,
        "layer": 2,
        "dependencies": [],
        "optional": True,
        "shell": True
    },
    "hardhat": {
        "name": "Hardhat",
        "description": "Nomic Labs development environment",
        "install_cmd": "npm install -g hardhat",
        "check_cmd": "hardhat",
        "dpga_compliant": True,
        "layer": 2,
        "dependencies": ["npm"],
        "optional": True
    },

    # Layer 3: Symbolic Execution
    "mythril": {
        "name": "Mythril",
        "description": "ConsenSys symbolic execution tool",
        "install_cmd": "pip3 install mythril",
        "check_cmd": "myth",
        "dpga_compliant": True,
        "layer": 3,
        "dependencies": ["python3", "pip3"],
        "optional": True
    },
    "manticore": {
        "name": "Manticore",
        "description": "Trail of Bits symbolic execution engine",
        "install_cmd": "pip3 install manticore[native]",
        "check_cmd": "manticore",
        "dpga_compliant": True,
        "layer": 3,
        "dependencies": ["python3", "pip3"],
        "optional": True
    },
    "halmos": {
        "name": "Halmos",
        "description": "a16z symbolic testing framework",
        "install_cmd": "pip3 install halmos",
        "check_cmd": "halmos",
        "dpga_compliant": True,
        "layer": 3,
        "dependencies": ["python3", "pip3"],
        "optional": True
    },

    # Layer 4: Formal Verification
    "certora": {
        "name": "Certora Prover",
        "description": "Commercial formal verifier (requires license)",
        "install_cmd": "pip3 install certora-cli",
        "check_cmd": "certoraRun",
        "dpga_compliant": False,
        "layer": 4,
        "dependencies": ["python3", "pip3"],
        "optional": True,
        "note": "Requires Certora API key"
    },
    "smtchecker": {
        "name": "SMTChecker",
        "description": "Built-in Solidity compiler verification",
        "install_cmd": "echo 'Included with solc >= 0.8.0'",
        "check_cmd": "solc",
        "dpga_compliant": True,
        "layer": 4,
        "dependencies": ["solc"],
        "optional": True,
        "shell": True
    },
    "wake": {
        "name": "Wake",
        "description": "Ackee Python-based development framework",
        "install_cmd": "pip3 install eth-wake",
        "check_cmd": "wake",
        "dpga_compliant": True,
        "layer": 4,
        "dependencies": ["python3", "pip3"],
        "optional": True
    },
    "propertygpt": {
        "name": "PropertyGPT",
        "description": "LLM-driven formal property generation (NDSS 2025)",
        "install_cmd": {
            "Darwin": "brew install ollama && ollama pull openhermes",
            "Linux": "curl https://ollama.ai/install.sh | sh && ollama pull openhermes"
        },
        "check_cmd": "ollama",
        "dpga_compliant": True,
        "layer": 4,
        "dependencies": [],
        "optional": True,
        "note": "Uses local Ollama for property generation (80% recall on CVL specs)"
    },

    # Layer 5: AI-Powered Analysis
    "smartllm": {
        "name": "SmartLLM",
        "description": "Local LLM via Ollama (deepseek-coder)",
        "install_cmd": {
            "Darwin": "brew install ollama && ollama pull deepseek-coder",
            "Linux": "curl -fsSL https://ollama.com/install.sh | sh && ollama pull deepseek-coder"
        },
        "check_cmd": "ollama",
        "dpga_compliant": True,
        "layer": 5,
        "dependencies": [],
        "optional": True,
        "shell": True
    },
    "gptscan": {
        "name": "GPTScan",
        "description": "GPT-4 vulnerability scanner (requires API key)",
        "install_cmd": "pip3 install gptscan",
        "check_cmd": "gptscan",
        "dpga_compliant": False,
        "layer": 5,
        "dependencies": ["python3", "pip3"],
        "optional": True,
        "note": "Requires OPENAI_API_KEY environment variable"
    },
    "llm_smartaudit": {
        "name": "LLM-SmartAudit",
        "description": "Multi-agent LLM auditing framework",
        "install_cmd": "echo 'Built-in module - no installation required'",
        "check_cmd": "python3",
        "dpga_compliant": True,
        "layer": 5,
        "dependencies": ["python3"],
        "optional": True,
        "shell": True
    },

    # Layer 6: ML-Based Detection
    "dagnn": {
        "name": "DA-GNN",
        "description": "Deep Attention Graph Neural Network (95.7% accuracy, Computer Networks 2024)",
        "install_cmd": "pip3 install torch torch-geometric scikit-learn networkx",
        "check_cmd": "python3",
        "dpga_compliant": True,
        "layer": 6,
        "dependencies": ["python3", "pip3", "slither"],
        "optional": True,
        "note": "GNN-based vulnerability detection with CFG+DFG analysis"
    },
    "lightgbm": {
        "name": "LightGBM",
        "description": "Microsoft gradient boosting for anomaly detection",
        "install_cmd": "pip3 install lightgbm scikit-learn pandas",
        "check_cmd": "python3",
        "dpga_compliant": True,
        "layer": 6,
        "dependencies": ["python3", "pip3"],
        "optional": True
    },
    "prophet": {
        "name": "Prophet",
        "description": "Facebook time-series anomaly detection",
        "install_cmd": "pip3 install prophet",
        "check_cmd": "python3",
        "dpga_compliant": True,
        "layer": 6,
        "dependencies": ["python3", "pip3"],
        "optional": True
    },

    # Layer 7: Policy & Compliance
    "swc_registry": {
        "name": "SWC Registry",
        "description": "Smart Contract Weakness Classification",
        "install_cmd": "echo 'Built-in SWC mapping - no installation required'",
        "check_cmd": "python3",
        "dpga_compliant": True,
        "layer": 7,
        "dependencies": ["python3"],
        "optional": True,
        "shell": True
    },
    "eip_checker": {
        "name": "EIP Checker",
        "description": "Ethereum Improvement Proposal compliance",
        "install_cmd": "echo 'Built-in EIP checker - no installation required'",
        "check_cmd": "python3",
        "dpga_compliant": True,
        "layer": 7,
        "dependencies": ["python3"],
        "optional": True,
        "shell": True
    },

    # Dependencies
    "solc": {
        "name": "Solidity Compiler",
        "description": "Official Solidity compiler (includes SMTChecker)",
        "install_cmd": {
            "Darwin": "brew install solidity",
            "Linux": "sudo add-apt-repository ppa:ethereum/ethereum && sudo apt-get update && sudo apt-get install solc"
        },
        "check_cmd": "solc",
        "dpga_compliant": True,
        "layer": 0,
        "dependencies": [],
        "optional": False,
        "shell": True
    },
    "docker": {
        "name": "Docker",
        "description": "Container runtime for isolated analysis",
        "install_cmd": {
            "Darwin": "brew install --cask docker",
            "Linux": "curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh"
        },
        "check_cmd": "docker",
        "dpga_compliant": True,
        "layer": 0,
        "dependencies": [],
        "optional": True,
        "shell": True
    }
}


def check_tool_status(tool_key: str, tool_info: Dict) -> bool:
    """Check if a tool is already installed"""
    return check_command(tool_info["check_cmd"])


def install_tool(tool_key: str, tool_info: Dict, os_type: str) -> bool:
    """Install a single tool"""
    print(f"\n{Colors.OKCYAN}[INSTALL]{Colors.ENDC} Installing {tool_info['name']}...")

    # Get install command (may be OS-specific)
    install_cmd = tool_info["install_cmd"]
    if isinstance(install_cmd, dict):
        if os_type not in install_cmd:
            print(f"{Colors.WARNING}[WARN]{Colors.ENDC} No installation command for {os_type}")
            return False
        install_cmd = install_cmd[os_type]

    # Check dependencies
    for dep in tool_info.get("dependencies", []):
        if not check_command(dep):
            print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} Missing dependency: {dep}")
            print(f"Please install {dep} first")
            return False

    # Run installation
    shell = tool_info.get("shell", False)
    success, output = run_command(install_cmd, shell=shell)

    if success:
        print(f"{Colors.OKGREEN}[OK]{Colors.ENDC} {tool_info['name']} installed successfully")
        return True
    else:
        print(f"{Colors.FAIL}[FAIL]{Colors.ENDC} Installation failed:")
        print(output)
        return False


def print_tool_list():
    """Print categorized tool list"""
    print(f"\n{Colors.BOLD}Available Tools by Layer:{Colors.ENDC}\n")

    layers = {
        0: "Core Dependencies",
        1: "Static Analysis",
        2: "Dynamic Testing",
        3: "Symbolic Execution",
        4: "Formal Verification",
        5: "AI-Powered Analysis",
        6: "ML-Based Detection",
        7: "Policy & Compliance"
    }

    for layer_num in sorted(layers.keys()):
        print(f"{Colors.HEADER}Layer {layer_num}: {layers[layer_num]}{Colors.ENDC}")

        for tool_key, tool_info in TOOLS.items():
            if tool_info["layer"] == layer_num:
                status = "✓" if check_tool_status(tool_key, tool_info) else "✗"
                dpga = "DPGA" if tool_info["dpga_compliant"] else "NON-DPGA"
                optional = "(Optional)" if tool_info["optional"] else "(Required)"

                color = Colors.OKGREEN if status == "✓" else Colors.FAIL
                print(f"  {color}[{status}]{Colors.ENDC} {tool_key:15} - {tool_info['name']:30} {dpga:10} {optional}")

                if "note" in tool_info:
                    print(f"      {Colors.WARNING}Note: {tool_info['note']}{Colors.ENDC}")

        print()


def interactive_menu(os_type: str):
    """Interactive installation menu"""
    while True:
        print(f"\n{Colors.BOLD}Installation Options:{Colors.ENDC}")
        print("1. Install all DPGA-compliant tools")
        print("2. Install all tools (including non-DPGA)")
        print("3. Install by layer")
        print("4. Install specific tool")
        print("5. Show tool status")
        print("6. Install core dependencies only")
        print("0. Exit")

        choice = input(f"\n{Colors.OKCYAN}Select option:{Colors.ENDC} ").strip()

        if choice == "0":
            print(f"{Colors.OKGREEN}Installation complete!{Colors.ENDC}")
            break
        elif choice == "1":
            install_dpga_tools(os_type)
        elif choice == "2":
            install_all_tools(os_type)
        elif choice == "3":
            install_by_layer(os_type)
        elif choice == "4":
            install_specific_tool(os_type)
        elif choice == "5":
            print_tool_list()
        elif choice == "6":
            install_dependencies(os_type)
        else:
            print(f"{Colors.FAIL}Invalid option{Colors.ENDC}")


def install_dpga_tools(os_type: str):
    """Install all DPGA-compliant tools"""
    print(f"\n{Colors.HEADER}Installing DPGA-compliant tools...{Colors.ENDC}")

    for tool_key, tool_info in TOOLS.items():
        if tool_info["dpga_compliant"] and not check_tool_status(tool_key, tool_info):
            install_tool(tool_key, tool_info, os_type)


def install_all_tools(os_type: str):
    """Install all tools"""
    print(f"\n{Colors.HEADER}Installing all tools...{Colors.ENDC}")
    print(f"{Colors.WARNING}Warning: This includes non-DPGA-compliant tools that may require licenses{Colors.ENDC}")

    confirm = input("Continue? (y/n): ").strip().lower()
    if confirm != "y":
        return

    for tool_key, tool_info in TOOLS.items():
        if not check_tool_status(tool_key, tool_info):
            install_tool(tool_key, tool_info, os_type)


def install_by_layer(os_type: str):
    """Install tools by layer"""
    layers = {
        0: "Core Dependencies",
        1: "Static Analysis",
        2: "Dynamic Testing",
        3: "Symbolic Execution",
        4: "Formal Verification",
        5: "AI-Powered Analysis",
        6: "ML-Based Detection",
        7: "Policy & Compliance"
    }

    print(f"\n{Colors.BOLD}Select Layer:{Colors.ENDC}")
    for num, name in layers.items():
        print(f"{num}. {name}")

    layer_choice = input(f"{Colors.OKCYAN}Layer number:{Colors.ENDC} ").strip()

    try:
        layer_num = int(layer_choice)
        if layer_num not in layers:
            print(f"{Colors.FAIL}Invalid layer{Colors.ENDC}")
            return

        print(f"\n{Colors.HEADER}Installing {layers[layer_num]} tools...{Colors.ENDC}")

        for tool_key, tool_info in TOOLS.items():
            if tool_info["layer"] == layer_num and not check_tool_status(tool_key, tool_info):
                install_tool(tool_key, tool_info, os_type)

    except ValueError:
        print(f"{Colors.FAIL}Invalid input{Colors.ENDC}")


def install_specific_tool(os_type: str):
    """Install a specific tool"""
    print(f"\n{Colors.BOLD}Available tools:{Colors.ENDC}")
    for tool_key in TOOLS.keys():
        status = "✓" if check_tool_status(tool_key, TOOLS[tool_key]) else "✗"
        print(f"  [{status}] {tool_key}")

    tool_choice = input(f"\n{Colors.OKCYAN}Tool name:{Colors.ENDC} ").strip()

    if tool_choice in TOOLS:
        if check_tool_status(tool_choice, TOOLS[tool_choice]):
            print(f"{Colors.WARNING}Tool already installed{Colors.ENDC}")
        else:
            install_tool(tool_choice, TOOLS[tool_choice], os_type)
    else:
        print(f"{Colors.FAIL}Unknown tool{Colors.ENDC}")


def install_dependencies(os_type: str):
    """Install only core dependencies"""
    print(f"\n{Colors.HEADER}Installing core dependencies...{Colors.ENDC}")

    for tool_key, tool_info in TOOLS.items():
        if not tool_info["optional"] and not check_tool_status(tool_key, tool_info):
            install_tool(tool_key, tool_info, os_type)


def main():
    """Main entry point"""
    print_banner()

    # Detect OS
    os_type, arch = detect_os()

    if os_type not in ["Darwin", "Linux"]:
        print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} Unsupported OS: {os_type}")
        print("This installer supports macOS (Darwin) and Linux only")
        sys.exit(1)

    # Check if running as root (needed for some installations)
    if os.geteuid() != 0 and os_type == "Linux":
        print(f"{Colors.WARNING}[WARN]{Colors.ENDC} Some tools may require sudo privileges")
        print("You may be prompted for your password during installation")

    # Show current status
    print_tool_list()

    # Start interactive menu
    interactive_menu(os_type)

    # Final status
    print(f"\n{Colors.BOLD}Final Installation Status:{Colors.ENDC}")
    print_tool_list()

    print(f"""
{Colors.OKGREEN}Installation complete.{Colors.ENDC}

All tools are optional per DPGA compliance requirements.
The framework will adapt based on which tools are available.

Usage:
  python3 demo_v3.5.py                            # Demo
  python3 -m miesc.api                            # API server
  python3 -m miesc.cli analyze <contract.sol>    # CLI

Documentation: ./docs/
""")


if __name__ == "__main__":
    main()
