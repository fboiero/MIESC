#!/usr/bin/env python3
"""
MIESC 2025 - Complete 17-Tool Verification Script
==================================================

Verifies that all 17 tools from README are implemented with proper adapters.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 11, 2025
"""

import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple

# Add MIESC root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.tool_protocol import ToolCategory


class NeonColors:
    """Cyberpunk color scheme"""
    NEON_CYAN = '\033[96m'
    NEON_GREEN = '\033[92m'
    NEON_YELLOW = '\033[93m'
    NEON_RED = '\033[91m'
    NEON_PURPLE = '\033[95m'
    NEON_PINK = '\033[38;5;213m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'


# Define all 17 tools from README with expected metadata
EXPECTED_TOOLS = {
    # Layer 1: Static Analysis
    "slither": {
        "name": "Slither",
        "version": "0.10.3+",
        "category": ToolCategory.STATIC_ANALYSIS,
        "layer": 1,
        "adapter_file": None,  # Not yet implemented
        "expected_class": "SlitherAdapter"
    },
    "aderyn": {
        "name": "Aderyn",
        "version": "0.6.4+",
        "category": ToolCategory.STATIC_ANALYSIS,
        "layer": 1,
        "adapter_file": "src/adapters/aderyn_adapter.py",
        "expected_class": "AderynAdapter"
    },
    "solhint": {
        "name": "Solhint",
        "version": "4.1.1+",
        "category": ToolCategory.STATIC_ANALYSIS,
        "layer": 1,
        "adapter_file": None,  # Not yet implemented
        "expected_class": "SolhintAdapter"
    },

    # Layer 2: Dynamic Testing
    "echidna": {
        "name": "Echidna",
        "version": "2.2.4+",
        "category": ToolCategory.DYNAMIC_TESTING,
        "layer": 2,
        "adapter_file": None,  # Not yet implemented
        "expected_class": "EchidnaAdapter"
    },
    "medusa": {
        "name": "Medusa",
        "version": "1.3.1+",
        "category": ToolCategory.DYNAMIC_TESTING,
        "layer": 2,
        "adapter_file": "src/adapters/medusa_adapter.py",
        "expected_class": "MedusaAdapter"
    },
    "foundry": {
        "name": "Foundry",
        "version": "0.2.0+",
        "category": ToolCategory.DYNAMIC_TESTING,
        "layer": 2,
        "adapter_file": None,  # Not yet implemented
        "expected_class": "FoundryAdapter"
    },

    # Layer 3: Symbolic Execution
    "mythril": {
        "name": "Mythril",
        "version": "0.24.2+",
        "category": ToolCategory.SYMBOLIC_EXECUTION,
        "layer": 3,
        "adapter_file": None,  # Not yet implemented
        "expected_class": "MythrilAdapter"
    },
    "manticore": {
        "name": "Manticore",
        "version": "0.3.7+",
        "category": ToolCategory.SYMBOLIC_EXECUTION,
        "layer": 3,
        "adapter_file": None,  # Not yet implemented
        "expected_class": "ManticoreAdapter"
    },
    "halmos": {
        "name": "Halmos",
        "version": "0.1.13+",
        "category": ToolCategory.SYMBOLIC_EXECUTION,
        "layer": 3,
        "adapter_file": None,  # Not yet implemented
        "expected_class": "HalmosAdapter"
    },

    # Layer 4: Formal Verification
    "certora": {
        "name": "Certora",
        "version": "2024.12+",
        "category": ToolCategory.FORMAL_VERIFICATION,
        "layer": 4,
        "adapter_file": None,  # Not yet implemented (license required)
        "expected_class": "CertoraAdapter"
    },
    "smtchecker": {
        "name": "SMTChecker",
        "version": "0.8.20+",
        "category": ToolCategory.FORMAL_VERIFICATION,
        "layer": 4,
        "adapter_file": None,  # Built-in to Solidity compiler
        "expected_class": "SMTCheckerAdapter"
    },
    "wake": {
        "name": "Wake",
        "version": "4.20.1+",
        "category": ToolCategory.FORMAL_VERIFICATION,
        "layer": 4,
        "adapter_file": None,  # Not yet implemented
        "expected_class": "WakeAdapter"
    },

    # Layer 5: AI-Powered Analysis
    "gptscan": {
        "name": "GPTScan",
        "version": "1.0.0+",
        "category": ToolCategory.AI_ANALYSIS,
        "layer": 5,
        "adapter_file": None,  # Not yet implemented (requires OpenAI API)
        "expected_class": "GPTScanAdapter"
    },
    "llm_smartaudit": {
        "name": "LLM-SmartAudit",
        "version": "1.0.0+",
        "category": ToolCategory.AI_ANALYSIS,
        "layer": 5,
        "adapter_file": None,  # Not yet implemented (requires API)
        "expected_class": "LLMSmartAuditAdapter"
    },
    "smartllm": {
        "name": "SmartLLM",
        "version": "1.0.0+",
        "category": ToolCategory.AI_ANALYSIS,
        "layer": 5,
        "adapter_file": None,  # Not yet implemented (requires Ollama)
        "expected_class": "SmartLLMAdapter"
    },

    # Layer 6: Policy Compliance
    "policyagent": {
        "name": "PolicyAgent",
        "version": "2.2+",
        "category": ToolCategory.COMPLIANCE,
        "layer": 6,
        "adapter_file": None,  # Built-in agent (not an adapter)
        "expected_class": None  # Uses Agent, not Adapter
    },

    # Layer 7: Audit Readiness
    "layer7agent": {
        "name": "Layer7Agent",
        "version": "1.0+",
        "category": ToolCategory.AUDIT_READINESS,
        "layer": 7,
        "adapter_file": None,  # Built-in agent (not an adapter)
        "expected_class": None  # Uses Agent, not Adapter
    }
}


def print_banner():
    """Print verification banner"""
    print(f"\n{NeonColors.NEON_CYAN}{'='*70}{NeonColors.ENDC}")
    print(f"{NeonColors.BOLD}{NeonColors.NEON_PINK}MIESC v3.4.0 - 17-TOOL VERIFICATION{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_CYAN}{'='*70}{NeonColors.ENDC}\n")


def check_adapter_file_exists(tool_key: str, tool_info: Dict) -> Tuple[bool, str]:
    """Check if adapter file exists"""
    adapter_file = tool_info.get("adapter_file")

    if adapter_file is None:
        return False, "Not implemented"

    file_path = Path(adapter_file)
    if file_path.exists():
        return True, f"Found: {adapter_file}"
    else:
        return False, f"Missing: {adapter_file}"


def check_adapter_registered(tool_key: str) -> Tuple[bool, str]:
    """Check if adapter is registered in adapter registry"""
    try:
        from src.adapters import register_all_adapters

        # Register adapters
        report = register_all_adapters()

        # Check if tool is in registered adapters
        adapter_names = [a['name'].lower() for a in report['adapters']]

        if tool_key in adapter_names:
            # Find adapter status
            adapter_data = next((a for a in report['adapters'] if a['name'].lower() == tool_key), None)
            if adapter_data:
                status = adapter_data['status']
                return True, f"Registered ({status})"

        return False, "Not registered"

    except Exception as e:
        return False, f"Error: {str(e)}"


def verify_all_tools():
    """Verify all 17 tools"""
    results = {
        "total": 17,
        "implemented": 0,
        "registered": 0,
        "not_implemented": 0,
        "builtin_agents": 0,
        "details": []
    }

    print(f"{NeonColors.NEON_CYAN}Checking all 17 tools across 7 layers...{NeonColors.ENDC}\n")

    current_layer = 0
    for tool_key, tool_info in EXPECTED_TOOLS.items():
        layer = tool_info["layer"]

        # Print layer header
        if layer != current_layer:
            current_layer = layer
            print(f"\n{NeonColors.BOLD}{NeonColors.NEON_PURPLE}Layer {layer}: {get_layer_name(layer)}{NeonColors.ENDC}")
            print(f"{NeonColors.NEON_CYAN}{'-'*70}{NeonColors.ENDC}")

        # Check adapter file
        file_exists, file_msg = check_adapter_file_exists(tool_key, tool_info)

        # Check registration
        is_registered, reg_msg = check_adapter_registered(tool_key)

        # Determine status
        if tool_info["expected_class"] is None:
            # Built-in agent
            status = "builtin"
            status_icon = f"{NeonColors.NEON_CYAN}🔧{NeonColors.ENDC}"
            status_text = "Built-in Agent"
            results["builtin_agents"] += 1
        elif file_exists and is_registered:
            status = "implemented"
            status_icon = f"{NeonColors.NEON_GREEN}✅{NeonColors.ENDC}"
            status_text = "Implemented & Registered"
            results["implemented"] += 1
            results["registered"] += 1
        elif file_exists:
            status = "partial"
            status_icon = f"{NeonColors.NEON_YELLOW}⚠️{NeonColors.ENDC}"
            status_text = "File exists, not registered"
            results["implemented"] += 1
        else:
            status = "not_implemented"
            status_icon = f"{NeonColors.NEON_RED}❌{NeonColors.ENDC}"
            status_text = "Not implemented"
            results["not_implemented"] += 1

        # Print result
        print(f"  {status_icon} {tool_info['name']:20} {status_text:35} {file_msg if file_exists else reg_msg}")

        # Store details
        results["details"].append({
            "tool": tool_key,
            "name": tool_info["name"],
            "layer": layer,
            "status": status,
            "file_exists": file_exists,
            "registered": is_registered
        })

    return results


def get_layer_name(layer_num: int) -> str:
    """Get layer name by number"""
    layer_names = {
        1: "Static Analysis",
        2: "Dynamic Testing",
        3: "Symbolic Execution",
        4: "Formal Verification",
        5: "AI-Powered Analysis",
        6: "Policy Compliance",
        7: "Audit Readiness"
    }
    return layer_names.get(layer_num, "Unknown")


def print_summary(results: Dict):
    """Print verification summary"""
    print(f"\n{NeonColors.NEON_CYAN}{'='*70}{NeonColors.ENDC}")
    print(f"{NeonColors.BOLD}{NeonColors.NEON_PINK}VERIFICATION SUMMARY{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_CYAN}{'='*70}{NeonColors.ENDC}\n")

    total = results["total"]
    implemented = results["implemented"]
    registered = results["registered"]
    builtin = results["builtin_agents"]
    not_impl = results["not_implemented"]

    # Calculate coverage
    tools_needing_adapters = total - builtin  # 15 tools need adapters (17 - 2 builtin agents)
    adapter_coverage = (implemented / tools_needing_adapters * 100) if tools_needing_adapters > 0 else 0
    registration_coverage = (registered / tools_needing_adapters * 100) if tools_needing_adapters > 0 else 0

    print(f"{NeonColors.NEON_CYAN}Total Tools (README): {total}{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_CYAN}Built-in Agents: {builtin} (PolicyAgent, Layer7Agent){NeonColors.ENDC}")
    print(f"{NeonColors.NEON_CYAN}Tools Requiring Adapters: {tools_needing_adapters}{NeonColors.ENDC}")
    print()
    print(f"{NeonColors.NEON_GREEN}✅ Adapter Files Created: {implemented}/{tools_needing_adapters} ({adapter_coverage:.1f}%){NeonColors.ENDC}")
    print(f"{NeonColors.NEON_GREEN}✅ Adapters Registered: {registered}/{tools_needing_adapters} ({registration_coverage:.1f}%){NeonColors.ENDC}")
    print(f"{NeonColors.NEON_RED}❌ Not Implemented: {not_impl}/{tools_needing_adapters} ({not_impl/tools_needing_adapters*100:.1f}%){NeonColors.ENDC}")
    print()

    # Print implementation breakdown by layer
    print(f"{NeonColors.NEON_PURPLE}Implementation Status by Layer:{NeonColors.ENDC}\n")

    for layer in range(1, 8):
        layer_tools = [d for d in results["details"] if d["layer"] == layer]
        if not layer_tools:
            continue

        implemented_count = sum(1 for t in layer_tools if t["status"] in ["implemented", "builtin"])
        total_count = len(layer_tools)
        percentage = (implemented_count / total_count * 100) if total_count > 0 else 0

        status_icon = f"{NeonColors.NEON_GREEN}✅{NeonColors.ENDC}" if percentage == 100 else f"{NeonColors.NEON_YELLOW}⚠️{NeonColors.ENDC}"

        print(f"  {status_icon} Layer {layer} ({get_layer_name(layer)}): {implemented_count}/{total_count} ({percentage:.0f}%)")

    print()

    # Print next steps
    print(f"{NeonColors.NEON_CYAN}{'='*70}{NeonColors.ENDC}")
    print(f"{NeonColors.BOLD}{NeonColors.NEON_PINK}NEXT STEPS{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_CYAN}{'='*70}{NeonColors.ENDC}\n")

    missing_tools = [d for d in results["details"] if d["status"] == "not_implemented"]

    if missing_tools:
        print(f"{NeonColors.NEON_YELLOW}Missing Adapters (Priority Order):{NeonColors.ENDC}\n")

        # Group by layer
        for layer in range(1, 8):
            layer_missing = [t for t in missing_tools if t["layer"] == layer]
            if layer_missing:
                print(f"{NeonColors.NEON_PURPLE}Layer {layer} ({get_layer_name(layer)}):{NeonColors.ENDC}")
                for tool in layer_missing:
                    print(f"  - {tool['name']} ({tool['tool']})")
                print()
    else:
        print(f"{NeonColors.NEON_GREEN}🎉 All tools are implemented!{NeonColors.ENDC}\n")

    # DPGA compliance check
    print(f"{NeonColors.NEON_CYAN}{'='*70}{NeonColors.ENDC}")
    print(f"{NeonColors.BOLD}{NeonColors.NEON_PINK}DPGA COMPLIANCE{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_CYAN}{'='*70}{NeonColors.ENDC}\n")

    try:
        from src.adapters import register_all_adapters
        report = register_all_adapters()
        all_optional = all(a.get('optional', False) for a in report['adapters'])

        if all_optional:
            print(f"{NeonColors.NEON_GREEN}✅ DPGA Compliance: PASS (100%){NeonColors.ENDC}")
            print(f"{NeonColors.NEON_GREEN}   All {len(report['adapters'])} registered adapters are optional{NeonColors.ENDC}\n")
        else:
            non_optional = [a['name'] for a in report['adapters'] if not a.get('optional', False)]
            print(f"{NeonColors.NEON_RED}❌ DPGA Compliance: FAIL{NeonColors.ENDC}")
            print(f"{NeonColors.NEON_RED}   Non-optional adapters: {', '.join(non_optional)}{NeonColors.ENDC}\n")
    except Exception as e:
        print(f"{NeonColors.NEON_YELLOW}⚠️  DPGA Compliance: Unable to verify ({str(e)}){NeonColors.ENDC}\n")


def main():
    """Main verification routine"""
    print_banner()

    # Run verification
    results = verify_all_tools()

    # Print summary
    print_summary(results)

    # Exit code
    if results["not_implemented"] == 0:
        print(f"{NeonColors.NEON_GREEN}✅ All 17 tools are ready!{NeonColors.ENDC}\n")
        return 0
    else:
        print(f"{NeonColors.NEON_YELLOW}⚠️  {results['not_implemented']} tools still need implementation{NeonColors.ENDC}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
