#!/usr/bin/env python3
"""
MIESC Adapter Diagnostic Tool
Verifies availability of all 50 security tool adapters using their internal is_available() methods.

Usage:
    python scripts/diagnose-adapters.py
    # or inside Docker:
    docker run --rm -e OLLAMA_HOST=http://host.docker.internal:11434 ghcr.io/fboiero/miesc:full python /app/scripts/diagnose-adapters.py
"""

import sys
import os
import json
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Now import MIESC modules
try:
    from src.adapters import (
        get_adapter_status_report,
        get_available_adapters,
        register_all_adapters,
    )
    from src.core.tool_protocol import ToolStatus
except ImportError as e:
    print(f"Error importing MIESC modules: {e}")
    print("Make sure you're running from the MIESC project directory")
    sys.exit(1)


# ANSI color codes
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color


# Layer mapping for display
LAYER_MAP = {
    'static_analysis': ('Layer 1', 'Static Analysis'),
    'dynamic_testing': ('Layer 2', 'Dynamic Testing / Fuzzing'),
    'symbolic_execution': ('Layer 3', 'Symbolic Execution'),
    'formal_verification': ('Layer 4', 'Formal Verification'),
    'ai_analysis': ('Layer 5', 'AI Analysis'),
    'ml_detection': ('Layer 6', 'ML Detection'),
    'specialized': ('Layer 7', 'Specialized Analysis'),
    'crosschain_zk': ('Layer 8', 'Cross-Chain & ZK'),
    'advanced_ensemble': ('Layer 9', 'Advanced AI Ensemble'),
}


def status_color(status: ToolStatus) -> str:
    """Get color for status."""
    if status == ToolStatus.AVAILABLE:
        return Colors.GREEN
    elif status == ToolStatus.NOT_INSTALLED:
        return Colors.RED
    elif status == ToolStatus.CONFIGURATION_ERROR:
        return Colors.YELLOW
    elif status == ToolStatus.LICENSE_REQUIRED:
        return Colors.YELLOW
    else:
        return Colors.NC


def status_label(status: ToolStatus) -> str:
    """Get label for status."""
    labels = {
        ToolStatus.AVAILABLE: "[PASS]",
        ToolStatus.NOT_INSTALLED: "[FAIL]",
        ToolStatus.CONFIGURATION_ERROR: "[CONF]",
        ToolStatus.LICENSE_REQUIRED: "[KEY ]",
        ToolStatus.DEPRECATED: "[DEPR]",
    }
    return labels.get(status, "[????]")


def print_header():
    """Print diagnostic header."""
    print("=" * 70)
    print("MIESC Adapter Diagnostic Tool v5.1.0")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"OLLAMA_HOST: {os.environ.get('OLLAMA_HOST', 'not set')}")
    print("=" * 70)
    print()


def init_adapters():
    """Initialize all adapters."""
    print("Registering adapters...")
    try:
        result = register_all_adapters()
        print(f"Registered {result.get('total', 0)} adapters")
        print()
        return result
    except Exception as e:
        print(f"{Colors.YELLOW}Warning during adapter registration: {e}{Colors.NC}")
        return {}


def diagnose_all_adapters():
    """Run diagnostics on all adapters."""
    print_header()

    # First register all adapters
    init_adapters()

    # Get status report from the adapter registry
    try:
        status_report = get_adapter_status_report()
    except Exception as e:
        print(f"{Colors.RED}Error getting adapter status: {e}{Colors.NC}")
        sys.exit(1)

    # Organize by layer
    by_layer = {}
    for adapter_info in status_report.get('adapters', []):
        layer = adapter_info.get('layer', 'unknown')
        if layer not in by_layer:
            by_layer[layer] = []
        by_layer[layer].append(adapter_info)

    # Statistics
    total = 0
    passed = 0
    failed = 0
    config_error = 0
    license_required = 0
    deprecated = 0

    failed_list = []
    config_list = []
    license_list = []

    # Print by layer
    for layer_key, (layer_num, layer_name) in LAYER_MAP.items():
        adapters = by_layer.get(layer_key, [])
        if not adapters:
            continue

        print(f"=== {layer_num}: {layer_name} ({len(adapters)} tools) ===")

        for adapter in sorted(adapters, key=lambda x: x.get('name', '')):
            total += 1
            name = adapter.get('name', 'unknown')
            status_str = adapter.get('status', 'unknown')
            version = adapter.get('version', '')
            error = adapter.get('error', '')

            # Convert status string to enum
            try:
                status = ToolStatus[status_str.upper()] if isinstance(status_str, str) else status_str
            except (KeyError, AttributeError):
                status = ToolStatus.NOT_INSTALLED

            # Count statistics
            if status == ToolStatus.AVAILABLE:
                passed += 1
            elif status == ToolStatus.NOT_INSTALLED:
                failed += 1
                failed_list.append((name, layer_num, error))
            elif status == ToolStatus.CONFIGURATION_ERROR:
                config_error += 1
                config_list.append((name, layer_num, error))
            elif status == ToolStatus.LICENSE_REQUIRED:
                license_required += 1
                license_list.append((name, layer_num, error))
            elif status == ToolStatus.DEPRECATED:
                deprecated += 1

            # Print status
            color = status_color(status)
            label = status_label(status)
            version_str = f" - {version}" if version else ""
            error_str = f" ({error})" if error and status != ToolStatus.AVAILABLE else ""
            print(f"{color}{label}{Colors.NC} {name}{version_str}{error_str}")

        print()

    # Handle unknown layers
    unknown_adapters = []
    for layer_key, adapters in by_layer.items():
        if layer_key not in LAYER_MAP and layer_key != 'unknown':
            unknown_adapters.extend(adapters)

    if unknown_adapters or 'unknown' in by_layer:
        print("=== Uncategorized Tools ===")
        all_unknown = unknown_adapters + by_layer.get('unknown', [])
        for adapter in all_unknown:
            total += 1
            name = adapter.get('name', 'unknown')
            status_str = adapter.get('status', 'unknown')
            print(f"  {name}: {status_str}")
        print()

    # Summary
    print("=" * 70)
    print("DIAGNOSTIC SUMMARY")
    print("=" * 70)
    print()
    print(f"Total adapters checked:  {total}")
    print(f"{Colors.GREEN}Available:               {passed}{Colors.NC}")
    print(f"{Colors.RED}Not installed:           {failed}{Colors.NC}")
    print(f"{Colors.YELLOW}Configuration error:     {config_error}{Colors.NC}")
    print(f"{Colors.YELLOW}License required:        {license_required}{Colors.NC}")
    print(f"Deprecated:              {deprecated}")
    print()

    if total > 0:
        pass_rate = (passed / total) * 100
        print(f"Pass rate: {pass_rate:.1f}%")
        print()

    # Failed tools details
    if failed_list:
        print(f"{Colors.RED}=== FAILED TOOLS (Not Installed) ==={Colors.NC}")
        for name, layer, error in failed_list:
            error_info = f" - {error}" if error else ""
            print(f"  {layer}: {name}{error_info}")
        print()

    # Config errors
    if config_list:
        print(f"{Colors.YELLOW}=== CONFIGURATION ERRORS ==={Colors.NC}")
        for name, layer, error in config_list:
            error_info = f" - {error}" if error else ""
            print(f"  {layer}: {name}{error_info}")
        print()

    # License required
    if license_list:
        print(f"{Colors.YELLOW}=== LICENSE/API KEY REQUIRED ==={Colors.NC}")
        for name, layer, error in license_list:
            error_info = f" - {error}" if error else ""
            print(f"  {layer}: {name}{error_info}")
        print()

    # Recommendations
    print("=" * 70)
    print("RECOMMENDATIONS")
    print("=" * 70)
    print()

    # Check for common issues
    failed_names = [f[0] for f in failed_list]

    if 'mythril' in failed_names:
        print("Mythril:")
        print("  pip install mythril")
        print("  Note: May fail on ARM/Apple Silicon")
        print()

    if 'manticore' in failed_names:
        print("Manticore:")
        print("  pip install 'protobuf<4.0.0' manticore[native]")
        print("  Note: Incompatible with Python 3.12 on some platforms")
        print()

    if 'halmos' in failed_names:
        print("Halmos (Recommended for symbolic execution):")
        print("  pip install halmos")
        print("  Note: Compiles z3-solver natively, works on ARM")
        print()

    if 'echidna' in failed_names:
        print("Echidna:")
        print("  # Install from: https://github.com/crytic/echidna/releases")
        print()

    if 'medusa' in failed_names:
        print("Medusa:")
        print("  # Install from: https://github.com/crytic/medusa/releases")
        print()

    # Check for Ollama-dependent tools
    ollama_tools = ['smartllm', 'gptscan', 'llmsmartaudit', 'gptlens',
                   'llamaaudit', 'iaudit', 'llmbugscanner', 'audit_consensus']
    ollama_failed = [t for t in ollama_tools if t in failed_names]

    if ollama_failed:
        print("Ollama-dependent tools failed. Ensure Ollama is running:")
        print("  # On macOS with Docker:")
        print("  export OLLAMA_HOST=http://host.docker.internal:11434")
        print()
        print("  # On Linux with Docker:")
        print("  export OLLAMA_HOST=http://172.17.0.1:11434")
        print()

    # Export JSON report
    report = {
        'timestamp': datetime.now().isoformat(),
        'version': '5.1.0',
        'summary': {
            'total': total,
            'available': passed,
            'not_installed': failed,
            'config_error': config_error,
            'license_required': license_required,
            'deprecated': deprecated,
            'pass_rate': f"{pass_rate:.1f}%" if total > 0 else "N/A"
        },
        'failed': [{'name': n, 'layer': l, 'error': e} for n, l, e in failed_list],
        'config_errors': [{'name': n, 'layer': l, 'error': e} for n, l, e in config_list],
        'license_required': [{'name': n, 'layer': l, 'error': e} for n, l, e in license_list],
        'ollama_host': os.environ.get('OLLAMA_HOST', 'not set'),
    }

    # Save JSON report
    report_path = project_root / 'diagnostic-report.json'
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"JSON report saved to: {report_path}")
    print()

    return failed


if __name__ == '__main__':
    try:
        failed_count = diagnose_all_adapters()
        sys.exit(1 if failed_count > 0 else 0)
    except KeyboardInterrupt:
        print("\nDiagnostic interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}Diagnostic failed: {e}{Colors.NC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
