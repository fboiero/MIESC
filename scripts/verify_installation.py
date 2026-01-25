#!/usr/bin/env python3
"""
MIESC v4.3.0 - Installation Verification Script

This script verifies that MIESC is properly installed and all tools are available.
Run after installation to confirm everything is working.

Usage:
    python scripts/verify_installation.py

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_header(title: str):
    """Print a formatted header."""
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}\n")


def print_section(title: str):
    """Print a formatted section."""
    print(f"\n{BOLD}{title}{RESET}")
    print("-" * 40)


def check_ok(message: str):
    """Print success message."""
    print(f"  {GREEN}[OK]{RESET} {message}")


def check_fail(message: str):
    """Print failure message."""
    print(f"  {RED}[FAIL]{RESET} {message}")


def check_warn(message: str):
    """Print warning message."""
    print(f"  {YELLOW}[WARN]{RESET} {message}")


def check_python_version() -> bool:
    """Check Python version is 3.12+."""
    version = sys.version_info
    if version >= (3, 12):
        check_ok(f"Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        check_fail(f"Python {version.major}.{version.minor} (requires 3.12+)")
        return False


def check_command(cmd: str, version_flag: str = "--version") -> Tuple[bool, str]:
    """Check if a command is available."""
    try:
        result = subprocess.run(
            [cmd, version_flag],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            version = result.stdout.strip().split("\n")[0][:50]
            return True, version
        return False, "not available"
    except FileNotFoundError:
        return False, "not installed"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


def check_python_package(package: str) -> Tuple[bool, str]:
    """Check if a Python package is installed."""
    try:
        result = subprocess.run(
            [sys.executable, "-c", f"import {package}; print({package}.__version__ if hasattr({package}, '__version__') else 'installed')"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            return True, version
        return False, "import failed"
    except Exception as e:
        return False, str(e)


def check_ollama_models() -> List[str]:
    """Check which Ollama models are available."""
    available_models = []
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")[1:]  # Skip header
            for line in lines:
                if line.strip():
                    model = line.split()[0]
                    available_models.append(model)
    except Exception:
        pass
    return available_models


def verify_miesc_adapters() -> Dict[str, Any]:
    """Verify MIESC adapter registration."""
    try:
        # Add project root to path
        project_root = Path(__file__).parent.parent
        sys.path.insert(0, str(project_root))

        from src.adapters import register_all_adapters

        report = register_all_adapters()
        return report
    except Exception as e:
        return {"error": str(e), "registered": 0, "total_adapters": 0}


def run_quick_test(contract_path: str) -> Dict[str, Any]:
    """Run a quick analysis test."""
    try:
        project_root = Path(__file__).parent.parent
        sys.path.insert(0, str(project_root))

        from src.adapters.slither_adapter import SlitherAdapter

        adapter = SlitherAdapter()
        if adapter.is_available().value == "available":
            result = adapter.analyze(contract_path)
            return {
                "success": result.get("success", False),
                "findings": len(result.get("findings", [])),
                "tool": "slither",
            }
        return {"success": False, "error": "Slither not available"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def main():
    """Main verification function."""
    print_header("MIESC v4.3.0 - Installation Verification")

    results = {
        "timestamp": datetime.now().isoformat(),
        "python_ok": False,
        "core_deps_ok": False,
        "tools_available": 0,
        "tools_total": 31,
        "issues": [],
    }

    # 1. Check Python version
    print_section("1. Python Environment")
    results["python_ok"] = check_python_version()

    # 2. Check core Python dependencies
    print_section("2. Core Python Dependencies")
    core_packages = [
        ("slither_analyzer", "slither-analyzer"),
        ("fastapi", "fastapi"),
        ("pydantic", "pydantic"),
        ("click", "click"),
        ("streamlit", "streamlit"),
        ("flask", "flask"),
    ]

    all_core_ok = True
    for package, pip_name in core_packages:
        ok, version = check_python_package(package)
        if ok:
            check_ok(f"{pip_name} ({version})")
        else:
            check_fail(f"{pip_name} - install with: pip install {pip_name}")
            all_core_ok = False
            results["issues"].append(f"Missing package: {pip_name}")

    results["core_deps_ok"] = all_core_ok

    # 3. Check external tools
    print_section("3. External Tools (Optional)")
    external_tools = [
        ("solc", "--version"),
        ("aderyn", "--version"),
        ("solhint", "--version"),
        ("myth", "version"),
        ("echidna", "--version"),
        ("medusa", "--version"),
        ("forge", "--version"),
        ("halmos", "--version"),
        ("certoraRun", "--version"),
        ("circomspect", "--help"),
    ]

    for tool, flag in external_tools:
        ok, version = check_command(tool, flag)
        if ok:
            check_ok(f"{tool} ({version[:30]}...)" if len(version) > 30 else f"{tool} ({version})")
        else:
            check_warn(f"{tool} - not installed (optional)")

    # 4. Check Ollama and models
    print_section("4. Ollama (AI Features)")
    ollama_ok, ollama_version = check_command("ollama", "--version")
    if ollama_ok:
        check_ok(f"Ollama ({ollama_version})")

        models = check_ollama_models()
        recommended_models = ["deepseek-coder", "codellama", "deepseek-coder:6.7b"]

        for model in recommended_models:
            if any(model in m for m in models):
                check_ok(f"Model: {model}")
            else:
                check_warn(f"Model: {model} - pull with: ollama pull {model}")
    else:
        check_warn("Ollama not installed - AI features will be limited")
        check_warn("Install from: https://ollama.ai")

    # 5. Verify MIESC adapters
    print_section("5. MIESC Adapter Registration")
    adapter_report = verify_miesc_adapters()

    if "error" in adapter_report:
        check_fail(f"Adapter registration failed: {adapter_report['error']}")
        results["issues"].append(f"Adapter error: {adapter_report['error']}")
    else:
        registered = adapter_report.get("registered", 0)
        total = adapter_report.get("total_adapters", 0)
        failed = adapter_report.get("failed", 0)

        results["tools_available"] = registered
        results["tools_total"] = total

        if registered == total:
            check_ok(f"All {registered}/{total} adapters registered")
        else:
            check_warn(f"{registered}/{total} adapters registered ({failed} failed)")

        # Count available tools
        available_count = 0
        adapters = adapter_report.get("adapters", [])
        for adapter in adapters:
            if adapter.get("status") == "available":
                available_count += 1

        if available_count > 0:
            check_ok(f"{available_count} tools currently available")

    # 6. Quick functionality test
    print_section("6. Quick Functionality Test")

    # Find a test contract
    project_root = Path(__file__).parent.parent
    test_contracts = list(project_root.glob("examples/contracts/*.sol"))

    if test_contracts:
        contract = test_contracts[0]
        check_ok(f"Test contract found: {contract.name}")

        test_result = run_quick_test(str(contract))
        if test_result.get("success"):
            check_ok(f"Analysis test passed ({test_result.get('findings', 0)} findings)")
        else:
            error = test_result.get("error", "Unknown error")
            check_warn(f"Analysis test: {error}")
    else:
        check_warn("No test contracts found in examples/contracts/")

    # Summary
    print_header("Installation Summary")

    if results["python_ok"] and results["core_deps_ok"]:
        print(f"{GREEN}MIESC is ready to use!{RESET}\n")
        print("Quick start commands:")
        print(f"  {BLUE}miesc doctor{RESET}              # Check tool status")
        print(f"  {BLUE}miesc audit quick contract.sol{RESET}  # Quick analysis")
        print(f"  {BLUE}miesc audit full contract.sol{RESET}   # Full 9-layer audit")
    else:
        print(f"{YELLOW}MIESC installation has issues:{RESET}\n")
        for issue in results["issues"]:
            print(f"  - {issue}")
        print(f"\nRun {BLUE}pip install -e .[full]{RESET} to install all dependencies.")

    print(f"\nTools available: {results['tools_available']}/{results['tools_total']}")
    print(f"Timestamp: {results['timestamp']}")

    # Save report
    report_path = project_root / "validation_results" / "installation_check.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nReport saved to: {report_path}")

    return 0 if (results["python_ok"] and results["core_deps_ok"]) else 1


if __name__ == "__main__":
    sys.exit(main())
