#!/usr/bin/env python3
"""
MIESC Installation Verification Script

Verifies that all required tools and dependencies are properly installed.
Run this after cloning the repository and installing dependencies.

Usage:
    python scripts/verify_installation.py

Exit codes:
    0 - All checks passed
    1 - One or more checks failed
"""

import subprocess
import sys
import os
from pathlib import Path

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

class InstallationChecker:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.checks = []

    def print_header(self, text):
        print(f"\n{BOLD}{BLUE}{'='*70}{RESET}")
        print(f"{BOLD}{BLUE}{text:^70}{RESET}")
        print(f"{BOLD}{BLUE}{'='*70}{RESET}\n")

    def print_section(self, text):
        print(f"\n{BOLD}📋 {text}{RESET}")
        print(f"{'-'*70}")

    def check_command(self, name, command, description, required=True):
        """Check if a command-line tool is available"""
        print(f"  Checking {name}... ", end='', flush=True)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                shell=True
            )

            if result.returncode == 0 or "version" in result.stdout.lower() or "version" in result.stderr.lower():
                version = self._extract_version(result.stdout + result.stderr)
                print(f"{GREEN}✓ PASS{RESET} {version}")
                self.passed += 1
                self.checks.append({
                    'name': name,
                    'status': 'pass',
                    'description': description,
                    'version': version,
                    'required': required
                })
                return True
            else:
                raise Exception("Command failed")

        except Exception as e:
            if required:
                print(f"{RED}✗ FAIL{RESET} - {description}")
                self.failed += 1
                self.checks.append({
                    'name': name,
                    'status': 'fail',
                    'description': description,
                    'required': required
                })
            else:
                print(f"{YELLOW}⚠ WARN{RESET} - {description} (optional)")
                self.warnings += 1
                self.checks.append({
                    'name': name,
                    'status': 'warn',
                    'description': description,
                    'required': required
                })
            return False

    def check_python_package(self, package_name, import_name=None, description="", required=True):
        """Check if a Python package is installed"""
        if import_name is None:
            import_name = package_name

        print(f"  Checking {package_name}... ", end='', flush=True)
        try:
            exec(f"import {import_name}")
            module = sys.modules[import_name]
            version = getattr(module, '__version__', 'unknown')
            print(f"{GREEN}✓ PASS{RESET} v{version}")
            self.passed += 1
            self.checks.append({
                'name': package_name,
                'status': 'pass',
                'description': description,
                'version': f'v{version}',
                'required': required
            })
            return True
        except ImportError:
            if required:
                print(f"{RED}✗ FAIL{RESET} - {description}")
                self.failed += 1
                self.checks.append({
                    'name': package_name,
                    'status': 'fail',
                    'description': description,
                    'required': required
                })
            else:
                print(f"{YELLOW}⚠ WARN{RESET} - {description} (optional)")
                self.warnings += 1
                self.checks.append({
                    'name': package_name,
                    'status': 'warn',
                    'description': description,
                    'required': required
                })
            return False

    def check_file_exists(self, filepath, description, required=True):
        """Check if a file exists"""
        print(f"  Checking {filepath}... ", end='', flush=True)
        path = Path(filepath)
        if path.exists():
            print(f"{GREEN}✓ PASS{RESET}")
            self.passed += 1
            self.checks.append({
                'name': str(filepath),
                'status': 'pass',
                'description': description,
                'required': required
            })
            return True
        else:
            if required:
                print(f"{RED}✗ FAIL{RESET} - {description}")
                self.failed += 1
                self.checks.append({
                    'name': str(filepath),
                    'status': 'fail',
                    'description': description,
                    'required': required
                })
            else:
                print(f"{YELLOW}⚠ WARN{RESET} - {description} (optional)")
                self.warnings += 1
            return False

    def _extract_version(self, text):
        """Extract version number from command output"""
        import re
        # Common version patterns
        patterns = [
            r'version[:\s]+([0-9]+\.[0-9]+\.[0-9]+)',
            r'v?([0-9]+\.[0-9]+\.[0-9]+)',
            r'([0-9]+\.[0-9]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return f"v{match.group(1)}"
        return ""

    def print_summary(self):
        """Print summary of all checks"""
        self.print_header("VERIFICATION SUMMARY")

        total = self.passed + self.failed + self.warnings

        print(f"\n{BOLD}Results:{RESET}")
        print(f"  {GREEN}✓ Passed:{RESET}   {self.passed}/{total}")
        print(f"  {RED}✗ Failed:{RESET}   {self.failed}/{total}")
        print(f"  {YELLOW}⚠ Warnings:{RESET} {self.warnings}/{total}")

        if self.failed > 0:
            print(f"\n{BOLD}{RED}INSTALLATION INCOMPLETE{RESET}")
            print(f"\n{BOLD}Failed checks:{RESET}")
            for check in self.checks:
                if check['status'] == 'fail':
                    print(f"  {RED}✗{RESET} {check['name']}: {check['description']}")

            print(f"\n{BOLD}Installation instructions:{RESET}")
            print("  See README.md for detailed setup instructions")
            print("  Run: pip install -r requirements_core.txt")
            print("  For optional tools, see: docs/INSTALLATION.md")

            return False
        elif self.warnings > 0:
            print(f"\n{BOLD}{YELLOW}INSTALLATION COMPLETE WITH WARNINGS{RESET}")
            print(f"\nOptional tools not installed:")
            for check in self.checks:
                if check['status'] == 'warn':
                    print(f"  {YELLOW}⚠{RESET} {check['name']}: {check['description']}")
            return True
        else:
            print(f"\n{BOLD}{GREEN}✓ INSTALLATION COMPLETE{RESET}")
            print(f"\nAll required and optional tools are properly installed!")
            return True


def main():
    checker = InstallationChecker()

    checker.print_header("MIESC INSTALLATION VERIFICATION")
    print("Checking all dependencies for MIESC v2.2...\n")

    # 1. Core Python Environment
    checker.print_section("Core Python Environment")
    checker.check_command(
        "Python",
        "python3 --version",
        "Python 3.9+ required",
        required=True
    )
    checker.check_command(
        "pip",
        "pip3 --version",
        "pip package manager",
        required=True
    )

    # 2. Core Python Packages
    checker.print_section("Core Python Packages")
    core_packages = [
        ("python-dotenv", "dotenv", "Environment configuration"),
        ("openai", "openai", "OpenAI API client"),
        ("torch", "torch", "PyTorch for ML models"),
        ("transformers", "transformers", "HuggingFace transformers"),
        ("langchain", "langchain", "LangChain framework"),
        ("tiktoken", "tiktoken", "OpenAI tokenizer"),
    ]

    for pkg, import_name, desc in core_packages:
        checker.check_python_package(pkg, import_name, desc, required=True)

    # 3. Layer 1: Static Analysis Tools
    checker.print_section("Layer 1: Static Analysis Tools")
    checker.check_command(
        "Slither",
        "slither --version",
        "Static analysis framework (Trail of Bits)",
        required=True
    )
    checker.check_command(
        "Aderyn",
        "aderyn --version",
        "Ultra-fast Rust-based analyzer (Cyfrin)",
        required=False
    )
    checker.check_command(
        "Solhint",
        "solhint --version",
        "Solidity linter",
        required=False
    )

    # 4. Layer 2: Dynamic Testing Tools
    checker.print_section("Layer 2: Dynamic Testing Tools")
    checker.check_command(
        "Echidna",
        "echidna --version",
        "Property-based fuzzer (Trail of Bits)",
        required=False
    )
    checker.check_command(
        "Medusa",
        "medusa version",
        "Coverage-guided fuzzer (Crytic)",
        required=False
    )
    checker.check_command(
        "Foundry",
        "forge --version",
        "Testing framework (Paradigm)",
        required=False
    )

    # 5. Layer 3: Symbolic Execution Tools
    checker.print_section("Layer 3: Symbolic Execution Tools")
    checker.check_python_package(
        "mythril",
        "mythril",
        "Symbolic execution engine",
        required=False
    )
    checker.check_python_package(
        "manticore",
        "manticore",
        "Dynamic symbolic execution",
        required=False
    )
    checker.check_command(
        "Halmos",
        "halmos --version",
        "Symbolic testing for Foundry (a16z)",
        required=False
    )

    # 6. Layer 4: Formal Verification Tools
    checker.print_section("Layer 4: Formal Verification Tools")
    checker.check_command(
        "Certora",
        "certoraRun --version",
        "Formal verification (Certora)",
        required=False
    )
    checker.check_command(
        "SMTChecker",
        "solc --version",
        "Built-in Solidity formal verification",
        required=False
    )
    checker.check_command(
        "Wake",
        "wake --version",
        "Python-based verification (Ackee)",
        required=False
    )

    # 7. Node.js Environment (for some tools)
    checker.print_section("Node.js Environment")
    checker.check_command(
        "Node.js",
        "node --version",
        "JavaScript runtime (for Solhint, Surya)",
        required=False
    )
    checker.check_command(
        "npm",
        "npm --version",
        "Node package manager",
        required=False
    )

    # 8. Git and Version Control
    checker.print_section("Version Control")
    checker.check_command(
        "Git",
        "git --version",
        "Version control system",
        required=True
    )

    # 9. Required Files
    checker.print_section("Required Files")
    required_files = [
        ("requirements_core.txt", "Core Python dependencies"),
        ("README.md", "Project documentation"),
        ("REFERENCES.md", "Scientific references"),
        ("COMPLIANCE.md", "Standards compliance mapping"),
        ("CONTRIBUTING.md", "Contribution guidelines"),
        ("src/agents/policy_agent.py", "PolicyAgent v2.2"),
        ("scripts/run_regression_tests.py", "Regression test suite"),
        ("tests/regression_results.json", "Latest test results"),
    ]

    for filepath, desc in required_files:
        checker.check_file_exists(filepath, desc, required=True)

    # 10. Optional Files and Directories
    checker.print_section("Optional Components")
    optional_paths = [
        ("examples/", "Example vulnerable contracts"),
        ("thesis/", "Thesis materials"),
        ("docs/", "Technical documentation"),
        ("standards/", "Compliance standards"),
    ]

    for filepath, desc in optional_paths:
        checker.check_file_exists(filepath, desc, required=False)

    # Print summary
    success = checker.print_summary()

    if not success and checker.failed > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
