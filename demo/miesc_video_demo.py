#!/usr/bin/env python3
"""
MIESC v4.2.2 - Visual Demo for Video Recording
Showcases the complete MIESC pipeline for developers and security researchers

This demo is designed to be recorded for promotional/educational videos.
It demonstrates:
1. Rich CLI interface with animations
2. Multi-layer security analysis
3. Real-time progress visualization
4. Professional audit report generation (HTML/PDF)

Run with:
    source venv314/bin/activate && python demo/miesc_video_demo.py

For slower video recording:
    python demo/miesc_video_demo.py --speed 0.3

Requirements:
    pip install rich webbrowser

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
"""

import hashlib
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Rich imports for beautiful CLI
try:
    from rich import box
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
except ImportError:
    print("Installing rich for beautiful CLI output...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "-q"])
    from rich import box
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.tree import Tree

console = Console()

# Demo configuration - SLOWER for video recording
DEMO_CONFIG = {
    "speed": 0.4,  # Animation speed multiplier (lower = slower, 0.4 is good for video)
    "pause_between_sections": 4.0,  # Pause between sections (4 seconds)
    "pause_short": 2.0,  # Short pause
    "progress_step_delay": 0.06,  # Delay per progress step
}

# Sample vulnerable contract for demo
SAMPLE_CONTRACT = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    // Vulnerability 1: Reentrancy
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");

        // External call BEFORE state update - VULNERABLE!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;  // State update after call
    }

    // Vulnerability 2: Integer overflow (pre-0.8)
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerability 3: Missing access control
    function setBalance(address user, uint256 amount) external {
        balances[user] = amount;  // Anyone can call this!
    }

    // Vulnerability 4: Timestamp dependence
    function timeLock() external view returns (bool) {
        return block.timestamp > 1700000000;  // Manipulable
    }
}
'''

# Simulated findings for demo
DEMO_FINDINGS = [
    {
        "id": "MIESC-001",
        "title": "Reentrancy Vulnerability in withdraw()",
        "severity": "Critical",
        "tool": "Slither",
        "layer": 1,
        "swc": "SWC-107",
        "cwe": "CWE-841",
        "location": "VulnerableVault.sol:10-17",
        "description": "External call before state update allows reentrant calls. An attacker can recursively call withdraw() before the balance is updated.",
        "remediation": "Apply the Checks-Effects-Interactions pattern. Update state variables before making external calls.",
    },
    {
        "id": "MIESC-002",
        "title": "Unrestricted setBalance() Function",
        "severity": "Critical",
        "tool": "Slither",
        "layer": 1,
        "swc": "SWC-105",
        "cwe": "CWE-284",
        "location": "VulnerableVault.sol:24-26",
        "description": "Missing access control allows any address to modify user balances arbitrarily.",
        "remediation": "Add onlyOwner modifier or implement role-based access control (RBAC).",
    },
    {
        "id": "MIESC-003",
        "title": "Reentrancy Attack Path Confirmed",
        "severity": "High",
        "tool": "Mythril",
        "layer": 3,
        "swc": "SWC-107",
        "location": "VulnerableVault.sol:12",
        "description": "Symbolic execution confirmed exploitable reentrancy path with concrete attack transaction.",
        "remediation": "Use ReentrancyGuard from OpenZeppelin or apply CEI pattern.",
    },
    {
        "id": "MIESC-004",
        "title": "Block Timestamp Dependence",
        "severity": "Medium",
        "tool": "SmartBugsDetector",
        "layer": 2,
        "swc": "SWC-116",
        "location": "VulnerableVault.sol:29",
        "description": "Timestamp can be manipulated by miners within a ~15 second window.",
        "remediation": "Avoid using block.timestamp for critical logic. Use block.number instead.",
    },
    {
        "id": "MIESC-005",
        "title": "Missing Zero Address Validation",
        "severity": "Low",
        "tool": "Aderyn",
        "layer": 1,
        "swc": "SWC-123",
        "location": "VulnerableVault.sol:24",
        "description": "setBalance() does not validate that the user address is not zero.",
        "remediation": "Add require(user != address(0), 'Invalid address') check.",
    },
]

# Layer definitions
LAYERS = {
    1: {"name": "Static Analysis", "tools": ["Slither", "Aderyn", "Solhint"], "color": "blue"},
    2: {"name": "Pattern Detection", "tools": ["SmartBugsDetector"], "color": "purple"},
    3: {"name": "Symbolic Execution", "tools": ["Mythril", "Manticore"], "color": "magenta"},
    4: {"name": "Fuzzing", "tools": ["Echidna", "Medusa", "DogeFuzz"], "color": "yellow"},
    5: {"name": "Formal Verification", "tools": ["Certora", "Halmos", "SMTChecker"], "color": "green"},
    6: {"name": "ML Detection", "tools": ["DA-GNN", "SmartGuard"], "color": "cyan"},
    7: {"name": "AI Analysis", "tools": ["SmartLLM", "PropertyGPT"], "color": "bright_blue"},
    8: {"name": "DeFi Security", "tools": ["DeFiDetector", "MEVAnalyzer"], "color": "red"},
    9: {"name": "Dependency Scan", "tools": ["DepScanner", "CVEChecker"], "color": "bright_green"},
}


def sleep(seconds: float):
    """Sleep with speed multiplier"""
    time.sleep(seconds * DEMO_CONFIG["speed"])


def pause():
    """Pause between sections"""
    time.sleep(DEMO_CONFIG["pause_between_sections"] * DEMO_CONFIG["speed"])


def short_pause():
    """Short pause"""
    time.sleep(DEMO_CONFIG["pause_short"] * DEMO_CONFIG["speed"])


def print_banner():
    """Display MIESC banner"""
    banner = """
[bold blue]
    ███╗   ███╗██╗███████╗███████╗ ██████╗
    ████╗ ████║██║██╔════╝██╔════╝██╔════╝
    ██╔████╔██║██║█████╗  ███████╗██║
    ██║╚██╔╝██║██║██╔══╝  ╚════██║██║
    ██║ ╚═╝ ██║██║███████╗███████║╚██████╗
    ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝
[/bold blue]
[bold white]Multi-layer Intelligent Evaluation for Smart Contracts[/bold white]
[dim]Version 4.2.1 | Defense-in-Depth Security Analysis[/dim]
"""
    console.print(Panel(banner, border_style="blue", box=box.DOUBLE))


def section_header(title: str, subtitle: str = ""):
    """Print section header with pause"""
    console.print()
    console.print(Panel(
        f"[bold white]{title}[/bold white]\n[dim]{subtitle}[/dim]" if subtitle else f"[bold white]{title}[/bold white]",
        border_style="cyan",
        box=box.ROUNDED
    ))
    short_pause()


def demo_intro():
    """Introduction section"""
    print_banner()
    pause()

    intro = """
## What is MIESC?

MIESC is a **Defense-in-Depth** security framework for smart contracts that combines:

- **25+ Security Tools** across 9 specialized layers
- **AI-Powered Analysis** with LLM integration
- **Scientific Validation** (84.3% recall on SmartBugs benchmark)
- **Professional Audit Reports** in HTML/PDF format

### Target Audience

- **Developers**: Catch vulnerabilities before deployment
- **Security Researchers**: Accelerate manual audits
- **Audit Firms**: Generate comprehensive reports
"""
    console.print(Markdown(intro))
    pause()


def demo_architecture():
    """Show architecture visualization"""
    section_header("Defense-in-Depth Architecture", "9 Specialized Security Layers with 25+ Tools")

    tree = Tree("[bold blue]MIESC Security Layers[/bold blue]")

    for layer_num, layer_info in LAYERS.items():
        layer_node = tree.add(f"[bold {layer_info['color']}]Layer {layer_num}: {layer_info['name']}[/bold {layer_info['color']}]")
        for tool in layer_info['tools']:
            layer_node.add(f"[dim]• {tool}[/dim]")
        sleep(0.3)  # Animate tree building

    console.print(tree)
    pause()


def demo_contract_input():
    """Show contract being analyzed"""
    section_header("Input: Smart Contract", "VulnerableVault.sol - Demo Contract with Known Vulnerabilities")

    syntax = Syntax(SAMPLE_CONTRACT, "solidity", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title="[bold red]VulnerableVault.sol[/bold red]", border_style="red"))
    pause()


def demo_analysis_progress():
    """Show multi-layer analysis with progress bars"""
    section_header("Multi-Layer Security Analysis", "Running 9-layer Defense-in-Depth scan...")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:

        # Add tasks for each layer
        layer_tasks = {}
        for layer_num, layer_info in LAYERS.items():
            task_id = progress.add_task(
                f"[{layer_info['color']}]Layer {layer_num}: {layer_info['name']}[/{layer_info['color']}]",
                total=100
            )
            layer_tasks[layer_num] = task_id

        # Simulate analysis progress - SLOWER
        for i in range(101):
            for layer_num in range(1, 10):
                # Stagger the progress
                layer_progress = max(0, min(100, i - (layer_num - 1) * 8))
                progress.update(layer_tasks[layer_num], completed=layer_progress)
            time.sleep(DEMO_CONFIG["progress_step_delay"])

    console.print()
    console.print("[bold green]✓ Analysis complete! 5 vulnerabilities detected across 3 layers.[/bold green]")
    pause()


def demo_findings_display():
    """Display findings in a beautiful table"""
    section_header("Security Findings Summary", f"{len(DEMO_FINDINGS)} vulnerabilities detected")

    # Summary by severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in DEMO_FINDINGS:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    summary_table = Table(title="Severity Distribution", box=box.ROUNDED)
    summary_table.add_column("Severity", style="bold", width=12)
    summary_table.add_column("Count", justify="center", width=8)
    summary_table.add_column("Risk Level", justify="center", width=20)

    summary_table.add_row("Critical", str(severity_counts["Critical"]), "[bold red]██████████████[/bold red]")
    summary_table.add_row("High", str(severity_counts["High"]), "[bold orange1]██████████[/bold orange1]")
    summary_table.add_row("Medium", str(severity_counts["Medium"]), "[bold yellow]██████[/bold yellow]")
    summary_table.add_row("Low", str(severity_counts["Low"]), "[bold green]███[/bold green]")

    console.print(summary_table)
    short_pause()

    # Detailed findings
    console.print()
    findings_table = Table(title="Detailed Vulnerability Findings", box=box.ROUNDED, show_lines=True)
    findings_table.add_column("ID", style="cyan", width=12)
    findings_table.add_column("Severity", width=10)
    findings_table.add_column("Title", width=38)
    findings_table.add_column("Tool", width=18)
    findings_table.add_column("Layer", width=8, justify="center")
    findings_table.add_column("SWC", width=10)

    severity_styles = {
        "Critical": "[bold red]Critical[/bold red]",
        "High": "[bold orange1]High[/bold orange1]",
        "Medium": "[bold yellow]Medium[/bold yellow]",
        "Low": "[bold green]Low[/bold green]",
    }

    for f in DEMO_FINDINGS:
        findings_table.add_row(
            f["id"],
            severity_styles.get(f["severity"], f["severity"]),
            f["title"],
            f["tool"],
            str(f["layer"]),
            f.get("swc", "-"),
        )

    console.print(findings_table)
    pause()


def demo_finding_detail():
    """Show detailed view of a critical finding"""
    section_header("Critical Finding Detail", "MIESC-001: Reentrancy Vulnerability")

    finding = DEMO_FINDINGS[0]  # Reentrancy finding

    detail = f"""
## {finding['title']}

**Severity:** [bold red]{finding['severity']}[/bold red]
**Tool:** {finding['tool']} (Layer {finding['layer']})
**Location:** `{finding['location']}`
**SWC ID:** {finding.get('swc', 'N/A')} | **CWE ID:** {finding.get('cwe', 'N/A')}

### Description
{finding['description']}

### Vulnerable Code
```solidity
function withdraw(uint256 amount) external {{
    require(balances[msg.sender] >= amount, "Insufficient");

    // VULNERABLE: External call before state update
    (bool success, ) = msg.sender.call{{value: amount}}("");
    require(success, "Transfer failed");

    balances[msg.sender] -= amount;  // Too late!
}}
```

### Remediation
{finding['remediation']}

### Fixed Code
```solidity
function withdraw(uint256 amount) external nonReentrant {{
    require(balances[msg.sender] >= amount, "Insufficient");

    // FIXED: Update state BEFORE external call
    balances[msg.sender] -= amount;

    (bool success, ) = msg.sender.call{{value: amount}}("");
    require(success, "Transfer failed");
}}
```
"""
    console.print(Markdown(detail))
    pause()


def demo_report_generation():
    """Demonstrate report generation"""
    section_header("Professional Audit Report Generation", "Creating HTML & PDF reports with full evidence...")

    with console.status("[bold green]Generating comprehensive audit report...", spinner="dots"):
        sleep(3)

    # Show report preview
    report_preview = """
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY AUDIT REPORT                         │
│                        MIESC v4.2.1                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Project:     VulnerableVault.sol                               │
│  Auditor:     MIESC Automated Security Audit                    │
│  Date:        {date}                                     │
│  Report ID:   MIESC-{report_id}                       │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  OVERALL RISK SCORE                                              │
│  ┌────────────────────────────────────────────────────┐         │
│  │ [██████████████████████████░░░░░░]  85/100  HIGH  │         │
│  └────────────────────────────────────────────────────┘         │
│                                                                  │
│  FINDINGS BREAKDOWN                                              │
│    • Critical:  2  ████████████                                 │
│    • High:      1  ██████                                       │
│    • Medium:    1  ███                                          │
│    • Low:       1  █                                            │
│                                                                  │
│  ANALYSIS COVERAGE                                               │
│    • Layers analyzed: 9/9                                        │
│    • Tools executed:  25+                                        │
│    • Lines analyzed:  32                                         │
│    • Execution time:  3.2 seconds                                │
│                                                                  │
│  METHODOLOGY                                                     │
│    Defense-in-Depth multi-layer security analysis               │
│    Static Analysis → Pattern Detection → Symbolic Execution     │
│    → Fuzzing → Formal Verification → ML Detection               │
│    → AI Analysis → DeFi Security → Dependency Scan              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
""".format(
        date=datetime.now().strftime("%Y-%m-%d"),
        report_id=datetime.now().strftime("%Y%m%d-001")
    )

    console.print(Panel(
        report_preview,
        title="[bold blue]Audit Report Preview[/bold blue]",
        border_style="blue"
    ))

    short_pause()

    console.print("\n[bold green]✓[/bold green] Report files generated:")
    console.print("  [cyan]→[/cyan] reports/audit_report.html  [dim](Interactive HTML report)[/dim]")
    console.print("  [cyan]→[/cyan] reports/audit_report.pdf   [dim](Professional PDF document)[/dim]")
    console.print("  [cyan]→[/cyan] reports/audit_report.json  [dim](Machine-readable data)[/dim]")

    pause()


def demo_metrics():
    """Show performance metrics"""
    section_header("Scientific Validation", "Benchmark results on SmartBugs Curated dataset (143 contracts)")

    metrics_table = Table(title="MIESC v4.2.1 Performance Metrics", box=box.ROUNDED)
    metrics_table.add_column("Metric", style="bold", width=25)
    metrics_table.add_column("Value", justify="right", width=18)
    metrics_table.add_column("Context", style="dim", width=35)

    metrics_table.add_row("Recall", "[bold green]84.3%[/bold green]", "+27.3% vs literature baseline")
    metrics_table.add_row("F1-Score", "[bold green]80.0%[/bold green]", "Slither adapter validation")
    metrics_table.add_row("Pattern Detection", "[bold green]100%[/bold green]", "SmartBugsDetector coverage")
    metrics_table.add_row("Contracts Tested", "143", "SmartBugs Curated benchmark")
    metrics_table.add_row("Vulnerability Categories", "10", "Reentrancy, overflow, access control...")
    metrics_table.add_row("Analysis Speed", "346 contracts/min", "Parallel 4-worker execution")
    metrics_table.add_row("False Positive Rate", "[bold green]<5%[/bold green]", "ML-based filtering")

    console.print(metrics_table)
    pause()


def demo_developer_workflow():
    """Show developer integration workflow"""
    section_header("Developer Integration", "Seamlessly integrate MIESC into your development workflow")

    workflow = """
## Command Line Interface

```bash
# Install MIESC
pip install miesc

# Quick scan (Layer 1 only - fast feedback)
miesc analyze MyContract.sol --quick

# Full 9-layer deep scan
miesc analyze MyContract.sol --deep

# Generate professional audit report
miesc analyze MyContract.sol --report html,pdf

# Analyze entire project
miesc analyze contracts/ --recursive
```

## CI/CD Integration (GitHub Actions)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: MIESC Security Scan
        uses: fboiero/miesc-action@v1
        with:
          contract: contracts/*.sol
          fail-on: high
          report: true
```

## Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/fboiero/miesc
    rev: v4.2.1
    hooks:
      - id: miesc-scan
        args: [--quick, --fail-on, high]
```
"""
    console.print(Markdown(workflow))
    pause()


def demo_researcher_workflow():
    """Show security researcher workflow"""
    section_header("Security Researcher Workflow", "Accelerate manual audits with MIESC")

    workflow = """
## For Security Researchers & Audit Firms

### 1. Automated Triage
MIESC pre-analyzes contracts to prioritize your manual review:
- Critical and High findings require immediate attention
- AI-generated remediation suggestions save research time
- Cross-reference with SWC Registry and CWE database

### 2. Evidence Collection
All tool outputs are preserved for your audit trail:
- Raw Slither/Mythril/Aderyn outputs in JSON
- Transaction traces from symbolic execution
- Fuzzing campaign results and edge cases

### 3. API Integration

```python
from miesc import MIESCAnalyzer

# Initialize analyzer
analyzer = MIESCAnalyzer()

# Run analysis on specific layers
results = analyzer.analyze(
    "contract.sol",
    layers=[1, 2, 3],  # Static, Pattern, Symbolic
    parallel=True
)

# Generate professional report
report = analyzer.generate_report(
    results,
    format="html",
    template="audit-firm"
)

# Export findings to your ticketing system
findings = results.to_json()
```

### 4. Custom Report Templates
Generate reports in your firm's format:
- Customizable HTML/PDF templates
- Add manual findings alongside automated ones
- Export to Word, PDF, HTML, or Markdown
"""
    console.print(Markdown(workflow))
    pause()


def demo_conclusion():
    """Conclusion and call to action"""
    section_header("Get Started with MIESC", "Open Source • Community Driven • Scientifically Validated")

    conclusion = """
## Quick Installation

```bash
pip install miesc

# Or from source
git clone https://github.com/fboiero/MIESC
cd MIESC && pip install -e .
```

## Resources

- **Documentation**: https://fboiero.github.io/MIESC
- **GitHub Repository**: https://github.com/fboiero/MIESC
- **API Reference**: https://fboiero.github.io/MIESC/api
- **License**: AGPL-3.0 (Open Source)

## Key Features

- [x] 25+ security analysis tools integrated
- [x] 9-layer defense-in-depth architecture
- [x] AI-powered analysis (SmartLLM, PropertyGPT)
- [x] Professional HTML/PDF audit reports
- [x] Scientific validation (SmartBugs benchmark)
- [x] REST API & MCP integration
- [x] CI/CD ready with GitHub Actions
- [x] Docker support for isolated execution

---

**MIESC** - Making smart contract security accessible to everyone.

*Developed by Fernando Boiero at UNDEF - IUA Córdoba, Argentina*
"""
    console.print(Markdown(conclusion))

    console.print()
    console.print(Panel(
        "[bold green]Thank you for watching![/bold green]\n\n"
        "[cyan]Star us on GitHub:[/cyan] https://github.com/fboiero/MIESC\n"
        "[cyan]Follow for updates:[/cyan] @fboiero",
        border_style="green",
        box=box.DOUBLE
    ))


def generate_real_report(open_browser: bool = True):
    """Generate a real sample report using the report generator"""
    section_header("Generating Real Audit Report", "Creating actual HTML report with full evidence...")

    try:
        from src.reports.audit_report import AuditMetadata, AuditReportGenerator, Finding

        metadata = AuditMetadata(
            project_name="VulnerableVault Security Audit",
            contract_name="VulnerableVault.sol",
            version="1.0.0",
            auditor="MIESC Automated Security Audit",
            organization="MIESC Security Framework",
            audit_date=datetime.now().strftime("%Y-%m-%d"),
            report_id=f"MIESC-{datetime.now().strftime('%Y%m%d')}-DEMO",
            contract_hash=hashlib.sha256(SAMPLE_CONTRACT.encode()).hexdigest(),
            solidity_version="0.8.0",
            lines_of_code=len(SAMPLE_CONTRACT.splitlines()),
        )

        findings = [
            Finding(
                id=f["id"],
                title=f["title"],
                severity=f["severity"],
                category=f.get("swc", "Security"),
                description=f["description"],
                location=f["location"],
                tool=f["tool"],
                layer=f["layer"],
                swc_id=f.get("swc"),
                cwe_id=f.get("cwe"),
                remediation=f.get("remediation", ""),
            )
            for f in DEMO_FINDINGS
        ]

        generator = AuditReportGenerator(
            metadata=metadata,
            findings=findings,
            contract_source=SAMPLE_CONTRACT,
            raw_tool_outputs={
                "Slither": {
                    "version": "0.10.0",
                    "findings_count": 2,
                    "detectors_run": 92,
                    "execution_time": "0.8s"
                },
                "Mythril": {
                    "version": "0.24.7",
                    "findings_count": 1,
                    "symbolic_execution_time": "12.3s"
                },
                "SmartBugsDetector": {
                    "version": "1.0.0",
                    "patterns_matched": 1,
                    "patterns_checked": 47
                },
                "Aderyn": {
                    "version": "0.1.0",
                    "findings_count": 1,
                    "ast_analysis": True
                }
            }
        )

        output_dir = project_root / "reports"
        output_dir.mkdir(exist_ok=True)

        html_path = generator.save_html(output_dir / "demo_audit_report.html")
        json_path = generator.save_json(output_dir / "demo_audit_report.json")

        console.print()
        console.print("[bold green]✓[/bold green] Report files generated successfully:")
        console.print(f"  [cyan]→[/cyan] {html_path}")
        console.print(f"  [cyan]→[/cyan] {json_path}")

        # Try PDF
        pdf_path = generator.save_pdf(output_dir / "demo_audit_report.pdf")
        if pdf_path:
            console.print(f"  [cyan]→[/cyan] {pdf_path}")

        # Open in browser
        if open_browser:
            short_pause()
            console.print()
            console.print("[bold cyan]Opening HTML report in browser...[/bold cyan]")
            webbrowser.open(f"file://{html_path.absolute()}")

        return html_path

    except Exception as e:
        console.print(f"[yellow]Report generation note: {e}[/yellow]")
        return None


def run_demo(with_report: bool = True, open_browser: bool = True):
    """Run the complete demo"""
    console.clear()

    try:
        # Main demo sections
        demo_intro()
        demo_architecture()
        demo_contract_input()
        demo_analysis_progress()
        demo_findings_display()
        demo_finding_detail()
        demo_report_generation()
        demo_metrics()
        demo_developer_workflow()
        demo_researcher_workflow()
        demo_conclusion()

        # Generate real report at the end
        if with_report:
            pause()
            generate_real_report(open_browser=open_browser)

    except KeyboardInterrupt:
        console.print("\n[yellow]Demo interrupted by user[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="MIESC Video Demo - Visual demonstration for recordings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python demo/miesc_video_demo.py                    # Full demo with default speed
  python demo/miesc_video_demo.py --speed 0.3        # Slower for video recording
  python demo/miesc_video_demo.py --speed 0.5        # Medium speed
  python demo/miesc_video_demo.py --no-browser       # Don't open browser at end
  python demo/miesc_video_demo.py --section findings # Only show findings section
        """
    )
    parser.add_argument(
        "--speed", type=float, default=0.4,
        help="Animation speed (0.3=slow for video, 0.5=medium, 1.0=fast). Default: 0.4"
    )
    parser.add_argument(
        "--no-report", action="store_true",
        help="Skip generating real report at the end"
    )
    parser.add_argument(
        "--no-browser", action="store_true",
        help="Don't open HTML report in browser"
    )
    parser.add_argument(
        "--section",
        choices=["intro", "arch", "contract", "analysis", "findings", "detail", "report", "metrics", "dev", "researcher", "all"],
        default="all",
        help="Run only a specific section"
    )

    args = parser.parse_args()
    DEMO_CONFIG["speed"] = args.speed

    if args.section == "all":
        run_demo(with_report=not args.no_report, open_browser=not args.no_browser)
    elif args.section == "intro":
        demo_intro()
    elif args.section == "arch":
        demo_architecture()
    elif args.section == "contract":
        demo_contract_input()
    elif args.section == "analysis":
        demo_contract_input()
        demo_analysis_progress()
    elif args.section == "findings":
        demo_findings_display()
    elif args.section == "detail":
        demo_finding_detail()
    elif args.section == "report":
        demo_report_generation()
        if not args.no_report:
            generate_real_report(open_browser=not args.no_browser)
    elif args.section == "metrics":
        demo_metrics()
    elif args.section == "dev":
        demo_developer_workflow()
    elif args.section == "researcher":
        demo_researcher_workflow()
