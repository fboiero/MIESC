#!/usr/bin/env python3
"""
MIESC - Interactive Ollama & CrewAI Test Runner

This script provides a complete test suite with a rich console interface for:
1. Installing and configuring Ollama
2. Integrating agents into MIESC workflow
3. Running specific use case examples
4. Optimizing model configuration

Usage:
    python scripts/test_ollama_crewai.py
"""

import sys
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.layout import Layout
    from rich.live import Live
    from rich.syntax import Syntax
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  Warning: 'rich' library not found. Install with: pip install rich")
    print("Falling back to basic output...\n")

# Initialize console
console = Console() if RICH_AVAILABLE else None


class TestRunner:
    """Interactive test runner for Ollama and CrewAI integration"""

    def __init__(self):
        self.project_root = Path(__file__).parent.parent.absolute()
        self.results: Dict[str, Dict] = {}

    def print_header(self):
        """Print welcome header"""
        if RICH_AVAILABLE:
            console.print(Panel.fit(
                "[bold cyan]MIESC - Ollama & CrewAI Test Runner[/bold cyan]\n\n"
                "[white]Complete test suite for AI agent integration[/white]",
                border_style="cyan"
            ))
        else:
            print("=" * 60)
            print("MIESC - Ollama & CrewAI Test Runner")
            print("=" * 60)

    def check_system_requirements(self) -> Dict[str, bool]:
        """Check system requirements"""
        if RICH_AVAILABLE:
            console.print("\n[bold yellow]Step 1/4:[/bold yellow] Checking system requirements...\n")
        else:
            print("\n[1/4] Checking system requirements...\n")

        checks = {
            "Python 3.8+": sys.version_info >= (3, 8),
            "Ollama installed": self._check_ollama_installed(),
            "Ollama running": self._check_ollama_running(),
            "Redis available": self._check_redis_available(),
            "Required packages": self._check_python_packages()
        }

        # Display results
        if RICH_AVAILABLE:
            table = Table(title="System Requirements", show_header=True, header_style="bold magenta")
            table.add_column("Requirement", style="cyan", width=30)
            table.add_column("Status", width=15)

            for req, passed in checks.items():
                status = "[green]✓ PASSED[/green]" if passed else "[red]✗ FAILED[/red]"
                table.add_row(req, status)

            console.print(table)
        else:
            for req, passed in checks.items():
                status = "✓ PASSED" if passed else "✗ FAILED"
                print(f"  {req:30} {status}")

        self.results["system_requirements"] = checks
        return checks

    def _check_ollama_installed(self) -> bool:
        """Check if Ollama is installed"""
        try:
            result = subprocess.run(
                ["ollama", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def _check_ollama_running(self) -> bool:
        """Check if Ollama is running"""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def _check_redis_available(self) -> bool:
        """Check if Redis is available"""
        try:
            result = subprocess.run(
                ["redis-cli", "ping"],
                capture_output=True,
                timeout=2
            )
            return b"PONG" in result.stdout
        except:
            return False

    def _check_python_packages(self) -> bool:
        """Check if required Python packages are installed"""
        required = ["crewai", "langchain", "langchain_community"]
        try:
            import importlib
            for pkg in required:
                importlib.import_module(pkg)
            return True
        except ImportError:
            return False

    def install_ollama(self):
        """Install Ollama if needed"""
        if RICH_AVAILABLE:
            console.print("\n[bold yellow]Step 2/4:[/bold yellow] Installing Ollama...\n")
        else:
            print("\n[2/4] Installing Ollama...\n")

        if self._check_ollama_installed():
            if RICH_AVAILABLE:
                console.print("[green]✓ Ollama is already installed[/green]")
            else:
                print("✓ Ollama is already installed")
            return True

        # Detect OS
        import platform
        os_type = platform.system()

        # Ask if user wants to install
        if RICH_AVAILABLE:
            console.print("[yellow]Ollama is not installed.[/yellow]")
            install = Confirm.ask("Would you like to install it now?", default=True)
        else:
            print("Ollama is not installed.")
            install = input("Would you like to install it now? (y/n): ").lower() == 'y'

        if not install:
            if RICH_AVAILABLE:
                console.print("\n[yellow]⚠️  Skipping Ollama installation[/yellow]")
                console.print("[cyan]Install manually: https://ollama.ai/download[/cyan]")
            else:
                print("\n⚠️  Skipping Ollama installation")
                print("Install manually: https://ollama.ai/download")
            return False

        # Install based on OS
        if os_type == "Darwin":  # macOS
            return self._install_ollama_macos()
        elif os_type == "Linux":
            return self._install_ollama_linux()
        else:
            if RICH_AVAILABLE:
                console.print("\n[red]Automatic installation not supported on Windows[/red]")
                console.print("[cyan]Please download from: https://ollama.ai/download[/cyan]")
            else:
                print("\nAutomatic installation not supported on Windows")
                print("Please download from: https://ollama.ai/download")
            return False

    def _install_ollama_macos(self):
        """Install Ollama on macOS"""
        # Detect if running on Apple Silicon
        import platform
        is_arm = platform.machine() == 'arm64'

        # Check if Homebrew is available
        try:
            result = subprocess.run(["which", "brew"], capture_output=True, timeout=5)
            has_brew = result.returncode == 0
        except:
            has_brew = False

        if has_brew:
            if RICH_AVAILABLE:
                console.print("\n[cyan]Installing Ollama via Homebrew...[/cyan]")
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task("Running: brew install ollama", total=None)

                    # Use arch -arm64 if on Apple Silicon to avoid Rosetta issues
                    if is_arm:
                        result = subprocess.run(
                            ["arch", "-arm64", "brew", "install", "ollama"],
                            capture_output=True,
                            text=True
                        )
                    else:
                        result = subprocess.run(
                            ["brew", "install", "ollama"],
                            capture_output=True,
                            text=True
                        )
                    progress.update(task, completed=True)
            else:
                print("\nInstalling Ollama via Homebrew...")
                if is_arm:
                    result = subprocess.run(["arch", "-arm64", "brew", "install", "ollama"])
                else:
                    result = subprocess.run(["brew", "install", "ollama"])

            if result.returncode == 0:
                # Start Ollama service
                if RICH_AVAILABLE:
                    console.print("[green]✓ Ollama installed successfully![/green]")
                    console.print("[cyan]Starting Ollama service...[/cyan]")
                else:
                    print("✓ Ollama installed successfully!")
                    print("Starting Ollama service...")

                subprocess.run(["brew", "services", "start", "ollama"], capture_output=True)

                # Wait a bit for service to start
                import time
                time.sleep(3)

                if RICH_AVAILABLE:
                    console.print("[green]✓ Ollama is running![/green]")
                else:
                    print("✓ Ollama is running!")

                return True
            else:
                if RICH_AVAILABLE:
                    console.print(f"[yellow]⚠️  Homebrew installation failed[/yellow]")
                    console.print(f"[dim]{result.stderr[:200]}[/dim]")
                    console.print("\n[cyan]Trying alternative method...[/cyan]")
                else:
                    print("⚠️  Homebrew installation failed")
                    print("Trying alternative method...")

                # Fall through to curl method
                has_brew = False

        if not has_brew:
            # Open browser for manual download (most reliable)
            if RICH_AVAILABLE:
                console.print(Panel(
                    "[bold cyan]Manual Installation Required[/bold cyan]\n\n"
                    "[white]I'll open the download page in your browser.[/white]\n\n"
                    "[bold yellow]Steps:[/bold yellow]\n"
                    "1. Download Ollama-darwin.dmg from the browser\n"
                    "2. Open the downloaded .dmg file\n"
                    "3. Drag Ollama to Applications folder\n"
                    "4. Open Ollama from Applications\n"
                    "5. Come back here and press Enter",
                    border_style="cyan"
                ))

                # Open download page in browser
                console.print("\n[cyan]Opening download page in your browser...[/cyan]")
                subprocess.run(["open", "https://ollama.com/download"])

                import time
                time.sleep(2)

                console.print("[yellow]Complete the installation in your browser and then come back here.[/yellow]")
                input("\n[bold]Press Enter after you've installed Ollama...[/bold] ")

                # Check if installed
                if self._check_ollama_installed():
                    console.print("[green]✓ Ollama installed successfully![/green]")

                    # Try to start ollama
                    console.print("[cyan]Starting Ollama...[/cyan]")
                    subprocess.run(["open", "-a", "Ollama"], capture_output=True)

                    time.sleep(5)

                    if self._check_ollama_running():
                        console.print("[green]✓ Ollama is running![/green]")
                        return True
                    else:
                        console.print("[yellow]⚠️  Please open Ollama from Applications[/yellow]")
                        console.print("[dim]Look for the llama icon in your menu bar[/dim]")
                        return True
                else:
                    console.print("[yellow]⚠️  Ollama not detected. Please try again or install manually.[/yellow]")
                    console.print("[cyan]Visit: https://ollama.com/download[/cyan]")
                    return False
            else:
                print("\nPlease download Ollama manually from: https://ollama.com/download")
                subprocess.run(["open", "https://ollama.com/download"])
                return False

    def _install_ollama_linux(self):
        """Install Ollama on Linux"""
        if RICH_AVAILABLE:
            console.print("\n[cyan]Installing Ollama on Linux...[/cyan]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Running installation script...", total=None)
                result = subprocess.run(
                    "curl -fsSL https://ollama.ai/install.sh | sh",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                progress.update(task, completed=True)
        else:
            print("\nInstalling Ollama on Linux...")
            result = subprocess.run(
                "curl -fsSL https://ollama.ai/install.sh | sh",
                shell=True
            )

        if result.returncode == 0:
            if RICH_AVAILABLE:
                console.print("[green]✓ Ollama installed successfully![/green]")
            else:
                print("✓ Ollama installed successfully!")
            return True
        else:
            if RICH_AVAILABLE:
                console.print("[red]✗ Installation failed[/red]")
            else:
                print("✗ Installation failed")
            return False

    def install_python_packages(self):
        """Install required Python packages"""
        if RICH_AVAILABLE:
            console.print("\n[bold yellow]Installing Python packages...[/bold yellow]\n")
        else:
            print("\nInstalling Python packages...\n")

        packages = ["crewai>=0.22.0", "crewai-tools>=0.2.6", "langchain>=0.1.0",
                    "langchain-community>=0.0.20", "langchain-openai>=0.0.5",
                    "pyyaml>=6.0", "pydantic>=2.0.0"]

        if RICH_AVAILABLE:
            install = Confirm.ask("Install required packages?", default=True)
        else:
            install = input("Install required packages? (y/n): ").lower() == 'y'

        if not install:
            if RICH_AVAILABLE:
                console.print("[yellow]⚠️  Skipping package installation[/yellow]")
            else:
                print("⚠️  Skipping package installation")
            return False

        # Try to upgrade pip first
        if RICH_AVAILABLE:
            console.print("[cyan]Upgrading pip...[/cyan]")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
            capture_output=True
        )

        # Install packages one by one for better error handling
        failed_packages = []
        installed_packages = []

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                for package in packages:
                    task = progress.add_task(f"Installing {package.split('>=')[0]}...", total=None)
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", package, "--quiet"],
                        capture_output=True,
                        text=True
                    )
                    progress.update(task, completed=True)

                    if result.returncode == 0:
                        installed_packages.append(package)
                        console.print(f"[green]✓ {package.split('>=')[0]}[/green]")
                    else:
                        failed_packages.append(package)
                        console.print(f"[yellow]⚠️  {package.split('>=')[0]} (skipped)[/yellow]")
        else:
            for package in packages:
                print(f"Installing {package}...")
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", package],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    installed_packages.append(package)
                    print(f"✓ {package}")
                else:
                    failed_packages.append(package)
                    print(f"⚠️  {package} (skipped)")

        # Show summary
        if RICH_AVAILABLE:
            if installed_packages:
                console.print(f"\n[green]✓ Installed {len(installed_packages)}/{len(packages)} packages[/green]")
            if failed_packages:
                console.print(f"[yellow]⚠️  {len(failed_packages)} packages skipped (may already be installed)[/yellow]")
        else:
            if installed_packages:
                print(f"\n✓ Installed {len(installed_packages)}/{len(packages)} packages")
            if failed_packages:
                print(f"⚠️  {len(failed_packages)} packages skipped")

        # Consider success if most packages installed
        return len(installed_packages) >= len(packages) * 0.7  # 70% success rate

    def download_ollama_model(self, model="codellama:13b"):
        """Download Ollama model"""
        if RICH_AVAILABLE:
            console.print(f"\n[bold yellow]Downloading model: {model}[/bold yellow]\n")
        else:
            print(f"\nDownloading model: {model}\n")

        if RICH_AVAILABLE:
            download = Confirm.ask(f"Download {model}? (This may take a few minutes)", default=True)
        else:
            download = input(f"Download {model}? (y/n): ").lower() == 'y'

        if not download:
            if RICH_AVAILABLE:
                console.print("[yellow]⚠️  Skipping model download[/yellow]")
            else:
                print("⚠️  Skipping model download")
            return False

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"Downloading {model}...", total=None)
                result = subprocess.run(
                    ["ollama", "pull", model],
                    capture_output=True,
                    text=True
                )
                progress.update(task, completed=True)
        else:
            print(f"Downloading {model}...")
            result = subprocess.run(["ollama", "pull", model])

        if result.returncode == 0:
            if RICH_AVAILABLE:
                console.print(f"[green]✓ {model} downloaded successfully![/green]")
            else:
                print(f"✓ {model} downloaded successfully!")
            return True
        else:
            if RICH_AVAILABLE:
                console.print(f"[red]✗ Download failed[/red]")
            else:
                print("✗ Download failed")
            return False

    def test_ollama_agent(self) -> Dict:
        """Test OllamaAgent with example contract"""
        if RICH_AVAILABLE:
            console.print("\n[bold yellow]Step 3/4:[/bold yellow] Testing OllamaAgent...\n")
        else:
            print("\n[3/4] Testing OllamaAgent...\n")

        try:
            from src.agents.ollama_agent import OllamaAgent
        except ImportError as e:
            if RICH_AVAILABLE:
                console.print(f"[red]✗ Failed to import OllamaAgent: {e}[/red]")
            else:
                print(f"✗ Failed to import OllamaAgent: {e}")
            return {"success": False, "error": str(e)}

        # Check available models
        if RICH_AVAILABLE:
            console.print("[cyan]Checking available Ollama models...[/cyan]")
        else:
            print("Checking available Ollama models...")

        available_models = OllamaAgent.get_available_models()

        if not available_models:
            if RICH_AVAILABLE:
                console.print("[red]✗ No Ollama models found. Run: ollama pull codellama:7b[/red]")
            else:
                print("✗ No Ollama models found. Run: ollama pull codellama:7b")
            return {"success": False, "error": "No models found"}

        # Display available models
        if RICH_AVAILABLE:
            table = Table(title="Available Models", show_header=True)
            table.add_column("Model", style="cyan")
            for model in available_models[:5]:
                table.add_row(model)
            console.print(table)
        else:
            print("\nAvailable models:")
            for model in available_models[:5]:
                print(f"  - {model}")

        # Select model to test
        test_model = available_models[0] if available_models else "codellama:7b"

        if RICH_AVAILABLE:
            console.print(f"\n[cyan]Testing with model:[/cyan] {test_model}")
        else:
            print(f"\nTesting with model: {test_model}")

        # Create test contract
        test_contract = self.project_root / "examples" / "reentrancy.sol"

        if not test_contract.exists():
            if RICH_AVAILABLE:
                console.print(f"[yellow]⚠️  Test contract not found: {test_contract}[/yellow]")
            else:
                print(f"⚠️  Test contract not found: {test_contract}")

            # Create simple test contract
            test_contract = self.project_root / "test_contract.sol"
            test_contract.write_text("""
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint) public balances;

    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;  // State update after external call (reentrancy)
    }
}
            """.strip())

        # Run analysis with progress
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Analyzing contract with {test_model}...",
                    total=100
                )

                start_time = time.time()
                agent = OllamaAgent(model=test_model)

                progress.update(task, advance=30)
                results = agent.run(str(test_contract))
                progress.update(task, advance=70)

                execution_time = time.time() - start_time
        else:
            print(f"Analyzing contract with {test_model}...")
            start_time = time.time()
            agent = OllamaAgent(model=test_model)
            results = agent.run(str(test_contract))
            execution_time = time.time() - start_time

        # Display results
        findings = results.get("ollama_findings", [])

        if RICH_AVAILABLE:
            console.print(f"\n[green]✓ Analysis complete![/green]")
            console.print(f"[cyan]Execution time:[/cyan] {execution_time:.2f}s")
            console.print(f"[cyan]Findings:[/cyan] {len(findings)}")

            if findings:
                table = Table(title="Ollama Findings", show_header=True)
                table.add_column("ID", style="cyan", width=12)
                table.add_column("Severity", style="yellow", width=10)
                table.add_column("Category", style="magenta", width=15)
                table.add_column("Description", style="white", width=50)

                for finding in findings[:5]:
                    table.add_row(
                        finding.get("id", "N/A"),
                        finding.get("severity", "N/A"),
                        finding.get("category", "N/A"),
                        finding.get("description", "N/A")[:47] + "..."
                    )

                console.print(table)
        else:
            print(f"\n✓ Analysis complete!")
            print(f"Execution time: {execution_time:.2f}s")
            print(f"Findings: {len(findings)}")

            if findings:
                print("\nTop findings:")
                for i, finding in enumerate(findings[:3], 1):
                    print(f"\n{i}. [{finding.get('severity', 'N/A')}] {finding.get('category', 'N/A')}")
                    print(f"   {finding.get('description', 'N/A')[:100]}...")

        self.results["ollama_test"] = {
            "success": True,
            "model": test_model,
            "findings": len(findings),
            "execution_time": execution_time
        }

        return self.results["ollama_test"]

    def test_crewai_coordinator(self) -> Dict:
        """Test CrewAI coordinator"""
        if RICH_AVAILABLE:
            console.print("\n[bold yellow]Step 4/4:[/bold yellow] Testing CrewAI Coordinator...\n")
        else:
            print("\n[4/4] Testing CrewAI Coordinator...\n")

        try:
            from src.agents.crewai_coordinator import CrewAICoordinator
        except ImportError as e:
            if RICH_AVAILABLE:
                console.print(f"[red]✗ Failed to import CrewAICoordinator: {e}[/red]")
            else:
                print(f"✗ Failed to import CrewAICoordinator: {e}")
            return {"success": False, "error": str(e)}

        # Create coordinator with Ollama
        if RICH_AVAILABLE:
            console.print("[cyan]Creating multi-agent coordinator with Ollama...[/cyan]")
        else:
            print("Creating multi-agent coordinator with Ollama...")

        test_contract = self.project_root / "examples" / "reentrancy.sol"
        if not test_contract.exists():
            test_contract = self.project_root / "test_contract.sol"

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(
                    "[cyan]Running multi-agent analysis...",
                    total=None
                )

                start_time = time.time()
                coordinator = CrewAICoordinator(
                    use_local_llm=True,
                    llm_model="ollama/codellama:7b"
                )

                results = coordinator.run(str(test_contract))
                execution_time = time.time() - start_time

                progress.update(task, completed=True)
        else:
            print("Running multi-agent analysis...")
            start_time = time.time()
            coordinator = CrewAICoordinator(
                use_local_llm=True,
                llm_model="ollama/codellama:7b"
            )
            results = coordinator.run(str(test_contract))
            execution_time = time.time() - start_time

        # Display results
        findings = results.get("crew_findings", [])
        summary = results.get("crew_summary", {})

        if RICH_AVAILABLE:
            console.print(f"\n[green]✓ Multi-agent analysis complete![/green]")
            console.print(f"[cyan]Execution time:[/cyan] {execution_time:.2f}s")
            console.print(f"[cyan]Findings:[/cyan] {len(findings)}")

            if findings:
                table = Table(title="CrewAI Findings", show_header=True)
                table.add_column("ID", style="cyan", width=12)
                table.add_column("Severity", style="yellow", width=10)
                table.add_column("Agent", style="magenta", width=20)
                table.add_column("Description", style="white", width=45)

                for finding in findings[:5]:
                    table.add_row(
                        finding.get("id", "N/A"),
                        finding.get("severity", "N/A"),
                        finding.get("source", "N/A"),
                        finding.get("description", "N/A")[:42] + "..."
                    )

                console.print(table)
        else:
            print(f"\n✓ Multi-agent analysis complete!")
            print(f"Execution time: {execution_time:.2f}s")
            print(f"Findings: {len(findings)}")

            if findings:
                print("\nTop findings:")
                for i, finding in enumerate(findings[:3], 1):
                    print(f"\n{i}. [{finding.get('severity', 'N/A')}] {finding.get('source', 'N/A')}")
                    print(f"   {finding.get('description', 'N/A')[:100]}...")

        self.results["crewai_test"] = {
            "success": True,
            "findings": len(findings),
            "execution_time": execution_time
        }

        return self.results["crewai_test"]

    def display_summary(self):
        """Display test summary"""
        if RICH_AVAILABLE:
            console.print("\n" + "="*60)
            console.print(Panel.fit(
                "[bold green]✓ Test Suite Complete[/bold green]",
                border_style="green"
            ))
        else:
            print("\n" + "="*60)
            print("✓ Test Suite Complete")
            print("="*60)

        # System requirements summary
        if "system_requirements" in self.results:
            reqs = self.results["system_requirements"]
            passed = sum(1 for v in reqs.values() if v)
            total = len(reqs)

            if RICH_AVAILABLE:
                console.print(f"\n[cyan]System Requirements:[/cyan] {passed}/{total} passed")
            else:
                print(f"\nSystem Requirements: {passed}/{total} passed")

        # Ollama test summary
        if "ollama_test" in self.results:
            test = self.results["ollama_test"]
            if test.get("success"):
                if RICH_AVAILABLE:
                    console.print(
                        f"[cyan]Ollama Test:[/cyan] [green]✓ PASSED[/green] "
                        f"({test['findings']} findings, {test['execution_time']:.2f}s)"
                    )
                else:
                    print(
                        f"Ollama Test: ✓ PASSED "
                        f"({test['findings']} findings, {test['execution_time']:.2f}s)"
                    )

        # CrewAI test summary
        if "crewai_test" in self.results:
            test = self.results["crewai_test"]
            if test.get("success"):
                if RICH_AVAILABLE:
                    console.print(
                        f"[cyan]CrewAI Test:[/cyan] [green]✓ PASSED[/green] "
                        f"({test['findings']} findings, {test['execution_time']:.2f}s)"
                    )
                else:
                    print(
                        f"CrewAI Test: ✓ PASSED "
                        f"({test['findings']} findings, {test['execution_time']:.2f}s)"
                    )

        # Next steps
        if RICH_AVAILABLE:
            console.print("\n[bold cyan]Next Steps:[/bold cyan]")
            console.print("  1. Integrate agents into main MIESC workflow")
            console.print("  2. Run: python xaudit.py --target contract.sol --ai-agent ollama")
            console.print("  3. Explore examples: python examples/use_ollama_crewai.py")
            console.print("  4. Read docs: docs/OLLAMA_CREWAI_GUIDE.md")
        else:
            print("\nNext Steps:")
            print("  1. Integrate agents into main MIESC workflow")
            print("  2. Run: python xaudit.py --target contract.sol --ai-agent ollama")
            print("  3. Explore examples: python examples/use_ollama_crewai.py")
            print("  4. Read docs: docs/OLLAMA_CREWAI_GUIDE.md")

    def run(self):
        """Run complete test suite"""
        self.print_header()

        try:
            # Step 1: Check system requirements
            checks = self.check_system_requirements()

            # Step 2: Install Ollama if needed
            ollama_installed = False
            if not checks.get("Ollama installed") or not checks.get("Ollama running"):
                ollama_installed = self.install_ollama()
            else:
                ollama_installed = True

            # Step 2.5: Install Python packages if needed
            if not checks.get("Required packages"):
                self.install_python_packages()

            # Step 2.6: Download model if Ollama is installed but no models
            if ollama_installed:
                available_models = OllamaAgent.get_available_models() if ollama_installed else []
                if not available_models:
                    if RICH_AVAILABLE:
                        console.print("\n[yellow]No Ollama models found.[/yellow]")
                    else:
                        print("\nNo Ollama models found.")
                    self.download_ollama_model("codellama:13b")

            # Step 3: Test OllamaAgent (only if Ollama is available)
            if ollama_installed:
                self.test_ollama_agent()

            # Step 4: Test CrewAI
            self.test_crewai_coordinator()

            # Display summary
            self.display_summary()

        except KeyboardInterrupt:
            if RICH_AVAILABLE:
                console.print("\n\n[yellow]⚠️  Test suite interrupted by user[/yellow]")
            else:
                print("\n\n⚠️  Test suite interrupted by user")
        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"\n[red]✗ Error: {e}[/red]")
            else:
                print(f"\n✗ Error: {e}")
            raise


def main():
    """Main entry point"""
    runner = TestRunner()
    runner.run()


if __name__ == "__main__":
    main()
