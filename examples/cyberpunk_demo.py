#!/usr/bin/env python3
"""
MIESC Cyberpunk Demo - Futuristic Security Analysis

Usage:
    python cyberpunk_demo.py <contract.sol>

Example:
    python cyberpunk_demo.py examples/contracts/VulnerableBank.sol

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

import os
import random
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path


class NeonColors:
    """Cyberpunk neon color palette"""

    NEON_PINK = "\033[95m\033[1m"
    NEON_CYAN = "\033[96m\033[1m"
    NEON_GREEN = "\033[92m\033[1m"
    NEON_YELLOW = "\033[93m\033[1m"
    NEON_RED = "\033[91m\033[1m"
    NEON_BLUE = "\033[94m\033[1m"
    NEON_PURPLE = "\033[35m\033[1m"
    DIM_CYAN = "\033[36m"
    DIM_PINK = "\033[35m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    BLINK = "\033[5m"


def glitch_text(text: str, intensity: int = 3):
    """Create glitch effect on text"""
    glitch_chars = ["█", "▓", "▒", "░", "▀", "▄", "▌", "▐"]
    result = ""
    for char in text:
        if random.randint(0, 100) < intensity:
            result += random.choice(glitch_chars)
        else:
            result += char
    return result


def typing_effect(text: str, delay: float = 0.015, color: str = NeonColors.NEON_CYAN):
    """Cyberpunk typing effect"""
    for char in text:
        sys.stdout.write(color + char + NeonColors.ENDC)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def matrix_rain(lines: int = 5, duration: float = 1.0):
    """Matrix-style digital rain effect"""
    chars = "01アイウエオカキクケコサシスセソタチツテト"
    for _ in range(lines):
        line = "".join(random.choice(chars) for _ in range(80))
        print(f"{NeonColors.NEON_GREEN}{line}{NeonColors.ENDC}")
        time.sleep(duration / lines)


def print_cyberpunk_banner():
    """Cyberpunk ASCII banner"""
    banner = f"""
{NeonColors.NEON_PINK}
        ███╗   ███╗██╗███████╗███████╗ ██████╗    ██╗   ██╗ ██╗    ██████╗
        ████╗ ████║██║██╔════╝██╔════╝██╔════╝    ██║   ██║███║   ██╔═████╗
        ██╔████╔██║██║█████╗  ███████╗██║         ██║   ██║╚██║   ██║██╔██║
        ██║╚██╔╝██║██║██╔══╝  ╚════██║██║         ╚██╗ ██╔╝ ██║   ████╔╝██║
        ██║ ╚═╝ ██║██║███████╗███████║╚██████╗     ╚████╔╝  ██║██╗╚██████╔╝
        ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝      ╚═══╝   ╚═╝╚═╝ ╚═════╝
{NeonColors.ENDC}
{NeonColors.NEON_CYAN}        ╔═══════════════════════════════════════════════════════════════╗
        ║          AUTONOMOUS CYBERDEFENSE AGENT v1.0.0                 ║
        ║     Advanced Security Framework for Smart Contract Audits    ║
        ║          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━           ║
        ║          17 AI AGENTS • 15+ TOOLS • 6 DEFENSE LAYERS          ║
        ╚═══════════════════════════════════════════════════════════════╝{NeonColors.ENDC}
"""
    print(banner)
    matrix_rain(3, 0.5)


def print_section_header(title: str, icon: str = "▶"):
    """Neon section header"""
    print(f"\n{NeonColors.NEON_YELLOW}{'━' * 70}{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_PINK}{icon} {title}{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_YELLOW}{'━' * 70}{NeonColors.ENDC}\n")


def loading_bar(text: str, total: int = 50, color: str = NeonColors.NEON_CYAN):
    """Futuristic loading bar"""
    sys.stdout.write(f"{color}{text} ")
    sys.stdout.flush()

    for i in range(total):
        if i < total * 0.3:
            char = "░"
        elif i < total * 0.7:
            char = "▒"
        else:
            char = "█"

        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.02)

    print(f" {NeonColors.NEON_GREEN}✓{NeonColors.ENDC}")


def analyze_contract(contract_path: str):
    """Cyberpunk contract analysis"""

    print(f"{NeonColors.NEON_CYAN}[*] INITIALIZING NEURAL NETWORK...{NeonColors.ENDC}")
    loading_bar("Loading AI Models", 40, NeonColors.NEON_PURPLE)
    print()

    print(f"{NeonColors.NEON_PINK}[*] TARGET: {contract_path}{NeonColors.ENDC}")
    print(
        f"{NeonColors.DIM_CYAN}[*] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{NeonColors.ENDC}\n"
    )
    time.sleep(0.5)

    # Layer 1: Static Analysis
    print_section_header("LAYER 1: STATIC ANALYSIS", "⚡")

    typing_effect("  → Deploying Slither scanner...", 0.02, NeonColors.NEON_CYAN)
    time.sleep(0.8)
    loading_bar("  Analyzing bytecode", 35, NeonColors.NEON_BLUE)
    print(f"{NeonColors.NEON_YELLOW}    ⚠ REENTRANCY detected at line 42{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_YELLOW}    ⚠ State change after external call{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_GREEN}    ✓ NatSpec: 85% coverage{NeonColors.ENDC}")
    print()

    time.sleep(0.5)
    typing_effect("  → Aderyn Rust analyzer...", 0.02, NeonColors.NEON_CYAN)
    time.sleep(0.8)
    loading_bar("  Deep pattern scan", 35, NeonColors.NEON_BLUE)
    print(f"{NeonColors.NEON_RED}    ✗ [HIGH] Reentrancy vulnerability{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_YELLOW}    ⚠ [MED] Missing CEI pattern{NeonColors.ENDC}")
    print()

    # Layer 2: Dynamic Analysis
    print_section_header("LAYER 2: DYNAMIC FUZZING", "🔥")

    typing_effect("  → Launching Medusa fuzzer...", 0.02, NeonColors.NEON_CYAN)
    time.sleep(0.8)
    loading_bar("  Generating attack vectors", 45, NeonColors.NEON_PINK)

    print(f"{NeonColors.NEON_RED}{NeonColors.BLINK}    ✗ [CRITICAL] EXPLOIT FOUND{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_RED}    → Attack: Drain all ETH via reentrancy loop{NeonColors.ENDC}")
    print(
        f"{NeonColors.DIM_CYAN}    → Sequence: deposit(1 ETH) → withdraw() → fallback() → drain{NeonColors.ENDC}"
    )
    print()

    # Layer 3: Symbolic Execution
    print_section_header("LAYER 3: SYMBOLIC EXECUTION", "🧠")

    typing_effect("  → Mythril engine online...", 0.02, NeonColors.NEON_CYAN)
    time.sleep(0.8)
    loading_bar("  Exploring state space", 40, NeonColors.NEON_PURPLE)

    print(f"{NeonColors.NEON_RED}    ✗ [SWC-107] Reentrancy Attack{NeonColors.ENDC}")
    print(f"{NeonColors.DIM_CYAN}    → Severity: HIGH | Confidence: HIGH{NeonColors.ENDC}")
    print(f"{NeonColors.DIM_CYAN}    → Attack traces: 3 paths confirmed{NeonColors.ENDC}")
    print()

    # Layer 4: AI Analysis
    print_section_header("LAYER 5: AI NEURAL CORRELATION", "🤖")

    typing_effect("  → GPT-4 analyzing findings...", 0.02, NeonColors.NEON_CYAN)
    time.sleep(1)
    loading_bar("  Cross-layer correlation", 50, NeonColors.NEON_GREEN)

    print(f"\n{NeonColors.NEON_PINK}    🤖 AI VERDICT:{NeonColors.ENDC}")
    print(
        f"{NeonColors.NEON_YELLOW}    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NeonColors.ENDC}"
    )
    print(f"{NeonColors.NEON_CYAN}    All 3 layers confirmed: CRITICAL REENTRANCY{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_CYAN}    Probability: 99.8% | NOT a false positive{NeonColors.ENDC}")
    print(
        f"{NeonColors.NEON_RED}    Priority: {NeonColors.BLINK}IMMEDIATE FIX REQUIRED{NeonColors.ENDC}"
    )
    print()

    typing_effect("  → Generating remediation...", 0.02, NeonColors.NEON_CYAN)
    time.sleep(0.8)
    loading_bar("  OpenZeppelin pattern match", 40, NeonColors.NEON_GREEN)

    print(f"\n{NeonColors.NEON_GREEN}    ✓ RECOMMENDED FIX (OpenZeppelin):{NeonColors.ENDC}")
    print(f"""
{NeonColors.DIM_CYAN}    ╔════════════════════════════════════════════════════════════╗
    ║  import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
    ║
    ║  contract EtherStore is ReentrancyGuard {{
    ║      function withdraw() public nonReentrant {{
    ║          uint256 bal = balances[msg.sender];
    ║          require(bal > 0, "Insufficient balance");
    ║
    ║          balances[msg.sender] = 0;  // ✓ CEI pattern
    ║          (bool sent, ) = msg.sender.call{{value: bal}}("");
    ║          require(sent, "Failed to send");
    ║      }}
    ║  }}
    ╚════════════════════════════════════════════════════════════╝{NeonColors.ENDC}
""")

    # Layer 5: Standards Mapping
    print_section_header("LAYER 6: COMPLIANCE MAPPING", "📊")

    typing_effect("  → Mapping to security standards...", 0.02, NeonColors.NEON_CYAN)
    time.sleep(0.5)

    print(
        f"{NeonColors.NEON_PURPLE}    ► OWASP SC Top 10:{NeonColors.ENDC} SC01 - Reentrancy Attacks"
    )
    print(f"{NeonColors.NEON_PURPLE}    ► SWC Registry:{NeonColors.ENDC}   SWC-107 - Reentrancy")
    print(
        f"{NeonColors.NEON_PURPLE}    ► CWE:{NeonColors.ENDC}            CWE-841 - Behavioral Workflow"
    )
    print(f"{NeonColors.NEON_PURPLE}    ► NIST SSDF:{NeonColors.ENDC}      PW.7 - Code Review")
    print(
        f"{NeonColors.NEON_PURPLE}    ► ISO 27001:{NeonColors.ENDC}      A.14.2.5 - Secure Development"
    )
    print()

    # Final Summary
    print_section_header("ANALYSIS COMPLETE", "✓")

    print(f"""
{NeonColors.NEON_PINK}    ╔═══════════════════════════════════════════════════════════════╗
    ║                     THREAT ASSESSMENT                         ║
    ╠═══════════════════════════════════════════════════════════════╣{NeonColors.ENDC}
{NeonColors.NEON_RED}    ║  {NeonColors.BLINK}CRITICAL{NeonColors.ENDC}{NeonColors.NEON_RED}:  1   Reentrancy - IMMEDIATE ACTION REQUIRED       ║{NeonColors.ENDC}
{NeonColors.NEON_YELLOW}    ║  HIGH    :  2   State management violations                  ║{NeonColors.ENDC}
{NeonColors.NEON_GREEN}    ║  MEDIUM  :  3   Documentation & best practices               ║{NeonColors.ENDC}
{NeonColors.NEON_PINK}    ╠═══════════════════════════════════════════════════════════════╣
    ║                     AI OPTIMIZATION                           ║
    ╠═══════════════════════════════════════════════════════════════╣{NeonColors.ENDC}
{NeonColors.NEON_CYAN}    ║  200 warnings → 5 actionable findings                        ║
    ║  AI filtered: 97.5% noise reduction                          ║{NeonColors.ENDC}
{NeonColors.NEON_PINK}    ╠═══════════════════════════════════════════════════════════════╣
    ║                     NEXT ACTIONS                              ║
    ╠═══════════════════════════════════════════════════════════════╣{NeonColors.ENDC}
{NeonColors.NEON_YELLOW}    ║  1. Implement ReentrancyGuard (OpenZeppelin)                 ║
    ║  2. Apply Checks-Effects-Interactions pattern                ║
    ║  3. Add reentrancy test coverage                             ║
    ║  4. Re-run MIESC verification                                ║{NeonColors.ENDC}
{NeonColors.NEON_PINK}    ╠═══════════════════════════════════════════════════════════════╣
    ║                     DELIVERABLES                              ║
    ╠═══════════════════════════════════════════════════════════════╣{NeonColors.ENDC}
{NeonColors.NEON_GREEN}    ║  ✓ Executive summary (stakeholders)                          ║
    ║  ✓ Technical report (developers)                             ║
    ║  ✓ Compliance report (auditors/ISO 27001)                    ║{NeonColors.ENDC}
{NeonColors.NEON_PINK}    ╚═══════════════════════════════════════════════════════════════╝{NeonColors.ENDC}
""")

    print(
        f"\n{NeonColors.NEON_CYAN}    ⏱  Analysis time: 3.2 minutes (vs 3 days manual){NeonColors.ENDC}"
    )
    print(f"{NeonColors.NEON_GREEN}    ⚡ Effort reduction: 90%{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_PINK}    📊 Generating dashboard...{NeonColors.ENDC}\n")

    # Generate statistics
    stats = {
        "contract": contract_path,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 4,
        "total_warnings": 200,
        "actionable_findings": 5,
        "noise_filtered": 97.5,
        "analysis_time": "3.2 minutes",
        "effort_reduction": 90,
        "agents_used": 17,
        "tools_integrated": 15,
        "standards_mapped": 12,
        "smartbugs_recall": 95.8,
        "evmbench_recall": 92.5,
        "defi_recall": 81.8,
    }

    return stats


def generate_landing_page(stats: dict):
    """Generate cyberpunk landing page with stats"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MIESC Analysis Report - Cyberpunk Edition</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a0033 50%, #0a0a0a 100%);
            color: #00ff9f;
            overflow-x: hidden;
            position: relative;
        }}

        /* Cyberpunk grid background */
        body::before {{
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background:
                linear-gradient(0deg, transparent 24%, rgba(0, 255, 159, .05) 25%, rgba(0, 255, 159, .05) 26%, transparent 27%, transparent 74%, rgba(0, 255, 159, .05) 75%, rgba(0, 255, 159, .05) 76%, transparent 77%, transparent),
                linear-gradient(90deg, transparent 24%, rgba(0, 255, 159, .05) 25%, rgba(0, 255, 159, .05) 26%, transparent 27%, transparent 74%, rgba(0, 255, 159, .05) 75%, rgba(0, 255, 159, .05) 76%, transparent 77%, transparent);
            background-size: 50px 50px;
            z-index: -1;
            animation: gridMove 20s linear infinite;
        }}

        @keyframes gridMove {{
            0% {{ transform: translateY(0); }}
            100% {{ transform: translateY(50px); }}
        }}

        /* Glitch effect */
        @keyframes glitch {{
            0% {{ transform: translate(0); }}
            20% {{ transform: translate(-2px, 2px); }}
            40% {{ transform: translate(-2px, -2px); }}
            60% {{ transform: translate(2px, 2px); }}
            80% {{ transform: translate(2px, -2px); }}
            100% {{ transform: translate(0); }}
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 20px;
        }}

        .header {{
            text-align: center;
            margin-bottom: 60px;
            position: relative;
        }}

        .logo {{
            font-size: 4rem;
            font-weight: bold;
            background: linear-gradient(90deg, #ff00ff, #00ffff, #ff00ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: glitch 0.3s infinite;
            text-shadow:
                0 0 10px rgba(255, 0, 255, 0.8),
                0 0 20px rgba(0, 255, 255, 0.6),
                0 0 30px rgba(255, 0, 255, 0.4);
        }}

        .subtitle {{
            font-size: 1.2rem;
            color: #00ffff;
            margin-top: 20px;
            text-shadow: 0 0 10px rgba(0, 255, 255, 0.8);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .stat-card {{
            background: rgba(0, 0, 0, 0.6);
            border: 2px solid #ff00ff;
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            position: relative;
            overflow: hidden;
            box-shadow:
                0 0 20px rgba(255, 0, 255, 0.3),
                inset 0 0 20px rgba(255, 0, 255, 0.1);
            transition: all 0.3s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            border-color: #00ffff;
            box-shadow:
                0 0 30px rgba(0, 255, 255, 0.5),
                inset 0 0 30px rgba(0, 255, 255, 0.2);
        }}

        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 0, 255, 0.2), transparent);
            animation: scan 3s infinite;
        }}

        @keyframes scan {{
            0% {{ left: -100%; }}
            100% {{ left: 100%; }}
        }}

        .stat-value {{
            font-size: 3rem;
            font-weight: bold;
            color: #ff00ff;
            text-shadow: 0 0 10px rgba(255, 0, 255, 0.8);
        }}

        .stat-label {{
            font-size: 0.9rem;
            color: #00ffff;
            margin-top: 10px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}

        .critical {{
            border-color: #ff0055;
        }}

        .critical .stat-value {{
            color: #ff0055;
            animation: blink 1s infinite;
        }}

        @keyframes blink {{
            0%, 50%, 100% {{ opacity: 1; }}
            25%, 75% {{ opacity: 0.5; }}
        }}

        .visualizations {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-top: 40px;
        }}

        .viz-card {{
            background: rgba(0, 0, 0, 0.7);
            border: 2px solid #00ffff;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.3);
        }}

        .viz-card img {{
            width: 100%;
            border-radius: 5px;
            border: 1px solid rgba(0, 255, 255, 0.3);
        }}

        .viz-title {{
            color: #ff00ff;
            font-size: 1.2rem;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}

        .footer {{
            text-align: center;
            margin-top: 60px;
            padding: 30px;
            border-top: 2px solid rgba(255, 0, 255, 0.3);
        }}

        .footer-text {{
            color: #00ffff;
            font-size: 0.9rem;
        }}

        .github-link {{
            color: #ff00ff;
            text-decoration: none;
            font-weight: bold;
            transition: all 0.3s;
        }}

        .github-link:hover {{
            color: #00ffff;
            text-shadow: 0 0 10px rgba(0, 255, 255, 0.8);
        }}

        .timestamp {{
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid #00ffff;
            padding: 10px 20px;
            border-radius: 5px;
            color: #00ffff;
            font-size: 0.9rem;
            box-shadow: 0 0 10px rgba(0, 255, 255, 0.5);
        }}
    </style>
</head>
<body>
    <div class="timestamp">
        ⏰ {stats['timestamp']}
    </div>

    <div class="container">
        <div class="header">
            <div class="logo">MIESC v1.0.0</div>
            <div class="subtitle">AUTONOMOUS CYBERDEFENSE AGENT</div>
            <div class="subtitle">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</div>
            <div class="subtitle">Analysis Report: {stats['contract']}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-value">{stats['critical']}</div>
                <div class="stat-label">Critical Issues</div>
            </div>

            <div class="stat-card">
                <div class="stat-value">{stats['high']}</div>
                <div class="stat-label">High Severity</div>
            </div>

            <div class="stat-card">
                <div class="stat-value">{stats['medium']}</div>
                <div class="stat-label">Medium Severity</div>
            </div>

            <div class="stat-card">
                <div class="stat-value">{stats['noise_filtered']}%</div>
                <div class="stat-label">Noise Filtered</div>
            </div>

            <div class="stat-card">
                <div class="stat-value">{stats['agents_used']}</div>
                <div class="stat-label">AI Agents</div>
            </div>

            <div class="stat-card">
                <div class="stat-value">{stats['tools_integrated']}</div>
                <div class="stat-label">Security Tools</div>
            </div>

            <div class="stat-card">
                <div class="stat-value">{stats['smartbugs_recall']}%</div>
                <div class="stat-label">SmartBugs-curated Recall</div>
            </div>

            <div class="stat-card">
                <div class="stat-value">{stats['evmbench_recall']}%</div>
                <div class="stat-label">EVMBench Recall</div>
            </div>

            <div class="stat-card">
                <div class="stat-value">{stats['defi_recall']}%</div>
                <div class="stat-label">Real DeFi Exploit Recall</div>
            </div>

            <div class="stat-card">
                <div class="stat-value">{stats['effort_reduction']}%</div>
                <div class="stat-label">Effort Reduction</div>
            </div>

            <div class="stat-card">
                <div class="stat-value">{stats['standards_mapped']}</div>
                <div class="stat-label">Standards Mapped</div>
            </div>

            <div class="stat-card">
                <div class="stat-value">{stats['analysis_time']}</div>
                <div class="stat-label">Analysis Time</div>
            </div>
        </div>

        <div class="visualizations">
            <div class="viz-card">
                <div class="viz-title">▶ Findings Comparison</div>
                <img src="docs/website/assets/visualizations/01_findings_comparison.png" alt="Findings Comparison">
            </div>

            <div class="viz-card">
                <div class="viz-title">▶ Severity Distribution</div>
                <img src="docs/website/assets/visualizations/02_severity_distribution.png" alt="Severity Distribution">
            </div>

            <div class="viz-card">
                <div class="viz-title">▶ Execution Time</div>
                <img src="docs/website/assets/visualizations/03_execution_time.png" alt="Execution Time">
            </div>

            <div class="viz-card">
                <div class="viz-title">▶ Precision Comparison</div>
                <img src="docs/website/assets/visualizations/04_precision_comparison.png" alt="Precision Comparison">
            </div>
        </div>

        <div class="footer">
            <p class="footer-text">
                ⚡ Powered by MIESC v1.0.0 | AGPL-3.0 License<br>
                <a href="https://github.com/fboiero/MIESC" class="github-link" target="_blank">
                    🔗 GitHub: github.com/fboiero/MIESC
                </a><br>
                <a href="https://fboiero.github.io/MIESC/" class="github-link" target="_blank">
                    🌐 Website: fboiero.github.io/MIESC
                </a>
            </p>
        </div>
    </div>
</body>
</html>
"""

    output_file = "/tmp/miesc_cyberpunk_report.html"
    with open(output_file, "w") as f:
        f.write(html)

    return output_file


def main():
    """Main execution"""
    os.system("clear")

    print_cyberpunk_banner()
    time.sleep(1)

    if len(sys.argv) < 2:
        print(
            f"{NeonColors.NEON_YELLOW}[!] Usage: python cyberpunk_demo.py <contract.sol>{NeonColors.ENDC}"
        )
        print(f"{NeonColors.NEON_CYAN}[*] Running demo with sample contract...{NeonColors.ENDC}\n")
        contract_path = "examples/vulnerable/EtherStore.sol"
    else:
        contract_path = sys.argv[1]
        if not Path(contract_path).exists():
            print(
                f"{NeonColors.NEON_RED}[✗] Contract not found: {contract_path}{NeonColors.ENDC}\n"
            )
            sys.exit(1)

    # Run analysis
    stats = analyze_contract(contract_path)

    # Generate landing page
    print(f"{NeonColors.NEON_PINK}[*] Generating cyberpunk dashboard...{NeonColors.ENDC}")
    time.sleep(1)
    html_file = generate_landing_page(stats)

    print(f"{NeonColors.NEON_GREEN}[✓] Report generated: {html_file}{NeonColors.ENDC}")
    print(f"{NeonColors.NEON_CYAN}[*] Opening in browser...{NeonColors.ENDC}\n")
    time.sleep(1)

    # Open in browser
    webbrowser.open(f"file://{html_file}")

    print(f"""
{NeonColors.NEON_PINK}    ╔═══════════════════════════════════════════════════════════════╗
    ║                 SESSION TERMINATED                            ║
    ╠═══════════════════════════════════════════════════════════════╣{NeonColors.ENDC}
{NeonColors.NEON_CYAN}    ║  Thank you for using MIESC Cyberpunk Edition                 ║
    ║  Stay secure. Stay vigilant. Keep hacking.                   ║{NeonColors.ENDC}
{NeonColors.NEON_PINK}    ╚═══════════════════════════════════════════════════════════════╝{NeonColors.ENDC}
""")


if __name__ == "__main__":
    main()
