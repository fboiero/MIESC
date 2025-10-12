#!/usr/bin/env python3
"""
Visualization Script for AI Tools Comparison

Generates charts and graphs from comparison results for thesis defense.

Usage:
    python visualize_comparison.py outputs/ai_tools_comparison_*.json
"""

import sys
import os
import json
import glob
from pathlib import Path
from typing import List, Dict, Any
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend

# Style
plt.style.use('seaborn-v0_8-darkgrid')
COLORS = {
    'static': '#3498db',      # Blue
    'gptscan': '#e74c3c',     # Red
    'ai_triage': '#2ecc71',   # Green
    'llm_smartaudit': '#f39c12'  # Orange
}

def load_comparison_results(file_pattern: str = "outputs/ai_tools_comparison_*.json") -> List[Dict[str, Any]]:
    """Load all comparison JSON files"""
    files = glob.glob(file_pattern)

    if not files:
        print(f"❌ No comparison files found matching: {file_pattern}")
        return []

    results = []
    for file_path in files:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                results.append(data)
                print(f"✅ Loaded: {file_path}")
        except Exception as e:
            print(f"⚠️  Error loading {file_path}: {e}")

    return results

def create_findings_comparison_chart(results: List[Dict], output_path: str):
    """Create bar chart comparing total findings across tools"""

    if not results:
        return

    # Extract data
    contracts = [r['contract'] for r in results]
    tools = ['static', 'gptscan', 'ai_triage']

    data = {tool: [] for tool in tools}

    for result in results:
        for tool in tools:
            count = result['results'].get(tool, {}).get('count', 0)
            data[tool].append(count)

    # Create chart
    fig, ax = plt.subplots(figsize=(12, 6))

    x = range(len(contracts))
    width = 0.25

    for i, tool in enumerate(tools):
        offset = width * (i - 1)
        label = tool.replace('_', ' ').title()
        ax.bar([p + offset for p in x], data[tool], width,
               label=label, color=COLORS.get(tool, '#95a5a6'))

    ax.set_xlabel('Contract', fontsize=12, fontweight='bold')
    ax.set_ylabel('Number of Findings', fontsize=12, fontweight='bold')
    ax.set_title('AI Tools Comparison: Total Findings by Contract',
                 fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels([c.replace('.sol', '') for c in contracts], rotation=45, ha='right')
    ax.legend(loc='upper right', framealpha=0.9)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"📊 Chart saved: {output_path}")
    plt.close()

def create_severity_distribution_chart(results: List[Dict], output_path: str):
    """Create stacked bar chart showing severity distribution"""

    if not results:
        return

    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    tools = ['static', 'gptscan', 'ai_triage']
    severities = ['High', 'Medium', 'Low', 'Informational']
    severity_colors = {
        'High': '#e74c3c',
        'Medium': '#f39c12',
        'Low': '#f1c40f',
        'Informational': '#95a5a6'
    }

    for idx, tool in enumerate(tools):
        ax = axes[idx]

        contracts = []
        severity_data = {sev: [] for sev in severities}

        for result in results:
            contracts.append(result['contract'].replace('.sol', ''))
            severity_count = result['results'].get(tool, {}).get('severity_count', {})

            for sev in severities:
                severity_data[sev].append(severity_count.get(sev, 0))

        # Create stacked bars
        x = range(len(contracts))
        bottom = [0] * len(contracts)

        for sev in severities:
            ax.bar(x, severity_data[sev], label=sev,
                   color=severity_colors[sev], bottom=bottom)
            bottom = [b + v for b, v in zip(bottom, severity_data[sev])]

        ax.set_title(tool.replace('_', ' ').title(), fontweight='bold')
        ax.set_ylabel('Findings Count' if idx == 0 else '')
        ax.set_xticks(x)
        ax.set_xticklabels(contracts, rotation=45, ha='right')
        ax.legend(loc='upper right', fontsize=8)
        ax.grid(axis='y', alpha=0.3)

    fig.suptitle('Severity Distribution by Tool', fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"📊 Chart saved: {output_path}")
    plt.close()

def create_execution_time_chart(results: List[Dict], output_path: str):
    """Create line chart comparing execution times"""

    if not results:
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    tools = ['static', 'gptscan', 'ai_triage']

    contracts = [r['contract'].replace('.sol', '') for r in results]

    for tool in tools:
        times = []
        for result in results:
            time = result['results'].get(tool, {}).get('execution_time', 0)
            times.append(time)

        ax.plot(contracts, times, marker='o', linewidth=2,
                label=tool.replace('_', ' ').title(),
                color=COLORS.get(tool, '#95a5a6'))

    ax.set_xlabel('Contract', fontsize=12, fontweight='bold')
    ax.set_ylabel('Execution Time (seconds)', fontsize=12, fontweight='bold')
    ax.set_title('Execution Time Comparison', fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='upper right', framealpha=0.9)
    ax.grid(True, alpha=0.3)
    plt.xticks(rotation=45, ha='right')

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"📊 Chart saved: {output_path}")
    plt.close()

def create_precision_comparison_chart(results: List[Dict], output_path: str):
    """Create chart showing precision metrics (if available)"""

    if not results:
        return

    fig, ax = plt.subplots(figsize=(10, 6))

    contracts = [r['contract'].replace('.sol', '') for r in results]
    tools = ['static', 'gptscan', 'ai_triage']

    # Calculate precision as (High + Medium) / Total
    precision_data = {tool: [] for tool in tools}

    for result in results:
        for tool in tools:
            tool_results = result['results'].get(tool, {})
            severity_count = tool_results.get('severity_count', {})
            total = tool_results.get('count', 0)

            if total > 0:
                critical = severity_count.get('High', 0) + severity_count.get('Medium', 0)
                precision = (critical / total) * 100
            else:
                precision = 0

            precision_data[tool].append(precision)

    x = range(len(contracts))
    width = 0.25

    for i, tool in enumerate(tools):
        offset = width * (i - 1)
        label = tool.replace('_', ' ').title()
        ax.bar([p + offset for p in x], precision_data[tool], width,
               label=label, color=COLORS.get(tool, '#95a5a6'))

    ax.set_xlabel('Contract', fontsize=12, fontweight='bold')
    ax.set_ylabel('Precision (% High+Medium)', fontsize=12, fontweight='bold')
    ax.set_title('Critical Findings Precision', fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(contracts, rotation=45, ha='right')
    ax.legend(loc='upper right', framealpha=0.9)
    ax.grid(axis='y', alpha=0.3)
    ax.set_ylim(0, 100)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"📊 Chart saved: {output_path}")
    plt.close()

def create_summary_table(results: List[Dict], output_path: str):
    """Create summary statistics table"""

    if not results:
        return

    summary = []

    for result in results:
        contract = result['contract']

        for tool_name in ['static', 'gptscan', 'ai_triage']:
            tool_data = result['results'].get(tool_name, {})

            if tool_data.get('success'):
                summary.append({
                    'Contract': contract.replace('.sol', ''),
                    'Tool': tool_name.replace('_', ' ').title(),
                    'Findings': tool_data.get('count', 0),
                    'High': tool_data.get('severity_count', {}).get('High', 0),
                    'Medium': tool_data.get('severity_count', {}).get('Medium', 0),
                    'Low': tool_data.get('severity_count', {}).get('Low', 0),
                    'Time (s)': f"{tool_data.get('execution_time', 0):.2f}"
                })

    # Create table figure
    fig, ax = plt.subplots(figsize=(12, len(summary) * 0.4 + 2))
    ax.axis('off')

    # Convert to table data
    headers = list(summary[0].keys())
    table_data = [[str(row[h]) for h in headers] for row in summary]

    table = ax.table(cellText=table_data, colLabels=headers,
                     cellLoc='center', loc='center',
                     colWidths=[0.15, 0.15, 0.1, 0.1, 0.1, 0.1, 0.15])

    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 2)

    # Style header
    for i in range(len(headers)):
        table[(0, i)].set_facecolor('#3498db')
        table[(0, i)].set_text_props(weight='bold', color='white')

    # Alternate row colors
    for i in range(1, len(summary) + 1):
        for j in range(len(headers)):
            if i % 2 == 0:
                table[(i, j)].set_facecolor('#ecf0f1')

    plt.title('Summary Statistics Table', fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"📊 Table saved: {output_path}")
    plt.close()

def generate_all_visualizations(results: List[Dict], output_dir: str = "outputs/visualizations"):
    """Generate all visualization charts"""

    os.makedirs(output_dir, exist_ok=True)

    print("\n📊 Generating visualizations...")

    # 1. Total findings comparison
    create_findings_comparison_chart(
        results,
        os.path.join(output_dir, "01_findings_comparison.png")
    )

    # 2. Severity distribution
    create_severity_distribution_chart(
        results,
        os.path.join(output_dir, "02_severity_distribution.png")
    )

    # 3. Execution time
    create_execution_time_chart(
        results,
        os.path.join(output_dir, "03_execution_time.png")
    )

    # 4. Precision comparison
    create_precision_comparison_chart(
        results,
        os.path.join(output_dir, "04_precision_comparison.png")
    )

    # 5. Summary table
    create_summary_table(
        results,
        os.path.join(output_dir, "05_summary_table.png")
    )

    print(f"\n✅ All visualizations generated in: {output_dir}/")
    print(f"\n📁 Files:")
    for f in sorted(glob.glob(os.path.join(output_dir, "*.png"))):
        print(f"   - {os.path.basename(f)}")

def main():
    print("=" * 60)
    print("📊 MIESC - AI Tools Comparison Visualizations")
    print("=" * 60)

    # Load results
    if len(sys.argv) > 1:
        pattern = sys.argv[1]
    else:
        pattern = "outputs/ai_tools_comparison_*.json"

    print(f"\n🔍 Loading results from: {pattern}")
    results = load_comparison_results(pattern)

    if not results:
        print("\n❌ No results found. Run demo_ai_tools_comparison.py first.")
        sys.exit(1)

    print(f"\n✅ Loaded {len(results)} comparison results")

    # Generate visualizations
    generate_all_visualizations(results)

    print("\n" + "=" * 60)
    print("✅ Visualization Complete")
    print("=" * 60)
    print("\n💡 Use these charts for your thesis defense presentation!")
    print()

if __name__ == "__main__":
    main()
