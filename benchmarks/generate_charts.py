#!/usr/bin/env python3
"""
Generate scientific charts for SmartBugs evaluation results.
"""

import json
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

RESULTS_PATH = Path(__file__).parent / "results"

# Load latest results
results_files = sorted(RESULTS_PATH.glob("smartbugs_evaluation_*.json"))
if not results_files:
    print("No results found")
    exit(1)

latest_results = results_files[-1]
print(f"Loading: {latest_results}")

with open(latest_results) as f:
    data = json.load(f)

# Extract data
categories = list(data['by_category'].keys())
recalls = [data['by_category'][c]['recall'] * 100 for c in categories]
precisions = [data['by_category'][c]['precision'] * 100 for c in categories]
contracts = [data['by_category'][c]['contracts'] for c in categories]

# Sort by recall
sorted_indices = np.argsort(recalls)[::-1]
categories = [categories[i] for i in sorted_indices]
recalls = [recalls[i] for i in sorted_indices]
precisions = [precisions[i] for i in sorted_indices]
contracts = [contracts[i] for i in sorted_indices]

# Create figure with 2 subplots
fig, axes = plt.subplots(1, 2, figsize=(14, 6))

# Chart 1: Recall by Category
ax1 = axes[0]
colors = ['#2ecc71' if r > 50 else '#f39c12' if r > 20 else '#e74c3c' for r in recalls]
bars1 = ax1.barh(categories, recalls, color=colors)
ax1.set_xlabel('Recall (%)', fontsize=12)
ax1.set_title('Detection Recall by Vulnerability Category', fontsize=14, fontweight='bold')
ax1.set_xlim(0, 100)
ax1.axvline(x=50, color='gray', linestyle='--', alpha=0.5, label='50% threshold')

# Add value labels
for bar, val in zip(bars1, recalls):
    ax1.text(val + 2, bar.get_y() + bar.get_height()/2, f'{val:.1f}%',
             va='center', fontsize=10)

# Chart 2: Comparison with literature
ax2 = axes[1]
tools = ['MIESC v4.1\n(This Study)', 'Slither', 'Securify', 'Mythril', 'SmartCheck']
lit_recalls = [50.22, 43.2, 36.8, 27.4, 18.9]
lit_colors = ['#3498db', '#95a5a6', '#95a5a6', '#95a5a6', '#95a5a6']

bars2 = ax2.bar(tools, lit_recalls, color=lit_colors)
ax2.set_ylabel('Recall (%)', fontsize=12)
ax2.set_title('Comparison with Literature\n(Durieux et al., ICSE 2020)', fontsize=14, fontweight='bold')
ax2.set_ylim(0, 60)

# Add value labels
for bar, val in zip(bars2, lit_recalls):
    ax2.text(bar.get_x() + bar.get_width()/2, val + 1, f'{val:.1f}%',
             ha='center', fontsize=10, fontweight='bold')

plt.tight_layout()

# Save figure
output_file = RESULTS_PATH / "smartbugs_evaluation_chart.png"
plt.savefig(output_file, dpi=300, bbox_inches='tight')
print(f"Chart saved: {output_file}")

# Also save to thesis figures directory
thesis_fig = Path(__file__).parent.parent / "thesis_generator" / "figuras" / "Figura 31 SmartBugs Evaluation Results.png"
plt.savefig(thesis_fig, dpi=300, bbox_inches='tight')
print(f"Chart saved: {thesis_fig}")

plt.close()
print("Done!")
