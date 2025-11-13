#!/usr/bin/env python3
"""
MIESC - Graph Visualizer
Creates visual representations of contract dependencies
"""

import os
import json
from typing import Dict, List


class GraphVisualizer:
    """Visualizes contract dependency graphs"""

    def __init__(self, analysis: Dict):
        """
        Initialize visualizer with project analysis

        Args:
            analysis: Project analysis from ProjectAnalyzer
        """
        self.analysis = analysis
        self.graph = analysis.get('dependency_graph', {})

    def generate_mermaid(self) -> str:
        """
        Generate Mermaid diagram syntax

        Returns:
            Mermaid diagram as string
        """
        lines = []
        lines.append("```mermaid")
        lines.append("graph TD")
        lines.append("")

        # Add nodes with styling
        for node in self.graph['nodes']:
            node_id = node['id'].replace(' ', '_')
            label = f"{node['label']}\\n{node['lines']} lines, {node['functions']} fn"

            if node['type'] == 'interface':
                lines.append(f"  {node_id}[{label}]:::interface")
            elif node['type'] == 'library':
                lines.append(f"  {node_id}[{label}]:::library")
            else:
                lines.append(f"  {node_id}[{label}]:::contract")

        lines.append("")

        # Add edges
        for edge in self.graph['edges']:
            from_id = edge['from'].replace(' ', '_')
            to_id = edge['to'].replace(' ', '_')

            if edge['type'] == 'inherits':
                lines.append(f"  {from_id} -.->|inherits| {to_id}")
            else:
                lines.append(f"  {from_id} -->|imports| {to_id}")

        # Add styling
        lines.append("")
        lines.append("  classDef interface fill:#e1f5ff,stroke:#01579b,stroke-width:2px")
        lines.append("  classDef library fill:#fff3e0,stroke:#e65100,stroke-width:2px")
        lines.append("  classDef contract fill:#f3e5f5,stroke:#4a148c,stroke-width:2px")
        lines.append("```")

        return '\n'.join(lines)

    def generate_dot(self) -> str:
        """
        Generate Graphviz DOT format

        Returns:
            DOT format as string
        """
        lines = []
        lines.append("digraph ContractDependencies {")
        lines.append("  rankdir=LR;")
        lines.append("  node [shape=box, style=filled];")
        lines.append("")

        # Add nodes
        for node in self.graph['nodes']:
            node_id = node['id'].replace(' ', '_')
            label = f"{node['label']}\\n{node['lines']} lines\\n{node['functions']} functions"

            if node['type'] == 'interface':
                color = "#e1f5ff"
            elif node['type'] == 'library':
                color = "#fff3e0"
            else:
                color = "#f3e5f5"

            lines.append(f'  {node_id} [label="{label}", fillcolor="{color}"];')

        lines.append("")

        # Add edges
        for edge in self.graph['edges']:
            from_id = edge['from'].replace(' ', '_')
            to_id = edge['to'].replace(' ', '_')

            if edge['type'] == 'inherits':
                lines.append(f'  {from_id} -> {to_id} [label="inherits", style=dashed];')
            else:
                lines.append(f'  {from_id} -> {to_id} [label="imports"];')

        lines.append("}")

        return '\n'.join(lines)

    def generate_ascii_tree(self) -> str:
        """
        Generate ASCII tree representation

        Returns:
            ASCII tree as string
        """
        lines = []
        lines.append("Contract Dependency Tree")
        lines.append("=" * 60)
        lines.append("")

        # Build tree structure
        roots = self._find_root_contracts()

        for root in roots:
            self._add_tree_branch(lines, root, "", set())

        return '\n'.join(lines)

    def _find_root_contracts(self) -> List[str]:
        """Find contracts with no dependencies (roots)"""
        all_contracts = {node['id'] for node in self.graph['nodes']}
        has_parents = {edge['from'] for edge in self.graph['edges']}

        roots = all_contracts - has_parents
        return sorted(roots)

    def _add_tree_branch(self, lines: List[str], contract: str, prefix: str, visited: set):
        """Recursively add tree branches"""
        if contract in visited:
            lines.append(f"{prefix}├── {contract} (circular)")
            return

        visited.add(contract)

        # Find contract info
        node = next((n for n in self.graph['nodes'] if n['id'] == contract), None)
        if not node:
            return

        symbol = "I" if node['type'] == 'interface' else "L" if node['type'] == 'library' else "C"
        info = f"[{symbol}] {node['lines']}L {node['functions']}F"

        lines.append(f"{prefix}├── {contract} {info}")

        # Find children (contracts that depend on this one)
        children = [edge['from'] for edge in self.graph['edges'] if edge['to'] == contract]

        for i, child in enumerate(sorted(children)):
            is_last = i == len(children) - 1
            new_prefix = prefix + ("    " if is_last else "│   ")
            self._add_tree_branch(lines, child, new_prefix, visited.copy())

    def generate_html_interactive(self, output_path: str):
        """
        Generate interactive HTML visualization using vis.js

        Args:
            output_path: Path to save HTML file
        """
        html_template = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>MIESC - Contract Dependency Graph</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        #header {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            margin: 0 0 10px 0;
            color: #333;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }
        .stat {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            border-left: 3px solid #007bff;
        }
        .stat-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #333;
        }
        #mynetwork {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            height: 600px;
        }
        .legend {
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .legend-item {
            display: inline-block;
            margin-right: 20px;
            margin-bottom: 10px;
        }
        .legend-box {
            display: inline-block;
            width: 20px;
            height: 20px;
            margin-right: 5px;
            border-radius: 3px;
            vertical-align: middle;
        }
    </style>
</head>
<body>
    <div id="header">
        <h1>🔍 Contract Dependency Graph</h1>
        <p>Source: <code>{{SOURCE}}</code></p>
        <div class="stats">
            <div class="stat">
                <div class="stat-label">Total Contracts</div>
                <div class="stat-value">{{TOTAL_CONTRACTS}}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Total Lines</div>
                <div class="stat-value">{{TOTAL_LINES}}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Interfaces</div>
                <div class="stat-value">{{INTERFACES}}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Libraries</div>
                <div class="stat-value">{{LIBRARIES}}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Dependencies</div>
                <div class="stat-value">{{EDGES}}</div>
            </div>
        </div>
    </div>

    <div id="mynetwork"></div>

    <div class="legend">
        <strong>Legend:</strong>
        <div class="legend-item">
            <span class="legend-box" style="background: #f3e5f5; border: 2px solid #4a148c;"></span>
            <span>Contract</span>
        </div>
        <div class="legend-item">
            <span class="legend-box" style="background: #e1f5ff; border: 2px solid #01579b;"></span>
            <span>Interface</span>
        </div>
        <div class="legend-item">
            <span class="legend-box" style="background: #fff3e0; border: 2px solid #e65100;"></span>
            <span>Library</span>
        </div>
        <div class="legend-item">
            <span style="margin-right: 5px;">━━→</span> imports
        </div>
        <div class="legend-item">
            <span style="margin-right: 5px;">╌╌→</span> inherits
        </div>
    </div>

    <script type="text/javascript">
        // Network data
        var nodes = new vis.DataSet({{NODES}});
        var edges = new vis.DataSet({{EDGES}});

        // Network configuration
        var container = document.getElementById('mynetwork');
        var data = {
            nodes: nodes,
            edges: edges
        };
        var options = {
            nodes: {
                shape: 'box',
                margin: 10,
                widthConstraint: {
                    maximum: 200
                },
                font: {
                    size: 14,
                    face: 'monospace'
                }
            },
            edges: {
                arrows: {
                    to: {
                        enabled: true,
                        scaleFactor: 0.5
                    }
                },
                font: {
                    size: 11,
                    align: 'top'
                },
                smooth: {
                    type: 'cubicBezier',
                    roundness: 0.4
                }
            },
            layout: {
                hierarchical: {
                    enabled: true,
                    direction: 'LR',
                    sortMethod: 'directed',
                    levelSeparation: 200,
                    nodeSpacing: 150
                }
            },
            physics: {
                enabled: false
            },
            interaction: {
                hover: true,
                tooltipDelay: 100
            }
        };

        // Create network
        var network = new vis.Network(container, data, options);

        // Add click handler
        network.on("click", function (params) {
            if (params.nodes.length > 0) {
                var nodeId = params.nodes[0];
                var node = nodes.get(nodeId);
                alert('Contract: ' + node.label + '\\n' +
                      'Lines: ' + node.lines + '\\n' +
                      'Functions: ' + node.functions);
            }
        });
    </script>
</body>
</html>"""

        # Prepare nodes for vis.js
        vis_nodes = []
        for node in self.graph['nodes']:
            color = {
                'interface': {'background': '#e1f5ff', 'border': '#01579b'},
                'library': {'background': '#fff3e0', 'border': '#e65100'},
                'contract': {'background': '#f3e5f5', 'border': '#4a148c'}
            }[node['type']]

            vis_nodes.append({
                'id': node['id'],
                'label': f"{node['label']}\\n{node['lines']}L {node['functions']}F",
                'color': color,
                'lines': node['lines'],
                'functions': node['functions']
            })

        # Prepare edges for vis.js
        vis_edges = []
        for edge in self.graph['edges']:
            style = 'dashed' if edge['type'] == 'inherits' else 'solid'
            vis_edges.append({
                'from': edge['from'],
                'to': edge['to'],
                'label': edge['label'],
                'dashes': edge['type'] == 'inherits'
            })

        # Replace placeholders
        stats = self.analysis['statistics']
        html = html_template.replace('{{SOURCE}}', self.analysis['source'])
        html = html.replace('{{TOTAL_CONTRACTS}}', str(stats['total_files']))
        html = html.replace('{{TOTAL_LINES}}', str(stats['total_lines']))
        html = html.replace('{{INTERFACES}}', str(stats['interfaces']))
        html = html.replace('{{LIBRARIES}}', str(stats['libraries']))
        html = html.replace('{{EDGES}}', str(len(self.graph['edges'])))
        html = html.replace('{{NODES}}', json.dumps(vis_nodes))
        html = html.replace('{{EDGES}}', json.dumps(vis_edges))

        # Write file
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_path

    def save_all_formats(self, output_dir: str):
        """
        Save visualizations in all formats

        Args:
            output_dir: Directory to save files
        """
        os.makedirs(output_dir, exist_ok=True)

        # Save Mermaid
        mermaid_path = os.path.join(output_dir, 'dependency_graph.mmd')
        with open(mermaid_path, 'w') as f:
            f.write(self.generate_mermaid())

        # Save DOT
        dot_path = os.path.join(output_dir, 'dependency_graph.dot')
        with open(dot_path, 'w') as f:
            f.write(self.generate_dot())

        # Save ASCII tree
        tree_path = os.path.join(output_dir, 'dependency_tree.txt')
        with open(tree_path, 'w') as f:
            f.write(self.generate_ascii_tree())

        # Save interactive HTML
        html_path = os.path.join(output_dir, 'dependency_graph.html')
        self.generate_html_interactive(html_path)

        return {
            'mermaid': mermaid_path,
            'dot': dot_path,
            'tree': tree_path,
            'html': html_path
        }
