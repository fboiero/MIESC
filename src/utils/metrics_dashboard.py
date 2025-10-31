#!/usr/bin/env python3
"""
Metrics Dashboard Generator for Xaudit
Creates visualizations and HTML dashboard from analysis results
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
except ImportError:
    print("Warning: matplotlib not installed. Run: pip install matplotlib")
    plt = None


class XauditDashboard:
    """Generate metrics dashboard from analysis results."""

    def __init__(self, results_dir: str):
        self.results_dir = Path(results_dir)
        self.metrics = self.collect_metrics()

    def collect_metrics(self) -> Dict:
        """Collect all metrics from analysis results."""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'slither': self._collect_slither_metrics(),
            'foundry': self._collect_foundry_metrics(),
            'echidna': self._collect_echidna_metrics(),
            'summary': {}
        }

        # Calculate summary
        metrics['summary'] = {
            'total_issues': sum(m.get('count', 0) for m in metrics['slither'].values()),
            'critical': metrics['slither'].get('high', {}).get('count', 0),
            'high': metrics['slither'].get('medium', {}).get('count', 0),
            'medium': metrics['slither'].get('low', {}).get('count', 0),
            'tests_passed': metrics['foundry'].get('passed', 0),
            'tests_failed': metrics['foundry'].get('failed', 0),
            'properties_violated': metrics['echidna'].get('violated', 0)
        }

        return metrics

    def _collect_slither_metrics(self) -> Dict:
        """Parse Slither JSON results."""
        slither_dir = self.results_dir / 'slither'
        if not slither_dir.exists():
            return {}

        issues_by_severity = {'high': [], 'medium': [], 'low': [], 'info': []}

        for json_file in slither_dir.glob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    detectors = data.get('results', {}).get('detectors', [])

                    for detector in detectors:
                        impact = detector.get('impact', 'info').lower()
                        if impact in issues_by_severity:
                            issues_by_severity[impact].append({
                                'check': detector.get('check'),
                                'description': detector.get('description', '')[:100],
                                'confidence': detector.get('confidence')
                            })
            except Exception as e:
                print(f"Warning: Failed to parse {json_file}: {e}")

        return {
            severity: {'count': len(issues), 'issues': issues}
            for severity, issues in issues_by_severity.items()
        }

    def _collect_foundry_metrics(self) -> Dict:
        """Parse Foundry test results."""
        foundry_dir = self.results_dir / 'foundry'
        if not foundry_dir.exists():
            return {'passed': 0, 'failed': 0}

        test_file = foundry_dir / 'test_results.txt'
        if not test_file.exists():
            return {'passed': 0, 'failed': 0}

        try:
            content = test_file.read_text()
            # Parse Foundry output (simplified)
            passed = content.count('[PASS]')
            failed = content.count('[FAIL]')
            return {'passed': passed, 'failed': failed, 'total': passed + failed}
        except:
            return {'passed': 0, 'failed': 0}

    def _collect_echidna_metrics(self) -> Dict:
        """Parse Echidna results."""
        echidna_dir = self.results_dir / 'echidna'
        if not echidna_dir.exists():
            return {'violated': 0, 'passed': 0}

        violated = 0
        passed = 0

        for txt_file in echidna_dir.glob('*.txt'):
            try:
                content = txt_file.read_text()
                violated += content.count('failed!')
                passed += content.count('passed!')
            except:
                pass

        return {'violated': violated, 'passed': passed, 'total': violated + passed}

    def generate_charts(self, output_dir: Path):
        """Generate visualization charts."""
        if plt is None:
            print("Skipping chart generation (matplotlib not available)")
            return

        output_dir.mkdir(parents=True, exist_ok=True)

        # Chart 1: Issues by Severity
        self._chart_severity_distribution(output_dir)

        # Chart 2: Test Results
        self._chart_test_results(output_dir)

        # Chart 3: Summary Dashboard
        self._chart_summary_dashboard(output_dir)

        print(f"Charts saved to: {output_dir}")

    def _chart_severity_distribution(self, output_dir: Path):
        """Bar chart of issues by severity."""
        severities = ['Critical', 'High', 'Medium', 'Low']
        counts = [
            self.metrics['slither'].get('high', {}).get('count', 0),
            self.metrics['slither'].get('medium', {}).get('count', 0),
            self.metrics['slither'].get('low', {}).get('count', 0),
            self.metrics['slither'].get('info', {}).get('count', 0)
        ]

        colors = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c']

        plt.figure(figsize=(10, 6))
        bars = plt.bar(severities, counts, color=colors)

        plt.xlabel('Severity', fontsize=12, fontweight='bold')
        plt.ylabel('Number of Issues', fontsize=12, fontweight='bold')
        plt.title('Vulnerability Distribution by Severity', fontsize=14, fontweight='bold')
        plt.grid(axis='y', alpha=0.3)

        # Add count labels on bars
        for bar, count in zip(bars, counts):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(count)}',
                    ha='center', va='bottom', fontweight='bold')

        plt.tight_layout()
        plt.savefig(output_dir / 'severity_distribution.png', dpi=300)
        plt.close()

    def _chart_test_results(self, output_dir: Path):
        """Pie chart of test results."""
        foundry = self.metrics['foundry']
        echidna = self.metrics['echidna']

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # Foundry tests
        foundry_data = [foundry.get('passed', 0), foundry.get('failed', 0)]
        foundry_labels = ['Passed', 'Failed']
        foundry_colors = ['#4caf50', '#f44336']

        ax1.pie(foundry_data, labels=foundry_labels, colors=foundry_colors,
                autopct='%1.1f%%', startangle=90)
        ax1.set_title('Foundry Test Results', fontsize=14, fontweight='bold')

        # Echidna properties
        echidna_data = [echidna.get('passed', 0), echidna.get('violated', 0)]
        echidna_labels = ['Passed', 'Violated']
        echidna_colors = ['#4caf50', '#f44336']

        ax2.pie(echidna_data, labels=echidna_labels, colors=echidna_colors,
                autopct='%1.1f%%', startangle=90)
        ax2.set_title('Echidna Property Results', fontsize=14, fontweight='bold')

        plt.tight_layout()
        plt.savefig(output_dir / 'test_results.png', dpi=300)
        plt.close()

    def _chart_summary_dashboard(self, output_dir: Path):
        """Summary dashboard with key metrics."""
        fig, ax = plt.subplots(figsize=(12, 8))
        ax.axis('off')

        summary = self.metrics['summary']

        # Title
        title_text = "Xaudit Analysis Summary"
        ax.text(0.5, 0.95, title_text, ha='center', fontsize=20, fontweight='bold')

        # Metrics boxes
        metrics_data = [
            ("Total Issues", summary['total_issues'], '#2196f3'),
            ("Critical", summary['critical'], '#d32f2f'),
            ("High", summary['high'], '#f57c00'),
            ("Medium", summary['medium'], '#fbc02d'),
            ("Tests Passed", summary['tests_passed'], '#4caf50'),
            ("Tests Failed", summary['tests_failed'], '#f44336'),
        ]

        y_pos = 0.75
        for i, (label, value, color) in enumerate(metrics_data):
            x_pos = 0.15 + (i % 3) * 0.3
            if i >= 3:
                y_pos = 0.45

            # Draw box
            box = plt.Rectangle((x_pos - 0.1, y_pos - 0.05), 0.2, 0.2,
                               facecolor=color, alpha=0.2, edgecolor=color, linewidth=2)
            ax.add_patch(box)

            # Add text
            ax.text(x_pos, y_pos + 0.08, str(value), ha='center', fontsize=24, fontweight='bold', color=color)
            ax.text(x_pos, y_pos - 0.02, label, ha='center', fontsize=12)

        # Timestamp
        ax.text(0.5, 0.05, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                ha='center', fontsize=10, style='italic', color='gray')

        plt.tight_layout()
        plt.savefig(output_dir / 'summary_dashboard.png', dpi=300)
        plt.close()

    def generate_html_report(self, output_file: Path):
        """Generate HTML dashboard."""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Xaudit Analysis Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #1976d2; text-align: center; }}
        .metrics {{ display: flex; justify-content: space-around; flex-wrap: wrap; margin: 30px 0; }}
        .metric {{ background: #f0f0f0; padding: 20px; border-radius: 8px; min-width: 150px; text-align: center; margin: 10px; }}
        .metric .value {{ font-size: 36px; font-weight: bold; color: #1976d2; }}
        .metric .label {{ font-size: 14px; color: #666; margin-top: 5px; }}
        .critical {{ border-left: 5px solid #d32f2f; }}
        .high {{ border-left: 5px solid #f57c00; }}
        .medium {{ border-left: 5px solid #fbc02d; }}
        .chart {{ margin: 30px 0; text-align: center; }}
        .chart img {{ max-width: 100%; height: auto; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #1976d2; color: white; }}
        .footer {{ text-align: center; color: #999; margin-top: 30px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Xaudit Analysis Dashboard</h1>
        <p style="text-align: center; color: #666;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="metrics">
            <div class="metric critical">
                <div class="value">{self.metrics['summary']['critical']}</div>
                <div class="label">Critical Issues</div>
            </div>
            <div class="metric high">
                <div class="value">{self.metrics['summary']['high']}</div>
                <div class="label">High Issues</div>
            </div>
            <div class="metric medium">
                <div class="value">{self.metrics['summary']['medium']}</div>
                <div class="label">Medium Issues</div>
            </div>
            <div class="metric">
                <div class="value">{self.metrics['summary']['tests_passed']}</div>
                <div class="label">Tests Passed</div>
            </div>
            <div class="metric">
                <div class="value">{self.metrics['summary']['tests_failed']}</div>
                <div class="label">Tests Failed</div>
            </div>
        </div>

        <div class="chart">
            <h2>Vulnerability Distribution</h2>
            <img src="severity_distribution.png" alt="Severity Distribution">
        </div>

        <div class="chart">
            <h2>Test Results</h2>
            <img src="test_results.png" alt="Test Results">
        </div>

        <div class="chart">
            <h2>Summary Dashboard</h2>
            <img src="summary_dashboard.png" alt="Summary">
        </div>

        <div class="footer">
            <p>Generated by Xaudit - Hybrid Smart Contract Auditing Framework</p>
            <p>Universidad Tecnológica Nacional - FRVM | Fernando Boiero</p>
        </div>
    </div>
</body>
</html>
"""

        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(html_content)
        print(f"HTML dashboard saved to: {output_file}")

    def save_metrics_json(self, output_file: Path):
        """Save metrics as JSON."""
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        print(f"Metrics JSON saved to: {output_file}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate Xaudit Metrics Dashboard")
    parser.add_argument("--results", required=True, help="Path to analysis results directory")
    parser.add_argument("--output", default="analysis/dashboard", help="Output directory for dashboard")

    args = parser.parse_args()

    results_dir = Path(args.results)
    output_dir = Path(args.output)

    if not results_dir.exists():
        print(f"Error: Results directory not found: {results_dir}")
        sys.exit(1)

    print("Generating dashboard...")
    dashboard = XauditDashboard(results_dir)

    # Generate outputs
    dashboard.generate_charts(output_dir)
    dashboard.generate_html_report(output_dir / "index.html")
    dashboard.save_metrics_json(output_dir / "metrics.json")

    print(f"\n✅ Dashboard generated successfully!")
    print(f"\nOpen in browser: file://{output_dir.absolute()}/index.html")


if __name__ == "__main__":
    main()
