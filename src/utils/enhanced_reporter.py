#!/usr/bin/env python3
"""
Enhanced Reporter for Xaudit v2.0
Supports all 10 tools with advanced reporting capabilities
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict

@dataclass
class Finding:
    """Structured finding from any tool."""
    tool: str
    severity: str
    category: str
    title: str
    description: str
    location: Dict[str, Any]
    confidence: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    swc_id: Optional[str] = None
    ai_classification: Optional[Dict] = None

@dataclass
class ExecutiveSummary:
    """Executive summary of the audit."""
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    tools_executed: List[str]
    analysis_duration: str
    contracts_analyzed: int
    lines_of_code: int
    coverage_percentage: float
    exploits_generated: int
    invariants_tested: int
    properties_violated: int
    ai_false_positives_filtered: int

class EnhancedReporter:
    """
    Enhanced reporting system for Xaudit v2.0
    Generates comprehensive reports from all 10 tools
    """

    SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational']

    TOOL_NAMES = {
        'solhint': 'Solhint (Linting)',
        'slither': 'Slither (Static Analysis)',
        'surya': 'Surya (Visualization)',
        'mythril': 'Mythril (Symbolic - SMT)',
        'manticore': 'Manticore (Symbolic - Dynamic)',
        'echidna': 'Echidna (Fuzzing - Property)',
        'medusa': 'Medusa (Fuzzing - Coverage)',
        'foundry_fuzz': 'Foundry (Fuzzing - Stateless)',
        'foundry_invariants': 'Foundry (Invariant Testing)',
        'certora': 'Certora (Formal Verification)',
        'ai_triage': 'AI Triage (GPT-4o-mini)'
    }

    def __init__(self, results_dir: Path):
        self.results_dir = Path(results_dir)
        self.findings: List[Finding] = []
        self.metrics = defaultdict(dict)
        self.timestamp = datetime.now()
        self.start_time = None  # Will be set if analysis timing is tracked

    def collect_all_findings(self):
        """Collect findings from all tools."""
        print("Collecting findings from all tools...")

        # 1. Solhint
        self._collect_solhint()

        # 2. Slither
        self._collect_slither()

        # 3. Surya (metrics only, no findings)
        self._collect_surya()

        # 4. Mythril
        self._collect_mythril()

        # 5. Manticore
        self._collect_manticore()

        # 6. Echidna
        self._collect_echidna()

        # 7. Medusa
        self._collect_medusa()

        # 8. Foundry Fuzz
        self._collect_foundry_fuzz()

        # 9. Foundry Invariants
        self._collect_foundry_invariants()

        # 10. Certora
        self._collect_certora()

        # 11. AI Triage
        self._collect_ai_triage()

        print(f"Total findings collected: {len(self.findings)}")

    def _collect_solhint(self):
        """Parse Solhint JSON results."""
        solhint_dir = self.results_dir / 'solhint'
        if not solhint_dir.exists():
            return

        for json_file in solhint_dir.glob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    for issue in data:
                        self.findings.append(Finding(
                            tool='solhint',
                            severity=issue.get('severity', 'low'),
                            category=issue.get('type', 'style'),
                            title=issue.get('ruleId', 'Unknown'),
                            description=issue.get('message', ''),
                            location={
                                'file': str(json_file),
                                'line': issue.get('line', 0),
                                'column': issue.get('column', 0)
                            }
                        ))
            except Exception as e:
                print(f"Warning: Failed to parse Solhint {json_file}: {e}")

    def _collect_slither(self):
        """Parse Slither JSON results."""
        slither_dir = self.results_dir / 'slither'
        if not slither_dir.exists():
            return

        for json_file in slither_dir.glob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    detectors = data.get('results', {}).get('detectors', [])

                    for detector in detectors:
                        self.findings.append(Finding(
                            tool='slither',
                            severity=detector.get('impact', 'informational').lower(),
                            category=detector.get('check', 'unknown'),
                            title=detector.get('check', 'Unknown'),
                            description=detector.get('description', ''),
                            location={
                                'file': detector.get('elements', [{}])[0].get('source_mapping', {}).get('filename_relative', 'unknown'),
                                'line': detector.get('elements', [{}])[0].get('source_mapping', {}).get('lines', [0])[0]
                            },
                            confidence=detector.get('confidence'),
                            impact=detector.get('impact')
                        ))
            except Exception as e:
                print(f"Warning: Failed to parse Slither {json_file}: {e}")

    def _collect_surya(self):
        """Collect Surya metrics (no findings)."""
        surya_dir = self.results_dir / 'surya' / 'outputs'
        if not surya_dir.exists():
            return

        metrics_file = surya_dir / 'metrics.txt'
        if metrics_file.exists():
            try:
                content = metrics_file.read_text()
                # Parse metrics (simplified)
                self.metrics['surya'] = {
                    'complexity_analyzed': True,
                    'graphs_generated': True
                }
            except Exception as e:
                print(f"Warning: Failed to parse Surya metrics: {e}")

    def _collect_mythril(self):
        """Parse Mythril JSON results."""
        mythril_dir = self.results_dir / 'mythril'
        if not mythril_dir.exists():
            return

        for json_file in mythril_dir.glob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    issues = data.get('issues', [])

                    for issue in issues:
                        self.findings.append(Finding(
                            tool='mythril',
                            severity=issue.get('severity', 'medium').lower(),
                            category=issue.get('title', 'unknown'),
                            title=issue.get('title', 'Unknown'),
                            description=issue.get('description', ''),
                            location={
                                'file': issue.get('filename', 'unknown'),
                                'line': issue.get('lineno', 0)
                            },
                            swc_id=issue.get('swc-id')
                        ))
            except Exception as e:
                print(f"Warning: Failed to parse Mythril {json_file}: {e}")

    def _collect_manticore(self):
        """Parse Manticore results and exploits."""
        manticore_dir = self.results_dir / 'manticore'
        if not manticore_dir.exists():
            return

        exploits_count = len(list(manticore_dir.glob('exploit_*.sol')))
        self.metrics['manticore'] = {
            'exploits_generated': exploits_count
        }

        # Parse workspace for findings
        for workspace in manticore_dir.glob('mcore_*'):
            try:
                test_files = list(workspace.glob('test_*.txt'))
                for test_file in test_files:
                    content = test_file.read_text()
                    if 'REVERT' not in content and 'SUCCESS' in content:
                        # Found a vulnerability
                        self.findings.append(Finding(
                            tool='manticore',
                            severity='high',
                            category='symbolic_execution',
                            title='Symbolic Execution Vulnerability',
                            description=f'Exploit path found: {test_file.name}',
                            location={'file': str(workspace)}
                        ))
            except Exception as e:
                print(f"Warning: Failed to parse Manticore workspace: {e}")

    def _collect_echidna(self):
        """Parse Echidna results."""
        echidna_dir = self.results_dir / 'echidna'
        if not echidna_dir.exists():
            return

        for txt_file in echidna_dir.glob('*.txt'):
            try:
                content = txt_file.read_text()
                lines = content.split('\n')

                for line in lines:
                    if 'failed!' in line:
                        # Property violated
                        prop_name = line.split(':')[0].strip() if ':' in line else 'unknown'
                        self.findings.append(Finding(
                            tool='echidna',
                            severity='high',
                            category='property_violation',
                            title=f'Property violated: {prop_name}',
                            description=line,
                            location={'file': str(txt_file)}
                        ))
            except Exception as e:
                print(f"Warning: Failed to parse Echidna {txt_file}: {e}")

    def _collect_medusa(self):
        """Parse Medusa results."""
        medusa_dir = self.results_dir / 'medusa'
        if not medusa_dir.exists():
            return

        for json_file in medusa_dir.glob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    # Parse Medusa results (structure depends on version)
                    # Simplified parsing
                    if 'fuzzing' in data:
                        test_results = data['fuzzing'].get('test_results', {})
                        for test_name, result in test_results.items():
                            if result.get('status') == 'FAILED':
                                self.findings.append(Finding(
                                    tool='medusa',
                                    severity='high',
                                    category='assertion_failure',
                                    title=f'Test failed: {test_name}',
                                    description=result.get('message', ''),
                                    location={'file': str(json_file)}
                                ))
            except Exception as e:
                print(f"Warning: Failed to parse Medusa {json_file}: {e}")

    def _collect_foundry_fuzz(self):
        """Parse Foundry fuzz test results."""
        foundry_dir = self.results_dir / 'foundry'
        if not foundry_dir.exists():
            return

        fuzz_results = foundry_dir / 'fuzz_results.txt'
        if fuzz_results.exists():
            try:
                content = fuzz_results.read_text()
                # Parse [FAIL] lines
                for line in content.split('\n'):
                    if '[FAIL]' in line:
                        self.findings.append(Finding(
                            tool='foundry_fuzz',
                            severity='medium',
                            category='fuzz_failure',
                            title='Fuzz test failed',
                            description=line.strip(),
                            location={'file': str(fuzz_results)}
                        ))
            except Exception as e:
                print(f"Warning: Failed to parse Foundry fuzz: {e}")

    def _collect_foundry_invariants(self):
        """Parse Foundry invariant test results."""
        foundry_dir = self.results_dir / 'foundry'
        if not foundry_dir.exists():
            return

        for log_file in foundry_dir.glob('invariant_*.log'):
            try:
                content = log_file.read_text()
                # Look for invariant violations
                if 'FAILED' in content or 'violated' in content.lower():
                    # Extract invariant name
                    for line in content.split('\n'):
                        if 'invariant_' in line:
                            self.findings.append(Finding(
                                tool='foundry_invariants',
                                severity='critical',
                                category='invariant_violation',
                                title='Invariant violated',
                                description=line.strip(),
                                location={'file': str(log_file)}
                            ))
            except Exception as e:
                print(f"Warning: Failed to parse Foundry invariants: {e}")

    def _collect_certora(self):
        """Parse Certora verification results."""
        certora_dir = self.results_dir / 'certora'
        if not certora_dir.exists():
            return

        for json_file in certora_dir.glob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    rules = data.get('rules', [])

                    for rule in rules:
                        if rule.get('status') == 'VIOLATED':
                            self.findings.append(Finding(
                                tool='certora',
                                severity='critical',
                                category='formal_verification',
                                title=f"Rule violated: {rule.get('name', 'unknown')}",
                                description=rule.get('message', ''),
                                location={'file': str(json_file)}
                            ))
            except Exception as e:
                print(f"Warning: Failed to parse Certora {json_file}: {e}")

    def _collect_ai_triage(self):
        """Collect AI triage classifications."""
        ai_dir = self.results_dir / 'ai_triage'
        if not ai_dir.exists():
            return

        triage_file = ai_dir / 'classification.json'
        if triage_file.exists():
            try:
                with open(triage_file) as f:
                    data = json.load(f)
                    self.metrics['ai_triage'] = {
                        'false_positives_filtered': data.get('fp_filtered', 0),
                        'findings_reclassified': data.get('reclassified', 0)
                    }

                    # Add AI classifications to findings
                    classifications = data.get('classifications', [])
                    for idx, classification in enumerate(classifications):
                        if idx < len(self.findings):
                            self.findings[idx].ai_classification = classification
            except Exception as e:
                print(f"Warning: Failed to parse AI triage: {e}")

    def _calculate_analysis_duration(self) -> str:
        """Calculate analysis duration from start_time if available."""
        if self.start_time:
            duration = self.timestamp - self.start_time
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            if hours > 0:
                return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
            elif minutes > 0:
                return f"{int(minutes)}m {int(seconds)}s"
            else:
                return f"{int(seconds)}s"
        return "N/A"

    def _calculate_lines_of_code(self) -> int:
        """Calculate total lines of code in analyzed Solidity contracts."""
        total_loc = 0
        try:
            for sol_file in self.results_dir.glob('**/*.sol'):
                try:
                    with open(sol_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        # Count non-empty, non-comment-only lines
                        code_lines = [
                            line for line in lines
                            if line.strip() and not line.strip().startswith('//')
                        ]
                        total_loc += len(code_lines)
                except Exception as e:
                    print(f"Warning: Could not read {sol_file}: {e}")
        except Exception as e:
            print(f"Warning: Failed to calculate LOC: {e}")
        return total_loc

    def _calculate_coverage_percentage(self) -> float:
        """Calculate code coverage from fuzzing results."""
        # Try to get coverage from fuzzing tools
        coverage = 0.0

        # Check Medusa results
        if 'medusa' in self.metrics:
            coverage = max(coverage, self.metrics['medusa'].get('coverage_percentage', 0.0))

        # Check Echidna results
        if 'echidna' in self.metrics:
            coverage = max(coverage, self.metrics['echidna'].get('coverage_percentage', 0.0))

        # Check Foundry results
        if 'foundry_fuzz' in self.metrics:
            coverage = max(coverage, self.metrics['foundry_fuzz'].get('coverage_percentage', 0.0))

        return coverage

    def generate_executive_summary(self) -> ExecutiveSummary:
        """Generate executive summary."""
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity_counts[finding.severity] += 1

        tools_executed = list(set(f.tool for f in self.findings))

        return ExecutiveSummary(
            total_findings=len(self.findings),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            info_count=severity_counts.get('informational', 0) + severity_counts.get('info', 0),
            tools_executed=tools_executed,
            analysis_duration=self._calculate_analysis_duration(),
            contracts_analyzed=len(list(self.results_dir.glob('**/*.sol'))),
            lines_of_code=self._calculate_lines_of_code(),
            coverage_percentage=self._calculate_coverage_percentage(),
            exploits_generated=self.metrics.get('manticore', {}).get('exploits_generated', 0),
            invariants_tested=len([f for f in self.findings if f.tool == 'foundry_invariants']),
            properties_violated=len([f for f in self.findings if f.tool in ['echidna', 'medusa']]),
            ai_false_positives_filtered=self.metrics.get('ai_triage', {}).get('false_positives_filtered', 0)
        )

    def generate_json_report(self, output_file: Path):
        """Generate comprehensive JSON report."""
        summary = self.generate_executive_summary()

        report = {
            'metadata': {
                'version': '2.0',
                'timestamp': self.timestamp.isoformat(),
                'results_directory': str(self.results_dir),
                'generator': 'Xaudit Enhanced Reporter'
            },
            'executive_summary': asdict(summary),
            'findings': [asdict(f) for f in sorted(
                self.findings,
                key=lambda x: (self.SEVERITY_ORDER.index(x.severity) if x.severity in self.SEVERITY_ORDER else 999, x.tool)
            )],
            'metrics_by_tool': dict(self.metrics),
            'statistics': self._generate_statistics()
        }

        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"✅ JSON report saved to: {output_file}")

    def _generate_statistics(self) -> Dict:
        """Generate detailed statistics."""
        stats = {
            'by_severity': defaultdict(int),
            'by_tool': defaultdict(int),
            'by_category': defaultdict(int),
            'tools_summary': {}
        }

        for finding in self.findings:
            stats['by_severity'][finding.severity] += 1
            stats['by_tool'][finding.tool] += 1
            stats['by_category'][finding.category] += 1

        # Convert defaultdicts to regular dicts
        stats['by_severity'] = dict(stats['by_severity'])
        stats['by_tool'] = dict(stats['by_tool'])
        stats['by_category'] = dict(stats['by_category'])

        # Tools summary
        for tool_key, tool_name in self.TOOL_NAMES.items():
            count = stats['by_tool'].get(tool_key, 0)
            stats['tools_summary'][tool_name] = {
                'findings': count,
                'executed': tool_key in [f.tool for f in self.findings] or tool_key in self.metrics
            }

        return stats

    def generate_markdown_report(self, output_file: Path):
        """Generate Markdown report for GitHub/GitLab."""
        summary = self.generate_executive_summary()
        stats = self._generate_statistics()

        md_content = f"""# 🔍 Xaudit Security Analysis Report

**Generated:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
**Framework Version:** Xaudit v2.0
**Analysis Pipeline:** 12 Phases, 10 Tools

---

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| **Total Findings** | {summary.total_findings} |
| **Critical** | 🔴 {summary.critical_count} |
| **High** | 🟠 {summary.high_count} |
| **Medium** | 🟡 {summary.medium_count} |
| **Low** | 🟢 {summary.low_count} |
| **Informational** | ℹ️ {summary.info_count} |
| **Exploits Generated** | ⚡ {summary.exploits_generated} (Manticore) |
| **Invariants Tested** | 🧪 {summary.invariants_tested} |
| **Properties Violated** | ⚠️ {summary.properties_violated} |
| **AI FP Filtered** | 🤖 {summary.ai_false_positives_filtered} |

---

## 🛠️ Tools Executed

"""
        for tool_name, info in stats['tools_summary'].items():
            status = "✅" if info['executed'] else "⏭️"
            md_content += f"- {status} **{tool_name}**: {info['findings']} findings\n"

        md_content += "\n---\n\n## 🚨 Critical & High Findings\n\n"

        critical_high = [f for f in self.findings if f.severity in ['critical', 'high']]
        if critical_high:
            for idx, finding in enumerate(critical_high[:20], 1):  # Limit to top 20
                severity_emoji = "🔴" if finding.severity == 'critical' else "🟠"
                md_content += f"""
### {idx}. {severity_emoji} {finding.title}

**Tool:** {self.TOOL_NAMES.get(finding.tool, finding.tool)}
**Severity:** {finding.severity.upper()}
**Category:** {finding.category}

**Description:**
{finding.description[:200]}...

**Location:** `{finding.location.get('file', 'N/A')}:{finding.location.get('line', '?')}`

"""
        else:
            md_content += "✨ No critical or high severity findings detected!\n\n"

        md_content += """
---

## 📈 Findings by Tool

"""
        for tool_key, count in sorted(stats['by_tool'].items(), key=lambda x: -x[1]):
            tool_name = self.TOOL_NAMES.get(tool_key, tool_key)
            md_content += f"- **{tool_name}**: {count} findings\n"

        md_content += """

---

## 💡 Recommendations

1. **Immediate Action Required**: Address all CRITICAL findings within 24 hours
2. **High Priority**: Fix HIGH severity issues before deployment
3. **Review Medium Issues**: Plan fixes in next sprint
4. **AI-Assisted Triage**: {ai_filtered} false positives filtered by AI
5. **Exploit Validation**: {exploits} executable exploits generated for testing

---

## 🔗 Additional Resources

- **Full JSON Report**: See `report.json` for complete details
- **Exploit PoCs**: Check `analysis/manticore/exploits/` directory
- **Coverage Reports**: See `analysis/foundry/coverage/` for test coverage
- **Visualization**: Open `dashboard/index.html` for interactive dashboard

---

**Generated by Xaudit v2.0** | [GitHub](https://github.com/fboiero/MIESC)
Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba | Maestría en Ciberdefensa
""".format(
            ai_filtered=summary.ai_false_positives_filtered,
            exploits=summary.exploits_generated
        )

        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(md_content)

        print(f"✅ Markdown report saved to: {output_file}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Xaudit Enhanced Reporter v2.0")
    parser.add_argument("--results", required=True, help="Path to analysis results directory")
    parser.add_argument("--output", default="reports", help="Output directory for reports")
    parser.add_argument("--format", nargs='+', default=['json', 'markdown'],
                       choices=['json', 'markdown', 'html', 'pdf'],
                       help="Output formats")

    args = parser.parse_args()

    results_dir = Path(args.results)
    output_dir = Path(args.output)

    if not results_dir.exists():
        print(f"❌ Error: Results directory not found: {results_dir}")
        sys.exit(1)

    print("🔍 Xaudit Enhanced Reporter v2.0")
    print("=" * 60)

    reporter = EnhancedReporter(results_dir)
    reporter.collect_all_findings()

    print("\n📝 Generating reports...")

    if 'json' in args.format:
        reporter.generate_json_report(output_dir / 'report.json')

    if 'markdown' in args.format:
        reporter.generate_markdown_report(output_dir / 'REPORT.md')

    summary = reporter.generate_executive_summary()

    print("\n" + "=" * 60)
    print("✅ ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"\n📊 Total Findings: {summary.total_findings}")
    print(f"   🔴 Critical: {summary.critical_count}")
    print(f"   🟠 High: {summary.high_count}")
    print(f"   🟡 Medium: {summary.medium_count}")
    print(f"   🟢 Low: {summary.low_count}")
    print(f"\n⚡ Exploits Generated: {summary.exploits_generated}")
    print(f"🧪 Invariants Tested: {summary.invariants_tested}")
    print(f"🤖 AI FP Filtered: {summary.ai_false_positives_filtered}")
    print(f"\n📁 Reports saved to: {output_dir.absolute()}")


if __name__ == "__main__":
    main()
