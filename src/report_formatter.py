"""
Enhanced Report Formatter for MIESC
Parses and formats security analysis reports with better visualization
"""

import re
import json
from typing import Dict, List, Tuple
from pathlib import Path
from collections import defaultdict


class SlitherParser:
    """Parse and categorize Slither output"""

    # Severity patterns from Slither detector documentation
    SEVERITY_PATTERNS = {
        'HIGH': ['reentrancy-eth', 'reentrancy-no-eth', 'reentrancy-benign', 'controlled-delegatecall',
                 'arbitrary-send-eth', 'suicidal', 'uninitialized-state', 'uninitialized-storage'],
        'MEDIUM': ['dangerous-strict-equality', 'incorrect-equality', 'locked-ether', 'shadowing-state',
                   'weak-prng', 'void-cst', 'unchecked-transfer', 'tx-origin'],
        'LOW': ['solc-version', 'naming-convention', 'pragma', 'unused-state', 'costly-loop',
                'external-function', 'dead-code', 'constable-states', 'immutable-states'],
        'INFORMATIONAL': ['low-level-calls', 'similar-names', 'too-many-digits', 'assembly']
    }

    def __init__(self, slither_output: str):
        self.output = slither_output
        self.issues = []

    def parse(self) -> Dict:
        """Parse Slither output and categorize findings"""
        lines = self.output.split('\n')

        current_issue = None
        issue_lines = []

        for line in lines:
            # Detect new issue (INFO:Detectors:)
            if line.startswith('INFO:Detectors:'):
                if current_issue:
                    self.issues.append(self._create_issue(issue_lines))
                issue_lines = []
            elif line.strip():
                issue_lines.append(line)

        # Add last issue
        if issue_lines:
            self.issues.append(self._create_issue(issue_lines))

        return self._categorize_issues()

    def _create_issue(self, lines: List[str]) -> Dict:
        """Create issue dict from lines"""
        text = '\n'.join(lines)

        # Extract function name and contract
        function_match = re.search(r'(\w+)\.(\w+)\([^)]*\)', text)
        contract = function_match.group(1) if function_match else 'Unknown'
        function = function_match.group(2) if function_match else 'Unknown'

        # Extract reference URL if available
        reference = ''
        ref_match = re.search(r'Reference: (https?://[^\s]+)', text)
        if ref_match:
            reference = ref_match.group(1)

        # Detect issue type and severity
        issue_type, severity = self._detect_issue_type(text)

        # Extract file location
        location = self._extract_location(text)

        return {
            'type': issue_type,
            'severity': severity,
            'contract': contract,
            'function': function,
            'description': text.strip(),
            'reference': reference,
            'location': location
        }

    def _detect_issue_type(self, text: str) -> Tuple[str, str]:
        """Detect issue type and severity from text"""
        text_lower = text.lower()

        # Check for known patterns
        if 'reentrancy' in text_lower:
            return 'Reentrancy', 'HIGH'
        elif 'weak prng' in text_lower:
            return 'Weak PRNG', 'MEDIUM'
        elif 'strict equality' in text_lower:
            return 'Dangerous Strict Equality', 'MEDIUM'
        elif 'solc version' in text_lower or 'pragma' in text_lower:
            return 'Solidity Version', 'LOW'
        elif 'naming convention' in text_lower:
            return 'Naming Convention', 'LOW'
        elif 'low-level calls' in text_lower:
            return 'Low-level Calls', 'INFORMATIONAL'
        elif 'timestamp' in text_lower:
            return 'Timestamp Dependence', 'MEDIUM'
        elif 'unused' in text_lower:
            return 'Unused State', 'LOW'
        elif 'constable' in text_lower:
            return 'State Mutability', 'LOW'
        else:
            return 'Other', 'INFORMATIONAL'

    def _extract_location(self, text: str) -> str:
        """Extract file location from text"""
        # Look for file path patterns
        match = re.search(r'\(([^)]+\.sol)#(\d+)-?(\d+)?\)', text)
        if match:
            file = match.group(1).split('/')[-1]  # Get filename only
            line_start = match.group(2)
            line_end = match.group(3) if match.group(3) else line_start
            return f"{file}:{line_start}-{line_end}"
        return 'Unknown'

    def _categorize_issues(self) -> Dict:
        """Categorize issues by severity"""
        categorized = {
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFORMATIONAL': []
        }

        for issue in self.issues:
            severity = issue['severity']
            categorized[severity].append(issue)

        # Calculate statistics
        stats = {
            'total': len(self.issues),
            'high': len(categorized['HIGH']),
            'medium': len(categorized['MEDIUM']),
            'low': len(categorized['LOW']),
            'informational': len(categorized['INFORMATIONAL'])
        }

        return {
            'issues': categorized,
            'statistics': stats
        }


class OllamaParser:
    """Parse Ollama LLM output"""

    def __init__(self, ollama_output: str):
        self.output = ollama_output

    def parse(self) -> Dict:
        """Parse Ollama output"""
        lines = self.output.split('\n')

        # Look for "Found X potential issues"
        issues_count = 0
        for line in lines:
            if 'Found' in line and 'issue' in line:
                match = re.search(r'Found (\d+)', line)
                if match:
                    issues_count = int(match.group(1))
                    break

        # Extract any detailed findings
        issues = []
        current_issue = []
        in_issue_section = False

        for line in lines:
            if line.startswith('**') or line.startswith('##'):
                if current_issue:
                    issues.append('\n'.join(current_issue))
                current_issue = [line]
                in_issue_section = True
            elif in_issue_section and line.strip():
                current_issue.append(line)
            elif not line.strip() and current_issue:
                issues.append('\n'.join(current_issue))
                current_issue = []
                in_issue_section = False

        if current_issue:
            issues.append('\n'.join(current_issue))

        return {
            'issues_count': issues_count,
            'issues': issues,
            'status': 'SAFE' if issues_count == 0 else 'ISSUES_FOUND'
        }


class ReportFormatter:
    """Format reports in various formats"""

    @staticmethod
    def format_markdown(contract_name: str, slither_data: Dict, ollama_data: Dict) -> str:
        """Generate markdown report with conclusions and next steps"""
        md = f"# Security Analysis Report: {contract_name}\n\n"
        md += f"**Generated:** {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        # Executive Summary
        md += "## 📊 Executive Summary\n\n"
        md += f"**Contract:** {contract_name}\n\n"

        # Calculate total severity
        total_critical = 0
        total_issues = 0

        # Slither Statistics
        if slither_data:
            stats = slither_data['statistics']
            total_critical += stats['high']
            total_issues += stats['total']

            md += "### Static Analysis (Slither Agent)\n\n"
            md += f"- **Total Issues:** {stats['total']}\n"
            md += f"- **High Severity:** {stats['high']} 🔴\n"
            md += f"- **Medium Severity:** {stats['medium']} 🟡\n"
            md += f"- **Low Severity:** {stats['low']} 🟢\n"
            md += f"- **Informational:** {stats['informational']} ℹ️\n\n"

        # Ollama Analysis
        if ollama_data:
            total_issues += ollama_data['issues_count']
            md += "### AI Analysis (Ollama Agent)\n\n"
            md += f"- **Status:** {ollama_data['status']}\n"
            md += f"- **Issues Found:** {ollama_data['issues_count']}\n"
            md += f"- **Model:** CodeLlama\n\n"

        # Risk Assessment
        md += "### 🎯 Risk Assessment\n\n"
        if total_critical > 0:
            md += f"⚠️ **CRITICAL** - {total_critical} high-severity issues require immediate attention\n\n"
        elif total_issues > 5:
            md += f"⚠️ **MODERATE** - {total_issues} issues identified, review recommended\n\n"
        elif total_issues > 0:
            md += f"✅ **LOW** - {total_issues} minor issues, mostly informational\n\n"
        else:
            md += "✅ **SECURE** - No critical issues detected\n\n"

        # Detailed Findings
        md += "---\n\n"
        md += "## 🔍 Detailed Findings\n\n"

        if slither_data:
            for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
                issues = slither_data['issues'][severity]
                if issues:
                    emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFORMATIONAL': 'ℹ️'}
                    md += f"### {emoji[severity]} {severity} Severity Issues ({len(issues)})\n\n"

                    for i, issue in enumerate(issues, 1):
                        md += f"#### Finding #{i}: {issue['type']}\n\n"
                        md += f"**Agent:** Slither (Static Analysis)\n\n"
                        md += f"**Contract:** {issue['contract']}\n\n"
                        md += f"**Function:** `{issue['function']}`\n\n"
                        md += f"**Location:** {issue['location']}\n\n"
                        md += f"**Severity:** {severity}\n\n"

                        md += f"**Description:**\n\n"
                        md += f"```\n{issue['description'][:800]}\n```\n\n"

                        if issue['reference']:
                            md += f"**📚 Reference:** [{issue['reference']}]({issue['reference']})\n\n"

                        # Add impact and recommendation based on type
                        md += "**💥 Impact:**\n"
                        if "reentrancy" in issue['type'].lower():
                            md += "- Attacker can drain contract funds\n"
                            md += "- Critical security vulnerability\n\n"
                            md += "**✅ Recommendation:**\n"
                            md += "- Use Checks-Effects-Interactions pattern\n"
                            md += "- Add ReentrancyGuard from OpenZeppelin\n"
                            md += "- Update state before external calls\n\n"
                        elif "access control" in issue['type'].lower():
                            md += "- Unauthorized users can execute privileged functions\n"
                            md += "- Contract ownership can be compromised\n\n"
                            md += "**✅ Recommendation:**\n"
                            md += "- Implement proper access control (Ownable, AccessControl)\n"
                            md += "- Use modifiers to restrict function access\n"
                            md += "- Follow principle of least privilege\n\n"
                        elif "integer overflow" in issue['type'].lower():
                            md += "- Arithmetic operations can overflow/underflow\n"
                            md += "- Balances and values can be corrupted\n\n"
                            md += "**✅ Recommendation:**\n"
                            md += "- Use Solidity 0.8.x (built-in overflow checks)\n"
                            md += "- Or use SafeMath library for older versions\n\n"
                        else:
                            md += f"- {severity.lower()} severity security concern\n\n"
                            md += "**✅ Recommendation:**\n"
                            md += "- Review the reference documentation\n"
                            md += "- Apply recommended fixes\n\n"

                        md += "---\n\n"

        # Ollama Findings
        if ollama_data and ollama_data['issues']:
            md += "### 🤖 AI-Detected Issues (Ollama Agent)\n\n"
            for i, issue in enumerate(ollama_data['issues'], 1):
                md += f"#### AI Finding #{i}\n\n"
                md += f"**Agent:** Ollama (AI Analysis)\n\n"
                md += f"{issue}\n\n"
                md += "---\n\n"

        # Conclusions
        md += "## 🎯 Conclusions\n\n"

        if total_critical > 0:
            md += f"### ⚠️ Critical Issues Identified\n\n"
            md += f"This contract has **{total_critical} high-severity vulnerabilities** that require immediate attention before deployment.\n\n"
            md += "**Key Concerns:**\n"
            if slither_data and slither_data['issues']['HIGH']:
                for issue in slither_data['issues']['HIGH'][:3]:
                    md += f"- {issue['type']} in {issue['function']}()\n"
            md += "\n**Status:** ❌ NOT READY FOR PRODUCTION\n\n"
        elif total_issues > 5:
            md += f"### ⚠️ Multiple Issues Require Review\n\n"
            md += f"While no critical vulnerabilities were found, this contract has **{total_issues} issues** that should be reviewed.\n\n"
            md += "**Status:** ⚠️ NEEDS REVIEW BEFORE DEPLOYMENT\n\n"
        elif total_issues > 0:
            md += f"### ✅ Minor Issues Detected\n\n"
            md += f"The contract is relatively secure with only **{total_issues} minor issues**, mostly informational.\n\n"
            md += "**Status:** ✅ READY WITH MINOR IMPROVEMENTS\n\n"
        else:
            md += f"### ✅ No Critical Issues\n\n"
            md += "No security vulnerabilities were detected by the analysis agents.\n\n"
            md += "**Status:** ✅ APPEARS SECURE\n\n"
            md += "**Note:** This is automated analysis. Always conduct manual audit for production contracts.\n\n"

        # Multi-Agent Analysis Summary
        md += "### 🤖 Multi-Agent Analysis\n\n"
        md += "This report combines findings from:\n"
        if slither_data:
            md += "- **Slither Agent** - Static analysis with 87 detectors\n"
        if ollama_data:
            md += "- **Ollama Agent** - AI-powered logic analysis (local, private)\n"
        md += "\nEach agent provides independent evidence, maximizing vulnerability detection coverage.\n\n"

        # Next Steps
        md += "## 📋 Recommended Next Steps\n\n"

        if total_critical > 0:
            md += "### Immediate Actions (Priority: HIGH)\n\n"
            md += "1. **Fix Critical Vulnerabilities**\n"
            md += "   - Address all high-severity findings\n"
            md += "   - Apply recommended patches\n"
            md += "   - Re-run analysis to verify fixes\n\n"
            md += "2. **Security Audit**\n"
            md += "   - Engage professional auditors\n"
            md += "   - DO NOT deploy to mainnet until issues are resolved\n\n"
            md += "3. **Testing**\n"
            md += "   - Write exploit tests for identified vulnerabilities\n"
            md += "   - Verify fixes work correctly\n"
            md += "   - Test on testnet extensively\n\n"
        else:
            md += "### Standard Development Workflow\n\n"
            md += "1. **Review Findings**\n"
            md += "   - Address informational and low-severity issues\n"
            md += "   - Improve code quality based on recommendations\n\n"
            md += "2. **Additional Testing**\n"
            md += "   - Run additional analysis tools (Mythril, Echidna)\n"
            md += "   - Write comprehensive unit tests\n"
            md += "   - Perform integration testing\n\n"
            md += "3. **Pre-Deployment Checklist**\n"
            md += "   - ✅ All high/medium issues resolved\n"
            md += "   - ✅ Code reviewed by multiple developers\n"
            md += "   - ✅ Test coverage > 90%\n"
            md += "   - ✅ Deployed and tested on testnet\n"
            md += "   - ✅ Consider professional audit for high-value contracts\n\n"

        md += "### Further Analysis\n\n"
        md += "Consider running additional analysis:\n\n"
        md += "```bash\n"
        md += f"# Symbolic execution (deeper analysis)\n"
        md += f"python main_ai.py {contract_name}.sol analysis --use-mythril\n\n"
        md += f"# Multi-contract project analysis\n"
        md += f"python main_project.py contracts/ project --visualize --use-ollama\n"
        md += "```\n\n"

        # Footer
        md += "---\n\n"
        md += "**Report generated by MIESC** - Multi-agent Integrated Security for Smart Contracts\n\n"
        md += "**Agents used:**\n"
        if slither_data:
            md += "- Slither (Trail of Bits) - Static Analysis\n"
        if ollama_data:
            md += "- Ollama (CodeLlama) - AI Analysis (local, $0 cost)\n"
        md += "\n**Disclaimer:** This is an automated analysis. Always conduct manual code review and professional audit for production smart contracts.\n"

        return md

    @staticmethod
    def format_html_dashboard(project_name: str, contracts_data: Dict) -> str:
        """Generate interactive HTML dashboard"""

        # Calculate overall statistics
        total_high = sum(c['slither']['statistics']['high'] for c in contracts_data.values() if c.get('slither'))
        total_medium = sum(c['slither']['statistics']['medium'] for c in contracts_data.values() if c.get('slither'))
        total_low = sum(c['slither']['statistics']['low'] for c in contracts_data.values() if c.get('slither'))
        total_info = sum(c['slither']['statistics']['informational'] for c in contracts_data.values() if c.get('slither'))
        total_issues = total_high + total_medium + total_low + total_info

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MIESC Security Report - {project_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        .header {{
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }}

        .header h1 {{
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .header .subtitle {{
            color: #666;
            font-size: 1.2em;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }}

        .stat-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}

        .stat-card .label {{
            font-size: 1.1em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .stat-card.total .number {{ color: #667eea; }}
        .stat-card.high .number {{ color: #e53e3e; }}
        .stat-card.medium .number {{ color: #f59e0b; }}
        .stat-card.low .number {{ color: #10b981; }}
        .stat-card.info .number {{ color: #3b82f6; }}

        .contracts-section {{
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}

        .contracts-section h2 {{
            color: #667eea;
            margin-bottom: 25px;
            font-size: 2em;
        }}

        .contract-card {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 20px;
            border-left: 5px solid #667eea;
        }}

        .contract-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}

        .contract-name {{
            font-size: 1.5em;
            font-weight: bold;
            color: #333;
        }}

        .contract-stats {{
            display: flex;
            gap: 15px;
        }}

        .severity-badge {{
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}

        .severity-badge.high {{
            background: #fee2e2;
            color: #991b1b;
        }}

        .severity-badge.medium {{
            background: #fef3c7;
            color: #92400e;
        }}

        .severity-badge.low {{
            background: #d1fae5;
            color: #065f46;
        }}

        .severity-badge.info {{
            background: #dbeafe;
            color: #1e40af;
        }}

        .issues-list {{
            margin-top: 20px;
        }}

        .issue-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 3px solid #667eea;
        }}

        .issue-type {{
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }}

        .issue-location {{
            font-size: 0.85em;
            color: #666;
            font-family: 'Courier New', monospace;
        }}

        .collapsible {{
            cursor: pointer;
            user-select: none;
        }}

        .collapsible:hover {{
            opacity: 0.8;
        }}

        .collapsible-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }}

        .collapsible-content.active {{
            max-height: 2000px;
        }}

        .expand-btn {{
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9em;
            margin-top: 10px;
        }}

        .expand-btn:hover {{
            background: #5568d3;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ MIESC Security Analysis Report</h1>
            <div class="subtitle">Project: {project_name}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card total">
                <div class="number">{total_issues}</div>
                <div class="label">Total Issues</div>
            </div>
            <div class="stat-card high">
                <div class="number">{total_high}</div>
                <div class="label">High Risk</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{total_medium}</div>
                <div class="label">Medium Risk</div>
            </div>
            <div class="stat-card low">
                <div class="number">{total_low}</div>
                <div class="label">Low Risk</div>
            </div>
            <div class="stat-card info">
                <div class="number">{total_info}</div>
                <div class="label">Informational</div>
            </div>
        </div>

        <div class="contracts-section">
            <h2>📋 Contract Analysis</h2>
"""

        # Add contract cards
        for contract_name, data in contracts_data.items():
            if not data.get('slither'):
                continue

            stats = data['slither']['statistics']
            issues = data['slither']['issues']

            html += f"""
            <div class="contract-card">
                <div class="contract-header">
                    <div class="contract-name">📄 {contract_name}</div>
                    <div class="contract-stats">
"""

            if stats['high'] > 0:
                html += f'<span class="severity-badge high">🔴 {stats["high"]} High</span>'
            if stats['medium'] > 0:
                html += f'<span class="severity-badge medium">🟡 {stats["medium"]} Medium</span>'
            if stats['low'] > 0:
                html += f'<span class="severity-badge low">🟢 {stats["low"]} Low</span>'
            if stats['informational'] > 0:
                html += f'<span class="severity-badge info">ℹ️ {stats["informational"]} Info</span>'

            html += """
                    </div>
                </div>
"""

            # Add Ollama status
            if data.get('ollama'):
                ollama_status = data['ollama']['status']
                status_emoji = '✅' if ollama_status == 'SAFE' else '⚠️'
                html += f"""
                <div style="margin-bottom: 15px;">
                    <strong>AI Analysis:</strong> {status_emoji} {ollama_status.replace('_', ' ').title()}
                    ({data['ollama']['issues_count']} issues detected)
                </div>
"""

            # Add collapsible issues sections
            for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
                severity_issues = issues[severity]
                if severity_issues:
                    severity_lower = severity.lower()
                    emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFORMATIONAL': 'ℹ️'}

                    html += f"""
                <div class="collapsible" onclick="toggleCollapsible(this)">
                    <h3>{emoji[severity]} {severity} Severity ({len(severity_issues)} issues) ▼</h3>
                </div>
                <div class="collapsible-content">
                    <div class="issues-list">
"""

                    for issue in severity_issues[:10]:  # Limit to 10 issues per severity
                        html += f"""
                        <div class="issue-item">
                            <div class="issue-type">{issue['type']}</div>
                            <div class="issue-location">📍 {issue['location']} → {issue['function']}()</div>
                        </div>
"""

                    if len(severity_issues) > 10:
                        html += f"""
                        <div style="text-align: center; padding: 10px; color: #666;">
                            ... and {len(severity_issues) - 10} more issues
                        </div>
"""

                    html += """
                    </div>
                </div>
"""

            html += """
            </div>
"""

        html += """
        </div>
    </div>

    <script>
        function toggleCollapsible(element) {
            element.classList.toggle('active');
            var content = element.nextElementSibling;
            content.classList.toggle('active');
        }
    </script>
</body>
</html>
"""

        return html


def generate_project_report(output_dir: str, project_name: str):
    """Generate consolidated report for entire project or single contract"""
    output_path = Path(output_dir)

    # Find all contract directories
    contracts_data = {}

    # Check if this is a single contract analysis (files at root level)
    slither_at_root = (output_path / 'Slither.txt').exists()
    ollama_at_root = (output_path / 'Ollama.txt').exists()

    if slither_at_root or ollama_at_root:
        # Single contract analysis - files are at root level
        contract_name = project_name
        contracts_data[contract_name] = {}

        # Parse Slither report
        if slither_at_root:
            with open(output_path / 'Slither.txt', 'r') as f:
                slither_output = f.read()
            parser = SlitherParser(slither_output)
            contracts_data[contract_name]['slither'] = parser.parse()

        # Parse Ollama report
        if ollama_at_root:
            with open(output_path / 'Ollama.txt', 'r') as f:
                ollama_output = f.read()
            parser = OllamaParser(ollama_output)
            contracts_data[contract_name]['ollama'] = parser.parse()
    else:
        # Multi-contract analysis - files in subdirectories
        for contract_dir in output_path.iterdir():
            if not contract_dir.is_dir() or contract_dir.name in ['visualizations', 'reports']:
                continue

            contract_name = contract_dir.name
            contracts_data[contract_name] = {}

            # Parse Slither report
            slither_file = contract_dir / 'Slither.txt'
            if slither_file.exists():
                with open(slither_file, 'r') as f:
                    slither_output = f.read()
                parser = SlitherParser(slither_output)
                contracts_data[contract_name]['slither'] = parser.parse()

            # Parse Ollama report
            ollama_file = contract_dir / 'Ollama.txt'
            if ollama_file.exists():
                with open(ollama_file, 'r') as f:
                    ollama_output = f.read()
                parser = OllamaParser(ollama_output)
                contracts_data[contract_name]['ollama'] = parser.parse()

    # Generate reports
    reports_dir = output_path / 'reports'
    reports_dir.mkdir(exist_ok=True)

    # HTML Dashboard
    html_content = ReportFormatter.format_html_dashboard(project_name, contracts_data)
    with open(reports_dir / 'dashboard.html', 'w') as f:
        f.write(html_content)

    # Individual Markdown reports
    for contract_name, data in contracts_data.items():
        md_content = ReportFormatter.format_markdown(
            contract_name,
            data.get('slither'),
            data.get('ollama')
        )
        with open(reports_dir / f'{contract_name}_report.md', 'w') as f:
            f.write(md_content)

    # Consolidated Markdown report
    consolidated_md = f"# {project_name} - Consolidated Security Report\n\n"
    consolidated_md += f"**Generated by MIESC**\n\n"
    consolidated_md += "---\n\n"

    for contract_name, data in contracts_data.items():
        consolidated_md += ReportFormatter.format_markdown(
            contract_name,
            data.get('slither'),
            data.get('ollama')
        )
        consolidated_md += "\n\n---\n\n"

    with open(reports_dir / 'consolidated_report.md', 'w') as f:
        f.write(consolidated_md)

    return reports_dir
