#!/usr/bin/env python3
"""
MIESC Audit Report Generator
Generates professional HTML and PDF audit reports with all evidence

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """Represents a single security finding"""
    id: str
    title: str
    severity: str  # Critical, High, Medium, Low, Informational
    category: str
    description: str
    location: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    tool: str = ""
    layer: int = 0
    swc_id: Optional[str] = None
    cwe_id: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditMetadata:
    """Audit metadata"""
    project_name: str
    contract_name: str
    version: str
    auditor: str
    organization: str
    audit_date: str
    report_id: str
    contract_hash: str
    solidity_version: str = ""
    lines_of_code: int = 0
    complexity_score: float = 0.0


class AuditReportGenerator:
    """
    Professional audit report generator for MIESC
    Generates HTML and PDF reports with complete evidence
    """

    VERSION = "1.0.0"

    # Severity colors and icons
    SEVERITY_CONFIG = {
        'Critical': {'color': '#dc2626', 'bg': '#fef2f2', 'icon': '!!!'},
        'High': {'color': '#ea580c', 'bg': '#fff7ed', 'icon': '!!'},
        'Medium': {'color': '#ca8a04', 'bg': '#fefce8', 'icon': '!'},
        'Low': {'color': '#16a34a', 'bg': '#f0fdf4', 'icon': 'i'},
        'Informational': {'color': '#2563eb', 'bg': '#eff6ff', 'icon': '*'},
    }

    def __init__(
        self,
        metadata: AuditMetadata,
        findings: List[Finding],
        raw_tool_outputs: Optional[Dict[str, Any]] = None,
        contract_source: Optional[str] = None,
    ):
        self.metadata = metadata
        self.findings = findings
        self.raw_tool_outputs = raw_tool_outputs or {}
        self.contract_source = contract_source
        self.generated_at = datetime.now()

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score based on findings"""
        weights = {'Critical': 10, 'High': 5, 'Medium': 2, 'Low': 1, 'Informational': 0}
        total = sum(weights.get(f.severity, 0) for f in self.findings)
        max_score = len(self.findings) * 10 if self.findings else 1
        return min(100, (total / max_score) * 100) if max_score > 0 else 0

    def _get_severity_summary(self) -> Dict[str, int]:
        """Count findings by severity"""
        summary = {s: 0 for s in self.SEVERITY_CONFIG.keys()}
        for f in self.findings:
            if f.severity in summary:
                summary[f.severity] += 1
        return summary

    def _get_layer_summary(self) -> Dict[int, int]:
        """Count findings by layer"""
        layers = {}
        for f in self.findings:
            layers[f.layer] = layers.get(f.layer, 0) + 1
        return dict(sorted(layers.items()))

    def _get_tool_summary(self) -> Dict[str, int]:
        """Count findings by tool"""
        tools = {}
        for f in self.findings:
            tools[f.tool] = tools.get(f.tool, 0) + 1
        return dict(sorted(tools.items(), key=lambda x: -x[1]))

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;'))

    def _generate_css(self) -> str:
        """Generate CSS styles for the report"""
        return """
        :root {
            --primary: #1e40af;
            --secondary: #475569;
            --success: #16a34a;
            --warning: #ca8a04;
            --danger: #dc2626;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --border: #e2e8f0;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
            background: var(--bg);
            color: #1e293b;
            line-height: 1.6;
        }

        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

        /* Header */
        .header {
            background: linear-gradient(135deg, var(--primary) 0%, #3b82f6 100%);
            color: white;
            padding: 3rem 2rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            box-shadow: 0 10px 40px rgba(30, 64, 175, 0.3);
        }

        .header h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
        .header .subtitle { opacity: 0.9; font-size: 1.1rem; }

        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid rgba(255,255,255,0.2);
        }

        .meta-item label { opacity: 0.7; font-size: 0.85rem; display: block; }
        .meta-item span { font-weight: 600; }

        /* Cards */
        .card {
            background: var(--card-bg);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border: 1px solid var(--border);
        }

        .card h2 {
            color: var(--primary);
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--primary);
        }

        .card h3 { color: var(--secondary); margin: 1rem 0 0.5rem; }

        /* Summary Grid */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .summary-box {
            background: var(--card-bg);
            border-radius: 0.75rem;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid var(--border);
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .summary-box:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }

        .summary-box .count {
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1;
        }

        .summary-box .label {
            font-size: 0.9rem;
            color: var(--secondary);
            margin-top: 0.5rem;
        }

        /* Risk Meter */
        .risk-meter {
            background: #e2e8f0;
            height: 1.5rem;
            border-radius: 0.75rem;
            overflow: hidden;
            margin: 1rem 0;
        }

        .risk-meter-fill {
            height: 100%;
            border-radius: 0.75rem;
            transition: width 0.5s ease;
        }

        /* Findings */
        .finding {
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            overflow: hidden;
        }

        .finding-header {
            padding: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            cursor: pointer;
        }

        .finding-header:hover { background: #f8fafc; }

        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .finding-title { flex: 1; font-weight: 600; }
        .finding-location { color: var(--secondary); font-size: 0.9rem; }

        .finding-body {
            padding: 1rem;
            border-top: 1px solid var(--border);
            background: #f8fafc;
        }

        .finding-section { margin-bottom: 1rem; }
        .finding-section:last-child { margin-bottom: 0; }
        .finding-section h4 {
            font-size: 0.85rem;
            text-transform: uppercase;
            color: var(--secondary);
            margin-bottom: 0.5rem;
        }

        /* Code blocks */
        .code-block {
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 0.5rem;
            font-family: 'Fira Code', 'Monaco', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            white-space: pre;
        }

        .code-block .line-num {
            color: #64748b;
            margin-right: 1rem;
            user-select: none;
        }

        .code-block .highlight { background: rgba(234, 88, 12, 0.3); }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }

        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th { background: #f1f5f9; font-weight: 600; }
        tr:hover { background: #f8fafc; }

        /* Charts placeholder */
        .chart-container {
            height: 300px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #f1f5f9;
            border-radius: 0.5rem;
            color: var(--secondary);
        }

        /* Bar chart */
        .bar-chart { margin: 1rem 0; }
        .bar-item { margin-bottom: 0.5rem; }
        .bar-label { font-size: 0.9rem; margin-bottom: 0.25rem; }
        .bar-track { background: #e2e8f0; height: 1.5rem; border-radius: 0.25rem; overflow: hidden; }
        .bar-fill { height: 100%; border-radius: 0.25rem; display: flex; align-items: center; padding: 0 0.5rem; color: white; font-size: 0.8rem; }

        /* Footer */
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--secondary);
            font-size: 0.9rem;
            border-top: 1px solid var(--border);
            margin-top: 2rem;
        }

        /* Print styles */
        @media print {
            body { background: white; }
            .container { max-width: none; padding: 0; }
            .card { break-inside: avoid; box-shadow: none; border: 1px solid #ddd; }
            .header { background: var(--primary) !important; -webkit-print-color-adjust: exact; }
            .no-print { display: none; }
        }

        /* Remediation code section */
        .remediation-code pre {
            margin: 0;
            padding: 1rem;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .remediation-code .code-block {
            border-left: 4px solid #16a34a;
        }

        /* Layer colors */
        .layer-1 { --layer-color: #3b82f6; }
        .layer-2 { --layer-color: #8b5cf6; }
        .layer-3 { --layer-color: #ec4899; }
        .layer-4 { --layer-color: #f59e0b; }
        .layer-5 { --layer-color: #10b981; }
        .layer-6 { --layer-color: #06b6d4; }
        .layer-7 { --layer-color: #6366f1; }
        .layer-8 { --layer-color: #f43f5e; }
        .layer-9 { --layer-color: #84cc16; }
        """

    def _generate_executive_summary(self) -> str:
        """Generate executive summary section"""
        severity_summary = self._get_severity_summary()
        risk_score = self._calculate_risk_score()

        # Determine risk level
        if risk_score >= 80:
            risk_level, risk_color = "CRITICAL", "#dc2626"
        elif risk_score >= 60:
            risk_level, risk_color = "HIGH", "#ea580c"
        elif risk_score >= 40:
            risk_level, risk_color = "MEDIUM", "#ca8a04"
        elif risk_score >= 20:
            risk_level, risk_color = "LOW", "#16a34a"
        else:
            risk_level, risk_color = "MINIMAL", "#2563eb"

        return f"""
        <div class="card">
            <h2>Executive Summary</h2>

            <div class="summary-grid">
                <div class="summary-box">
                    <div class="count" style="color: {risk_color}">{risk_score:.0f}</div>
                    <div class="label">Risk Score</div>
                </div>
                <div class="summary-box">
                    <div class="count">{len(self.findings)}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="summary-box">
                    <div class="count" style="color: #dc2626">{severity_summary['Critical']}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-box">
                    <div class="count" style="color: #ea580c">{severity_summary['High']}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-box">
                    <div class="count" style="color: #ca8a04">{severity_summary['Medium']}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-box">
                    <div class="count" style="color: #16a34a">{severity_summary['Low']}</div>
                    <div class="label">Low</div>
                </div>
            </div>

            <h3>Overall Risk Assessment</h3>
            <div class="risk-meter">
                <div class="risk-meter-fill" style="width: {risk_score}%; background: {risk_color}"></div>
            </div>
            <p style="text-align: center; font-weight: 600; color: {risk_color}">{risk_level} RISK</p>

            <h3>Key Statistics</h3>
            <table>
                <tr><td>Contract</td><td><strong>{self.metadata.contract_name}</strong></td></tr>
                <tr><td>Lines of Code</td><td>{self.metadata.lines_of_code}</td></tr>
                <tr><td>Solidity Version</td><td>{self.metadata.solidity_version or 'N/A'}</td></tr>
                <tr><td>Contract Hash (SHA256)</td><td><code>{self.metadata.contract_hash[:16]}...</code></td></tr>
                <tr><td>Analysis Tools Used</td><td>{len(self._get_tool_summary())}</td></tr>
                <tr><td>Security Layers Analyzed</td><td>{len(self._get_layer_summary())}</td></tr>
            </table>
        </div>
        """

    def _generate_methodology_section(self) -> str:
        """Generate methodology section"""
        layer_summary = self._get_layer_summary()
        tool_summary = self._get_tool_summary()

        layer_names = {
            1: "Static Analysis",
            2: "Pattern Detection",
            3: "Symbolic Execution",
            4: "Fuzzing",
            5: "Formal Verification",
            6: "ML Detection",
            7: "AI Analysis",
            8: "DeFi Security",
            9: "Dependency Security",
        }

        layers_html = ""
        for layer, count in layer_summary.items():
            name = layer_names.get(layer, f"Layer {layer}")
            layers_html += f"""
            <div class="bar-item">
                <div class="bar-label">{name} (Layer {layer})</div>
                <div class="bar-track">
                    <div class="bar-fill layer-{layer}" style="width: {min(100, count * 10)}%; background: var(--layer-color, #3b82f6)">
                        {count} findings
                    </div>
                </div>
            </div>
            """

        tools_html = ""
        max_tool_count = max(tool_summary.values()) if tool_summary else 1
        for tool, count in tool_summary.items():
            width = (count / max_tool_count) * 100
            tools_html += f"""
            <div class="bar-item">
                <div class="bar-label">{tool}</div>
                <div class="bar-track">
                    <div class="bar-fill" style="width: {width}%; background: var(--primary)">
                        {count}
                    </div>
                </div>
            </div>
            """

        return f"""
        <div class="card">
            <h2>Methodology</h2>

            <p>This security audit was conducted using <strong>MIESC v4.2.1</strong>
            (Multi-layer Intelligent Evaluation for Smart Contracts), a comprehensive
            security analysis framework implementing a Defense-in-Depth strategy across
            9 specialized security layers.</p>

            <h3>Findings by Security Layer</h3>
            <div class="bar-chart">
                {layers_html if layers_html else '<p>No layer-specific findings</p>'}
            </div>

            <h3>Findings by Analysis Tool</h3>
            <div class="bar-chart">
                {tools_html if tools_html else '<p>No tool-specific findings</p>'}
            </div>

            <h3>Analysis Coverage</h3>
            <table>
                <thead>
                    <tr>
                        <th>Layer</th>
                        <th>Analysis Type</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td>1</td><td>Static Analysis</td><td>AST-based vulnerability detection (Slither, Aderyn)</td></tr>
                    <tr><td>2</td><td>Pattern Detection</td><td>Known vulnerability pattern matching</td></tr>
                    <tr><td>3</td><td>Symbolic Execution</td><td>Path exploration and constraint solving (Mythril)</td></tr>
                    <tr><td>4</td><td>Fuzzing</td><td>Property-based testing (Echidna, Medusa)</td></tr>
                    <tr><td>5</td><td>Formal Verification</td><td>Mathematical correctness proofs (Certora, Halmos)</td></tr>
                    <tr><td>6</td><td>ML Detection</td><td>Graph neural network analysis (DA-GNN)</td></tr>
                    <tr><td>7</td><td>AI Analysis</td><td>LLM-powered semantic analysis (SmartLLM)</td></tr>
                    <tr><td>8</td><td>DeFi Security</td><td>Flash loans, MEV, oracle manipulation</td></tr>
                    <tr><td>9</td><td>Dependency Security</td><td>Supply chain vulnerability scanning</td></tr>
                </tbody>
            </table>
        </div>
        """

    def _generate_finding_html(self, finding: Finding) -> str:
        """Generate HTML for a single finding"""
        config = self.SEVERITY_CONFIG.get(finding.severity, self.SEVERITY_CONFIG['Informational'])

        code_html = ""
        if finding.code_snippet:
            escaped_code = self._escape_html(finding.code_snippet)
            code_html = f"""
            <div class="finding-section">
                <h4>Vulnerable Code</h4>
                <div class="code-block">{escaped_code}</div>
            </div>
            """

        refs_html = ""
        if finding.references:
            refs = "".join(f"<li><a href='{ref}' target='_blank'>{ref}</a></li>" for ref in finding.references)
            refs_html = f"""
            <div class="finding-section">
                <h4>References</h4>
                <ul>{refs}</ul>
            </div>
            """

        swc_cwe = ""
        if finding.swc_id:
            swc_cwe += f"<span style='margin-right: 0.5rem'><strong>SWC:</strong> {finding.swc_id}</span>"
        if finding.cwe_id:
            swc_cwe += f"<span><strong>CWE:</strong> {finding.cwe_id}</span>"

        return f"""
        <div class="finding">
            <div class="finding-header" onclick="this.parentElement.classList.toggle('expanded')">
                <span class="severity-badge" style="background: {config['bg']}; color: {config['color']}">
                    {finding.severity}
                </span>
                <span class="finding-title">{self._escape_html(finding.title)}</span>
                <span class="finding-location">{self._escape_html(finding.location)}</span>
            </div>
            <div class="finding-body">
                <div class="finding-section">
                    <h4>Description</h4>
                    <p>{self._escape_html(finding.description)}</p>
                </div>

                {f'<div class="finding-section">{swc_cwe}</div>' if swc_cwe else ''}

                <div class="finding-section">
                    <h4>Category</h4>
                    <p>{finding.category} | Detected by: <strong>{finding.tool}</strong> (Layer {finding.layer})</p>
                </div>

                {code_html}

                {self._generate_remediation_section(finding)}

                {refs_html}
            </div>
        </div>
        """

    def _generate_remediation_section(self, finding: Finding) -> str:
        """
        Generate enhanced remediation section with code fixes.

        If the finding has generated remediation code, show it with syntax highlighting.
        Otherwise, fall back to basic remediation text.
        """
        if not finding.remediation and not finding.evidence.get('fixed_code'):
            return ""

        sections = []

        # Basic remediation description
        if finding.remediation:
            sections.append(f"""
            <div class="finding-section">
                <h4>Remediation</h4>
                <p>{self._escape_html(finding.remediation)}</p>
            </div>
            """)

        # Generated code fix (if available)
        fixed_code = finding.evidence.get('fixed_code')
        if fixed_code:
            escaped_code = self._escape_html(fixed_code)
            sections.append(f"""
            <div class="finding-section remediation-code">
                <h4>Suggested Fix</h4>
                <div class="code-block" style="background: #f0fdf4; border: 1px solid #16a34a;">
                    <span style="color: #16a34a; font-weight: bold;">// FIXED CODE</span>
                    <pre>{escaped_code}</pre>
                </div>
            </div>
            """)

        # Fix explanation (if available)
        fix_explanation = finding.evidence.get('fix_explanation')
        if fix_explanation:
            sections.append(f"""
            <div class="finding-section">
                <h4>Why This Fixes The Issue</h4>
                <p>{self._escape_html(fix_explanation)}</p>
            </div>
            """)

        # Suggested tests (if available)
        test_suggestions = finding.evidence.get('test_suggestions')
        if test_suggestions and isinstance(test_suggestions, list):
            tests_html = "".join(f"<li>{self._escape_html(t)}</li>" for t in test_suggestions[:5])
            sections.append(f"""
            <div class="finding-section">
                <h4>Suggested Tests</h4>
                <ul>{tests_html}</ul>
            </div>
            """)

        return "".join(sections)

    def _generate_findings_section(self) -> str:
        """Generate all findings section"""
        if not self.findings:
            return """
            <div class="card">
                <h2>Detailed Findings</h2>
                <p style="color: var(--success); font-size: 1.2rem; text-align: center; padding: 2rem;">
                    No security vulnerabilities detected.
                </p>
            </div>
            """

        # Group by severity
        grouped = {}
        for f in self.findings:
            grouped.setdefault(f.severity, []).append(f)

        findings_html = ""
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
            if severity in grouped:
                config = self.SEVERITY_CONFIG[severity]
                findings_html += f"<h3 style='color: {config['color']}; margin-top: 1.5rem;'>{severity} ({len(grouped[severity])})</h3>"
                for finding in grouped[severity]:
                    findings_html += self._generate_finding_html(finding)

        return f"""
        <div class="card">
            <h2>Detailed Findings</h2>
            {findings_html}
        </div>
        """

    def _generate_raw_outputs_section(self) -> str:
        """Generate raw tool outputs section for evidence"""
        if not self.raw_tool_outputs:
            return ""

        outputs_html = ""
        for tool, output in self.raw_tool_outputs.items():
            if isinstance(output, (dict, list)):
                output_str = json.dumps(output, indent=2)
            else:
                output_str = str(output)

            escaped = self._escape_html(output_str)
            if len(escaped) > 5000:
                escaped = escaped[:5000] + "\n\n... (truncated)"

            outputs_html += f"""
            <div class="finding-section">
                <h4>{self._escape_html(tool)}</h4>
                <div class="code-block">{escaped}</div>
            </div>
            """

        return f"""
        <div class="card">
            <h2>Raw Tool Outputs (Evidence)</h2>
            <p>Complete tool outputs preserved for audit trail and verification.</p>
            {outputs_html}
        </div>
        """

    def generate_html(self) -> str:
        """Generate complete HTML report"""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {self._escape_html(self.metadata.contract_name)}</title>
    <style>{self._generate_css()}</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Audit Report</h1>
            <p class="subtitle">{self._escape_html(self.metadata.project_name)}</p>

            <div class="meta-grid">
                <div class="meta-item">
                    <label>Contract</label>
                    <span>{self._escape_html(self.metadata.contract_name)}</span>
                </div>
                <div class="meta-item">
                    <label>Version</label>
                    <span>{self._escape_html(self.metadata.version)}</span>
                </div>
                <div class="meta-item">
                    <label>Auditor</label>
                    <span>{self._escape_html(self.metadata.auditor)}</span>
                </div>
                <div class="meta-item">
                    <label>Organization</label>
                    <span>{self._escape_html(self.metadata.organization)}</span>
                </div>
                <div class="meta-item">
                    <label>Audit Date</label>
                    <span>{self._escape_html(self.metadata.audit_date)}</span>
                </div>
                <div class="meta-item">
                    <label>Report ID</label>
                    <span>{self._escape_html(self.metadata.report_id)}</span>
                </div>
            </div>
        </div>

        {self._generate_executive_summary()}
        {self._generate_methodology_section()}
        {self._generate_findings_section()}
        {self._generate_raw_outputs_section()}

        <div class="card">
            <h2>Disclaimer</h2>
            <p>This report is provided for informational purposes only and does not constitute
            legal, financial, or professional advice. The security analysis was performed using
            automated tools and should be supplemented with manual code review by qualified
            security professionals.</p>

            <p style="margin-top: 1rem">Smart contract security is an evolving field.
            This audit represents a point-in-time assessment and does not guarantee the
            absence of all vulnerabilities. New attack vectors may emerge after this audit.</p>
        </div>

        <div class="footer">
            <p>Generated by <strong>MIESC v4.2.1</strong> - Multi-layer Intelligent Evaluation for Smart Contracts</p>
            <p>Report generated on {self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p><a href="https://github.com/fboiero/MIESC" target="_blank">https://github.com/fboiero/MIESC</a></p>
        </div>
    </div>

    <script>
        // Add toggle functionality for findings
        document.querySelectorAll('.finding').forEach(el => {{
            el.querySelector('.finding-body').style.display = 'none';
        }});

        document.querySelectorAll('.finding-header').forEach(header => {{
            header.addEventListener('click', () => {{
                const body = header.nextElementSibling;
                body.style.display = body.style.display === 'none' ? 'block' : 'none';
            }});
        }});
    </script>
</body>
</html>"""

    def save_html(self, output_path: Path) -> Path:
        """Save HTML report to file"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.generate_html(), encoding='utf-8')
        return output_path

    def save_pdf(self, output_path: Path) -> Optional[Path]:
        """
        Save PDF report (requires weasyprint or wkhtmltopdf)
        Returns None if PDF generation is not available
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Try weasyprint first
        try:
            from weasyprint import HTML
            html_content = self.generate_html()
            HTML(string=html_content).write_pdf(str(output_path))
            return output_path
        except ImportError:
            pass

        # Try pdfkit (wkhtmltopdf wrapper)
        try:
            import pdfkit
            html_content = self.generate_html()
            pdfkit.from_string(html_content, str(output_path))
            return output_path
        except ImportError:
            pass

        # Fallback: save HTML and print instructions
        html_path = output_path.with_suffix('.html')
        self.save_html(html_path)
        print("PDF generation requires 'weasyprint' or 'pdfkit'.")
        print("Install with: pip install weasyprint")
        print(f"HTML saved to: {html_path}")
        print("You can print to PDF from your browser.")
        return None

    def save_json(self, output_path: Path) -> Path:
        """Save findings as JSON for programmatic access"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            'metadata': {
                'project_name': self.metadata.project_name,
                'contract_name': self.metadata.contract_name,
                'version': self.metadata.version,
                'auditor': self.metadata.auditor,
                'organization': self.metadata.organization,
                'audit_date': self.metadata.audit_date,
                'report_id': self.metadata.report_id,
                'contract_hash': self.metadata.contract_hash,
                'solidity_version': self.metadata.solidity_version,
                'lines_of_code': self.metadata.lines_of_code,
            },
            'summary': {
                'risk_score': self._calculate_risk_score(),
                'total_findings': len(self.findings),
                'by_severity': self._get_severity_summary(),
                'by_layer': self._get_layer_summary(),
                'by_tool': self._get_tool_summary(),
            },
            'findings': [
                {
                    'id': f.id,
                    'title': f.title,
                    'severity': f.severity,
                    'category': f.category,
                    'description': f.description,
                    'location': f.location,
                    'line_number': f.line_number,
                    'tool': f.tool,
                    'layer': f.layer,
                    'swc_id': f.swc_id,
                    'cwe_id': f.cwe_id,
                    'remediation': f.remediation,
                    'references': f.references,
                }
                for f in self.findings
            ],
            'generated_at': self.generated_at.isoformat(),
            'generator': 'MIESC v4.2.1',
        }

        output_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        return output_path


def create_sample_report():
    """Create a sample report for testing"""
    metadata = AuditMetadata(
        project_name="DeFi Protocol v2.0",
        contract_name="LendingPool.sol",
        version="2.0.0",
        auditor="Fernando Boiero",
        organization="MIESC Security",
        audit_date=datetime.now().strftime("%Y-%m-%d"),
        report_id=f"MIESC-{datetime.now().strftime('%Y%m%d')}-001",
        contract_hash=hashlib.sha256(b"sample contract").hexdigest(),
        solidity_version="0.8.20",
        lines_of_code=1250,
    )

    findings = [
        Finding(
            id="MIESC-001",
            title="Reentrancy Vulnerability in withdraw()",
            severity="Critical",
            category="Reentrancy",
            description="The withdraw function makes an external call before updating state, allowing reentrant calls.",
            location="LendingPool.sol:142",
            line_number=142,
            code_snippet="function withdraw(uint256 amount) external {\n    (bool success,) = msg.sender.call{value: amount}(\"\");\n    balances[msg.sender] -= amount; // State update after call\n}",
            tool="Slither",
            layer=1,
            swc_id="SWC-107",
            cwe_id="CWE-841",
            remediation="Apply checks-effects-interactions pattern. Update state before making external calls.",
            references=["https://swcregistry.io/docs/SWC-107"],
        ),
        Finding(
            id="MIESC-002",
            title="Integer Overflow in deposit calculation",
            severity="High",
            category="Arithmetic",
            description="The deposit function does not check for overflow when calculating interest.",
            location="LendingPool.sol:89",
            line_number=89,
            tool="Mythril",
            layer=3,
            swc_id="SWC-101",
            remediation="Use SafeMath or Solidity 0.8+ built-in overflow checks.",
        ),
        Finding(
            id="MIESC-003",
            title="Missing access control on setInterestRate()",
            severity="High",
            category="Access Control",
            description="The setInterestRate function can be called by any address.",
            location="LendingPool.sol:205",
            tool="Slither",
            layer=1,
            remediation="Add onlyOwner or role-based access control modifier.",
        ),
        Finding(
            id="MIESC-004",
            title="Potential flash loan attack vector",
            severity="Medium",
            category="DeFi",
            description="The liquidation function does not implement flash loan protection.",
            location="LendingPool.sol:312",
            tool="DeFiDetector",
            layer=8,
            remediation="Add same-block transaction checks or use TWAP for price oracle.",
        ),
    ]

    generator = AuditReportGenerator(
        metadata=metadata,
        findings=findings,
        raw_tool_outputs={
            "Slither": {"detectors": ["reentrancy-eth", "missing-zero-check"]},
            "Mythril": {"issues": [{"swc-id": "SWC-101", "severity": "High"}]},
        }
    )

    return generator


if __name__ == "__main__":
    # Demo: generate sample report
    generator = create_sample_report()

    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    html_path = generator.save_html(output_dir / "sample_audit_report.html")
    json_path = generator.save_json(output_dir / "sample_audit_report.json")

    print(f"HTML report saved to: {html_path}")
    print(f"JSON report saved to: {json_path}")

    # Try PDF
    pdf_path = generator.save_pdf(output_dir / "sample_audit_report.pdf")
    if pdf_path:
        print(f"PDF report saved to: {pdf_path}")
