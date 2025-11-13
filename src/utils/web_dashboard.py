#!/usr/bin/env python3
"""
Modern Interactive Web Dashboard for Xaudit v2.0
Integrates all 10 analysis tools with dynamic visualizations
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import re


class WebDashboardGenerator:
    """Generate modern interactive web dashboard for Xaudit results."""

    def __init__(self, results_dir: str):
        self.results_dir = Path(results_dir)
        self.metrics = self._collect_all_metrics()

    def _collect_all_metrics(self) -> Dict[str, Any]:
        """Collect metrics from all 10 tools."""
        return {
            'timestamp': datetime.now().isoformat(),
            'tools': {
                'solhint': self._parse_solhint(),
                'slither': self._parse_slither(),
                'surya': self._parse_surya(),
                'mythril': self._parse_mythril(),
                'manticore': self._parse_manticore(),
                'echidna': self._parse_echidna(),
                'medusa': self._parse_medusa(),
                'foundry_fuzz': self._parse_foundry_fuzz(),
                'foundry_invariants': self._parse_foundry_invariants(),
                'certora': self._parse_certora()
            },
            'summary': {}
        }

    def _parse_solhint(self) -> Dict[str, Any]:
        """Parse Solhint linting results."""
        solhint_dir = self.results_dir / 'solhint'
        if not solhint_dir.exists():
            return {'executed': False, 'issues': []}

        issues = []
        for json_file in solhint_dir.glob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    for item in data:
                        issues.append({
                            'file': item.get('filePath', 'unknown'),
                            'line': item.get('line', 0),
                            'severity': item.get('severity', 'info'),
                            'message': item.get('message', ''),
                            'ruleId': item.get('ruleId', '')
                        })
            except:
                pass

        return {
            'executed': True,
            'total_issues': len(issues),
            'issues': issues,
            'by_severity': self._group_by_severity(issues, 'severity')
        }

    def _parse_slither(self) -> Dict[str, Any]:
        """Parse Slither static analysis results."""
        slither_dir = self.results_dir / 'slither'
        if not slither_dir.exists():
            return {'executed': False, 'detectors': []}

        detectors = []
        for json_file in slither_dir.glob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    for det in data.get('results', {}).get('detectors', []):
                        detectors.append({
                            'check': det.get('check', 'unknown'),
                            'impact': det.get('impact', 'Informational'),
                            'confidence': det.get('confidence', 'Medium'),
                            'description': det.get('description', ''),
                            'elements': len(det.get('elements', []))
                        })
            except:
                pass

        return {
            'executed': True,
            'total_detectors': len(detectors),
            'detectors': detectors,
            'by_impact': self._group_by_severity(detectors, 'impact')
        }

    def _parse_surya(self) -> Dict[str, Any]:
        """Parse Surya visualization and analysis."""
        surya_dir = self.results_dir / 'surya'
        if not surya_dir.exists():
            return {'executed': False}

        # Count generated artifacts
        graphs = list(surya_dir.glob('*.dot')) + list(surya_dir.glob('*.png'))
        reports = list(surya_dir.glob('*.md')) + list(surya_dir.glob('*.txt'))

        return {
            'executed': True,
            'graphs_generated': len(graphs),
            'reports_generated': len(reports),
            'artifacts': [f.name for f in graphs + reports]
        }

    def _parse_mythril(self) -> Dict[str, Any]:
        """Parse Mythril symbolic execution results."""
        mythril_dir = self.results_dir / 'mythril'
        if not mythril_dir.exists():
            return {'executed': False, 'issues': []}

        issues = []
        for json_file in mythril_dir.glob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    for issue in data.get('issues', []):
                        issues.append({
                            'title': issue.get('title', ''),
                            'severity': issue.get('severity', 'Low'),
                            'swc_id': issue.get('swc-id', ''),
                            'description': issue.get('description', {}).get('head', ''),
                            'address': issue.get('address', 0)
                        })
            except:
                pass

        return {
            'executed': True,
            'total_issues': len(issues),
            'issues': issues,
            'by_severity': self._group_by_severity(issues, 'severity')
        }

    def _parse_manticore(self) -> Dict[str, Any]:
        """Parse Manticore symbolic execution and exploit generation."""
        manticore_dir = self.results_dir / 'manticore'
        if not manticore_dir.exists():
            return {'executed': False, 'exploits': 0}

        # Count test cases and exploits
        test_cases = list(manticore_dir.glob('**/test_*.txt'))
        exploits = list(manticore_dir.glob('**/exploit_*.py'))

        return {
            'executed': True,
            'test_cases': len(test_cases),
            'exploits_generated': len(exploits),
            'paths_explored': len(list(manticore_dir.glob('**/state_*')))
        }

    def _parse_echidna(self) -> Dict[str, Any]:
        """Parse Echidna fuzzing results."""
        echidna_dir = self.results_dir / 'echidna'
        if not echidna_dir.exists():
            return {'executed': False, 'properties': []}

        properties = []
        for txt_file in echidna_dir.glob('*.txt'):
            try:
                content = txt_file.read_text()
                # Parse property results
                for line in content.split('\n'):
                    if 'echidna_' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            prop_name = parts[0].strip()
                            result = 'passed' if 'passed!' in line else 'failed'
                            properties.append({
                                'name': prop_name,
                                'status': result
                            })
            except:
                pass

        passed = sum(1 for p in properties if p['status'] == 'passed')
        failed = sum(1 for p in properties if p['status'] == 'failed')

        return {
            'executed': True,
            'total_properties': len(properties),
            'passed': passed,
            'failed': failed,
            'properties': properties
        }

    def _parse_medusa(self) -> Dict[str, Any]:
        """Parse Medusa fuzzing results."""
        medusa_dir = self.results_dir / 'medusa'
        if not medusa_dir.exists():
            return {'executed': False, 'tests': []}

        tests = []
        for json_file in medusa_dir.glob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    for test in data.get('testResults', []):
                        tests.append({
                            'name': test.get('name', ''),
                            'status': test.get('status', ''),
                            'coverage': test.get('coverage', 0)
                        })
            except:
                pass

        return {
            'executed': True,
            'total_tests': len(tests),
            'passed': sum(1 for t in tests if t['status'] == 'passed'),
            'failed': sum(1 for t in tests if t['status'] == 'failed'),
            'tests': tests
        }

    def _parse_foundry_fuzz(self) -> Dict[str, Any]:
        """Parse Foundry fuzz testing results."""
        foundry_dir = self.results_dir / 'foundry' / 'fuzz'
        if not foundry_dir.exists():
            return {'executed': False, 'tests': []}

        tests = []
        for txt_file in foundry_dir.glob('*.txt'):
            try:
                content = txt_file.read_text()
                passed = content.count('[PASS]')
                failed = content.count('[FAIL]')
                tests.append({
                    'file': txt_file.stem,
                    'passed': passed,
                    'failed': failed
                })
            except:
                pass

        total_passed = sum(t['passed'] for t in tests)
        total_failed = sum(t['failed'] for t in tests)

        return {
            'executed': True,
            'total_tests': total_passed + total_failed,
            'passed': total_passed,
            'failed': total_failed,
            'tests': tests
        }

    def _parse_foundry_invariants(self) -> Dict[str, Any]:
        """Parse Foundry invariant testing results."""
        foundry_dir = self.results_dir / 'foundry' / 'invariants'
        if not foundry_dir.exists():
            return {'executed': False, 'invariants': []}

        invariants = []
        for txt_file in foundry_dir.glob('*.txt'):
            try:
                content = txt_file.read_text()
                # Parse invariant results
                for line in content.split('\n'):
                    if 'invariant_' in line:
                        status = 'passed' if '[PASS]' in line else 'failed'
                        invariants.append({
                            'name': line.split()[0],
                            'status': status
                        })
            except:
                pass

        return {
            'executed': True,
            'total_invariants': len(invariants),
            'passed': sum(1 for i in invariants if i['status'] == 'passed'),
            'failed': sum(1 for i in invariants if i['status'] == 'failed'),
            'invariants': invariants
        }

    def _parse_certora(self) -> Dict[str, Any]:
        """Parse Certora formal verification results."""
        certora_dir = self.results_dir / 'certora'
        if not certora_dir.exists():
            return {'executed': False, 'rules': []}

        rules = []
        for json_file in certora_dir.glob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    for rule in data.get('results', []):
                        rules.append({
                            'name': rule.get('ruleName', ''),
                            'status': rule.get('status', ''),
                            'verified': rule.get('status') == 'verified'
                        })
            except:
                pass

        return {
            'executed': True,
            'total_rules': len(rules),
            'verified': sum(1 for r in rules if r.get('verified', False)),
            'violated': sum(1 for r in rules if not r.get('verified', False)),
            'rules': rules
        }

    def _group_by_severity(self, items: List[Dict], key: str) -> Dict[str, int]:
        """Group items by severity level."""
        severity_map = {}
        for item in items:
            severity = item.get(key, 'unknown').lower()
            severity_map[severity] = severity_map.get(severity, 0) + 1
        return severity_map

    def _calculate_summary(self) -> Dict[str, Any]:
        """Calculate overall summary statistics."""
        tools = self.metrics['tools']

        # Count executed tools
        executed_tools = sum(1 for tool in tools.values() if tool.get('executed', False))

        # Aggregate findings
        total_issues = 0
        critical = high = medium = low = info = 0

        # Slither
        if tools['slither'].get('executed'):
            by_impact = tools['slither'].get('by_impact', {})
            critical += by_impact.get('critical', 0)
            high += by_impact.get('high', 0)
            medium += by_impact.get('medium', 0)
            low += by_impact.get('low', 0)
            info += by_impact.get('informational', 0)

        # Mythril
        if tools['mythril'].get('executed'):
            by_sev = tools['mythril'].get('by_severity', {})
            high += by_sev.get('high', 0)
            medium += by_sev.get('medium', 0)
            low += by_sev.get('low', 0)

        # Solhint
        if tools['solhint'].get('executed'):
            by_sev = tools['solhint'].get('by_severity', {})
            critical += by_sev.get('error', 0)
            medium += by_sev.get('warning', 0)
            info += by_sev.get('info', 0)

        total_issues = critical + high + medium + low + info

        # Testing metrics
        fuzz_passed = tools['foundry_fuzz'].get('passed', 0)
        fuzz_failed = tools['foundry_fuzz'].get('failed', 0)
        invariants_passed = tools['foundry_invariants'].get('passed', 0)
        invariants_failed = tools['foundry_invariants'].get('failed', 0)
        echidna_passed = tools['echidna'].get('passed', 0)
        echidna_failed = tools['echidna'].get('failed', 0)

        total_tests = fuzz_passed + fuzz_failed + invariants_passed + invariants_failed + echidna_passed + echidna_failed
        tests_passed = fuzz_passed + invariants_passed + echidna_passed
        tests_failed = fuzz_failed + invariants_failed + echidna_failed

        return {
            'tools_executed': executed_tools,
            'total_tools': 10,
            'total_issues': total_issues,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'informational': info,
            'total_tests': total_tests,
            'tests_passed': tests_passed,
            'tests_failed': tests_failed,
            'test_pass_rate': round(tests_passed / total_tests * 100, 2) if total_tests > 0 else 0,
            'exploits_generated': tools['manticore'].get('exploits_generated', 0),
            'formal_rules_verified': tools['certora'].get('verified', 0),
            'coverage_artifacts': tools['surya'].get('graphs_generated', 0)
        }

    def generate_html_dashboard(self, output_file: Path):
        """Generate modern interactive HTML dashboard."""
        summary = self._calculate_summary()
        self.metrics['summary'] = summary

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xaudit v2.0 - Dashboard Interactivo</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            text-align: center;
        }}

        header h1 {{
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        header p {{
            color: #666;
            font-size: 1.1em;
        }}

        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .metric-card {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }}

        .metric-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
        }}

        .metric-value {{
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }}

        .metric-label {{
            color: #666;
            font-size: 1em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #17a2b8; }}
        .success {{ color: #28a745; }}
        .primary {{ color: #667eea; }}

        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }}

        .chart-card {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }}

        .chart-card h3 {{
            color: #333;
            margin-bottom: 20px;
            font-size: 1.3em;
        }}

        .tool-status {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}

        .tool-badge {{
            background: white;
            border-radius: 10px;
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }}

        .status-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}

        .status-executed {{ background: #28a745; }}
        .status-skipped {{ background: #6c757d; }}

        .details-section {{
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }}

        .details-section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}

        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }}

        tr:hover {{
            background: #f8f9fa;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }}

        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #17a2b8; color: white; }}
        .badge-info {{ background: #6c757d; color: white; }}
        .badge-success {{ background: #28a745; color: white; }}

        footer {{
            background: white;
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            color: #666;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }}

        .tabs {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #e9ecef;
        }}

        .tab {{
            padding: 12px 24px;
            cursor: pointer;
            border: none;
            background: none;
            font-size: 1em;
            color: #666;
            transition: all 0.3s;
        }}

        .tab.active {{
            color: #667eea;
            border-bottom: 3px solid #667eea;
            margin-bottom: -2px;
        }}

        .tab-content {{
            display: none;
        }}

        .tab-content.active {{
            display: block;
        }}

        @media (max-width: 768px) {{
            .metrics-grid {{
                grid-template-columns: 1fr;
            }}

            .charts-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Xaudit v2.0</h1>
            <p>Dashboard Interactivo de Análisis de Seguridad</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Generado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Herramientas Ejecutadas</div>
                <div class="metric-value primary">{summary['tools_executed']}/{summary['total_tools']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Issues Totales</div>
                <div class="metric-value">{summary['total_issues']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Críticos</div>
                <div class="metric-value critical">{summary['critical']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Altos</div>
                <div class="metric-value high">{summary['high']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Tests Pasados</div>
                <div class="metric-value success">{summary['tests_passed']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Tasa de Éxito</div>
                <div class="metric-value success">{summary['test_pass_rate']}%</div>
            </div>
        </div>

        <div class="tool-status">
            {self._generate_tool_badges()}
        </div>

        <div class="charts-grid">
            <div class="chart-card">
                <h3>Distribución por Severidad</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Resultados de Testing</h3>
                <canvas id="testingChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Cobertura de Herramientas</h3>
                <canvas id="toolsChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Métricas de Seguridad</h3>
                <canvas id="securityChart"></canvas>
            </div>
        </div>

        <div class="details-section">
            <h2>Detalles de Análisis</h2>
            <div class="tabs">
                <button class="tab active" onclick="showTab('static')">Análisis Estático</button>
                <button class="tab" onclick="showTab('symbolic')">Ejecución Simbólica</button>
                <button class="tab" onclick="showTab('fuzzing')">Fuzzing</button>
                <button class="tab" onclick="showTab('formal')">Verificación Formal</button>
            </div>

            <div id="static-content" class="tab-content active">
                {self._generate_static_analysis_table()}
            </div>

            <div id="symbolic-content" class="tab-content">
                {self._generate_symbolic_analysis_table()}
            </div>

            <div id="fuzzing-content" class="tab-content">
                {self._generate_fuzzing_table()}
            </div>

            <div id="formal-content" class="tab-content">
                {self._generate_formal_verification_table()}
            </div>
        </div>

        <footer>
            <p><strong>Xaudit v2.0</strong> - Framework Híbrido de Auditoría de Smart Contracts</p>
            <p>Universidad Tecnológica Nacional - FRVM | Fernando Boiero</p>
        </footer>
    </div>

    <script>
        // Datos para gráficos
        const severityData = {{
            labels: ['Crítico', 'Alto', 'Medio', 'Bajo', 'Informacional'],
            datasets: [{{
                label: 'Vulnerabilidades',
                data: [{summary['critical']}, {summary['high']}, {summary['medium']}, {summary['low']}, {summary['informational']}],
                backgroundColor: [
                    '#dc3545',
                    '#fd7e14',
                    '#ffc107',
                    '#17a2b8',
                    '#6c757d'
                ]
            }}]
        }};

        const testingData = {{
            labels: ['Pasados', 'Fallidos'],
            datasets: [{{
                label: 'Tests',
                data: [{summary['tests_passed']}, {summary['tests_failed']}],
                backgroundColor: ['#28a745', '#dc3545']
            }}]
        }};

        const toolsData = {{
            labels: ['Ejecutadas', 'No Ejecutadas'],
            datasets: [{{
                label: 'Herramientas',
                data: [{summary['tools_executed']}, {summary['total_tools'] - summary['tools_executed']}],
                backgroundColor: ['#667eea', '#e9ecef']
            }}]
        }};

        const securityData = {{
            labels: ['Exploits', 'Reglas Verificadas', 'Artefactos'],
            datasets: [{{
                label: 'Métricas',
                data: [{summary['exploits_generated']}, {summary['formal_rules_verified']}, {summary['coverage_artifacts']}],
                backgroundColor: ['#dc3545', '#28a745', '#17a2b8']
            }}]
        }};

        // Configuración de gráficos
        const chartConfig = {{
            responsive: true,
            maintainAspectRatio: true,
            plugins: {{
                legend: {{
                    position: 'bottom'
                }}
            }}
        }};

        // Crear gráficos
        new Chart(document.getElementById('severityChart'), {{
            type: 'bar',
            data: severityData,
            options: chartConfig
        }});

        new Chart(document.getElementById('testingChart'), {{
            type: 'doughnut',
            data: testingData,
            options: chartConfig
        }});

        new Chart(document.getElementById('toolsChart'), {{
            type: 'pie',
            data: toolsData,
            options: chartConfig
        }});

        new Chart(document.getElementById('securityChart'), {{
            type: 'bar',
            data: securityData,
            options: chartConfig
        }});

        // Función para cambiar tabs
        function showTab(tabName) {{
            // Ocultar todos los contenidos
            document.querySelectorAll('.tab-content').forEach(content => {{
                content.classList.remove('active');
            }});

            // Desactivar todos los tabs
            document.querySelectorAll('.tab').forEach(tab => {{
                tab.classList.remove('active');
            }});

            // Activar el contenido seleccionado
            document.getElementById(tabName + '-content').classList.add('active');

            // Activar el tab seleccionado
            event.target.classList.add('active');
        }}
    </script>
</body>
</html>
"""

        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(html)
        print(f"✅ Dashboard web generado: {output_file}")
        return output_file

    def _generate_tool_badges(self) -> str:
        """Generate HTML for tool status badges."""
        tools_info = [
            ('Solhint', 'solhint'),
            ('Slither', 'slither'),
            ('Surya', 'surya'),
            ('Mythril', 'mythril'),
            ('Manticore', 'manticore'),
            ('Echidna', 'echidna'),
            ('Medusa', 'medusa'),
            ('Foundry Fuzz', 'foundry_fuzz'),
            ('Foundry Invariants', 'foundry_invariants'),
            ('Certora', 'certora')
        ]

        badges_html = ""
        for name, key in tools_info:
            executed = self.metrics['tools'][key].get('executed', False)
            status_class = 'status-executed' if executed else 'status-skipped'
            status_text = 'Ejecutada' if executed else 'No ejecutada'
            badges_html += f"""
            <div class="tool-badge">
                <span class="status-dot {status_class}"></span>
                <span><strong>{name}</strong><br><small>{status_text}</small></span>
            </div>
            """

        return badges_html

    def _generate_static_analysis_table(self) -> str:
        """Generate HTML table for static analysis results."""
        slither = self.metrics['tools']['slither']
        solhint = self.metrics['tools']['solhint']

        html = "<h3>Análisis Estático (Slither, Solhint, Surya)</h3>"

        if slither.get('executed'):
            html += f"<p><strong>Slither:</strong> {slither['total_detectors']} detectores activados</p>"
            if slither['detectors']:
                html += "<table><thead><tr><th>Detector</th><th>Impacto</th><th>Confianza</th><th>Elementos</th></tr></thead><tbody>"
                for det in slither['detectors'][:10]:  # Primeros 10
                    impact_class = det['impact'].lower()
                    html += f"""<tr>
                        <td>{det['check']}</td>
                        <td><span class="badge badge-{impact_class}">{det['impact']}</span></td>
                        <td>{det['confidence']}</td>
                        <td>{det['elements']}</td>
                    </tr>"""
                html += "</tbody></table>"

        if solhint.get('executed'):
            html += f"<p style='margin-top: 20px'><strong>Solhint:</strong> {solhint['total_issues']} issues encontrados</p>"

        return html

    def _generate_symbolic_analysis_table(self) -> str:
        """Generate HTML table for symbolic execution results."""
        mythril = self.metrics['tools']['mythril']
        manticore = self.metrics['tools']['manticore']

        html = "<h3>Ejecución Simbólica (Mythril, Manticore)</h3>"

        if mythril.get('executed'):
            html += f"<p><strong>Mythril:</strong> {mythril['total_issues']} vulnerabilidades detectadas</p>"
            if mythril['issues']:
                html += "<table><thead><tr><th>Título</th><th>Severidad</th><th>SWC ID</th><th>Descripción</th></tr></thead><tbody>"
                for issue in mythril['issues'][:10]:
                    sev_class = issue['severity'].lower()
                    html += f"""<tr>
                        <td>{issue['title']}</td>
                        <td><span class="badge badge-{sev_class}">{issue['severity']}</span></td>
                        <td>{issue['swc_id']}</td>
                        <td>{issue['description'][:100]}...</td>
                    </tr>"""
                html += "</tbody></table>"

        if manticore.get('executed'):
            html += f"""<p style='margin-top: 20px'><strong>Manticore:</strong>
                {manticore['exploits_generated']} exploits generados |
                {manticore['test_cases']} casos de prueba |
                {manticore['paths_explored']} paths explorados</p>"""

        return html

    def _generate_fuzzing_table(self) -> str:
        """Generate HTML table for fuzzing results."""
        echidna = self.metrics['tools']['echidna']
        medusa = self.metrics['tools']['medusa']
        foundry_fuzz = self.metrics['tools']['foundry_fuzz']

        html = "<h3>Fuzzing (Echidna, Medusa, Foundry)</h3>"

        if echidna.get('executed'):
            html += f"<p><strong>Echidna:</strong> {echidna['total_properties']} propiedades testeadas</p>"
            if echidna['properties']:
                html += "<table><thead><tr><th>Propiedad</th><th>Estado</th></tr></thead><tbody>"
                for prop in echidna['properties']:
                    badge_class = 'badge-success' if prop['status'] == 'passed' else 'badge-critical'
                    html += f"""<tr>
                        <td>{prop['name']}</td>
                        <td><span class="badge {badge_class}">{prop['status'].upper()}</span></td>
                    </tr>"""
                html += "</tbody></table>"

        if foundry_fuzz.get('executed'):
            html += f"<p style='margin-top: 20px'><strong>Foundry Fuzz:</strong> {foundry_fuzz['passed']} pasados, {foundry_fuzz['failed']} fallidos</p>"

        if medusa.get('executed'):
            html += f"<p style='margin-top: 20px'><strong>Medusa:</strong> {medusa['passed']} pasados, {medusa['failed']} fallidos</p>"

        return html

    def _generate_formal_verification_table(self) -> str:
        """Generate HTML table for formal verification results."""
        certora = self.metrics['tools']['certora']
        foundry_inv = self.metrics['tools']['foundry_invariants']

        html = "<h3>Verificación Formal (Certora, Foundry Invariants)</h3>"

        if certora.get('executed'):
            html += f"<p><strong>Certora:</strong> {certora['verified']} reglas verificadas, {certora['violated']} violadas</p>"
            if certora['rules']:
                html += "<table><thead><tr><th>Regla</th><th>Estado</th></tr></thead><tbody>"
                for rule in certora['rules']:
                    badge_class = 'badge-success' if rule.get('verified') else 'badge-critical'
                    html += f"""<tr>
                        <td>{rule['name']}</td>
                        <td><span class="badge {badge_class}">{rule['status'].upper()}</span></td>
                    </tr>"""
                html += "</tbody></table>"

        if foundry_inv.get('executed'):
            html += f"<p style='margin-top: 20px'><strong>Foundry Invariants:</strong> {foundry_inv['passed']} pasados, {foundry_inv['failed']} fallidos</p>"

        return html

    def save_metrics_json(self, output_file: Path):
        """Save complete metrics as JSON."""
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.metrics, f, indent=2, ensure_ascii=False)
        print(f"✅ Métricas JSON guardadas: {output_file}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate interactive web dashboard for Xaudit v2.0")
    parser.add_argument("--results", required=True, help="Directory with analysis results")
    parser.add_argument("--output", default="analysis/dashboard", help="Output directory")

    args = parser.parse_args()

    results_dir = Path(args.results)
    output_dir = Path(args.output)

    if not results_dir.exists():
        print(f"❌ Error: Results directory not found: {results_dir}")
        sys.exit(1)

    print("🚀 Generating interactive web dashboard...")

    dashboard = WebDashboardGenerator(results_dir)

    # Generate outputs
    dashboard.generate_html_dashboard(output_dir / "index.html")
    dashboard.save_metrics_json(output_dir / "metrics.json")

    print(f"\n✅ Dashboard generated successfully!")
    print(f"\n📊 Open in browser: file://{(output_dir / 'index.html').absolute()}")


if __name__ == "__main__":
    main()
