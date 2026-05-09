#!/usr/bin/env python3
"""
MIESC Profesional HTML Report Generator

Converts Markdown audit reports to professional HTML format
with embedded CSS for PDF printing via browser.

Usage:
    python scripts/generate_html_report.py input.md output.html
    # Then open in browser and Print -> Save as PDF
"""

import argparse
import re
import sys
from pathlib import Path

try:
    import markdown
except ImportError:
    print("Installing markdown...")
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "markdown", "-q"])
    import markdown


PROFESIONAL_CSS = """
/* MIESC Profesional Report - Professional Print Styles */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
    --color-critical: #dc3545;
    --color-high: #fd7e14;
    --color-medium: #ffc107;
    --color-low: #28a745;
    --color-info: #17a2b8;
    --color-primary: #2563eb;
    --color-dark: #1e293b;
    --color-gray: #64748b;
    --color-light: #f8fafc;
    --color-border: #e2e8f0;
}

@page {
    size: A4;
    margin: 2cm;
}

@media print {
    body { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
    .page-break { page-break-after: always; }
    h1, h2, h3 { page-break-after: avoid; }
    table, pre, .finding-card { page-break-inside: avoid; }
    .no-print { display: none !important; }
}

* { box-sizing: border-box; }

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: var(--color-dark);
    background: white;
    max-width: 210mm;
    margin: 0 auto;
    padding: 20px;
}

/* Cover Page */
.cover-page {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
    background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
    color: white;
    margin: -20px -20px 40px -20px;
    padding: 60px 40px;
    border-radius: 0 0 20px 20px;
}

.cover-page h1 { font-size: 36pt; font-weight: 700; margin-bottom: 10px; color: white; border: none; }
.cover-page h2 { font-size: 18pt; font-weight: 400; color: #94a3b8; margin: 10px 0; }
.cover-page h3 { font-size: 16pt; font-weight: 500; color: #60a5fa; border: 2px solid #60a5fa; padding: 12px 30px; border-radius: 8px; display: inline-block; margin: 20px 0; }
.cover-page p { color: #cbd5e1; margin: 5px 0; }
.cover-page strong { color: white; }
.cover-page em { color: #94a3b8; font-size: 10pt; display: block; margin-top: 40px; }
.cover-page hr { border: none; border-top: 1px solid #475569; margin: 30px 0; width: 60%; }

/* Typography */
h1 { font-size: 22pt; font-weight: 700; color: var(--color-dark); margin: 40px 0 15px 0; padding-bottom: 10px; border-bottom: 3px solid var(--color-primary); }
h2 { font-size: 14pt; font-weight: 600; color: var(--color-dark); margin: 30px 0 10px 0; }
h3 { font-size: 12pt; font-weight: 600; color: var(--color-gray); margin: 20px 0 8px 0; }
p { margin: 10px 0; text-align: justify; }

/* Tables */
table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 10pt; }
thead { background: var(--color-dark); color: white; }
th { padding: 12px 10px; text-align: left; font-weight: 600; text-transform: uppercase; font-size: 9pt; letter-spacing: 0.5px; }
td { padding: 10px; border-bottom: 1px solid var(--color-border); vertical-align: top; }
tbody tr:nth-child(even) { background: var(--color-light); }

/* Severity Badges */
.severity-critical { background: var(--color-critical); color: white; padding: 3px 10px; border-radius: 4px; font-weight: 600; font-size: 9pt; }
.severity-high { background: var(--color-high); color: white; padding: 3px 10px; border-radius: 4px; font-weight: 600; font-size: 9pt; }
.severity-medium { background: var(--color-medium); color: var(--color-dark); padding: 3px 10px; border-radius: 4px; font-weight: 600; font-size: 9pt; }
.severity-low { background: var(--color-low); color: white; padding: 3px 10px; border-radius: 4px; font-weight: 600; font-size: 9pt; }
.severity-info { background: var(--color-info); color: white; padding: 3px 10px; border-radius: 4px; font-weight: 600; font-size: 9pt; }

/* Recommendation Box */
.recommendation-box { border-radius: 10px; padding: 20px; margin: 20px 0; }
.recommendation-box[style*="dc3545"] { background: #fef2f2; }
.recommendation-box[style*="ff9800"], .recommendation-box[style*="ffc107"] { background: #fffbeb; }
.recommendation-box[style*="28a745"] { background: #dcfce7; }

/* Finding Cards */
.finding-header { border-radius: 10px; padding: 15px; margin: 15px 0 10px 0; color: white; }
.finding-header table { margin: 0; background: transparent; }
.finding-header th, .finding-header td { color: white; border: none; padding: 5px 10px; background: transparent; }
.finding-header thead { background: transparent; }
.finding-header[style*="dc3545"] { background: linear-gradient(135deg, #dc3545 0%, #b91c1c 100%); }
.finding-header[style*="fd7e14"] { background: linear-gradient(135deg, #fd7e14 0%, #ea580c 100%); }
.finding-header[style*="ffc107"] { background: linear-gradient(135deg, #ffc107 0%, #d97706 100%); color: var(--color-dark); }
.finding-header[style*="ffc107"] th, .finding-header[style*="ffc107"] td { color: var(--color-dark); }
.finding-header[style*="28a745"] { background: linear-gradient(135deg, #28a745 0%, #16a34a 100%); }
.finding-header[style*="17a2b8"] { background: linear-gradient(135deg, #17a2b8 0%, #0891b2 100%); }

/* Code */
pre, code { font-family: 'JetBrains Mono', 'Fira Code', Consolas, monospace; font-size: 9pt; }
pre { background: #1e293b; color: #e2e8f0; padding: 15px; border-radius: 8px; overflow-x: auto; margin: 15px 0; line-height: 1.5; }
code { background: #f1f5f9; color: #be185d; padding: 2px 6px; border-radius: 4px; }
pre code { background: transparent; color: inherit; padding: 0; }

/* Risk Matrix */
pre:has(code:contains("LIKELIHOOD")), pre:first-of-type:contains("LIKELIHOOD") {
    background: var(--color-light);
    color: var(--color-dark);
    border: 1px solid var(--color-border);
}

/* Lists */
ul, ol { margin: 10px 0; padding-left: 25px; }
li { margin: 5px 0; }

/* Links */
a { color: var(--color-primary); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Horizontal Rules */
hr { border: none; border-top: 1px solid var(--color-border); margin: 30px 0; }

/* Footer */
.footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid var(--color-border); text-align: center; color: var(--color-gray); font-size: 10pt; }

/* Metrics */
.metric-box { display: inline-block; background: var(--color-light); border: 1px solid var(--color-border); border-radius: 8px; padding: 15px 25px; margin: 5px; text-align: center; }
.metric-value { font-size: 28pt; font-weight: 700; color: var(--color-primary); display: block; }
.metric-label { font-size: 9pt; color: var(--color-gray); text-transform: uppercase; }

/* Print button */
.print-btn { position: fixed; top: 20px; right: 20px; background: var(--color-primary); color: white; border: none; padding: 12px 24px; border-radius: 8px; font-size: 11pt; cursor: pointer; font-weight: 600; box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3); z-index: 1000; }
.print-btn:hover { background: #1d4ed8; }

/* Table of Contents */
.toc { background: var(--color-light); border: 1px solid var(--color-border); border-radius: 10px; padding: 20px 30px; margin: 20px 0; }
.toc h2 { margin-top: 0; }
.toc ol { counter-reset: section; list-style: none; padding-left: 0; }
.toc li { counter-increment: section; margin: 8px 0; }
.toc li::before { content: counter(section) ". "; color: var(--color-primary); font-weight: 600; }
"""


def enhance_html(html: str) -> str:
    """Enhance HTML with better styling classes."""

    # Add severity classes
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        html = re.sub(
            rf'\*\*({sev})\*\*',
            rf'<span class="severity-{sev.lower()}">{sev}</span>',
            html
        )
        html = re.sub(
            rf'<td>({sev})</td>',
            rf'<td><span class="severity-{sev.lower()}">{sev}</span></td>',
            html
        )

    # Fix finding headers gradient
    for color in ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#17a2b8']:
        html = html.replace(f'background: {color}', f'background: {color}')

    return html


def markdown_to_html(md_content: str) -> str:
    """Convert Markdown to HTML."""
    extensions = [
        'markdown.extensions.tables',
        'markdown.extensions.fenced_code',
        'markdown.extensions.toc',
        'markdown.extensions.attr_list',
    ]
    md = markdown.Markdown(extensions=extensions)
    return md.convert(md_content)


def create_html_document(body: str, title: str) -> str:
    """Create complete HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
{PROFESIONAL_CSS}
    </style>
</head>
<body>
    <button class="print-btn no-print" onclick="window.print()">📄 Save as PDF</button>
    {body}
    <script>
        // Auto-enhance severity badges
        document.querySelectorAll('td, strong').forEach(el => {{
            const text = el.textContent.trim();
            if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(text)) {{
                el.innerHTML = '<span class="severity-' + text.toLowerCase() + '">' + text + '</span>';
            }}
        }});
    </script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Generate HTML report from Markdown")
    parser.add_argument("input", type=Path, help="Input Markdown file")
    parser.add_argument("output", type=Path, help="Output HTML file")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: {args.input} not found")
        sys.exit(1)

    print(f"📖 Reading: {args.input}")
    md_content = args.input.read_text(encoding='utf-8')

    # Extract title
    title_match = re.search(r'^title:\s*(.+)$', md_content, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else "Security Audit Report"

    # Remove YAML frontmatter
    md_content = re.sub(r'^---\n.*?\n---\n', '', md_content, flags=re.DOTALL)

    print("🔄 Converting to HTML...")
    html_body = markdown_to_html(md_content)
    html_body = enhance_html(html_body)

    print("🎨 Applying premium styles...")
    full_html = create_html_document(html_body, title)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(full_html, encoding='utf-8')

    print(f"✅ HTML report generated: {args.output}")
    print(f"   Size: {args.output.stat().st_size / 1024:.1f} KB")
    print()
    print("📄 To create PDF:")
    print(f"   1. Open {args.output} in browser")
    print("   2. Click 'Save as PDF' button (or Cmd+P / Ctrl+P)")
    print("   3. Select 'Save as PDF' as destination")


if __name__ == "__main__":
    main()
