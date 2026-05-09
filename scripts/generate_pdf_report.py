#!/usr/bin/env python3
"""
MIESC Profesional PDF Report Generator

Converts Markdown audit reports to professional PDF format
using weasyprint with custom CSS styling.

Usage:
    python scripts/generate_pdf_report.py input.md output.pdf
    python scripts/generate_pdf_report.py input.md output.pdf --css custom.css
"""

import argparse
import re
import sys
from pathlib import Path

try:
    import markdown
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install markdown weasyprint")
    sys.exit(1)


# Default CSS path
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
DEFAULT_CSS = PROJECT_ROOT / "docs" / "templates" / "reports" / "profesional.css"


def enhance_html(html_content: str) -> str:
    """Add CSS classes and enhance HTML for better PDF rendering."""

    # Add severity badge classes
    severity_colors = {
        'CRITICAL': ('severity-critical', '#dc3545'),
        'HIGH': ('severity-high', '#fd7e14'),
        'MEDIUM': ('severity-medium', '#ffc107'),
        'LOW': ('severity-low', '#28a745'),
        'INFO': ('severity-info', '#17a2b8'),
    }

    for severity, (css_class, color) in severity_colors.items():
        # Wrap **SEVERITY** in spans
        html_content = re.sub(
            rf'\*\*({severity})\*\*',
            rf'<span class="{css_class}">\1</span>',
            html_content
        )
        # Also handle plain text in tables
        html_content = re.sub(
            rf'<td>({severity})</td>',
            rf'<td><span class="{css_class}">\1</span></td>',
            html_content
        )

    # Enhance recommendation boxes
    html_content = re.sub(
        r'<div class="recommendation-box"([^>]*)>',
        lambda m: f'<div class="recommendation-box{get_recommendation_class(m.group(0))}"\\1>',
        html_content
    )

    # Add risk matrix class
    html_content = html_content.replace(
        '<pre><code>                    LIKELIHOOD',
        '<pre class="risk-matrix"><code>                    LIKELIHOOD'
    )

    # Enhance finding headers with better colors
    finding_colors = {
        '#dc3545': 'background: linear-gradient(135deg, #dc3545 0%, #b91c1c 100%);',
        '#fd7e14': 'background: linear-gradient(135deg, #fd7e14 0%, #ea580c 100%);',
        '#ffc107': 'background: linear-gradient(135deg, #ffc107 0%, #d97706 100%);',
        '#28a745': 'background: linear-gradient(135deg, #28a745 0%, #16a34a 100%);',
        '#17a2b8': 'background: linear-gradient(135deg, #17a2b8 0%, #0891b2 100%);',
    }

    for color, gradient in finding_colors.items():
        html_content = html_content.replace(
            f'background: {color};',
            gradient
        )

    return html_content


def get_recommendation_class(text: str) -> str:
    """Determine recommendation box class based on content."""
    if 'NO-GO' in text or '#dc3545' in text:
        return ' no-go'
    elif 'CONDITIONAL' in text or '#ff9800' in text or '#ffc107' in text:
        return ' conditional'
    elif 'GO' in text or '#28a745' in text:
        return ' go'
    return ''


def markdown_to_html(md_content: str) -> str:
    """Convert Markdown to HTML with extensions."""
    extensions = [
        'markdown.extensions.tables',
        'markdown.extensions.fenced_code',
        'markdown.extensions.codehilite',
        'markdown.extensions.toc',
        'markdown.extensions.meta',
        'markdown.extensions.attr_list',
    ]

    md = markdown.Markdown(extensions=extensions)
    html_body = md.convert(md_content)

    return html_body


def create_full_html(body_html: str, title: str = "Security Audit Report") -> str:
    """Wrap HTML body in full document structure."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
</head>
<body>
{body_html}
</body>
</html>"""


def generate_pdf(
    input_path: Path,
    output_path: Path,
    css_path: Path = None
) -> bool:
    """Generate PDF from Markdown file."""

    # Read input
    print(f"Reading: {input_path}")
    md_content = input_path.read_text(encoding='utf-8')

    # Extract title from frontmatter or first heading
    title_match = re.search(r'^title:\s*(.+)$', md_content, re.MULTILINE)
    if title_match:
        title = title_match.group(1).strip()
    else:
        title_match = re.search(r'^#\s+(.+)$', md_content, re.MULTILINE)
        title = title_match.group(1) if title_match else "Security Audit Report"

    # Remove YAML frontmatter for markdown processing
    md_content = re.sub(r'^---\n.*?\n---\n', '', md_content, flags=re.DOTALL)

    # Convert to HTML
    print("Converting Markdown to HTML...")
    html_body = markdown_to_html(md_content)

    # Enhance HTML
    html_body = enhance_html(html_body)

    # Create full HTML document
    full_html = create_full_html(html_body, title)

    # Load CSS
    css_path = css_path or DEFAULT_CSS
    if css_path.exists():
        print(f"Loading CSS: {css_path}")
        css_content = css_path.read_text(encoding='utf-8')
    else:
        print(f"Warning: CSS not found at {css_path}, using minimal styles")
        css_content = """
        body { font-family: Arial, sans-serif; font-size: 11pt; line-height: 1.5; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background: #333; color: white; }
        pre { background: #f5f5f5; padding: 1em; overflow-x: auto; }
        code { font-family: monospace; }
        """

    # Configure fonts
    font_config = FontConfiguration()

    # Generate PDF
    print(f"Generating PDF: {output_path}")
    try:
        html = HTML(string=full_html)
        css = CSS(string=css_content, font_config=font_config)
        html.write_pdf(output_path, stylesheets=[css], font_config=font_config)
        print(f"✓ PDF generated successfully: {output_path}")
        print(f"  Size: {output_path.stat().st_size / 1024:.1f} KB")
        return True
    except Exception as e:
        print(f"✗ PDF generation failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Generate professional PDF from Markdown audit report"
    )
    parser.add_argument("input", type=Path, help="Input Markdown file")
    parser.add_argument("output", type=Path, help="Output PDF file")
    parser.add_argument("--css", type=Path, help="Custom CSS file (optional)")

    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)

    # Ensure output directory exists
    args.output.parent.mkdir(parents=True, exist_ok=True)

    success = generate_pdf(args.input, args.output, args.css)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
