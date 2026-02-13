"""
MIESC CLI - Report Commands

Commands for generating formatted security reports from audit results.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import click

from miesc import __version__ as VERSION
from miesc.cli.utils import (
    RICH_AVAILABLE,
    console,
    error,
    get_root_dir,
    info,
    print_banner,
    success,
    warning,
)

# Import Rich components if available
if RICH_AVAILABLE:
    pass  # Rich imports handled via console

logger = logging.getLogger(__name__)

# Get ROOT_DIR for template paths
ROOT_DIR = get_root_dir()


# =============================================================================
# Helper Functions
# =============================================================================


def _get_impact_description(severity: str) -> str:
    """Get impact description based on severity."""
    impacts = {
        "critical": "Complete loss of funds or contract takeover possible. Immediate exploitation risk.",
        "high": "Significant financial loss or contract compromise possible under certain conditions.",
        "medium": "Limited financial impact or requires specific conditions to exploit.",
        "low": "Minor impact on contract functionality or gas efficiency.",
        "info": "Informational finding for code quality improvement.",
    }
    return impacts.get(severity, "Impact assessment pending.")


def _interactive_wizard(variables: dict, console) -> dict:
    """
    Interactive wizard for report metadata.
    Only asks for client and auditor info - everything else comes from audit data.
    """
    from rich.prompt import Prompt

    def is_missing(value):
        if value is None:
            return True
        if isinstance(value, str):
            return value.strip() == "" or value.lower() in ("n/a", "unknown", "none")
        return False

    fields_to_ask = []

    if is_missing(variables.get("client_name")):
        fields_to_ask.append(("client_name", "Client/Project Name"))

    if is_missing(variables.get("auditor_name")):
        fields_to_ask.append(("auditor_name", "Auditor Name"))

    if not fields_to_ask:
        console.print("[green]✓ Report metadata complete.[/green]")
        return variables

    console.print("\n[bold cyan]MIESC Report Wizard[/bold cyan]")
    console.print("[dim]Press Enter to skip.[/dim]\n")

    changes = 0
    for key, label in fields_to_ask:
        value = Prompt.ask(f"[yellow]{label}[/yellow]", default="")
        if value.strip():
            variables[key] = value.strip()
            changes += 1

    if changes:
        console.print(f"[green]✓ {changes} field(s) updated.[/green]\n")

    return variables


def _calculate_risk_level(summary: dict) -> str:
    """Calculate overall risk level from summary."""
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)

    if critical > 0:
        return "CRITICAL"
    elif high > 2:
        return "HIGH"
    elif high > 0 or medium > 3:
        return "MEDIUM"
    elif medium > 0:
        return "LOW"
    return "MINIMAL"


def _render_template(template: str, variables: dict) -> str:
    """Render template using Jinja2 if available, otherwise simple replacement."""
    try:
        from jinja2 import BaseLoader, Environment

        # Create Jinja2 environment with proper settings
        env = Environment(loader=BaseLoader())
        jinja_template = env.from_string(template)
        return jinja_template.render(**variables)
    except ImportError:
        # Fallback to simple rendering
        return _simple_render_template(template, variables)


def _simple_render_template(template: str, variables: dict) -> str:
    """Simple template rendering fallback without Jinja2."""
    output = template

    # Replace variables with default values {{ var | default('value') }}
    def replace_with_default(match):
        var_name = match.group(1).strip()
        default_val = match.group(2).strip().strip("'\"")
        return str(variables.get(var_name, default_val))

    output = re.sub(
        r"\{\{\s*(\w+)\s*\|\s*default\s*\(\s*['\"]?([^'\")\s]+)['\"]?\s*\)\s*\}\}",
        replace_with_default,
        output,
    )

    # Replace simple variables {{ var }}
    for key, value in variables.items():
        if not isinstance(value, (list, dict)):
            output = output.replace("{{ " + key + " }}", str(value))
            output = output.replace("{{" + key + "}}", str(value))

    # Handle generic for loops (including {%- and -%} whitespace control)
    loop_pattern = r"\{%-?\s*for\s+(\w+)\s+in\s+(\w+)\s*-?%\}(.*?)\{%-?\s*endfor\s*-?%\}"

    def replace_loop(match):
        item_name = match.group(1)
        list_name = match.group(2)
        loop_body = match.group(3)

        items = variables.get(list_name, [])
        if not items:
            return ""

        result = ""
        for item in items:
            item_output = loop_body
            if isinstance(item, dict):
                for key, value in item.items():
                    if isinstance(value, list):
                        value = ", ".join(str(v) for v in value)
                    item_output = item_output.replace(f"{{{{ {item_name}.{key} }}}}", str(value))
                    item_output = item_output.replace(f"{{{{{item_name}.{key}}}}}", str(value))
            else:
                item_output = item_output.replace(f"{{{{ {item_name} }}}}", str(item))
            result += item_output
        return result

    # Process all loops (may need multiple passes for nested loops)
    for _ in range(5):  # Max 5 passes for nested loops
        new_output = re.sub(loop_pattern, replace_loop, output, flags=re.DOTALL)
        if new_output == output:
            break
        output = new_output

    # Handle conditionals (including {%- and -%} whitespace control)
    # Remove entire if/else/endif blocks that weren't processed
    output = re.sub(r"\{%-?\s*if\s+[^%]+%\}.*?\{%-?\s*endif\s*-?%\}", "", output, flags=re.DOTALL)

    # Clean up any remaining Jinja2 syntax
    output = re.sub(r"\{%-?\s*else\s*-?%\}", "", output)
    output = re.sub(r"\{%-?\s*elif\s+[^%]+%\}", "", output)

    # Remove leftover unprocessed variables with defaults
    output = re.sub(r"\{\{\s*\w+\s*\|\s*default\s*\([^)]+\)\s*\}\}", "", output)

    # Remove leftover unprocessed simple variables
    output = re.sub(r"\{\{\s*\w+\s*\}\}", "", output)

    # Clean up multiple blank lines
    output = re.sub(r"\n{4,}", "\n\n\n", output)

    return output


def _markdown_to_html(markdown: str, title: str, use_premium_css: bool = True) -> str:
    """Convert markdown to HTML with professional styling."""
    try:
        import markdown as md

        html_body = md.markdown(markdown, extensions=["tables", "fenced_code", "toc", "attr_list"])
    except ImportError:
        # Fallback: wrap in pre tag
        html_body = f"<pre>{markdown}</pre>"

    # Try to load premium CSS
    css_content = ""
    if use_premium_css:
        css_path = ROOT_DIR / "docs" / "templates" / "reports" / "profesional.css"
        if css_path.exists():
            css_content = css_path.read_text()

    # Fallback to basic CSS if premium not available
    if not css_content:
        css_content = """
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 2rem; line-height: 1.6; }
        h1, h2, h3 { color: #1a1a2e; }
        table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #1a1a2e; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        code { background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
        pre { background-color: #f4f4f4; padding: 1rem; border-radius: 5px; overflow-x: auto; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .medium { color: #ffc107; }
        .low { color: #17a2b8; }
        """

    # Enhance HTML with severity badges
    html_body = _enhance_html_severity(html_body)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
{css_content}
    </style>
</head>
<body>
{html_body}
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


def _enhance_html_severity(html: str) -> str:
    """Add CSS classes to severity indicators in HTML."""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        # Wrap **SEVERITY** in spans
        html = re.sub(
            rf"\*\*({sev})\*\*", rf'<span class="severity-{sev.lower()}">{sev}</span>', html
        )
        # Also handle plain text in tables
        html = re.sub(
            rf"<td>({sev})</td>",
            rf'<td><span class="severity-{sev.lower()}">{sev}</span></td>',
            html,
        )

    return html


# =============================================================================
# Report Command
# =============================================================================


@click.command()
@click.argument("results_file", type=click.Path(exists=True))
@click.option(
    "--template",
    "-t",
    type=click.Choice(
        ["professional", "executive", "technical", "github-pr", "simple", "profesional", "premium"]
    ),
    default="simple",
    help="Report template to use (premium/profesional include CVSS scores, attack scenarios, and deployment recommendations)",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["markdown", "html", "pdf"]),
    default="markdown",
    help="Output format",
)
@click.option("--client", type=str, help="Client name for the report")
@click.option("--auditor", type=str, help="Auditor name for the report")
@click.option("--title", type=str, help="Custom report title")
@click.option("--contract-name", type=str, help="Contract name (overrides auto-detected)")
@click.option("--repository", type=str, help="Repository URL or path")
@click.option("--commit", type=str, help="Commit hash for the audited code")
@click.option(
    "--network",
    type=str,
    default="Ethereum Mainnet",
    help="Target network (e.g., Ethereum Mainnet, Polygon)",
)
@click.option(
    "--classification",
    type=str,
    default="CONFIDENTIAL",
    help="Report classification (CONFIDENTIAL, PUBLIC, etc.)",
)
@click.option(
    "--llm-interpret",
    is_flag=True,
    default=False,
    help="Use LLM to interpret findings and generate executive insights (requires Ollama)",
)
@click.option(
    "--interactive",
    "-i",
    is_flag=True,
    default=False,
    help="Interactive wizard mode: prompt for missing/unknown values before generating report",
)
def report(
    results_file,
    template,
    output,
    output_format,
    client,
    auditor,
    title,
    contract_name,
    repository,
    commit,
    network,
    classification,
    llm_interpret,
    interactive,
):
    """Generate formatted security reports from audit results.

    Takes JSON audit results and applies a template to generate
    professional security reports.

    Examples:

      miesc report results.json -t professional -o report.md

      miesc report results.json -t executive --client "Acme" -o summary.md

      miesc report results.json -t premium --client "Acme Corp" --auditor "Security Team" \\
          --contract-name "TokenV2.sol" --repository "github.com/acme/token" \\
          --network "Polygon" -o audit.pdf -f pdf

      miesc report results.json -t premium -i  # Interactive wizard mode

      miesc report results.json -t github-pr  # Output to stdout
    """
    print_banner()

    # Load results
    try:
        with open(results_file, "r") as f:
            results = json.load(f)
    except json.JSONDecodeError as e:
        error(f"Invalid JSON in {results_file}: {e}")
        sys.exit(1)
    except Exception as e:
        error(f"Failed to read {results_file}: {e}")
        sys.exit(1)

    info(f"Loaded results from {results_file}")

    # Locate template
    templates_dir = ROOT_DIR / "docs" / "templates" / "reports"
    template_file = templates_dir / f"{template}.md"

    if not template_file.exists():
        error(f"Template not found: {template_file}")
        info("Available templates: professional, executive, technical, github-pr, simple, premium")
        sys.exit(1)

    # Load template
    template_content = template_file.read_text()

    # Extract data from results
    summary = results.get("summary", {})

    # For batch results, use aggregated_summary if available
    if not summary and "aggregated_summary" in results:
        summary = results.get("aggregated_summary", {})

    # Extract findings from results (can be at root level, within tool results, or in batch format)
    findings = results.get("findings", [])

    # Smart audit format: prefer ML-enhanced findings (adjusted severities) over raw
    if not findings:
        ml_enhanced = results.get("ml_enhanced", {})
        if (
            isinstance(ml_enhanced, dict)
            and isinstance(ml_enhanced.get("findings"), list)
            and ml_enhanced["findings"]
        ):
            findings = ml_enhanced["findings"]
        elif (
            isinstance(ml_enhanced, dict)
            and isinstance(ml_enhanced.get("top_findings"), list)
            and ml_enhanced["top_findings"]
        ):
            findings = ml_enhanced["top_findings"]
        elif "raw_findings" in results and results["raw_findings"].get("findings"):
            findings = results["raw_findings"]["findings"]

    if not findings:
        # Extract from tool results (single contract format)
        for tool_result in results.get("results", []):
            tool_findings = tool_result.get("findings", [])
            for f in tool_findings:
                f["tool"] = tool_result.get("tool", "unknown")
            findings.extend(tool_findings)

    if not findings:
        # Extract from batch format: contracts[].results[].findings
        for contract_data in results.get("contracts", []):
            contract_file = contract_data.get("contract", "unknown")
            for tool_result in contract_data.get("results", []):
                tool_findings = tool_result.get("findings", [])
                for f in tool_findings:
                    f["tool"] = tool_result.get("tool", "unknown")
                    f["source_contract"] = contract_file
                findings.extend(tool_findings)

    # Normalize summary keys (can be uppercase or lowercase)
    if summary:
        summary = {k.lower(): v for k, v in summary.items()}

    # Calculate severity counts from summary or from findings
    if summary:
        critical_count = summary.get("critical", 0)
        high_count = summary.get("high", 0)
        medium_count = summary.get("medium", 0)
        low_count = summary.get("low", 0)
        info_count = summary.get("info", summary.get("informational", 0))
    else:
        # Calculate from findings if summary is not available
        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        medium_count = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
        low_count = sum(1 for f in findings if f.get("severity", "").lower() == "low")
        info_count = sum(
            1 for f in findings if f.get("severity", "").lower() in ("info", "informational")
        )

    def get_status(count, severity):
        if count == 0:
            return "✅ None Found"
        elif severity in ("critical", "high"):
            return f"⚠️ {count} Issue{'s' if count > 1 else ''} - Action Required"
        else:
            return f"ℹ️ {count} Issue{'s' if count > 1 else ''}"

    # Get tools used per layer
    tools_by_layer = results.get("tools_by_layer", {})
    tool_list = results.get("tools", [])

    # Generate risk summary based on findings
    overall_risk = _calculate_risk_level(summary)
    risk_summaries = {
        "CRITICAL": "**CRITICAL RISK**: This contract contains critical vulnerabilities that could lead to complete loss of funds or contract takeover. Immediate remediation is required before deployment.",
        "HIGH": "**HIGH RISK**: Significant security issues were identified that could result in substantial financial loss or contract compromise. These issues should be addressed before deployment.",
        "MEDIUM": "**MEDIUM RISK**: Several security concerns were found that could potentially be exploited under certain conditions. Recommended to address before deployment.",
        "LOW": "**LOW RISK**: Minor issues were identified that should be addressed to improve code quality and security posture.",
        "MINIMAL": "**MINIMAL RISK**: No significant security issues were identified. The contract follows security best practices.",
    }

    # Prepare template variables
    # CLI parameters override auto-detected values from results
    # Support multiple JSON formats: contract, contract_path, path
    detected_contract = (
        results.get("contract") or results.get("contract_path") or results.get("path") or "Unknown"
    )
    # Extract just the filename from path
    if "/" in detected_contract:
        detected_contract = detected_contract.split("/")[-1]

    variables = {
        "contract_name": contract_name or detected_contract,
        "audit_date": results.get("timestamp", datetime.now().isoformat())[:10],
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "client_name": client or "Client",
        "auditor_name": auditor or "MIESC Security",
        "version": results.get("version", VERSION),
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "info_count": info_count,
        "total_findings": len(findings),
        "files_count": results.get("files_count", results.get("contracts_analyzed", 1)),
        "tools_count": len(tool_list),
        "overall_risk": overall_risk,
        "miesc_version": VERSION,
        # Additional fields for professional template
        "repository": repository or results.get("repository", "Local Analysis"),
        "commit_hash": commit or results.get("commit", "N/A"),
        "lines_of_code": results.get("lines_of_code", "N/A"),
        "audit_duration": results.get("duration", "N/A"),
        "critical_status": get_status(critical_count, "critical"),
        "high_status": get_status(high_count, "high"),
        "medium_status": get_status(medium_count, "medium"),
        "low_status": get_status(low_count, "low"),
        "info_status": get_status(info_count, "info"),
        "risk_summary": risk_summaries.get(overall_risk, "Risk assessment pending."),
        # Layer tools
        "layer1_tools": ", ".join(
            tools_by_layer.get("static_analysis", ["slither", "aderyn", "solhint"])
        ),
        "layer2_tools": ", ".join(
            tools_by_layer.get("dynamic_testing", ["echidna", "medusa", "foundry"])
        ),
        "layer3_tools": ", ".join(
            tools_by_layer.get("symbolic_execution", ["mythril", "manticore", "halmos"])
        ),
        "layer4_tools": ", ".join(
            tools_by_layer.get("formal_verification", ["certora", "smtchecker"])
        ),
        "layer5_tools": ", ".join(tools_by_layer.get("property_testing", ["propertygpt"])),
        "layer6_tools": ", ".join(
            tools_by_layer.get("ai_analysis", ["smartllm", "gptscan", "llmsmartaudit"])
        ),
        "layer7_tools": ", ".join(tools_by_layer.get("ml_detection", ["dagnn", "smartbugs_ml"])),
        "layer8_tools": ", ".join(tools_by_layer.get("defi", ["defi", "mev_detector"])),
        "layer9_tools": ", ".join(
            tools_by_layer.get("specialized", ["gas_analyzer", "threat_model"])
        ),
        # Empty lists for optional sections
        "swc_mappings": [],
        "owasp_mappings": [],
        "tool_outputs": [],
        "files_analyzed": [],  # Will be populated below
        "files_in_scope": [],  # Will be populated below
        # LLM interpretation placeholders (populated if --llm-interpret is used)
        "llm_executive_summary": "",
        "llm_risk_narrative": "",
        "llm_remediation_priority": [],
        "llm_critical_interpretations": [],
        "llm_enabled": False,
        # Profesional template variables (populated for profesional template)
        "cvss_scores": [],
        "risk_matrix": {},
        "overall_risk_score": 0,
        "deployment_recommendation": "CONDITIONAL",
        "deployment_justification": "",
        "deployment_recommendation_color": "#ff9800",
        "deployment_recommendation_bg": "#fff8e1",
        "quick_wins": [],
        "effort_impact_matrix": {},
        "attack_scenarios": [],
        "code_remediations": [],
        "category_summary": [],
        "exploitability_rating": "Medium",
        "business_impact": "Medium",
        "confidence_level": "High",
        "value_at_risk": None,
        "out_of_scope": [],
        "engagement_type": "Security Audit",
        "target_network": network,
        "classification": classification,
        "report_version": "1.0",
    }

    # =========================================================================
    # Generate Files Analyzed / Files In Scope
    # =========================================================================
    files_analyzed = []
    files_in_scope = []
    total_lines = 0

    # Check if batch audit (has "contracts" array)
    if "contracts" in results:
        for idx, contract_data in enumerate(results.get("contracts", []), 1):
            contract_path = contract_data.get("contract", "Unknown")
            contract_name_short = (
                Path(contract_path).name if contract_path != "Unknown" else f"Contract {idx}"
            )
            contract_findings = contract_data.get("total_findings", 0)

            # Try to get lines of code
            lines = "N/A"
            try:
                if contract_path and Path(contract_path).exists():
                    with open(contract_path, "r") as f:
                        lines = len(f.readlines())
                        total_lines += lines
            except Exception:
                pass

            files_analyzed.append(
                {
                    "path": contract_name_short,
                    "full_path": contract_path,
                    "lines": lines,
                    "findings": contract_findings,
                }
            )
            files_in_scope.append(
                {"path": contract_name_short, "lines": lines, "description": "Smart Contract"}
            )
    else:
        # Single contract - try multiple sources for contract path
        contract_path = results.get(
            "contract", results.get("contract_path", results.get("path", "Unknown"))
        )

        # If not found at root level, try to get from first result
        if contract_path == "Unknown" and results.get("results"):
            for r in results.get("results", []):
                if r.get("contract"):
                    contract_path = r.get("contract")
                    break

        contract_name_short = (
            Path(contract_path).name if contract_path and contract_path != "Unknown" else "Contract"
        )

        lines = 0
        functions_count = 0
        try:
            if contract_path and contract_path != "Unknown" and Path(contract_path).exists():
                with open(contract_path, "r") as f:
                    content = f.read()
                    lines = len(content.splitlines())
                    total_lines = lines
                    # Count functions
                    functions_count = len(re.findall(r"\bfunction\s+\w+\s*\(", content))
        except Exception:
            lines = "N/A"

        files_analyzed.append(
            {
                "path": contract_name_short,
                "full_path": contract_path,
                "lines": lines,
                "functions": functions_count,
                "findings": len(findings),
            }
        )
        files_in_scope.append(
            {
                "path": contract_name_short,
                "lines": lines,
                "functions": functions_count,
                "description": "Smart Contract",
            }
        )

    variables["files_analyzed"] = files_analyzed
    variables["files_in_scope"] = files_in_scope
    variables["files_count"] = len(files_analyzed)
    if total_lines > 0:
        variables["lines_of_code"] = total_lines

    # =========================================================================
    # Enhanced Tool Execution Summary
    # =========================================================================
    # Get tool results - handle multiple audit formats
    tool_results = results.get("results", [])
    if not tool_results and "contracts" in results:
        # Batch audit format: aggregate results from all contracts
        for contract_data in results.get("contracts", []):
            tool_results.extend(contract_data.get("results", []))

    # Smart audit format: build tool_results from tools_run/success/failed
    if not tool_results and "tools_run" in results:
        tools_run = results.get("tools_run", [])
        tools_success = set(results.get("tools_success", []))
        tools_failed = set(results.get("tools_failed", []))
        raw_findings = results.get("raw_findings", {}).get("findings", [])
        ml_findings = results.get("ml_filtered", {}).get("findings", [])
        all_findings = ml_findings if ml_findings else raw_findings

        # Group findings by tool
        findings_by_tool: Dict[str, list] = {}
        for f in all_findings:
            tool = f.get("tool", "unknown")
            if tool not in findings_by_tool:
                findings_by_tool[tool] = []
            findings_by_tool[tool].append(f)

        # Build tool_results from tools_run
        for tool in tools_run:
            tool_findings = findings_by_tool.get(tool, [])
            if tool in tools_success:
                status = "success"
            elif tool in tools_failed:
                status = "failed"
            else:
                status = "unknown"
            tool_results.append(
                {
                    "tool": tool,
                    "status": status,
                    "findings": tool_findings,
                    "duration": "N/A",
                }
            )

    tools_execution_summary = []
    layer_summary: Dict[str, Any] = {}

    # Layer name mapping
    layer_names = {
        "static_analysis": "Layer 1: Static Analysis",
        "dynamic_testing": "Layer 2: Dynamic Testing",
        "symbolic_execution": "Layer 3: Symbolic Execution",
        "formal_verification": "Layer 4: Formal Verification",
        "property_testing": "Layer 5: Property Testing",
        "ai_analysis": "Layer 6: AI/LLM Analysis",
        "ml_detection": "Layer 7: ML Detection",
        "defi": "Layer 8: DeFi Security",
        "specialized": "Layer 9: Specialized Analysis",
    }

    # Tool to layer mapping (when layer not specified by adapter)
    TOOL_LAYER_MAP = {
        # Layer 1: Static Analysis
        "slither": "static_analysis",
        "aderyn": "static_analysis",
        "solhint": "static_analysis",
        "semgrep": "static_analysis",
        "solc": "static_analysis",
        "wake": "static_analysis",
        # Layer 2: Dynamic Testing
        "echidna": "dynamic_testing",
        "foundry": "dynamic_testing",
        "hardhat": "dynamic_testing",
        "medusa": "dynamic_testing",
        "dogefuzz": "dynamic_testing",
        "vertigo": "dynamic_testing",
        # Layer 3: Symbolic Execution
        "mythril": "symbolic_execution",
        "manticore": "symbolic_execution",
        "halmos": "symbolic_execution",
        "hevm": "symbolic_execution",
        "oyente": "symbolic_execution",
        # Layer 4: Formal Verification
        "certora": "formal_verification",
        "scribble": "formal_verification",
        "pyrometer": "formal_verification",
        "smtchecker": "formal_verification",
        "propertygpt": "formal_verification",
        # Layer 5: AI Analysis
        "smartllm": "ai_analysis",
        "gptscan": "ai_analysis",
        "llmsmartaudit": "ai_analysis",
        "4naly3er": "ai_analysis",
        "gpt-4": "ai_analysis",
        # Layer 6: ML Detection
        "dagnn": "ml_detection",
        "smartbugs_ml": "ml_detection",
        "smartbugs_detector": "ml_detection",
        "smartguard": "ml_detection",
        "ml-detector": "ml_detection",
        # Layer 7: DeFi Security
        "defi": "defi",
        "defi-scanner": "defi",
        "mev_detector": "defi",
        # Layer 8: Specialized Analysis
        "threat_model": "specialized",
        "gas_analyzer": "specialized",
        "contract_clone_detector": "specialized",
        "advanced_detector": "specialized",
        "token-analyzer": "specialized",
    }

    for tool_result in tool_results:
        tool_name = tool_result.get("tool", "unknown")
        tool_status = tool_result.get("status", "unknown")
        tool_duration = tool_result.get("duration", "N/A")
        tool_findings = tool_result.get("findings", [])
        tool_layer = tool_result.get("layer") or TOOL_LAYER_MAP.get(tool_name.lower(), "unknown")
        tool_error = tool_result.get("error", "")

        # Map status to human-readable
        status_map = {
            "success": "Success",
            "failed": "Failed",
            "skipped": "Skipped",
            "timeout": "Timeout",
            "error": "Error",
        }
        display_status = status_map.get(
            tool_status, tool_status.capitalize() if isinstance(tool_status, str) else "Unknown"
        )

        tools_execution_summary.append(
            {
                "name": tool_name,
                "status": display_status,
                "status_icon": (
                    "✅"
                    if tool_status == "success"
                    else ("⚠️" if tool_status in ("failed", "error", "timeout") else "⏭️")
                ),
                "duration": (
                    f"{tool_duration}s"
                    if isinstance(tool_duration, (int, float))
                    else str(tool_duration)
                ),
                "findings_count": len(tool_findings),
                "layer": layer_names.get(tool_layer, tool_layer),
                "error": tool_error[:100] if tool_error else "",
            }
        )

        # Aggregate by layer
        layer_key = tool_layer if tool_layer else "unknown"
        if layer_key not in layer_summary:
            layer_summary[layer_key] = {
                "name": layer_names.get(layer_key, layer_key),
                "tools_executed": [],
                "tools_success": 0,
                "tools_failed": 0,
                "findings_count": 0,
            }
        layer_summary[layer_key]["tools_executed"].append(tool_name)
        layer_summary[layer_key]["findings_count"] += len(tool_findings)
        if tool_status == "success":
            layer_summary[layer_key]["tools_success"] += 1
        elif tool_status in ("failed", "error", "timeout"):
            layer_summary[layer_key]["tools_failed"] += 1

    # Convert layer_summary to list sorted by layer order
    layer_order = [
        "static_analysis",
        "dynamic_testing",
        "symbolic_execution",
        "formal_verification",
        "property_testing",
        "ai_analysis",
        "ml_detection",
        "defi",
        "specialized",
    ]
    layer_summary_list = []
    for layer_key in layer_order:
        if layer_key in layer_summary:
            ls = layer_summary[layer_key]
            layer_summary_list.append(
                {
                    "name": ls["name"],
                    "tools": ", ".join(ls["tools_executed"]) if ls["tools_executed"] else "None",
                    "success_count": ls["tools_success"],
                    "failed_count": ls["tools_failed"],
                    "findings_count": ls["findings_count"],
                    "coverage_status": (
                        "✅ Complete"
                        if ls["tools_success"] > 0 and ls["tools_failed"] == 0
                        else ("⚠️ Partial" if ls["tools_success"] > 0 else "❌ Not Executed")
                    ),
                }
            )

    variables["tools_execution_summary"] = tools_execution_summary
    variables["layer_summary"] = layer_summary_list
    variables["total_tools_executed"] = len(tools_execution_summary)

    # Populate tool_outputs for Appendix A (detailed tool execution)
    tool_outputs = []
    for tool_result in tool_results:
        tool_name = tool_result.get("tool", "unknown")
        tool_status = tool_result.get("status", "unknown")
        tool_duration = tool_result.get("execution_time", "N/A")
        tool_findings = tool_result.get("findings", [])
        tool_error = tool_result.get("error", "")

        # Build output summary
        output_lines = []
        if tool_status == "success":
            output_lines.append("Analysis completed successfully.")
            output_lines.append(f"Findings detected: {len(tool_findings)}")
            if tool_findings:
                output_lines.append("")
                output_lines.append("Findings summary:")
                for i, f in enumerate(tool_findings[:10], 1):
                    sev = f.get("severity", "unknown").upper()
                    ftype = f.get("type", f.get("title", "unknown"))
                    loc = f.get("location", {})
                    line = loc.get("line", "?")
                    output_lines.append(f"  {i}. [{sev}] {ftype} (line {line})")
                if len(tool_findings) > 10:
                    output_lines.append(f"  ... and {len(tool_findings) - 10} more")
        elif tool_error:
            output_lines.append(f"Error: {tool_error}")
        else:
            output_lines.append(f"Status: {tool_status}")

        tool_outputs.append(
            {
                "name": tool_name,
                "duration": (
                    f"{tool_duration}s"
                    if isinstance(tool_duration, (int, float))
                    else str(tool_duration)
                ),
                "exit_code": 0 if tool_status == "success" else 1,
                "findings_count": len(tool_findings),
                "output": "\n".join(output_lines),
            }
        )

    variables["tool_outputs"] = tool_outputs

    # Interactive wizard mode
    if interactive and RICH_AVAILABLE:
        variables = _interactive_wizard(variables, console)
    variables["tools_success_count"] = sum(
        1 for t in tools_execution_summary if t["status"] == "Success"
    )
    variables["tools_failed_count"] = sum(
        1 for t in tools_execution_summary if t["status"] in ("Failed", "Error", "Timeout")
    )

    # =========================================================================
    # LLM Interpretation (if enabled)
    # =========================================================================
    if llm_interpret:
        info("LLM interpretation enabled - generating AI-powered insights...")
        try:
            from src.reports.llm_interpreter import LLMReportInterpreter

            # Get contract code if available
            contract_path = results.get("contract_path") or results.get("contract")
            contract_code = ""
            if contract_path:
                try:
                    contract_file = Path(contract_path)
                    if contract_file.exists():
                        contract_code = contract_file.read_text()[:10000]  # Limit to 10k chars
                except Exception:
                    pass

            interpreter = LLMReportInterpreter()

            if interpreter.is_available():
                variables["llm_enabled"] = True
                variables["llm_model"] = interpreter.config.model

                # Generate executive interpretation
                info("Generating executive summary interpretation...")
                exec_summary = interpreter.generate_executive_interpretation(
                    findings=findings,
                    summary=summary,
                    contract_name=results.get("contract", "Unknown"),
                )
                variables["llm_executive_summary"] = exec_summary

                # Generate risk narrative
                info("Generating risk narrative...")
                risk_narrative = interpreter.generate_risk_narrative(
                    summary=summary, findings=findings
                )
                variables["llm_risk_narrative"] = risk_narrative

                # Interpret critical findings
                critical_high = [
                    f for f in findings if f.get("severity", "").lower() in ("critical", "high")
                ]
                if critical_high:
                    info(f"Interpreting {len(critical_high[:5])} critical/high findings...")
                    interpreted = interpreter.interpret_critical_findings(
                        critical_findings=critical_high[:5], contract_code=contract_code  # Top 5
                    )
                    variables["llm_critical_interpretations"] = interpreted

                # Generate remediation priority
                if findings:
                    info("Generating remediation priority recommendations...")
                    priority = interpreter.suggest_remediation_priority(
                        findings=findings[:10]  # Top 10
                    )
                    variables["llm_remediation_priority"] = priority

                success("LLM interpretation complete!")
            else:
                warning("Ollama not available - skipping LLM interpretation")
                warning("Start Ollama with: ollama serve && ollama pull deepseek-coder:6.7b")

        except ImportError as e:
            warning(f"LLM interpreter not available: {e}")
        except Exception as e:
            warning(f"LLM interpretation failed: {e}")

    # =========================================================================
    # Profesional Template Processing
    # =========================================================================
    if template in ("profesional", "premium"):
        info("Generating premium report data (CVSS scores, risk matrix, etc.)...")
        try:
            from src.reports.risk_calculator import calculate_premium_risk_data

            # Calculate risk data
            risk_data = calculate_premium_risk_data(findings)

            # Update variables with risk data
            variables.update(
                {
                    "cvss_scores": risk_data.get("cvss_scores", []),
                    "risk_matrix": risk_data.get("risk_matrix", {}),
                    "overall_risk_score": risk_data.get("overall_risk_score", 0),
                    "deployment_recommendation": risk_data.get(
                        "deployment_recommendation", "CONDITIONAL"
                    ),
                    "deployment_justification": risk_data.get("deployment_justification", ""),
                    "deployment_recommendation_color": risk_data.get(
                        "deployment_recommendation_color", "#ff9800"
                    ),
                    "deployment_recommendation_bg": risk_data.get(
                        "deployment_recommendation_bg", "#fff8e1"
                    ),
                    "quick_wins": risk_data.get("quick_wins", []),
                    "effort_impact_matrix": risk_data.get("effort_impact_matrix", {}),
                    "critical_percent": risk_data.get("critical_percent", 0),
                    "high_percent": risk_data.get("high_percent", 0),
                    "medium_percent": risk_data.get("medium_percent", 0),
                    "low_percent": risk_data.get("low_percent", 0),
                    "info_percent": risk_data.get("info_percent", 0),
                }
            )

            # Calculate category summary
            categories: Dict[str, Any] = {}
            for f in findings:
                cat = f.get("category") or f.get("type", "General")
                if cat not in categories:
                    categories[cat] = {"count": 0, "severities": []}
                categories[cat]["count"] += 1
                categories[cat]["severities"].append(f.get("severity", "unknown").lower())

            category_summary = []
            for cat, data in sorted(categories.items(), key=lambda x: -x[1]["count"]):
                sev_counts: Dict[str, int] = {}
                for s in data["severities"]:
                    sev_counts[s] = sev_counts.get(s, 0) + 1
                breakdown = ", ".join([f"{v} {k}" for k, v in sorted(sev_counts.items())])
                category_summary.append(
                    {
                        "name": cat,
                        "count": data["count"],
                        "breakdown": breakdown,
                    }
                )
            variables["category_summary"] = category_summary

            # =================================================================
            # Generate SWC Registry Compliance
            # =================================================================
            SWC_MAPPING = {
                "reentrancy": ("SWC-107", "Reentrancy"),
                "reentrant": ("SWC-107", "Reentrancy"),
                "integer-overflow": ("SWC-101", "Integer Overflow and Underflow"),
                "overflow": ("SWC-101", "Integer Overflow and Underflow"),
                "underflow": ("SWC-101", "Integer Overflow and Underflow"),
                "unchecked-call": ("SWC-104", "Unchecked Call Return Value"),
                "unchecked-return": ("SWC-104", "Unchecked Call Return Value"),
                "tx-origin": ("SWC-115", "Authorization through tx.origin"),
                "tx.origin": ("SWC-115", "Authorization through tx.origin"),
                "access-control": ("SWC-105", "Unprotected Ether Withdrawal"),
                "delegatecall": ("SWC-112", "Delegatecall to Untrusted Callee"),
                "timestamp": ("SWC-116", "Block values as a proxy for time"),
                "block-timestamp": ("SWC-116", "Block values as a proxy for time"),
                "denial-of-service": ("SWC-113", "DoS with Failed Call"),
                "dos": ("SWC-113", "DoS with Failed Call"),
                "assembly": ("SWC-127", "Arbitrary Jump with Function Type Variable"),
                "uninitialized": ("SWC-109", "Uninitialized Storage Pointer"),
                "floating-pragma": ("SWC-103", "Floating Pragma"),
                "pragma": ("SWC-103", "Floating Pragma"),
                "outdated-compiler": ("SWC-102", "Outdated Compiler Version"),
                "solc-version": ("SWC-102", "Outdated Compiler Version"),
                "shadowing": ("SWC-119", "Shadowing State Variables"),
                "visibility": ("SWC-100", "Function Default Visibility"),
            }

            swc_found: Dict[str, Any] = {}
            for f in findings:
                f_type = (
                    (f.get("type") or f.get("check") or f.get("category") or "")
                    .lower()
                    .replace("_", "-")
                    .replace(" ", "-")
                )
                f_title = (f.get("title") or f.get("name") or "").lower()

                # Try to match by type or title
                for key, (swc_id, swc_title) in SWC_MAPPING.items():
                    if key in f_type or key in f_title:
                        if swc_id not in swc_found:
                            swc_found[swc_id] = {
                                "id": swc_id,
                                "title": swc_title,
                                "count": 0,
                                "status": "Found",
                                "status_icon": "⚠️",
                                "finding_ids": [],
                            }
                        swc_found[swc_id]["count"] += 1
                        swc_found[swc_id]["finding_ids"].append(
                            f"F{len(swc_found[swc_id]['finding_ids'])+1}"
                        )
                        break

            # Add common SWC entries that were checked but not found
            common_swc = [
                ("SWC-107", "Reentrancy"),
                ("SWC-101", "Integer Overflow and Underflow"),
                ("SWC-104", "Unchecked Call Return Value"),
                ("SWC-115", "Authorization through tx.origin"),
                ("SWC-103", "Floating Pragma"),
                ("SWC-102", "Outdated Compiler Version"),
            ]
            for swc_id, swc_title in common_swc:
                if swc_id not in swc_found:
                    swc_found[swc_id] = {
                        "id": swc_id,
                        "title": swc_title,
                        "count": 0,
                        "status": "Not Found",
                        "status_icon": "✅",
                        "finding_ids": "--",
                    }

            # Convert finding_ids list to string
            for swc in swc_found.values():
                if isinstance(swc["finding_ids"], list):
                    swc["finding_ids"] = (
                        ", ".join(swc["finding_ids"]) if swc["finding_ids"] else "--"
                    )

            variables["swc_mappings"] = sorted(swc_found.values(), key=lambda x: x["id"])

            # =================================================================
            # Generate OWASP Smart Contract Top 10 Compliance
            # =================================================================
            OWASP_MAPPING = {
                "reentrancy": (1, "SC01", "Reentrancy Attacks"),
                "access-control": (2, "SC02", "Access Control Vulnerabilities"),
                "arithmetic": (3, "SC03", "Arithmetic Issues"),
                "overflow": (3, "SC03", "Arithmetic Issues"),
                "unchecked": (4, "SC04", "Unchecked Return Values"),
                "dos": (5, "SC05", "Denial of Service"),
                "denial-of-service": (5, "SC05", "Denial of Service"),
                "randomness": (6, "SC06", "Bad Randomness"),
                "front-running": (7, "SC07", "Front-Running"),
                "timestamp": (8, "SC08", "Time Manipulation"),
                "short-address": (9, "SC09", "Short Address Attack"),
                "unknown-unknowns": (10, "SC10", "Unknown Unknowns"),
            }

            owasp_found: Dict[str, Any] = {}
            for f in findings:
                f_type = (
                    (f.get("type") or f.get("check") or f.get("category") or "")
                    .lower()
                    .replace("_", "-")
                )
                f_title = (f.get("title") or f.get("name") or "").lower()

                for key, (rank, owasp_id, owasp_category) in OWASP_MAPPING.items():
                    if key in f_type or key in f_title:
                        if owasp_id not in owasp_found:
                            owasp_found[owasp_id] = {
                                "rank": rank,
                                "id": owasp_id,
                                "category": owasp_category,
                                "count": 0,
                                "status": "Found",
                                "status_icon": "⚠️",
                            }
                        owasp_found[owasp_id]["count"] += 1
                        break

            # Add top OWASP entries that were checked
            top_owasp = [
                (1, "SC01", "Reentrancy Attacks"),
                (2, "SC02", "Access Control Vulnerabilities"),
                (3, "SC03", "Arithmetic Issues"),
                (4, "SC04", "Unchecked Return Values"),
                (5, "SC05", "Denial of Service"),
            ]
            for rank, owasp_id, owasp_category in top_owasp:
                if owasp_id not in owasp_found:
                    owasp_found[owasp_id] = {
                        "rank": rank,
                        "id": owasp_id,
                        "category": owasp_category,
                        "count": 0,
                        "status": "Not Found",
                        "status_icon": "✅",
                    }

            variables["owasp_mappings"] = sorted(owasp_found.values(), key=lambda x: x["rank"])

            # Add layer coverage bars
            for layer in variables.get("layer_summary", []):
                success_count = layer.get("success_count", 0)
                failed_count = layer.get("failed_count", 0)
                total = success_count + failed_count
                if total > 0:
                    percentage = int(success_count / total * 100)
                    bar = "█" * (percentage // 10) + "░" * (10 - percentage // 10)
                    layer["coverage_bar"] = f"{bar} {percentage}%"
                else:
                    layer["coverage_bar"] = "░░░░░░░░░░ N/A"

            # If LLM is enabled and premium, use premium insights
            if llm_interpret and variables.get("llm_enabled"):
                try:
                    from src.reports.llm_interpreter import generate_premium_report_insights

                    info(
                        "Generating premium LLM insights (attack scenarios, deployment recommendation)..."
                    )

                    # Get contract code if available
                    contract_path = results.get("contract_path") or results.get("contract")
                    contract_code = ""
                    if contract_path:
                        try:
                            contract_file = Path(contract_path)
                            if contract_file.exists():
                                contract_code = contract_file.read_text()[:10000]
                        except Exception:
                            pass

                    premium_insights = generate_premium_report_insights(
                        findings=findings,
                        summary=summary,
                        contract_name=results.get("contract", "Unknown"),
                        contract_code=contract_code,
                    )

                    if premium_insights.get("available"):
                        # LLM deployment recommendation - only allow stricter recommendations
                        # Severity order: NO-GO > CONDITIONAL > GO
                        if premium_insights.get("deployment_recommendation"):
                            llm_rec = premium_insights["deployment_recommendation"]
                            calc_rec = variables.get("deployment_recommendation", "GO")
                            severity_order = {"NO-GO": 3, "CONDITIONAL": 2, "GO": 1}

                            # Only use LLM recommendation if it's stricter (or equal)
                            llm_severity = severity_order.get(llm_rec, 1)
                            calc_severity = severity_order.get(calc_rec, 1)

                            if llm_severity >= calc_severity:
                                variables["deployment_recommendation"] = llm_rec
                                variables["deployment_justification"] = premium_insights.get(
                                    "deployment_justification", ""
                                )
                            else:
                                # Keep calculated recommendation, but add LLM justification as note
                                existing_just = variables.get("deployment_justification", "")
                                if existing_just:
                                    variables["deployment_justification"] = existing_just

                        # Add attack scenarios
                        if premium_insights.get("attack_scenarios"):
                            variables["attack_scenarios"] = premium_insights["attack_scenarios"]

                        # Add code remediations
                        if premium_insights.get("code_remediations"):
                            variables["code_remediations"] = premium_insights["code_remediations"]

                        # Update remediation priority with effort
                        if premium_insights.get("remediation_priority"):
                            variables["llm_remediation_priority"] = premium_insights[
                                "remediation_priority"
                            ]

                        success("Profesional LLM insights generated!")

                except Exception as e:
                    warning(f"Profesional LLM insights failed: {e}")

            success("Profesional report data generated!")

        except ImportError as e:
            warning(f"Risk calculator not available: {e}")
        except Exception as e:
            warning(f"Profesional report processing failed: {e}")

    # =========================================================================
    # Proof of Concept Generation (for Critical/High findings)
    # =========================================================================
    if template in ("profesional", "premium"):
        try:
            from src.poc.poc_generator import PoCGenerator

            poc_generator = PoCGenerator()
            contract_name_for_poc = (
                results.get("contract")
                or results.get("contract_path")
                or results.get("path")
                or "Unknown"
            )
            # For batch format, strip trailing slash from directory path
            if contract_name_for_poc.endswith("/"):
                contract_name_for_poc = "Unknown"

            critical_high_for_poc = [
                f
                for f in findings
                if f.get("severity", "").lower() in ("critical", "high") and f.get("type")
            ]

            if critical_high_for_poc:
                info(
                    f"Generating PoC exploits for {len(critical_high_for_poc)} critical/high findings..."
                )
                for finding in critical_high_for_poc:
                    try:
                        # Use per-finding source_contract (batch) or global contract name
                        target = finding.get("source_contract") or contract_name_for_poc
                        poc = poc_generator.generate(finding, target_contract=target)
                        finding["poc"] = poc.solidity_code
                        finding["poc_available"] = True
                        finding["poc_name"] = poc.name
                        finding["poc_prerequisites"] = poc.prerequisites
                        finding["poc_expected_outcome"] = poc.expected_outcome
                    except Exception as e:
                        logger.debug(f"PoC generation failed for {finding.get('type')}: {e}")

                poc_count = sum(1 for f in critical_high_for_poc if f.get("poc_available"))
                if poc_count:
                    success(f"Generated {poc_count} PoC exploit templates")
        except ImportError:
            logger.debug("PoCGenerator not available")
        except Exception as e:
            warning(f"PoC generation failed: {e}")

    # Prepare findings for template
    formatted_findings = []
    for i, finding in enumerate(findings, 1):
        # Handle location (can be string or dict)
        location = finding.get("location", {})
        if isinstance(location, dict):
            loc_str = f"{location.get('file', 'unknown')}:{location.get('line', '?')}"
            if location.get("function"):
                loc_str += f" ({location.get('function')})"
        else:
            loc_str = str(location) if location else "unknown"

        # Get title from various possible fields
        title_field = (
            finding.get("title") or finding.get("type") or finding.get("message", "Unknown")[:50]
        )

        # Get category from swc_id, owasp_category, or type
        category = (
            finding.get("category")
            or finding.get("owasp_category")
            or finding.get("swc_id")
            or finding.get("type", "general")
        )

        # Severity display helpers for premium template
        severity_lower = finding.get("severity", "unknown").lower()
        severity_badges = {
            "critical": "**CRITICAL**",
            "high": "**HIGH**",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
            "informational": "INFO",
        }
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
            "informational": "#17a2b8",
        }

        # Get CVSS score if available
        cvss_score = None
        for score in variables.get("cvss_scores", []):
            if score.get("title") == title_field or score.get("finding_id") == f"F-{i:03d}":
                cvss_score = score.get("base_score")
                break

        # Get attack scenario if available
        attack_scenario = None
        attack_steps = []
        for scenario in variables.get("attack_scenarios", []):
            if scenario.get("title") == title_field:
                attack_scenario = scenario.get("scenario_description")
                attack_steps = scenario.get("attack_steps", [])
                break

        # Get code remediation if available
        remediation_code = None
        remediation_effort = None
        fix_time = None
        for remediation in variables.get("code_remediations", []):
            if remediation.get("title") == title_field:
                remediation_code = remediation.get("diff")
                remediation_effort = remediation.get("effort")
                fix_time = remediation.get("fix_time")
                break

        formatted_findings.append(
            {
                "id": f"F-{i:03d}",
                "title": title_field,
                "severity": severity_lower,
                "severity_badge": severity_badges.get(severity_lower, severity_lower.upper()),
                "severity_color": severity_colors.get(severity_lower, "#6c757d"),
                "category": category,
                "location": loc_str,
                "description": finding.get("description", finding.get("message", "")),
                "recommendation": finding.get(
                    "recommendation", "Review and fix the vulnerability."
                ),
                "tool": finding.get("tool", "unknown"),
                "status": finding.get("status", "open"),
                "impact": finding.get("impact", _get_impact_description(severity_lower)),
                "poc": finding.get("poc", "// No PoC provided"),
                "vulnerable_code": finding.get(
                    "vulnerable_code", finding.get("poc", "// No code snippet")
                ),
                "references": finding.get("references", []),
                # Premium fields
                "cvss_score": cvss_score,
                "attack_scenario": attack_scenario,
                "attack_steps": attack_steps,
                "remediation_code": remediation_code,
                "remediation_effort": remediation_effort,
                "fix_time": fix_time,
                "llm_interpretation": finding.get("llm_interpretation", ""),
                # PoC fields
                "poc_available": finding.get("poc_available", False),
                "poc_name": finding.get("poc_name", ""),
                "poc_prerequisites": finding.get("poc_prerequisites", []),
                "poc_expected_outcome": finding.get("poc_expected_outcome", ""),
            }
        )

    variables["findings"] = formatted_findings
    variables["critical_high_findings"] = [
        f for f in formatted_findings if f["severity"] in ("critical", "high")
    ]
    variables["medium_low_findings"] = [
        f for f in formatted_findings if f["severity"] in ("medium", "low")
    ]

    # Simple template rendering (basic variable substitution)
    output_content = _render_template(template_content, variables)

    # Handle output
    if output:
        output_path = Path(output)

        if output_format == "html":
            output_content = _markdown_to_html(output_content, title or "MIESC Security Report")
        elif output_format == "pdf":
            # Generate PDF from HTML using weasyprint (preferred) or pandoc fallback
            html_content = _markdown_to_html(output_content, title or "MIESC Security Report")
            pdf_generated = False

            # Try weasyprint first (available in Docker image)
            try:
                from weasyprint import CSS, HTML
                from weasyprint.text.fonts import FontConfiguration

                info("Generating PDF with WeasyPrint...")
                font_config = FontConfiguration()

                # Load premium CSS if available
                css_path = ROOT_DIR / "docs" / "templates" / "reports" / "profesional.css"
                if css_path.exists():
                    css_content = css_path.read_text()
                    css = CSS(string=css_content, font_config=font_config)
                    HTML(string=html_content).write_pdf(
                        output_path, stylesheets=[css], font_config=font_config
                    )
                else:
                    HTML(string=html_content).write_pdf(output_path)

                pdf_generated = True
                success(f"PDF report saved to {output_path}")
                return
            except ImportError:
                info("WeasyPrint not available, trying pandoc...")
            except Exception as e:
                warning(f"WeasyPrint PDF generation failed: {e}")

            # Fallback to pandoc
            if not pdf_generated:
                try:
                    import subprocess

                    temp_html = output_path.with_suffix(".tmp.html")
                    temp_html.write_text(html_content)
                    subprocess.run(
                        [
                            "pandoc",
                            str(temp_html),
                            "-o",
                            str(output_path),
                            "--pdf-engine=wkhtmltopdf",
                        ],
                        check=True,
                        capture_output=True,
                    )
                    temp_html.unlink()
                    success(f"PDF report saved to {output_path}")
                    return
                except FileNotFoundError:
                    warning("pandoc not found, saving as HTML instead")
                    output_path = output_path.with_suffix(".html")
                    output_content = html_content
                except subprocess.CalledProcessError as e:
                    warning(f"PDF generation failed: {e}")
                    output_path = output_path.with_suffix(".html")
                    output_content = html_content

        output_path.write_text(output_content)
        success(f"Report saved to {output_path}")
    else:
        # Output to stdout
        print(output_content)  # noqa: T201

    # Summary
    if RICH_AVAILABLE and output:
        console.print(
            f"\n[bold]Report Summary:[/bold] "
            f"[red]{variables['critical_count']}[/red] critical, "
            f"[red]{variables['high_count']}[/red] high, "
            f"[yellow]{variables['medium_count']}[/yellow] medium, "
            f"[cyan]{variables['low_count']}[/cyan] low"
        )
