#!/usr/bin/env python3
"""
MIESC v4.2.0 - Demo: OpenAPI Documentation
==========================================
Demonstrates the OpenAPI 3.1.0 specification:
- API endpoints and tags
- Schema definitions
- MCP Tool Discovery
- Compliance and Export endpoints

Author: Fernando Boiero
License: GPL-3.0
"""

import sys

import yaml

sys.path.insert(0, "/Users/fboiero/Documents/GitHub/MIESC")


def print_separator(title: str):
    """Print a visual separator."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60 + "\n")


def load_openapi_spec():
    """Load the OpenAPI specification."""
    with open("/Users/fboiero/Documents/GitHub/MIESC/docs/openapi.yaml", "r") as f:
        return yaml.safe_load(f)


def demo_api_info(spec):
    """Demo API information."""
    print_separator("API Information")

    info = spec["info"]
    print(f"Title: {info['title']}")
    print(f"Version: {info['version']}")
    print(f"License: {info['license']['name']}")

    print("\nContact:")
    print(f"  Name: {info['contact']['name']}")
    print(f"  Email: {info['contact']['email']}")

    print("\nDescription Highlights:")
    desc_lines = info["description"].split("\n")
    for line in desc_lines[4:20]:  # Key features
        if line.strip():
            print(f"  {line.strip()}")


def demo_servers(spec):
    """Demo server configurations."""
    print_separator("Server Configurations")

    for server in spec["servers"]:
        print(f"  {server['url']:30} - {server['description']}")


def demo_tags(spec):
    """Demo API tags/categories."""
    print_separator("API Categories (Tags)")

    for tag in spec["tags"]:
        print(f"  {tag['name']:15} - {tag['description']}")


def demo_endpoints_by_tag(spec):
    """Demo endpoints grouped by tag."""
    print_separator("Endpoints by Category")

    # Group endpoints by tag
    tag_endpoints = {}
    for path, methods in spec["paths"].items():
        for method, details in methods.items():
            if method in ["get", "post", "patch", "delete", "put"]:
                tags = details.get("tags", ["Other"])
                for tag in tags:
                    if tag not in tag_endpoints:
                        tag_endpoints[tag] = []
                    tag_endpoints[tag].append(
                        {
                            "method": method.upper(),
                            "path": path,
                            "summary": details.get("summary", "N/A"),
                            "operationId": details.get("operationId", "N/A"),
                        }
                    )

    # Display by category
    for tag in [
        "MCP",
        "MCP Tools",
        "Analysis",
        "Correlation",
        "Remediation",
        "Export",
        "Persistence",
        "Compliance",
        "Observability",
        "WebSocket",
    ]:
        if tag in tag_endpoints:
            print(f"\n{tag}:")
            for ep in tag_endpoints[tag]:
                print(f"  {ep['method']:6} {ep['path']:35} - {ep['summary'][:40]}")


def demo_mcp_tools(spec):
    """Demo MCP Tool Discovery endpoints."""
    print_separator("MCP Tool Discovery")

    # tools/list endpoint
    tools_list = spec["paths"].get("/mcp/tools/list", {}).get("get", {})
    print("GET /mcp/tools/list")
    print(f"  Summary: {tools_list.get('summary', 'N/A')}")
    print(f"  Operation ID: {tools_list.get('operationId', 'N/A')}")

    # tools/call endpoint
    tools_call = spec["paths"].get("/mcp/tools/call", {}).get("post", {})
    print("\nPOST /mcp/tools/call")
    print(f"  Summary: {tools_call.get('summary', 'N/A')}")
    print(f"  Operation ID: {tools_call.get('operationId', 'N/A')}")

    # Available MCP tools
    print("\nAvailable MCP Tools (from description):")
    tools = [
        ("miesc_run_audit", "Execute comprehensive smart contract audit"),
        ("miesc_correlate", "Correlate findings from multiple tools"),
        ("miesc_map_compliance", "Map findings to compliance frameworks"),
        ("miesc_remediate", "Get remediation suggestions"),
        ("miesc_generate_report", "Generate audit report"),
        ("miesc_quick_scan", "Fast security scan"),
        ("miesc_deep_scan", "Comprehensive deep analysis"),
        ("miesc_get_metrics", "Get scientific validation metrics"),
        ("miesc_get_status", "Get system health status"),
        ("miesc_analyze_defi", "DeFi-specific security analysis"),
        ("miesc_detect_exploit_chains", "Detect exploit chains"),
    ]
    for name, desc in tools:
        print(f"  - {name:30} {desc}")


def demo_schemas(spec):
    """Demo key schema definitions."""
    print_separator("Key Schema Definitions")

    schemas = spec["components"]["schemas"]

    # Count and categorize schemas
    categories = {
        "MCP": [
            "MCPTool",
            "MCPToolCallRequest",
            "MCPToolCallResponse",
            "MCPToolsListResponse",
            "MCPInitializeRequest",
            "MCPInitializeResponse",
        ],
        "Findings": ["Finding", "CorrelatedFinding", "EnrichedFinding", "FindingRecord"],
        "Audit": ["AuditRequest", "AuditResponse", "AuditRecord", "AuditListResponse"],
        "Correlation": ["CorrelateRequest", "CorrelateResponse", "CorrelationStatistics"],
        "Exploit Chains": ["ExploitChain", "ExploitChainSummary", "ExploitChainsResponse"],
        "Remediation": [
            "RemediateRequest",
            "RemediateResponse",
            "RemediationReport",
            "FixPlanStep",
        ],
        "Compliance": ["ComplianceMapping", "ComplianceReportRequest", "ComplianceReportResponse"],
        "Metrics": ["MetricsResponse", "ScientificValidation"],
    }

    print(f"Total Schemas: {len(schemas)}\n")

    for category, schema_names in categories.items():
        print(f"{category}:")
        for name in schema_names:
            if name in schemas:
                schema = schemas[name]
                props = len(schema.get("properties", {}))
                required = len(schema.get("required", []))
                print(f"  - {name:30} ({props} properties, {required} required)")
        print()


def demo_finding_schema(spec):
    """Demo the Finding schema in detail."""
    print_separator("Finding Schema (Detailed)")

    finding = spec["components"]["schemas"].get("Finding", {})
    props = finding.get("properties", {})

    print("Finding Properties:")
    for name, details in props.items():
        prop_type = details.get("type", details.get("$ref", "object"))
        enum_vals = details.get("enum", [])
        if enum_vals:
            print(f"  {name:20} {prop_type:15} enum: {enum_vals}")
        else:
            print(f"  {name:20} {prop_type}")


def demo_scientific_validation(spec):
    """Demo scientific validation metrics schema."""
    print_separator("Scientific Validation Metrics")

    validation = spec["components"]["schemas"].get("ScientificValidation", {})
    props = validation.get("properties", {})

    print("Validation Metrics (from thesis experiments):")
    for name, details in props.items():
        example = details.get("example", "N/A")
        print(f"  {name:25} = {example}")


def demo_export_formats(spec):
    """Demo export endpoint and formats."""
    print_separator("Export Formats")

    export = spec["paths"].get("/export", {}).get("post", {})
    print(f"POST /export - {export.get('summary', 'N/A')}")

    # Export request schema
    export_req = spec["components"]["schemas"].get("ExportRequest", {})
    format_prop = export_req.get("properties", {}).get("format", {})
    formats = format_prop.get("enum", [])

    print("\nSupported Formats:")
    format_details = {
        "sarif": ("application/json", "GitHub/GitLab integration"),
        "sonarqube": ("application/json", "Enterprise CI/CD"),
        "checkmarx": ("application/xml", "Enterprise SAST"),
        "markdown": ("text/markdown", "Human-readable reports"),
        "json": ("application/json", "API integration"),
    }

    for fmt in formats:
        content_type, desc = format_details.get(fmt, ("unknown", "Unknown"))
        print(f"  - {fmt:12} ({content_type:20}) - {desc}")


def demo_compliance_endpoints(spec):
    """Demo compliance mapping endpoints."""
    print_separator("Compliance Mapping Endpoints")

    compliance_endpoints = [
        ("/compliance/map", "POST", "Map finding to compliance frameworks"),
        ("/compliance/report", "POST", "Generate compliance report"),
        ("/compliance/enrich", "POST", "Enrich findings with compliance data"),
        ("/compliance/gaps/iso27001", "POST", "Identify ISO 27001 gaps"),
    ]

    print("Endpoints:")
    for path, method, desc in compliance_endpoints:
        print(f"  {method:6} {path:30} - {desc}")

    print("\nSupported Frameworks:")
    frameworks = [
        ("SWC", "Smart Contract Weakness Classification"),
        ("CWE", "Common Weakness Enumeration"),
        ("ISO 27001:2022", "Information Security Controls"),
        ("NIST CSF", "Cybersecurity Framework"),
        ("OWASP SC Top 10", "Smart Contract Security"),
    ]
    for code, name in frameworks:
        print(f"  - {code:20} {name}")


def demo_websocket_events(spec):
    """Demo WebSocket event types."""
    print_separator("WebSocket Real-Time Events")

    ws_info = spec["paths"].get("/ws", {}).get("get", {})
    print(f"GET /ws - {ws_info.get('summary', 'N/A')}")

    print("\nWebSocket Endpoints:")
    print("  ws://host:port/ws              - Main WebSocket endpoint")
    print("  ws://host:port/ws/audit/{id}   - Audit-specific endpoint")

    print("\nEvent Types:")
    events = [
        ("audit_started", "Audit begins execution"),
        ("audit_progress", "Progress update (0-100%)"),
        ("audit_completed", "Audit finished successfully"),
        ("audit_error", "Audit encountered error"),
        ("tool_started", "Tool begins execution"),
        ("tool_completed", "Tool finished"),
        ("finding_detected", "New vulnerability found"),
        ("layer_started", "Analysis layer begins"),
        ("layer_completed", "Analysis layer finished"),
        ("heartbeat", "Connection keep-alive"),
    ]
    for event, desc in events:
        print(f"  - {event:20} {desc}")


def demo_api_statistics(spec):
    """Demo API statistics summary."""
    print_separator("API Statistics Summary")

    # Count endpoints
    total_endpoints = 0
    methods_count = {"get": 0, "post": 0, "patch": 0, "delete": 0}
    for _path, methods in spec["paths"].items():
        for method in methods:
            if method in methods_count:
                methods_count[method] += 1
                total_endpoints += 1

    print(f"Total Endpoints: {total_endpoints}")
    print("\nBy Method:")
    for method, count in methods_count.items():
        if count > 0:
            print(f"  {method.upper():8} {count}")

    # Count schemas
    schemas = spec["components"]["schemas"]
    print(f"\nTotal Schemas: {len(schemas)}")

    # Count tags
    print(f"API Categories: {len(spec['tags'])}")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("       MIESC v4.2.0 'Fortress' - OpenAPI Demo")
    print("       API Documentation & Specification")
    print("=" * 60)

    spec = load_openapi_spec()

    demo_api_info(spec)
    demo_servers(spec)
    demo_tags(spec)
    demo_endpoints_by_tag(spec)
    demo_mcp_tools(spec)
    demo_schemas(spec)
    demo_finding_schema(spec)
    demo_scientific_validation(spec)
    demo_export_formats(spec)
    demo_compliance_endpoints(spec)
    demo_websocket_events(spec)
    demo_api_statistics(spec)

    print("\n" + "=" * 60)
    print("  OpenAPI Demo Complete!")
    print("  Full spec: docs/openapi.yaml (2273 lines)")
    print("=" * 60 + "\n")
