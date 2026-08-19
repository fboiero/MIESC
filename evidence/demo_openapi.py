#!/usr/bin/env python3
"""
MIESC v5.4.2 - Demo: Core REST OpenAPI Documentation
====================================================
Demonstrates the OpenAPI 3.1.0 specification:
- API endpoints and tags
- Schema definitions
- Tool discovery
- Analysis, remediation, and report endpoints

Author: Fernando Boiero
License: AGPL-3.0
"""

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OPENAPI_SPEC = PROJECT_ROOT / "docs" / "openapi.yaml"


def print_separator(title: str):
    """Print a visual separator."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60 + "\n")


def load_openapi_spec():
    """Load the OpenAPI specification."""
    with OPENAPI_SPEC.open() as f:
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
    for tag in [tag["name"] for tag in spec.get("tags", [])]:
        if tag in tag_endpoints:
            print(f"\n{tag}:")
            for ep in tag_endpoints[tag]:
                print(f"  {ep['method']:6} {ep['path']:35} - {ep['summary'][:40]}")


def demo_core_tools(spec):
    """Demo REST tool discovery endpoints."""
    print_separator("Core Tool Discovery")

    tools_list = spec["paths"].get("/api/v1/tools/", {}).get("get", {})
    print("GET /api/v1/tools/")
    print(f"  Summary: {tools_list.get('summary', 'N/A')}")
    print(f"  Operation ID: {tools_list.get('operationId', 'N/A')}")

    tool_detail = spec["paths"].get("/api/v1/tools/{tool_name}/", {}).get("get", {})
    print("\nGET /api/v1/tools/{tool_name}/")
    print(f"  Summary: {tool_detail.get('summary', 'N/A')}")
    print(f"  Operation ID: {tool_detail.get('operationId', 'N/A')}")

    print("\nCore REST capabilities:")
    tools = [
        ("health", "Check service status and package version"),
        ("tools", "List configured analysis adapters"),
        ("layers", "List configured analysis layers"),
        ("quick-analysis", "Run a fast audit against Solidity source"),
        ("full-analysis", "Run all configured audit layers"),
        ("remediation", "Generate remediation guidance"),
        ("reports", "Generate local report artifacts"),
    ]
    for name, desc in tools:
        print(f"  - {name:30} {desc}")


def demo_schemas(spec):
    """Demo key schema definitions."""
    print_separator("Key Schema Definitions")

    schemas = spec["components"]["schemas"]

    categories = {
        "Service": ["RootResponse", "HealthResponse"],
        "Analysis": ["AnalyzeRequest"],
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


def demo_analysis_schema(spec):
    """Demo the analysis request schema in detail."""
    print_separator("AnalyzeRequest Schema")

    analyze_request = spec["components"]["schemas"].get("AnalyzeRequest", {})
    props = analyze_request.get("properties", {})

    print("AnalyzeRequest Properties:")
    for name, details in props.items():
        prop_type = details.get("type", details.get("$ref", "object"))
        enum_vals = details.get("enum", [])
        if enum_vals:
            print(f"  {name:20} {prop_type:15} enum: {enum_vals}")
        else:
            print(f"  {name:20} {prop_type}")


def demo_analysis_endpoints(spec):
    """Demo analysis endpoints."""
    print_separator("Analysis Endpoints")

    endpoints = [
        "/api/v1/analyze/quick/",
        "/api/v1/analyze/full/",
        "/api/v1/analyze/layer/{layer_num}/",
        "/api/v1/analyze/tool/{tool_name}/",
    ]
    for path in endpoints:
        operation = spec["paths"].get(path, {}).get("post", {})
        print(f"  POST   {path:35} - {operation.get('summary', 'N/A')}")


def demo_remediation_and_reports(spec):
    """Demo remediation and report endpoints."""
    print_separator("Remediation and Reports")

    endpoints = [
        ("POST", "/api/v1/remediate/"),
        ("POST", "/api/v1/validate-remediation/"),
        ("POST", "/api/v1/reports/"),
    ]
    for method, path in endpoints:
        operation = spec["paths"].get(path, {}).get(method.lower(), {})
        print(f"  {method:6} {path:35} - {operation.get('summary', 'N/A')}")


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
    print("       MIESC v5.4.2 - Core REST OpenAPI Demo")
    print("       API Documentation & Specification")
    print("=" * 60)

    spec = load_openapi_spec()

    demo_api_info(spec)
    demo_servers(spec)
    demo_tags(spec)
    demo_endpoints_by_tag(spec)
    demo_core_tools(spec)
    demo_schemas(spec)
    demo_analysis_schema(spec)
    demo_analysis_endpoints(spec)
    demo_remediation_and_reports(spec)
    demo_api_statistics(spec)

    print("\n" + "=" * 60)
    print("  OpenAPI Demo Complete!")
    print(f"  Full spec: {OPENAPI_SPEC.relative_to(PROJECT_ROOT)}")
    print("=" * 60 + "\n")
