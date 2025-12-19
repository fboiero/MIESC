"""
Tests for MIESC v4.1.0 New Modules

Tests for:
- MCP Tool Registry (tool discovery)
- Persistence Layer (SQLite)
- Compliance Mapper (CWE→ISO→NIST)

Author: Fernando Boiero
"""

import pytest
import tempfile
import os
from pathlib import Path


# =============================================================================
# MCP TOOL REGISTRY TESTS
# =============================================================================

class TestMCPToolRegistry:
    """Tests for MCP Tool Registry and tool discovery."""

    def test_registry_initialization(self):
        """Test registry initializes with default tools."""
        from src.mcp.tool_registry import MCPToolRegistry

        registry = MCPToolRegistry()
        assert len(registry._tools) > 0
        assert "miesc_run_audit" in registry._tools

    def test_list_tools_mcp_format(self):
        """Test tools are listed in MCP format."""
        from src.mcp.tool_registry import get_tool_registry

        registry = get_tool_registry()
        tools = registry.list_tools()

        assert isinstance(tools, list)
        assert len(tools) > 0

        # Check MCP format compliance
        tool = tools[0]
        assert "name" in tool
        assert "description" in tool
        assert "inputSchema" in tool
        assert tool["inputSchema"]["type"] == "object"

    def test_get_tool(self):
        """Test getting a specific tool."""
        from src.mcp.tool_registry import get_tool_registry

        registry = get_tool_registry()
        tool = registry.get_tool("miesc_run_audit")

        assert tool is not None
        assert tool.name == "miesc_run_audit"
        assert len(tool.parameters) > 0

    def test_register_custom_tool(self):
        """Test registering a custom tool."""
        from src.mcp.tool_registry import MCPToolRegistry, MCPTool, ToolCategory

        registry = MCPToolRegistry()
        custom_tool = MCPTool(
            name="custom_test_tool",
            description="A test tool",
            category=ToolCategory.STATIC_ANALYSIS,
            parameters=[]
        )

        registry.register(custom_tool)
        assert "custom_test_tool" in registry._tools

    def test_unregister_tool(self):
        """Test unregistering a tool."""
        from src.mcp.tool_registry import MCPToolRegistry, MCPTool, ToolCategory

        registry = MCPToolRegistry()
        custom_tool = MCPTool(
            name="temp_tool",
            description="Temporary",
            category=ToolCategory.REPORTING,
            parameters=[]
        )

        registry.register(custom_tool)
        assert "temp_tool" in registry._tools

        result = registry.unregister("temp_tool")
        assert result is True
        assert "temp_tool" not in registry._tools

    def test_tool_parameter_schema(self):
        """Test tool parameter JSON schema generation."""
        from src.mcp.tool_registry import MCPToolParameter

        param = MCPToolParameter(
            name="contract_path",
            type="string",
            description="Path to contract",
            required=True
        )

        schema = param.to_json_schema()
        assert schema["type"] == "string"
        assert "description" in schema

    def test_mcp_response_format(self):
        """Test MCP tools/list response format."""
        from src.mcp.tool_registry import get_tool_registry

        registry = get_tool_registry()
        response = registry.get_mcp_response()

        assert "tools" in response
        assert isinstance(response["tools"], list)

    def test_capabilities(self):
        """Test capabilities for MCP initialize."""
        from src.mcp.tool_registry import get_tool_registry

        registry = get_tool_registry()
        caps = registry.get_capabilities()

        assert "tools" in caps
        assert "experimental" in caps
        assert caps["experimental"]["miesc"]["version"] == "4.1.0"

    def test_filter_by_category(self):
        """Test filtering tools by category."""
        from src.mcp.tool_registry import get_tool_registry, ToolCategory

        registry = get_tool_registry()
        correlation_tools = registry.list_tools(category=ToolCategory.CORRELATION)

        assert len(correlation_tools) > 0
        # All returned tools should be correlation tools
        for tool in correlation_tools:
            assert "correlate" in tool["name"].lower() or "chain" in tool["name"].lower()


# =============================================================================
# PERSISTENCE LAYER TESTS
# =============================================================================

class TestPersistence:
    """Tests for SQLite persistence layer."""

    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            from src.core.persistence import MIESCDatabase
            yield MIESCDatabase(db_path)

    def test_database_initialization(self, temp_db):
        """Test database creates tables correctly."""
        import sqlite3

        conn = sqlite3.connect(temp_db.db_path)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()

        assert "audits" in tables
        assert "findings" in tables
        assert "metrics" in tables
        assert "tool_performance" in tables

    def test_create_audit(self, temp_db):
        """Test creating an audit record."""
        audit_id = temp_db.create_audit("/tmp/Token.sol", ["slither", "mythril"])

        assert audit_id is not None
        assert audit_id.startswith("audit-")

        # Verify it can be retrieved
        audit = temp_db.get_audit(audit_id)
        assert audit is not None
        assert audit.contract_path == "/tmp/Token.sol"
        assert audit.status == "pending"

    def test_update_audit_status(self, temp_db):
        """Test updating audit status."""
        from src.core.persistence import AuditStatus

        audit_id = temp_db.create_audit("/tmp/Test.sol", ["slither"])

        result = temp_db.update_audit_status(
            audit_id,
            AuditStatus.COMPLETED,
            {
                "tools_success": ["slither"],
                "tools_failed": [],
                "total_findings": 5,
                "findings_by_severity": {"high": 2, "medium": 3},
                "execution_time_ms": 1234.5
            }
        )

        assert result is True

        audit = temp_db.get_audit(audit_id)
        assert audit.status == "completed"
        assert audit.total_findings == 5
        assert audit.findings_by_severity["high"] == 2

    def test_store_finding(self, temp_db):
        """Test storing a finding."""
        audit_id = temp_db.create_audit("/tmp/Test.sol", ["slither"])

        finding_id = temp_db.store_finding(audit_id, {
            "tool": "slither",
            "type": "reentrancy",
            "severity": "high",
            "title": "Reentrancy in withdraw()",
            "confidence": 0.9
        })

        assert finding_id is not None
        assert finding_id.startswith("find-")

    def test_store_multiple_findings(self, temp_db):
        """Test storing multiple findings."""
        audit_id = temp_db.create_audit("/tmp/Test.sol", ["slither"])

        findings = [
            {"tool": "slither", "type": "reentrancy", "severity": "high", "title": "Reentrancy"},
            {"tool": "mythril", "type": "overflow", "severity": "medium", "title": "Overflow"},
        ]

        count = temp_db.store_findings(audit_id, findings)
        assert count == 2

    def test_get_findings_for_audit(self, temp_db):
        """Test retrieving findings for an audit."""
        audit_id = temp_db.create_audit("/tmp/Test.sol", ["slither"])

        temp_db.store_findings(audit_id, [
            {"tool": "slither", "type": "reentrancy", "severity": "high", "title": "A"},
            {"tool": "slither", "type": "overflow", "severity": "critical", "title": "B"},
        ])

        findings = temp_db.get_findings_for_audit(audit_id)
        assert len(findings) == 2
        # Should be ordered by severity (critical first)
        assert findings[0].severity == "critical"

    def test_mark_false_positive(self, temp_db):
        """Test marking a finding as false positive."""
        audit_id = temp_db.create_audit("/tmp/Test.sol", ["slither"])
        finding_id = temp_db.store_finding(audit_id, {
            "tool": "slither",
            "type": "reentrancy",
            "severity": "high",
            "title": "FP Test"
        })

        result = temp_db.mark_false_positive(finding_id, True)
        assert result is True

    def test_get_statistics(self, temp_db):
        """Test getting database statistics."""
        # Create some data
        audit_id = temp_db.create_audit("/tmp/Test.sol", ["slither"])
        temp_db.store_findings(audit_id, [
            {"tool": "slither", "type": "reentrancy", "severity": "high", "title": "A"},
            {"tool": "slither", "type": "overflow", "severity": "medium", "title": "B"},
        ])

        stats = temp_db.get_statistics()

        assert stats["total_audits"] == 1
        assert stats["total_findings"] == 2
        assert "high" in stats["findings_by_severity"]

    def test_record_tool_performance(self, temp_db):
        """Test recording tool performance metrics."""
        temp_db.record_tool_performance(
            tool_name="slither",
            execution_time_ms=1500.0,
            findings_count=5,
            success=True
        )

        stats = temp_db.get_tool_statistics("slither")
        assert "slither" in stats
        assert stats["slither"]["total_runs"] == 1

    def test_get_recent_audits(self, temp_db):
        """Test getting recent audits."""
        for i in range(5):
            temp_db.create_audit(f"/tmp/Test{i}.sol", ["slither"])

        recent = temp_db.get_recent_audits(limit=3)
        assert len(recent) == 3


# =============================================================================
# COMPLIANCE MAPPER TESTS
# =============================================================================

class TestComplianceMapper:
    """Tests for compliance mapping module."""

    def test_mapper_initialization(self):
        """Test compliance mapper initializes."""
        from src.security.compliance_mapper import ComplianceMapper

        mapper = ComplianceMapper()
        assert mapper is not None

    def test_map_reentrancy_finding(self):
        """Test mapping reentrancy vulnerability."""
        from src.security.compliance_mapper import get_compliance_mapper

        mapper = get_compliance_mapper()
        finding = {"type": "reentrancy", "severity": "high"}

        mapping = mapper.map_finding(finding)

        assert mapping.swc_id == "SWC-107"
        assert mapping.swc_title == "Reentrancy"
        assert "CWE-841" in mapping.cwe_ids
        assert len(mapping.iso27001_controls) > 0
        assert len(mapping.nist_csf_functions) > 0
        assert "SC01" in mapping.owasp_sc_categories

    def test_map_integer_overflow(self):
        """Test mapping integer overflow."""
        from src.security.compliance_mapper import get_compliance_mapper

        mapper = get_compliance_mapper()
        finding = {"type": "integer-overflow"}

        mapping = mapper.map_finding(finding)

        assert mapping.swc_id == "SWC-101"
        assert "CWE-190" in mapping.cwe_ids or "CWE-191" in mapping.cwe_ids

    def test_map_tx_origin(self):
        """Test mapping tx.origin vulnerability."""
        from src.security.compliance_mapper import get_compliance_mapper

        mapper = get_compliance_mapper()
        finding = {"type": "tx-origin"}

        mapping = mapper.map_finding(finding)

        assert mapping.swc_id == "SWC-115"
        assert "SC04" in mapping.owasp_sc_categories  # Access control

    def test_generate_report(self):
        """Test generating compliance report."""
        from src.security.compliance_mapper import get_compliance_mapper

        mapper = get_compliance_mapper()
        findings = [
            {"type": "reentrancy", "severity": "high"},
            {"type": "integer-overflow", "severity": "medium"},
            {"type": "unchecked-call", "severity": "low"},
        ]

        report = mapper.generate_report(findings)

        assert report.total_findings == 3
        assert report.mapped_findings == 3
        assert "ISO27001" in report.coverage_by_framework
        assert "NIST_CSF" in report.coverage_by_framework
        assert 0 <= report.overall_score <= 1

    def test_iso27001_gaps(self):
        """Test identifying ISO 27001 gaps."""
        from src.security.compliance_mapper import get_compliance_mapper

        mapper = get_compliance_mapper()
        findings = [{"type": "reentrancy"}]

        gaps = mapper.get_iso27001_gaps(findings)

        assert len(gaps) > 0
        assert all(g["framework"] == "ISO27001" for g in gaps)

    def test_enrich_finding(self):
        """Test enriching a finding with compliance data."""
        from src.security.compliance_mapper import get_compliance_mapper

        mapper = get_compliance_mapper()
        finding = {"type": "reentrancy", "severity": "high", "title": "Test"}

        enriched = mapper.enrich_finding(finding)

        assert "compliance" in enriched
        assert enriched["compliance"]["swc_id"] == "SWC-107"
        assert enriched["title"] == "Test"  # Original preserved

    def test_unknown_vulnerability_type(self):
        """Test handling unknown vulnerability type."""
        from src.security.compliance_mapper import get_compliance_mapper

        mapper = get_compliance_mapper()
        finding = {"type": "unknown-vulnerability"}

        mapping = mapper.map_finding(finding)

        # Should not crash, may have empty mappings
        assert mapping is not None
        assert mapping.compliance_score >= 0

    def test_existing_swc_preserved(self):
        """Test that existing SWC ID is preserved."""
        from src.security.compliance_mapper import get_compliance_mapper

        mapper = get_compliance_mapper()
        finding = {"type": "unknown", "swc_id": "SWC-107"}

        mapping = mapper.map_finding(finding)

        assert mapping.swc_id == "SWC-107"

    def test_vuln_type_normalization(self):
        """Test vulnerability type normalization."""
        from src.security.compliance_mapper import get_compliance_mapper

        mapper = get_compliance_mapper()

        # All these should map to the same SWC
        types = ["reentrancy", "reentrancy-eth", "REENTRANCY", "reentrancy_eth"]

        for vtype in types:
            finding = {"type": vtype}
            mapping = mapper.map_finding(finding)
            assert mapping.swc_id == "SWC-107", f"Failed for type: {vtype}"


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """Integration tests for new modules."""

    def test_mcp_to_persistence_flow(self):
        """Test flow from MCP tool registry to persistence."""
        from src.mcp.tool_registry import get_tool_registry
        from src.core.persistence import MIESCDatabase

        # Get tools from registry
        registry = get_tool_registry()
        tools = registry.list_tools()
        assert len(tools) > 0

        # Create audit in temp db
        with tempfile.TemporaryDirectory() as tmpdir:
            db = MIESCDatabase(os.path.join(tmpdir, "test.db"))
            audit_id = db.create_audit("/tmp/Test.sol", ["slither"])
            assert audit_id is not None

    def test_compliance_with_persistence(self):
        """Test compliance mapper with persistence."""
        from src.security.compliance_mapper import get_compliance_mapper
        from src.core.persistence import MIESCDatabase

        mapper = get_compliance_mapper()

        with tempfile.TemporaryDirectory() as tmpdir:
            db = MIESCDatabase(os.path.join(tmpdir, "test.db"))
            audit_id = db.create_audit("/tmp/Test.sol", ["slither"])

            # Store finding with compliance mapping
            finding = {"type": "reentrancy", "severity": "high", "title": "Test"}
            enriched = mapper.enrich_finding(finding)

            finding_id = db.store_finding(audit_id, {
                **enriched,
                "swc_id": enriched["compliance"]["swc_id"],
                "cwe_id": enriched["compliance"]["cwe_ids"][0] if enriched["compliance"]["cwe_ids"] else None,
            })

            assert finding_id is not None

            # Retrieve and verify
            findings = db.get_findings_for_audit(audit_id)
            assert len(findings) == 1
            assert findings[0].swc_id == "SWC-107"
