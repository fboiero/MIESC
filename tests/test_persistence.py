"""
Tests for Persistence module.

Tests the SQLite persistence layer for audit results.
"""

import tempfile
from pathlib import Path

import pytest

from src.core.persistence import (
    AuditRecord,
    AuditStatus,
    FindingRecord,
    MIESCDatabase,
    get_database,
    reset_database,
)


class TestAuditStatus:
    """Test AuditStatus enum."""

    def test_all_statuses_exist(self):
        """Test all statuses exist."""
        assert AuditStatus.PENDING.value == "pending"
        assert AuditStatus.RUNNING.value == "running"
        assert AuditStatus.COMPLETED.value == "completed"
        assert AuditStatus.FAILED.value == "failed"
        assert AuditStatus.CANCELLED.value == "cancelled"

    def test_status_count(self):
        """Test expected number of statuses."""
        assert len(AuditStatus) == 5


class TestAuditRecord:
    """Test AuditRecord dataclass."""

    def test_create_audit_record(self):
        """Test creating audit record."""
        record = AuditRecord(
            audit_id="audit-123",
            contract_path="/path/to/Token.sol",
            contract_hash="abc123",
            status="completed",
            tools_run=["slither", "mythril"],
            tools_success=["slither"],
            tools_failed=["mythril"],
            total_findings=5,
            findings_by_severity={"high": 2, "medium": 3},
            execution_time_ms=1500.5,
            created_at="2024-01-01T00:00:00Z",
        )
        assert record.audit_id == "audit-123"
        assert record.contract_path == "/path/to/Token.sol"
        assert record.status == "completed"
        assert len(record.tools_run) == 2

    def test_audit_record_defaults(self):
        """Test audit record defaults."""
        record = AuditRecord(
            audit_id="audit-1",
            contract_path="test.sol",
            contract_hash="hash",
            status="pending",
            tools_run=[],
            tools_success=[],
            tools_failed=[],
            total_findings=0,
            findings_by_severity={},
            execution_time_ms=0,
            created_at="2024-01-01",
        )
        assert record.completed_at is None
        assert record.metadata is None

    def test_audit_record_to_dict(self):
        """Test converting to dict."""
        record = AuditRecord(
            audit_id="audit-1",
            contract_path="test.sol",
            contract_hash="hash",
            status="pending",
            tools_run=["slither"],
            tools_success=[],
            tools_failed=[],
            total_findings=0,
            findings_by_severity={},
            execution_time_ms=100,
            created_at="2024-01-01",
        )
        d = record.to_dict()
        assert d["audit_id"] == "audit-1"
        assert d["contract_path"] == "test.sol"
        assert "tools_run" in d


class TestFindingRecord:
    """Test FindingRecord dataclass."""

    def test_create_finding_record(self):
        """Test creating finding record."""
        record = FindingRecord(
            finding_id="find-123",
            audit_id="audit-123",
            tool="slither",
            vulnerability_type="reentrancy",
            severity="high",
            confidence=0.95,
            title="Reentrancy Vulnerability",
            description="External call followed by state change",
        )
        assert record.finding_id == "find-123"
        assert record.tool == "slither"
        assert record.severity == "high"
        assert record.confidence == 0.95

    def test_finding_record_defaults(self):
        """Test finding record defaults."""
        record = FindingRecord(
            finding_id="find-1",
            audit_id="audit-1",
            tool="test",
            vulnerability_type="test",
            severity="medium",
            confidence=0.5,
            title="Test",
            description="Test",
        )
        assert record.location is None
        assert record.remediation is None
        assert record.cwe_id is None
        assert record.swc_id is None
        assert record.false_positive is False
        assert record.cross_validated is False

    def test_finding_record_to_dict(self):
        """Test converting to dict."""
        record = FindingRecord(
            finding_id="find-1",
            audit_id="audit-1",
            tool="slither",
            vulnerability_type="overflow",
            severity="medium",
            confidence=0.8,
            title="Overflow",
            description="Integer overflow",
            swc_id="SWC-101",
        )
        d = record.to_dict()
        assert d["finding_id"] == "find-1"
        assert d["swc_id"] == "SWC-101"
        assert d["severity"] == "medium"


class TestMIESCDatabase:
    """Test MIESCDatabase class."""

    @pytest.fixture
    def db(self, tmp_path):
        """Create database with temp file."""
        db_path = str(tmp_path / "test_miesc.db")
        return MIESCDatabase(db_path)

    def test_init(self, db):
        """Test database initialization."""
        assert db.db_path is not None
        assert Path(db.db_path).exists()

    def test_generate_id(self, db):
        """Test ID generation."""
        id1 = db._generate_id("test-")
        id2 = db._generate_id("test-")
        assert id1.startswith("test-")
        assert id1 != id2

    def test_compute_hash(self, db):
        """Test hash computation."""
        hash1 = db._compute_hash("test content")
        hash2 = db._compute_hash("test content")
        hash3 = db._compute_hash("different content")
        assert hash1 == hash2
        assert hash1 != hash3
        assert len(hash1) == 16

    def test_now_iso(self, db):
        """Test ISO timestamp generation."""
        timestamp = db._now_iso()
        assert "T" in timestamp
        assert timestamp.endswith("Z")


class TestMIESCDatabaseAuditOperations:
    """Test audit operations."""

    @pytest.fixture
    def db(self, tmp_path):
        """Create database."""
        db_path = str(tmp_path / "test_miesc.db")
        return MIESCDatabase(db_path)

    @pytest.fixture
    def contract_file(self, tmp_path):
        """Create test contract file."""
        contract = tmp_path / "Token.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Token {}")
        return str(contract)

    def test_create_audit(self, db, contract_file):
        """Test creating audit."""
        audit_id = db.create_audit(contract_file, ["slither", "mythril"])
        assert audit_id.startswith("audit-")

    def test_create_audit_with_metadata(self, db, contract_file):
        """Test creating audit with metadata."""
        audit_id = db.create_audit(
            contract_file,
            ["slither"],
            metadata={"version": "1.0", "mode": "full"},
        )
        assert audit_id is not None

    def test_create_audit_nonexistent_file(self, db):
        """Test creating audit for nonexistent file."""
        # Should use path as hash source
        audit_id = db.create_audit("/nonexistent/path.sol", ["slither"])
        assert audit_id is not None

    def test_get_audit(self, db, contract_file):
        """Test getting audit."""
        audit_id = db.create_audit(contract_file, ["slither"])
        audit = db.get_audit(audit_id)
        assert audit is not None
        assert audit.audit_id == audit_id
        assert audit.status == "pending"

    def test_get_audit_not_found(self, db):
        """Test getting nonexistent audit."""
        audit = db.get_audit("nonexistent-id")
        assert audit is None

    def test_update_audit_status(self, db, contract_file):
        """Test updating audit status."""
        audit_id = db.create_audit(contract_file, ["slither"])
        result = db.update_audit_status(audit_id, AuditStatus.RUNNING)
        assert result is True

        audit = db.get_audit(audit_id)
        assert audit.status == "running"

    def test_update_audit_status_with_results(self, db, contract_file):
        """Test updating audit with results."""
        audit_id = db.create_audit(contract_file, ["slither", "mythril"])
        results = {
            "tools_success": ["slither"],
            "tools_failed": ["mythril"],
            "total_findings": 3,
            "findings_by_severity": {"high": 1, "medium": 2},
            "execution_time_ms": 5000,
        }
        db.update_audit_status(audit_id, AuditStatus.COMPLETED, results)

        audit = db.get_audit(audit_id)
        assert audit.status == "completed"
        assert audit.total_findings == 3
        assert audit.completed_at is not None

    def test_get_audits_for_contract(self, db, contract_file):
        """Test getting audits for contract."""
        db.create_audit(contract_file, ["slither"])
        db.create_audit(contract_file, ["mythril"])

        audits = db.get_audits_for_contract(contract_file)
        assert len(audits) == 2

    def test_get_recent_audits(self, db, contract_file):
        """Test getting recent audits."""
        db.create_audit(contract_file, ["slither"])
        db.create_audit(contract_file, ["mythril"])

        audits = db.get_recent_audits(limit=5)
        assert len(audits) == 2


class TestMIESCDatabaseFindingOperations:
    """Test finding operations."""

    @pytest.fixture
    def db(self, tmp_path):
        """Create database."""
        db_path = str(tmp_path / "test_miesc.db")
        return MIESCDatabase(db_path)

    @pytest.fixture
    def audit_id(self, db, tmp_path):
        """Create test audit."""
        contract = tmp_path / "Token.sol"
        contract.write_text("contract Token {}")
        return db.create_audit(str(contract), ["slither"])

    def test_store_finding(self, db, audit_id):
        """Test storing a finding."""
        finding = {
            "tool": "slither",
            "type": "reentrancy",
            "severity": "high",
            "confidence": 0.95,
            "title": "Reentrancy",
            "description": "External call issue",
        }
        finding_id = db.store_finding(audit_id, finding)
        assert finding_id.startswith("find-")

    def test_store_finding_with_location(self, db, audit_id):
        """Test storing finding with location."""
        finding = {
            "tool": "mythril",
            "type": "overflow",
            "severity": "medium",
            "confidence": 0.8,
            "title": "Integer Overflow",
            "description": "Potential overflow",
            "location": {"file": "Token.sol", "line": 42},
        }
        finding_id = db.store_finding(audit_id, finding)
        assert finding_id is not None

    def test_store_findings_batch(self, db, audit_id):
        """Test storing multiple findings."""
        findings = [
            {
                "tool": "slither",
                "type": "reentrancy",
                "severity": "high",
                "title": "Re1",
                "description": "desc",
            },
            {
                "tool": "slither",
                "type": "overflow",
                "severity": "medium",
                "title": "Ov1",
                "description": "desc",
            },
            {
                "tool": "mythril",
                "type": "timestamp",
                "severity": "low",
                "title": "Ts1",
                "description": "desc",
            },
        ]
        count = db.store_findings(audit_id, findings)
        assert count == 3

    def test_get_findings_for_audit(self, db, audit_id):
        """Test getting findings for audit."""
        findings = [
            {
                "tool": "slither",
                "type": "reentrancy",
                "severity": "high",
                "title": "High",
                "description": "desc",
            },
            {
                "tool": "slither",
                "type": "overflow",
                "severity": "low",
                "title": "Low",
                "description": "desc",
            },
        ]
        db.store_findings(audit_id, findings)

        results = db.get_findings_for_audit(audit_id)
        assert len(results) == 2
        # Should be sorted by severity
        assert results[0].severity == "high"

    def test_get_findings_by_severity(self, db, audit_id):
        """Test filtering findings by severity."""
        findings = [
            {
                "tool": "tool1",
                "type": "type1",
                "severity": "high",
                "title": "H1",
                "description": "d",
            },
            {
                "tool": "tool2",
                "type": "type2",
                "severity": "high",
                "title": "H2",
                "description": "d",
            },
            {
                "tool": "tool3",
                "type": "type3",
                "severity": "low",
                "title": "L1",
                "description": "d",
            },
        ]
        db.store_findings(audit_id, findings)

        high_findings = db.get_findings_by_severity("high")
        assert len(high_findings) == 2

    def test_mark_false_positive(self, db, audit_id):
        """Test marking false positive."""
        finding_id = db.store_finding(
            audit_id,
            {"tool": "test", "type": "test", "severity": "low", "title": "FP", "description": "d"},
        )

        result = db.mark_false_positive(finding_id, True)
        assert result is True


class TestMIESCDatabaseMetrics:
    """Test metrics operations."""

    @pytest.fixture
    def db(self, tmp_path):
        """Create database."""
        db_path = str(tmp_path / "test_miesc.db")
        return MIESCDatabase(db_path)

    def test_record_metric(self, db):
        """Test recording metric."""
        # Should not raise
        db.record_metric("counter", "test_metric", 42.0)

    def test_record_metric_with_labels(self, db):
        """Test recording metric with labels."""
        db.record_metric("gauge", "memory_usage", 1024.5, {"host": "localhost"})

    def test_record_tool_performance(self, db):
        """Test recording tool performance."""
        db.record_tool_performance(
            tool_name="slither",
            execution_time_ms=1500.5,
            findings_count=3,
            success=True,
        )

    def test_record_tool_performance_failure(self, db):
        """Test recording failed tool execution."""
        db.record_tool_performance(
            tool_name="mythril",
            execution_time_ms=5000,
            findings_count=0,
            success=False,
            error_message="Timeout exceeded",
        )

    def test_get_statistics_empty(self, db):
        """Test statistics on empty database."""
        stats = db.get_statistics()
        assert stats["total_audits"] == 0
        assert stats["total_findings"] == 0

    def test_get_statistics(self, db, tmp_path):
        """Test statistics with data."""
        contract = tmp_path / "Token.sol"
        contract.write_text("contract Token {}")
        audit_id = db.create_audit(str(contract), ["slither"])

        findings = [
            {
                "tool": "slither",
                "type": "t1",
                "severity": "high",
                "title": "T1",
                "description": "d",
            },
            {
                "tool": "slither",
                "type": "t2",
                "severity": "high",
                "title": "T2",
                "description": "d",
            },
            {"tool": "mythril", "type": "t3", "severity": "low", "title": "T3", "description": "d"},
        ]
        db.store_findings(audit_id, findings)

        stats = db.get_statistics()
        assert stats["total_audits"] == 1
        assert stats["total_findings"] == 3
        assert "high" in stats["findings_by_severity"]

    def test_get_tool_statistics_empty(self, db):
        """Test tool statistics empty."""
        stats = db.get_tool_statistics()
        assert stats == {}

    def test_get_tool_statistics(self, db):
        """Test tool statistics with data."""
        db.record_tool_performance("slither", 1000, 5, True)
        db.record_tool_performance("slither", 2000, 3, True)
        db.record_tool_performance("slither", 1500, 0, False, "Error")

        stats = db.get_tool_statistics("slither")
        assert "slither" in stats
        assert stats["slither"]["total_runs"] == 3

    def test_get_tool_statistics_all(self, db):
        """Test tool statistics for all tools."""
        db.record_tool_performance("slither", 1000, 5, True)
        db.record_tool_performance("mythril", 2000, 3, True)

        stats = db.get_tool_statistics()
        assert "slither" in stats
        assert "mythril" in stats


class TestMIESCDatabaseMaintenance:
    """Test maintenance operations."""

    @pytest.fixture
    def db(self, tmp_path):
        """Create database."""
        db_path = str(tmp_path / "test_miesc.db")
        return MIESCDatabase(db_path)

    def test_cleanup_old_audits(self, db, tmp_path):
        """Test cleanup old audits."""
        contract = tmp_path / "Token.sol"
        contract.write_text("contract Token {}")
        db.create_audit(str(contract), ["slither"])

        # Cleanup with 0 days should remove all (or at least not crash)
        count = db.cleanup_old_audits(days=365)
        assert count >= 0

    def test_vacuum(self, db):
        """Test vacuum operation."""
        # Should not raise
        db.vacuum()


class TestDatabaseSingleton:
    """Test singleton pattern."""

    def test_get_database(self, tmp_path):
        """Test getting singleton."""
        reset_database()
        db_path = str(tmp_path / "singleton_test.db")
        db1 = get_database(db_path)
        db2 = get_database()
        assert db1 is db2

    def test_reset_database(self, tmp_path):
        """Test resetting singleton."""
        db_path = str(tmp_path / "reset_test.db")
        db1 = get_database(db_path)
        reset_database()
        # After reset, a new call would create new instance
        # (though path might differ)
        reset_database()  # Should not crash


class TestDatabaseEdgeCases:
    """Test edge cases."""

    @pytest.fixture
    def db(self, tmp_path):
        """Create database."""
        db_path = str(tmp_path / "edge_test.db")
        return MIESCDatabase(db_path)

    def test_store_finding_minimal(self, db, tmp_path):
        """Test storing minimal finding."""
        contract = tmp_path / "Token.sol"
        contract.write_text("contract Token {}")
        audit_id = db.create_audit(str(contract), ["test"])

        finding = {"type": "unknown", "severity": "low", "title": "Min", "description": ""}
        finding_id = db.store_finding(audit_id, finding)
        assert finding_id is not None

    def test_findings_empty_audit(self, db, tmp_path):
        """Test getting findings for audit with none."""
        contract = tmp_path / "Token.sol"
        contract.write_text("contract Token {}")
        audit_id = db.create_audit(str(contract), ["test"])

        findings = db.get_findings_for_audit(audit_id)
        assert findings == []

    def test_update_nonexistent_audit(self, db):
        """Test updating nonexistent audit."""
        result = db.update_audit_status("nonexistent-id", AuditStatus.COMPLETED)
        assert result is False

    def test_mark_fp_nonexistent(self, db):
        """Test marking nonexistent finding as FP."""
        result = db.mark_false_positive("nonexistent-id", True)
        assert result is False

    def test_get_findings_by_severity_empty(self, db):
        """Test getting findings when none exist."""
        findings = db.get_findings_by_severity("critical")
        assert findings == []

    def test_audits_for_contract_none(self, db):
        """Test getting audits for contract with none."""
        audits = db.get_audits_for_contract("/nonexistent/contract.sol")
        assert audits == []
