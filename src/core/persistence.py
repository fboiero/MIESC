"""
MIESC Persistence Layer - SQLite Storage for Audit Results

Provides persistent storage for audit history, findings, and metrics.
Supports both SQLite (local) and PostgreSQL (production) backends.

Scientific Context:
- Audit trail for compliance (ISO 27001 A.12.4)
- Historical analysis for trend detection
- Data retention for reproducibility

Author: Fernando Boiero
Thesis: Master's in Cyberdefense - UNDEF
Version: 4.1.0
"""

import os
import json
import sqlite3
import logging
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from enum import Enum

logger = logging.getLogger(__name__)


class AuditStatus(Enum):
    """Status of an audit run."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AuditRecord:
    """Record of a completed audit."""
    audit_id: str
    contract_path: str
    contract_hash: str
    status: str
    tools_run: List[str]
    tools_success: List[str]
    tools_failed: List[str]
    total_findings: int
    findings_by_severity: Dict[str, int]
    execution_time_ms: float
    created_at: str
    completed_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FindingRecord:
    """Record of a security finding."""
    finding_id: str
    audit_id: str
    tool: str
    vulnerability_type: str
    severity: str
    confidence: float
    title: str
    description: str
    location: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    swc_id: Optional[str] = None
    false_positive: bool = False
    cross_validated: bool = False
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MIESCDatabase:
    """
    MIESC Persistent Storage Manager.

    Provides SQLite-based storage for:
    - Audit records and history
    - Security findings
    - Tool performance metrics
    - Compliance reports

    Usage:
        db = MIESCDatabase()

        # Store audit
        audit_id = db.create_audit("Token.sol", ["slither", "mythril"])
        db.update_audit_status(audit_id, AuditStatus.COMPLETED, {...})

        # Store findings
        db.store_findings(audit_id, findings_list)

        # Query history
        audits = db.get_audits_for_contract("Token.sol")
        findings = db.get_findings_by_severity("critical")
    """

    # SQL Schema
    SCHEMA = """
    -- Audits table
    CREATE TABLE IF NOT EXISTS audits (
        audit_id TEXT PRIMARY KEY,
        contract_path TEXT NOT NULL,
        contract_hash TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        tools_run TEXT,  -- JSON array
        tools_success TEXT,  -- JSON array
        tools_failed TEXT,  -- JSON array
        total_findings INTEGER DEFAULT 0,
        findings_by_severity TEXT,  -- JSON object
        execution_time_ms REAL,
        created_at TEXT NOT NULL,
        completed_at TEXT,
        metadata TEXT,  -- JSON object
        UNIQUE(contract_hash, created_at)
    );

    -- Findings table
    CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        audit_id TEXT NOT NULL,
        tool TEXT NOT NULL,
        vulnerability_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence REAL DEFAULT 0.5,
        title TEXT NOT NULL,
        description TEXT,
        location TEXT,  -- JSON object
        remediation TEXT,
        cwe_id TEXT,
        swc_id TEXT,
        false_positive INTEGER DEFAULT 0,
        cross_validated INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (audit_id) REFERENCES audits(audit_id)
    );

    -- Metrics table
    CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        metric_type TEXT NOT NULL,
        metric_name TEXT NOT NULL,
        metric_value REAL NOT NULL,
        labels TEXT,  -- JSON object
        recorded_at TEXT NOT NULL
    );

    -- Tool performance table
    CREATE TABLE IF NOT EXISTS tool_performance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_name TEXT NOT NULL,
        execution_time_ms REAL NOT NULL,
        findings_count INTEGER DEFAULT 0,
        success INTEGER DEFAULT 1,
        error_message TEXT,
        contract_hash TEXT,
        recorded_at TEXT NOT NULL
    );

    -- Create indexes
    CREATE INDEX IF NOT EXISTS idx_audits_contract ON audits(contract_path);
    CREATE INDEX IF NOT EXISTS idx_audits_hash ON audits(contract_hash);
    CREATE INDEX IF NOT EXISTS idx_audits_status ON audits(status);
    CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(vulnerability_type);
    CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(metric_type);
    CREATE INDEX IF NOT EXISTS idx_tool_perf_name ON tool_performance(tool_name);
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file.
                     Default: ~/.miesc/miesc.db
        """
        if db_path is None:
            db_dir = Path.home() / ".miesc"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "miesc.db")

        self.db_path = db_path
        self._init_database()
        logger.info(f"MIESC Database initialized: {self.db_path}")

    def _init_database(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.executescript(self.SCHEMA)
            conn.commit()

    @contextmanager
    def _get_connection(self):
        """Get database connection with proper error handling."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _generate_id(self, prefix: str = "") -> str:
        """Generate unique ID."""
        import uuid
        return f"{prefix}{uuid.uuid4().hex[:12]}"

    def _compute_hash(self, content: str) -> str:
        """Compute SHA256 hash of content."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _now_iso(self) -> str:
        """Get current UTC timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # =========================================================================
    # AUDIT OPERATIONS
    # =========================================================================

    def create_audit(
        self,
        contract_path: str,
        tools: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new audit record.

        Args:
            contract_path: Path to the contract file
            tools: List of tools to run
            metadata: Optional metadata

        Returns:
            Audit ID
        """
        audit_id = self._generate_id("audit-")

        # Compute contract hash
        try:
            with open(contract_path, 'r') as f:
                contract_hash = self._compute_hash(f.read())
        except Exception:
            contract_hash = self._compute_hash(contract_path)

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO audits (
                    audit_id, contract_path, contract_hash, status,
                    tools_run, created_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                audit_id,
                contract_path,
                contract_hash,
                AuditStatus.PENDING.value,
                json.dumps(tools),
                self._now_iso(),
                json.dumps(metadata) if metadata else None
            ))
            conn.commit()

        logger.info(f"Created audit {audit_id} for {contract_path}")
        return audit_id

    def update_audit_status(
        self,
        audit_id: str,
        status: AuditStatus,
        results: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Update audit status and results.

        Args:
            audit_id: Audit ID
            status: New status
            results: Optional results data

        Returns:
            True if updated successfully
        """
        with self._get_connection() as conn:
            if results:
                conn.execute("""
                    UPDATE audits SET
                        status = ?,
                        tools_success = ?,
                        tools_failed = ?,
                        total_findings = ?,
                        findings_by_severity = ?,
                        execution_time_ms = ?,
                        completed_at = ?
                    WHERE audit_id = ?
                """, (
                    status.value,
                    json.dumps(results.get('tools_success', [])),
                    json.dumps(results.get('tools_failed', [])),
                    results.get('total_findings', 0),
                    json.dumps(results.get('findings_by_severity', {})),
                    results.get('execution_time_ms', 0),
                    self._now_iso() if status in [AuditStatus.COMPLETED, AuditStatus.FAILED] else None,
                    audit_id
                ))
            else:
                conn.execute("""
                    UPDATE audits SET status = ? WHERE audit_id = ?
                """, (status.value, audit_id))

            conn.commit()
            return conn.total_changes > 0

    def get_audit(self, audit_id: str) -> Optional[AuditRecord]:
        """Get audit by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM audits WHERE audit_id = ?",
                (audit_id,)
            ).fetchone()

            if row:
                return AuditRecord(
                    audit_id=row['audit_id'],
                    contract_path=row['contract_path'],
                    contract_hash=row['contract_hash'],
                    status=row['status'],
                    tools_run=json.loads(row['tools_run'] or '[]'),
                    tools_success=json.loads(row['tools_success'] or '[]'),
                    tools_failed=json.loads(row['tools_failed'] or '[]'),
                    total_findings=row['total_findings'] or 0,
                    findings_by_severity=json.loads(row['findings_by_severity'] or '{}'),
                    execution_time_ms=row['execution_time_ms'] or 0,
                    created_at=row['created_at'],
                    completed_at=row['completed_at'],
                    metadata=json.loads(row['metadata']) if row['metadata'] else None
                )
        return None

    def get_audits_for_contract(
        self,
        contract_path: str,
        limit: int = 10
    ) -> List[AuditRecord]:
        """Get audit history for a contract."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM audits
                WHERE contract_path = ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (contract_path, limit)).fetchall()

            return [
                AuditRecord(
                    audit_id=row['audit_id'],
                    contract_path=row['contract_path'],
                    contract_hash=row['contract_hash'],
                    status=row['status'],
                    tools_run=json.loads(row['tools_run'] or '[]'),
                    tools_success=json.loads(row['tools_success'] or '[]'),
                    tools_failed=json.loads(row['tools_failed'] or '[]'),
                    total_findings=row['total_findings'] or 0,
                    findings_by_severity=json.loads(row['findings_by_severity'] or '{}'),
                    execution_time_ms=row['execution_time_ms'] or 0,
                    created_at=row['created_at'],
                    completed_at=row['completed_at'],
                    metadata=json.loads(row['metadata']) if row['metadata'] else None
                )
                for row in rows
            ]

    def get_recent_audits(self, limit: int = 20) -> List[AuditRecord]:
        """Get most recent audits."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM audits
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,)).fetchall()

            return [
                AuditRecord(
                    audit_id=row['audit_id'],
                    contract_path=row['contract_path'],
                    contract_hash=row['contract_hash'],
                    status=row['status'],
                    tools_run=json.loads(row['tools_run'] or '[]'),
                    tools_success=json.loads(row['tools_success'] or '[]'),
                    tools_failed=json.loads(row['tools_failed'] or '[]'),
                    total_findings=row['total_findings'] or 0,
                    findings_by_severity=json.loads(row['findings_by_severity'] or '{}'),
                    execution_time_ms=row['execution_time_ms'] or 0,
                    created_at=row['created_at'],
                    completed_at=row['completed_at'],
                    metadata=json.loads(row['metadata']) if row['metadata'] else None
                )
                for row in rows
            ]

    # =========================================================================
    # FINDINGS OPERATIONS
    # =========================================================================

    def store_finding(
        self,
        audit_id: str,
        finding: Dict[str, Any]
    ) -> str:
        """
        Store a single finding.

        Args:
            audit_id: Associated audit ID
            finding: Finding data

        Returns:
            Finding ID
        """
        finding_id = self._generate_id("find-")

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO findings (
                    finding_id, audit_id, tool, vulnerability_type, severity,
                    confidence, title, description, location, remediation,
                    cwe_id, swc_id, false_positive, cross_validated, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id,
                audit_id,
                finding.get('tool', 'unknown'),
                finding.get('type', finding.get('vulnerability_type', 'unknown')),
                finding.get('severity', 'unknown'),
                finding.get('confidence', 0.5),
                finding.get('title', 'Untitled'),
                finding.get('description', ''),
                json.dumps(finding.get('location')) if finding.get('location') else None,
                finding.get('remediation'),
                finding.get('cwe_id'),
                finding.get('swc_id'),
                1 if finding.get('false_positive') else 0,
                1 if finding.get('cross_validated') else 0,
                self._now_iso()
            ))
            conn.commit()

        return finding_id

    def store_findings(
        self,
        audit_id: str,
        findings: List[Dict[str, Any]]
    ) -> int:
        """
        Store multiple findings.

        Args:
            audit_id: Associated audit ID
            findings: List of finding data

        Returns:
            Number of findings stored
        """
        count = 0
        for finding in findings:
            try:
                self.store_finding(audit_id, finding)
                count += 1
            except Exception as e:
                logger.warning(f"Failed to store finding: {e}")
        return count

    def get_findings_for_audit(self, audit_id: str) -> List[FindingRecord]:
        """Get all findings for an audit."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM findings WHERE audit_id = ?
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    confidence DESC
            """, (audit_id,)).fetchall()

            return [
                FindingRecord(
                    finding_id=row['finding_id'],
                    audit_id=row['audit_id'],
                    tool=row['tool'],
                    vulnerability_type=row['vulnerability_type'],
                    severity=row['severity'],
                    confidence=row['confidence'],
                    title=row['title'],
                    description=row['description'],
                    location=json.loads(row['location']) if row['location'] else None,
                    remediation=row['remediation'],
                    cwe_id=row['cwe_id'],
                    swc_id=row['swc_id'],
                    false_positive=bool(row['false_positive']),
                    cross_validated=bool(row['cross_validated']),
                    created_at=row['created_at']
                )
                for row in rows
            ]

    def get_findings_by_severity(
        self,
        severity: str,
        limit: int = 100
    ) -> List[FindingRecord]:
        """Get findings filtered by severity."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM findings
                WHERE severity = ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (severity.lower(), limit)).fetchall()

            return [
                FindingRecord(
                    finding_id=row['finding_id'],
                    audit_id=row['audit_id'],
                    tool=row['tool'],
                    vulnerability_type=row['vulnerability_type'],
                    severity=row['severity'],
                    confidence=row['confidence'],
                    title=row['title'],
                    description=row['description'],
                    location=json.loads(row['location']) if row['location'] else None,
                    remediation=row['remediation'],
                    cwe_id=row['cwe_id'],
                    swc_id=row['swc_id'],
                    false_positive=bool(row['false_positive']),
                    cross_validated=bool(row['cross_validated']),
                    created_at=row['created_at']
                )
                for row in rows
            ]

    def mark_false_positive(self, finding_id: str, is_fp: bool = True) -> bool:
        """Mark a finding as false positive."""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE findings SET false_positive = ? WHERE finding_id = ?",
                (1 if is_fp else 0, finding_id)
            )
            conn.commit()
            return conn.total_changes > 0

    # =========================================================================
    # METRICS & STATISTICS
    # =========================================================================

    def record_metric(
        self,
        metric_type: str,
        metric_name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None
    ) -> None:
        """Record a metric value."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO metrics (metric_type, metric_name, metric_value, labels, recorded_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                metric_type,
                metric_name,
                value,
                json.dumps(labels) if labels else None,
                self._now_iso()
            ))
            conn.commit()

    def record_tool_performance(
        self,
        tool_name: str,
        execution_time_ms: float,
        findings_count: int,
        success: bool,
        error_message: Optional[str] = None,
        contract_hash: Optional[str] = None
    ) -> None:
        """Record tool execution performance."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO tool_performance (
                    tool_name, execution_time_ms, findings_count,
                    success, error_message, contract_hash, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                tool_name,
                execution_time_ms,
                findings_count,
                1 if success else 0,
                error_message,
                contract_hash,
                self._now_iso()
            ))
            conn.commit()

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        with self._get_connection() as conn:
            audits_count = conn.execute("SELECT COUNT(*) FROM audits").fetchone()[0]
            findings_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

            severity_dist = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM findings
                GROUP BY severity
            """).fetchall()

            tool_dist = conn.execute("""
                SELECT tool, COUNT(*) as count
                FROM findings
                GROUP BY tool
                ORDER BY count DESC
            """).fetchall()

            return {
                "total_audits": audits_count,
                "total_findings": findings_count,
                "findings_by_severity": {row[0]: row[1] for row in severity_dist},
                "findings_by_tool": {row[0]: row[1] for row in tool_dist},
                "database_path": self.db_path,
            }

    def get_tool_statistics(self, tool_name: Optional[str] = None) -> Dict[str, Any]:
        """Get tool performance statistics."""
        with self._get_connection() as conn:
            if tool_name:
                rows = conn.execute("""
                    SELECT
                        tool_name,
                        AVG(execution_time_ms) as avg_time,
                        MAX(execution_time_ms) as max_time,
                        MIN(execution_time_ms) as min_time,
                        AVG(findings_count) as avg_findings,
                        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes,
                        COUNT(*) as total_runs
                    FROM tool_performance
                    WHERE tool_name = ?
                    GROUP BY tool_name
                """, (tool_name,)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT
                        tool_name,
                        AVG(execution_time_ms) as avg_time,
                        MAX(execution_time_ms) as max_time,
                        MIN(execution_time_ms) as min_time,
                        AVG(findings_count) as avg_findings,
                        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes,
                        COUNT(*) as total_runs
                    FROM tool_performance
                    GROUP BY tool_name
                """).fetchall()

            return {
                row[0]: {
                    "avg_execution_time_ms": round(row[1] or 0, 2),
                    "max_execution_time_ms": row[2] or 0,
                    "min_execution_time_ms": row[3] or 0,
                    "avg_findings": round(row[4] or 0, 2),
                    "success_rate": round((row[5] / row[6]) * 100 if row[6] > 0 else 0, 2),
                    "total_runs": row[6]
                }
                for row in rows
            }

    # =========================================================================
    # CLEANUP & MAINTENANCE
    # =========================================================================

    def cleanup_old_audits(self, days: int = 90) -> int:
        """Remove audits older than specified days."""
        cutoff = datetime.now(timezone.utc).isoformat()
        # Simple approach: delete based on timestamp string comparison
        with self._get_connection() as conn:
            # Get old audit IDs
            old_audits = conn.execute("""
                SELECT audit_id FROM audits
                WHERE datetime(created_at) < datetime('now', ?)
            """, (f'-{days} days',)).fetchall()

            audit_ids = [row[0] for row in old_audits]

            if audit_ids:
                # Delete findings first (foreign key)
                placeholders = ','.join(['?'] * len(audit_ids))
                conn.execute(f"DELETE FROM findings WHERE audit_id IN ({placeholders})", audit_ids)
                conn.execute(f"DELETE FROM audits WHERE audit_id IN ({placeholders})", audit_ids)
                conn.commit()

            return len(audit_ids)

    def vacuum(self) -> None:
        """Optimize database (VACUUM)."""
        with self._get_connection() as conn:
            conn.execute("VACUUM")
        logger.info("Database vacuumed")


# Singleton instance
_db_instance: Optional[MIESCDatabase] = None


def get_database(db_path: Optional[str] = None) -> MIESCDatabase:
    """Get singleton database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = MIESCDatabase(db_path)
    return _db_instance


def reset_database() -> None:
    """Reset database instance (for testing)."""
    global _db_instance
    _db_instance = None
