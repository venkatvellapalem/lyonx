"""SQLite-backed scan state with resume capability."""
import sqlite3
import json
import time
import os
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    type: str
    severity: str
    url: str
    evidence: str = ""
    plugin: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()


class ScanState:
    """Persistent scan state backed by SQLite. Supports resume."""

    def __init__(self, scan_id: str, base_dir: str):
        self.scan_id = scan_id
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base_dir / "state.db"
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_tables()

    def _init_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT,
                started_at REAL,
                completed_at REAL,
                status TEXT DEFAULT 'running',
                config TEXT DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                type TEXT,
                severity TEXT,
                url TEXT,
                evidence TEXT DEFAULT '',
                plugin TEXT DEFAULT '',
                timestamp REAL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS phase_state (
                scan_id TEXT,
                phase TEXT,
                key TEXT,
                value TEXT,
                PRIMARY KEY (scan_id, phase, key)
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                scan_id TEXT,
                name TEXT,
                path TEXT,
                phase TEXT,
                timestamp REAL,
                PRIMARY KEY (scan_id, name)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
            CREATE INDEX IF NOT EXISTS idx_phase_state_scan ON phase_state(scan_id);
        """)
        self._conn.commit()

    def init_scan(self, target: str, config: dict = None):
        """Initialize a new scan."""
        self._conn.execute(
            "INSERT OR REPLACE INTO scans (id, target, started_at, status, config) VALUES (?, ?, ?, ?, ?)",
            (self.scan_id, target, time.time(), "running", json.dumps(config or {}))
        )
        self._conn.commit()

    def complete_scan(self):
        """Mark scan as completed."""
        self._conn.execute(
            "UPDATE scans SET completed_at = ?, status = 'completed' WHERE id = ?",
            (time.time(), self.scan_id)
        )
        self._conn.commit()

    def interrupt_scan(self):
        """Mark scan as interrupted."""
        self._conn.execute(
            "UPDATE scans SET status = 'interrupted' WHERE id = ?",
            (self.scan_id,)
        )
        self._conn.commit()

    def add_finding(self, finding: Finding):
        """Record a finding."""
        self._conn.execute(
            "INSERT INTO findings (scan_id, type, severity, url, evidence, plugin, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self.scan_id, finding.type, finding.severity, finding.url, finding.evidence, finding.plugin, finding.timestamp)
        )
        self._conn.commit()

    def get_findings(self, severity: str = None, finding_type: str = None) -> list[Finding]:
        """Get findings with optional filters."""
        query = "SELECT * FROM findings WHERE scan_id = ?"
        params = [self.scan_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if finding_type:
            query += " AND type = ?"
            params.append(finding_type)
        rows = self._conn.execute(query, params).fetchall()
        return [Finding(type=r["type"], severity=r["severity"], url=r["url"],
                        evidence=r["evidence"], plugin=r["plugin"], timestamp=r["timestamp"])
                for r in rows]

    def set_state(self, phase: str, key: str, value):
        """Store phase state (for resume)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO phase_state (scan_id, phase, key, value) VALUES (?, ?, ?, ?)",
            (self.scan_id, phase, key, json.dumps(value) if not isinstance(value, str) else value)
        )
        self._conn.commit()

    def get_state(self, phase: str, key: str, default=None):
        """Retrieve phase state."""
        row = self._conn.execute(
            "SELECT value FROM phase_state WHERE scan_id = ? AND phase = ? AND key = ?",
            (self.scan_id, phase, key)
        ).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            return row["value"]

    def add_artifact(self, name: str, path: str, phase: str):
        """Record an output artifact."""
        self._conn.execute(
            "INSERT OR REPLACE INTO artifacts (scan_id, name, path, phase, timestamp) VALUES (?, ?, ?, ?, ?)",
            (self.scan_id, name, path, phase, time.time())
        )
        self._conn.commit()

    def get_artifacts(self, phase: str = None) -> list[dict]:
        """Get artifacts, optionally filtered by phase."""
        if phase:
            rows = self._conn.execute(
                "SELECT * FROM artifacts WHERE scan_id = ? AND phase = ?",
                (self.scan_id, phase)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM artifacts WHERE scan_id = ?",
                (self.scan_id,)
            ).fetchall()
        return [{"name": r["name"], "path": r["path"], "phase": r["phase"]} for r in rows]

    def get_completed_phases(self) -> list[str]:
        """Get list of completed phases (for resume)."""
        rows = self._conn.execute(
            "SELECT DISTINCT phase FROM phase_state WHERE scan_id = ? AND key = '_completed'",
            (self.scan_id,)
        ).fetchall()
        return [r["phase"] for r in rows]

    def mark_phase_complete(self, phase: str):
        """Mark a phase as completed."""
        self.set_state(phase, "_completed", "1")

    def is_phase_complete(self, phase: str) -> bool:
        """Check if a phase was already completed."""
        return self.get_state(phase, "_completed") is not None

    def summary(self) -> dict:
        """Get scan summary."""
        scan = self._conn.execute("SELECT * FROM scans WHERE id = ?", (self.scan_id,)).fetchone()
        findings = self._conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings WHERE scan_id = ? GROUP BY severity",
            (self.scan_id,)
        ).fetchall()
        return {
            "scan_id": self.scan_id,
            "target": scan["target"] if scan else None,
            "status": scan["status"] if scan else None,
            "started_at": scan["started_at"] if scan else None,
            "completed_at": scan["completed_at"] if scan else None,
            "findings": {r["severity"]: r["cnt"] for r in findings},
            "total_findings": sum(r["cnt"] for r in findings),
            "completed_phases": self.get_completed_phases()
        }

    def close(self):
        """Close database connection."""
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
