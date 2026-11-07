"""Scan History Database Service (SQLite).

Stores audit reports persistently, enabling users to view past scans,
inspect historical trends, and retrieve previously generated reports.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "trustweaver.db"))


class HistoryDB:
    """Manages SQLite persistence for website security audit reports."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or DB_PATH
        # Ensure parent directory exists
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        """Create scans table and indexes if they do not exist."""
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT UNIQUE NOT NULL,
                    target_url TEXT NOT NULL,
                    scanned_domain TEXT NOT NULL,
                    digital_trust_score INTEGER NOT NULL,
                    trust_grade TEXT NOT NULL,
                    overall_verdict TEXT NOT NULL,
                    phishing_score INTEGER NOT NULL,
                    ssl_score INTEGER NOT NULL,
                    header_score INTEGER NOT NULL,
                    critical_flags_count INTEGER NOT NULL,
                    report_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_target_url ON scans(target_url);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scanned_domain ON scans(scanned_domain);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON scans(created_at DESC);")
            conn.commit()

    def save_scan(self, report: Dict[str, Any]) -> str:
        """Persist a scan report to the database."""
        report_id = report.get("report_id") or f"DTS-{hash(report.get('target_url', '')) & 0xffffffff:08x}"
        target_url = report.get("target_url", "")

        # Extract domain
        from urllib.parse import urlparse
        domain = urlparse(target_url).hostname or target_url

        comp = report.get("component_scores") or {}
        phishing_score = comp.get("phishing_hygiene_score", 0)
        ssl_score = comp.get("ssl_tls_security_score", 0)
        header_score = comp.get("header_hardening_score", 0)
        flags_count = len(report.get("critical_red_flags") or [])

        now_iso = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans (
                    report_id, target_url, scanned_domain, digital_trust_score,
                    trust_grade, overall_verdict, phishing_score, ssl_score,
                    header_score, critical_flags_count, report_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    target_url,
                    domain,
                    report.get("digital_trust_score", 0),
                    report.get("trust_grade", "?"),
                    report.get("overall_verdict", "UNKNOWN"),
                    phishing_score,
                    ssl_score,
                    header_score,
                    flags_count,
                    json.dumps(report),
                    now_iso,
                ),
            )
            conn.commit()

        return report_id

    def get_scan_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a full report by report_id."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT report_json FROM scans WHERE report_id = ?", (report_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["report_json"])
        return None

    def get_recent_scans(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Retrieve recent scan summaries."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT report_id, target_url, scanned_domain, digital_trust_score,
                       trust_grade, overall_verdict, phishing_score, ssl_score,
                       header_score, critical_flags_count, created_at
                FROM scans
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

