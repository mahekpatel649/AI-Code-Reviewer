"""Database manager for AI Code Intelligence & Security Reviewer.

Handles SQLite operations with parameterized queries, connection management,
and structured object mapping.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional


DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "reviewer.db"
)


class DatabaseManager:
    """Thread-safe SQLite database manager for code reviewer operations."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.getenv("DATABASE_PATH", DEFAULT_DB_PATH)
        # Ensure path is absolute or resolved properly
        self.db_path = os.path.abspath(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for SQLite connections with foreign keys enabled."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Initialize the database schema if tables do not exist."""
        schema_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "schema.sql"
        )
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        with self.get_connection() as conn:
            conn.executescript(schema_sql)

    # ---------------------------------------------------------
    # Project & Scan Management
    # ---------------------------------------------------------
    def get_or_create_project(self, project_name: str) -> str:
        """Find an existing project by name or create a new one."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT project_id FROM projects WHERE project_name = ? LIMIT 1",
                (project_name,),
            )
            row = cursor.fetchone()
            if row:
                return str(row["project_id"])

            project_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO projects (project_id, project_name, created_at) VALUES (?, ?, ?)",
                (project_id, project_name, datetime.now(timezone.utc).isoformat()),
            )
            return project_id

    def save_scan_results(
        self,
        project_name: str,
        scan_id: str,
        total_files: int,
        scanned_files: int,
        unsupported_files: int,
        total_issues: int,
        security_score: float,
        findings: List[Dict[str, Any]],
        recommendations: Optional[Dict[str, Dict[str, Any]]] = None,
        scan_status: str = "COMPLETED",
    ) -> str:
        """Save a complete scan with all its findings and optional recommendations."""
        project_id = self.get_or_create_project(project_name)

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Insert Scan
            cursor.execute(
                """
                INSERT INTO scans (
                    scan_id, project_id, scan_date, total_files, scanned_files,
                    unsupported_files, total_issues, security_score, scan_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    project_id,
                    datetime.now(timezone.utc).isoformat(),
                    total_files,
                    scanned_files,
                    unsupported_files,
                    total_issues,
                    round(float(security_score), 2),
                    scan_status,
                ),
            )

            # Insert Findings
            for f in findings:
                f_id = f.get("finding_id") or str(uuid.uuid4())
                cursor.execute(
                    """
                    INSERT INTO findings (
                        finding_id, scan_id, rule_id, title, category,
                        severity, confidence, file, line, description,
                        code_snippet, scanner, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f_id,
                        scan_id,
                        f.get("rule_id", "UNKNOWN"),
                        f.get("title", "Detected Issue"),
                        f.get("category", "Security"),
                        f.get("severity", "MEDIUM"),
                        f.get("confidence", "MEDIUM"),
                        f.get("file", "unknown"),
                        int(f.get("line", 1)),
                        f.get("description", ""),
                        f.get("code_snippet", ""),
                        f.get("scanner", "Custom"),
                        f.get("status", "Open"),
                    ),
                )

                # Insert Recommendation if available for this finding
                if recommendations and f_id in recommendations:
                    rec = recommendations[f_id]
                    rec_id = str(uuid.uuid4())
                    cursor.execute(
                        """
                        INSERT INTO recommendations (
                            recommendation_id, finding_id, explanation,
                            root_cause, impact, suggested_fix, prevention_advice,
                            created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            rec_id,
                            f_id,
                            rec.get("explanation", ""),
                            rec.get("root_cause", ""),
                            rec.get("impact", ""),
                            rec.get("suggested_fix", ""),
                            rec.get("prevention_advice", ""),
                            datetime.now(timezone.utc).isoformat(),
                        ),
                    )

        return scan_id

    def save_recommendation(
        self,
        finding_id: str,
        explanation: str,
        root_cause: str,
        impact: str,
        suggested_fix: str,
        prevention_advice: str,
    ) -> str:
        """Insert or replace recommendation for an existing finding."""
        rec_id = str(uuid.uuid4())
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO recommendations (
                    recommendation_id, finding_id, explanation,
                    root_cause, impact, suggested_fix, prevention_advice,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    explanation=excluded.explanation,
                    root_cause=excluded.root_cause,
                    impact=excluded.impact,
                    suggested_fix=excluded.suggested_fix,
                    prevention_advice=excluded.prevention_advice
                """,
                (
                    rec_id,
                    finding_id,
                    explanation,
                    root_cause,
                    impact,
                    suggested_fix,
                    prevention_advice,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return rec_id

    # ---------------------------------------------------------
    # Retrieval Methods
    # ---------------------------------------------------------
    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch list of recent scans with project details."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    s.scan_id,
                    p.project_name,
                    s.scan_date,
                    s.total_files,
                    s.scanned_files,
                    s.unsupported_files,
                    s.total_issues,
                    s.security_score,
                    s.scan_status
                FROM scans s
                JOIN projects p ON s.project_id = p.project_id
                ORDER BY s.scan_date DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_scan_details(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Fetch full details of a single scan including all findings and AI fixes."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    s.scan_id,
                    p.project_name,
                    p.project_id,
                    s.scan_date,
                    s.total_files,
                    s.scanned_files,
                    s.unsupported_files,
                    s.total_issues,
                    s.security_score,
                    s.scan_status
                FROM scans s
                JOIN projects p ON s.project_id = p.project_id
                WHERE s.scan_id = ?
                """,
                (scan_id,),
            )
            scan_row = cursor.fetchone()
            if not scan_row:
                return None

            scan_dict = dict(scan_row)

            # Fetch findings with joined recommendations
            cursor.execute(
                """
                SELECT 
                    f.finding_id,
                    f.rule_id,
                    f.title,
                    f.category,
                    f.severity,
                    f.confidence,
                    f.file,
                    f.line,
                    f.description,
                    f.code_snippet,
                    f.scanner,
                    f.status,
                    r.explanation,
                    r.root_cause,
                    r.impact,
                    r.suggested_fix,
                    r.prevention_advice
                FROM findings f
                LEFT JOIN recommendations r ON f.finding_id = r.finding_id
                WHERE f.scan_id = ?
                ORDER BY 
                    CASE f.severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END,
                    f.file ASC,
                    f.line ASC
                """,
                (scan_id,),
            )
            findings_rows = cursor.fetchall()
            scan_dict["findings"] = [dict(r) for r in findings_rows]
            return scan_dict

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Aggregate global statistics for the overview dashboard."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Total projects
            cursor.execute("SELECT COUNT(*) AS count FROM projects")
            total_projects = cursor.fetchone()["count"]

            # Total files analyzed, total issues across all scans
            cursor.execute(
                """
                SELECT 
                    COUNT(*) AS total_scans,
                    COALESCE(SUM(scanned_files), 0) AS total_files,
                    COALESCE(SUM(total_issues), 0) AS total_issues,
                    COALESCE(AVG(security_score), 100.0) AS avg_security_score
                FROM scans
                """
            )
            scan_stats = dict(cursor.fetchone())

            # Severity counts
            cursor.execute(
                """
                SELECT severity, COUNT(*) AS count
                FROM findings
                GROUP BY severity
                """
            )
            severity_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            }
            for row in cursor.fetchall():
                sev = row["severity"].upper()
                if sev in severity_counts:
                    severity_counts[sev] = row["count"]

            # Category counts
            cursor.execute(
                """
                SELECT category, COUNT(*) AS count
                FROM findings
                GROUP BY category
                ORDER BY count DESC
                LIMIT 8
                """
            )
            category_counts = {row["category"]: row["count"] for row in cursor.fetchall()}

            # Latest scan score
            cursor.execute(
                "SELECT security_score FROM scans ORDER BY scan_date DESC LIMIT 1"
            )
            latest_row = cursor.fetchone()
            latest_score = latest_row["security_score"] if latest_row else 100.0

            return {
                "total_projects": total_projects,
                "total_scans": scan_stats["total_scans"],
                "total_files": scan_stats["total_files"],
                "total_issues": scan_stats["total_issues"],
                "avg_security_score": round(scan_stats["avg_security_score"], 1),
                "latest_security_score": round(latest_score, 1),
                "critical_count": severity_counts["CRITICAL"],
                "high_count": severity_counts["HIGH"],
                "severity_counts": severity_counts,
                "category_counts": category_counts,
            }

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and cascade-delete its findings and recommendations."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            return cursor.rowcount > 0

    def delete_project(self, project_id: str) -> bool:
        """Delete a project and cascade-delete all its scans."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM projects WHERE project_id = ?", (project_id,))
            return cursor.rowcount > 0
