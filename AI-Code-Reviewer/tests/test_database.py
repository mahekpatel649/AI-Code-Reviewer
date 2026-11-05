"""Unit tests for SQLite database operations."""

import os
import tempfile
import pytest
from database.db import DatabaseManager


@pytest.fixture
def temp_db():
    """Create a temporary database file for test isolation."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = DatabaseManager(db_path=path)
    yield db
    if os.path.exists(path):
        os.remove(path)


def test_db_initialization(temp_db):
    """Test that schema initializes without errors."""
    with temp_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        assert "projects" in tables
        assert "scans" in tables
        assert "findings" in tables
        assert "recommendations" in tables


def test_save_and_retrieve_scan(temp_db):
    """Test saving scan results and retrieving scan details."""
    sample_findings = [
        {
            "finding_id": "test-f1",
            "rule_id": "B105",
            "title": "Possible hardcoded password",
            "category": "Hardcoded credentials",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "file": "app.py",
            "line": 15,
            "description": "Possible hardcoded password detected",
            "code_snippet": "secret_key = 'admin123'",
            "scanner": "Bandit",
            "status": "Open",
        }
    ]

    sample_recommendations = {
        "test-f1": {
            "explanation": "Credentials should not be hardcoded.",
            "root_cause": "Plaintext secret in source code.",
            "impact": "Exposing secrets leads to unauthorized access.",
            "suggested_fix": "secret_key = os.getenv('SECRET_KEY')",
            "prevention_advice": "Use environment variables.",
        }
    }

    scan_id = "test-scan-001"
    temp_db.save_scan_results(
        project_name="Demo Secure App",
        scan_id=scan_id,
        total_files=5,
        scanned_files=4,
        unsupported_files=1,
        total_issues=1,
        security_score=85.0,
        findings=sample_findings,
        recommendations=sample_recommendations,
    )

    details = temp_db.get_scan_details(scan_id)
    assert details is not None
    assert details["project_name"] == "Demo Secure App"
    assert details["total_issues"] == 1
    assert len(details["findings"]) == 1
    f = details["findings"][0]
    assert f["finding_id"] == "test-f1"
    assert f["severity"] == "HIGH"
    assert f["explanation"] == "Credentials should not be hardcoded."
    assert f["suggested_fix"] == "secret_key = os.getenv('SECRET_KEY')"


def test_dashboard_metrics(temp_db):
    """Test aggregated dashboard metrics."""
    metrics = temp_db.get_dashboard_metrics()
    assert metrics["total_projects"] == 0
    assert metrics["total_issues"] == 0

    temp_db.save_scan_results(
        project_name="Project 1",
        scan_id="s1",
        total_files=2,
        scanned_files=2,
        unsupported_files=0,
        total_issues=1,
        security_score=75.0,
        findings=[
            {
                "finding_id": "f1",
                "rule_id": "CRIT01",
                "title": "eval() usage",
                "category": "Dangerous execution",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "file": "calc.py",
                "line": 4,
                "description": "Arbitrary code execution via eval",
                "code_snippet": "eval(user_input)",
                "scanner": "Custom AST",
                "status": "Open",
            }
        ],
    )

    metrics_after = temp_db.get_dashboard_metrics()
    assert metrics_after["total_projects"] == 1
    assert metrics_after["total_issues"] == 1
    assert metrics_after["critical_count"] == 1
