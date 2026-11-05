"""Unit tests for multi-format report generator (JSON, CSV, PDF)."""

import json
from backend.report_generator import generate_csv_report, generate_json_report, generate_pdf_report


def test_generate_json_report():
    """Verify JSON report formatting."""
    scan_data = {
        "project_name": "Test App",
        "total_files": 2,
        "scanned_files": 2,
        "unsupported_files": 0,
        "total_issues": 1,
        "security_score": 85.0,
        "findings": [
            {
                "finding_id": "F1",
                "rule_id": "B105",
                "title": "Hardcoded password",
                "severity": "HIGH",
                "category": "Hardcoded credentials",
                "file": "app.py",
                "line": 10,
            }
        ],
    }
    json_str = generate_json_report(scan_data)
    parsed = json.loads(json_str)
    assert parsed["project_name"] == "Test App"
    assert parsed["security_score"] == 85.0
    assert len(parsed["findings"]) == 1


def test_generate_csv_report():
    """Verify CSV report headers and content."""
    scan_data = {
        "findings": [
            {
                "finding_id": "F100",
                "rule_id": "AST-C001",
                "title": "Dangerous eval",
                "category": "Dangerous execution",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "file": "main.py",
                "line": 4,
                "scanner": "Custom AST",
                "status": "Open",
                "explanation": "eval executes arbitrary strings",
                "suggested_fix": "ast.literal_eval()",
            }
        ]
    }
    csv_str = generate_csv_report(scan_data)
    assert "Finding ID,Rule ID,Title" in csv_str
    assert "F100,AST-C001,Dangerous eval" in csv_str
    assert "CRITICAL" in csv_str


def test_generate_pdf_report():
    """Verify PDF report generation produces valid PDF bytes."""
    scan_data = {
        "project_name": "Security Benchmark",
        "scan_date": "2026-11-01 12:00:00",
        "scanned_files": 3,
        "unsupported_files": 1,
        "security_score": 78.5,
        "security_grade": "B",
        "findings": [
            {
                "finding_id": "F1",
                "rule_id": "AST-H001",
                "title": "SQL Injection",
                "severity": "HIGH",
                "category": "SQL injection",
                "file": "db.py",
                "line": 25,
                "scanner": "Custom AST",
                "explanation": "Dynamic SQL construction detected.",
                "suggested_fix": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            }
        ],
    }
    pdf_bytes = generate_pdf_report(scan_data)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    # PDF magic byte signature "%PDF"
    assert pdf_bytes.startswith(b"%PDF")
