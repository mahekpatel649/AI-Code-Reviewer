"""Unit tests for code scanning, AST rules, and security score."""

import os
import tempfile
from backend.custom_rules import scan_file_with_ast
from backend.scanner import deduplicate_findings, run_bandit, scan_repository
from backend.security_score import calculate_security_score
from backend.severity import Severity, normalize_severity


def test_normalize_severity():
    """Verify severity string normalization."""
    assert normalize_severity("high") == Severity.HIGH.value
    assert normalize_severity("CRITICAL") == Severity.CRITICAL.value
    assert normalize_severity("minor") == Severity.LOW.value
    assert normalize_severity("unknown") == Severity.INFO.value


def test_security_score_calculation():
    """Verify transparent point deduction formula."""
    findings = [
        {"severity": "CRITICAL"},  # -25
        {"severity": "HIGH"},      # -15
        {"severity": "MEDIUM"},    # -7
        {"severity": "LOW"},       # -2
        {"severity": "INFO"},      # -0
    ]
    # 100 - (25 + 15 + 7 + 2) = 51
    result = calculate_security_score(findings)
    assert result["score"] == 51.0
    assert result["grade"] == "D"
    assert result["total_deductions"] == 49


def test_security_score_cannot_be_negative():
    """Verify security score never falls below 0."""
    findings = [{"severity": "CRITICAL"}] * 10  # 10 * 25 = 250 deductions
    result = calculate_security_score(findings)
    assert result["score"] == 0.0
    assert result["grade"] == "F"


def test_ast_scanner_catches_eval_and_credentials():
    """Verify AST visitor detects dangerous eval and hardcoded password."""
    code = """
import os

password = "supersecretpassword123"

def execute_user_code(user_input):
    return eval(user_input)

try:
    x = 1 / 0
except:
    pass
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        f_path = f.name

    try:
        findings = scan_file_with_ast(f_path, rel_path="vulnerable.py")
        rules = [f["rule_id"] for f in findings]
        categories = [f["category"] for f in findings]

        # Should catch eval (AST-C001), password (AST-H002), bare except (AST-M002), empty handler (AST-L002)
        assert "AST-C001" in rules
        assert "AST-H002" in rules
        assert "AST-M002" in rules
        assert "AST-L002" in rules
        assert "Dangerous execution" in categories
        assert "Hardcoded credentials" in categories
    finally:
        if os.path.exists(f_path):
            os.remove(f_path)


def test_full_repository_scan():
    """Test full repository scanning flow producing structured JSON."""
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, "test_app.py")
    with open(file_path, "w") as f:
        f.write("def run():\n    eval('1+1')\n")

    extract_meta = {
        "extract_dir": temp_dir,
        "python_files": ["test_app.py"],
        "unsupported_files": ["app.js"],
    }

    try:
        result = scan_repository(extract_meta, project_name="Test Project")
        assert result["project_name"] == "Test Project"
        assert result["total_files"] == 2
        assert result["scanned_files"] == 1
        assert result["unsupported_files"] == 1
        assert result["total_issues"] >= 1
        assert "findings" in result
        assert isinstance(result["security_score"], float)
    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
