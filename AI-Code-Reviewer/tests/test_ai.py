"""Unit tests for AI explanation engine and rule-based fallback."""

import os
import pytest
from ai.code_assistant import CodeAssistantEngine
from ai.explanation import AIExplanationEngine, get_rule_fallback


def test_rule_based_fallback_structure():
    """Verify fallback returns all required fields for a known finding."""
    sample_finding = {
        "finding_id": "F001",
        "rule_id": "AST-C001",
        "title": "Use of dangerous eval() function",
        "category": "Dangerous execution",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "file": "calculator.py",
        "line": 10,
        "description": "eval() usage detected",
        "code_snippet": "eval(user_query)",
        "scanner": "Custom AST",
    }

    fallback = get_rule_fallback(sample_finding)
    required_keys = ["explanation", "root_cause", "impact", "suggested_fix", "why_safer", "prevention_advice", "fix_priority"]
    for k in required_keys:
        assert k in fallback
        assert len(fallback[k]) > 0
    assert "ast.literal_eval" in fallback["suggested_fix"]


def test_ai_engine_works_without_api_key(monkeypatch):
    """Verify AIExplanationEngine operates smoothly when AI_API_KEY is unset."""
    monkeypatch.delenv("AI_API_KEY", raising=False)
    engine = AIExplanationEngine()
    assert not engine.is_ai_available()

    finding = {
        "finding_id": "F002",
        "rule_id": "AST-H002",
        "title": "Potential hardcoded secret",
        "category": "Hardcoded credentials",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "file": "settings.py",
        "line": 5,
        "description": "Hardcoded password",
        "code_snippet": "SECRET_KEY = 'secret123'",
        "scanner": "Custom AST",
    }

    rec = engine.explain_finding(finding)
    assert rec is not None
    assert "os.getenv" in rec["suggested_fix"]
    assert "explanation" in rec


def test_code_assistant_offline_queries():
    """Verify offline conversational assistant answers specific query types."""
    assistant = CodeAssistantEngine()
    finding = {
        "finding_id": "F003",
        "rule_id": "AST-C001",
        "title": "eval() usage",
        "category": "Dangerous execution",
        "severity": "CRITICAL",
        "file": "calc.py",
        "line": 4,
        "explanation": "eval() evaluates arbitrary code.",
        "root_cause": "Dynamic evaluation.",
        "impact": "Remote Code Execution.",
        "suggested_fix": "ast.literal_eval(expr)",
        "prevention_advice": "Avoid eval.",
    }

    resp_why = assistant.ask(finding, "Why is this code problematic?")
    assert "Problematic" in resp_why or "eval" in resp_why

    resp_fix = assistant.ask(finding, "How do I fix this?")
    assert "ast.literal_eval" in resp_fix
