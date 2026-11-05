"""Security score calculation and deduction breakdown."""

from __future__ import annotations

from typing import Any, Dict, List
from backend.severity import SEVERITY_WEIGHTS, Severity


SCORE_DISCLAIMER = (
    "Indicative static-analysis score based on identified vulnerabilities and "
    "coding weaknesses. Not a guarantee that the application is secure."
)


def calculate_security_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate the transparent security score (0-100) based on findings."""
    severity_counts = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
        Severity.INFO.value: 0,
    }

    for f in findings:
        sev = f.get("severity", Severity.INFO.value).upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts[Severity.INFO.value] += 1

    deductions = {
        Severity.CRITICAL.value: severity_counts[Severity.CRITICAL.value] * SEVERITY_WEIGHTS[Severity.CRITICAL.value],
        Severity.HIGH.value: severity_counts[Severity.HIGH.value] * SEVERITY_WEIGHTS[Severity.HIGH.value],
        Severity.MEDIUM.value: severity_counts[Severity.MEDIUM.value] * SEVERITY_WEIGHTS[Severity.MEDIUM.value],
        Severity.LOW.value: severity_counts[Severity.LOW.value] * SEVERITY_WEIGHTS[Severity.LOW.value],
        Severity.INFO.value: 0,
    }

    total_deductions = sum(deductions.values())
    raw_score = 100.0 - total_deductions
    final_score = max(0.0, float(raw_score))

    # Rating classification
    if final_score >= 90:
        grade = "A"
        label = "Excellent Security Posture"
    elif final_score >= 75:
        grade = "B"
        label = "Good (Minor Issues Found)"
    elif final_score >= 60:
        grade = "C"
        label = "Needs Improvement"
    elif final_score >= 40:
        grade = "D"
        label = "Poor (Significant Risks)"
    else:
        grade = "F"
        label = "Critical Risk (Action Required)"

    # Formulate main reasons for deduction
    reasons: List[str] = []
    if severity_counts[Severity.CRITICAL.value] > 0:
        reasons.append(
            f"{severity_counts[Severity.CRITICAL.value]} critical vulnerability(-ies) detected (-{deductions[Severity.CRITICAL.value]} pts)."
        )
    if severity_counts[Severity.HIGH.value] > 0:
        reasons.append(
            f"{severity_counts[Severity.HIGH.value]} high-severity issue(s) detected (-{deductions[Severity.HIGH.value]} pts)."
        )
    if severity_counts[Severity.MEDIUM.value] > 0:
        reasons.append(
            f"{severity_counts[Severity.MEDIUM.value]} medium-severity weakness(es) detected (-{deductions[Severity.MEDIUM.value]} pts)."
        )
    if severity_counts[Severity.LOW.value] > 0:
        reasons.append(
            f"{severity_counts[Severity.LOW.value]} low-severity issue(s) detected (-{deductions[Severity.LOW.value]} pts)."
        )
    if not reasons:
        reasons.append("No security vulnerabilities or code quality issues detected.")

    return {
        "score": round(final_score, 1),
        "grade": grade,
        "rating_label": label,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "deductions": deductions,
        "total_deductions": total_deductions,
        "main_reasons": reasons,
        "disclaimer": SCORE_DISCLAIMER,
    }
