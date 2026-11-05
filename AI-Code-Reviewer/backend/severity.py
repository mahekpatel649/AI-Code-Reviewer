"""Severity classification and mappings for code security findings."""

from __future__ import annotations

from enum import Enum
from typing import Dict, Tuple


class Severity(str, Enum):
    """Normalized severity levels for all scanner findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_WEIGHTS: Dict[str, int] = {
    Severity.CRITICAL.value: 25,
    Severity.HIGH.value: 15,
    Severity.MEDIUM.value: 7,
    Severity.LOW.value: 2,
    Severity.INFO.value: 0,
}

SEVERITY_COLORS: Dict[str, str] = {
    Severity.CRITICAL.value: "#EF4444",  # Red
    Severity.HIGH.value: "#F97316",      # Orange
    Severity.MEDIUM.value: "#F59E0B",    # Yellow/Amber
    Severity.LOW.value: "#3B82F6",       # Blue
    Severity.INFO.value: "#94A3B8",      # Slate / Gray
}

SEVERITY_ORDER: Dict[str, int] = {
    Severity.CRITICAL.value: 1,
    Severity.HIGH.value: 2,
    Severity.MEDIUM.value: 3,
    Severity.LOW.value: 4,
    Severity.INFO.value: 5,
}


def normalize_severity(raw_severity: str) -> str:
    """Normalize scanner severity strings into standard uppercase levels."""
    if not raw_severity:
        return Severity.INFO.value
    clean = raw_severity.strip().upper()
    if clean in ("CRITICAL", "BLOCKER"):
        return Severity.CRITICAL.value
    if clean in ("HIGH", "MAJOR"):
        return Severity.HIGH.value
    if clean in ("MEDIUM", "MODERATE"):
        return Severity.MEDIUM.value
    if clean in ("LOW", "MINOR"):
        return Severity.LOW.value
    return Severity.INFO.value
