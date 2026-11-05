"""Multi-engine code scanner combining Bandit and Custom AST analysis.

Orchestrates static analysis, normalizes results, eliminates duplicates,
and returns structured findings adhering to the review standard.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.custom_rules import scan_file_with_ast
from backend.security_score import calculate_security_score
from backend.severity import Severity, normalize_severity


# Mapping Bandit rule IDs to project security categories
BANDIT_CATEGORY_MAP = {
    # Hardcoded credentials
    "B105": "Hardcoded credentials",
    "B106": "Hardcoded credentials",
    "B107": "Hardcoded credentials",
    # SQL Injection
    "B608": "SQL injection",
    # Dangerous execution & subprocess
    "B102": "Dangerous execution",
    "B307": "Dangerous execution",
    "B601": "Dangerous execution",
    "B602": "Dangerous execution",
    "B603": "Dangerous execution",
    "B604": "Dangerous execution",
    "B605": "Dangerous execution",
    "B606": "Dangerous execution",
    "B607": "Dangerous execution",
    "B301": "Dangerous execution",  # pickle
    "B302": "Dangerous execution",  # marshal
    # Insecure cryptography
    "B303": "Insecure cryptography",  # MD5
    "B304": "Insecure cryptography",  # ciphers
    "B305": "Insecure cryptography",
    "B324": "Insecure cryptography",  # hashlib insecure
    "B311": "Insecure cryptography",  # pseudo-random
    # Exception handling
    "B110": "Exception handling",  # try-except-pass
    "B112": "Exception handling",  # try-except-continue
    # File & Input
    "B108": "File and input security",  # /tmp usage
    "B306": "File and input security",  # mktemp
    "B310": "File and input security",  # urllib
}


def run_bandit(target_dir: str) -> List[Dict[str, Any]]:
    """Run Bandit programmatically via subprocess and parse structured JSON results."""
    # Find python or bandit executable
    bandit_cmd = [sys.executable, "-m", "bandit", "-r", target_dir, "-f", "json", "-q"]

    try:
        proc = subprocess.run(
            bandit_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=45,
        )
        raw_output = proc.stdout.strip()
        if not raw_output:
            return []

        bandit_data = json.loads(raw_output)
        results = bandit_data.get("results", [])

        normalized_findings: List[Dict[str, Any]] = []
        for item in results:
            raw_filename = item.get("filename", "")
            try:
                rel_file = os.path.relpath(raw_filename, target_dir).replace("\\", "/")
            except Exception:
                rel_file = os.path.basename(raw_filename)

            rule_id = item.get("test_id", "BANDIT-GENERIC")
            category = BANDIT_CATEGORY_MAP.get(rule_id, "Security")

            # Map Bandit severity
            sev = normalize_severity(item.get("issue_severity", "MEDIUM"))

            normalized_findings.append({
                "finding_id": f"BND-{uuid.uuid4().hex[:8].upper()}",
                "rule_id": rule_id,
                "title": item.get("issue_text", "Security Vulnerability Detected"),
                "category": category,
                "severity": sev,
                "confidence": item.get("issue_confidence", "MEDIUM").upper(),
                "file": rel_file,
                "line": int(item.get("line_number", 1)),
                "description": f"Bandit finding [{rule_id}]: {item.get('issue_text')}",
                "code_snippet": item.get("code", "").strip(),
                "scanner": "Bandit",
                "status": "Open",
            })

        return normalized_findings

    except subprocess.TimeoutExpired:
        return [{
            "finding_id": f"BND-TIMEOUT-{uuid.uuid4().hex[:6].upper()}",
            "rule_id": "BANDIT-TIMEOUT",
            "title": "Bandit Scanner Timeout",
            "category": "Code quality",
            "severity": Severity.INFO.value,
            "confidence": "HIGH",
            "file": "repository",
            "line": 1,
            "description": "Bandit static scan timed out on target repository.",
            "code_snippet": "",
            "scanner": "Bandit",
            "status": "Open",
        }]
    except Exception as e:
        # If Bandit cannot run (e.g. malformed or path issue), return empty list and let AST handle
        return []


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate findings between Bandit and Custom AST scanner.
    
    If both report an issue at the same file and line with similar category,
    keep Bandit's finding with enhanced description.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    unique_list: List[Dict[str, Any]] = []

    for f in findings:
        # Create a spatial key: file + line
        key = f"{f['file']}:{f['line']}:{f['category']}"
        if key in seen:
            existing = seen[key]
            # If current is Bandit and existing was AST, replace or merge
            if f["scanner"] == "Bandit" and existing["scanner"] != "Bandit":
                # Replace with Bandit
                existing.update(f)
            continue
        seen[key] = f
        unique_list.append(f)

    # Sort findings by severity (Critical first) then file and line
    order_map = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
    unique_list.sort(key=lambda x: (order_map.get(x["severity"], 99), x["file"], x["line"]))
    return unique_list


def scan_repository(
    extract_metadata: Dict[str, Any],
    project_name: str = "Uploaded Project",
) -> Dict[str, Any]:
    """Execute full scan on the extracted repository using Bandit and Custom AST.
    
    Args:
        extract_metadata: Output from backend.upload.extract_repository
        project_name: Human-readable project name
        
    Returns:
        Structured scan results dictionary.
    """
    base_dir = extract_metadata["extract_dir"]
    python_files = extract_metadata.get("python_files", [])
    unsupported_files = extract_metadata.get("unsupported_files", [])

    all_findings: List[Dict[str, Any]] = []

    # 1. Run Bandit if python files exist
    if python_files:
        bandit_findings = run_bandit(base_dir)
        all_findings.extend(bandit_findings)

    # 2. Run Custom AST scanner across all Python files
    for rel_file in python_files:
        full_path = os.path.join(base_dir, rel_file)
        ast_findings = scan_file_with_ast(full_path, rel_path=rel_file)
        all_findings.extend(ast_findings)

    # 3. Deduplicate
    deduped_findings = deduplicate_findings(all_findings)

    # 4. Calculate Security Score
    score_details = calculate_security_score(deduped_findings)

    total_files = len(python_files) + len(unsupported_files)

    return {
        "project_name": project_name,
        "total_files": total_files,
        "scanned_files": len(python_files),
        "unsupported_files": len(unsupported_files),
        "total_issues": len(deduped_findings),
        "security_score": score_details["score"],
        "security_grade": score_details["grade"],
        "security_label": score_details["rating_label"],
        "score_details": score_details,
        "findings": deduped_findings,
    }
