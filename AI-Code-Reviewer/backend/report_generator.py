"""Multi-format report generator (JSON, CSV, PDF) for security reviews."""

from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fpdf import FPDF
from fpdf.enums import XPos, YPos


class SecurityReviewPDF(FPDF):
    """Custom PDF layout for cybersecurity review summaries."""

    def __init__(self, project_name: str, scan_date: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.project_name = project_name
        self.scan_date = scan_date
        self.set_left_margin(10)
        self.set_right_margin(10)
        self.set_top_margin(10)
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        # Top banner
        self.set_fill_color(15, 23, 42)  # Dark slate
        self.rect(0, 0, 210, 16, "F")
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(255, 255, 255)
        self.set_xy(10, 4)
        self.cell(130, 8, "AI CODE INTELLIGENCE & SECURITY REVIEWER", align="L")
        self.set_xy(140, 4)
        self.cell(60, 8, f"Date: {self.scan_date[:10]}", align="R")
        self.ln(14)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(190, 8, f"Page {self.page_no()}/{{nb}} | Confidential Security Assessment", align="C")


def generate_json_report(scan_data: Dict[str, Any]) -> str:
    """Generate pretty-printed JSON scan report."""
    return json.dumps(scan_data, indent=2, default=str)


def generate_csv_report(scan_data: Dict[str, Any]) -> str:
    """Generate CSV findings report with full remediation details."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "Finding ID",
        "Rule ID",
        "Title",
        "Category",
        "Severity",
        "Confidence",
        "File",
        "Line",
        "Scanner",
        "Status",
        "Explanation",
        "Root Cause",
        "Impact",
        "Suggested Fix",
        "Prevention Advice",
    ])

    findings = scan_data.get("findings", [])
    for f in findings:
        writer.writerow([
            f.get("finding_id", ""),
            f.get("rule_id", ""),
            f.get("title", ""),
            f.get("category", ""),
            f.get("severity", ""),
            f.get("confidence", ""),
            f.get("file", ""),
            f.get("line", ""),
            f.get("scanner", ""),
            f.get("status", "Open"),
            f.get("explanation", ""),
            f.get("root_cause", ""),
            f.get("impact", ""),
            f.get("suggested_fix", ""),
            f.get("prevention_advice", ""),
        ])

    return output.getvalue()


def _sanitize_for_latin1(text: Any) -> str:
    """Replace unicode characters not supported by standard PDF core fonts."""
    if not text:
        return ""
    text_str = str(text)
    replacements = {
        "–": "-", "—": "-", """: '"', """: '"',
        "'": "'", "'": "'", "…": "...", "•": "*",
        "→": "->", "←": "<-", "≥": ">=", "≤": "<=",
        "\t": "    ",
    }
    for orig, rep in replacements.items():
        text_str = text_str.replace(orig, rep)
    # Filter to latin-1
    return text_str.encode("latin-1", errors="replace").decode("latin-1")


def generate_pdf_report(scan_data: Dict[str, Any], output_path: Optional[str] = None) -> bytes:
    """Generate high-quality multi-page PDF security report."""
    project_name = _sanitize_for_latin1(scan_data.get("project_name", "Uploaded Repository"))
    current_time_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scan_date = _sanitize_for_latin1(str(scan_data.get("scan_date", current_time_str)))
    score = scan_data.get("security_score", 100.0)
    findings = scan_data.get("findings", [])

    pdf = SecurityReviewPDF(project_name=project_name, scan_date=scan_date)
    pdf.alias_nb_pages()
    pdf.add_page()

    # Title & Metadata Card
    pdf.set_fill_color(241, 245, 249)
    pdf.rect(10, 20, 190, 36, "F")

    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(15, 23, 42)
    pdf.set_xy(14, 22)
    pdf.cell(130, 7, f"Project: {project_name}")

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.set_xy(14, 30)
    pdf.cell(130, 5, f"Files Scanned: {scan_data.get('scanned_files', 0)} Python | {scan_data.get('unsupported_files', 0)} Other | Total Issues: {len(findings)}")
    pdf.set_xy(14, 36)
    pdf.cell(130, 5, f"Evaluation Time: {scan_date}")

    # Security Score Box
    score_x, score_y = 152, 22
    pdf.set_fill_color(30, 41, 59)
    pdf.rect(score_x, score_y, 44, 32, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_xy(score_x, score_y + 2)
    pdf.cell(44, 5, "SECURITY SCORE", align="C")

    # Colorize based on score
    if score >= 85:
        pdf.set_text_color(52, 211, 153)  # Emerald
    elif score >= 65:
        pdf.set_text_color(251, 191, 36)  # Amber
    else:
        pdf.set_text_color(248, 113, 113)  # Red

    pdf.set_font("Helvetica", "B", 18)
    pdf.set_xy(score_x, score_y + 9)
    pdf.cell(44, 10, f"{score}/100", align="C")

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(203, 213, 225)
    pdf.set_xy(score_x, score_y + 23)
    grade = scan_data.get("security_grade", "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F")
    pdf.cell(44, 5, f"Grade: {grade}", align="C")

    # Severity Summary Metrics Bar
    pdf.set_xy(10, 60)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(190, 7, "Vulnerability Breakdown by Severity")
    pdf.ln(7)

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["INFO"] += 1

    pdf.set_x(10)
    pdf.set_font("Helvetica", "B", 8)
    badge_width = 38
    pdf.set_fill_color(254, 226, 226); pdf.set_text_color(153, 27, 27)
    pdf.cell(badge_width, 7, f"Critical: {sev_counts['CRITICAL']}", border=1, fill=True, align="C")
    pdf.set_fill_color(254, 237, 213); pdf.set_text_color(154, 52, 18)
    pdf.cell(badge_width, 7, f"High: {sev_counts['HIGH']}", border=1, fill=True, align="C")
    pdf.set_fill_color(254, 243, 199); pdf.set_text_color(146, 64, 14)
    pdf.cell(badge_width, 7, f"Medium: {sev_counts['MEDIUM']}", border=1, fill=True, align="C")
    pdf.set_fill_color(224, 231, 255); pdf.set_text_color(30, 58, 138)
    pdf.cell(badge_width, 7, f"Low: {sev_counts['LOW']}", border=1, fill=True, align="C")
    pdf.set_fill_color(241, 245, 249); pdf.set_text_color(71, 85, 105)
    pdf.cell(badge_width, 7, f"Info: {sev_counts['INFO']}", border=1, fill=True, align="C")
    pdf.ln(10)

    # Detailed Findings List
    pdf.set_x(10)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(190, 7, f"Detailed Findings ({len(findings)} Total)")
    pdf.ln(7)

    if not findings:
        pdf.set_x(10)
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(190, 8, "No vulnerabilities or security weaknesses detected! Clean repository.")
        pdf.ln(8)
    else:
        for i, f in enumerate(findings, 1):
            if pdf.get_y() > 230:
                pdf.add_page()

            sev = str(f.get("severity", "MEDIUM")).upper()
            title = _sanitize_for_latin1(f.get("title", "Finding"))
            rule_id = _sanitize_for_latin1(f.get("rule_id", "RULE"))
            file_loc = _sanitize_for_latin1(f"{f.get('file', '')}:{f.get('line', 1)}")

            # Card Header
            pdf.set_x(10)
            pdf.set_fill_color(248, 250, 252)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(190, 6, f"{i}. [{rule_id}] {title} ({sev})", border="LTR", fill=True)
            pdf.ln(6)

            pdf.set_x(10)
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(190, 5, f"   Location: {file_loc} | Scanner: {f.get('scanner', 'Scanner')}", border="LR", fill=True)
            pdf.ln(5)

            # AI Explanation
            explanation = _sanitize_for_latin1(f.get("explanation") or f.get("description", ""))
            if explanation:
                pdf.set_x(10)
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(51, 65, 85)
                pdf.multi_cell(190, 4, f"   Explanation: {explanation}", border="LR", fill=True)

            # Suggested Fix Code Box
            suggested_fix = _sanitize_for_latin1(f.get("suggested_fix", ""))
            if suggested_fix:
                pdf.set_x(10)
                pdf.set_font("Courier", "", 7)
                pdf.set_text_color(15, 23, 42)
                lines = suggested_fix.strip().splitlines()[:6]
                fix_text = "\n".join("      " + l for l in lines)
                pdf.multi_cell(190, 3.5, f"   Suggested Fix:\n{fix_text}", border="LRB", fill=True)
            else:
                pdf.set_x(10)
                pdf.cell(190, 2, "", border="B")
                pdf.ln(2)

            pdf.ln(3)

    # Disclaimer on last page
    if pdf.get_y() > 240:
        pdf.add_page()
    pdf.ln(4)
    pdf.set_x(10)
    pdf.set_fill_color(254, 242, 242)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(153, 27, 27)
    pdf.multi_cell(
        190,
        4,
        "DISCLAIMER: This report is generated by automated static security analysis and AI-assisted code "
        "intelligence. It provides an indicative assessment of potential weaknesses and is not a guarantee of full application "
        "security or lack of vulnerabilities. Always conduct thorough peer reviews and manual penetration testing.",
        border=1,
        fill=True,
    )

    pdf_bytes = bytes(pdf.output())

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes
