"""Reports page for previewing and downloading JSON, CSV, and PDF audit files."""

from __future__ import annotations

import streamlit as st
import pandas as pd
from backend.report_generator import generate_csv_report, generate_json_report, generate_pdf_report
from database.db import DatabaseManager


def render_reports_page(db: DatabaseManager):
    """Render report generation and export interface."""
    st.markdown("## 📑 Security Audit Reports")
    st.markdown(
        "<p style='color: #CBD5E1; font-size: 1rem;'>"
        "Generate and download compliance-ready security review reports in <strong>JSON</strong>, <strong>CSV</strong>, or <strong>PDF</strong> format."
        "</p>",
        unsafe_allow_html=True,
    )

    scans = db.get_recent_scans(limit=30)
    if not scans:
        st.info("No scan history found. Run a scan first to generate reports.")
        if st.button("🚀 Go to New Code Scan", type="primary"):
            st.session_state["nav_page"] = "New Code Scan"
            st.rerun()
        return

    # Select Scan dropdown
    scan_options = {
        f"{s['project_name']} ({str(s['scan_date'])[:16]}) - Score: {s['security_score']}": s["scan_id"]
        for s in scans
    }

    active_scan_id = st.session_state.get("active_scan_id")
    default_idx = 0
    if active_scan_id:
        for idx, (label, s_id) in enumerate(scan_options.items()):
            if s_id == active_scan_id:
                default_idx = idx
                break

    selected_label = st.selectbox(
        "Select Repository Scan:",
        options=list(scan_options.keys()),
        index=default_idx,
    )
    chosen_scan_id = scan_options[selected_label]

    # Fetch full scan details
    scan_data = db.get_scan_details(chosen_scan_id)
    if not scan_data:
        st.error("Failed to retrieve scan records.")
        return

    # Report Preview Card
    project_slug = scan_data["project_name"].lower().replace(" ", "_").replace("-", "_")
    findings = scan_data.get("findings", [])

    score = scan_data["security_score"]
    score_color = "#34D399" if score >= 85 else "#FBBF24" if score >= 65 else "#F87171"

    st.markdown(f"""
        <div style="background: #131C2E; border: 1px solid #2B3D62; border-radius: 12px; padding: 22px; margin: 18px 0;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px;">
                <div>
                    <h3 style="margin: 0; font-size: 1.35rem; color: #FFFFFF;">📋 Report: {scan_data['project_name']}</h3>
                    <p style="margin: 6px 0 0 0; color: #94A3B8; font-size: 0.9rem;">
                        Scan Date: {str(scan_data['scan_date'])[:19]} | Scan ID: <code style="color: #38BDF8;">{chosen_scan_id[:8]}</code>
                    </p>
                </div>
                <div>
                    <span style="font-size: 2rem; font-weight: 800; color: {score_color}; font-family: 'JetBrains Mono', monospace;">
                        {score}/100
                    </span>
                    <span style="color: #CBD5E1; font-size: 0.88rem; margin-left: 8px;">Indicative Score</span>
                </div>
            </div>
            <div style="margin-top: 18px; display: flex; gap: 24px; color: #F1F5F9; font-size: 0.94rem; flex-wrap: wrap;">
                <div>📁 <strong style="color: #38BDF8;">{scan_data['scanned_files']}</strong> Python Files Scanned</div>
                <div>📄 <strong style="color: #E2E8F0;">{scan_data['unsupported_files']}</strong> Unsupported Source Files</div>
                <div>⚠️ <strong style="color: #F87171;">{len(findings)}</strong> Total Issues Detected</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # 3 Download Buttons
    st.markdown("### 📥 Download Security Audit Artifacts")
    btn_col1, btn_col2, btn_col3 = st.columns(3)

    # 1. JSON Report
    with btn_col1:
        json_data = generate_json_report(scan_data)
        st.download_button(
            label="📄 Download JSON Report",
            data=json_data,
            file_name=f"{project_slug}_security_report.json",
            mime="application/json",
            use_container_width=True,
            help="Download complete raw JSON data structure including all AST metrics and AI fixes.",
        )

    # 2. CSV Findings Report
    with btn_col2:
        csv_data = generate_csv_report(scan_data)
        st.download_button(
            label="📊 Download CSV Findings",
            data=csv_data,
            file_name=f"{project_slug}_vulnerabilities.csv",
            mime="text/csv",
            use_container_width=True,
            help="Download flat CSV table suitable for Excel, Jira imports, or security tracking.",
        )

    # 3. PDF Summary Report
    with btn_col3:
        try:
            pdf_data = generate_pdf_report(scan_data)
            st.download_button(
                label="📑 Download PDF Summary",
                data=pdf_data,
                file_name=f"{project_slug}_security_summary.pdf",
                mime="application/pdf",
                use_container_width=True,
                help="Download executive PDF summary complete with severity charts and remediation cards.",
            )
        except Exception as e:
            st.error(f"PDF creation notice: {e}")

    # Preview Findings Table
    st.markdown("### 🔍 Summary Table of Findings")
    if findings:
        df_display = pd.DataFrame([
            {
                "Severity": f.get("severity"),
                "Rule": f.get("rule_id"),
                "Title": f.get("title"),
                "Category": f.get("category"),
                "File": f"{f.get('file')}:{f.get('line')}",
                "Scanner": f.get("scanner"),
            }
            for f in findings
        ])
        st.dataframe(df_display, use_container_width=True, hide_index=True)
    else:
        st.info("No findings in this scan report.")
