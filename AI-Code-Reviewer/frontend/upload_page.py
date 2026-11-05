"""Repository Upload and Code Scanning Page."""

from __future__ import annotations

import os
import streamlit as st
from backend.analyzer import RepositoryAnalyzer
from backend.upload import UploadSecurityError
from database.db import DatabaseManager


SAMPLE_VULNERABLE_ZIP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "sample_projects",
    "vulnerable_demo.zip",
)
SAMPLE_CLEAN_ZIP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "sample_projects",
    "clean_demo.zip",
)


def render_upload_page(db: DatabaseManager):
    """Render the upload and scan initiation view."""
    st.markdown("## 📤 New Code Security Scan")
    st.markdown(
        "<p style='color: #CBD5E1; font-size: 1rem;'>"
        "Upload a software repository archive (<code>.zip</code>) or a standalone Python script (<code>.py</code>) "
        "to run multi-engine static security analysis, AST inspection, and AI remediation."
        "</p>",
        unsafe_allow_html=True,
    )

    analyzer = RepositoryAnalyzer(db_manager=db)

    # 1. Project Info Form
    col_input1, col_input2 = st.columns([2, 1])
    with col_input1:
        project_name = st.text_input(
            "Project Name",
            value=st.session_state.get("prefill_project_name", "My Code Project"),
            placeholder="e.g. Fintech Backend API",
            help="Assign a descriptive name for this repository review.",
        )
    with col_input2:
        scan_mode = st.radio(
            "Upload Mode",
            options=["ZIP Repository", "Single Python Script"],
            horizontal=True,
        )

    # 2. File Upload Box or Demo Loader
    st.markdown("### 📁 Select Code Source")

    c_upload, c_demo = st.columns([3, 2])

    uploaded_file = None
    is_single_file = False
    single_filename = "app.py"

    with c_upload:
        if scan_mode == "ZIP Repository":
            uploaded_file = st.file_uploader(
                "Upload Repository ZIP archive",
                type=["zip"],
                help="Max archive size: 50MB. Nested subdirectories supported.",
            )
        else:
            uploaded_file = st.file_uploader(
                "Upload Single Python Script (.py)",
                type=["py"],
                help="Max script size: 2MB.",
            )
            is_single_file = True
            if uploaded_file:
                single_filename = uploaded_file.name

    with c_demo:
        st.markdown("""
            <div style="background: #131C2E; border: 1px solid #2B3D62; border-radius: 10px; padding: 16px 18px;">
                <div style="font-weight: 700; font-size: 0.95rem; color: #FFFFFF; margin-bottom: 6px;">
                    ⚡ Hackathon Instant Demo
                </div>
                <div style="font-size: 0.88rem; color: #CBD5E1; margin-bottom: 14px; line-height: 1.4;">
                    Test the analyzer immediately using pre-configured sample projects:
                </div>
            </div>
        """, unsafe_allow_html=True)

        d_col1, d_col2 = st.columns(2)
        with d_col1:
            if st.button("🔴 Load Vulnerable Demo", use_container_width=True, help="Loads intentionally vulnerable project with hardcoded secrets, SQLi, and eval()"):
                if os.path.exists(SAMPLE_VULNERABLE_ZIP):
                    with open(SAMPLE_VULNERABLE_ZIP, "rb") as f:
                        st.session_state["demo_zip_bytes"] = f.read()
                    st.session_state["prefill_project_name"] = "Vulnerable Demo App"
                    st.session_state["demo_loaded"] = "vulnerable"
                    st.rerun()
                else:
                    st.error("Sample vulnerable zip not found on disk.")

        with d_col2:
            if st.button("🟢 Load Clean Demo", use_container_width=True, help="Loads clean project with env vars, parameterized SQL, and safe parsing"):
                if os.path.exists(SAMPLE_CLEAN_ZIP):
                    with open(SAMPLE_CLEAN_ZIP, "rb") as f:
                        st.session_state["demo_zip_bytes"] = f.read()
                    st.session_state["prefill_project_name"] = "Secure Clean App"
                    st.session_state["demo_loaded"] = "clean"
                    st.rerun()
                else:
                    st.error("Sample clean zip not found on disk.")

    # Check if demo was loaded
    demo_bytes = st.session_state.get("demo_zip_bytes")
    if demo_bytes and not uploaded_file:
        demo_type = st.session_state.get("demo_loaded", "Demo")
        st.success(f"📦 Preloaded: **{st.session_state.get('prefill_project_name')}** ({len(demo_bytes)} bytes ready for scan).")

    # 3. Language Support Information
    st.markdown("""
        <div style="background: #131C2E; border: 1px solid #2B3D62; border-radius: 8px; padding: 14px 18px; margin: 18px 0;">
            <span style="font-weight: 700; color: #38BDF8; font-size: 0.95rem;">ℹ️ Supported Languages:</span>
            <span style="color: #CBD5E1; font-size: 0.9rem; margin-left: 8px; line-height: 1.5;">
                <strong style="color: #FFFFFF;">Python (.py)</strong> undergoes comprehensive AST & Bandit static analysis. Other source formats (.js, .java, .cpp, .html, .css, .sql) are identified and indexed but marked as unsupported for detailed AST analysis.
            </span>
        </div>
    """, unsafe_allow_html=True)

    # 4. Trigger Scan Action
    has_target = bool(uploaded_file or demo_bytes)

    if st.button("🚀 Run Comprehensive Code Scan", type="primary", disabled=not has_target, use_container_width=True):
        if not project_name.strip():
            st.error("Please specify a project name.")
            return

        progress_bar = st.progress(0.0)
        status_text = st.empty()

        def update_progress(msg: str, val: float):
            status_text.markdown(f"⏳ **Status:** {msg}")
            progress_bar.progress(val)

        try:
            # Determine source
            source = uploaded_file.getvalue() if uploaded_file else demo_bytes

            results = analyzer.analyze_repository(
                upload_source=source,
                project_name=project_name.strip(),
                is_single_file=is_single_file,
                single_filename=single_filename,
                progress_callback=update_progress,
            )

            # Store active scan in session
            st.session_state["active_scan_id"] = results["scan_id"]
            st.session_state["active_scan_results"] = results
            # Clean demo cache
            st.session_state.pop("demo_zip_bytes", None)

            st.balloons()
            st.success(f"🎉 **Scan completed!** Analyzed {results['scanned_files']} Python file(s). Found {results['total_issues']} issue(s). Security Score: {results['security_score']}/100 ({results['security_grade']})")

            btn_c1, btn_c2 = st.columns(2)
            with btn_c1:
                if st.button("🔍 Explore Detected Vulnerabilities", type="primary", use_container_width=True):
                    st.session_state["nav_page"] = "Vulnerability Explorer"
                    st.rerun()
            with btn_c2:
                if st.button("📥 Download Security Reports", use_container_width=True):
                    st.session_state["nav_page"] = "Reports"
                    st.rerun()

        except UploadSecurityError as e:
            st.error(f"🛑 Security Rejection: {str(e)}")
        except Exception as e:
            st.error(f"❌ Scan failed due to an unexpected error: {str(e)}")
            st.exception(e)
