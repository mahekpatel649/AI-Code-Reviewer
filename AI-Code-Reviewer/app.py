"""AI Code Intelligence & Security Reviewer.

Main application entry point orchestrating sidebar navigation, CSS styling,
and multi-page view routing.
"""


from __future__ import annotations

import os
import streamlit as st
from dotenv import load_dotenv

# Load local environment variables if available
load_dotenv()

from database.db import DatabaseManager
from frontend.about_page import render_about_page
from frontend.assistant_page import render_assistant_page
from frontend.dashboard import render_dashboard
from frontend.history_page import render_history_page
from frontend.reports_page import render_reports_page
from frontend.settings_page import render_settings_page
from frontend.upload_page import render_upload_page
from frontend.vulnerability_page import render_vulnerability_page


def load_custom_css():
    """Inject cybersecurity SaaS dark stylesheet into Streamlit."""
    css_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "styles.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            css_content = f.read()
        st.markdown(f"<style>{css_content}</style>", unsafe_allow_html=True)


def main():
    """Configure app and handle primary navigation."""
    st.set_page_config(
        page_title="AI Code Intelligence & Security Reviewer",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Apply custom design theme
    load_custom_css()

    # Initialize SQLite database
    db = DatabaseManager()

    # Session State defaults
    if "nav_page" not in st.session_state:
        st.session_state["nav_page"] = "Dashboard"

    # Sidebar Navigation
    with st.sidebar:
        st.markdown("""
            <div style="padding: 10px 0 15px 0; border-bottom: 1px solid #1E293B; margin-bottom: 15px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.8rem;">🛡️</span>
                    <div>
                        <div style="font-weight: 800; font-size: 1.05rem; color: #FFFFFF; line-height: 1.2;">
                            AI Code Intelligence
                        </div>
                        <div style="font-size: 0.75rem; color: #60A5FA; letter-spacing: 0.05em; text-transform: uppercase;">
                            Security Reviewer
                        </div>
                    </div>
                </div>
            </div>
        """, unsafe_allow_html=True)

        pages = [
            "Dashboard",
            "New Code Scan",
            "Scan History",
            "Vulnerability Explorer",
            "AI Code Assistant",
            "Reports",
            "Settings",
            "About Project",
        ]

        # Sync nav_page with radio
        current_index = pages.index(st.session_state["nav_page"]) if st.session_state["nav_page"] in pages else 0
        selected_page = st.radio(
            "Navigation",
            options=pages,
            index=current_index,
            label_visibility="collapsed",
        )

        if selected_page != st.session_state["nav_page"]:
            st.session_state["nav_page"] = selected_page
            st.rerun()

        st.markdown("<div style='margin-top: 30px;'></div>", unsafe_allow_html=True)

        # Active Scan Info Widget in Sidebar
        active_id = st.session_state.get("active_scan_id")
        if active_id:
            scan_detail = db.get_scan_details(active_id)
            if scan_detail:
                sc = scan_detail["security_score"]
                sc_color = "#10B981" if sc >= 85 else "#F59E0B" if sc >= 65 else "#EF4444"
                st.markdown(f"""
                    <div style="background: #131C2E; border: 1px solid #2B3D62; border-radius: 8px; padding: 12px; margin-bottom: 15px;">
                        <div style="font-size: 0.74rem; color: #94A3B8; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em;">Active Review</div>
                        <div style="font-weight: 700; color: #FFFFFF; font-size: 0.92rem; margin: 4px 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                            {scan_detail['project_name']}
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 6px; font-size: 0.82rem;">
                            <span style="color: #CBD5E1;">{scan_detail['total_issues']} issues</span>
                            <span style="font-weight: 800; color: {sc_color};">Score: {sc}</span>
                        </div>
                    </div>
                """, unsafe_allow_html=True)

        # System Status Indicator
        api_key = os.getenv("AI_API_KEY", "").strip()
        if api_key:
            st.caption("🟢 Live AI Engine: Connected")
        else:
            st.caption("🟡 Rule Fallback Mode: Active")

        st.caption("v1.0.0 | Student Hackathon Edition")

    # Route to selected page
    current_page = st.session_state["nav_page"]

    if current_page == "Dashboard":
        render_dashboard(db)
    elif current_page == "New Code Scan":
        render_upload_page(db)
    elif current_page == "Scan History":
        render_history_page(db)
    elif current_page == "Vulnerability Explorer":
        render_vulnerability_page(db)
    elif current_page == "AI Code Assistant":
        render_assistant_page(db)
    elif current_page == "Reports":
        render_reports_page(db)
    elif current_page == "Settings":
        render_settings_page(db)
    elif current_page == "About Project":
        render_about_page()


if __name__ == "__main__":
    main()
