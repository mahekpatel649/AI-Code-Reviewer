"""Settings and Configuration Page."""

from __future__ import annotations

import os
import streamlit as st
from ai.explanation import AIExplanationEngine
from database.db import DatabaseManager


def render_settings_page(db: DatabaseManager):
    """Render application settings and AI provider configuration."""
    st.markdown("## ⚙️ Application Settings")
    st.markdown(
        "<p style='color: #CBD5E1; font-size: 1rem;'>"
        "Configure AI endpoints, security scan thresholds, and database storage."
        "</p>",
        unsafe_allow_html=True,
    )

    # 1. AI Configuration
    st.markdown("### 🤖 AI Engine & Provider Configuration")
    st.markdown(
        "<p style='color: #CBD5E1; font-size: 0.92rem; line-height: 1.5;'>"
        "The reviewer connects to any OpenAI-compatible API endpoint (OpenAI, Groq, Ollama, OpenRouter, etc.). "
        "If no API key is provided, the application continues to run seamlessly using its built-in rule-based intelligence engine."
        "</p>",
        unsafe_allow_html=True,
    )

    current_key = os.getenv("AI_API_KEY", "")
    current_model = os.getenv("AI_MODEL", "gpt-4o-mini")
    current_base = os.getenv("AI_BASE_URL", "https://api.openai.com/v1")

    with st.form("ai_config_form"):
        api_key_input = st.text_input(
            "API Key",
            value=current_key,
            type="password",
            help="Your OpenAI, Groq, or OpenRouter API key. Stored only in runtime memory.",
        )
        model_input = st.text_input(
            "Model Identifier",
            value=current_model,
            help="e.g. gpt-4o-mini, gpt-4o, llama-3.3-70b-versatile",
        )
        base_url_input = st.text_input(
            "API Base URL (OpenAI-compatible)",
            value=current_base,
            help="Defaults to https://api.openai.com/v1. For Ollama: http://localhost:11434/v1",
        )

        submit_save = st.form_submit_button("💾 Save Settings", type="primary")
        if submit_save:
            os.environ["AI_API_KEY"] = api_key_input.strip()
            os.environ["AI_MODEL"] = model_input.strip()
            os.environ["AI_BASE_URL"] = base_url_input.strip()
            st.success("Configuration updated successfully for current runtime!")
            st.rerun()

    # Current AI Status
    engine = AIExplanationEngine()
    if engine.is_ai_available():
        st.success(f"🟢 **Live AI Active**: Connected with model `{os.getenv('AI_MODEL')}`.")
    else:
        st.info("🟡 **Rule-Based Fallback Mode Active**: Running without external AI API key. All scans and explanations are fully functional.")

    st.divider()

    # 2. Database Maintenance
    st.markdown("### 🗄️ Database Management")
    st.markdown(f"<p style='color: #F1F5F9;'><strong>Database Path:</strong> <code style='color: #38BDF8;'>{db.db_path}</code></p>", unsafe_allow_html=True)

    metrics = db.get_dashboard_metrics()
    st.markdown(f"<p style='color: #CBD5E1;'>Current Records: <strong style='color: #FFFFFF;'>{metrics['total_projects']}</strong> projects, <strong style='color: #FFFFFF;'>{metrics['total_scans']}</strong> scans.</p>", unsafe_allow_html=True)

    col_db1, col_db2 = st.columns([1.5, 3])
    with col_db1:
        if st.button("🧹 Clear All Scans", help="Deletes all scan records and findings from database."):
            with db.get_connection() as conn:
                conn.execute("DELETE FROM recommendations;")
                conn.execute("DELETE FROM findings;")
                conn.execute("DELETE FROM scans;")
                conn.execute("DELETE FROM projects;")
            st.session_state.pop("active_scan_id", None)
            st.session_state.pop("active_scan_results", None)
            st.success("Database cleared!")
            st.rerun()
