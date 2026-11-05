"""Overview Dashboard page for AI Code Intelligence & Security Reviewer."""

from __future__ import annotations

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Any, Dict, List
from database.db import DatabaseManager
from backend.severity import SEVERITY_COLORS


def render_dashboard(db: DatabaseManager):
    """Render the main security overview dashboard."""
    st.markdown("""
        <div class="hero-banner">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px;">
                <div>
                    <h2 style="margin: 0; font-size: 1.85rem; color: #FFFFFF;">🛡️ AI Code Intelligence & Security Reviewer</h2>
                    <p style="margin: 6px 0 0 0; color: #CBD5E1; font-size: 1rem; font-weight: 500;">
                        Enterprise-grade automated static analysis, AST vulnerability detection, and AI-powered remediation advice.
                    </p>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    col_btn1, col_btn2 = st.columns([1.2, 4])
    with col_btn1:
        if st.button("🚀 Start New Scan", type="primary", use_container_width=True):
            st.session_state["nav_page"] = "New Code Scan"
            st.rerun()

    # Fetch live data from SQLite
    metrics = db.get_dashboard_metrics()
    recent_scans = db.get_recent_scans(limit=8)

    # Empty State Check
    if metrics["total_scans"] == 0:
        st.info("👋 **Welcome to AI Code Reviewer!** No repositories have been scanned yet. Click **Start New Scan** above or select sample repositories in the scan page to begin.")
        st.markdown("""
            <div style="background: #131C2E; border: 1px dashed #2B3D62; border-radius: 12px; padding: 40px; text-align: center; margin: 30px 0;">
                <h4 style="color: #FFFFFF; margin-bottom: 10px; font-size: 1.2rem;">No Scan Telemetry Available</h4>
                <p style="color: #CBD5E1; font-size: 0.95rem; max-width: 550px; margin: 0 auto 20px auto; line-height: 1.6;">
                    Upload a ZIP repository or individual Python script to identify vulnerabilities, view AI fix recommendations, and calculate real-time security scores.
                </p>
            </div>
        """, unsafe_allow_html=True)
        return

    # 1. Statistics Cards
    st.markdown("### 📊 Security Posture Metrics")
    m1, m2, m3, m4, m5, m6 = st.columns(6)

    with m1:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Repositories</div>
                <div class="metric-value">{metrics['total_projects']}</div>
                <div class="metric-subtext">{metrics['total_scans']} total scan(s)</div>
            </div>
        """, unsafe_allow_html=True)

    with m2:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Files Analyzed</div>
                <div class="metric-value">{metrics['total_files']}</div>
                <div class="metric-subtext">Source files inspected</div>
            </div>
        """, unsafe_allow_html=True)

    with m3:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Total Findings</div>
                <div class="metric-value">{metrics['total_issues']}</div>
                <div class="metric-subtext">Issues flagged</div>
            </div>
        """, unsafe_allow_html=True)

    with m4:
        st.markdown(f"""
            <div class="metric-card" style="border-left: 3px solid #EF4444;">
                <div class="metric-label" style="color: #FFA4A4;">Critical</div>
                <div class="metric-value" style="color: #FF5A5A;">{metrics['critical_count']}</div>
                <div class="metric-subtext">P0 vulnerabilities</div>
            </div>
        """, unsafe_allow_html=True)

    with m5:
        st.markdown(f"""
            <div class="metric-card" style="border-left: 3px solid #F97316;">
                <div class="metric-label" style="color: #FFC085;">High</div>
                <div class="metric-value" style="color: #FF8F3D;">{metrics['high_count']}</div>
                <div class="metric-subtext">High priority risks</div>
            </div>
        """, unsafe_allow_html=True)

    with m6:
        score = metrics['latest_security_score']
        score_color = "#34D399" if score >= 85 else "#FBBF24" if score >= 65 else "#F87171"
        st.markdown(f"""
            <div class="metric-card" style="border-left: 3px solid {score_color};">
                <div class="metric-label">Security Score</div>
                <div class="metric-value" style="color: {score_color};">{score}</div>
                <div class="metric-subtext">Latest score (0-100)</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 25px;'></div>", unsafe_allow_html=True)

    # 2. Charts Section
    c1, c2 = st.columns([1, 1])

    with c1:
        st.markdown("#### 🍩 Findings by Severity")
        sev_data = metrics["severity_counts"]
        df_sev = pd.DataFrame({
            "Severity": list(sev_data.keys()),
            "Count": list(sev_data.values()),
        })
        color_map = {
            "CRITICAL": "#EF4444",
            "HIGH": "#F97316",
            "MEDIUM": "#F59E0B",
            "LOW": "#38BDF8",
            "INFO": "#94A3B8",
        }
        fig_donut = px.pie(
            df_sev,
            names="Severity",
            values="Count",
            hole=0.55,
            color="Severity",
            color_discrete_map=color_map,
        )
        fig_donut.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#F1F5F9", size=12),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5, font=dict(color="#E2E8F0")),
            margin=dict(t=10, b=10, l=10, r=10),
            height=280,
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with c2:
        st.markdown("#### 📂 Top Issue Categories")
        cat_data = metrics.get("category_counts", {})
        if cat_data:
            df_cat = pd.DataFrame({
                "Category": list(cat_data.keys()),
                "Findings": list(cat_data.values()),
            }).sort_values(by="Findings", ascending=True)

            fig_bar = px.bar(
                df_cat,
                x="Findings",
                y="Category",
                orientation="h",
                color="Findings",
                color_continuous_scale="Tealgrn",
            )
            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#F1F5F9", size=12),
                margin=dict(t=10, b=10, l=10, r=10),
                height=280,
                coloraxis_showscale=False,
                xaxis=dict(showgrid=True, gridcolor="#22314E", tickfont=dict(color="#CBD5E1")),
                yaxis=dict(showgrid=False, tickfont=dict(color="#CBD5E1")),
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.caption("No categories recorded.")

    # 3. Scan History Trend
    if len(recent_scans) > 1:
        st.markdown("#### 📈 Scan Security Score Trend")
        df_scans = pd.DataFrame(recent_scans).sort_values(by="scan_date", ascending=True)
        fig_trend = px.line(
            df_scans,
            x="scan_date",
            y="security_score",
            markers=True,
            title="Score Trajectory Over Scans",
            labels={"scan_date": "Scan Timestamp", "security_score": "Security Score (0-100)"},
        )
        fig_trend.update_traces(line_color="#38BDF8", line_width=3, marker=dict(size=8, color="#60A5FA"))
        fig_trend.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#F1F5F9"),
            yaxis=dict(range=[0, 105], showgrid=True, gridcolor="#22314E", tickfont=dict(color="#CBD5E1")),
            xaxis=dict(showgrid=False, tickfont=dict(color="#CBD5E1")),
            margin=dict(t=30, b=10, l=10, r=10),
            height=240,
        )
        st.plotly_chart(fig_trend, use_container_width=True)

    # 4. Recent Scans Table
    st.markdown("### 🕒 Recent Repository Scans")
    if recent_scans:
        for scan in recent_scans:
            s_col1, s_col2, s_col3, s_col4, s_col5, s_col6 = st.columns([3, 2, 1.5, 1.5, 2, 2])
            with s_col1:
                st.markdown(f"<span style='color: #FFFFFF; font-weight: 700; font-size: 1.05rem;'>{scan['project_name']}</span>", unsafe_allow_html=True)
            with s_col2:
                st.markdown(f"<span style='color: #94A3B8; font-size: 0.88rem;'>{str(scan['scan_date'])[:16]}</span>", unsafe_allow_html=True)
            with s_col3:
                st.markdown(f"<span style='color: #CBD5E1;'>📁 {scan['scanned_files']} files</span>", unsafe_allow_html=True)
            with s_col4:
                st.markdown(f"<span style='color: #CBD5E1;'>⚠️ {scan['total_issues']} issues</span>", unsafe_allow_html=True)
            with s_col5:
                sc = scan['security_score']
                badge_style = "color: #34D399" if sc >= 85 else "color: #FBBF24" if sc >= 65 else "color: #F87171"
                st.markdown(f"<span style='font-weight: 800; font-size: 1rem; {badge_style}'>Score: {sc}</span>", unsafe_allow_html=True)
            with s_col6:
                if st.button("🔍 View Details", key=f"view_{scan['scan_id']}", use_container_width=True):
                    st.session_state["active_scan_id"] = scan["scan_id"]
                    st.session_state["nav_page"] = "Vulnerability Explorer"
                    st.rerun()
            st.divider()
