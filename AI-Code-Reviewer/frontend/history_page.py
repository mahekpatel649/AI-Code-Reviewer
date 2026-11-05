"""Scan History management page."""

from __future__ import annotations

import streamlit as st
import pandas as pd
from database.db import DatabaseManager


def render_history_page(db: DatabaseManager):
    """Render historical scan archives and management interface."""
    st.markdown("## 📜 Historical Repository Scans")
    st.markdown(
        "<p style='color: #CBD5E1; font-size: 1rem;'>"
        "Review and inspect prior codebase scans stored in the SQLite database."
        "</p>",
        unsafe_allow_html=True,
    )

    scans = db.get_recent_scans(limit=50)
    if not scans:
        st.info("No prior scan history found in database. Complete a scan to populate history.")
        if st.button("🚀 Run a New Scan", type="primary"):
            st.session_state["nav_page"] = "New Code Scan"
            st.rerun()
        return

    # Filter / Search
    search_query = st.text_input("🔍 Search scans by project name", placeholder="Filter by name...")

    filtered_scans = [
        s for s in scans
        if not search_query or search_query.lower() in s["project_name"].lower()
    ]

    st.markdown(f"<p style='color: #FFFFFF; font-weight: 600;'>Showing {len(filtered_scans)} of {len(scans)} scan record(s):</p>", unsafe_allow_html=True)
    st.markdown("<div style='margin-bottom: 15px;'></div>", unsafe_allow_html=True)

    for s in filtered_scans:
        score = s["security_score"]
        score_color = "#34D399" if score >= 85 else "#FBBF24" if score >= 65 else "#F87171"

        with st.container():
            c1, c2, c3, c4, c5, c6 = st.columns([3, 2, 1.5, 1.5, 2, 2.5])
            with c1:
                st.markdown(f"<span style='font-size: 1.15rem; font-weight: 700; color: #FFFFFF;'>{s['project_name']}</span>", unsafe_allow_html=True)
                st.markdown(f"<span style='color: #94A3B8; font-size: 0.8rem;'>ID: <code>{s['scan_id'][:8]}...</code></span>", unsafe_allow_html=True)
            with c2:
                st.markdown(f"<span style='color: #CBD5E1;'>📅 <strong>Date:</strong><br>{str(s['scan_date'])[:16]}</span>", unsafe_allow_html=True)
            with c3:
                st.markdown(f"<span style='color: #CBD5E1;'>📁 <strong>Files:</strong><br>{s['scanned_files']} / {s['total_files']}</span>", unsafe_allow_html=True)
            with c4:
                st.markdown(f"<span style='color: #CBD5E1;'>⚠️ <strong>Issues:</strong><br>{s['total_issues']}</span>", unsafe_allow_html=True)
            with c5:
                st.markdown(
                    f"<span style='color: #CBD5E1;'>🛡️ <strong>Score:</strong><br><span style='font-size: 1.3rem; font-weight: 800; font-family: monospace; color: {score_color};'>{score}</span>/100</span>",
                    unsafe_allow_html=True,
                )
            with c6:
                act_c1, act_c2 = st.columns(2)
                with act_c1:
                    if st.button("🔍 Explore", key=f"hist_view_{s['scan_id']}", use_container_width=True):
                        st.session_state["active_scan_id"] = s["scan_id"]
                        st.session_state["nav_page"] = "Vulnerability Explorer"
                        st.rerun()
                with act_c2:
                    if st.button("🗑️ Delete", key=f"hist_del_{s['scan_id']}", use_container_width=True):
                        db.delete_scan(s["scan_id"])
                        if st.session_state.get("active_scan_id") == s["scan_id"]:
                            st.session_state.pop("active_scan_id", None)
                        st.success("Scan deleted.")
                        st.rerun()
            st.divider()
