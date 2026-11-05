"""AI Code Assistant interactive chat page."""

from __future__ import annotations

import streamlit as st
from typing import Any, Dict, List
from ai.code_assistant import CodeAssistantEngine, PRESET_PROMPTS
from database.db import DatabaseManager


def render_assistant_page(db: DatabaseManager):
    """Render conversational assistant for contextual vulnerability remediations."""
    st.markdown("## 🤖 AI Code Intelligence Assistant")
    st.markdown(
        "<p style='color: #CBD5E1; font-size: 1rem;'>"
        "Ask questions about specific detected vulnerabilities, understand architectural risks, "
        "and get step-by-step guidance on implementing secure refactors."
        "</p>",
        unsafe_allow_html=True,
    )

    assistant = CodeAssistantEngine()

    # Active scan & findings
    active_scan_id = st.session_state.get("active_scan_id")
    if not active_scan_id:
        recent = db.get_recent_scans(limit=1)
        if recent:
            active_scan_id = recent[0]["scan_id"]
            st.session_state["active_scan_id"] = active_scan_id

    findings = []
    if active_scan_id:
        scan_data = db.get_scan_details(active_scan_id)
        if scan_data:
            findings = scan_data.get("findings", [])

    if not findings:
        st.info("No findings currently available to discuss. Please scan a repository first.")
        if st.button("🚀 Run a New Scan", type="primary"):
            st.session_state["nav_page"] = "New Code Scan"
            st.rerun()
        return

    # Finding selection box
    finding_options = {
        f"[{f.get('severity')}] {f.get('title')} ({f.get('file')}:{f.get('line')})": f
        for f in findings
    }

    # Check if a finding was pre-selected from vulnerability page
    preselected = st.session_state.get("assistant_finding")
    default_idx = 0
    if preselected:
        for idx, (label, f_obj) in enumerate(finding_options.items()):
            if f_obj.get("finding_id") == preselected.get("finding_id"):
                default_idx = idx
                break

    selected_label = st.selectbox(
        "🎯 Select Finding to Investigate:",
        options=list(finding_options.keys()),
        index=default_idx,
    )
    selected_finding = finding_options[selected_label]

    # Context Card
    with st.expander("📌 Selected Finding Context Details", expanded=True):
        c1, c2 = st.columns([1, 1])
        with c1:
            st.markdown(f"<p style='color: #FFFFFF; font-size: 0.95rem;'><strong>Rule ID:</strong> <code style='color: #38BDF8;'>{selected_finding.get('rule_id')}</code> | <strong>Severity:</strong> <span style='font-weight: 700; color: #FFFFFF;'>{selected_finding.get('severity')}</span></p>", unsafe_allow_html=True)
            st.markdown(f"<p style='color: #CBD5E1;'><strong>Location:</strong> <span style='color: #38BDF8;'>{selected_finding.get('file')}:{selected_finding.get('line')}</span></p>", unsafe_allow_html=True)
            st.markdown(f"<p style='color: #94A3B8; font-size: 0.85rem;'>Category: {selected_finding.get('category')} | Scanner: {selected_finding.get('scanner')}</p>", unsafe_allow_html=True)
        with c2:
            st.code(selected_finding.get("code_snippet") or "# (No snippet available)", language="python")

    # Chat session initialization
    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []

    # Preset Question Pills
    st.markdown("#### ⚡ Quick Inquiries")
    p_cols = st.columns(len(PRESET_PROMPTS))
    triggered_preset = None
    for i, prompt_text in enumerate(PRESET_PROMPTS):
        with p_cols[i]:
            if st.button(prompt_text, key=f"preset_{i}", use_container_width=True):
                triggered_preset = prompt_text

    st.markdown("<div style='margin-bottom: 12px;'></div>", unsafe_allow_html=True)

    # Render Chat History
    for msg in st.session_state["chat_history"]:
        role = msg.get("role", "user")
        with st.chat_message(role, avatar="🧑‍💻" if role == "user" else "🛡️"):
            st.markdown(msg.get("content", ""))

    # Handle user query (either from preset click or chat input)
    user_query = st.chat_input("Ask a security question about this finding...")
    query_to_process = triggered_preset or user_query

    if query_to_process:
        # Append user message
        st.session_state["chat_history"].append({"role": "user", "content": query_to_process})
        with st.chat_message("user", avatar="🧑‍💻"):
            st.markdown(query_to_process)

        # Generate response
        with st.chat_message("assistant", avatar="🛡️"):
            with st.spinner("Analyzing code vulnerability and generating advice..."):
                response_text = assistant.ask(
                    finding=selected_finding,
                    user_question=query_to_process,
                    chat_history=st.session_state["chat_history"],
                )
                st.markdown(response_text)

        st.session_state["chat_history"].append({"role": "assistant", "content": response_text})

    # Clear chat option
    if st.session_state["chat_history"]:
        if st.button("🧹 Clear Chat History"):
            st.session_state["chat_history"] = []
            st.rerun()
