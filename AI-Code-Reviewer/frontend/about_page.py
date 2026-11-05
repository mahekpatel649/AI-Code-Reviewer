"""About and Project Architecture Overview page."""

from __future__ import annotations

import streamlit as st


def render_about_page():
    """Render the project documentation and architecture overview."""
    st.markdown("## 🛡️ About AI Code Intelligence & Security Reviewer")
    st.markdown("""
        <p style="color: #CBD5E1; font-size: 1.05rem; line-height: 1.6;">
            <strong>AI Code Intelligence & Security Reviewer</strong> is an enterprise-ready cybersecurity SaaS platform 
            developed for automated code quality auditing, static vulnerability detection, and AI-driven 
            remediation advice.
        </p>
    """, unsafe_allow_html=True)

    # Architecture Overview
    st.markdown("### 🏛️ System Architecture")
    st.markdown("""
        <div style="background: #131C2E; border: 1px solid #2B3D62; border-radius: 12px; padding: 22px; margin-bottom: 20px;">
            <p style="color: #F1F5F9; font-size: 0.98rem; margin-bottom: 12px;">The platform implements a modular multi-tier architecture:</p>
            <ol style="color: #CBD5E1; line-height: 1.8; font-size: 0.95rem;">
                <li><strong style="color: #FFFFFF;">Safe Ingestion Layer:</strong> Decompresses ZIP repositories with strict protection against directory traversal (Zip Slip) and decompression bombs. Excludes binary files and filters sensitive configs.</li>
                <li><strong style="color: #FFFFFF;">Multi-Engine Static Analysis:</strong> Runs <strong>Bandit</strong> for standard Python security benchmarks and a custom <strong>Python AST visitor</strong> for injection vulnerabilities, hardcoded secrets, unsafe execution (<code>eval()</code>, <code>exec()</code>, <code>shell=True</code>), and bare exceptions.</li>
                <li><strong style="color: #FFFFFF;">Deduplication Matrix:</strong> Spatial deduplication (<code>file:line:category</code>) merges overlapping findings into unified, traceable reports.</li>
                <li><strong style="color: #FFFFFF;">Transparent Security Scoring:</strong> Deterministic 0–100 score starting from 100 points with explicit deductions for Critical (-25), High (-15), Medium (-7), and Low (-2) findings.</li>
                <li><strong style="color: #FFFFFF;">AI Intelligence & Remediation Engine:</strong> Generates beginner-friendly explanations, root causes, security impacts, and verified safe replacement code with zero-downtime offline rule fallback.</li>
                <li><strong style="color: #FFFFFF;">Reporting & Persistence:</strong> SQLite relational storage with parameterized SQL queries and instant exports in JSON, CSV, and multi-page PDF format.</li>
            </ol>
        </div>
    """, unsafe_allow_html=True)

    # Supported Categories
    st.markdown("### 🔍 Monitored Security Categories")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("""
            <div style="background: #131C2E; border: 1px solid #2B3D62; border-radius: 10px; padding: 18px;">
                <ul style="color: #CBD5E1; line-height: 1.8; font-size: 0.92rem; margin: 0; padding-left: 18px;">
                    <li>🔑 <strong style="color: #FFFFFF;">Hardcoded Credentials:</strong> Plaintext passwords, API tokens, JWT secrets, database connection strings.</li>
                    <li>💉 <strong style="color: #FFFFFF;">SQL Injection:</strong> Dynamic query formatting, string concatenation, and f-strings inside query executors.</li>
                    <li>⚡ <strong style="color: #FFFFFF;">Dangerous Execution:</strong> <code>eval()</code>, <code>exec()</code>, <code>pickle.loads()</code>, and <code>subprocess</code> with <code>shell=True</code>.</li>
                </ul>
            </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown("""
            <div style="background: #131C2E; border: 1px solid #2B3D62; border-radius: 10px; padding: 18px;">
                <ul style="color: #CBD5E1; line-height: 1.8; font-size: 0.92rem; margin: 0; padding-left: 18px;">
                    <li>🔐 <strong style="color: #FFFFFF;">Insecure Cryptography:</strong> Broken algorithms like MD5/SHA1 and insecure pseudo-random generators.</li>
                    <li>🛡️ <strong style="color: #FFFFFF;">Exception Handling:</strong> Bare <code>except:</code> clauses, empty catch blocks, and silent <code>pass</code> suppression.</li>
                    <li>🧹 <strong style="color: #FFFFFF;">Code Quality:</strong> Production debug breakpoints (<code>breakpoint()</code>, <code>pdb.set_trace()</code>).</li>
                </ul>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)

    # Tech Stack
    st.markdown("### 💻 Technology Stack")
    st.markdown("""
        <div style="background: #131C2E; border: 1px solid #2B3D62; border-radius: 10px; padding: 18px;">
            <ul style="color: #CBD5E1; line-height: 1.8; font-size: 0.92rem; margin: 0; padding-left: 18px;">
                <li><strong style="color: #FFFFFF;">Frontend & UI:</strong> Streamlit, Custom High-Contrast Cybersecurity SaaS Dark CSS, Plotly Express</li>
                <li><strong style="color: #FFFFFF;">Backend & Scanning:</strong> Python 3, Python <code>ast</code>, Bandit</li>
                <li><strong style="color: #FFFFFF;">AI Intelligence:</strong> OpenAI-compatible API client, Prompt Engineering, Structured JSON Validation, Rule-Based Fallback</li>
                <li><strong style="color: #FFFFFF;">Data & Reports:</strong> SQLite (<code>sqlite3</code>), Pandas, <code>fpdf2</code></li>
                <li><strong style="color: #FFFFFF;">Testing:</strong> Pytest</li>
            </ul>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("""
        <div style="background: #131C2E; border: 1px solid #2B3D62; border-radius: 10px; padding: 16px; margin-top: 25px; text-align: center;">
            <span style="color: #CBD5E1; font-size: 0.92rem; font-weight: 500;">
                Built for Student Hackathon 2026 | AI Code Intelligence & Security Reviewer
            </span>
        </div>
    """, unsafe_allow_html=True)
