# AI Code Intelligence & Security Reviewer 🛡️

An intelligent, full-stack cybersecurity code analysis SaaS platform that audits software repositories, identifies security vulnerabilities and code smells, explains root causes in plain language, calculates deterministic security scores, and generates automated AI-assisted remediation recommendations.

Built for **1–2 Day Student Hackathons** and developer security demonstrations.

---

## 🌟 Key Features

1. **Secure Repository Ingestion & Extraction:**
   - Multi-file ZIP archive upload with defense against Zip Slip directory traversal, zip bombs (decompression limits & file count caps), and binary file exclusion.
   - Single-file Python script (.py) scanning mode.
   - One-click hackathon demonstration presets (`Load Vulnerable Demo` and `Load Clean Demo`).
   - Multi-language awareness: scans Python (.py) and indexes other common languages (.js, .java, .cpp, .c, .html, .css, .sql) without false scanning claims.

2. **Dual-Engine Static Analysis (Bandit + Custom AST):**
   - **Bandit Integration:** Analyzes source trees using Bandit's rules (B105, B608, B307, B602, etc.).
   - **Custom AST Engine:** Python Abstract Syntax Tree visitor detecting dangerous dynamic execution (`eval()`, `exec()`, `pickle.loads()`, `yaml.load()`), subprocess command injection (`shell=True`), hardcoded passwords/tokens, SQL injection formatting, bare exceptions, and debug breakpoints.
   - **Deduplication Engine:** Merges findings to prevent redundant alerts and correlates rule IDs with CWE classifications.

3. **Transparent Security Score (0–100):**
   - Starts at 100 points with deterministic deductions:
     - **Critical (P0):** -25 points
     - **High (P1):** -15 points
     - **Medium (P2):** -7 points
     - **Low (P3):** -2 points
     - **Informational:** 0 points
   - Letter grades: **A** (90–100), **B** (75–89), **C** (60–74), **D** (40–59), **F** (0–39).
   - Clear breakdown of deduction causes and standard security disclaimers.

4. **Contextual AI Intelligence & Zero-Downtime Fallback:**
   - OpenAI-compatible API integration (works with OpenAI, Groq, Ollama, OpenRouter).
   - Explains vulnerabilities in simple language suitable for beginner developers.
   - Identifies programmatic root cause, security impact, prevention advice, and suggested fix code.
   - **Built-in Offline Fallback:** Operates 100% reliably with detailed local rules when no API key is provided.

5. **Before-and-After Code Comparison Interface:**
   - Side-by-side view of original problematic code vs. AI-recommended safe implementation.
   - Copyable code blocks and "Why this fix is safer" rationales.

6. **Interactive AI Code Assistant:**
   - Chat directly about any specific detected finding with pre-configured quick inquiries:
     - *"Why is this code problematic?"*
     - *"How do I fix this issue step-by-step?"*
     - *"What are the potential impacts?"*
     - *"Show alternative secure implementations"*

7. **Multi-Format Export & Audit Reports:**
   - **JSON Report:** Raw machine-readable audit report with full AST telemetry.
   - **CSV Findings:** Flat spreadsheet for Excel, Jira, and bug tracker import.
   - **PDF Summary:** Branded multi-page executive report generated with `fpdf2` containing security score badges, breakdown cards, and disclaimer notes.

8. **Relational SQLite Database & Scan History:**
   - Persistent scan history, project records, findings, and recommendations.
   - Fast retrieval, search, filter, and deletion actions with parameterized SQL queries.

---

## 🏛️ Architecture Overview

```
                                [Uploaded ZIP / Script]
                                          │
                                 (Security Validation)
                         [Zip-Slip & Bomb Protection Layer]
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    ▼                                           ▼
          [Bandit Security Scanner]                 [Custom AST Visitor Engine]
                    │                                           │
                    └─────────────────────┬─────────────────────┘
                                          │
                             (Deduplication & Mapping)
                                          │
                                          ▼
                            [Security Score Calculator]
                                  (100 - Deductions)
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    ▼                                           ▼
      [OpenAI-Compatible LLM Layer]             [Offline Rule-Based Fallback]
                    │                                           │
                    └─────────────────────┬─────────────────────┘
                                          │
                                          ▼
                         [SQLite Relational Database Engine]
                                          │
         ┌────────────────────────────────┼────────────────────────────────┐
         ▼                                ▼                                ▼
[Streamlit SaaS UI]               [AI Code Assistant]              [Report Generator]
- Dark Cybersecurity Theme       - Interactive Chat                - JSON Export
- Plotly Donut & Bar Charts      - Preset Remediation Inquiries    - CSV Findings
- Code Diff Comparison                                             - Branded PDF
```

---

## 💻 Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| **Frontend** | Streamlit + Custom CSS | Cybersecurity SaaS dark interface |
| **Visualizations** | Plotly Express | Interactive donut charts, bar graphs, history trends |
| **Backend Core** | Python 3 | Modular scanner, upload, scoring, and diff services |
| **Static Security** | Bandit | Python security scanner targeting common flaws |
| **AST Inspection** | Python `ast` | Native Abstract Syntax Tree analysis |
| **AI Intelligence** | OpenAI Python SDK | GPT-4o-mini / Groq / Ollama integration |
| **Database** | SQLite (`sqlite3`) | Parameterized relational audit storage |
| **Data Processing** | Pandas | Findings filtering and tabular formatting |
| **PDF Generation** | `fpdf2` | Multi-page executive security audit reports |
| **Testing** | Pytest | Automated unit and integration testing suite |

---

## 📂 Project Directory Structure

```
AI-Code-Reviewer/
│
├── app.py                      # Main Streamlit application entry point
├── requirements.txt            # Python dependencies
├── README.md                   # Comprehensive documentation
├── .env.example                # Sample environment configuration
├── .gitignore                  # Git ignore rules
│
├── frontend/
│   ├── dashboard.py            # Overview dashboard with metrics & Plotly charts
│   ├── upload_page.py          # Repository upload and scanning page
│   ├── history_page.py         # Scan history management
│   ├── vulnerability_page.py   # Finding explorer & before-after code diff
│   ├── assistant_page.py       # Conversational AI Code Assistant
│   ├── reports_page.py         # PDF, CSV, JSON export view
│   ├── settings_page.py        # AI provider & DB configuration
│   ├── about_page.py           # Architecture and documentation
│   └── styles.css              # Dark cybersecurity SaaS styling
│
├── backend/
│   ├── upload.py               # Secure ZIP extraction & path-traversal defense
│   ├── scanner.py              # Multi-engine coordinator (Bandit + AST)
│   ├── custom_rules.py         # AST visitor for injection, credentials, exec
│   ├── analyzer.py             # End-to-end repository review orchestrator
│   ├── severity.py             # Severity levels, weights, and color mappings
│   ├── security_score.py       # Deterministic 0-100 score calculator
│   └── report_generator.py     # JSON, CSV, and PDF report generator
│
├── ai/
│   ├── explanation.py          # AI explanation engine with rule-based fallback
│   ├── code_assistant.py       # Interactive Q&A engine
│   └── prompts.py              # System prompts and templates
│
├── database/
│   ├── db.py                   # Thread-safe SQLite manager
│   └── schema.sql              # Relational database schema with foreign keys
│
├── tests/
│   ├── test_upload.py          # ZIP security & Zip Slip prevention tests
│   ├── test_scanner.py         # Bandit, AST, and scoring tests
│   ├── test_ai.py              # AI engine and offline fallback tests
│   ├── test_database.py        # SQLite persistence and metrics tests
│   └── test_report.py          # JSON, CSV, and PDF export tests
│
├── sample_projects/
│   ├── vulnerable_demo/        # Educational vulnerable demo application
│   ├── vulnerable_demo.zip     # Pre-packaged vulnerable test archive
│   ├── clean_demo/             # Clean reference implementation
│   └── clean_demo.zip          # Pre-packaged secure test archive
│
└── data/
    └── reports/                # Report generation cache
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.9+ (Python 3.10, 3.11, 3.12, 3.13 supported)
- pip

### 1. Clone or Open the Repository
```bash
cd AI-Code-Reviewer
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables (Optional)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Edit `.env` to configure your AI provider (optional):
```ini
AI_PROVIDER=openai
AI_API_KEY=your_openai_or_groq_key_here
AI_MODEL=gpt-4o-mini
AI_BASE_URL=https://api.openai.com/v1
```
> [!NOTE]
> If `AI_API_KEY` is not provided, the application runs automatically in **Rule-Based Fallback Mode** with complete functionality!

### 4. Run the Application
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 🧪 Running Automated Tests

Run the full Pytest test suite:
```bash
pytest tests/ -v
```
All 19 tests will execute, verifying:
- ZIP extraction and Zip-Slip traversal rejection
- Bandit and AST custom rule detection
- Security score calculation and non-negative bounds
- Database insertion, queries, and cascade deletion
- AI fallback generation without API keys
- Multi-format report generation (JSON, CSV, PDF)

---

## 📖 How to Use the Reviewer

### Step 1: Upload or Load a Repository
1. Navigate to **New Code Scan** in the sidebar.
2. Enter a project name (e.g. `Fintech API`).
3. Either:
   - Upload a `.zip` repository from your machine, or
   - Upload a single `.py` file, or
   - Click **Load Vulnerable Demo** or **Load Clean Demo** for an instant hackathon demonstration.
4. Click **Run Comprehensive Code Scan**.

### Step 2: Review Overview Metrics
1. The dashboard displays the real-time security score (0–100), letter grade (A–F), and severity counts.
2. Interactive Plotly charts visualize the vulnerability distribution and affected files.

### Step 3: Explore Vulnerabilities & Code Diff
1. Open **Vulnerability Explorer**.
2. Filter findings by **Severity**, **Category**, or **File**.
3. Expand a finding to inspect:
   - Problematic source line and snippet.
   - Plain-English explanation and root cause.
   - **Code Comparison**: Side-by-side view of original code vs. AI-recommended safe replacement.

### Step 4: Chat with AI Code Assistant
1. Navigate to **AI Code Assistant**.
2. Select any finding from the dropdown.
3. Click preset questions (e.g., *"How do I fix this issue step-by-step?"*) or type custom questions to receive contextual remediation advice.

### Step 5: Export Audit Reports
1. Navigate to **Reports**.
2. Download the audit results in **JSON**, **CSV**, or executive **PDF** format.

---

## 🛡️ Monitored Security Rules Reference

| Rule ID | Category | Severity | Description |
|---|---|---|---|
| `AST-C001` | Dangerous Execution | **CRITICAL** | `eval()` arbitrary code execution |
| `AST-C002` | Dangerous Execution | **CRITICAL** | `exec()` dynamic statement execution |
| `AST-C003` | Dangerous Execution | **CRITICAL** | `pickle.loads()` insecure deserialization |
| `AST-C005` | Dangerous Execution | **CRITICAL** | `subprocess` execution with `shell=True` |
| `AST-H001` | SQL Injection | **HIGH** | Dynamic string formatting in SQL statements |
| `AST-H002` | Hardcoded Credentials | **HIGH** | Plaintext password or API secret in code |
| `B105` | Hardcoded Credentials | **HIGH** | Bandit detected hardcoded password string |
| `B608` | SQL Injection | **HIGH** | Bandit detected SQL injection risk |
| `AST-M001` | Insecure Cryptography | **MEDIUM** | Weak hash function (`hashlib.md5` / `sha1`) |
| `AST-M002` | Exception Handling | **MEDIUM** | Bare `except:` catching system interrupts |
| `AST-L001` | Code Quality | **LOW** | Production debug breakpoint (`breakpoint()`, `pdb`) |
| `AST-L002` | Exception Handling | **LOW** | Empty `except:` handler with `pass` |

---

## 🔮 Future Scope

- **Multi-language static scanning:** Integration with ESLint / Semgrep for JavaScript, TypeScript, and Java.
- **Git Provider Webhooks:** Automatic PR security scanning via GitHub Actions and GitLab CI.
- **Auto-Fix Pull Requests:** One-click branch generation applying verified AI remediations.
- **SAST + DAST Hybrid:** Combining static code analysis with dynamic API fuzz testing.

---

## 👥 Hackathon Team Attribution

- **Project:** AI Code Intelligence & Security Reviewer
- **Event:** Student Hackathon 2026
- **Roles:** Full-Stack Development, Cybersecurity Engineering, AI Prompt Engineering, UI/UX Design.
