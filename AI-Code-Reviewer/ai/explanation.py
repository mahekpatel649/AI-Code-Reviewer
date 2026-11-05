"""AI-powered security explanation and fix recommendation engine.

Integrates with OpenAI-compatible LLM endpoints with intelligent caching,
strict JSON validation, retry limits, and comprehensive rule-based fallback.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional

from ai.prompts import EXPLANATION_USER_PROMPT, REVIEWER_SYSTEM_PROMPT


# Detailed rule-based fallbacks when AI API is unconfigured or unreachable
FALLBACK_RULES: Dict[str, Dict[str, str]] = {
    # Dangerous Execution
    "AST-C001": {
        "explanation": "The 'eval()' function evaluates arbitrary strings as Python expressions. Any untrusted or external input passed to eval() allows an attacker to execute arbitrary system code.",
        "root_cause": "Dynamic code evaluation via eval() without strict input parsing or mathematical abstraction.",
        "impact": "Remote Code Execution (RCE), complete system compromise, and unauthorized data exfiltration.",
        "suggested_fix": "# Use ast.literal_eval() for safe literal evaluation or math-parsing libraries\nimport ast\n\nsafe_result = ast.literal_eval(user_expression)",
        "why_safer": "ast.literal_eval() only parses literals (strings, numbers, tuples, lists, dicts, booleans, and None) and rejects execution of functions or system calls.",
        "prevention_advice": "Never pass user-controlled input to eval(). Use declarative parsers or mathematical AST visitors for mathematical expressions.",
        "fix_priority": "P0 (Immediate)",
    },
    "AST-C002": {
        "explanation": "The 'exec()' function dynamically executes multi-line Python code. Running untrusted code allows attackers to hijack application behavior or run shell commands.",
        "root_cause": "Arbitrary statement execution on dynamic strings.",
        "impact": "Arbitrary code execution with the full permissions of the running Python process.",
        "suggested_fix": "# Avoid dynamic code generation. Use predefined dispatch dictionaries or functions:\nACTION_DISPATCH = {\n    'start': start_service,\n    'stop': stop_service,\n}\nhandler = ACTION_DISPATCH.get(user_action)",
        "why_safer": "Dispatch tables only invoke explicitly allowed, pre-tested functions without evaluating untrusted strings.",
        "prevention_advice": "Architect applications using object-oriented patterns or function registries instead of dynamic code execution.",
        "fix_priority": "P0 (Immediate)",
    },
    "AST-C003": {
        "explanation": "Python's 'pickle' library is inherently unsafe for untrusted data. Objects can define '__reduce__' methods that execute malicious system commands upon deserialization.",
        "root_cause": "Deserializing untrusted byte streams using Python's native pickle module.",
        "impact": "Critical Remote Code Execution during deserialization before any application checks can run.",
        "suggested_fix": "# Replace pickle with standard JSON or Protocol Buffers:\nimport json\n\ndata = json.loads(untrusted_payload)",
        "why_safer": "JSON parses purely structured data attributes without instantiating arbitrary executable Python classes.",
        "prevention_advice": "Never unpickle data received from untrusted sources, networks, or cookies.",
        "fix_priority": "P0 (Immediate)",
    },
    "AST-C005": {
        "explanation": "Subprocess calls executed with 'shell=True' invoke an underlying system shell (/bin/sh or cmd.exe). Characters like ';', '&&', or '|' in input cause command injection.",
        "root_cause": "Invoking system shell interpreter for subprocess execution with unvalidated arguments.",
        "impact": "Operating system command injection, privilege escalation, and lateral network movement.",
        "suggested_fix": "# Pass arguments as a list with shell=False (default):\nimport subprocess\n\nsubprocess.run(['ping', '-c', '1', validated_host], check=True)",
        "why_safer": "Executing arguments as a list without a shell passes arguments directly to the OS kernel without shell meta-character expansion.",
        "prevention_advice": "Always use shell=False and pass commands as tokenized argument lists.",
        "fix_priority": "P0 (Immediate)",
    },
    # Hardcoded Credentials
    "AST-H002": {
        "explanation": "A secret credential, password, or API key is hardcoded directly in the source code as a plaintext string literal.",
        "root_cause": "Embedding static authentication secrets in version-controlled application files.",
        "impact": "Anyone with read access to the repository, logs, or compiled artifacts can extract secrets and breach backend systems.",
        "suggested_fix": "# Read sensitive credentials from environment variables:\nimport os\n\napi_key = os.getenv('API_KEY')\nif not api_key:\n    raise ValueError('API_KEY environment variable is missing')",
        "why_safer": "Environment variables decouple secrets from code, preventing credential exposure in version control and source archives.",
        "prevention_advice": "Use secret management systems (AWS Secrets Manager, HashiCorp Vault, Doppler) and .env files added to .gitignore.",
        "fix_priority": "P1 (High)",
    },
    "B105": {
        "explanation": "Possible hardcoded password string discovered in source code.",
        "root_cause": "Storing authentication credentials in plaintext code variables.",
        "impact": "Direct compromise of protected services and API endpoints.",
        "suggested_fix": "import os\n\npassword = os.getenv('APP_PASSWORD')",
        "why_safer": "Secrets remain outside source repositories and can be rotated easily without rebuilding code.",
        "prevention_advice": "Use git pre-commit hooks (like detect-secrets) to prevent commits containing credentials.",
        "fix_priority": "P1 (High)",
    },
    # SQL Injection
    "AST-H001": {
        "explanation": "SQL query is formed by concatenating or formatting user input into a SQL string. Attackers can inject SQL syntax to alter queries and bypass authentication or leak databases.",
        "root_cause": "String interpolation in SQL queries rather than parameterized bind parameters.",
        "impact": "SQL Injection leading to unauthorized data readout, database deletion, or authentication bypass.",
        "suggested_fix": "# Use parameterized placeholders (e.g. ? for SQLite, %s for PostgreSQL):\ncursor.execute('SELECT * FROM users WHERE username = ?', (username,))",
        "why_safer": "Parameterized queries separate SQL instructions from user data, rendering injected quotes harmlessly escaped as data.",
        "prevention_advice": "Always use parameterized queries or trusted ORM queries (SQLAlchemy, Django ORM). Never format SQL strings.",
        "fix_priority": "P0 (Immediate)",
    },
    "B608": {
        "explanation": "Possible SQL injection vector detected through formatted query construction.",
        "root_cause": "Dynamic string construction inside SQL execution call.",
        "impact": "Complete database dump or destructive schema modification.",
        "suggested_fix": "cursor.execute('SELECT * FROM accounts WHERE id = ?', (account_id,))",
        "why_safer": "The database driver treats parameter values strictly as literals, eliminating injection.",
        "prevention_advice": "Adopt parameterized query patterns across all data access layers.",
        "fix_priority": "P0 (Immediate)",
    },
    # Insecure Cryptography
    "AST-M001": {
        "explanation": "MD5 or SHA1 is used for cryptographic hashing. These algorithms suffer from known collision vulnerabilities.",
        "root_cause": "Using obsolete hash algorithms for sensitive data or integrity verification.",
        "impact": "Hash collision attacks allowing forged signatures, cracked passwords, or tampered payloads.",
        "suggested_fix": "# Use modern SHA-256 for integrity or bcrypt/argon2 for passwords:\nimport hashlib\n\nhash_digest = hashlib.sha256(data_bytes).hexdigest()",
        "why_safer": "SHA-256 has a 256-bit hash size and currently possesses no practical collision attacks.",
        "prevention_advice": "Use hashlib.sha256/sha512 for file integrity and argon2-cffi or bcrypt for password hashing.",
        "fix_priority": "P2 (Medium)",
    },
    # Exception Handling
    "AST-M002": {
        "explanation": "A bare 'except:' clause intercepts all exceptions, including KeyboardInterrupt (Ctrl+C) and SystemExit.",
        "root_cause": "Catching unspecified exceptions without specifying the target exception class.",
        "impact": "Masks unexpected fatal errors, causes infinite loops, and prevents graceful program shutdown.",
        "suggested_fix": "# Catch specific exceptions or Exception at minimum:\ntry:\n    perform_action()\nexcept SpecificError as e:\n    logger.error('Failed to perform action: %s', e)\n    raise",
        "why_safer": "Permits system-level interrupts to propagate normally while explicitly handling anticipated application faults.",
        "prevention_advice": "Always specify exact exception classes like ValueError, KeyError, or IOError.",
        "fix_priority": "P2 (Medium)",
    },
    "AST-L002": {
        "explanation": "An exception handler contains only 'pass', silently dropping errors without logging or mitigation.",
        "root_cause": "Empty exception block suppressing runtime exceptions.",
        "impact": "Silent software failure leading to corrupted state and difficult debugging in production.",
        "suggested_fix": "# Log the exception or handle appropriately:\nimport logging\n\ntry:\n    do_task()\nexcept Exception as err:\n    logging.warning('Task failed gracefully: %s', err)",
        "why_safer": "Provides audit trails and visibility when operational failures occur.",
        "prevention_advice": "Log all handled exceptions with context or re-raise if unrecoverable.",
        "fix_priority": "P3 (Low)",
    },
}


def get_rule_fallback(finding: Dict[str, Any]) -> Dict[str, str]:
    """Retrieve or synthesize an intelligent rule-based explanation."""
    rule_id = finding.get("rule_id", "")
    category = finding.get("category", "")
    title = finding.get("title", "")
    code = finding.get("code_snippet", "")

    # Exact match on rule ID
    if rule_id in FALLBACK_RULES:
        rec = dict(FALLBACK_RULES[rule_id])
        return rec

    # Prefix match on Bandit
    if rule_id.startswith("B"):
        bandit_alt = f"B{rule_id[1:4]}"
        if bandit_alt in FALLBACK_RULES:
            return dict(FALLBACK_RULES[bandit_alt])

    # Category-based synthesis
    if "credential" in category.lower() or "password" in title.lower():
        return {
            "explanation": f"Detected potential hardcoded secret in '{finding.get('file', 'code')}'.",
            "root_cause": "Secrets placed directly into source code.",
            "impact": "Unauthorized access to confidential data or APIs.",
            "suggested_fix": "import os\n\nsecret = os.getenv('APP_SECRET')",
            "why_safer": "Keeps credentials isolated in environment variables.",
            "prevention_advice": "Use secret management tools and add .env to .gitignore.",
            "fix_priority": "P1 (High)",
        }
    elif "sql" in category.lower() or "sql" in title.lower():
        return {
            "explanation": "Potential SQL injection vulnerability via dynamic query construction.",
            "root_cause": "String interpolation in SQL statements.",
            "impact": "Data breach, unauthorized modification, or query tampering.",
            "suggested_fix": "cursor.execute('SELECT * FROM data WHERE id = ?', (id_val,))",
            "why_safer": "Parameterized queries protect SQL structure from malicious input.",
            "prevention_advice": "Never format or concatenate raw strings into database queries.",
            "fix_priority": "P0 (Immediate)",
        }
    elif "execution" in category.lower():
        return {
            "explanation": f"Potentially dangerous dynamic execution pattern in {title}.",
            "root_cause": "Direct execution of dynamic commands or deserialization.",
            "impact": "Potential arbitrary code execution.",
            "suggested_fix": "# Validate inputs strictly and avoid dynamic evaluation\nsafe_output = sanitize_and_execute(input_val)",
            "why_safer": "Strict validation limits input domain to safe characters.",
            "prevention_advice": "Use static routing or safe parser alternatives.",
            "fix_priority": "P0 (Immediate)",
        }
    elif "exception" in category.lower():
        return {
            "explanation": "Improper exception handling pattern detected.",
            "root_cause": "Broad or empty exception handling clause.",
            "impact": "Suppressed errors make failures invisible and cause subtle bugs.",
            "suggested_fix": "try:\n    risky_operation()\nexcept Exception as err:\n    logger.error('Error: %s', err)",
            "why_safer": "Preserves error visibility and diagnostic traces.",
            "prevention_advice": "Catch specific exceptions and log all caught exceptions.",
            "fix_priority": "P3 (Low)",
        }

    # Default fallback
    return {
        "explanation": f"Security scanner flagged '{title}' at line {finding.get('line', 1)}.",
        "root_cause": f"Violates static security rule {rule_id}.",
        "impact": "Potential security or maintainability weakness.",
        "suggested_fix": f"# Review and refactor {finding.get('file', 'code')}\n# Ensure input validation and standard libraries are utilized.",
        "why_safer": "Following secure coding guidelines eliminates common vulnerabilities.",
        "prevention_advice": "Conduct peer code reviews and run automated static analysis regularly.",
        "fix_priority": "P2 (Medium)",
    }


class AIExplanationEngine:
    """Manages AI-driven vulnerability explanations with caching and robust fallback."""

    def __init__(self):
        self.api_key = os.getenv("AI_API_KEY", "").strip()
        self.provider = os.getenv("AI_PROVIDER", "openai").lower()
        self.model = os.getenv("AI_MODEL", "gpt-4o-mini").strip()
        self.base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").strip()
        self._cache: Dict[str, Dict[str, str]] = {}
        self._client = None

        if self.api_key:
            self._init_client()

    def _init_client(self) -> None:
        """Initialize the OpenAI client safely."""
        try:
            from openai import OpenAI
            self._client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url if self.base_url else None,
                timeout=15.0,
                max_retries=1,
            )
        except Exception:
            self._client = None

    def is_ai_available(self) -> bool:
        """Check whether live AI API is configured and ready."""
        return bool(self.api_key and self._client is not None)

    def _cache_key(self, finding: Dict[str, Any]) -> str:
        """Generate consistent cache key based on rule, file, and code snippet."""
        raw = f"{finding.get('rule_id')}:{finding.get('code_snippet', '')}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def explain_finding(self, finding: Dict[str, Any]) -> Dict[str, str]:
        """Generate AI explanation for a single finding with fallback protection."""
        cache_key = self._cache_key(finding)
        if cache_key in self._cache:
            return self._cache[cache_key]

        # If no client or no key, return rule-based fallback immediately
        if not self.is_ai_available():
            fallback = get_rule_fallback(finding)
            self._cache[cache_key] = fallback
            return fallback

        # Attempt AI completion
        prompt = EXPLANATION_USER_PROMPT.format(
            title=finding.get("title", ""),
            rule_id=finding.get("rule_id", ""),
            category=finding.get("category", ""),
            severity=finding.get("severity", ""),
            confidence=finding.get("confidence", ""),
            file=finding.get("file", ""),
            line=finding.get("line", 1),
            scanner=finding.get("scanner", ""),
            description=finding.get("description", ""),
            code_snippet=finding.get("code_snippet", "")[:1000],  # bounded context
        )

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": REVIEWER_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                response_format={"type": "json_object"} if "gpt" in self.model else None,
            )

            raw_content = response.choices[0].message.content or ""
            # Strip markdown code blocks if wrapped
            clean_json = re.sub(r"^```json\s*|\s*```$", "", raw_content.strip(), flags=re.MULTILINE)
            parsed = json.loads(clean_json)

            required_keys = ["explanation", "root_cause", "impact", "suggested_fix", "prevention_advice"]
            if all(k in parsed for k in required_keys):
                result = {
                    "explanation": str(parsed.get("explanation", "")),
                    "root_cause": str(parsed.get("root_cause", "")),
                    "impact": str(parsed.get("impact", "")),
                    "suggested_fix": str(parsed.get("suggested_fix", "")),
                    "why_safer": str(parsed.get("why_safer", "")),
                    "prevention_advice": str(parsed.get("prevention_advice", "")),
                    "fix_priority": str(parsed.get("fix_priority", "P2 (Medium)")),
                }
                self._cache[cache_key] = result
                return result

            # Incomplete JSON schema
            fallback = get_rule_fallback(finding)
            self._cache[cache_key] = fallback
            return fallback

        except Exception:
            # Fall back transparently on any network, auth, or parsing error
            fallback = get_rule_fallback(finding)
            self._cache[cache_key] = fallback
            return fallback

    def explain_all_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, str]]:
        """Explain a collection of findings, returning finding_id -> recommendation map."""
        recommendations: Dict[str, Dict[str, str]] = {}
        for f in findings:
            f_id = f.get("finding_id", "")
            if f_id:
                recommendations[f_id] = self.explain_finding(f)
        return recommendations
