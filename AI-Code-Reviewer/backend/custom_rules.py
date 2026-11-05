"""Custom AST-based static security and code quality analysis engine.

Inspects Python Abstract Syntax Trees for security patterns, injection flaws,
unsafe execution, weak cryptography, bare exceptions, and credential leaks.
"""

from __future__ import annotations

import ast
import re
import uuid
from typing import Any, Dict, List, Optional


CREDENTIAL_KEYWORD_REGEX = re.compile(
    r"(password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|jwt_secret|private_key|db_password)",
    re.IGNORECASE,
)

SQL_KEYWORDS_REGEX = re.compile(
    r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE)\b",
    re.IGNORECASE,
)


class ASTSecurityVisitor(ast.NodeVisitor):
    """AST Visitor that checks for coding flaws and security risks."""

    def __init__(self, filename: str, source_lines: List[str]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings: List[Dict[str, Any]] = []

    def _get_snippet(self, line_no: int, context: int = 2) -> str:
        """Extract code snippet around line_no (1-indexed)."""
        idx = max(0, line_no - 1)
        start = max(0, idx - context)
        end = min(len(self.source_lines), idx + context + 1)
        return "\n".join(self.source_lines[start:end])

    def _add_finding(
        self,
        rule_id: str,
        title: str,
        category: str,
        severity: str,
        confidence: str,
        line_no: int,
        description: str,
    ) -> None:
        """Helper to create and append a structured finding."""
        snippet = self._get_snippet(line_no)
        self.findings.append({
            "finding_id": f"AST-{uuid.uuid4().hex[:8].upper()}",
            "rule_id": rule_id,
            "title": title,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "file": self.filename,
            "line": line_no,
            "description": description,
            "code_snippet": snippet,
            "scanner": "Custom AST",
            "status": "Open",
        })

    # -------------------------------------------------------------
    # Rule C: Dangerous Execution (eval, exec, pickle, subprocess)
    # -------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        # Check direct functions: eval(), exec(), breakpoint()
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # eval() check
        if func_name == "eval":
            self._add_finding(
                rule_id="AST-C001",
                title="Use of dangerous eval() function",
                category="Dangerous execution",
                severity="CRITICAL",
                confidence="HIGH",
                line_no=node.lineno,
                description="eval() allows dynamic execution of arbitrary code, presenting a major remote code execution risk.",
            )

        # exec() check
        elif func_name == "exec":
            self._add_finding(
                rule_id="AST-C002",
                title="Use of dangerous exec() function",
                category="Dangerous execution",
                severity="CRITICAL",
                confidence="HIGH",
                line_no=node.lineno,
                description="exec() executes arbitrary dynamic statements, which can be abused for command injection.",
            )

        # pickle deserialization check
        elif func_name in ("loads", "load") and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id in ("pickle", "_pickle", "cPickle"):
                self._add_finding(
                    rule_id="AST-C003",
                    title="Insecure deserialization using pickle",
                    category="Dangerous execution",
                    severity="CRITICAL",
                    confidence="HIGH",
                    line_no=node.lineno,
                    description="Unpickling untrusted data can lead to arbitrary code execution. Use safer serializations like JSON.",
                )

        # yaml.load without safe loader
        elif func_name == "load" and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
                has_safe_loader = any(
                    kw.arg == "Loader" and "Safe" in ast.unparse(kw.value)
                    for kw in node.keywords
                )
                if not has_safe_loader:
                    self._add_finding(
                        rule_id="AST-C004",
                        title="Unsafe YAML deserialization",
                        category="Dangerous execution",
                        severity="HIGH",
                        confidence="HIGH",
                        line_no=node.lineno,
                        description="yaml.load() without SafeLoader or yaml.safe_load() can execute arbitrary Python objects.",
                    )

        # subprocess with shell=True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ("Popen", "call", "run", "check_output"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self._add_finding(
                            rule_id="AST-C005",
                            title="Subprocess execution with shell=True",
                            category="Dangerous execution",
                            severity="CRITICAL",
                            confidence="HIGH",
                            line_no=node.lineno,
                            description="Executing commands with shell=True can allow arbitrary OS command injection.",
                        )

        # Insecure cryptography: md5 and sha1
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ("md5", "sha1"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                self._add_finding(
                    rule_id="AST-M001",
                    title=f"Use of weak cryptographic hash function (hashlib.{node.func.attr})",
                    category="Insecure cryptography",
                    severity="MEDIUM",
                    confidence="HIGH",
                    line_no=node.lineno,
                    description=f"{node.func.attr.upper()} is cryptographically broken and vulnerable to collision attacks. Use SHA-256 or bcrypt.",
                )

        # SQL Injection via cursor.execute(...) with string formatting / f-strings
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany"):
            if node.args:
                first_arg = node.args[0]
                is_dynamic = False
                # Check for f-string (JoinedStr)
                if isinstance(first_arg, ast.JoinedStr):
                    is_dynamic = True
                # Check for string concatenation (+)
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Add, ast.Mod)):
                    is_dynamic = True
                # Check for .format() call
                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                    is_dynamic = True

                if is_dynamic:
                    self._add_finding(
                        rule_id="AST-H001",
                        title="Potential SQL Injection via dynamic query formatting",
                        category="SQL injection",
                        severity="HIGH",
                        confidence="HIGH",
                        line_no=node.lineno,
                        description="SQL query is constructed using dynamic string formatting instead of parameterized query arguments (?, %s).",
                    )

        # Code quality: debug breakpoints
        if func_name in ("breakpoint",) or (func_name == "set_trace" and isinstance(node.func, ast.Attribute)):
            self._add_finding(
                rule_id="AST-L001",
                title="Debug breakpoint left in production code",
                category="Code quality",
                severity="LOW",
                confidence="HIGH",
                line_no=node.lineno,
                description="Debugging calls like breakpoint() or pdb.set_trace() must be removed before production deployment.",
            )

        self.generic_visit(node)

    # -------------------------------------------------------------
    # Rule A: Hardcoded credentials
    # -------------------------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if CREDENTIAL_KEYWORD_REGEX.search(var_name):
                    # Check if assigned value is a literal non-empty string
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        secret_val = node.value.value.strip()
                        # Exclude obvious placeholders like "", "TODO", "env", "placeholder"
                        if len(secret_val) >= 4 and not secret_val.startswith(("$", "{", "<", "os.getenv")):
                            self._add_finding(
                                rule_id="AST-H002",
                                title=f"Potential hardcoded secret or credential in '{var_name}'",
                                category="Hardcoded credentials",
                                severity="HIGH",
                                confidence="MEDIUM",
                                line_no=node.lineno,
                                description=f"Variable '{var_name}' is assigned a plaintext string literal. Sensitive credentials should be stored in environment variables.",
                            )
        self.generic_visit(node)

    # -------------------------------------------------------------
    # Rule F: Exception handling (Bare except, empty handlers)
    # -------------------------------------------------------------
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        # Bare except (except:) or except BaseException:
        if node.type is None:
            self._add_finding(
                rule_id="AST-M002",
                title="Bare except clause used",
                category="Exception handling",
                severity="MEDIUM",
                confidence="HIGH",
                line_no=node.lineno,
                description="A bare 'except:' catches all exceptions including SystemExit and KeyboardInterrupt. Catch specific exceptions instead.",
            )
        elif isinstance(node.type, ast.Name) and node.type.id == "BaseException":
            self._add_finding(
                rule_id="AST-M003",
                title="Catching BaseException directly",
                category="Exception handling",
                severity="MEDIUM",
                confidence="HIGH",
                line_no=node.lineno,
                description="Catching BaseException masks severe system events. Catch Exception or more specific exception classes.",
            )

        # Empty exception handler with pass
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self._add_finding(
                rule_id="AST-L002",
                title="Empty exception handler silently ignores errors",
                category="Exception handling",
                severity="LOW",
                confidence="HIGH",
                line_no=node.lineno,
                description="Exception block containing only 'pass' silently suppresses failures, making debugging and auditing difficult.",
            )

        self.generic_visit(node)


def scan_file_with_ast(file_path: str, rel_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Parse and analyze a single Python file using AST.
    
    Gracefully handles SyntaxError or decoding errors without raising exceptions.
    """
    display_path = rel_path or file_path
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return [{
            "finding_id": f"AST-ERR-{uuid.uuid4().hex[:6].upper()}",
            "rule_id": "AST-ERR01",
            "title": "Failed to read source file",
            "category": "Code quality",
            "severity": "INFO",
            "confidence": "HIGH",
            "file": display_path,
            "line": 1,
            "description": f"File could not be opened: {str(e)}",
            "code_snippet": "",
            "scanner": "Custom AST",
            "status": "Open",
        }]

    source_lines = content.splitlines()

    try:
        tree = ast.parse(content, filename=display_path)
    except SyntaxError as e:
        snippet = source_lines[e.lineno - 1] if (e.lineno and e.lineno <= len(source_lines)) else ""
        return [{
            "finding_id": f"AST-SYN-{uuid.uuid4().hex[:6].upper()}",
            "rule_id": "AST-SYNTAX",
            "title": "Python Syntax Error in file",
            "category": "Code quality",
            "severity": "LOW",
            "confidence": "HIGH",
            "file": display_path,
            "line": e.lineno or 1,
            "description": f"Syntax error prevented full AST parsing: {e.msg}",
            "code_snippet": snippet,
            "scanner": "Custom AST",
            "status": "Open",
        }]

    visitor = ASTSecurityVisitor(display_path, source_lines)
    visitor.visit(tree)
    return visitor.findings
