"""VULNERABLE DEMO APPLICATION.

WARNING: This file contains intentional security vulnerabilities created solely
for educational, demonstration, and security benchmarking purposes.
DO NOT USE THIS CODE IN PRODUCTION.
"""

import hashlib
import os
import subprocess

# 1. HARDCODED CREDENTIALS (VULNERABILITY: AST-H002, Bandit B105)
API_SECRET_KEY = "sk_live_9923847291837491823749"
DATABASE_PASSWORD = "SuperSecretAdminPassword2026!"


def calculate_user_expression(user_math_string: str):
    """VULNERABILITY: Arbitrary code execution via eval() (AST-C001, Bandit B307)."""
    print(f"DEBUG: evaluating user string: {user_math_string}")
    # Dangerous: arbitrary string evaluated directly
    result = eval(user_math_string)
    return result


def execute_system_backup(directory_path: str):
    """VULNERABILITY: Command injection via shell=True (AST-C005, Bandit B602)."""
    # Dangerous shell=True with unvalidated string formatting
    cmd = f"ls -la {directory_path}"
    subprocess.call(cmd, shell=True)


def hash_user_password(raw_password: str) -> str:
    """VULNERABILITY: Weak cryptographic hash MD5 (AST-M001, Bandit B303)."""
    # Dangerous: MD5 is vulnerable to collision attacks
    return hashlib.md5(raw_password.encode("utf-8")).hexdigest()


def process_payment_records(records: list):
    """VULNERABILITY: Bare except & silently ignored errors (AST-M002, AST-L002, Bandit B110)."""
    try:
        for r in records:
            amount = float(r["amount"])
            print(f"Processed ${amount}")
    except:
        # Silently suppresses any error, masking bugs or malicious tampering
        pass


if __name__ == "__main__":
    print("Vulnerable Demo Project Loaded.")
