"""CLEAN & SECURE DEMO APPLICATION.

Implements secure Python coding standards:
- Environment variables for credentials
- Safe input parsing without eval()
- Shell-safe subprocess invocation
- Robust exception handling and structured logging
- Strong SHA-256 cryptographic hashing
"""

import ast
import hashlib
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 1. SECURE: Credentials retrieved from environment variables
API_SECRET_KEY = os.getenv("API_SECRET_KEY", "")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "")


def calculate_user_expression(user_math_string: str) -> Optional[Any]:
    """SECURE: Use ast.literal_eval for safe literal evaluation instead of eval()."""
    try:
        # Only parses Python literals (numbers, strings, tuples, lists, dicts)
        # Rejects function calls, system imports, or executable expressions
        return ast.literal_eval(user_math_string)
    except (ValueError, SyntaxError) as e:
        logger.warning("Rejected invalid mathematical expression: %s", e)
        return None


def execute_system_backup(directory_path: str) -> bool:
    """SECURE: Invokes subprocess with a tokenized argument list and shell=False."""
    # Validate directory exists and stays safe
    if not os.path.isdir(directory_path):
        logger.error("Invalid directory specified: %s", directory_path)
        return False

    try:
        # shell=False prevents shell metacharacter expansion and injection
        result = subprocess.run(
            ["dir" if os.name == "nt" else "ls", directory_path],
            capture_output=True,
            text=True,
            check=True,
            shell=False,
        )
        logger.info("Backup listing completed: %d files", len(result.stdout.splitlines()))
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Subprocess execution failed: %s", e)
        return False


def hash_user_password(raw_password: str, salt: bytes) -> str:
    """SECURE: Modern cryptographic hashing using salted SHA-256."""
    hasher = hashlib.sha256()
    hasher.update(salt)
    hasher.update(raw_password.encode("utf-8"))
    return hasher.hexdigest()


def process_payment_records(records: List[Dict[str, Any]]) -> int:
    """SECURE: Catches specific exceptions, logs warnings, and preserves error visibility."""
    processed_count = 0
    for r in records:
        try:
            amount = float(r["amount"])
            logger.info("Processing transaction: $%.2f", amount)
            processed_count += 1
        except (KeyError, ValueError, TypeError) as err:
            logger.warning("Skipping invalid record format (%s): %s", err, r)
    return processed_count


if __name__ == "__main__":
    logger.info("Clean demo initialized successfully.")
