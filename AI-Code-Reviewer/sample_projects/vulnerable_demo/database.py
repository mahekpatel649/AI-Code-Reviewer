"""VULNERABLE DATABASE ACCESS MODULE.

WARNING: Intentional SQL injection flaws for educational scanning demonstration.
"""

import sqlite3


def get_user_profile(user_id: str):
    """VULNERABILITY: SQL Injection via f-string dynamic query formatting (AST-H001, Bandit B608)."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # Dangerous: user_id concatenated directly into SQL command
    query = f"SELECT * FROM users WHERE id = '{user_id}' AND is_active = 1"
    cursor.execute(query)
    return cursor.fetchall()


def delete_user_account(username: str):
    """VULNERABILITY: SQL Injection via string % formatting (AST-H001, Bandit B608)."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # Dangerous: string interpolation
    query = "DELETE FROM accounts WHERE username = '%s'" % username
    cursor.execute(query)
    conn.commit()
