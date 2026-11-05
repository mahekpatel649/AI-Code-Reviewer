"""CLEAN & SECURE DATABASE ACCESS MODULE.

Implements parameterized SQL statements preventing SQL injection.
"""

import sqlite3
from typing import Any, List, Tuple


def get_user_profile(user_id: str) -> List[Tuple[Any, ...]]:
    """SECURE: Parameterized SQL query using '?' placeholder."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # Parameterized query binds user_id as literal data, preventing SQL injection
    query = "SELECT * FROM users WHERE id = ? AND is_active = 1"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()


def delete_user_account(username: str) -> None:
    """SECURE: Parameterized DELETE statement."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    query = "DELETE FROM accounts WHERE username = ?"
    cursor.execute(query, (username,))
    conn.commit()
