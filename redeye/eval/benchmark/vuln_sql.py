"""Benchmark target: a genuine SQL injection (CWE-89) and one clean handler.

Used by `redeye eval` to measure precision/recall. Line numbers are pinned in
labels.json -- keep them in sync if you edit this file.
"""

import sqlite3

conn = sqlite3.connect(":memory:")


def get_user(request):
    # VULN (CWE-89): user input concatenated straight into SQL.
    username = request.args["username"]
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cur.fetchall()


def get_user_safe(request):
    # CLEAN: parameterised query, no injection.
    username = request.args["username"]
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cur.fetchall()
