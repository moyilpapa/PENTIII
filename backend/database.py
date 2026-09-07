"""
database.py
Zero-config SQLite persistence layer for the Web Application Security Tester.

Why a database at all: scan results only exist in memory for the moment
Flask processes a request. Without saving to SQLite, every result would
disappear on refresh -- this is what lets a report be generated later.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "security_tester.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            date_added TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Not Started'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            scan_type TEXT NOT NULL,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            location TEXT,
            parameter TEXT,
            description TEXT,
            evidence TEXT,
            severity TEXT NOT NULL DEFAULT 'Low',
            remediation TEXT,
            status TEXT NOT NULL DEFAULT 'Unconfirmed',
            status_mode TEXT NOT NULL DEFAULT 'auto',
            created_at TEXT NOT NULL,
            detection_method TEXT,
            http_method TEXT,
            confidence TEXT,
            response_comparison TEXT,
            FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE
        )
    """)

    # Pent III advancement: existing installs created before these columns
    # existed need them added in place -- this keeps old databases working
    # without forcing a fresh install (Section 20/23: don't break what exists).
    for col_def in [
        "status_mode TEXT NOT NULL DEFAULT 'auto'",
        "detection_method TEXT",
        "http_method TEXT",
        "confidence TEXT",
        "response_comparison TEXT",
    ]:
        try:
            cur.execute(f"ALTER TABLE findings ADD COLUMN {col_def}")
        except sqlite3.OperationalError:
            pass  # column already exists

    try:
        cur.execute("ALTER TABLE targets DROP COLUMN status_mode")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.execute("""
        UPDATE targets
        SET status = CASE
            WHEN EXISTS (SELECT 1 FROM scan_results s WHERE s.target_id = targets.id AND s.scan_type = 'http')
             AND EXISTS (SELECT 1 FROM scan_results s WHERE s.target_id = targets.id AND s.scan_type = 'endpoints')
             AND EXISTS (SELECT 1 FROM scan_results s WHERE s.target_id = targets.id AND s.scan_type = 'javascript')
                THEN 'Complete'
            WHEN EXISTS (SELECT 1 FROM scan_results s WHERE s.target_id = targets.id)
                THEN 'In Progress'
            ELSE 'Not Started'
        END
    """)
    conn.commit()
    conn.close()


def now():
    return datetime.utcnow().isoformat()
