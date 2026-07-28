#!/usr/bin/env python3
"""
Export assistant messages from the current Hermes session to JSONL.

Usage:
    python3 export_current_session.py > session.jsonl

The script finds the most recent Hermes session SQLite file under
~/.hermes/sessions/, reads messages, and writes only assistant messages
as JSONL with role/content keys. It does NOT include user messages.
"""

import json
import sqlite3
import sys
from pathlib import Path

SESSIONS_DIR = Path.home() / ".hermes" / "sessions"


def find_latest_session():
    files = sorted(SESSIONS_DIR.glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        print("No session database found in ~/.hermes/sessions/", file=sys.stderr)
        sys.exit(1)
    return files[0]


def main():
    db = find_latest_session()
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    # Hermes schema: messages table with role, content, timestamp, session_id
    cur.execute("SELECT role, content FROM messages WHERE role = 'assistant' ORDER BY id")
    for row in cur:
        msg = {"role": row["role"], "content": row["content"]}
        print(json.dumps(msg, ensure_ascii=False))


if __name__ == "__main__":
    main()
