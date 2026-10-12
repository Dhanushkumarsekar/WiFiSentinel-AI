import sqlite3, json
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).resolve().parent.parent / "wifisentinel.db"

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            mode TEXT NOT NULL,
            networks_json TEXT NOT NULL,
            summary_json TEXT NOT NULL
        )""")

def save_assessment(mode, networks, summary):
    with connect() as c:
        cur = c.execute("INSERT INTO assessments(created_at,mode,networks_json,summary_json) VALUES(?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), mode, json.dumps(networks), json.dumps(summary)))
        return cur.lastrowid

def list_assessments(limit=50):
    with connect() as c:
        rows = c.execute("SELECT id,created_at,mode,summary_json FROM assessments ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r["id"], "created_at": r["created_at"], "mode": r["mode"], "summary": json.loads(r["summary_json"])} for r in rows]

def get_assessment(aid):
    with connect() as c:
        row = c.execute("SELECT * FROM assessments WHERE id=?", (aid,)).fetchone()
        if not row: return None
        return {"id": row["id"], "created_at": row["created_at"], "mode": row["mode"], "networks": json.loads(row["networks_json"]), "summary": json.loads(row["summary_json"])}
