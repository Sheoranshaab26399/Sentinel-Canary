# storage.py
# SQLite me saara evidence store hota hai — events, alerts, offenders.
# Sirf REDACTED/minimal data rakhte hain, raw sensitive content nahi.

import os
import sqlite3
import time

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL,            -- event ka time
  pid INTEGER,
  etype TEXT,         -- modified/created/moved/deleted
  path TEXT,          -- redacted path
  entropy REAL,
  score INTEGER,
  is_alert INTEGER,   -- 0/1
  reasons TEXT        -- comma separated reasons
);
CREATE TABLE IF NOT EXISTS offenders (
  pid INTEGER PRIMARY KEY,
  strikes INTEGER,
  state TEXT,
  last_seen REAL
);
"""


def _redact(path: str) -> str:
    """
    Path ko thoda redact karo — poore absolute path ki jagah
    sirf filename + parent dir rakho (privacy/minimal data).
    """
    if not path:
        return ""
    p = path.replace("\\", "/")
    parts = p.split("/")
    return "/".join(parts[-2:])


def _open(path: str):
    """Db open karo + pragmas set karo. Fail ho toh exception."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
    # Kuch mounts/filesystems pe journal lock fail ho jata hai — WAL try, warna memory.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        try:
            conn.execute("PRAGMA journal_mode=MEMORY")
        except Exception:
            pass
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_SCHEMA)
    # write test — abhi fail kare toh fallback le sake
    conn.execute("CREATE TABLE IF NOT EXISTS _w (x)")
    conn.execute("INSERT INTO _w VALUES (1)")
    conn.execute("DROP TABLE _w")
    conn.commit()
    return conn


class Storage:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or config.DB_PATH
        try:
            self.conn = _open(self.db_path)
        except Exception:
            # mounted/locked fs pe write fail ho toh temp pe chal jao (warn karo)
            import tempfile, warnings
            fb = os.path.join(tempfile.gettempdir(), "sentinel.db")
            warnings.warn(f"db not writable at {self.db_path}; using {fb}")
            self.db_path = fb
            self.conn = _open(self.db_path)

    def log_event(self, ev: dict, res: dict):
        """Ek scored event store karo."""
        self.conn.execute(
            "INSERT INTO events (ts,pid,etype,path,entropy,score,is_alert,reasons)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (
                time.time(),
                ev.get("pid", 0),
                ev.get("type", "modified"),
                _redact(ev.get("path", "")),
                res.get("entropy", 0.0),
                res.get("score", 0),
                1 if res.get("alert") else 0,
                "; ".join(res.get("reasons", [])),
            ),
        )
        self.conn.commit()

    def upsert_offender(self, pid: int, strikes: int, state: str):
        """Offender ka state update karo."""
        self.conn.execute(
            "INSERT INTO offenders (pid,strikes,state,last_seen) VALUES (?,?,?,?)"
            " ON CONFLICT(pid) DO UPDATE SET strikes=excluded.strikes,"
            " state=excluded.state, last_seen=excluded.last_seen",
            (pid, strikes, state, time.time()),
        )
        self.conn.commit()

    def recent_events(self, limit: int = 50):
        cur = self.conn.execute(
            "SELECT ts,pid,etype,path,entropy,score,is_alert,reasons"
            " FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return cur.fetchall()

    def list_offenders(self):
        cur = self.conn.execute(
            "SELECT pid,strikes,state,last_seen FROM offenders ORDER BY strikes DESC")
        return cur.fetchall()

    def counts(self):
        cur = self.conn.execute(
            "SELECT COUNT(*), SUM(is_alert) FROM events")
        total, alerts = cur.fetchone()
        return {"events": total or 0, "alerts": alerts or 0}

    def close(self):
        self.conn.close()
