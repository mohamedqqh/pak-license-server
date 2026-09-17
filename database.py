"""
database.py - SQLite for license server
"""
import sqlite3
import os
from datetime import datetime
from contextlib import contextmanager

DB_PATH = os.getenv("DB_PATH", "licenses.db")


class Database:
    def __init__(self, path: str = None):
        self.path = path or DB_PATH
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self):
        with self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    key         TEXT PRIMARY KEY,
                    username    TEXT NOT NULL,
                    note        TEXT DEFAULT '',
                    expiry      TEXT NOT NULL,
                    active      INTEGER DEFAULT 1,
                    hwid        TEXT,
                    created_at  TEXT NOT NULL,
                    last_seen   TEXT,
                    last_ip     TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token       TEXT PRIMARY KEY,
                    key         TEXT NOT NULL,
                    hwid        TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    ip          TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    key         TEXT,
                    action      TEXT NOT NULL,
                    detail      TEXT,
                    ip          TEXT,
                    hwid        TEXT,
                    timestamp   TEXT NOT NULL
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_key ON sessions(key)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_key ON logs(key)")

    def get_key(self, key):
        with self._conn() as c:
            row = c.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
            return dict(row) if row else None

    def create_key(self, key, username, expiry, note=""):
        with self._conn() as c:
            c.execute("""
                INSERT INTO keys (key, username, expiry, note, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (key, username, expiry, note, datetime.now().isoformat()))

    def update_key(self, key, **fields):
        if not fields:
            return
        sets = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [key]
        with self._conn() as c:
            c.execute(f"UPDATE keys SET {sets} WHERE key=?", vals)

    def delete_key(self, key):
        with self._conn() as c:
            c.execute("DELETE FROM keys WHERE key=?", (key,))
            c.execute("DELETE FROM sessions WHERE key=?", (key,))

    def list_keys(self):
        with self._conn() as c:
            rows = c.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    def create_session(self, token, key, hwid, expires_at, ip):
        with self._conn() as c:
            c.execute("""
                INSERT OR REPLACE INTO sessions
                (token, key, hwid, created_at, expires_at, ip)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (token, key, hwid, datetime.now().isoformat(), expires_at, ip))

    def get_session(self, token):
        with self._conn() as c:
            row = c.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
            return dict(row) if row else None

    def delete_session(self, token):
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))

    def cleanup_expired_sessions(self):
        with self._conn() as c:
            cur = c.execute(
                "DELETE FROM sessions WHERE expires_at < ?",
                (datetime.now().isoformat(),)
            )
            return cur.rowcount

    def live_sessions(self):
        with self._conn() as c:
            rows = c.execute("""
                SELECT s.token, s.key, s.hwid, s.created_at,
                       s.expires_at, s.ip, k.username
                FROM sessions s
                JOIN keys k ON s.key = k.key
                WHERE s.expires_at > ?
                ORDER BY s.created_at DESC
            """, (datetime.now().isoformat(),)).fetchall()
            return [dict(r) for r in rows]

    def live_count(self):
        return len(self.live_sessions())

    def log(self, action, key=None, detail="", ip=None, hwid=None):
        with self._conn() as c:
            c.execute("""
                INSERT INTO logs (key, action, detail, ip, hwid, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (key, action, detail, ip, hwid, datetime.now().isoformat()))

    def recent_logs(self, limit=100):
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def stats(self):
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
            active = c.execute(
                "SELECT COUNT(*) FROM keys WHERE active=1 AND expiry > ?",
                (datetime.now().isoformat(),)
            ).fetchone()[0]
            expired = c.execute(
                "SELECT COUNT(*) FROM keys WHERE expiry <= ?",
                (datetime.now().isoformat(),)
            ).fetchone()[0]
            sessions = c.execute(
                "SELECT COUNT(*) FROM sessions WHERE expires_at > ?",
                (datetime.now().isoformat(),)
            ).fetchone()[0]
            return {
                "total_keys": total,
                "active_keys": active,
                "expired_keys": expired,
                "live_now": sessions,
            }


db = Database()
