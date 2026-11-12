"""SQLite dedup + pipeline state for yimirror.

One table `clips` keyed by (uid, day, clip_id): the clip id/range is whatever the
cloud enumeration yields; a second table `kv` caches the session token.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from pathlib import Path

log = logging.getLogger("yimirror")

SCHEMA = """
CREATE TABLE IF NOT EXISTS clips (
    uid       TEXT NOT NULL,
    day       TEXT NOT NULL,          -- YYYY-MM-DD (UTC)
    clip_id   TEXT NOT NULL,
    t0        INTEGER,
    t1        INTEGER,
    status    TEXT NOT NULL DEFAULT 'downloaded',  -- downloaded | uploaded | failed
    path      TEXT,
    updated_at INTEGER,
    PRIMARY KEY (uid, day, clip_id)
);
CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT
);
"""


class Store:
    def __init__(self, data_dir: str):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.dir / "state.db"
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------ clips

    def is_new(self, uid: str, day: str, clip_id: str) -> bool:
        cur = self.conn.execute(
            "SELECT 1 FROM clips WHERE uid=? AND day=? AND clip_id=?", (uid, day, clip_id)
        )
        return cur.fetchone() is None

    def mark_downloaded(self, uid: str, day: str, clip_id: str,
                        t0: int, t1: int, path: str) -> None:
        self.conn.execute(
            """INSERT INTO clips (uid, day, clip_id, t0, t1, status, path, updated_at)
               VALUES (?, ?, ?, ?, ?, 'downloaded', ?, ?)
               ON CONFLICT(uid, day, clip_id) DO UPDATE SET
                 status='downloaded', path=excluded.path, updated_at=excluded.updated_at""",
            (uid, day, clip_id, t0, t1, path, int(time.time())),
        )
        self.conn.commit()

    def mark_failed(self, uid: str, day: str, clip_id: str, note: str = "") -> None:
        self.conn.execute(
            """INSERT INTO clips (uid, day, clip_id, status, path, updated_at)
               VALUES (?, ?, ?, 'failed', ?, ?)
               ON CONFLICT(uid, day, clip_id) DO UPDATE SET
                 status='failed', updated_at=excluded.updated_at""",
            (uid, day, clip_id, note[:500], int(time.time())),
        )
        self.conn.commit()

    def mark_uploaded(self, uid: str, day: str, clip_id: str) -> None:
        self.conn.execute(
            """UPDATE clips SET status='uploaded', updated_at=? WHERE uid=? AND day=? AND clip_id=?""",
            (int(time.time()), uid, day, clip_id),
        )
        self.conn.commit()

    def pending_uploads(self) -> list[tuple[str, str, str, str]]:
        """(uid, day, clip_id, path) rows downloaded but not uploaded."""
        cur = self.conn.execute(
            "SELECT uid, day, clip_id, path FROM clips WHERE status='downloaded' AND path IS NOT NULL"
        )
        return [(r[0], r[1], r[2], r[3]) for r in cur.fetchall()]

    def stats(self) -> dict:
        cur = self.conn.execute("SELECT status, COUNT(*) FROM clips GROUP BY status")
        return {status: count for status, count in cur.fetchall()}

    # ------------------------------------------------------------------ kv

    def get_kv(self, k: str) -> str | None:
        cur = self.conn.execute("SELECT v FROM kv WHERE k=?", (k,))
        row = cur.fetchone()
        return row[0] if row else None

    def set_kv(self, k: str, v: str) -> None:
        self.conn.execute(
            "INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (k, v),
        )
        self.conn.commit()
