# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""orchestrator.store — SQLite state store.

Single-file SQLite database under ``$VVAHARNESS_STATE_DIR`` (or
``~/.vvaharness/state``) holding per-run checkpoint blobs and run metadata.
Replaces the per-step JSON files; payloads are still pydantic
``TypeAdapter.dump_json()`` bytes, so the CWE-502 guarantee (no constructor
opcodes, validate-on-load) is preserved unchanged.

The schema is created idempotently on every ``connect()`` — there is no
"first run" branch: ``sqlite3.connect`` creates the file if absent and
``CREATE TABLE IF NOT EXISTS`` is a no-op thereafter. Changing
``$VVAHARNESS_STATE_DIR`` therefore yields a fresh, empty database; the old
file is simply orphaned.
"""
from __future__ import annotations
import os
import sqlite3
from pathlib import Path

_SCHEMA_VERSION = 1

# auto_vacuum MUST precede the first CREATE TABLE or it is silently ignored;
# journal_mode=WAL persists once set. foreign_keys / busy_timeout /
# synchronous are per-connection and set separately in connect().
_DDL = """
PRAGMA auto_vacuum  = INCREMENTAL;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS runs (
  run_id     TEXT PRIMARY KEY,
  repo_root  TEXT NOT NULL,
  repo_name  TEXT,
  app_id     TEXT,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS checkpoints (
  run_id     TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  step       TEXT    NOT NULL,
  payload    BLOB    NOT NULL,
  size       INTEGER NOT NULL CHECK (size <= 104857600),
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (run_id, step)
);

CREATE INDEX IF NOT EXISTS ix_runs_updated ON runs(updated_at);
"""


def db_path() -> Path:
    """Resolve the state DB path the same way scan.py resolves the legacy
    ``checkpoints/`` root — keep these in lockstep so ``--resume`` and the
    in-target safety check (scan.py) see the same location."""
    root = Path(os.environ.get("VVAHARNESS_STATE_DIR")
                or Path.home() / ".vvaharness" / "state")
    root.mkdir(parents=True, exist_ok=True)
    return root / "vvaharness.db"


def connect() -> sqlite3.Connection:
    """Open the state DB, ensure the schema exists, and return a connection.

    Concurrency model: WAL gives N readers + 1 writer with no reader/writer
    blocking; ``busy_timeout`` makes a second concurrent writer wait up to
    30 s for the single write lock instead of failing. SQLite has one write
    lock per DB (not per row), so there is no lock-ordering deadlock to
    avoid — the only failure mode is timeout, and our transactions are
    sub-second. ``synchronous=NORMAL`` is the documented WAL companion:
    still crash-safe (the WAL is fsynced on checkpoint), ~10× faster than
    the FULL default, and appropriate for disposable resume-state.

    Cheap enough to call per operation; a fresh connection per call avoids
    cross-thread/process reuse (sqlite3 connections are thread-affine)."""
    con = sqlite3.connect(db_path())
    # Per-connection pragmas — must be set on every handle.
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA busy_timeout = 30000")
    con.execute("PRAGMA synchronous  = NORMAL")
    # Schema bootstrap — skipped entirely once user_version matches, so the
    # hot path is three pragmas + one integer read; no executescript, no
    # CREATE-IF-NOT-EXISTS lock churn on every save_ckpt().
    have = con.execute("PRAGMA user_version").fetchone()[0]
    if have != _SCHEMA_VERSION:
        _migrate(con, have)
    return con


def _migrate(con: sqlite3.Connection, have: int) -> None:
    if have == 0:
        con.executescript(_DDL)
    # elif have < 2: con.execute("ALTER TABLE checkpoints ADD COLUMN ...")
    con.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
    con.commit()


def register_run(run_id: str, *, repo_root: str,
                 repo_name: str | None = None,
                 app_id: str | None = None) -> None:
    """Upsert the per-run metadata row. Called once at the top of
    ``scan_repo()`` so ``gc`` can rank runs by recency and so a future
    ``findings`` table has something to FK against."""
    con = connect()
    with con:
        con.execute(
            "INSERT INTO runs(run_id, repo_root, repo_name, app_id) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(run_id) DO UPDATE SET "
            "  repo_root = excluded.repo_root, "
            "  repo_name = excluded.repo_name, "
            "  app_id    = excluded.app_id, "
            "  updated_at = datetime('now')",
            (run_id, repo_root, repo_name, app_id),
        )
    con.close()


def reset_run(run_id: str) -> int:
    """Delete every checkpoint row for one run — the fixed s1..s9 steps AND the
    dynamic ``remediate_<idx>`` / ``validate_<id>`` steps.

    Called by a FRESH (non ``--resume``) scan. ``run_id`` is derived purely from
    the repo path, so a rescan of the same project reuses the prior run's rows;
    ``save_ckpt`` (INSERT OR REPLACE) overwrites only the steps the new scan
    reaches, leaving stale rows (steps a stopped run skipped, plus per-finding
    remediate/validate rows whose keys don't recur) for a later ``--resume`` to
    load. Clearing them here makes "fresh scan" mean a genuinely empty slate.

    The ``runs`` metadata row is intentionally kept (``register_run`` upserts
    it just before this call); only its checkpoints are removed. No vacuum is
    issued — the freed pages are immediately reused by this scan's own writes,
    so the per-scan cost is a single DELETE. Returns rows deleted."""
    con = connect()
    try:
        with con:
            cur = con.execute(
                "DELETE FROM checkpoints WHERE run_id = ?", (run_id,))
            return cur.rowcount if cur.rowcount is not None else 0
    finally:
        con.close()


def delete_run(run_id: str) -> bool:
    """Fully evict a single run: delete its ``runs`` row, which drops its
    ``checkpoints`` via ON DELETE CASCADE. Reclaims freed pages afterwards
    (unlike :func:`reset_run`, this is an on-demand ``gc`` operation, not a
    per-scan hot path). Returns True if a run row was deleted."""
    con = connect()
    try:
        with con:
            cur = con.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
            deleted = cur.rowcount or 0
        if deleted:
            con.execute("PRAGMA incremental_vacuum")
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return deleted > 0
    finally:
        con.close()
