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

"""Independent SQLite persistence for cross-scan experience.

Nothing in the current vvaharness pipeline imports this module.  The database
and its parent directory are created only when a future caller invokes
``connect`` or a write operation.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from vvaharness.experience.models import (
    CandidateExperience,
    MemoryExperience,
    OutcomeExperience,
    ScanExperience,
)


_SCHEMA_VERSION = 1

_DDL = """
PRAGMA auto_vacuum  = INCREMENTAL;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS experience_scans (
  scan_id                  TEXT PRIMARY KEY,
  repository_fingerprint   TEXT NOT NULL,
  commit_sha               TEXT,
  config_sha256             TEXT,
  payload                  TEXT NOT NULL,
  started_at               TEXT NOT NULL,
  completed_at             TEXT
);

CREATE TABLE IF NOT EXISTS experience_candidates (
  candidate_id             INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id                  TEXT NOT NULL REFERENCES experience_scans(scan_id)
                                  ON DELETE CASCADE,
  finding_fingerprint      TEXT NOT NULL,
  stage                    TEXT NOT NULL,
  language                 TEXT NOT NULL,
  vulnerability_class      TEXT NOT NULL,
  cwe                      TEXT,
  file                     TEXT NOT NULL,
  payload                  TEXT NOT NULL,
  created_at               TEXT NOT NULL,
  UNIQUE(scan_id, finding_fingerprint)
);

CREATE TABLE IF NOT EXISTS experience_outcomes (
  outcome_id               INTEGER PRIMARY KEY AUTOINCREMENT,
  candidate_id             INTEGER NOT NULL
                                  REFERENCES experience_candidates(candidate_id)
                                  ON DELETE CASCADE,
  source                   TEXT NOT NULL,
  verdict                  TEXT NOT NULL,
  trust_level              INTEGER NOT NULL CHECK (trust_level BETWEEN 0 AND 4),
  payload                  TEXT NOT NULL,
  created_at               TEXT NOT NULL,
  UNIQUE(candidate_id, source)
);

CREATE TABLE IF NOT EXISTS experience_memories (
  finding_fingerprint      TEXT PRIMARY KEY,
  repository_fingerprint   TEXT,
  language                 TEXT NOT NULL,
  vulnerability_class      TEXT NOT NULL,
  cwe                      TEXT,
  verdict                  TEXT NOT NULL,
  trust_level              INTEGER NOT NULL CHECK (trust_level BETWEEN 0 AND 4),
  payload                  TEXT NOT NULL,
  updated_at               TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_experience_candidates_lookup
  ON experience_candidates(language, vulnerability_class, cwe);
CREATE INDEX IF NOT EXISTS ix_experience_outcomes_verdict
  ON experience_outcomes(verdict, trust_level);
CREATE INDEX IF NOT EXISTS ix_experience_memories_lookup
  ON experience_memories(language, vulnerability_class, trust_level);
"""


def state_root() -> Path:
    """Resolve the existing vvaharness state-directory convention."""
    return Path(os.environ.get("VVAHARNESS_STATE_DIR")
                or Path.home() / ".vvaharness" / "state")


def db_path() -> Path:
    return state_root() / "experience.db"


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open and initialize an experience database on explicit use."""
    target = Path(path) if path is not None else db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(target)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA busy_timeout = 30000")
    con.execute("PRAGMA synchronous = NORMAL")
    have = int(con.execute("PRAGMA user_version").fetchone()[0])
    if have != _SCHEMA_VERSION:
        _migrate(con, have)
    return con


def _migrate(con: sqlite3.Connection, have: int) -> None:
    if have == 0:
        con.executescript(_DDL)
    elif have > _SCHEMA_VERSION:
        raise RuntimeError(
            f"experience database schema {have} is newer than supported "
            f"schema {_SCHEMA_VERSION}"
        )
    else:
        raise RuntimeError(
            f"experience database migration {have} -> {_SCHEMA_VERSION} "
            "is not implemented"
        )
    con.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
    con.commit()


def register_scan(scan: ScanExperience, *, path: str | Path | None = None) -> None:
    con = connect(path)
    try:
        with con:
            con.execute(
                "INSERT INTO experience_scans("
                "scan_id, repository_fingerprint, commit_sha, config_sha256, "
                "payload, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(scan_id) DO UPDATE SET "
                "repository_fingerprint=excluded.repository_fingerprint, "
                "commit_sha=excluded.commit_sha, config_sha256=excluded.config_sha256, "
                "payload=excluded.payload, started_at=excluded.started_at, "
                "completed_at=excluded.completed_at",
                (
                    scan.scan_id,
                    scan.repository_fingerprint,
                    scan.commit_sha,
                    scan.config_sha256,
                    scan.model_dump_json(),
                    scan.started_at.isoformat(),
                    scan.completed_at.isoformat() if scan.completed_at else None,
                ),
            )
    finally:
        con.close()


def upsert_candidate(
    candidate: CandidateExperience, *, path: str | Path | None = None
) -> int:
    """Persist a candidate and return its database identifier."""
    con = connect(path)
    try:
        with con:
            con.execute(
                "INSERT INTO experience_candidates("
                "scan_id, finding_fingerprint, stage, language, "
                "vulnerability_class, cwe, file, payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(scan_id, finding_fingerprint) DO UPDATE SET "
                "stage=excluded.stage, language=excluded.language, "
                "vulnerability_class=excluded.vulnerability_class, "
                "cwe=excluded.cwe, file=excluded.file, payload=excluded.payload",
                (
                    candidate.scan_id,
                    candidate.finding_fingerprint,
                    candidate.stage.value,
                    candidate.language,
                    candidate.vulnerability_class,
                    candidate.cwe,
                    candidate.file,
                    candidate.model_dump_json(),
                    candidate.created_at.isoformat(),
                ),
            )
            row = con.execute(
                "SELECT candidate_id FROM experience_candidates "
                "WHERE scan_id = ? AND finding_fingerprint = ?",
                (candidate.scan_id, candidate.finding_fingerprint),
            ).fetchone()
            if row is None:
                raise RuntimeError("candidate upsert succeeded without a stored row")
            return int(row[0])
    finally:
        con.close()


def record_outcome(
    outcome: OutcomeExperience, *, path: str | Path | None = None
) -> int:
    """Upsert one source's judgment for an already-recorded candidate."""
    con = connect(path)
    try:
        with con:
            candidate = con.execute(
                "SELECT candidate_id FROM experience_candidates "
                "WHERE scan_id = ? AND finding_fingerprint = ?",
                (outcome.scan_id, outcome.finding_fingerprint),
            ).fetchone()
            if candidate is None:
                raise KeyError(
                    "outcome candidate is not registered: "
                    f"{outcome.scan_id}/{outcome.finding_fingerprint}"
                )
            candidate_id = int(candidate[0])
            con.execute(
                "INSERT INTO experience_outcomes("
                "candidate_id, source, verdict, trust_level, payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(candidate_id, source) DO UPDATE SET "
                "verdict=excluded.verdict, trust_level=excluded.trust_level, "
                "payload=excluded.payload, created_at=excluded.created_at",
                (
                    candidate_id,
                    outcome.source.value,
                    outcome.verdict.value,
                    outcome.trust_level,
                    outcome.model_dump_json(),
                    outcome.created_at.isoformat(),
                ),
            )
            row = con.execute(
                "SELECT outcome_id FROM experience_outcomes "
                "WHERE candidate_id = ? AND source = ?",
                (candidate_id, outcome.source.value),
            ).fetchone()
            if row is None:
                raise RuntimeError("outcome upsert succeeded without a stored row")
            return int(row[0])
    finally:
        con.close()


def promote_memory(
    memory: MemoryExperience, *, path: str | Path | None = None
) -> None:
    """Persist a retrieval-ready memory selected by a future trust policy."""
    con = connect(path)
    try:
        with con:
            con.execute(
                "INSERT INTO experience_memories("
                "finding_fingerprint, repository_fingerprint, language, "
                "vulnerability_class, cwe, verdict, trust_level, payload, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(finding_fingerprint) DO UPDATE SET "
                "repository_fingerprint=excluded.repository_fingerprint, "
                "language=excluded.language, "
                "vulnerability_class=excluded.vulnerability_class, "
                "cwe=excluded.cwe, verdict=excluded.verdict, "
                "trust_level=excluded.trust_level, payload=excluded.payload, "
                "updated_at=excluded.updated_at",
                (
                    memory.finding_fingerprint,
                    memory.repository_fingerprint,
                    memory.language,
                    memory.vulnerability_class,
                    memory.cwe,
                    memory.verdict.value,
                    memory.trust_level,
                    memory.model_dump_json(),
                    memory.updated_at.isoformat(),
                ),
            )
    finally:
        con.close()


def retrieve_memories(
    *,
    language: str | None = None,
    vulnerability_class: str | None = None,
    minimum_trust: int = 2,
    limit: int = 5,
    path: str | Path | None = None,
) -> list[MemoryExperience]:
    """Return narrowly filtered memories; no scan currently calls this."""
    if not 0 <= minimum_trust <= 4:
        raise ValueError("minimum_trust must be between 0 and 4")
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")

    clauses = ["trust_level >= ?"]
    params: list[object] = [minimum_trust]
    if language:
        clauses.append("language = ?")
        params.append(language)
    if vulnerability_class:
        clauses.append("vulnerability_class = ?")
        params.append(vulnerability_class)
    params.append(limit)

    con = connect(path)
    try:
        rows = con.execute(
            "SELECT payload FROM experience_memories WHERE "
            + " AND ".join(clauses)
            + " ORDER BY trust_level DESC, updated_at DESC LIMIT ?",
            params,
        ).fetchall()
        return [MemoryExperience.model_validate_json(row[0]) for row in rows]
    finally:
        con.close()

