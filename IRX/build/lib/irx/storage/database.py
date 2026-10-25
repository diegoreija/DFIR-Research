"""SQLite schema and transaction helpers."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from irx.core.config import initialize_data_dir
from irx.core.models import IRXConfig

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  analyst TEXT, organization TEXT, started_at TEXT NOT NULL, timezone TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('open','closed')), tags_json TEXT NOT NULL DEFAULT '[]',
  storage_path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, address TEXT NOT NULL,
  os TEXT, case_id TEXT REFERENCES cases(id) ON DELETE SET NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), name TEXT NOT NULL,
  source_path TEXT NOT NULL, stored_path TEXT NOT NULL, sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL, added_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'verified'
);
CREATE TABLE IF NOT EXISTS operations (
  id TEXT PRIMARY KEY, case_id TEXT REFERENCES cases(id), target_id TEXT,
  analyst TEXT, timestamp TEXT NOT NULL, action TEXT NOT NULL,
  parameters_json TEXT NOT NULL, result TEXT NOT NULL, error TEXT
);
CREATE INDEX IF NOT EXISTS operations_case_time ON operations(case_id, timestamp);
CREATE INDEX IF NOT EXISTS evidence_case ON evidence(case_id);
"""


def database_path(config: IRXConfig) -> Path:
    return config.data_dir / "irx.sqlite3"


@contextmanager
def connect(config: IRXConfig) -> Iterator[sqlite3.Connection]:
    initialize_data_dir(config)
    db = sqlite3.connect(str(database_path(config)))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(SCHEMA)
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def row_dict(row):
    return dict(row) if row is not None else None


def parse_json_field(row, field: str):
    data = row_dict(row)
    if data is not None:
        data[field[:-5] if field.endswith("_json") else field] = json.loads(data.pop(field))
    return data
