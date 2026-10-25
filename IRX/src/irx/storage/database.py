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

EVTX_SCHEMA = """
CREATE TABLE IF NOT EXISTS evtx_analyses (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
  evidence_id TEXT NOT NULL REFERENCES evidence(id), source_sha256 TEXT NOT NULL,
  parser TEXT NOT NULL, parser_version TEXT NOT NULL, started_at TEXT NOT NULL,
  finished_at TEXT, status TEXT NOT NULL CHECK(status IN ('complete','partial','failed')),
  events_count INTEGER NOT NULL DEFAULT 0, parse_error_count INTEGER NOT NULL DEFAULT 0,
  first_event_utc TEXT, last_event_utc TEXT, error_summary TEXT
);
CREATE INDEX IF NOT EXISTS evtx_analyses_evidence ON evtx_analyses(case_id,evidence_id,started_at);
CREATE TABLE IF NOT EXISTS evtx_events (
  id INTEGER PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES evtx_analyses(id) ON DELETE CASCADE,
  sequence_no INTEGER NOT NULL, record_id TEXT, header_timestamp TEXT,
  event_timestamp_original TEXT, event_timestamp_utc TEXT, computer TEXT,
  provider_name TEXT, provider_guid TEXT, channel TEXT, event_id TEXT,
  event_version TEXT, level TEXT, task TEXT, opcode TEXT, keywords TEXT,
  user_sid TEXT, process_id TEXT, thread_id TEXT, event_data_json TEXT NOT NULL,
  raw_xml TEXT NOT NULL, UNIQUE(analysis_id,sequence_no)
);
CREATE INDEX IF NOT EXISTS evtx_events_analysis_time
  ON evtx_events(analysis_id,event_timestamp_utc);
CREATE INDEX IF NOT EXISTS evtx_events_filters
  ON evtx_events(event_id,channel,provider_name,computer);
CREATE TABLE IF NOT EXISTS evtx_parse_errors (
  id INTEGER PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES evtx_analyses(id) ON DELETE CASCADE,
  sequence_no INTEGER, error_kind TEXT NOT NULL, message TEXT NOT NULL
);
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
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version < 1:
        db.executescript(EVTX_SCHEMA)
        db.execute("PRAGMA user_version = 1")
    elif version > 1:
        db.close()
        raise RuntimeError(
            "Database schema version {} is newer than this IRX build".format(version)
        )
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
