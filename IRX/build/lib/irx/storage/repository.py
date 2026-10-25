"""Repository operations and structured audit logging."""

import json
import re
import sqlite3
import uuid
from typing import Any, Dict, List, Optional

from irx.core.models import IRXConfig, utc_now
from irx.storage.database import connect, parse_json_field, row_dict


def make_id(prefix: str) -> str:
    return "{}-{}".format(prefix, uuid.uuid4().hex[:10].upper())


def audit(
    config: IRXConfig,
    action: str,
    result: str,
    case_id: Optional[str] = None,
    target_id: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> str:
    operation_id = make_id("OP")
    with connect(config) as db:
        db.execute(
            "INSERT INTO operations VALUES (?,?,?,?,?,?,?,?,?)",
            (
                operation_id,
                case_id,
                target_id,
                config.analyst,
                utc_now(),
                action,
                json.dumps(parameters or {}, sort_keys=True),
                result,
                error,
            ),
        )
    return operation_id


def create_case(
    config: IRXConfig,
    name: str,
    case_id: Optional[str] = None,
    description: str = "",
    analyst: Optional[str] = None,
    organization: Optional[str] = None,
    tags: Optional[List[str]] = None,
    timezone: Optional[str] = None,
) -> Dict[str, Any]:
    identifier = case_id or make_id("IR")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", identifier):
        from irx.core.exceptions import ConflictError

        raise ConflictError(
            "Case ID must be 1-64 letters, digits, dots, underscores, or hyphens; "
            "it must start with a letter or digit"
        )
    storage_path = config.data_dir / "cases" / identifier
    (storage_path / "evidence" / "originals").mkdir(mode=0o700, parents=True, exist_ok=False)
    (storage_path / "reports").mkdir(mode=0o700)
    try:
        with connect(config) as db:
            db.execute(
                "INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    identifier,
                    name,
                    description,
                    analyst or config.analyst,
                    organization or config.organization,
                    utc_now(),
                    timezone or config.timezone,
                    "open",
                    json.dumps(tags or []),
                    str(storage_path),
                ),
            )
    except sqlite3.IntegrityError as exc:
        # The directory contains no evidence yet; remove only this newly created empty case tree.
        import shutil

        shutil.rmtree(storage_path, ignore_errors=True)
        from irx.core.exceptions import ConflictError

        raise ConflictError("Case ID already exists: {}".format(identifier)) from exc
    except Exception:
        import shutil

        shutil.rmtree(storage_path, ignore_errors=True)
        raise
    audit(config, "case.create", "completed", case_id=identifier, parameters={"name": name})
    return get_case(config, identifier)


def list_cases(config: IRXConfig) -> List[Dict[str, Any]]:
    with connect(config) as db:
        rows = db.execute("SELECT * FROM cases ORDER BY started_at DESC").fetchall()
    return [parse_json_field(row, "tags_json") for row in rows]


def get_case(config: IRXConfig, case_id: str) -> Optional[Dict[str, Any]]:
    with connect(config) as db:
        row = db.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            return None
        case = parse_json_field(row, "tags_json")
        case["operations"] = [
            row_dict(item)
            for item in db.execute(
                "SELECT * FROM operations WHERE case_id = ? ORDER BY timestamp", (case_id,)
            ).fetchall()
        ]
        return case


def close_case(config: IRXConfig, case_id: str) -> bool:
    with connect(config) as db:
        changed = db.execute(
            "UPDATE cases SET status='closed' WHERE id=? AND status='open'", (case_id,)
        ).rowcount
    if changed:
        audit(config, "case.close", "completed", case_id=case_id)
    return bool(changed)


def add_target(
    config: IRXConfig,
    name: str,
    address: str,
    os_name: Optional[str] = None,
    case_id: Optional[str] = None,
) -> Dict[str, Any]:
    target = {
        "id": make_id("TG"),
        "name": name,
        "address": address,
        "os": os_name,
        "case_id": case_id,
        "created_at": utc_now(),
    }
    with connect(config) as db:
        db.execute("INSERT INTO targets VALUES (?,?,?,?,?,?)", tuple(target.values()))
    audit(
        config,
        "target.add",
        "completed",
        case_id=case_id,
        target_id=target["id"],
        parameters={"name": name, "address": address},
    )
    return target


def list_targets(config: IRXConfig) -> List[Dict[str, Any]]:
    with connect(config) as db:
        return [
            row_dict(row) for row in db.execute("SELECT * FROM targets ORDER BY name").fetchall()
        ]


def get_target(config: IRXConfig, name_or_id: str) -> Optional[Dict[str, Any]]:
    with connect(config) as db:
        return row_dict(
            db.execute(
                "SELECT * FROM targets WHERE name=? OR id=?", (name_or_id, name_or_id)
            ).fetchone()
        )


def insert_evidence(config: IRXConfig, item: Dict[str, Any]) -> None:
    with connect(config) as db:
        db.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?)", tuple(item.values()))


def list_evidence(config: IRXConfig, case_id: str) -> List[Dict[str, Any]]:
    with connect(config) as db:
        return [
            row_dict(row)
            for row in db.execute(
                "SELECT * FROM evidence WHERE case_id=? ORDER BY added_at", (case_id,)
            ).fetchall()
        ]


def get_evidence(config: IRXConfig, case_id: str, evidence_id: str) -> Optional[Dict[str, Any]]:
    with connect(config) as db:
        return row_dict(
            db.execute(
                "SELECT * FROM evidence WHERE case_id=? AND id=?", (case_id, evidence_id)
            ).fetchone()
        )


def get_operations(config: IRXConfig, case_id: str) -> List[Dict[str, Any]]:
    with connect(config) as db:
        return [
            row_dict(row)
            for row in db.execute(
                "SELECT * FROM operations WHERE case_id=? ORDER BY timestamp", (case_id,)
            ).fetchall()
        ]
