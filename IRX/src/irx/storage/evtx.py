"""EVTX parsing, evidence-linked persistence, and event queries."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from typing import Any, Dict, Optional
from xml.etree import ElementTree

from evtx import PyEvtxParser

from irx.core.exceptions import ConflictError, NotFoundError
from irx.core.models import IRXConfig, utc_now
from irx.storage.evidence import sha256_file, verify_evidence
from irx.storage.repository import audit, get_case, get_evidence

PARSER_NAME = "pyevtx-rs"
PARSER_VERSION = version("evtx")
MAX_CONSECUTIVE_READER_ERRORS = 10


def _tag(element: ElementTree.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _child(parent: Optional[ElementTree.Element], name: str):
    if parent is None:
        return None
    return next((item for item in parent if _tag(item) == name), None)


def _text(parent: Optional[ElementTree.Element], name: str) -> Optional[str]:
    item = _child(parent, name)
    if item is None:
        return None
    return item.text if item.text is not None else ""


def _utc_timestamp(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _event_fields(xml: str) -> Dict[str, Any]:
    root = ElementTree.fromstring(xml)
    system = _child(root, "System")
    provider = _child(system, "Provider")
    event_id = _child(system, "EventID")
    time_created = _child(system, "TimeCreated")
    security = _child(system, "Security")
    execution = _child(system, "Execution")
    data_parent = _child(root, "EventData")
    data = []
    if data_parent is not None:
        for item in data_parent:
            data.append(
                {
                    "name": item.attrib.get("Name"),
                    "value": item.text if item.text is not None else "",
                }
            )
    user_data = _child(root, "UserData")
    if user_data is not None:
        data.append(
            {"name": "UserData", "value": ElementTree.tostring(user_data, encoding="unicode")}
        )
    record_id = _text(system, "EventRecordID")
    return {
        "record_id": record_id,
        "header_timestamp": None,
        "event_timestamp_original": time_created.attrib.get("SystemTime")
        if time_created is not None
        else None,
        "event_timestamp_utc": _utc_timestamp(
            time_created.attrib.get("SystemTime") if time_created is not None else None
        ),
        "computer": _text(system, "Computer"),
        "provider_name": provider.attrib.get("Name") if provider is not None else None,
        "provider_guid": provider.attrib.get("Guid") if provider is not None else None,
        "channel": _text(system, "Channel"),
        "event_id": _text(system, "EventID"),
        "event_version": event_id.attrib.get("Version") if event_id is not None else None,
        "level": _text(system, "Level"),
        "task": _text(system, "Task"),
        "opcode": _text(system, "Opcode"),
        "keywords": _text(system, "Keywords"),
        "user_sid": security.attrib.get("UserID") if security is not None else None,
        "process_id": execution.attrib.get("ProcessID") if execution is not None else None,
        "thread_id": execution.attrib.get("ThreadID") if execution is not None else None,
        "event_data_json": json.dumps(data, ensure_ascii=False),
        "raw_xml": xml,
    }


def _reader(path: Path):
    return PyEvtxParser(str(path))


def analyze_evidence(
    config: IRXConfig,
    case_id: str,
    evidence_id: str,
    rerun: bool = False,
    reader_factory=_reader,
) -> Dict[str, Any]:
    """Analyze an imported EVTX; repeated runs reuse matching successful results by default."""
    case = get_case(config, case_id)
    if case is None:
        raise NotFoundError("Case not found: {}".format(case_id))
    evidence = get_evidence(config, case_id, evidence_id)
    if evidence is None:
        raise NotFoundError("Evidence not found: {}".format(evidence_id))
    case_root = Path(case["storage_path"]).resolve(strict=True)
    path = Path(evidence["stored_path"]).resolve(strict=True)
    if not path.is_relative_to(case_root):
        raise ConflictError("Evidence path resolves outside the case storage directory")
    verified = verify_evidence(config, case_id, evidence_id)
    if not verified["ok"]:
        raise ConflictError("Evidence integrity check failed; EVTX analysis was not started")
    digest = sha256_file(path)
    analysis_id = "AX-{}".format(uuid.uuid4().hex[:12].upper())
    with sqlite3.connect(str(config.data_dir / "irx.sqlite3")) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        if not rerun:
            existing = db.execute(
                "SELECT * FROM evtx_analyses WHERE case_id=? AND evidence_id=? "
                "AND source_sha256=? AND parser_version=? AND status IN ('complete','partial') "
                "ORDER BY started_at DESC LIMIT 1",
                (case_id, evidence_id, digest, PARSER_VERSION),
            ).fetchone()
            if existing:
                return dict(existing) | {"reused": True}
        db.execute(
            "INSERT INTO evtx_analyses "
            "(id,case_id,evidence_id,source_sha256,parser,parser_version,started_at,status) "
            "VALUES (?,?,?,?,?,?,?,'failed')",
            (analysis_id, case_id, evidence_id, digest, PARSER_NAME, PARSER_VERSION, utc_now()),
        )
        db.commit()

    events_count = 0
    errors = []
    timestamps = []
    fatal = None
    try:
        parser = reader_factory(path)
        iterator = iter(parser.records())
        sequence = 0
        consecutive_errors = 0
        while True:
            try:
                record = next(iterator)
                consecutive_errors = 0
            except StopIteration:
                break
            except (
                Exception
            ) as exc:  # Reader failures are retained and surfaced as partial results.
                errors.append((sequence + 1, type(exc).__name__, str(exc)))
                consecutive_errors += 1
                if consecutive_errors >= MAX_CONSECUTIVE_READER_ERRORS:
                    fatal = "Stopped after repeated reader errors: {}".format(exc)
                    break
                continue
            sequence += 1
            raw = record.get("data")
            header_time = record.get("timestamp")
            try:
                if not isinstance(raw, str):
                    raise ValueError("Parser did not return XML text for this record")
                fields = _event_fields(raw)
                if fields["record_id"] is None and record.get("event_record_id") is not None:
                    fields["record_id"] = str(record["event_record_id"])
                fields["header_timestamp"] = header_time
                if not fields["event_timestamp_utc"]:
                    fields["event_timestamp_utc"] = _utc_timestamp(header_time)
                if fields["event_timestamp_utc"]:
                    timestamps.append(fields["event_timestamp_utc"])
                with sqlite3.connect(str(config.data_dir / "irx.sqlite3")) as db:
                    db.execute("PRAGMA foreign_keys=ON")
                    db.execute(
                        """INSERT INTO evtx_events (
                        analysis_id,sequence_no,record_id,header_timestamp,event_timestamp_original,
                        event_timestamp_utc,computer,provider_name,provider_guid,channel,event_id,
                        event_version,level,task,opcode,keywords,user_sid,process_id,thread_id,
                        event_data_json,raw_xml
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (analysis_id, sequence)
                        + tuple(
                            fields[key]
                            for key in (
                                "record_id",
                                "header_timestamp",
                                "event_timestamp_original",
                                "event_timestamp_utc",
                                "computer",
                                "provider_name",
                                "provider_guid",
                                "channel",
                                "event_id",
                                "event_version",
                                "level",
                                "task",
                                "opcode",
                                "keywords",
                                "user_sid",
                                "process_id",
                                "thread_id",
                                "event_data_json",
                                "raw_xml",
                            )
                        ),
                    )
                events_count += 1
            except Exception as exc:
                errors.append((sequence, type(exc).__name__, str(exc)))
                # Preserve uninterpretable source XML when available for later review.
                if isinstance(raw, str):
                    with sqlite3.connect(str(config.data_dir / "irx.sqlite3")) as db:
                        db.execute(
                            """INSERT INTO evtx_events
                            (analysis_id,sequence_no,event_data_json,raw_xml) VALUES (?,?,?,?)""",
                            (analysis_id, sequence, "[]", raw),
                        )
        status = "failed" if fatal and events_count == 0 else ("partial" if errors else "complete")
        fatal = fatal or None
    except Exception as exc:
        errors.append((None, type(exc).__name__, str(exc)))
        status = "failed"
        fatal = "{}: {}".format(type(exc).__name__, exc)

    try:
        final_digest = sha256_file(path)
    except OSError as exc:
        final_digest = None
        errors.append(
            (None, type(exc).__name__, "Could not recheck evidence after parsing: {}".format(exc))
        )
    if final_digest != digest:
        errors.append(
            (None, "IntegrityError", "Evidence bytes changed while EVTX analysis was running")
        )
        status = "failed"
        fatal = "Evidence integrity changed during analysis"

    finished = utc_now()
    first = min(timestamps) if timestamps else None
    last = max(timestamps) if timestamps else None
    with sqlite3.connect(str(config.data_dir / "irx.sqlite3")) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.executemany(
            """INSERT INTO evtx_parse_errors
            (analysis_id,sequence_no,error_kind,message) VALUES (?,?,?,?)""",
            [(analysis_id, seq, kind, message) for seq, kind, message in errors],
        )
        db.execute(
            "UPDATE evtx_analyses SET finished_at=?,status=?,events_count=?,parse_error_count=?,"
            "first_event_utc=?,last_event_utc=?,error_summary=? WHERE id=?",
            (finished, status, events_count, len(errors), first, last, fatal, analysis_id),
        )
        row = db.execute("SELECT * FROM evtx_analyses WHERE id=?", (analysis_id,)).fetchone()
    audit(
        config,
        "evtx.analyze",
        status,
        case_id=case_id,
        parameters={"evidence_id": evidence_id, "analysis_id": analysis_id},
    )
    return dict(row) | {"reused": False}


def get_analysis(
    config: IRXConfig, case_id: str, evidence_id: str, analysis_id: Optional[str] = None
):
    with sqlite3.connect(str(config.data_dir / "irx.sqlite3")) as db:
        db.row_factory = sqlite3.Row
        if analysis_id:
            row = db.execute(
                "SELECT * FROM evtx_analyses WHERE id=? AND case_id=? AND evidence_id=?",
                (analysis_id, case_id, evidence_id),
            ).fetchone()
        else:
            row = db.execute(
                "SELECT * FROM evtx_analyses WHERE case_id=? AND evidence_id=? "
                "ORDER BY started_at DESC LIMIT 1",
                (case_id, evidence_id),
            ).fetchone()
    if row is None:
        raise NotFoundError("No EVTX analysis found for evidence {}".format(evidence_id))
    return dict(row)


def list_events(
    config: IRXConfig,
    case_id: str,
    evidence_id: str,
    analysis_id: Optional[str] = None,
    after: Optional[str] = None,
    before: Optional[str] = None,
    event_id: Optional[str] = None,
    channel: Optional[str] = None,
    provider: Optional[str] = None,
    computer: Optional[str] = None,
    limit: int = 100,
):
    analysis = get_analysis(config, case_id, evidence_id, analysis_id)
    clauses, values = ["analysis_id=?"], [analysis["id"]]
    for field, value, op in (
        ("event_timestamp_utc", after, ">="),
        ("event_timestamp_utc", before, "<="),
        ("event_id", event_id, "="),
        ("channel", channel, "="),
        ("provider_name", provider, "="),
        ("computer", computer, "="),
    ):
        if value is not None:
            clauses.append("{}{}?".format(field, op))
            values.append(value)
    values.append(max(1, min(limit, 10000)))
    with sqlite3.connect(str(config.data_dir / "irx.sqlite3")) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """SELECT * FROM evtx_events WHERE {}
            ORDER BY event_timestamp_utc,sequence_no LIMIT ?""".format(" AND ".join(clauses)),
            values,
        ).fetchall()
    return [dict(row) for row in rows]


def show_event(
    config: IRXConfig,
    case_id: str,
    evidence_id: str,
    record_id: str,
    analysis_id: Optional[str] = None,
):
    analysis = get_analysis(config, case_id, evidence_id, analysis_id)
    with sqlite3.connect(str(config.data_dir / "irx.sqlite3")) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT * FROM evtx_events WHERE analysis_id=? AND record_id=? LIMIT 1",
            (analysis["id"], record_id),
        ).fetchone()
    if row is None:
        raise NotFoundError("Event record {} not found".format(record_id))
    result = dict(row)
    result["event_data"] = json.loads(result.pop("event_data_json"))
    return result


def analysis_summary(
    config: IRXConfig, case_id: str, evidence_id: str, analysis_id: Optional[str] = None
) -> Dict[str, Any]:
    analysis = get_analysis(config, case_id, evidence_id, analysis_id)
    analysis["reused"] = False
    return analysis
