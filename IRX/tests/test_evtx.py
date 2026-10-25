import json
import sqlite3
from pathlib import Path

import pytest
from evtx import PyEvtxParser
from typer.testing import CliRunner

from irx.cli.app import app
from irx.cli.commands import evtx as evtx_commands
from irx.core.exceptions import ConflictError
from irx.core.models import IRXConfig
from irx.reporting.reports import generate_report
from irx.storage.database import connect
from irx.storage.evidence import add_evidence, verify_evidence
from irx.storage.evtx import analyze_evidence, list_events, show_event
from irx.storage.repository import create_case

EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Example" Guid="{abc}"/><EventID Version="2">4624</EventID>
<Version>1</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>
<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2024-02-01T01:00:00+01:00"/>
<EventRecordID>42</EventRecordID><Channel>Security</Channel><Computer>LAB-01</Computer>
<Security UserID="S-1-5-18"/><Execution ProcessID="123" ThreadID="456"/></System>
<EventData><Data Name="TargetUserName">analyst</Data>
<Data Name="IpAddress">192.0.2.1</Data><Data Name="Empty"></Data></EventData>
</Event>"""
MINIMAL_XML = "<Event><System><EventRecordID>43</EventRecordID></System></Event>"


class FakeParser:
    def __init__(self, _path, records):
        self._records = records

    def records(self):
        return iter(self._records)


def _source_and_evidence(tmp_path, contents=b"synthetic EVTX test payload"):
    config = IRXConfig(data_dir=tmp_path / "irx-data")
    case = create_case(config, "EVTX lab")
    source = tmp_path / "synthetic.evtx"
    source.write_bytes(contents)
    evidence = add_evidence(config, case["id"], source)
    return config, case, source, evidence


def test_extract_persist_query_and_report_preserve_imported_evidence(tmp_path):
    config, case, source, evidence = _source_and_evidence(tmp_path)
    original = Path(evidence["stored_path"]).read_bytes()
    records = [
        {"event_record_id": 42, "timestamp": "2024-02-01T00:00:00Z", "data": EVENT_XML},
        {"event_record_id": 43, "timestamp": None, "data": MINIMAL_XML},
    ]
    result = analyze_evidence(
        config, case["id"], evidence["id"], reader_factory=lambda p: FakeParser(p, records)
    )

    assert result["status"] == "complete"
    assert result["events_count"] == 2
    assert result["first_event_utc"] == "2024-02-01T00:00:00.000000Z"
    assert result["last_event_utc"] == result["first_event_utc"]
    event = show_event(config, case["id"], evidence["id"], "42")
    assert event["event_timestamp_original"] == "2024-02-01T01:00:00+01:00"
    assert event["event_timestamp_utc"] == "2024-02-01T00:00:00.000000Z"
    assert event["computer"] == "LAB-01"
    assert event["provider_name"] == "Example"
    assert event["event_data"] == [
        {"name": "TargetUserName", "value": "analyst"},
        {"name": "IpAddress", "value": "192.0.2.1"},
        {"name": "Empty", "value": ""},
    ]
    assert event["raw_xml"] == EVENT_XML
    minimal = show_event(config, case["id"], evidence["id"], "43")
    assert minimal["computer"] is None
    assert minimal["event_id"] is None
    assert (
        list_events(config, case["id"], evidence["id"], event_id="4624", channel="Security")[0][
            "record_id"
        ]
        == "42"
    )
    assert Path(evidence["stored_path"]).read_bytes() == original
    assert verify_evidence(config, case["id"], evidence["id"])["ok"]

    json_report = generate_report(config, case["id"], "json")
    report_data = json.loads(json_report.read_text())
    assert report_data["evtx_analyses"][0]["events_count"] == 2
    html_report = generate_report(config, case["id"], "html")
    assert "EVTX analysis summaries" in html_report.read_text()
    assert "not security alerts" in html_report.read_text()


def test_repeated_run_reuses_results_unless_rerun_requested(tmp_path):
    config, case, _, evidence = _source_and_evidence(tmp_path)

    def factory(path):
        return FakeParser(path, [{"timestamp": None, "data": MINIMAL_XML}])

    first = analyze_evidence(config, case["id"], evidence["id"], reader_factory=factory)
    reused = analyze_evidence(config, case["id"], evidence["id"], reader_factory=factory)
    rerun = analyze_evidence(config, case["id"], evidence["id"], rerun=True, reader_factory=factory)
    assert reused["id"] == first["id"] and reused["reused"] is True
    assert rerun["id"] != first["id"] and rerun["reused"] is False
    with sqlite3.connect(config.data_dir / "irx.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM evtx_analyses").fetchone()[0] == 2


def test_reader_error_is_persisted_and_remaining_records_are_read(tmp_path):
    config, case, _, evidence = _source_and_evidence(tmp_path)

    class RecoveringIterator:
        def __init__(self):
            self.position = 0

        def __iter__(self):
            return self

        def __next__(self):
            self.position += 1
            if self.position == 1:
                raise ValueError("synthetic damaged chunk")
            if self.position == 2:
                return {"timestamp": None, "data": MINIMAL_XML}
            raise StopIteration

    class RecoveringParser:
        def __init__(self, _path):
            pass

        def records(self):
            return RecoveringIterator()

    result = analyze_evidence(config, case["id"], evidence["id"], reader_factory=RecoveringParser)
    assert result["status"] == "partial"
    assert result["events_count"] == 1
    assert result["parse_error_count"] == 1
    with sqlite3.connect(config.data_dir / "irx.sqlite3") as db:
        error = db.execute("SELECT message FROM evtx_parse_errors").fetchone()[0]
    assert "synthetic damaged chunk" in error


def test_invalid_evidence_is_reported_as_failed_with_real_parser(tmp_path):
    config, case, _, evidence = _source_and_evidence(tmp_path, b"not an EVTX file")
    result = analyze_evidence(config, case["id"], evidence["id"], reader_factory=PyEvtxParser)
    assert result["status"] == "failed"
    assert result["parse_error_count"] >= 1
    assert result["events_count"] == 0


def test_cli_returns_failure_code_for_invalid_evtx(tmp_path):
    config, case, _, evidence = _source_and_evidence(tmp_path, b"not an EVTX file")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"data_dir": str(config.data_dir)}), encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(config_file),
            "evtx",
            "analyze",
            "--case",
            case["id"],
            "--evidence",
            evidence["id"],
        ],
    )
    assert result.exit_code == 4
    assert "failed (0 events, 1 parse errors)" in result.output


def test_tampered_evidence_is_not_parsed(tmp_path):
    config, case, _, evidence = _source_and_evidence(tmp_path)
    Path(evidence["stored_path"]).write_bytes(b"tampered")
    with pytest.raises(ConflictError, match="integrity check failed"):
        analyze_evidence(
            config, case["id"], evidence["id"], reader_factory=lambda p: FakeParser(p, [])
        )


def test_evidence_change_during_read_is_reported_as_failed(tmp_path):
    config, case, _, evidence = _source_and_evidence(tmp_path)

    def changing_reader(path):
        path.write_bytes(b"changed during parse")
        return FakeParser(path, [{"timestamp": None, "data": MINIMAL_XML}])

    result = analyze_evidence(config, case["id"], evidence["id"], reader_factory=changing_reader)
    assert result["status"] == "failed"
    assert "changed during analysis" in result["error_summary"]


def test_cli_evtx_analysis_and_query_commands_with_synthetic_records(tmp_path, monkeypatch):
    config, case, _, evidence = _source_and_evidence(tmp_path)
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"data_dir": str(config.data_dir)}), encoding="utf-8")
    runner = CliRunner()

    def cli_analyze(active_config, active_case, active_evidence, rerun=False):
        return analyze_evidence(
            active_config,
            active_case,
            active_evidence,
            rerun=rerun,
            reader_factory=lambda path: FakeParser(path, [{"timestamp": None, "data": EVENT_XML}]),
        )

    monkeypatch.setattr(evtx_commands, "analyze_evidence", cli_analyze)
    options = ["--config", str(config_file), "evtx"]
    analyzed = runner.invoke(
        app, options + ["analyze", "--case", case["id"], "--evidence", evidence["id"]]
    )
    assert analyzed.exit_code == 0, analyzed.output
    assert "complete" in analyzed.output

    summary = runner.invoke(
        app,
        options
        + ["summary", "--case", case["id"], "--evidence", evidence["id"], "--format", "json"],
    )
    assert summary.exit_code == 0, summary.output
    assert json.loads(summary.output)["events_count"] == 1

    events = runner.invoke(
        app,
        options
        + [
            "list",
            "--case",
            case["id"],
            "--evidence",
            evidence["id"],
            "--channel",
            "Security",
            "--format",
            "json",
        ],
    )
    assert events.exit_code == 0, events.output
    assert json.loads(events.output)[0]["record_id"] == "42"

    shown = runner.invoke(
        app,
        options + ["show", "--case", case["id"], "--evidence", evidence["id"], "--record-id", "42"],
    )
    assert shown.exit_code == 0, shown.output
    assert json.loads(shown.output)["computer"] == "LAB-01"


def test_schema_upgrade_preserves_existing_case_and_evidence(tmp_path):
    config, case, source, evidence = _source_and_evidence(tmp_path)
    with sqlite3.connect(config.data_dir / "irx.sqlite3") as db:
        db.execute("PRAGMA user_version=0")
    with connect(config) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert (
            db.execute("SELECT id FROM cases WHERE id=?", (case["id"],)).fetchone()[0] == case["id"]
        )
        assert (
            db.execute("SELECT id FROM evidence WHERE id=?", (evidence["id"],)).fetchone()[0]
            == evidence["id"]
        )
    assert Path(evidence["stored_path"]).exists()
    assert source.exists()
