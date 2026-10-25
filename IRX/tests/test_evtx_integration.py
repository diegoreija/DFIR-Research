"""Optional end-to-end test against a caller-provided, real EVTX file."""

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _irx(config_path: Path, *args: str) -> str:
    env = os.environ.copy()
    source_path = str(PROJECT_ROOT / "src")
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, env.get("PYTHONPATH", "")) if part
    )
    result = subprocess.run(
        [sys.executable, "-m", "irx", "--config", str(config_path), *args],
        cwd=PROJECT_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, "IRX command failed ({}): {}\nstdout:\n{}\nstderr:\n{}".format(
        " ".join(args), result.returncode, result.stdout, result.stderr
    )
    return result.stdout.strip()


def _json_output(output: str):
    return json.loads(output)


def test_real_evtx_full_cli_flow(pytestconfig, tmp_path):
    supplied_path = pytestconfig.getoption("--evtx-file")
    if not supplied_path:
        pytest.skip("real EVTX integration test requires --evtx-file PATH")

    evtx_path = Path(supplied_path).expanduser().resolve(strict=True)
    assert evtx_path.is_file(), "--evtx-file must point to a regular file"
    with evtx_path.open("rb") as source:
        assert source.read(8) == b"ElfFile\0", "file does not have the EVTX ElfFile header"

    source_hash_before = _sha256(evtx_path)
    data_dir = tmp_path / "irx-data"
    config_path = tmp_path / "irx-config.json"
    config_path.write_text(json.dumps({"data_dir": str(data_dir)}), encoding="utf-8")

    created = _irx(config_path, "case", "create", "--name", "EVTX integration validation")
    case_match = re.search(r"Created case ([^ ]+)", created)
    assert case_match, "case create did not return a case identifier"
    case_id = case_match.group(1)

    imported = _irx(config_path, "evidence", "add", "--case", case_id, "--path", str(evtx_path))
    evidence_match = re.search(r"as (EV-[A-F0-9]+)", imported)
    assert evidence_match, "evidence add did not return an evidence identifier"
    evidence_id = evidence_match.group(1)

    first_verify = _json_output(
        _irx(config_path, "evidence", "verify", "--case", case_id, "--format", "json")
    )
    assert first_verify["ok"] is True
    evidence_row = next(row for row in first_verify["results"] if row["id"] == evidence_id)
    assert evidence_row["actual_sha256"] == source_hash_before

    _irx(config_path, "evtx", "analyze", "--case", case_id, "--evidence", evidence_id)
    summary = _json_output(
        _irx(
            config_path,
            "evtx",
            "summary",
            "--case",
            case_id,
            "--evidence",
            evidence_id,
            "--format",
            "json",
        )
    )
    assert summary["status"] == "complete"
    assert summary["events_count"] > 0
    assert summary["parse_error_count"] == 0

    events = _json_output(
        _irx(
            config_path,
            "evtx",
            "list",
            "--case",
            case_id,
            "--evidence",
            evidence_id,
            "--limit",
            "1",
            "--format",
            "json",
        )
    )
    assert events, "event list returned no rows despite a positive summary count"
    assert events[0]["record_id"] is not None
    shown = _json_output(
        _irx(
            config_path,
            "evtx",
            "show",
            "--case",
            case_id,
            "--evidence",
            evidence_id,
            "--record-id",
            str(events[0]["record_id"]),
        )
    )
    assert "<Event" in shown["raw_xml"]

    db_path = data_dir / "irx.sqlite3"
    with sqlite3.connect(db_path) as db:
        persisted = db.execute(
            "SELECT COUNT(*) FROM evtx_events WHERE analysis_id=?", (summary["id"],)
        ).fetchone()[0]
        linked = db.execute(
            "SELECT case_id,evidence_id,source_sha256 FROM evtx_analyses WHERE id=?",
            (summary["id"],),
        ).fetchone()
    assert persisted == summary["events_count"]
    assert linked == (case_id, evidence_id, source_hash_before)

    html_output = _irx(config_path, "report", "generate", "--case", case_id, "--format", "html")
    html_match = re.search(r"Report written: (.+)", html_output)
    assert html_match
    html_report = Path(html_match.group(1))
    assert html_report.is_file()
    assert "EVTX analysis summaries" in html_report.read_text(encoding="utf-8")
    assert str(summary["events_count"]) in html_report.read_text(encoding="utf-8")

    json_report_path = tmp_path / "case-report.json"
    _irx(
        config_path,
        "report",
        "generate",
        "--case",
        case_id,
        "--format",
        "json",
        "--output",
        str(json_report_path),
    )
    report_data = json.loads(json_report_path.read_text(encoding="utf-8"))
    assert report_data["evtx_analyses"][0]["events_count"] == summary["events_count"]

    final_verify = _json_output(
        _irx(config_path, "evidence", "verify", "--case", case_id, "--format", "json")
    )
    assert final_verify["ok"] is True
    assert _sha256(evtx_path) == source_hash_before
    assert (
        next(row for row in final_verify["results"] if row["id"] == evidence_id)["actual_sha256"]
        == source_hash_before
    )
