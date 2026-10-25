import json
from pathlib import Path

import pytest

from irx.core.exceptions import ConflictError
from irx.core.exceptions import PermissionError as IRXPermissionError
from irx.core.models import IRXConfig
from irx.reporting.reports import generate_report
from irx.storage import evidence as evidence_storage
from irx.storage.evidence import add_evidence, verify_evidence
from irx.storage.repository import create_case, list_evidence


def test_evidence_import_verify_and_report(tmp_path):
    config = IRXConfig(data_dir=tmp_path / "irx-data", analyst="lab-analyst")
    source = tmp_path / "sample.txt"
    source.write_text("known laboratory evidence\n", encoding="utf-8")
    case = create_case(config, "Laboratory Incident")

    item = add_evidence(config, case["id"], source)
    assert item["sha256"] == "c63a23603f9cf29d667f0afec9c6b37a39421eb17975ef9985e86818b954c4e2"
    assert verify_evidence(config, case["id"])["ok"] is True

    report = generate_report(config, case["id"], "json")
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["case"]["id"] == case["id"]
    assert payload["evidence"][0]["id"] == item["id"]
    with pytest.raises(ConflictError, match="Refusing to overwrite"):
        generate_report(config, case["id"], "json", report)


def test_evidence_tampering_is_detected(tmp_path):
    config = IRXConfig(data_dir=tmp_path / "irx-data")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"original")
    case = create_case(config, "Integrity test")
    item = add_evidence(config, case["id"], source)
    with open(item["stored_path"], "wb") as stored:
        stored.write(b"modified")
    result = verify_evidence(config, case["id"], item["id"])
    assert result["ok"] is False
    assert result["results"][0]["actual_sha256"] != result["results"][0]["expected_sha256"]


def test_existing_evidence_path_is_never_removed_on_collision(tmp_path, monkeypatch):
    config = IRXConfig(data_dir=tmp_path / "irx-data")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"source")
    case = create_case(config, "Collision test")
    destination = Path(case["storage_path"]) / "evidence" / "originals" / "EV-FIXED-sample.bin"
    destination.write_bytes(b"pre-existing evidence")
    monkeypatch.setattr(evidence_storage, "make_id", lambda prefix: "EV-FIXED")

    with pytest.raises(ConflictError):
        add_evidence(config, case["id"], source)

    assert destination.read_bytes() == b"pre-existing evidence"


def test_evidence_directory_symlink_cannot_escape_case_storage(tmp_path):
    config = IRXConfig(data_dir=tmp_path / "irx-data")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"source")
    case = create_case(config, "Path containment test")
    case_root = Path(case["storage_path"])
    evidence_directory = case_root / "evidence" / "originals"
    outside = tmp_path / "outside"
    outside.mkdir()
    evidence_directory.rmdir()
    evidence_directory.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ConflictError, match="outside the case storage"):
        add_evidence(config, case["id"], source)

    assert list(outside.iterdir()) == []


def test_read_error_is_reported_and_does_not_register_evidence(tmp_path, monkeypatch):
    config = IRXConfig(data_dir=tmp_path / "irx-data")
    source = tmp_path / "unreadable.bin"
    source.write_bytes(b"source")
    case = create_case(config, "Read error test")

    def fail_hash(_path):
        raise PermissionError("read denied")

    monkeypatch.setattr(evidence_storage, "sha256_file", fail_hash)
    with pytest.raises(IRXPermissionError, match="Cannot read source file"):
        add_evidence(config, case["id"], source)

    assert list_evidence(config, case["id"]) == []
    assert list((Path(case["storage_path"]) / "evidence" / "originals").iterdir()) == []
