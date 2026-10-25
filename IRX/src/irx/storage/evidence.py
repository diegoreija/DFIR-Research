"""Evidence import and SHA-256 verification."""

import hashlib
import shutil
from pathlib import Path
from typing import Dict

from irx.core.exceptions import ConflictError, NotFoundError
from irx.core.exceptions import PermissionError as IRXPermissionError
from irx.core.models import IRXConfig, utc_now
from irx.storage.repository import (
    audit,
    get_case,
    get_evidence,
    insert_evidence,
    list_evidence,
    make_id,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _remove_imported_copy(path: Path, created: bool) -> None:
    """Remove only a file this operation created; never unlink a collision."""
    if not created:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise ConflictError(
            "Could not remove partial evidence copy {}: {}".format(path, exc)
        ) from exc


def _io_error(action: str, exc: OSError) -> Exception:
    if isinstance(exc, FileNotFoundError):
        error_type = NotFoundError
    elif isinstance(exc, PermissionError):
        error_type = IRXPermissionError
    else:
        error_type = ConflictError
    return error_type("Cannot {} evidence: {}".format(action, exc))


def add_evidence(config: IRXConfig, case_id: str, source_path: Path) -> Dict[str, object]:
    case = get_case(config, case_id)
    if case is None:
        raise NotFoundError("Case not found: {}".format(case_id))
    if case["status"] != "open":
        raise ConflictError("Evidence cannot be added to a closed case")
    try:
        source = source_path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise _io_error("resolve source path for", exc) from exc
    if not source.is_file():
        raise ConflictError("Evidence source must be a regular file")
    evidence_id = make_id("EV")
    try:
        case_root = Path(case["storage_path"]).resolve(strict=True)
    except OSError as exc:
        raise _io_error("resolve case storage directory", exc) from exc
    evidence_directory = case_root / "evidence" / "originals"
    try:
        resolved_evidence_directory = evidence_directory.resolve(strict=True)
    except OSError as exc:
        raise _io_error("resolve case evidence directory", exc) from exc
    if not resolved_evidence_directory.is_relative_to(case_root):
        raise ConflictError("Evidence directory resolves outside the case storage directory")
    destination = resolved_evidence_directory / (evidence_id + "-" + source.name)
    try:
        before = sha256_file(source)
    except OSError as exc:
        raise _io_error("read source file", exc) from exc
    created_destination = False
    try:
        with source.open("rb") as original:
            with destination.open("xb") as imported:
                created_destination = True
                shutil.copyfileobj(original, imported, length=1024 * 1024)
    except OSError as exc:
        _remove_imported_copy(destination, created_destination)
        raise _io_error("copy source file", exc) from exc
    try:
        after = sha256_file(destination)
        size_bytes = destination.stat().st_size
    except OSError as exc:
        _remove_imported_copy(destination, created_destination)
        raise _io_error("verify copied file", exc) from exc
    if before != after:
        _remove_imported_copy(destination, created_destination)
        raise ConflictError("Evidence changed during import; copy was discarded")
    item = {
        "id": evidence_id,
        "case_id": case_id,
        "name": source.name,
        "source_path": str(source),
        "stored_path": str(destination),
        "sha256": after,
        "size_bytes": size_bytes,
        "added_at": utc_now(),
        "status": "verified",
    }
    try:
        insert_evidence(config, item)
    except Exception:
        _remove_imported_copy(destination, created_destination)
        raise
    audit(
        config,
        "evidence.add",
        "completed",
        case_id=case_id,
        parameters={"evidence_id": evidence_id, "sha256": after, "size_bytes": item["size_bytes"]},
    )
    return item


def verify_evidence(config: IRXConfig, case_id: str, evidence_id: str = "") -> Dict[str, object]:
    if get_case(config, case_id) is None:
        raise NotFoundError("Case not found: {}".format(case_id))
    items = (
        [get_evidence(config, case_id, evidence_id)]
        if evidence_id
        else list_evidence(config, case_id)
    )
    items = [item for item in items if item is not None]
    if evidence_id and not items:
        raise NotFoundError("Evidence not found: {}".format(evidence_id))
    if not items:
        raise NotFoundError("No evidence is registered for case {}".format(case_id))
    results = []
    for item in items:
        path = Path(item["stored_path"])
        error = None
        try:
            actual = sha256_file(path) if path.is_file() else None
            if actual is None:
                error = "Stored evidence file is missing or is not a regular file"
        except OSError as exc:
            actual = None
            error = "Cannot read stored evidence file: {}".format(exc)
        results.append(
            {
                "id": item["id"],
                "expected_sha256": item["sha256"],
                "actual_sha256": actual,
                "ok": actual == item["sha256"],
                "error": error,
            }
        )
    ok = all(row["ok"] for row in results)
    audit(
        config,
        "evidence.verify",
        "completed" if ok else "failed",
        case_id=case_id,
        parameters={"evidence_id": evidence_id or None, "verified": len(results)},
    )
    return {"case_id": case_id, "ok": ok, "results": results}
