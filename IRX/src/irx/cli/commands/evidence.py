"""Case evidence import and integrity verification commands."""

from pathlib import Path
from typing import Optional

import typer

from irx.cli.commands.common import emit
from irx.core.exceptions import NotFoundError
from irx.storage.evidence import add_evidence, verify_evidence
from irx.storage.repository import get_case, list_evidence

app = typer.Typer(help="Import, list, and verify evidence files stored with cases.")


@app.command("add")
def evidence_add(
    ctx: typer.Context,
    case_id: str = typer.Option(..., "--case", "-c", help="Open case identifier."),
    path: Path = typer.Option(
        ...,
        "--path",
        "-p",
        exists=True,
        readable=True,
        help="Source file to copy into case evidence storage.",
    ),
):
    """Copy a source file into a case and record its SHA-256 digest."""
    item = add_evidence(ctx.obj["config"], case_id, path)
    typer.echo("Imported {} as {} (SHA-256 {})".format(item["name"], item["id"], item["sha256"]))
    if ctx.obj.get("verbose"):
        typer.echo("Stored copy: {}".format(item["stored_path"]))


@app.command("list")
def evidence_list(
    ctx: typer.Context,
    case_id: str = typer.Option(..., "--case", "-c", help="Case identifier."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table or json."),
):
    """List evidence recorded for a case."""
    config = ctx.obj["config"]
    if get_case(config, case_id) is None:
        raise NotFoundError("Case not found: {}".format(case_id))
    if fmt not in ("table", "json"):
        raise typer.BadParameter("Format must be table or json")
    emit(list_evidence(config, case_id), fmt)


@app.command("verify")
def evidence_verify(
    ctx: typer.Context,
    case_id: str = typer.Option(..., "--case", "-c", help="Case identifier."),
    evidence_id: Optional[str] = typer.Option(None, "--id", help="Verify one evidence item."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table or json."),
):
    """Recompute SHA-256 from stored evidence and compare with its recorded digest."""
    if fmt not in ("table", "json"):
        raise typer.BadParameter("Format must be table or json")
    result = verify_evidence(ctx.obj["config"], case_id, evidence_id or "")
    emit(result, "json" if fmt == "json" else "table")
    if not result["ok"]:
        raise typer.Exit(code=4)
