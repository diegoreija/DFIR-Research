"""Local investigation case commands."""

from typing import List, Optional

import typer

from irx.cli.commands.common import emit
from irx.core.exceptions import ConflictError, NotFoundError
from irx.storage.repository import close_case, create_case, get_case, list_cases

app = typer.Typer(help="Create and manage local investigation cases.")


@app.command("create")
def case_create(
    ctx: typer.Context,
    name: str = typer.Option(..., "--name", "-n", help="Human-readable case name."),
    case_id: Optional[str] = typer.Option(None, "--id", help="Optional unique case identifier."),
    description: str = typer.Option("", "--description", help="Investigation scope or summary."),
    analyst: Optional[str] = typer.Option(None, "--analyst", help="Responsible analyst."),
    organization: Optional[str] = typer.Option(None, "--organization", help="Organization or lab."),
    tags: List[str] = typer.Option([], "--tag", help="Case tag; repeat as needed."),
    timezone: Optional[str] = typer.Option(
        None, "--timezone", help="Reference timezone (default UTC)."
    ),
):
    """Create a case directory and its local metadata record."""
    if not name.strip():
        raise ConflictError("Case name cannot be empty")
    case = create_case(
        ctx.obj["config"], name.strip(), case_id, description, analyst, organization, tags, timezone
    )
    typer.echo("Created case {} ({})".format(case["id"], case["name"]))
    if ctx.obj.get("verbose"):
        typer.echo("Storage: {}".format(case["storage_path"]))


@app.command("list")
def case_list(
    ctx: typer.Context,
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table or json."),
):
    """List local cases, newest first."""
    if fmt not in ("table", "json"):
        raise ConflictError("Format must be table or json")
    emit(list_cases(ctx.obj["config"]), fmt)


@app.command("show")
def case_show(
    ctx: typer.Context,
    case_id: str = typer.Argument(..., help="Case identifier."),
    fmt: str = typer.Option("json", "--format", "-f", help="Output format: json."),
):
    """Show case metadata and its chronological operation log."""
    case = get_case(ctx.obj["config"], case_id)
    if case is None:
        raise NotFoundError("Case not found: {}".format(case_id))
    if fmt != "json":
        raise typer.BadParameter("Format must be json")
    emit(case, "json")


@app.command("close")
def case_close(ctx: typer.Context, case_id: str = typer.Argument(..., help="Case identifier.")):
    """Close a case to prevent additional evidence imports."""
    if not close_case(ctx.obj["config"], case_id):
        raise NotFoundError("Open case not found: {}".format(case_id))
    typer.echo("Closed case {}".format(case_id))
