"""Local endpoint registry commands."""

from typing import Optional

import typer

from irx.cli.commands.common import emit
from irx.core.exceptions import ConflictError, NotFoundError
from irx.storage.repository import add_target, get_case, get_target, list_targets

app = typer.Typer(help="Register endpoint identities for case documentation.")


@app.command("add")
def target_add(
    ctx: typer.Context,
    name: str = typer.Option(..., "--name", "-n", help="Unique target alias."),
    address: str = typer.Option(..., "--address", "-a", help="Hostname or IP address."),
    os_name: Optional[str] = typer.Option(None, "--os", help="Known operating system."),
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Optional associated case."),
):
    """Add a target label and address; this does not test reachability."""
    config = ctx.obj["config"]
    if not name.strip() or not address.strip():
        raise ConflictError("Target name and address cannot be empty")
    if case_id and get_case(config, case_id) is None:
        raise NotFoundError("Case not found: {}".format(case_id))
    try:
        target = add_target(config, name.strip(), address.strip(), os_name, case_id)
    except Exception as exc:
        # Convert the SQLite uniqueness constraint into an actionable CLI message.
        if "UNIQUE constraint failed" in str(exc):
            raise ConflictError("A target with that name already exists") from exc
        raise
    typer.echo("Registered target {} at {}. No connection was attempted.".format(name, address))
    if ctx.obj.get("verbose"):
        typer.echo("Target ID: {}".format(target["id"]))


@app.command("list")
def target_list(
    ctx: typer.Context,
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table or json."),
):
    """List registered targets; registration does not imply accessibility."""
    if fmt not in ("table", "json"):
        raise ConflictError("Format must be table or json")
    emit(list_targets(ctx.obj["config"]), fmt)


@app.command("show")
def target_show(
    ctx: typer.Context, name_or_id: str = typer.Argument(..., help="Target alias or identifier.")
):
    """Show a registered target without connecting to it."""
    target = get_target(ctx.obj["config"], name_or_id)
    if target is None:
        raise NotFoundError("Target not found: {}".format(name_or_id))
    emit(target, "json")
