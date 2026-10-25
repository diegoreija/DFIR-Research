"""Case report generation commands."""

from pathlib import Path
from typing import Optional

import typer

from irx.core.exceptions import ConflictError
from irx.reporting.reports import generate_report

app = typer.Typer(help="Generate reports from data recorded in a case.")


@app.command("generate")
def report_generate(
    ctx: typer.Context,
    case_id: str = typer.Option(..., "--case", "-c", help="Case identifier."),
    fmt: str = typer.Option("html", "--format", "-f", help="Report format: html or json."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Destination path. Existing files are never overwritten."
    ),
):
    """Write a JSON or HTML case report from stored case records."""
    if fmt not in ("html", "json"):
        raise ConflictError("Format must be html or json")
    path = generate_report(ctx.obj["config"], case_id, fmt, output)
    typer.echo("Report written: {}".format(path))
