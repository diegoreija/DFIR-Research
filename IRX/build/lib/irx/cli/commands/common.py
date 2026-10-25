"""Shared CLI output helpers."""

import json
from typing import Any

import typer
from rich.console import Console
from rich.table import Table


def emit(data: Any, fmt: str = "table") -> None:
    if fmt == "json":
        typer.echo(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    elif isinstance(data, list):
        if not data:
            typer.echo("No records found.")
            return
        table = Table(show_header=True, header_style="bold cyan")
        for key in data[0].keys():
            if key not in ("storage_path", "source_path", "stored_path", "parameters_json"):
                table.add_column(str(key))
        for row in data:
            table.add_row(
                *[
                    str(row.get(key) if row.get(key) is not None else "")
                    for key in data[0].keys()
                    if key not in ("storage_path", "source_path", "stored_path", "parameters_json")
                ]
            )
        Console().print(table)
    else:
        typer.echo(json.dumps(data, indent=2, ensure_ascii=False, default=str))
