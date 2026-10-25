"""Top-level IRX Typer application."""

import os
import sys
import traceback
from pathlib import Path
from typing import Optional

import typer

from irx import __version__
from irx.cli.commands import cases, diagnostics, evidence, evtx, reports, targets
from irx.core.config import load_config
from irx.core.exceptions import IRXError

app = typer.Typer(
    name="irx",
    help="Local-first incident response case and evidence management.",
    invoke_without_command=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=True,
)
app.add_typer(diagnostics.capabilities_app, name="capabilities")
app.add_typer(diagnostics.config_app, name="config")
app.add_typer(cases.app, name="case")
app.add_typer(targets.app, name="target")
app.add_typer(evidence.app, name="evidence")
app.add_typer(evtx.app, name="evtx")
app.add_typer(reports.app, name="report")


@app.command("doctor")
def doctor_command(ctx: typer.Context):
    """Check the local Python runtime, dependencies, and writable storage."""
    result = diagnostics.doctor(ctx.obj["config"])
    if result:
        raise typer.Exit(code=result)


@app.command("status")
def status_command(ctx: typer.Context):
    """Summarize local case and evidence counts; no endpoint probes are made."""
    from irx.storage.database import connect
    from irx.storage.repository import list_cases, list_targets

    config = ctx.obj["config"]
    with connect(config) as db:
        evidence_count = db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    typer.echo(
        "Local cases: {} | targets: {} | evidence items: {}".format(
            len(list_cases(config)), len(list_targets(config)), evidence_count
        )
    )


@app.callback()
def root(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", is_eager=True, help="Show the installed version and exit."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show additional operational detail."
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress nonessential success messages."
    ),
    debug: bool = typer.Option(
        False, "--debug", help="Show diagnostic tracebacks for unexpected errors."
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable Rich terminal colors."),
    config_path: Optional[Path] = typer.Option(
        None, "--config", help="Read configuration from JSON PATH."
    ),
):
    """Configure global output behavior and select the local JSON config file."""
    if version:
        typer.echo(__version__)
        raise typer.Exit(code=0)
    if verbose and quiet:
        raise typer.BadParameter("--verbose and --quiet cannot be used together")
    if no_color:
        os.environ["NO_COLOR"] = "1"
    ctx.obj = {
        "config": load_config(config_path),
        "verbose": verbose,
        "quiet": quiet,
        "debug": debug,
    }


def main() -> None:
    """Console script entry point with stable, concise error reporting."""
    try:
        # Let Typer handle its own usage errors and normal Exit exceptions.
        app()
    except IRXError as exc:
        typer.echo("Error: {}".format(exc), err=True)
        raise SystemExit(exc.exit_code) from exc
    except Exception as exc:
        # Recover the parsed --debug flag where possible without exposing tracebacks by default.
        debug = "--debug" in sys.argv
        if debug:
            traceback.print_exc()
        else:
            typer.echo("Internal error: {} (rerun with --debug for details)".format(exc), err=True)
        raise SystemExit(1) from exc
