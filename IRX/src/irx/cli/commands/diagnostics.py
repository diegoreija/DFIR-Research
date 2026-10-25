"""Version, status, doctor, capabilities, and configuration commands."""

import json
import os
import sys
from importlib.metadata import PackageNotFoundError, version

import typer
from rich.console import Console
from rich.table import Table

from irx.core.config import initialize_data_dir
from irx.core.exceptions import ConfigurationError
from irx.core.models import IRXConfig
from irx.storage.database import connect, database_path

capabilities_app = typer.Typer(help="Inspect implemented and unavailable IRX capabilities.")
config_app = typer.Typer(help="Show and validate local IRX configuration.")


@capabilities_app.callback(invoke_without_command=True)
def capabilities(ctx: typer.Context):
    """Show the supported operations and known limitations of this build."""
    if ctx.invoked_subcommand:
        return
    entries = [
        {
            "capability": "local_cases",
            "status": "implemented",
            "details": "SQLite-backed local case metadata",
        },
        {
            "capability": "targets",
            "status": "implemented",
            "details": "Local target registry; no reachability claims",
        },
        {
            "capability": "evidence_import",
            "status": "implemented",
            "details": "Copy source into case storage and record SHA-256",
        },
        {
            "capability": "evidence_verify",
            "status": "implemented",
            "details": "Compare stored bytes to recorded SHA-256",
        },
        {
            "capability": "evtx_analysis",
            "status": "implemented",
            "details": "Local event field extraction only; no detection or maliciousness labels",
        },
        {
            "capability": "reports",
            "status": "implemented",
            "details": "JSON and HTML from locally recorded data",
        },
        {
            "capability": "audit",
            "status": "implemented",
            "details": "Structured local SQLite operation log; mutable by admins",
        },
        {
            "capability": "remote_transport",
            "status": "unavailable",
            "details": "No authenticated transport or remote agent shipped",
        },
        {
            "capability": "host_process_network_collectors",
            "status": "unavailable",
            "details": "Endpoint collection is not implemented",
        },
        {
            "capability": "timeline_profiles_persistence",
            "status": "planned",
            "details": "No operational collectors in this release",
        },
    ]
    table = Table("Capability", "Status", "Details", header_style="bold cyan")
    for item in entries:
        table.add_row(item["capability"], item["status"], item["details"])
    Console().print(table)


@config_app.command("show")
def config_show(ctx: typer.Context):
    """Show the effective configuration with defaults applied."""
    cfg = ctx.obj["config"]
    typer.echo(json.dumps(cfg.model_dump(mode="json"), indent=2))


@config_app.command("validate")
def config_validate(ctx: typer.Context):
    """Validate the selected JSON configuration and data directory."""
    cfg = ctx.obj["config"]
    initialize_data_dir(cfg)
    typer.echo("Configuration is valid. Data directory: {}".format(cfg.data_dir))


def doctor(config: IRXConfig) -> int:
    checks = [
        ("Python", sys.version_info >= (3, 12), sys.version.split()[0] + " (requires >=3.12)"),
        ("Data directory", True, str(config.data_dir)),
    ]
    for package in ("typer", "rich", "pydantic", "jinja2", "evtx"):
        try:
            checks.append((package, True, version(package)))
        except PackageNotFoundError:
            checks.append((package, False, "not installed"))
    try:
        initialize_data_dir(config)
        with connect(config):
            pass
        checks.append(("SQLite", True, str(database_path(config))))
        checks.append(("Data directory writable", os.access(config.data_dir, os.W_OK), ""))
    except (OSError, ConfigurationError) as exc:
        checks.append(("Storage", False, str(exc)))
    table = Table("Check", "Status", "Details", header_style="bold cyan")
    failed = False
    for name, ok, details in checks:
        table.add_row(name, "OK" if ok else "FAIL", details)
        failed = failed or not ok
    table.add_row("Remote agent", "UNAVAILABLE", "Not implemented in this release")
    Console().print(table)
    return 1 if failed else 0
