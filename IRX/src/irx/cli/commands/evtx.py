"""Commands for local, evidence-linked EVTX analysis."""

from typing import Optional

import typer

from irx.cli.commands.common import emit
from irx.core.exceptions import ConflictError
from irx.storage.evtx import (
    analysis_summary,
    analyze_evidence,
    list_events,
    show_event,
)

app = typer.Typer(help="Analyze and query imported Windows EVTX evidence.")


@app.command("analyze")
def evtx_analyze(
    ctx: typer.Context,
    case_id: str = typer.Option(..., "--case", "-c", help="Case identifier."),
    evidence_id: str = typer.Option(..., "--evidence", "-e", help="Imported evidence identifier."),
    rerun: bool = typer.Option(
        False, "--rerun", help="Create a new analysis while keeping prior results."
    ),
):
    """Parse an imported EVTX file after checking its recorded SHA-256."""
    result = analyze_evidence(ctx.obj["config"], case_id, evidence_id, rerun=rerun)
    typer.echo(
        "Analysis {}: {} ({} events, {} parse errors){}".format(
            result["id"],
            result["status"],
            result["events_count"],
            result["parse_error_count"],
            " (reused existing result)" if result.get("reused") else "",
        )
    )
    if result["status"] == "failed":
        raise typer.Exit(code=4)
    if result["status"] == "partial":
        raise typer.Exit(code=5)


@app.command("summary")
def evtx_summary(
    ctx: typer.Context,
    case_id: str = typer.Option(..., "--case", "-c"),
    evidence_id: str = typer.Option(..., "--evidence", "-e"),
    analysis_id: Optional[str] = typer.Option(None, "--analysis-id"),
    fmt: str = typer.Option("table", "--format", "-f"),
):
    """Show the selected or latest analysis counts and time range."""
    if fmt not in ("table", "json"):
        raise typer.BadParameter("Format must be table or json")
    emit(analysis_summary(ctx.obj["config"], case_id, evidence_id, analysis_id), fmt)


@app.command("list")
def evtx_list(
    ctx: typer.Context,
    case_id: str = typer.Option(..., "--case", "-c"),
    evidence_id: str = typer.Option(..., "--evidence", "-e"),
    analysis_id: Optional[str] = typer.Option(None, "--analysis-id"),
    after: Optional[str] = typer.Option(
        None, "--after", help="Inclusive ISO-8601 UTC/timezone timestamp."
    ),
    before: Optional[str] = typer.Option(
        None, "--before", help="Inclusive ISO-8601 UTC/timezone timestamp."
    ),
    event_id: Optional[str] = typer.Option(None, "--event-id"),
    channel: Optional[str] = typer.Option(None, "--channel"),
    provider: Optional[str] = typer.Option(None, "--provider"),
    computer: Optional[str] = typer.Option(None, "--computer"),
    limit: int = typer.Option(100, min=1, max=10000),
    fmt: str = typer.Option("table", "--format", "-f"),
):
    """List extracted events, optionally filtering stored Windows event fields."""
    if fmt not in ("table", "json"):
        raise typer.BadParameter("Format must be table or json")
    try:
        after_value = _normalize_filter_time(after)
        before_value = _normalize_filter_time(before)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if after_value and before_value and after_value > before_value:
        raise ConflictError("--after must be earlier than or equal to --before")
    events = list_events(
        ctx.obj["config"],
        case_id,
        evidence_id,
        analysis_id,
        after_value,
        before_value,
        event_id,
        channel,
        provider,
        computer,
        limit,
    )
    emit(events, fmt)


@app.command("show")
def evtx_show(
    ctx: typer.Context,
    case_id: str = typer.Option(..., "--case", "-c"),
    evidence_id: str = typer.Option(..., "--evidence", "-e"),
    record_id: str = typer.Option(..., "--record-id", help="Windows EventRecordID."),
    analysis_id: Optional[str] = typer.Option(None, "--analysis-id"),
):
    """Show all stored fields and original XML for one event record."""
    emit(show_event(ctx.obj["config"], case_id, evidence_id, record_id, analysis_id), "json")


def _normalize_filter_time(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    from datetime import datetime, timezone

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Filter timestamps must include a timezone, for example Z")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
