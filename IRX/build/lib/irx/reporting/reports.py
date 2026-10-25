"""JSON and HTML reports derived from stored case data."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from jinja2 import Environment, select_autoescape

from irx.core.exceptions import ConflictError, NotFoundError
from irx.core.models import IRXConfig
from irx.storage.repository import audit, get_case, get_operations, list_evidence, list_targets

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>IRX case {{ case.id }}</title>
<style>
body{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17212b}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #ccd3d9;padding:.5rem;text-align:left}
th{background:#edf2f6}
code{overflow-wrap:anywhere}
.note{background:#fff7dd;padding:1rem}
</style>
</head>
<body>
<h1>{{ case.name }}</h1>
<p><strong>Case:</strong> {{ case.id }} · <strong>Status:</strong> {{ case.status }}</p>
<p>{{ case.description }}</p>
<p><strong>Started:</strong> {{ case.started_at }} ({{ case.timezone }})</p>
<h2>Targets</h2>
<table>
<tr><th>Name</th><th>Address</th><th>OS</th></tr>
{% for row in targets %}
<tr><td>{{ row.name }}</td><td>{{ row.address }}</td><td>{{ row.os or "Unknown" }}</td></tr>
{% else %}
<tr><td colspan="3">No targets registered.</td></tr>
{% endfor %}
</table>
<h2>Evidence</h2>
<table>
<tr><th>ID</th><th>Name</th><th>SHA-256</th><th>Bytes</th><th>Added</th></tr>
{% for row in evidence %}
<tr><td>{{ row.id }}</td><td>{{ row.name }}</td><td><code>{{ row.sha256 }}</code></td>
<td>{{ row.size_bytes }}</td><td>{{ row.added_at }}</td></tr>
{% else %}
<tr><td colspan="5">No evidence registered.</td></tr>
{% endfor %}
</table>
<h2>Operations</h2>
<table>
<tr><th>Time</th><th>Action</th><th>Result</th><th>Details</th></tr>
{% for row in operations %}
<tr><td>{{ row.timestamp }}</td><td>{{ row.action }}</td><td>{{ row.result }}</td>
<td>{{ row.error or "" }}</td></tr>
{% else %}
<tr><td colspan="4">No operations recorded.</td></tr>
{% endfor %}
</table>
<h2>Limitations</h2>
<p class="note">This report reflects only data recorded in IRX at generation time.
A SHA-256 match detects byte changes relative to the recorded digest; it does not establish
authenticity or chain of custody. Local SQLite audit records can be modified by a user with
filesystem access. Remote endpoint collection is not implemented in this release.</p>
<footer>Generated {{ generated_at }} by IRX.</footer>
</body>
</html>"""


def build_report_data(config: IRXConfig, case_id: str) -> Dict[str, Any]:
    case = get_case(config, case_id)
    if case is None:
        raise NotFoundError("Case not found: {}".format(case_id))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "case": case,
        "targets": [target for target in list_targets(config) if target["case_id"] == case_id],
        "evidence": list_evidence(config, case_id),
        "operations": get_operations(config, case_id),
        "limitations": [
            "Report contains only information stored in IRX.",
            "A hash match does not prove authenticity or chain of custody.",
            "Local audit records are not immutable against filesystem administrators.",
            "Remote collection is not implemented in this release.",
        ],
    }


def generate_report(
    config: IRXConfig, case_id: str, fmt: str, output: Optional[Path] = None
) -> Path:
    if fmt not in ("html", "json"):
        raise ConflictError("Unsupported report format: {} (choose html or json)".format(fmt))
    data = build_report_data(config, case_id)
    directory = Path(data["case"]["storage_path"]) / "reports"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = (
        output.expanduser().resolve()
        if output
        else directory
        / ("report-{}.{}".format(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), fmt))
    )
    if destination.exists():
        raise ConflictError("Refusing to overwrite existing report: {}".format(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        if fmt == "json":
            rendered = json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n"
        else:
            env = Environment(autoescape=select_autoescape(default=True))
            rendered = env.from_string(HTML_TEMPLATE).render(**data)
        with destination.open("x", encoding="utf-8") as target:
            target.write(rendered)
    except OSError as exc:
        raise ConflictError("Cannot write report {}: {}".format(destination, exc)) from exc
    audit(
        config,
        "report.generate",
        "completed",
        case_id=case_id,
        parameters={"format": fmt, "output": str(destination)},
    )
    return destination
