# IRX — Incident Response Framework

IRX is a local-first CLI foundation for organizing incident-response cases,
registering target labels, importing evidence files, checking their recorded
SHA-256 digests, and generating reports from data actually stored in a case.
It does not yet connect to or collect data from endpoints.

## Implemented in 0.1.0

- Typer CLI with contextual help, shell completion support, version, global
  configuration, `doctor`, and a capability inventory.
- JSON configuration validated with Pydantic; SQLite metadata store.
- Local case creation, listing, detail, close, and chronological operation log.
- Target alias registry. Registering a target records a label and address only.
- Evidence import by copying the source into case storage, calculating SHA-256
  before and after the copy, and recording the import operation.
- SHA-256 verification against the recorded digest.
- HTML and JSON reports from locally stored case, evidence, target, audit,
  and EVTX analysis summary data. Existing report paths are never overwritten.
- Structured operation metadata with secrets excluded by design.
- Local EVTX extraction from imported evidence, with SHA-256 verification,
  evidence-linked events, query filters, and partial parse error recording.

## Not implemented

Remote transport, agent, sessions, endpoint reachability testing, host/process/
network collection, persistence review, profiles, timelines, and artifact
collectors are unavailable. `irx capabilities` reports these states. The
transport requirements and security gate are described in
[`docs/PROTOCOL.md`](docs/PROTOCOL.md). There are no simulated endpoint results.

## Requirements and installation

Python 3.12 or newer is required. Install from this directory in a virtual
environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
irx --help
```

The project declares Typer, Rich, Pydantic, Jinja2, and `evtx==0.13.1`
(`pyevtx-rs`) dependencies. Pytest and Ruff are in the `dev` extra. Standard Typer shell completion is available via
`irx --install-completion`; see `irx --help` for the shell-specific command.

`pyevtx-rs` is pinned because its API yields each record's identifier, header
timestamp, and rendered event XML, and its upstream package supports Python
3.10 and newer, including Python 3.12. See the [upstream README](https://github.com/omerbenamram/pyevtx-rs/blob/0.13.1/README.md).

## Configuration

By default, IRX reads `~/.config/irx/config.json` if present and stores data in
`~/.local/share/irx`. An alternate config file is selected with the global
`--config PATH` option. Example:

```json
{
  "data_dir": "~/.local/share/irx",
  "analyst": "analyst@example.org",
  "organization": "Incident Response Lab",
  "timezone": "UTC"
}
```

Unknown configuration fields are rejected. The configuration contains no
credentials. `irx config validate` validates the configuration and initializes
the local data directory; `irx config show` prints effective values.

## Usage

```sh
irx --version
irx doctor
irx capabilities
irx case create --name "Laboratory-Incident" --analyst "Analyst One"
irx case list
irx target add --name WS-LAB-01 --address 10.0.0.25 --os Linux --case IR-...
irx evidence add --case IR-... --path ./evidence/sample.txt
irx evidence list --case IR-...
irx evidence verify --case IR-...
irx evtx analyze --case IR-... --evidence EV-...
irx evtx summary --case IR-... --evidence EV-...
irx evtx list --case IR-... --evidence EV-... --event-id 4624
irx evtx show --case IR-... --evidence EV-... --record-id 42
irx report generate --case IR-... --format html
irx report generate --case IR-... --format json --output ./case-report.json
```

Use `--format json` on list commands for machine-readable output. Report output
files are created exclusively; IRX refuses to replace an existing path. Global
options include `--verbose`, `--quiet`, `--debug`, and `--no-color`.

## Evidence and audit limitations

Import creates a working copy under the case's `evidence/originals` directory;
the source file is left in place. Verify hashes the stored copy. A digest match
detects byte changes relative to the digest recorded at import, but does not
establish source authenticity or chain of custody. The local SQLite audit log
is chronological and useful for traceability, but a system administrator can
modify it. Preserve independent originals and protect the IRX data directory
according to laboratory policy.

Reports state that they reflect only IRX's locally recorded data and include
known collection limitations. A target entry does not prove accessibility,
agent authentication, or analysis.

## Architecture

`src/irx/cli` contains Typer commands; `core` owns configuration and errors;
`storage` owns SQLite schema, repositories, evidence hashing, and EVTX results; `reporting`
renders HTML and JSON. Remote transport has intentionally not been stubbed as
an operational feature. New collectors should register explicit capabilities
and must not add arbitrary shell execution.

EVTX analysis reads only the imported copy under the case directory, verifies
its recorded SHA-256 before parsing, and stores the original event XML for
review. Existing complete or partial results for the same file digest and
parser version are reused; pass `--rerun` to create a separate analysis run.
Re-running preserves prior results. Events are extracted data, not alerts or
maliciousness classifications. Parsing does not apply detection rules, and
results should be interpreted alongside the original evidence and other
forensic context. `evtx analyze` returns exit code 0 for complete, 5 for partial,
and 4 for failed parsing; the analysis summary remains available for review.

### Validate EVTX with a real file

The optional integration test accepts an EVTX path; it does not bundle or
generate a fixture. Prefer exporting a small log from a dedicated lab VM that
you control. In Windows Event Viewer, select a lab log and use **Save All
Events As...** to save it as `.evtx`. Review it for host names, account names,
addresses, or other identifying data before sharing it. Keep evidence outside
Git; the repository ignores EVTX and common forensic image formats.

The pyevtx-rs project also lists
[`Security_short_selected.evtx`](https://github.com/omerbenamram/pyevtx-rs/tree/master/samples)
as an upstream parser sample. To fetch that file into a temporary local
checkout (requires GitHub access):

```sh
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/omerbenamram/pyevtx-rs.git /tmp/pyevtx-rs-samples
git -C /tmp/pyevtx-rs-samples sparse-checkout set samples
```

The sample is not copied into IRX. The
[upstream project metadata](https://github.com/omerbenamram/pyevtx-rs/blob/master/pyproject.toml)
declares an MIT license for its package, but a separate data license for the EVTX sample is
not stated here and its records have not been inspected for personal data.
Treat it as local-only unless you independently verify the applicable data
rights and sanitize it; do not publish it as a test fixture without clearance.

First check the EVTX signature and let the real parser read a record. Set
`EVTX_FILE` to the file you obtained; this variable is local to your shell:

```sh
export EVTX_FILE="/path/to/lab-log.evtx"
python - "$EVTX_FILE" <<'PY'
import sys
from pathlib import Path
from evtx import PyEvtxParser

path = Path(sys.argv[1]).expanduser().resolve(strict=True)
with path.open("rb") as source:
    if source.read(8) != b"ElfFile\0":
        raise SystemExit("Not an EVTX file: missing ElfFile header")
record = next(PyEvtxParser(str(path)).records(), None)
if record is None:
    raise SystemExit("EVTX contains no readable records")
print("Valid EVTX record:", record["event_record_id"], record["timestamp"])
PY
```

Then run the real-file integration test. It creates a temporary IRX case,
imports the supplied evidence, verifies SHA-256, analyzes it, checks persisted
event count and linkage, lists and shows an event, generates HTML and JSON
reports, and verifies that the source hash is unchanged:

```sh
python -m pytest -q tests/test_evtx_integration.py --evtx-file "$EVTX_FILE"
```

A passing real-file run requires a complete parse with at least one event. If
no path is supplied, that integration test is skipped; the ordinary suite's
synthetic parser tests do not count as real-EVTX validation.

For direct CLI use after setting up a case, run:

```sh
shasum -a 256 "$EVTX_FILE"  # Record this pre-import digest.
irx case create --name "EVTX lab validation"
irx evidence add --case CASE_ID --path "$EVTX_FILE"
irx evidence verify --case CASE_ID
irx evtx analyze --case CASE_ID --evidence EVIDENCE_ID
irx evtx summary --case CASE_ID --evidence EVIDENCE_ID --format json
irx evtx list --case CASE_ID --evidence EVIDENCE_ID --limit 20 --format json
irx evtx show --case CASE_ID --evidence EVIDENCE_ID --record-id RECORD_ID
irx report generate --case CASE_ID --format html
irx report generate --case CASE_ID --format json --output ./case-report.json
irx evidence verify --case CASE_ID
shasum -a 256 "$EVTX_FILE"
```

Replace the uppercase identifiers with the values returned by the preceding
commands. The final verification should report the same SHA-256 as the
pre-import hash and the initial evidence record.

## Development

```sh
python -m pytest
ruff check .
ruff format --check .
```

The tests use temporary local data directories and do not contact endpoints.
No remote-agent integration test exists because the agent is not implemented.
Run all automated checks with `python -m pytest`, `ruff check .`, and
`ruff format --check .`. To run the real-file EVTX integration, pass
`--evtx-file PATH` as shown above; do not add real case evidence to the repo.

## License

MIT. See [`LICENSE`](LICENSE).
