# Contributing

Use Python 3.12 or newer. Create an isolated environment and install the
development dependencies with `python -m pip install -e '.[dev]'`.

Before submitting a change, run `python -m pytest`, `ruff check .`, and
`ruff format --check .` from this directory. Add tests for new storage and CLI
behavior. Tests must use temporary directories and must not contact real
endpoints.

Only advertise a capability after its implementation and tests exist. Remote
features must fail closed on authentication errors, use a documented operation
allowlist, and include controlled integration tests before being marked
available. Never add arbitrary remote shell execution or commit credentials,
keys, or real evidence.
