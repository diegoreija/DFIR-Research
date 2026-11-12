# KeyDis Inspector — DFIR CLI (development branch)

Rust CLI for evidence-first Windows PE triage and JSONL event filtering. This is an **early implementation**, not a validated solution to all 19 HTB KeyDis tasks.

## Build

```bash
cd keydis-inspector
cargo build --release
cargo run -- --help
```

## Supported commands

```bash
cargo run -- hash --input sample.exe --algorithm sha256
cargo run -- pe --input sample.exe --view imports
cargo run -- compiler --input sample.exe
cargo run -- api --input sample.exe --category keyboard --limit 10
cargo run -- strings --input sample.exe --contains http --ignore-case --limit 20
cargo run -- hex --input sample.exe --offset 0x104 --length 32
cargo run -- offset --input sample.exe --offset 0x104 --length 16
cargo run -- ioc --input sample.exe
cargo run -- keylogger --input sample.exe --vk-code 0x14
cargo run -- crypto --input sample.exe
cargo run -- exfil --input sample.exe
cargo run -- config --input sample.exe
cargo run -- analyze --input sample.exe --profile keydis
cargo run -- analyze --input sample.exe --task 1
cargo run -- report --input sample.exe --output report.json
cargo run -- compare --file-a sample1.exe --file-b sample2.exe
```

## Timeline / events (JSONL input only)

Each input line must be a JSON object containing an RFC3339 `timestamp`. Optional filters use `event_id` (number) and `process` (string). This version **does not parse EVTX or PCAP**.

```jsonl
{"timestamp":"2026-11-01T08:12:04Z","event_id":1,"process":"sample.exe","activity":"Process created"}
{"timestamp":"2026-11-01T08:12:07Z","event_id":3,"process":"sample.exe","activity":"Network connection"}
```

```bash
cargo run -- timeline --input events.jsonl --start-time 2026-11-01T08:00:00Z --end-time 2026-11-01T09:00:00Z
cargo run -- events --input events.jsonl --around 2026-11-01T08:12:00Z --window 10m --event-id 3
```

## Accuracy and security boundaries

- The PE timestamp is untrusted and is **not proof** of actual build time.
- Compiler identification, crypto keys, behavior and exfiltration are reported as inconclusive without direct evidence.
- `offset` and `hex` operate on **file offsets**, not RVAs or disassembly-relative offsets.
- IOC findings are unverified candidates.
- Config strings are redacted by default; `--show-secrets` reveals candidates and may expose sensitive data in logs.
- Never execute untrusted malware on your host; this tool reads input files statically.
- No actual KeyDis malware sample has been tested, and the build has **not yet been verified in CI**.

## Roadmap

1. Compile/test in Rust CI; add unit and integration tests with benign fixtures.
2. Implement disassembly, evidence references, API hash algorithm identification, compiler fingerprinting and actual KeyDis-specific analysis.
3. Add native EVTX/PCAP parsers and more advanced temporal correlations.
4. Add YARA scanning, archive inspection and case persistence.
