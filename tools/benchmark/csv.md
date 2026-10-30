# Native CSV and TSV functional comparison

Build the workspace and select a fresh absolute directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation csv --verify /private/csv-verification
```

Four isolated Node profiles use csv-parse 7.0.3 and csv-stringify 6.9.0,
the public CSV plugin and the actual standard/detailed telemetry modes.
Every input and output stream is exhausted. The fixed corpus checks comma,
tab and semicolon delimiters, BOM, one-byte UTF-8 fragments, embedded newlines,
quotes, empty cells, Unicode, leading zeros and empty streams. Tests also
exchange native/public encoded rows in both directions, preserve input bytes
and prove that one-shot sources are consumed once.

Only `--verify` is supported. Reports use `measured: false`, null resources,
no timing samples and `releaseGate: false`. `--smoke` fails before creating
workers or evidence. Streaming acceptance still needs time-to-first-byte,
backpressure and observed buffer measurements; completed row counts do not
establish rows/sec, memory limits or release performance budgets.

The bare SDK baseline handles a fixed valid corpus. It does not reproduce
framework schema validation, finite resource admission, fatal UTF-8 handling,
spreadsheet formula policy or cancellation guarantees. These remain covered
by the runtime package tests. No full-file buffering occurs inside the native
adapter; the test verifier collects only the small fixed fixture for assertions.
Record contents must remain absent from telemetry and reports. No repeated
campaign, one-hour soak or release acceptance is claimed.
