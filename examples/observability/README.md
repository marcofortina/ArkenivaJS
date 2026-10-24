# Logging and process diagnostics example

This executable example uses the public core, logging and diagnostics packages. It starts an isolated application, emits contextual Pino JSON, captures native process measurements and closes its plugins in a `finally` block. No external service or credential is required.

From the workspace root, use the pinned package manager on Node.js 24:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-observability start
pnpm --filter @arkenivajs/example-observability test
```

The program emits two JSON lines. The warning includes `service`, `requestId`, `component`, an ISO timestamp and Pino severity `40`. Its nested password is `[REDACTED]`; the typed error exposes only its safe code and message. The info line has severity `30` and a `snapshot` containing the real process id, cumulative CPU microseconds and current RSS/heap bytes. Values vary with the process. The opt-in event-loop histogram collects during a short wait; optional measurements remain absent when no usable sample is available.

The snapshot measures the whole process. The request id provides log correlation and does not allocate CPU or memory to that request. See the [diagnostics guide](../../packages/diagnostics/README.md) for units, provenance and intervals, and the [logging guide](../../packages/logging/README.md) for contextual scopes, redaction and transport counters.

The destination is caller-owned. Successful flush means its write callbacks acknowledged the lines, with no promise of downstream durability. If a destination fails or fails to acknowledge before the deadline, flush rejects with a typed error; the example still attempts application cleanup and its CLI emits a safe error envelope with a nonzero exit status. Check transport counters, output permissions and configured severity when investigating missing logs. Do not place unknown confidential values in free-form messages.

Tests capture actual JSON output, verify redaction and native measurements, and run the built CLI in a separate process with a finite deadline to check shutdown.
