# Acknowledged structured logging comparison

Build the workspace and choose a fresh absolute output directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation logging --verify /private/logging-verification
```

Four fresh sequential Node profiles exercise Pino 10.4.0 directly, the public
logging plugin and actual standard/detailed SDK modes. Every profile uses the
same synchronous acknowledging Writable destination with JSON parsing and
privacy checks. Preflight verifies actual redacted output, immutable input
fields, child bindings and level filtering against received rows.

`--verify` records `measured: false`, no timing samples and null resource results.
`--smoke` tests two operations, `info` and `childInfo`, with 100 warmup iterations
and at least 1,000 samples each. A final flush checks actual rows against sampled
and warmup work. It records byte/row acknowledgements and verifies the public
logger's real drop, write-failure, flush-failure and pending-byte counters.
Bare Pino has no invented equivalents for those framework counters.

The private fixture value must not appear in received JSON, telemetry or the
report. Redaction parity is limited to this fixed nested structured field;
the framework retains its broader message scrubbing, safe error handling,
context isolation, bounds and lifecycle policy. No artificial per-log spans or
metrics are added. SDK export/drop checks remain active.

Destination JSON parsing and validation costs are included equally in every
profile. Synchronous destination acknowledgement is not disk/fsync durability
or proof of a remote log collector. Construction and final flush are outside
per-call timing; process resources remain aggregate values. Reports always use
`releaseGate: false`. No asynchronous-backpressure, production transport budget,
five-repeat campaign or one-hour soak acceptance is claimed.
