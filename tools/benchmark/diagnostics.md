# Process diagnostics comparison

Build the workspace, then use a fresh absolute output directory outside the repository:

```sh
pnpm --filter @arkenivajs/benchmark-foundation diagnostics --verify /private/diagnostics-verification
```

The tool starts four fresh sequential Node processes: bare native counters,
the public diagnostics plugin, and the actual standard/detailed SDK profiles.
Each verifies twenty frozen snapshots against native CPU bounds, the current
process identity, real UTC timestamps and positive native memory values.
The optional delay histogram is disabled. Interval event-loop utilization may
be absent before any activity; different processes need not report equal ratios.

`--verify` records functional evidence with `measured: false`, no latency samples
and no resource measurement result. `--smoke` exercises the optional sampling
path with Tinybench: one snapshot operation, 1,000 warmup iterations and at least
10,000 completed samples per profile. Sampling is exploratory tool verification,
not release performance acceptance; every report retains `releaseGate: false`.

CPU counters are cumulative process measurements, memory values are instantaneous,
and comparison resources cover the entire isolated process. They cannot be
attributed to a tenant or request. There is no application input corpus. No
artificial spans or metrics are added to the snapshot method; standard/detailed
modes use the actual SDK and retain its export/drop checks. With this pure
snapshot operation the owned collector receives no telemetry bodies; zero
exports are expected and do not demonstrate exporter delivery.

The baseline uses the same native process and perf-hooks sources, freezes its
snapshot and tracks the same interval semantics. Framework construction,
validation and lifecycle remain additional work. No five-repetition campaign,
one-hour soak, dedicated-runner budget or production performance claim is made.
