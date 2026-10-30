# Identifier comparison

The UUID workload compares the public identifier service with `node:crypto`
`randomUUID()` and `uuid@14.0.3`, including the same canonical/version policy for
parsing and validation. UUIDv7 uses explicit options in both implementations.
Identifiers are not authorization tokens, and the uniqueness preflight is only
a bounded sanity check.

Run functional verification after building the workspace:

```sh
pnpm --filter @arkenivajs/benchmark-foundation identifiers --verify /private/new-identifier-verification
```

The absolute output directory must be new, outside the checkout, with an existing
parent. Four sequential child processes exercise `BASELINE`, `FRAMEWORK`,
`STANDARD` and `DETAILED`. Each checks actual generation, canonical parsing and
invalid versions. Verification writes `measured:false` and no timing results.

An explicitly requested exploratory measurement uses `--smoke` instead of
`--verify`. Tinybench warms up each operation for 1,000 iterations and retains
10,000 samples. Reports contain nanosecond latency quantiles, operations per
second and aggregate child-process CPU, memory, event-loop and GC observations.
Sampling and timer overhead remain part of this short microcomparison. CPU and
memory are process totals, not resource usage attributed to an individual UUID.

Identifier methods have no automatic per-operation telemetry. The standard and
detailed profiles install the actual telemetry SDK without adding artificial
spans or counters. Export quality and received payload counts are reported even
when no payload is emitted. Input identifiers never appear in reports or labels.

Both commands set `releaseGate:false`. Neither one repetition nor the functional
preflight establishes a performance budget, randomness proof, distributed UUIDv7
ordering or production acceptance. Complete comparative campaigns, five repeated
runs and soak evidence require their separate approved execution profile.
