<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Core capability resolution comparison

Build the workspace and choose a fresh absolute external report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation core --verify /private/core-verification
```

Four isolated profiles compare native Map lookup with actual public
`app.resolve`/`app.tryResolve`, including installed standard/detailed SDK profiles.
Checks preserve the same immutable capability identity, optional absence and
required absence errors. Each framework process also verifies rejection before
READY and after CLOSED, before acknowledging completion to the parent.

Capability lookup deliberately emits no per-lookup span or metric. The tool
does not add synthetic instruments to make exports appear. The actual installed
SDK must report zero lookup instruments/spans and the collector receives no
lookup bodies. This scenario does not exercise exporter delivery. The private
capability value is also excluded from the structured report.

`--verify` records functional evidence without samples. `--smoke` measures two
batch operations after 100 warmups, with at least 1000 samples each. Every batch
performs 256 lookups and consumes the returned values. Reported latency and
throughput are per batch, not individually timed nanosecond lookup samples.
The fixed hot key permits normal JIT optimization and does not represent dynamic
tenant dispatch. Native Map omits framework lifecycle/dependency checks and
typed errors; whole child CPU and sampled memory include measurement overhead.

Both modes retain `releaseGate: false`. Full application startup/shutdown,
export delivery, dedicated-runner performance budgets, five paired repetitions
and a one-hour soak remain separate workloads and acceptance work.
