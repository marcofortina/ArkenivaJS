<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Readiness probe comparison

Build the workspace and choose a fresh absolute report directory outside it:

```sh
pnpm --filter @arkenivajs/benchmark-foundation health --verify /private/health-verification
```

Four fresh sequential Node processes run the same owned loopback HTTP dependency
probe: direct Node HTTP, the public health plugin, and the actual standard/detailed
telemetry SDK profiles. Each verifies eight healthy readiness snapshots, changes
the fixture dependency to HTTP 503, confirms failed readiness while liveness stays
live, and restores the dependency. The fixture counts actual requests and changes;
neither a callback stub nor a fabricated readiness result can satisfy verification.

Reports and SDK exports exclude the fixture address and response marker. The
framework emits its actual readiness-duration histogram, without adding synthetic
per-probe spans. Native HTTP responses are fully consumed and connections closed.
Only the parent-owned loopback fixture exposes the bounded readiness control.

`--verify` records functional evidence without latency or resource samples.
`--smoke` exercises one sequential asynchronous `ready` workload per profile with
20 warmup iterations and at least 100 completed samples. Process CPU, sampled
RSS/heap, event-loop and GC observations cover the whole child measurement phase,
not a tenant or individual probe. Both modes keep `releaseGate: false`.

The direct baseline invokes the same actual HTTP callback and reports its result.
Framework registry ownership, startup probes, automatic plugin checks, concurrent
probe coalescing, deadline cleanup and lifecycle policy remain additional work.
This comparison does not measure HTTP health-route middleware, distributed service
latency, startup/shutdown overhead or cancellation under load. It does not replace
dedicated-runner performance budgets, five repetitions or a one-hour soak.
