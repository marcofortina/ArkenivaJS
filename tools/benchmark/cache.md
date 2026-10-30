<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Redis cache comparison

Build the workspace and use the private environment runner from the
[owned Redis fixture](../../packages/database-redis/test/fixtures/README.md):

```sh
python3 packages/database-redis/test/fixtures/run.py /private/redis-environment.json \
  pnpm --filter @arkenivajs/benchmark-foundation cache --verify /private/cache-verification
```

The harness requires explicit disposable-fixture opt-in, authenticated Redis TLS
on the owned loopback forward and a supplied CA. Native `redis` and the public
Redis/cache plugins run in four fresh isolated processes, including actual
standard/detailed SDK exports. Direct raw commands independently inspect the
versioned JSON envelope, finite native TTL, expiry and corrupt-state preservation.
Cache reads must return fresh values; successful and repeated deletion return
their actual distinct outcomes. No in-memory adapter participates.

Each invocation owns one random namespace. Cleanup removes only its four exact
keys before closing its connection; finite TTL also bounds interrupted residue.
Reports and exports exclude values, key namespace, credentials, local addresses
and CA paths. No credential environment mapping is retained in reports.

`--verify` records functional evidence without latency or resource samples.
`--smoke` exercises 20 warmup and at least 100 sequential acknowledged
set/get/delete roundtrips per profile, with actual value/deletion assertions.
Each recorded operation is three commands, not three independently timed samples.
Whole child CPU and sampled memory include client work, wrapper serialization,
instrumentation and measurement overhead; Redis server CPU is not measured.

The baseline performs Ajv envelope validation on this fixed valid JSON corpus.
Framework recursive traversal/capture limits, cancellation, admission, lifecycle
and observation policies add work. Their full hostile-input policy is not
duplicated by the baseline. This does not measure tenant authorization or
multi-pod concurrency. Both modes retain `releaseGate: false`; performance budgets,
five paired repetitions and a one-hour soak remain separate acceptance work.

The Redis integration CI job runs `test:integration:cache` on all supported Node
lines. It validates both bounded harness modes and a healthy wrong-SAN endpoint;
those tests verify execution and TLS rejection, without accepting timing budgets.
