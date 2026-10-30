<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native etcd revision, watch and lease verification

Build the workspace and load the private environment for the
[owned authenticated mTLS fixture](../../packages/database-etcd/test/fixtures/README.md):

```sh
python3 packages/database-etcd/test/fixtures/run.py /private/etcd-environment.json \
  pnpm --filter @arkenivajs/benchmark-foundation etcd --verify /private/etcd-verification
python3 packages/database-etcd/test/fixtures/run.py /private/etcd-environment.json \
  pnpm --filter @arkenivajs/benchmark-foundation etcd --smoke /private/etcd-smoke
```

Four isolated profiles compare pinned `etcd3@1.1.2` with the public provider and
actual standard/detailed SDK instrumentation. Actual server operations preserve
binary values and exact bigint revision/version metadata. Concurrent CAS calls
using the same revision have exactly one winner. Three watch events retain
order, bytes and revisions. A real lease attaches a key, accepts keepalive and
is explicitly revoked; independent native TTL readback first observes aging,
then an acknowledged increase after keepalive. Native readback confirms key removal and
server lease retirement.

Both paths capture explicit private client identities and CA material before
connecting, disable unary retry policies and require verified localhost mTLS.
Healthy native/public controls precede wrong-hostname and unauthorized-client
rejection checks. The native reference uses ordinary driver builders, native
watch responses and a lease with automatic keepalive disabled; its explicit
keepalive is one native request, while the public API starts its managed loop.
This verifies effects, without claiming identical background renewal scheduling.

An independent parent observer checks four distinct random profile namespaces
absent before claiming ownership and empty after cleanup. Cleanup deletes only
those exact owned namespaces. Reports and actual SDK exports exclude keys, prefixes, values,
connection strings and identity paths. Prefixes do not authenticate tenants.

The native valid-corpus reference omits portable input admission, cancellation
ownership, stream gap handling and lease ownership policy. Compaction,
disconnect/reconnect, expiry duration and multi-member failover remain separate
conformance scenarios. `--verify` preserves its existing watch, concurrent CAS,
lease-aging/renewal and negative TLS/identity controls without latency sampling.

`--smoke` adds one narrow scenario: a create-only transaction using
`compareAndSwap({expectedRevision: 0n, ...})` on a fresh owned key for every
callback. Each profile executes 20 warmup callbacks and exactly 100 retained
Tinybench samples. Every sequential callback awaits the actual successful
transaction acknowledgment. There is no harness callback retry or hidden queue.
One extra create-only CAS against an existing key must return false after timing;
it must not change the bytes or version of that key.

The parent independently reads every created key through a separate pinned
native `etcd3` client after all profiles finish. Each range is limited to 121
records (120 expected plus one overflow sentinel), 32 KiB of observed key/value
bytes and a 64 KiB gRPC receive limit. It verifies exactly 480 keys overall,
their exact binary values, version one and positive modification revisions that
increase with each profile's sequential callbacks. Revisions stay as bigint;
global revisions need not be adjacent. Only numeric summaries reach reports.
The keys are then removed and every exact owned namespace is independently
checked empty; cleanup is also attempted in `finally` on failure.

This measures fresh-key CAS creation, not update-CAS, watch/lease throughput,
multi-member concurrency or failover. Worker process resource observations
exclude the parent readback client and external etcd server; those resource
costs remain explicitly unknown (`null`). Reports retain `releaseGate: false`;
no complete resource parity, calibrated performance budget, five repetitions
or one-hour soak acceptance is claimed. Unsupported modes reject before opening
a native connection.
