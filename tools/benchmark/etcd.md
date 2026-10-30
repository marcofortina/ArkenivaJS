<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native etcd revision, watch and lease verification

Build the workspace and load the private environment for the
[owned authenticated mTLS fixture](../../packages/database-etcd/test/fixtures/README.md):

```sh
python3 packages/database-etcd/test/fixtures/run.py /private/etcd-environment.json \
  pnpm --filter @arkenivajs/benchmark-foundation etcd --verify /private/etcd-verification
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

An independent observer checks the random namespace absent before claiming
ownership and empty after all profiles. Cleanup deletes only that exact owned
namespace. Reports and actual SDK exports exclude keys, prefixes, values,
connection strings and identity paths. Prefixes do not authenticate tenants.

The native valid-corpus reference omits portable input admission, cancellation
ownership, stream gap handling and lease ownership policy. Compaction,
disconnect/reconnect, expiry duration and multi-member failover remain separate
conformance scenarios. Only `--verify` is supported until complete client/server
resource accounting is available. Reports retain `releaseGate: false`; no full
performance campaign, five repetitions or one-hour soak acceptance is claimed.
