<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Ordered persistent SSE events

[PostgresRealtimeSource](src/realtime-source.ts) implements the public `SseSource`
contract using the existing named SQL provider and actual authentication service.
Run `createRealtimeTables(sql, connectionName, ownedSchema)` as an explicit
application migration. The schema must already exist. Names are restricted to
allowlisted PostgreSQL identifiers; event values always use bound parameters.

Construct a source with `(sql, auth, connectionName, ownedSchema)`, append through
`append(verifiedTenant, {type,data})`, and register the source in the realtime
startup catalog. The source verifies runtime identity provenance independently.
The same issuer/tenant partition uses one locked sequence row, so concurrent
writers commit in sequence order. Event IDs are random UUIDs, not account data.
Replay starts strictly after the supplied owned cursor. Polls return at most 64
rows, use a 1-second SQL budget, and stop when the subscriber's signal aborts.

Each partition admits at most 1,000 retained events. `retainFrom(tenant,id)` is an
explicit retention operation: the named event and later events remain available;
older payloads are cleared. The latest 256 older IDs remain recognizable as
expired and return HTTP 410; older removed or unknown IDs return 409. A foreign
tenant's ID always returns 409. There is no automatic truncation when append
capacity is reached. Applications must schedule retention and bound the number
of tenant partitions according to their own lifecycle policy.

New subscriptions without a cursor start at the current retained head. An active
subscriber overtaken by retention terminates instead of silently jumping forward;
the next reconnect receives the explicit cursor error. Retention can race an
already committed HTTP response, so the current connection may close before the
next reconnect reports 410. Delivery is ordered per issuer/tenant partition and
at least once across reconnects; clients must tolerate duplicate events. No
exactly-once, global ordering, cross-region durability or automatic failover is
claimed. PostgreSQL durability and backup settings remain deployment-owned.

The integration test uses real signed JWTs, two independent SQL owners and the
actual HTTP listener. It verifies concurrent append, listener restart, strict
replay, foreign/unknown/expired cursors and safe failure after the source SQL
owner is stopped. Run it only against an explicitly disposable verified-TLS
PostgreSQL fixture:

```sh
node --test examples/postgres/dist-test/integration/realtime.integration.test.js
```
