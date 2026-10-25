# @arkenivajs/database-postgres

PostgreSQL pools for the portable SQL facade, using pinned `pg` 8.23.1,
`pg-cursor` 2.22.1 and `pg-connection-string` 2.14.1. Importing the package or
creating an application does not open a connection. Every configured pool is
validated and checked at application startup, and closed during reverse cleanup.

```ts
import { createApplication } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';

const app = await createApplication({
  service: { name: 'orders-service', version: '1.0.0', environment: 'development' },
  plugins: [postgresPlugin()],
  databases: {
    main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 10 },
  },
});
await app.start();
try {
  const result = await app.sql.query('main', {
    text: 'SELECT :id::bigint AS id',
    bindings: { id: 9007199254740993n },
  });
  console.log(result.rows);
} finally {
  await app.stop();
}
```

The zero-argument factory composes one application-owned SQL coordinator. Several
named PostgreSQL pools and other explicitly installed SQL drivers share `app.sql`.
Configuration lives in the root `databases` map. PostgreSQL uses
`connectionStringEnv`; an `endpoints` definition rejects. Pool minimum defaults to
0 and maximum to 10. As in `pg`, minimum is an idle-retention floor and does not
eagerly create that many connections. The startup check establishes connectivity.

## Connection and trust policy

The named environment value must contain a PostgreSQL URL with explicit host,
user and database. Credentials are captured at startup; the adapter does not fall
back to `PGPASSWORD` or an implicit `.pgpass` file. A password can be absent for an
explicit peer/client-certificate authentication setup, in which case the adapter
does not obtain a replacement secret from another source.

Network connections use certificate and endpoint identity verification, including
IP literals. Production network connections and shared development networks
require TLS. An isolated development/test loopback URL may use plaintext, as may
an explicit local Unix socket. `sslmode=no-verify` and other policies disabling
certificate verification reject. Use `sslmode=verify-full` and, for a private CA,
`sslrootcert` in the environment URL. Native certificate/key file options remain
explicit environment configuration. Never log that URL or the native pool config.

The default SQL deadline is **15,000 ms**, including acquisition, matching
`DEFAULT_SQL_TIMEOUT_MS`. An explicit positive `timeoutMs` overrides it.
Native connection/acquisition timeout is bounded to five seconds. An operation's
`timeoutMs` can impose an earlier total deadline, including pool wait. The portable
adapter owns the client deadline and disables `pg`'s separate `query_timeout`;
server-side `statement_timeout` can still be set explicitly. The portable protocol
uses UTF-8 and disables native query pipelining, which is incompatible with its
bounded cursor lifecycle.

## Queries and values

Named binds are compiled by `@arkenivajs/database`, with exact keys and separate
parameters. PostgreSQL repeats one `$N` index for repeated names. Caller Date and
binary data are captured before asynchronous work; queued transaction statements
compile with the actual session's `standard_conforming_strings` setting.

Results use a per-pool text-protocol policy. Boolean, int2/int4/OID and approximate
float values use JavaScript boolean/number. Bytea uses Buffer. Bigint, numeric,
date/time, JSON/JSONB, arrays and other types retain text, preserving integer,
decimal, temporal microsecond and JSON-number precision. Supply a custom native
query type parser when an advanced consumer deliberately wants another policy.
An explicitly native binary-format query uses `pg`'s binary type parsers; choose
per-query native decoders when their numeric/temporal precision needs another policy.
Date inputs represent instants at JavaScript millisecond precision; a textual
timestamp input can retain PostgreSQL microseconds.

`query` materializes at most `maxRows` (default 10,000, range 1..100,000), with
native fetches bounded to 256 rows plus a limit sentinel. Excess rows reject with
`EK_DATABASE_QUERY` and `details.limitExceeded=true`. `queryOne` fetches at most two
rows and rejects on the second. No partial result is returned as success.
`execute` retains backend-provided RETURNING rows and uses the same default bound.
This does not bound server execution cost, and an execution error or client result
limit is not evidence that a standalone write had no effects. Use an explicit
transaction for rollback on application failure; never blindly replay a write.

PostgreSQL portal completion tags report the final Execute batch's row count,
including for DML RETURNING. After multiple fetches, `rowCount` is therefore null
and unreliable `affectedRows` is omitted. `rows.length` remains the observed
materialized row count. A reliable single-fetch native count is retained, including
zero and affected counts for DML without RETURNING. No count is guessed.

## Transactions and lifecycle

`transaction(name, callback, options)` acquires one pinned connection, begins,
awaits the callback and its queued statements, then commits; rejection rolls back.
Statements on one handle serialize, including Promise.all calls. Always await
statement promises. Nested transactions and pool reentry reject; manual portable
BEGIN/COMMIT/ROLLBACK/savepoint/preparation commands use the native escape hatch.
Handles belong only to their active callback and cannot be borrowed by another
request. No operation or callback is retried automatically.

A lost socket or deadline during COMMIT reports `EK_DATABASE_TRANSACTION` with
`details.outcome='unknown'` and `retryable=false`. Reconcile using application
idempotency keys. A known server rollback is reported separately. Primary callback
and cleanup failures remain in the aggregate cause. Cancellation discards active
connections; an abandoned pool wait releases a connection acquired later.

Portable checkouts discard previous session state and restore UTF-8/standard
strings. Native prepared-statement caches are synchronized with that reset.
Do not rely on session roles, temporary tables, listeners or settings surviving
between portable calls. Use the transaction handle for transaction-local state.
Acquisitions and queued transaction statements have an outstanding-work bound of
at least 128 per pool, or the larger explicitly configured pool maximum.

## Error classification

Native causes remain internal. Safe details retain only a bounded SQLSTATE when
available; default logs omit statements, bindings and vendor detail messages.

| Condition                                                 | Framework code                                    |
| --------------------------------------------------------- | ------------------------------------------------- |
| Missing environment definition/value                      | `EK_CONFIG_MISSING`                               |
| Invalid connection/TLS, bindings, limits or encoding      | `EK_CONFIG_INVALID`                               |
| Pool capacity or acquisition deadline exhausted           | `EK_DATABASE_POOL_TIMEOUT`                        |
| Failed acquisition or unavailable active connection       | `EK_DATABASE_CONNECT` / `EK_DATABASE_UNAVAILABLE` |
| SQLSTATE class 23, including duplicate key 23505          | `EK_DATABASE_CONSTRAINT`                          |
| Serialization failure 40001 or deadlock 40P01             | `EK_DATABASE_CONFLICT`                            |
| Deadline or server cancellation 57014                     | `EK_TIMEOUT`                                      |
| Caller/application cancellation                           | `EK_ABORTED`                                      |
| Invalid transaction ownership/control or uncertain commit | `EK_DATABASE_TRANSACTION`                         |
| Other execution/cleanup failure                           | `EK_DATABASE_QUERY`                               |
| Use after pool closure                                    | `EK_RESOURCE_CLOSED`                              |

Conflict classification can set `retryable=true`, but never replays a callback.
The live suite races two serializable writers and verifies one committed update,
one actual SQLSTATE 40001 and exactly one invocation of each callback. It also
checks acquisition deadlines while a native borrower holds the only pool slot.

## Native API and observation

`app.sql.native(name)` returns the actual `pg.Pool`. Borrowed native clients must
be released before application shutdown. Native queries can use driver-specific
arrays, JSON conversion, binary formats, COPY/streaming and explicit savepoints;
their type/instrumentation policy belongs to that advanced call. Portable defaults
still apply to queries without an explicit native override.

Obtaining a native handle in an active managed meter scope marks
`not_instrumented`. A handle retained outside a scope cannot reveal its later usage
to the framework: explicitly account for those advanced operations. Host OpenTelemetry
auto-instrumentation must exclude `pg` when framework-owned SQL instrumentation
is active, to avoid duplicate observations.

Optional logger, telemetry and meter ports come through declared dependencies.
Each observed portable client statement records one `db.query` attempt and measured
`db.client.elapsed` milliseconds in the active trusted meter scope. Internal
checkout and transaction-control statements are excluded from that application
statement counter. Pool acquire duration is separate from query duration. Spans
use CLIENT kind; diagnostic failures never replay SQL or replace its result.
Default error logs contain a statement fingerprint and bounded error code, never
SQL text or bind values. Transport bytes and server CPU/I/O are unobserved and not
fabricated; managed scopes mark `driver_bytes_unavailable`.

`stats` reports native total/idle/waiting counts, checked-out-or-connecting count
(`active = total - idle`), outstanding framework acquisitions, client statement
attempts and observer failures. These are pool/process observations, not server
resource attribution to a tenant.

## Verification

Current local live evidence covers PostgreSQL **18.6**, Linux x86-64 in an isolated
VM, Node **22.23.4 / 24.22.1 / 26.12.1**, and the dependency versions above. The application role is
not a superuser and cannot create databases or roles. Other server/runtime claims
require their own passing integration evidence.

Unit/contract tests run without a database. Live tests require
`ARKENIVA_POSTGRES_URL` and a trusted-CA, wrong-hostname endpoint at
`ARKENIVA_POSTGRES_WRONG_SAN_URL`; missing infrastructure fails explicitly.
Set `ARKENIVA_POSTGRES_DISPOSABLE=1` only for a disposable test server; the suite
deliberately creates schemas and terminates its own transaction backend.
Run `pnpm test:integration:postgres` from the workspace root.
Tests isolate their own schemas and clean up their pools. They verify real rows,
constraints, rollback, pinned connections, mutable-value capture, TLS and
cancellation, plus distinct commit-acknowledgment fault scenarios.

The [disposable TLS fixture](test/fixtures/README.md) reproduces the server setup
and negative certificate endpoint in an isolated VM or CI runner. CI executes
the combined 95% line/branch coverage gate on all three supported Node versions.
The [orders example](../../examples/postgres/README.md) builds against the actual
packages and verifies exact values, duplicate rejection and rollback on that server.

| Driver                      | Server          | Node                      | Platform               | Live verification date |
| --------------------------- | --------------- | ------------------------- | ---------------------- | ---------------------- |
| pg 8.23.1, pg-cursor 2.22.1 | PostgreSQL 18.6 | 22.23.4, 24.22.1, 26.12.1 | Linux x86-64, QEMU/KVM | 2026-10-24             |

Upstream references: [pool lifecycle](https://node-postgres.com/apis/pool),
[cursors](https://node-postgres.com/apis/cursor),
[transactions](https://node-postgres.com/features/transactions),
[TLS](https://node-postgres.com/features/ssl), and
[data types](https://node-postgres.com/features/types).

With an optional health collector installed, the plugin performs a fresh
readonly native readiness probe through its owned client and bounded operation
scope. Health runs after owner initialization, before inbound listeners activate;
public provider facades still require application READY. Scoped hook integration
tests use the actual authenticated disposable server and reject stale callbacks
and pre-aborted operations. Health never closes the native owner's client.
