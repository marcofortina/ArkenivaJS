# @arkenivajs/database-mysql

MySQL Promise pools for the portable SQL facade, using pinned `mysql2` **3.24.6**.
Imports, the zero-argument factory and application creation open no connections.
Startup validates every named configuration, warms the requested minimum and
authenticates a readiness query. Reverse application cleanup closes all pools.

```ts
import { createApplication } from '@arkenivajs/core';
import { mysqlPlugin } from '@arkenivajs/database-mysql';

const app = await createApplication({
  service: { name: 'orders', version: '1.0.0', environment: 'production' },
  plugins: [mysqlPlugin()],
  databases: {
    main: { driver: 'mysql', connectionStringEnv: 'MYSQL_URL', poolMax: 10 },
  },
});
await app.start();
try {
  const row = await app.sql.queryOne('main', {
    text: 'SELECT :id AS id',
    bindings: { id: 9007199254740993n },
  });
  console.log(row);
} finally {
  await app.stop();
}
```

The factory explicitly composes the common SQL coordinator; multiple named pools
and other installed SQL drivers share `app.sql`. Only definitions with
`driver: 'mysql'` belong to this adapter. MariaDB has a separate native adapter.

## Connection policy

`MYSQL_URL` is the **name you configure**, not an implicitly consulted variable.
Its value is a `mysql://user:password@hostname:3306/database` URL with explicit
host, user and database. Percent-encode credentials and database names as URL
components. Credentials are captured at startup, with no ambient fallback.
Only the optional `ssl` and `sslca` query parameters are accepted, once each.

Network TLS verifies the CA chain and the configured DNS identity. Production and
shared networks require TLS. Use `?ssl=verify-full` and, for a private CA, append
`&sslca=%2Fabsolute%2Fpath%2Fca.crt`. Native certificate verification is never
disabled. With this mysql2 version, verified TLS requires a **DNS hostname**;
an IP URL rejects before acquisition because the native TLS identity path omits
an IP server name. Use the DNS identity present in the certificate. The adapter
does not claim verified IP support or replace the native TLS/MySQL protocol.
An isolated development/test loopback connection may explicitly use `ssl=disable`;
loopback defaults to that local policy when no TLS option is given.

Pool minimum defaults to 0 and maximum to 10, with `0 <= min <= max`.
The minimum warms that many native connections at startup; mysql2 retains up to
the configured maximum. It does not promise that failed connections remain live.
Connection and acquisition waits are bounded to **5,000 ms**. The total SQL
deadline is **15,000 ms** unless a positive `timeoutMs` overrides it, including
pool wait and queued transaction work. A shorter acquisition budget wins first.
Outstanding framework acquisitions and callback statements are each bounded to
128 per pool, or the larger configured pool maximum.

The adapter fixes UTF-8 (`utf8mb4_unicode_ci`), UTC, exact big-number strings,
textual dates and JSON, separate prepared parameters, a bounded native statement
cache, no SQL interpolation, no multiple statements and no local-file uploads.
URL options cannot override these policies.

## Queries and conversion

The common finite-state lexer compiles exact `:name` bindings to `?`, repeating
values in occurrence order. Missing/extra names reject before native execution.
Dates and binary values are captured before asynchronous queueing. Transaction
statements compile against the actual session's `NO_BACKSLASH_ESCAPES` and
`ANSI_QUOTES` modes. Executable comments and ambiguous native syntax use the
native API. SQL identifiers require an application allowlist; they cannot be bound.

Prepared binary result streams retain at most `maxRows` (default 10,000,
range 1..100,000) plus the overflow sentinel. An excess row rejects with
`EK_DATABASE_QUERY` and `details.limitExceeded=true`; no truncated success is
returned. `queryOne` accepts at most two rows and rejects on the second. Native
stream backpressure and a one-object high-water mark avoid unbounded native row
arrays. An early stop discards the connection before destroying the stream.
This bounds client materialization, not server execution or transport buffers.

BIGINT, DECIMAL, date/time values and JSON retain strings, preserving integer,
decimal, JSON-number and temporal microsecond precision. Integer literals can
also have MySQL BIGINT type, so `SELECT 1` may return `'1'`. Smaller integer and
approximate floating types retain native numbers; TINYINT booleans remain 0/1.
BLOB values are Buffers. Bigint binds are exact decimal strings, binary binds
are copied Buffers, and Date binds use UTC at JavaScript millisecond precision.

Completed SELECT `rowCount` is the number of observed rows. For native command
headers, a safe affected-row count becomes `rowCount` and `metadata.affectedRows`;
an unsafe/unknown count remains null and is omitted from metadata. Exact native
`insertId` strings and safe numbers are retained. `warningStatus` is a native
header field: positive bounded counts are logged with a safe fingerprint when a
logger is installed. The shared `SqlResult` type has no warning field; advanced
consumers obtain the complete `ResultSetHeader` through mysql2's native API.
Stored procedures and multiple result sets require that escape hatch.

## Transactions and effects

`transaction(name, callback, options)` pins one connection, resets its prior
session state, begins, serializes callback statements and commits once. Rejected
callbacks roll back. Always await statement promises. A failed queued statement prevents
commit even if the callback catches its rejection. Callback results and primitive
exceptions retain their identity; cleanup failures preserve both causes in an
aggregate. Nested transactions, stale/cross-request handles and pool reentry are
rejected by the common coordinator. Portable manual transaction/savepoint control
uses the callback or the explicit native API.

**MySQL DDL can implicitly commit.** Do not mix DDL with business writes expecting
rollback atomicity. When a native command header reports that the transaction
ended, the adapter rejects with `EK_DATABASE_TRANSACTION`,
`details.outcome='implicitly_committed'` and `retryable=false`, and discards the
connection. Previously committed effects remain. The live test verifies those
effects rather than treating a subsequent error as evidence of rollback.

A lost connection or deadline during COMMIT reports
`EK_DATABASE_TRANSACTION`, `details.outcome='unknown'` and `retryable=false`.
Reconcile using domain idempotency keys. No SQL or callback is replayed.
Cancellation discards active native connections; abandoned acquisitions still own
their eventual leases and release them without executing the abandoned statement.

Each portable checkout uses public native `reset()`, which also invalidates
mysql2's prepared statement cache, then restores UTF-8, UTC, autocommit and an
explicit `STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION` mode. Session variables,
temporary objects and settings do not survive between portable calls. Within a
transaction, mode evidence is refreshed after successful statements; a subsequent
portable call rejects if UTF-8 or UTC has changed.

## Errors and observation

| Condition                                           | Framework code                                    |
| --------------------------------------------------- | ------------------------------------------------- |
| Missing definition or environment value             | `EK_CONFIG_MISSING`                               |
| Invalid URL, TLS policy, binds or bounds            | `EK_CONFIG_INVALID`                               |
| Pool capacity or acquisition budget exhausted       | `EK_DATABASE_POOL_TIMEOUT`                        |
| Failed acquisition / active socket loss             | `EK_DATABASE_CONNECT` / `EK_DATABASE_UNAVAILABLE` |
| Duplicate 1062, null 1048, FK 1451/1452, check 3819 | `EK_DATABASE_CONSTRAINT`                          |
| Deadlock 1213 or lock wait 1205                     | `EK_DATABASE_CONFLICT`                            |
| Server cancellation 1317/3024 or owned deadline     | `EK_TIMEOUT`                                      |
| Caller/application cancellation                     | `EK_ABORTED`                                      |
| Invalid ownership/control or uncertain commit       | `EK_DATABASE_TRANSACTION`                         |
| Other statement/cleanup failure                     | `EK_DATABASE_QUERY`                               |
| Closed pool                                         | `EK_RESOURCE_CLOSED`                              |

Native causes stay internal; safe details retain bounded numeric `errno` only.
The native driver replaces TLS error codes with `HANDSHAKE_SSL_ERROR`; negative
tests additionally inspect the underlying identity/chain error evidence.
Default logs contain fingerprints and bounded codes, never raw SQL or bindings.
Conflict retryability is classification metadata, never an automatic retry.

Optional observation ports are explicit plugin dependencies. Each application
statement records one `db.query` attempt, a CLIENT span and monotonic round-trip
seconds for OpenTelemetry, plus `db.client.elapsed` milliseconds in a trusted
meter scope. Pool wait is measured separately; internal reset/control statements
do not count as application queries. Diagnostic failures cannot replay writes or
replace results. Server CPU, I/O and transport byte attribution are not measured;
managed scopes mark `driver_bytes_unavailable`.

`stats()` exposes framework-owned active leases, pending acquisitions, statement
attempts, diagnostic failures and cleanup failure counts. Native total/idle/queue
counts are null because mysql2 exposes no stable public counters for them. The
retained shutdown cleanup evidence is bounded to the pool's work capacity.

`native(name)` returns the actual callback-based **mysql2 Pool**; use `.promise()`
for its native Promise API and borrowed PoolConnections. Native borrowers must
release before application shutdown. Native query conversion, procedures,
streams, savepoints and instrumentation belong to those advanced calls. Obtaining
a handle in a managed meter scope marks `not_instrumented`; later usage of a
retained handle cannot be inferred. Exclude mysql2 from host auto-instrumentation
when the framework owns its spans to avoid duplicate observations.

## Verification

Unit and contract tests run without a server. Live tests require
`ARKENIVA_MYSQL_URL`, `ARKENIVA_MYSQL_WRONG_SAN_URL` and the explicit
`ARKENIVA_MYSQL_DISPOSABLE=1` marker. Missing infrastructure fails the suite.
Use the [disposable TLS fixtures](test/fixtures/README.md) in a VM or CI runner;
all private credentials remain outside the checkout. Tests create uniquely named
tables in the restricted fixture database and clean up their own resources.

| Driver        | Server          | Node                      | Platform               | Live verification date |
| ------------- | --------------- | ------------------------- | ---------------------- | ---------------------- |
| mysql2 3.24.6 | MySQL 9.7.4 LTS | 22.23.4, 24.22.1, 26.12.1 | Linux x86-64, QEMU/KVM | 2026-10-25             |

Other server/runtime versions require their own live evidence.
Upstream references: [mysql2 documentation](https://sidorares.github.io/node-mysql2/docs),
[prepared statements](https://sidorares.github.io/node-mysql2/docs/documentation/prepared-statements),
[official MySQL image](https://hub.docker.com/_/mysql), and
[implicit commits](https://dev.mysql.com/doc/refman/9.7/en/implicit-commit.html).
