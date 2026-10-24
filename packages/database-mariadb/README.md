# @arkenivajs/database-mariadb

Independent MariaDB pools for the portable SQL facade, using the native
**mariadb 3.5.4** Promise API. Imports and factory/application creation open no
connections. Startup validates all root definitions before constructing pools,
warms their configured minimum and authenticates a readiness query. Application
cleanup closes every named pool.

```ts
import { createApplication } from '@arkenivajs/core';
import { mariadbPlugin } from '@arkenivajs/database-mariadb';

const app = await createApplication({
  service: { name: 'orders', version: '1.0.0', environment: 'production' },
  plugins: [mariadbPlugin()],
  databases: {
    main: { driver: 'mariadb', connectionStringEnv: 'MARIADB_URL', poolMax: 10 },
  },
});
await app.start();
try {
  const row = await app.sql.queryOne('main', {
    text: 'SELECT :value AS exact_value',
    bindings: { value: 9007199254740993n },
  });
  console.log(row);
} finally {
  await app.stop();
}
```

The zero-argument factory explicitly composes the common application-owned SQL
coordinator. Several named MariaDB pools and other installed SQL drivers share
`app.sql`. This package does not import mysql2 or infer MariaDB compatibility from
MySQL tests. Only root definitions with `driver: 'mariadb'` belong to it.

## Configuration and trust

The configured environment variable contains a
`mariadb://user:password@hostname:3306/database` URL. Host, user and database are
explicit; percent-encode URL components. Credentials are captured at startup,
without an ambient password fallback. Only `ssl` and `sslca` query parameters are
accepted, once each. Invalid options, pool limits or trust settings reject before
native pool construction.

Production/shared network connections require verified TLS. Use `ssl=verify-full`
and, for a private CA, an absolute URL-encoded `sslca` path. Both DNS names and IP
literals are verified against the configured endpoint. TLS uses a nonempty
explicit CA bundle, or a captured copy of Node's built-in CA roots. This prevents
the native connector's password/fingerprint fallback from relaxing certificate
verification when no CA is supplied. Custom enterprise trust must be supplied
explicitly through `sslca`. Certificate and identity verification remain enabled
before credentials are sent.

An isolated development/test loopback URL may use `ssl=disable`, which is its
default local policy if no TLS option is given. A CA path with disabled TLS
rejects. Production loopback still requires verified TLS.

Pool minimum defaults to 0 and maximum to 10 (`0 <= min <= max`). MariaDB's native
minimum-idle target and explicit startup warmup preserve those bounds. Startup
cancellation reaches warmup as well as the readiness query. Native connection,
initialization and acquisition budgets are 5,000 ms. The owned SQL deadline is
15,000 ms by default; a positive `timeoutMs` can impose an earlier total budget,
including acquisition and queued callback work. No query is replayed.
Outstanding framework acquisitions and callback statements are bounded to 128 per
pool, or its larger explicitly configured maximum.

## Binding, fetching and conversion

The common finite-state lexer compiles exact `:name` bindings to ordered `?`
parameters using MariaDB's dialect and actual `ANSI_QUOTES` and
`NO_BACKSLASH_ESCAPES` session modes. Repeated names repeat values. Missing/extra
names, executable comments and native placeholder syntax reject before application
SQL is sent. Identifiers require an application allowlist; they cannot be bound.

Every application statement uses public native `prepare().executeStream()` with
separate parameters. Native text interpolation is not used for application binds.
Result streams retain bounded rows, with native backpressure and a fixed native
object buffer. `query` defaults to `maxRows=10000`, accepts 1..100000 and rejects
overflow with `EK_DATABASE_QUERY` and `details.limitExceeded=true`. `queryOne`
accepts at most two rows and rejects on the second. Early termination destroys
the owned connection before stopping the native stream; prepared statements are
closed on success, error and late cancellation. No partial success is returned.
This bounds materialization, not server execution cost or transport packet sizes.

MariaDB's conversion policy is independent of MySQL:

- BIGINT columns and native insert identifiers retain **JavaScript bigint**.
- DECIMAL, JSON and date/time columns retain text, preserving decimal, JSON-number
  and temporal microsecond precision. JSON auto-conversion is disabled.
- Smaller integer/approximate floating columns retain native numbers; BLOB uses
  Buffer and null remains null.
- Portable bigint parameters use exact decimal strings. Binary values are copied
  Buffers. Date inputs are captured and encoded as UTC timestamp text at JavaScript
  millisecond precision. The native binary Date encoder uses local calendar
  fields; portable UTC conversion explicitly avoids that host-timezone dependency.

Convert bigint to an explicit string DTO before JSON serialization where needed.
Native advanced calls retain the connector's own conversion behavior.

Completed row streams report their observed row count. Native command headers
retain safe `affectedRows` in `rowCount`/metadata, and exact bigint insert IDs.
Unknown/unsafe counts remain null and are omitted from metadata. MariaDB
`INSERT ... RETURNING` rows are retained; when no separate affected-row header is
available, metadata does not invent one. Native `warningStatus` is logged as a
bounded count with a fingerprint when a logger exists; the shared result type has
no warning field. Obtain the full native header through the escape hatch.

## Transactions and cleanup

`transaction` pins one connection, resets its previous session state, begins,
serializes queued statements and commits once. Await every statement. Failed
queued work prevents commit even if caught by the callback. Callback results and
primitive failures retain their identity; primary and cleanup failures remain in
aggregate causes. Nested transactions, pool reentry and cross-request/stale
handles reject through the common coordinator. Manual transaction controls,
savepoints, procedures and multiple result sets use the native API.

MariaDB DDL can implicitly commit. Keep schema DDL outside business transactions.
An ended native transaction status reports `EK_DATABASE_TRANSACTION`,
`details.outcome='implicitly_committed'`, with no retry; already committed effects
remain. Missing transaction status fails closed with an unknown outcome.
A lost/deadline-expired COMMIT acknowledgment likewise reports an unknown outcome
and `retryable=false`. Reconcile with domain idempotency keys; no automatic retry
of SQL or callbacks is performed.

Every portable checkout uses public native `reset()`, which also invalidates the
prepared statement cache, then restores UTF-8, UTC, autocommit and explicit
`STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION`. Session settings and temporary state
do not survive between portable calls. Successful callback statements refresh
actual mode/encoding/timezone evidence before the next queued compilation.
Changing UTF-8 or UTC makes subsequent portable work reject.
Native release promises are awaited, late acquisitions remain owned, and shutdown
waits for owned asynchronous disposal. Cancellation destroys active connections.

## Errors and measurement

| Condition                                                         | Framework code                                    |
| ----------------------------------------------------------------- | ------------------------------------------------- |
| Missing definition/environment value                              | `EK_CONFIG_MISSING`                               |
| Invalid URL, trust policy, binds or limits                        | `EK_CONFIG_INVALID`                               |
| Acquisition capacity/deadline exhausted                           | `EK_DATABASE_POOL_TIMEOUT`                        |
| Failed acquisition / lost active connection                       | `EK_DATABASE_CONNECT` / `EK_DATABASE_UNAVAILABLE` |
| Duplicate 1062, null 1048, FK 1451/1452, CHECK 4025               | `EK_DATABASE_CONSTRAINT`                          |
| Deadlock 1213 or lock wait 1205                                   | `EK_DATABASE_CONFLICT`                            |
| MariaDB statement timeout 1969, interruption 1317, owned deadline | `EK_TIMEOUT`                                      |
| Caller/application cancellation                                   | `EK_ABORTED`                                      |
| Ownership, implicit commit or uncertain commit                    | `EK_DATABASE_TRANSACTION`                         |
| Other statement/cleanup failure                                   | `EK_DATABASE_QUERY`                               |
| Closed pool                                                       | `EK_RESOURCE_CLOSED`                              |

Native acquisition errors can retain the actual authentication/TLS cause; that
cause determines classification instead of treating every failure as pool
saturation. Safe details retain bounded numeric errno only. Raw SQL, values,
credentials and vendor messages stay out of default logs and safe error JSON.

Optional diagnostic ports are explicit dependencies. Application statements count
one `db.query` attempt; CLIENT spans and OTel duration histograms use seconds.
Trusted meter scopes record `db.client.elapsed` in milliseconds, independently of
tracing. Pool acquisition duration is separate; internal reset/control statements
are excluded from application query counts. Diagnostic failures cannot replay work
or replace its result. Native bytes and server CPU/I/O are not attributed;
managed scopes mark `driver_bytes_unavailable`.

`stats()` uses the driver's **public** total/idle/active/queue counters and reports
framework-owned active leases, pending acquisitions, statement attempts and
diagnostic/cleanup failures separately. No queue depth is guessed.
`native()` returns the actual **mariadb Promise Pool**; `getConnection()` returns
a native Promise connection whose `release()` must be awaited. Release borrowers
and close prepared statements before shutdown. Advanced calls own their conversion,
transaction and instrumentation policy. Obtaining a handle in a managed meter
scope marks `not_instrumented`; retained-handle usage cannot be inferred later.
Exclude the native connector from host auto-instrumentation when framework-owned
spans are active.

## Verification and dependencies

The [disposable TLS fixtures](test/fixtures/README.md) use an independent MariaDB
server and restricted account; private credentials remain outside the checkout.
Live tests require `ARKENIVA_MARIADB_URL`, a trusted-CA wrong-identity endpoint at
`ARKENIVA_MARIADB_WRONG_SAN_URL` and `ARKENIVA_MARIADB_DISPOSABLE=1`. Missing
infrastructure fails rather than skipping tests. Unit/contract tests need no server.
Run `pnpm test:integration:mariadb` or `pnpm coverage:mariadb` with the private
fixture variables. CI enforces combined 95% line/branch coverage and the consumer
on each supported Node version.

| Driver        | Server             | Node                      | Platform               | Live verification date |
| ------------- | ------------------ | ------------------------- | ---------------------- | ---------------------- |
| mariadb 3.5.4 | MariaDB 12.3.3 LTS | 22.23.4, 24.22.1, 26.12.1 | Linux x86-64, QEMU/KVM | 2026-10-25             |

Other versions/platforms need independent live evidence. The separately installed
connector is exercised by the [runnable orders consumer](../../examples/mariadb/README.md),
including explicit bigint-to-JSON conversion and real rollback. The upstream
connector declares **LGPL-2.1-or-later**; its lru-cache 11.5.3 dependency declares
[BlueOak-1.0.0](https://blueoakcouncil.org/license/1.0.0). Product release licensing,
notices and redistribution review remain separate from private development checks.

Upstream: [Promise and prepared stream API](https://mariadb.com/docs/connectors/mariadb-connector-nodejs/connector-nodejs-promise-api),
[connector source](https://github.com/mariadb-corporation/mariadb-connector-nodejs),
[official server image](https://hub.docker.com/_/mariadb).
