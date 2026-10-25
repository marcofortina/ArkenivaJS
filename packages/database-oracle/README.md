# @arkenivajs/database-oracle

**Oracle adapter contract-tested with mocks; live compatibility not verified**.

An optional adapter for `app.sql`, using **oracledb 26.0.0**. Importing this
package or constructing its plugin opens no connections. Application startup
validates every named definition, creates independent native pools and
authenticates a readiness query. Thin mode is the default and needs no Oracle
Client. `oraclePlugin({ mode: 'thick' })` requires separately installed compatible
Oracle Client libraries. The SDK chooses one mode for the entire process;
conflicting mode requests fail instead of silently changing existing connections.

```ts
import { createApplication } from '@arkenivajs/core';
import { oraclePlugin } from '@arkenivajs/database-oracle';

const app = await createApplication({
  service: { name: 'legacy-reader', version: '1.0.0', environment: 'production' },
  plugins: [oraclePlugin({ mode: 'thin' })],
  databases: {
    legacy: { driver: 'oracle', connectionStringEnv: 'ORACLE_URL', poolMax: 4 },
  },
});
await app.start();
try {
  const row = await app.sql.queryOne('legacy', {
    text: 'SELECT CAST(:value AS NUMBER(38,0)) AS "exact" FROM DUAL',
    bindings: { value: 9007199254740993n },
  });
  console.log(row); // NUMBER columns retain strings, including small integers.
} finally {
  await app.stop();
}
```

## Connection and transport policy

The explicit environment variable contains
`oracle://user:password@host:2484/service?ssl=verify-full`. Percent-encode user,
password and query values. Host, credentials and one service name are required;
TNS aliases, arbitrary descriptors, ambient external authentication, connection
failover lists and unrecognized/duplicate URL options are rejected. Advanced
Oracle Net configurations require separately owned native pools.

Production and shared-network connections require TCPS. Native
`sslServerDNMatch=true` and `sslAllowWeakDNMatch=false` preserve certificate
identity checks. An optional absolute `wallet` directory supplies the SDK's
wallet location for private trust/mTLS; keep its contents outside Git with private
permissions. Wallet provisioning and native TLS compatibility require real-server
validation. The adapter does not claim these have been tested live. With no
wallet override, native SDK trust configuration applies. No certificate
verification bypass is offered.

Only isolated development/test loopback connections may use `ssl=disable`; this
is their default. Production loopback still uses TCPS. TCP defaults to port 1521,
TCPS to 2484. Only `ssl` and `wallet` URL options are accepted. Pool minimum
defaults to 0 and maximum to 10; safe integer bounds require `0 <= min <= max`.
Native pool aliases are unique across application instances, avoiding the default
global pool-cache name. Native minimum initialization occurs during startup.

Native connection/transport and pool-acquisition budgets are 5 seconds; native
retry count is zero. Each acquired connection has `callTimeout=5000` ms, which is
a **per-round-trip** SDK timeout. The separate monotonic framework deadline
defaults to 15,000 ms and covers acquisition, queued statements and all fetches.
A positive `timeoutMs` imposes a total caller budget; `signal` supports
cancellation. Outstanding acquisitions and pending callback statements are
bounded to 128 per pool, or its larger configured maximum.

## Values, precision and bounded results

The shared finite-state Oracle lexer preserves `:name` parameters, including
repeated names, quoted text, comments and alternative quotes. Exact missing/extra
binding checks run before acquisition; values never become SQL text. SQL identifiers
require an application allowlist. Portable binds support null, string, finite
number, boolean, bigint, Date and Uint8Array. Boolean support in the database is
version-dependent and is not a claim of verified live compatibility.

Oracle folds unquoted native bind names to uppercase. Distinct portable names
that collide under that rule, such as `:Id` and `:id`, reject before acquisition;
they cannot silently overwrite each other's values. Ordinary repeated names
remain valid. Quoted native bind names require explicit native SQL ownership.

- NUMBER results retain exact decimal **strings**, with no JavaScript number
  conversion. Approximate BINARY_FLOAT/BINARY_DOUBLE results use native floating
  precision represented as text.
- Bigint inputs are exact decimal text parameters. Date inputs are captured UTC
  ISO strings at JavaScript millisecond precision; use explicit SQL conversion,
  such as `FROM_TZ(TO_TIMESTAMP(:instant, 'YYYY-MM-DD"T"HH24:MI:SS.FF3"Z"'), 'UTC')`,
  with a format appropriate to your schema. Do not rely on implicit NLS
  date conversion.
- Binary inputs become copied Buffers; native RAW results retain Buffers and
  database null remains null. Oracle itself treats an empty VARCHAR string as
  null.
- Raw DATE/TIMESTAMP results reject: Thin SDK conversion can pass through
  JavaScript Date and lose submillisecond precision before a string handler sees
  the value. Project exact text explicitly with SQL
  `TO_CHAR(column, 'YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM')` for a timestamp with time
  zone, or the corresponding format for its actual type. This lets the server
  perform the precise conversion. SQL DATE has no fractional seconds/timezone.
- LOB, object, cursor, native JSON, XMLTYPE and vector results use the owned native API.
  Portable queries reject their metadata before fetching. LOBs are never silently
  materialized or returned after releasing the session. IN/OUT binds and
  `RETURNING INTO` also belong to the native interface.

Conversions are per execution; the adapter does not replace process-wide SDK
fetch settings. Explicit type handlers also prevent ambient legacy JSON
conversion from turning a textual JSON number into an imprecise JavaScript value.

Queries use native ResultSets, `prefetchRows=0`, and fetch batches of at most 256
rows. `maxRows` defaults to 10,000, accepts 1..100,000 and rejects overflow with
`EK_DATABASE_QUERY`/`details.limitExceeded=true`; no truncated success is returned.
`queryOne` fetches at most two rows and rejects on the second. This bounds row
materialization, not the size of one scalar column or server execution cost.
ResultSet closure is awaited before returning a connection to its pool.
Completed cursor row counts are observed; native safe affected counts populate
`rowCount` and `metadata.affectedRows`. Unknown counts remain null.

## Transactions, cancellation and cleanup

Portable checkouts roll back prior work and restore explicit UTC and numeric/date
NLS formats. This is **not a complete Oracle session reset**: package state,
temporary objects and native changes to schema/security context need explicitly
owned native sessions, separate pools and application policy. Do not mix security
context mutations with portable pool usage.

`transaction` pins one connection, starts `SET TRANSACTION READ WRITE`, serializes
its queued statements and commits once after the callback and queued work finish.
Failed statements prevent commit even when caught by the callback. Always await
every statement. Common coordination rejects nesting, pool reentry, stale handles
and cross-request ownership. PL/SQL, manual transaction controls and savepoints
require explicit native ownership. Callback failures retain their original
identity; cleanup failures remain in aggregate causes.

DDL can implicitly commit. Keep schema changes outside business transactions.
An observed end of the pinned transaction reports
`details.outcome='implicitly_committed'`; absent status reports `unknown`.
Previously committed effects cannot be undone. An unacknowledged, timed-out or
cancelled COMMIT reports `EK_DATABASE_TRANSACTION`, `outcome='unknown'` and
`retryable=false`, including when connection cleanup also fails. Reconcile domain
idempotency keys; the adapter never replays statements or callbacks.

Cancellation requests native `break()`, observes in-flight native promises,
closes owned cursors and drops the session. Late acquisitions and late ResultSets
remain owned. Disposal and shutdown have bounded cleanup waits; stalled native
cleanup is surfaced as an error and its promise remains observed, rather than
claiming successful release. Close every native borrower before `app.stop()`.
Shutdown closes all application pools even when another pool reports failure.

## Native LOB and OUT-bind ownership

`app.sql.native('legacy')` returns the actual **oracledb Pool**. Use
`pool.getConnection()` and keep that connection checked out until every ResultSet
and LOB stream completes. For example, select a CLOB with native execution options
that retain Lob objects, await `pipeline(lob, destination)` to a bounded caller-owned
destination, then close the ResultSet and finally the connection. A stream error
requires dropping the connection. A native writable LOB from `RETURNING INTO`
similarly remains tied to its transaction and must finish before commit.
Native `BIND_OUT`/`BIND_INOUT` descriptors are passed directly to `execute`.
These operations retain native SDK conversion, timeout and transaction semantics.

Retained native handles and their later calls cannot be inferred or automatically
instrumented. Obtaining a handle in a managed meter scope marks
`not_instrumented`. Avoid duplicate SDK auto-instrumentation when using framework
spans. See the [upstream LOB guide](https://node-oracledb.readthedocs.io/en/latest/user_guide/lob_data.html)
and [bind guide](https://node-oracledb.readthedocs.io/en/latest/user_guide/bind.html).

## Errors and measurement

Tested ORA mappings cover constraint codes 00001/01400/02290/02291/02292,
conflicts 00060/08177 and interruption 01013. Tested disconnect codes are
03113/03114/03135 and NJS-500/501/503; NJS-040 during acquisition is a pool
timeout. Other native errors retain a generic connect/query wrapper. Safe
details contain only bounded vendor codes; raw SQL, values, credentials and
vendor messages stay out of default diagnostic fields and safe error JSON.
Classification never authorizes automatic retry.

Each application statement counts one `db.query` attempt. Optional CLIENT spans
and OTel histograms use seconds; trusted meter scopes record observed
`db.client.elapsed` in milliseconds. Pool waiting is measured separately;
reset/begin/commit/rollback control calls are not application statement counts.
No server CPU, I/O or payload byte count is invented; managed scopes mark
`driver_bytes_unavailable`. Diagnostic failures cannot replay business work or
replace its result. `stats()` reports public native open/in-use counts, their
idle difference, framework leases/pending acquisitions and diagnostic/cleanup
failures. Queue depth is unknown (`null`).

## Verification and dependency policy

Run `pnpm --filter @arkenivajs/database-oracle coverage` after a workspace build.
Mandatory mocks cover pool lifecycle, exact binds/conversion policy, bounded
fetches, LOB lifetime boundaries, callback rollback/commit, cancellation,
late cleanup, implicit/unknown outcomes and observation failures. One offline
contract also constructs and closes actual empty Thin pools; it opens zero
database connections. No Oracle Instant Client is needed for these tests.

The separate optional suite requires an authorized **disposable** Oracle schema,
`ARKENIVA_ORACLE_URL`, `ARKENIVA_ORACLE_DISPOSABLE=1` and optional
`ARKENIVA_ORACLE_MODE=thin|thick`. The account needs its own table DDL/DML and
LOB privileges. It creates and drops only a bounded random allowlisted table;
never point it at production/customer data. Run
`pnpm test:integration:oracle` after a build. Missing authorization/credentials
fail this explicitly invoked suite. Normal CI does not invoke it or require
Oracle Client. Real SQL, LOB streaming, RETURNING/INOUT and transaction claims
remain unverified until that suite succeeds against recorded versions.

| Driver          | Server     | Mode                        | Node                        | Platform     | Evidence scope                                              |
| --------------- | ---------- | --------------------------- | --------------------------- | ------------ | ----------------------------------------------------------- |
| oracledb 26.0.0 | Not tested | Thin; Thick boundary mocked | 22.23.4 / 24.22.1 / 26.12.1 | Linux x86-64 | 2026-10-25 mock/contract suite; no live compatibility claim |

Oracle Client/Thick and real database versions remain unverified. Update the
table only after recording exact versions, mode, platform, date and a successful
authorized live run. SDK upstream compatibility lists are not adapter evidence.

The runtime dependency is dual-licensed `(Apache-2.0 OR UPL-1.0)` with no npm
runtime dependency tree. Its distribution includes license/notice and Node.js
third-party notices; retain applicable notices when redistributing. Type
declarations use `@types/oracledb` 26.0.0 (MIT). Both versions are pinned.
Oracle Client libraries and database server licensing/setup are separate and
are neither installed nor bundled by this adapter.

When an optional health collector is installed, the plugin pings each owned
named pool through the adapter's bounded operation scope. The callback retains
its original plugin context and cannot use resources after owner closure.
Oracle adapter contract-tested with mocks; live compatibility not verified.
