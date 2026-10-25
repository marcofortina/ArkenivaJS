# @arkenivajs/database-mongodb

Optional document support using the actual **mongodb 7.7.0** driver. Importing the
module and creating the application open no socket. Startup captures one explicit
MongoDB definition, authenticates and performs a scoped keys-only readiness read
before activating `app.mongo`. Operations use native MongoDB expressions.

```ts
import { createApplication } from '@arkenivajs/core';
import { mongodbPlugin } from '@arkenivajs/database-mongodb';

const app = await createApplication({
  service: { name: 'customer-service', version: '1.0.0', environment: 'production' },
  plugins: [mongodbPlugin()],
  databases: { documents: { driver: 'mongodb', connectionStringEnv: 'MONGODB_URL' } },
});
await app.start();
try {
  const identity = await app.mongo!.insertOne('customers', { customerId: 'customer-42' });
  const row = await app.mongo!.findOne<{ customerId: string }>('customers', {
    customerId: 'customer-42',
  });
  console.log(identity, row?.customerId);
} finally {
  await app.stop();
}
```

## Configuration and authority

Set an explicit URI such as
`mongodb://app:encoded-password@db.example:27017/customers?tls=true&tlsCAFile=/private/ca.crt&authSource=customers&replicaSet=main&prefix=service_`.
Percent-encode credentials and option values. The official driver URI parser
handles 1–8 seed hosts and SRV syntax. The allowed query fields are `tls`,
`tlsCAFile`, `authSource`, `authMechanism`, `directConnection`, `replicaSet` and
`prefix`, case-insensitively. Duplicate, empty and unknown fields reject.
Declare a database in the path. SQL `poolMin`/`poolMax` and root `endpoints`
are unsupported. This adapter profile uses SCRAM-SHA-256; alternate native
authentication profiles need separate review and verification.

Remote and production connections require credentials and verified TLS. The
client checks server identity and certificate trust with at least TLS 1.2.
An explicit CA file must be absolute, regular, nonempty and at most 1 MiB;
otherwise the process system roots are captured. Trust is captured before native
construction and does not reopen a mutable file during reconnect. Reconstruct
the application to rotate it. Plaintext is accepted only for explicitly trusted
development/test loopback hosts. There is no certificate-validation override.

The optional prefix contains at most 64 ASCII letters, digits, underscores and
hyphens. It prefixes portable collection arguments only. Embedded native names
in `$lookup`, `$unionWith`, `$merge` and other pipeline expressions remain
unchanged; supply their authorized physical names explicitly. A collection
prefix does not enforce authorization. Use a least-privileged database account.
For shared tenant collections, every lookup and mutation must include the
tenant from verified request identity. Spoofable headers are not authority;
MongoDB does not automatically install a row-level tenant policy.

## Document operations and BSON

| Operation                                                  | Result                                                                     |
| ---------------------------------------------------------- | -------------------------------------------------------------------------- |
| `findOne<T>(collection, filter, options?)`                 | One native BSON document or `null`.                                        |
| `findMany<T>(collection, filter, { limit?, ...options }?)` | Frozen result array; limit defaults to 100, maximum 1,000.                 |
| `insertOne(collection, document, options?)`                | Opaque canonical EJSON string representing the actual native inserted ID.  |
| `updateOne(collection, filter, update, options?)`          | Actual modified count, including zero for matched but unchanged documents. |
| `deleteOne(collection, filter, options?)`                  | Actual deleted count.                                                      |
| `aggregate<T>(collection, pipeline, options?)`             | Explicitly bounded native pipeline results.                                |
| `withTransaction(callback, options?)`                      | Callback result after one native session transaction attempt.              |

Portable inputs are captured before asynchronous submission. BSON classes such
as `ObjectId`, `Long`, `Int32`, `Double`, `Decimal128`, `Binary` and `BSONRegExp`
retain their native representation, as do dates. JavaScript bigint must fit
signed int64. Reads preserve numeric BSON wrappers, including `Int32` and
`Double`; select a matching TypeScript document type and perform explicit DTO
conversion for HTTP/JSON boundaries. Use `BSON.EJSON` from the selected driver
for exact serialization. An inserted ID is opaque: a string ID is EJSON-quoted,
and an ObjectId has its typed EJSON representation. Do not assume every ID is
an ObjectId or silently round a Long through a JavaScript number.

Inputs reject accessors, custom serializers, unsafe keys, cycles, invalid UTF-8,
sparse arrays and unsupported class instances. Portable documents/filters are
bounded to 1 MiB and nesting to 64 levels. Names must fit MongoDB's 235-byte
database/collection namespace bound and exclude control characters, `$` and
reserved system collections. Results are bounded to 1 MiB per document and
8 MiB total. Exceeding a bound fails and closes the cursor; no success is
returned with silently truncated results.

Aggregation accepts at most 128 stages and must prove a final output cardinality
of at most 1,000. An explicit `$limit`, `$count`, `$facet`, bounded sampling or
bucket stage can establish that bound. Expansion after an earlier limit may
require another explicit bound. Bounded `$unionWith` pipelines contribute their
own output to the proof. The adapter preserves every supplied stage and adds
no hidden limit or collection rewrite. `$out`/`$merge` have zero returned rows
but can write multiple documents: a later failure can leave partial effects.
Reconcile such failures before another attempt. Use an explicitly owned native
cursor, closed in `finally`, for larger streams or unsupported pipeline proofs.

## Transactions and uncertain effects

Transactions require a replica set or sharded deployment supporting sessions.
Standalone servers support CRUD and reject transaction callbacks before
invocation. The callback receives the actual `ClientSession`; pass it explicitly
to native operations. Portable calls are not implicitly enlisted. Await native
operations sequentially, and leave start/commit/abort/end-session ownership to
the provider. The callback runs once. The adapter uses the driver's Core session
API and disables retryReads, retryWrites and adaptive command retries.

A submitted write or commit interrupted before acknowledgment reports
`details.outcome='unknown'` and `retryable=false`. Missing SDK error labels do not
establish a rejected commit. Do not blindly replay a callback. A confirmed
rollback reports `rolled_back`; a confirmed commit remains `acknowledged` even
if later diagnostics fail. Explicit server constraints map to typed errors,
including native BSON-encoded error codes. Potentially partial aggregation
failures retain unknown effects even for duplicate-key errors.

Arbitrary callback JavaScript cannot be forcibly terminated. A public deadline
returns promptly while the callback remains owned and observed. A callback
that settles after cancellation is rolled back and cannot start a late commit.
Native session cleanup uses its own 5-second CSOT budget; idempotent native
rollback cleanup may make the driver's single documented cleanup retry.
Rollback acknowledgment and session completion are checked independently,
including errors the driver normally suppresses. Cleanup failures remain
visible with aggregate private causes and fail application drain.

## Budgets, lifecycle and observations

Calls accept positive safe-integer `timeoutMs` and `AbortSignal`. The monotonic
default is 15 seconds, readiness 5 seconds and connection shutdown 20 seconds.
The native pool has minimum 0, maximum 8 and at most 2 simultaneous connection
creations, with 5-second connection/server-selection/wait-queue budgets.
Admission is independently limited to 128 portable attempts and 8 transaction
sessions. Read cursors use the driver's supported AbortSignal; write/commit
APIs use native CSOT. Logical write cancellation does not prove physical
cancellation: admission remains held until the submitted native work settles.

Drain stops admission, cancels owned scopes and waits for cooperative native
work, cursors and sessions before closing the actual MongoClient. It still
attempts native close after a bounded drain failure and reports unfinished
work. Native change streams associated with that client close with it. A
retained provider facade rejects after closure.

Optional framework spans use bounded MongoDB operation names. Duration is
seconds for OTel and milliseconds for managed meter elapsed usage. Each
portable attempt records one `db.query`; startup probes are excluded. No
server CPU, I/O, wire bytes or pool-wait duration is fabricated. Meter quality
marks `driver_bytes_unavailable`, and native access inside a managed scope marks
`not_instrumented`. Diagnostic failures cannot replay work or replace a known
acknowledgment. Default logs omit documents, filters, URI credentials and raw
server messages. Native command logging is explicitly disabled even when
inherited MongoDB logging environment variables request tracing.

`native()` returns the actual application-owned `MongoClient`; obtain `Db`,
`Collection`, cursors and sessions from it. Native operations bypass portable
prefixes, bounds, conversion and instrumentation. The caller must close native
cursors/change streams and independently created sessions in `finally`, and
must not close the shared client independently. Avoid duplicate host database
auto-instrumentation unless collection/redaction has been reviewed.

## Verification

The [disposable TLS/SCRAM replica-set fixture](test/fixtures/README.md) runs in a
dedicated VM or ephemeral CI runner. Missing live configuration fails instead of
skipping. Tests cover native CRUD/BSON/custom IDs, unique indexes, limits,
aggregation, partial writes, session commit/rollback, late callbacks, dropped
insert/commit/abort replies, independent cancellation, TLS/authentication
negatives, tenant filters, metering and cursor/change-stream/session shutdown.
Coverage requires at least 95% of lines and branches.

Run the [executable customer consumer](../../examples/mongodb/README.md) for an
application-level BSON/DTO and native-session transaction example.

| Driver        | Server                                           | Node                        | Platform                            | Verified date |
| ------------- | ------------------------------------------------ | --------------------------- | ----------------------------------- | ------------- |
| mongodb 7.7.0 | MongoDB 9.0.4, one-member replica set, TLS/SCRAM | 22.23.4 / 24.22.1 / 26.12.1 | Linux x64; Ubuntu 24.04 QEMU server | 2026-10-25    |

SRV discovery, multi-member failover, sharded clusters and alternate authentication profiles
are outside this live compatibility claim. Server containers are separate test
prerequisites; the npm adapter has no native database addon and does not bundle
MongoDB Server. See [third-party notices](THIRD_PARTY_NOTICES.md).
